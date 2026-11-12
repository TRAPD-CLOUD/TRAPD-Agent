//! `RegNotifyChangeKeyValue` backend for the registry watcher.
//!
//! One dedicated OS thread owns every registration: it keeps a
//! [`WatchSet`](crate::collectors::registry_notify::WatchSet) of at most
//! `MAX_WATCHED_KEYS` keys, waits on their events and sends a coalescing wake
//! to the poll loop in `regwatch.rs`. Scheduling, bounds and fallback
//! accounting live in the platform-neutral `registry_notify.rs`; this file is
//! only the Win32 calls and the thread loop.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::mpsc::Sender;
use tracing::{info, warn};
use windows_sys::Win32::Foundation::{
    CloseHandle, HANDLE, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegNotifyChangeKeyValue, RegOpenKeyExW, HKEY, HKEY_LOCAL_MACHINE, HKEY_USERS,
    KEY_NOTIFY, REG_NOTIFY_CHANGE_ATTRIBUTES, REG_NOTIFY_CHANGE_LAST_SET, REG_NOTIFY_CHANGE_NAME,
    REG_NOTIFY_THREAD_AGNOSTIC,
};
use windows_sys::Win32::System::Threading::{
    CreateEventW, WaitForMultipleObjects, WaitForSingleObject,
};

use crate::collectors::registry_notify::{
    plan_targets, NotifyBackend, NotifyStats, WatchSet, WatchTarget, MAX_WATCHED_KEYS,
    RECONCILE_EVERY,
};
use crate::collectors::registry_watch::{RegRoot, SPECS};

const WAIT_SLICE: Duration = Duration::from_millis(1000);
const FILTER: u32 = REG_NOTIFY_CHANGE_NAME
    | REG_NOTIFY_CHANGE_ATTRIBUTES
    | REG_NOTIFY_CHANGE_LAST_SET
    | REG_NOTIFY_THREAD_AGNOSTIC;

/// An open key plus its auto-reset event. Both handles are released on drop.
struct NotifyKey {
    key: HKEY,
    event: HANDLE,
    subtree: bool,
}

impl Drop for NotifyKey {
    fn drop(&mut self) {
        // SAFETY: both handles were created by `open` and are closed once here.
        unsafe {
            RegCloseKey(self.key);
            CloseHandle(self.event);
        }
    }
}

impl NotifyKey {
    fn arm(&mut self) -> Result<(), u32> {
        // SAFETY: valid key and event handles owned by `self`; asynchronous
        // mode, so the call returns at once and signals `event` on change.
        let status = unsafe {
            RegNotifyChangeKeyValue(self.key, self.subtree as i32, FILTER, self.event, 1)
        };
        if status == 0 {
            Ok(())
        } else {
            Err(status)
        }
    }
}

struct Win32Backend;

impl NotifyBackend for Win32Backend {
    type Key = NotifyKey;

    fn open(&mut self, target: &WatchTarget) -> Result<NotifyKey, u32> {
        let root = match target.root {
            RegRoot::LocalMachine => HKEY_LOCAL_MACHINE,
            RegRoot::Users => HKEY_USERS,
        };
        let path: Vec<u16> = target.path.encode_utf16().chain(Some(0)).collect();
        let mut key: HKEY = std::ptr::null_mut();
        // SAFETY: terminated path and a valid out-pointer.
        let status = unsafe { RegOpenKeyExW(root, path.as_ptr(), 0, KEY_NOTIFY, &mut key) };
        if status != 0 {
            return Err(status);
        }
        // SAFETY: auto-reset, initially non-signalled, unnamed event.
        let event = unsafe { CreateEventW(std::ptr::null(), 0, 0, std::ptr::null()) };
        if event.is_null() {
            // SAFETY: `key` was opened above and is not used again.
            unsafe { RegCloseKey(key) };
            return Err(8); // ERROR_NOT_ENOUGH_MEMORY, no better status is available
        }
        // Dropping on failure closes both handles.
        let mut opened = NotifyKey {
            key,
            event,
            subtree: target.subtree,
        };
        opened.arm()?;
        Ok(opened)
    }

    fn rearm(&mut self, key: &mut NotifyKey) -> Result<(), u32> {
        key.arm()
    }

    fn wait(&mut self, keys: &[&NotifyKey], timeout: Duration) -> Result<Vec<usize>, u32> {
        if keys.is_empty() {
            std::thread::sleep(timeout);
            return Ok(Vec::new());
        }
        if keys.len() > MAX_WATCHED_KEYS {
            return Err(87); // ERROR_INVALID_PARAMETER; the set never exceeds the cap
        }
        let handles: Vec<HANDLE> = keys.iter().map(|k| k.event).collect();
        // SAFETY: `handles` holds at most 62 live event handles.
        let status = unsafe {
            WaitForMultipleObjects(
                handles.len() as u32,
                handles.as_ptr(),
                0,
                timeout.as_millis().min(u128::from(u32::MAX - 1)) as u32,
            )
        };
        if status == WAIT_TIMEOUT {
            return Ok(Vec::new());
        }
        if status == WAIT_FAILED {
            // SAFETY: trivially safe thread-local error read.
            return Err(unsafe { windows_sys::Win32::Foundation::GetLastError() });
        }
        let first = (status - WAIT_OBJECT_0) as usize;
        if first >= handles.len() {
            return Err(status); // abandoned or unexpected; rebuild the set
        }
        // WaitForMultipleObjects reports only the lowest signalled index and
        // resets just that auto-reset event: sweep the others without waiting.
        let mut fired = vec![first];
        for (index, handle) in handles.iter().enumerate().skip(first + 1) {
            // SAFETY: live event handle, zero timeout.
            if unsafe { WaitForSingleObject(*handle, 0) } == WAIT_OBJECT_0 {
                fired.push(index);
            }
        }
        Ok(fired)
    }
}

/// Stops the notification thread when dropped.
pub struct NotifyGuard(Arc<AtomicBool>);

impl Drop for NotifyGuard {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

/// Start the notification thread. Each notification sends one `()` on `wake`
/// (capacity-1 channel: bursts coalesce). The thread ends within one wait
/// slice of the guard dropping or the receiver closing. If it cannot start,
/// the poll loop simply runs at its normal interval.
pub fn spawn(wake: Sender<()>) -> Option<NotifyGuard> {
    let stop = Arc::new(AtomicBool::new(false));
    let thread_stop = stop.clone();
    let started = std::thread::Builder::new()
        .name("trapd-regnotify".into())
        .spawn(move || run(wake, thread_stop));
    match started {
        Ok(_) => Some(NotifyGuard(stop)),
        Err(error) => {
            warn!(%error, "registry change notification thread not started; polling only");
            crate::telemetry::coverage::update(|c| c.registry_sensor = Some("polling".into()));
            None
        }
    }
}

fn run(wake: Sender<()>, stop: Arc<AtomicBool>) {
    let mut backend = Win32Backend;
    let mut set: WatchSet<NotifyKey> = WatchSet::default();
    let mut last_reconcile: Option<Instant> = None;
    let mut reported: Option<NotifyStats> = None;
    while !stop.load(Ordering::Acquire) && !wake.is_closed() {
        if last_reconcile.is_none_or(|at| at.elapsed() >= RECONCILE_EVERY) {
            let hives = super::registry::subkeys_checked(super::registry::Hive::Users, "", 0)
                .unwrap_or_default();
            set.reconcile(&mut backend, plan_targets(SPECS, &hives, MAX_WATCHED_KEYS));
            last_reconcile = Some(Instant::now());
        }
        if set.wait(&mut backend, WAIT_SLICE) > 0 {
            // A full channel already holds a pending wake.
            let _ = wake.try_send(());
        }
        let stats = set.stats();
        if reported.as_ref() != Some(&stats) {
            publish(&stats);
            reported = Some(stats);
        }
    }
}

fn publish(stats: &NotifyStats) {
    crate::telemetry::coverage::update(|c| {
        c.registry_sensor = Some(
            if stats.watched > 0 {
                "notify"
            } else {
                "polling"
            }
            .into(),
        );
        c.registry_notify_keys = stats.watched as u64;
        c.registry_notify_fallbacks = stats
            .fallbacks
            .iter()
            .map(|(reason, n)| ((*reason).to_string(), *n as u64))
            .collect();
    });
    if stats.fallbacks.is_empty() {
        info!(
            watched = stats.watched,
            "registry change notification active"
        );
    } else {
        // `key_missing` alone is normal (optional keys); the rest degrades a
        // key to interval polling, which stays active.
        info!(watched = stats.watched, fallbacks = ?stats.fallbacks, "registry change notification state changed; keys listed fall back to interval polling");
    }
}
