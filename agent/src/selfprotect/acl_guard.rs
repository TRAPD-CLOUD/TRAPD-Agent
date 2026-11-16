//! Windows runtime for the service/registry ACL self-protection (WP2/WP3).
//!
//! At start, and every [`RECHECK_INTERVAL`] afterwards, the agent reads the
//! DACL of its own service and of the two registry keys it depends on
//! (`Services\trapd-agent`, `SOFTWARE\TRAPD\Agent`), compares them with
//! [`super::acl_policy`], reports any drift as a high-severity finding and
//! re-applies the expected DACL. Two dedicated threads block in
//! `RegNotifyChangeKeyValue` so a change is noticed within moments:
//!
//! * the service key itself (values, DACL, owner), not its subtree, so the
//!   agent's own re-application (which rewrites the `Security` subkey) does not
//!   wake it again;
//! * the `Security` subkey, where the SCM keeps the service DACL, which is the
//!   only change notification the service DACL has.
//!
//! Detection, not prevention: an administrator with take-ownership or
//! `SeDebugPrivilege` can still change these objects; the point is that it is
//! reported. A host installed with `TRAPD_LEGACY_ACLS=1` (the rollback switch)
//! carries a marker value and is not checked for DACL drift.
//!
//! Nothing here logs ACL contents at info level beyond the SDDL strings, which
//! hold SIDs and rights and no secrets.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{bail, Result};
use sha2::{Digest, Sha256};
use tracing::{debug, info, warn};
use trapd_schema::AgentEvent;
use windows_sys::Win32::Foundation::{CloseHandle, ERROR_MORE_DATA, ERROR_NO_MORE_ITEMS};
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegEnumValueW, RegNotifyChangeKeyValue, RegOpenKeyExW, HKEY, HKEY_LOCAL_MACHINE,
    KEY_NOTIFY, KEY_QUERY_VALUE, REG_NOTIFY_CHANGE_LAST_SET, REG_NOTIFY_CHANGE_NAME,
    REG_NOTIFY_CHANGE_SECURITY, RRF_SUBKEY_WOW6464KEY,
};
use windows_sys::Win32::System::Threading::{CreateEventW, WaitForSingleObject, INFINITE};

use super::acl_policy::{
    self as policy, RegistryChange, AGENT_KEY_PATH, REGISTRY_KEY_LEGACY_SDDL, REGISTRY_KEY_SDDL,
    SERVICE_DACL_LEGACY_SDDL, SERVICE_DACL_SDDL, SERVICE_KEY_PATH, SERVICE_SECURITY_KEY_PATH,
};
use crate::winacl;

const SERVICE_NAME: &str = "trapd-agent";
/// Periodic recheck: the service DACL has no change notification of its own
/// besides the `Security` subkey watch, which a key-level tamper could bypass.
pub const RECHECK_INTERVAL: Duration = Duration::from_secs(10 * 60);
/// Coalesce the burst of notifications one change causes.
const SETTLE: Duration = Duration::from_millis(500);
const MAX_VALUES: u32 = 256;
const MAX_VALUE_BYTES: usize = 64 * 1024;

/// Whether the MSI was installed with the legacy-ACL rollback switch.
pub fn legacy_mode() -> bool {
    crate::collectors::windows::registry::dword(
        policy::LEGACY_MARKER_KEY,
        policy::LEGACY_MARKER_VALUE,
        RRF_SUBKEY_WOW6464KEY,
    ) == Some(1)
}

// ── Registry key snapshot ─────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
struct KeySnapshot {
    owner: Option<String>,
    sddl: String,
    /// value name -> digest of (type, data)
    values: BTreeMap<String, String>,
}

struct Key(HKEY);
impl Drop for Key {
    fn drop(&mut self) {
        // SAFETY: opened by RegOpenKeyExW, closed once.
        unsafe {
            RegCloseKey(self.0);
        }
    }
}

fn open_key(subkey: &str, access: u32) -> Result<Key> {
    let wide: Vec<u16> = subkey.encode_utf16().chain(Some(0)).collect();
    let mut h: HKEY = std::ptr::null_mut();
    // SAFETY: NUL-terminated path; valid out-pointer.
    let status = unsafe { RegOpenKeyExW(HKEY_LOCAL_MACHINE, wide.as_ptr(), 0, access, &mut h) };
    if status != 0 {
        bail!(
            "open HKLM\\{subkey}: {}",
            std::io::Error::from_raw_os_error(status as i32)
        );
    }
    Ok(Key(h))
}

fn read_values(subkey: &str) -> Result<BTreeMap<String, String>> {
    let key = open_key(subkey, KEY_QUERY_VALUE)?;
    let mut out = BTreeMap::new();
    let mut data = vec![0u8; MAX_VALUE_BYTES];
    for index in 0..MAX_VALUES {
        let mut name = [0u16; 256];
        let mut name_len = name.len() as u32;
        let mut ty = 0u32;
        let mut data_len = data.len() as u32;
        // SAFETY: buffers are valid for the lengths passed.
        let status = unsafe {
            RegEnumValueW(
                key.0,
                index,
                name.as_mut_ptr(),
                &mut name_len,
                std::ptr::null(),
                &mut ty,
                data.as_mut_ptr(),
                &mut data_len,
            )
        };
        if status == ERROR_NO_MORE_ITEMS {
            break;
        }
        let name = String::from_utf16_lossy(&name[..(name_len as usize).min(name.len())]);
        let digest = if status == ERROR_MORE_DATA {
            "oversize".to_string()
        } else if status == 0 {
            let mut h = Sha256::new();
            h.update(ty.to_le_bytes());
            h.update(&data[..(data_len as usize).min(data.len())]);
            hex::encode(&h.finalize()[..8])
        } else {
            bail!(
                "enumerate values of HKLM\\{subkey}: {}",
                std::io::Error::from_raw_os_error(status as i32)
            );
        };
        out.insert(name, digest);
    }
    Ok(out)
}

fn snapshot(subkey: &str, with_values: bool) -> Result<KeySnapshot> {
    let sddl = winacl::get_machine_key_security(subkey)?;
    Ok(KeySnapshot {
        owner: policy::owner_of(&sddl),
        sddl,
        values: if with_values {
            read_values(subkey)?
        } else {
            BTreeMap::new()
        },
    })
}

// ── The guard ─────────────────────────────────────────────────────────────────

pub struct Guard {
    agent_id: String,
    hostname: String,
    legacy: bool,
    /// Baseline of the service key; taken at the first check.
    service_key: Mutex<Option<KeySnapshot>>,
}

impl Guard {
    pub fn new(agent_id: String, hostname: String, legacy: bool) -> Self {
        Self {
            agent_id,
            hostname,
            legacy,
            service_key: Mutex::new(None),
        }
    }

    fn event(&self, d: trapd_schema::DetectionData) -> AgentEvent {
        policy::event(d, &self.agent_id, &self.hostname)
    }

    /// Compare the service DACL with the expected one; report and re-assert on drift.
    pub fn check_service(&self) -> Option<AgentEvent> {
        if self.legacy {
            return None;
        }
        let actual = match winacl::get_service_dacl(SERVICE_NAME) {
            Ok(s) => s,
            Err(e) => {
                warn!(error = %e, "could not read the service DACL");
                return None;
            }
        };
        if policy::dacl_matches(&actual, SERVICE_DACL_SDDL, false) {
            debug!("service DACL as expected");
            return None;
        }
        let reasserted = match winacl::set_service_dacl(SERVICE_NAME, SERVICE_DACL_SDDL) {
            Ok(()) => true,
            Err(e) => {
                warn!(error = %e, "could not re-apply the service DACL");
                false
            }
        };
        warn!(reasserted, "service DACL differs from the expected one");
        Some(self.event(policy::service_acl_finding(&actual, reasserted)))
    }

    /// Service key (values, DACL, owner) and the agent configuration key (DACL).
    pub fn check_keys(&self) -> Vec<AgentEvent> {
        let mut events = Vec::new();
        if let Some(change) = self.check_service_key() {
            events.push(change);
        }
        if let Some(change) = self.check_agent_key() {
            events.push(change);
        }
        events
    }

    fn check_service_key(&self) -> Option<AgentEvent> {
        let now = match snapshot(SERVICE_KEY_PATH, true) {
            Ok(s) => s,
            Err(e) => {
                warn!(error = %e, "could not read the service registry key");
                return None;
            }
        };
        let mut baseline = self.service_key.lock().ok()?;
        let dacl_drift = !self.legacy && !policy::dacl_matches(&now.sddl, REGISTRY_KEY_SDDL, true);
        let (owner_changed, values) = match baseline.as_ref() {
            Some(before) => (
                before.owner != now.owner,
                policy::changed_values(&before.values, &now.values),
            ),
            None => (false, Vec::new()),
        };
        let change = RegistryChange {
            key: SERVICE_KEY_PATH.into(),
            dacl_drift,
            actual_sddl: dacl_drift.then(|| now.sddl.clone()),
            owner_changed,
            owner: owner_changed.then(|| now.owner.clone()).flatten(),
            changed_values: values,
        };
        if change.is_empty() {
            *baseline = Some(now);
            return None;
        }
        let reasserted = dacl_drift
            && match winacl::set_machine_key_dacl(SERVICE_KEY_PATH, REGISTRY_KEY_SDDL) {
                Ok(()) => true,
                Err(e) => {
                    warn!(error = %e, "could not re-apply the service key DACL");
                    false
                }
            };
        warn!(
            dacl_drift,
            owner_changed,
            values = ?change.changed_values,
            reasserted,
            "service registry key changed"
        );
        // Our own re-application is not a change: take the baseline after it.
        *baseline = snapshot(SERVICE_KEY_PATH, true).ok().or(Some(now));
        Some(self.event(policy::registry_finding(&change, reasserted)))
    }

    fn check_agent_key(&self) -> Option<AgentEvent> {
        if self.legacy {
            return None;
        }
        let now = match snapshot(AGENT_KEY_PATH, false) {
            Ok(s) => s,
            Err(e) => {
                debug!(error = %e, "agent configuration key not readable");
                return None;
            }
        };
        if policy::dacl_matches(&now.sddl, REGISTRY_KEY_SDDL, true) {
            return None;
        }
        let reasserted = match winacl::set_machine_key_dacl(AGENT_KEY_PATH, REGISTRY_KEY_SDDL) {
            Ok(()) => true,
            Err(e) => {
                warn!(error = %e, "could not re-apply the agent key DACL");
                false
            }
        };
        warn!(
            reasserted,
            "agent configuration key DACL differs from the expected one"
        );
        let change = RegistryChange {
            key: format!("HKLM\\{AGENT_KEY_PATH}"),
            dacl_drift: true,
            actual_sddl: Some(now.sddl),
            ..Default::default()
        };
        Some(self.event(policy::registry_finding(&change, reasserted)))
    }
}

/// Block in `RegNotifyChangeKeyValue` on `subkey` and call `on_change` after
/// every notification, until the key cannot be watched any more.
fn spawn_watcher(
    name: &'static str,
    subkey: &'static str,
    filter: u32,
    on_change: impl Fn() + Send + 'static,
) {
    let spawned = std::thread::Builder::new()
        .name(name.into())
        .spawn(move || {
            let key = match open_key(subkey, KEY_NOTIFY) {
                Ok(k) => k,
                Err(e) => {
                    info!(watcher = name, error = %e, "registry watch not started");
                    return;
                }
            };
            // SAFETY: auto-reset, initially unsignalled, unnamed event.
            let event = unsafe { CreateEventW(std::ptr::null(), 0, 0, std::ptr::null()) };
            if event.is_null() {
                warn!(watcher = name, "could not create the notification event");
                return;
            }
            loop {
                // SAFETY: `key` and `event` are valid for the call; async mode.
                let status = unsafe { RegNotifyChangeKeyValue(key.0, 0, filter, event, 1) };
                if status != 0 {
                    warn!(watcher = name, status, "registry watch ended");
                    break;
                }
                // SAFETY: valid event handle.
                unsafe { WaitForSingleObject(event, INFINITE) };
                std::thread::sleep(SETTLE);
                on_change();
            }
            // SAFETY: closing the handle created above.
            unsafe { CloseHandle(event) };
        });
    if let Err(e) = spawned {
        warn!(watcher = name, error = %e, "could not start the registry watcher");
    }
}

/// Start-up check, watchers and the periodic recheck. Runs for the life of the
/// service; findings go through the normal event pipeline.
pub async fn run(tx: tokio::sync::mpsc::Sender<AgentEvent>, agent_id: String, hostname: String) {
    if !winacl::is_local_system() {
        info!("service ACL guard not started: not running as LocalSystem");
        return;
    }
    let legacy = legacy_mode();
    if legacy {
        info!("legacy ACL mode (TRAPD_LEGACY_ACLS): DACL drift is not checked");
    }
    let guard = Arc::new(Guard::new(agent_id, hostname, legacy));

    let first = {
        let guard = Arc::clone(&guard);
        tokio::task::spawn_blocking(move || {
            let mut events: Vec<AgentEvent> = guard.check_service().into_iter().collect();
            events.extend(guard.check_keys());
            events
        })
        .await
        .unwrap_or_default()
    };
    for event in first {
        if tx.send(event).await.is_err() {
            return;
        }
    }

    // Registry key (values, DACL, owner) and the SCM's `Security` subkey.
    let (g, t) = (Arc::clone(&guard), tx.clone());
    spawn_watcher(
        "trapd-regwatch-svc",
        SERVICE_KEY_PATH,
        REG_NOTIFY_CHANGE_LAST_SET | REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_SECURITY,
        move || {
            for event in g.check_keys() {
                let _ = t.blocking_send(event);
            }
        },
    );
    let (g, t) = (Arc::clone(&guard), tx.clone());
    spawn_watcher(
        "trapd-regwatch-sd",
        SERVICE_SECURITY_KEY_PATH,
        REG_NOTIFY_CHANGE_LAST_SET,
        move || {
            if let Some(event) = g.check_service() {
                let _ = t.blocking_send(event);
            }
        },
    );

    let mut tick = tokio::time::interval(RECHECK_INTERVAL);
    tick.tick().await; // the first tick is immediate; the start-up check ran above
    loop {
        tick.tick().await;
        let guard = Arc::clone(&guard);
        let events = tokio::task::spawn_blocking(move || {
            let mut events: Vec<AgentEvent> = guard.check_service().into_iter().collect();
            events.extend(guard.check_keys());
            events
        })
        .await
        .unwrap_or_default();
        for event in events {
            if tx.send(event).await.is_err() {
                return;
            }
        }
    }
}

// ── One-shot verbs for the MSI (deferred custom actions, run as SYSTEM) ───────

fn report(label: &str, result: Result<()>) -> bool {
    match result {
        Ok(()) => {
            info!(target = label, "ACL applied");
            true
        }
        Err(e) => {
            warn!(target = label, error = %e, "ACL not applied");
            false
        }
    }
}

/// `trapd-agent acl apply`: the hardened service and registry descriptors.
/// Directories are applied by the MSI itself. Fails if any step failed so a
/// broken install is not reported as hardened.
pub fn apply_hardened() -> Result<()> {
    let ok = [
        report(
            "service",
            winacl::set_service_dacl(SERVICE_NAME, SERVICE_DACL_SDDL),
        ),
        report(
            "service key",
            winacl::set_machine_key_dacl(SERVICE_KEY_PATH, REGISTRY_KEY_SDDL),
        ),
        report(
            "agent key",
            winacl::set_machine_key_dacl(AGENT_KEY_PATH, REGISTRY_KEY_SDDL),
        ),
    ];
    if ok.iter().all(|x| *x) {
        Ok(())
    } else {
        bail!("could not apply the hardened ACLs (see agent.log)")
    }
}

/// `trapd-agent acl legacy`: put back what earlier releases installed
/// (rollback of `TRAPD_LEGACY_ACLS=1`): service, both keys, all directories.
pub fn apply_legacy() -> Result<()> {
    use crate::paths;
    let config = paths::config_dir();
    let data = config.parent().map(std::path::Path::to_path_buf);
    let install = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(std::path::Path::to_path_buf));
    let mut ok = vec![
        report(
            "service",
            winacl::set_service_dacl(SERVICE_NAME, SERVICE_DACL_LEGACY_SDDL),
        ),
        report(
            "service key",
            winacl::set_machine_key_dacl(SERVICE_KEY_PATH, REGISTRY_KEY_LEGACY_SDDL),
        ),
        report(
            "agent key",
            winacl::set_machine_key_dacl(AGENT_KEY_PATH, REGISTRY_KEY_LEGACY_SDDL),
        ),
    ];
    let dirs = [
        data,
        Some(config.to_path_buf()),
        Some(paths::state_dir().to_path_buf()),
        Some(paths::log_dir().to_path_buf()),
    ];
    for dir in dirs.into_iter().flatten() {
        ok.push(report(
            "data directory",
            winacl::set_dacl(&dir, policy::DATA_DIR_LEGACY_SDDL),
        ));
    }
    if let Some(dir) = install {
        ok.push(report(
            "install directory",
            winacl::set_dacl(&dir, policy::INSTALL_DIR_LEGACY_SDDL),
        ));
    }
    if ok.iter().all(|x| *x) {
        Ok(())
    } else {
        bail!("could not apply the legacy ACLs (see agent.log)")
    }
}
