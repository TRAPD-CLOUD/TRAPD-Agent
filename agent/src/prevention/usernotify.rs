//! Tell the signed-in Windows user when a response action changed their device.
//!
//! A Windows service runs in session 0 and cannot show a toast. For each message
//! the service starts this same binary once in the user's session, passing only
//! a fixed message id. There is no long-running helper and no IPC channel, and
//! no process, file or host name ever reaches the toast. A user who starts the
//! helper by hand can only show themselves one of the fixed messages.
#![cfg_attr(not(windows), allow(dead_code))]

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use crate::schema::EventAction;

pub const NOTIFY_FLAG: &str = "--notify-user";

const SAME_MESSAGE_INTERVAL: Duration = Duration::from_secs(30);
const WINDOW: Duration = Duration::from_secs(300);
const MAX_PER_WINDOW: usize = 6;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Message {
    HostIsolated,
    HostReleased,
    ProcessStopped,
    FileQuarantined,
    FileRestored,
}

const ALL: [Message; 5] = [
    Message::HostIsolated,
    Message::HostReleased,
    Message::ProcessStopped,
    Message::FileQuarantined,
    Message::FileRestored,
];

impl Message {
    pub fn id(self) -> &'static str {
        match self {
            Self::HostIsolated => "1",
            Self::HostReleased => "2",
            Self::ProcessStopped => "3",
            Self::FileQuarantined => "4",
            Self::FileRestored => "5",
        }
    }

    pub fn parse(id: &str) -> Option<Self> {
        ALL.into_iter().find(|message| message.id() == id)
    }

    /// Only actions the user can notice and that are confirmed to have happened.
    /// `success` alone is not enough: an alert-only rule reports success without
    /// stopping anything, and an automatic response reports success when any one
    /// of its steps worked. A freeze is left out on purpose: it holds a process
    /// quietly while it is being investigated.
    pub fn for_event(
        action: &EventAction,
        kind: &str,
        success: bool,
        details: &serde_json::Value,
    ) -> Option<Self> {
        if !success {
            return None;
        }
        match kind {
            "process_block" | "network_isolate" | "network_deisolate" | "quarantine"
            | "restore" => {}
            "auto_response" => {
                let step = match action {
                    EventAction::NetworkIsolated => "isolated",
                    EventAction::ProcessBlocked => "killed",
                    EventAction::FileQuarantined => "quarantined",
                    _ => return None,
                };
                if details.get(step).and_then(serde_json::Value::as_bool) != Some(true) {
                    return None;
                }
            }
            _ => return None,
        }
        match action {
            EventAction::NetworkIsolated => Some(Self::HostIsolated),
            EventAction::NetworkDeisolated => Some(Self::HostReleased),
            EventAction::ProcessBlocked => Some(Self::ProcessStopped),
            EventAction::FileQuarantined => Some(Self::FileQuarantined),
            EventAction::FileRestored => Some(Self::FileRestored),
            _ => None,
        }
    }

    /// Fixed text only, so there is nothing to escape.
    pub fn toast_xml(self) -> &'static str {
        match self {
            Self::HostIsolated => concat!(
                "<toast><visual><binding template=\"ToastGeneric\">",
                "<text>Device isolated from the network</text>",
                "<text>Your security team isolated this device. Contact your IT team if you need help.</text>",
                "</binding></visual></toast>"
            ),
            Self::HostReleased => concat!(
                "<toast><visual><binding template=\"ToastGeneric\">",
                "<text>Network access restored</text>",
                "<text>Your security team released this device from isolation.</text>",
                "</binding></visual></toast>"
            ),
            Self::ProcessStopped => concat!(
                "<toast><visual><binding template=\"ToastGeneric\">",
                "<text>Program stopped</text>",
                "<text>Your security team stopped a program on this device.</text>",
                "</binding></visual></toast>"
            ),
            Self::FileQuarantined => concat!(
                "<toast><visual><binding template=\"ToastGeneric\">",
                "<text>File quarantined</text>",
                "<text>Your security team moved a file on this device to quarantine.</text>",
                "</binding></visual></toast>"
            ),
            Self::FileRestored => concat!(
                "<toast><visual><binding template=\"ToastGeneric\">",
                "<text>File restored</text>",
                "<text>Your security team restored a file on this device.</text>",
                "</binding></visual></toast>"
            ),
        }
    }
}

/// Keeps a burst of automatic responses from flooding the user.
#[derive(Default)]
struct RateLimiter {
    last_shown: HashMap<Message, Instant>,
    recent: VecDeque<Instant>,
}

impl RateLimiter {
    fn allow(&mut self, message: Message, now: Instant) -> bool {
        while self
            .recent
            .front()
            .is_some_and(|shown| now.duration_since(*shown) >= WINDOW)
        {
            self.recent.pop_front();
        }
        let too_soon = self
            .last_shown
            .get(&message)
            .is_some_and(|shown| now.duration_since(*shown) < SAME_MESSAGE_INTERVAL);
        if too_soon || self.recent.len() >= MAX_PER_WINDOW {
            return false;
        }
        self.last_shown.insert(message, now);
        self.recent.push_back(now);
        true
    }
}

#[cfg(windows)]
pub use windows_impl::{notify, run_helper};

#[cfg(windows)]
mod windows_impl {
    use super::*;
    use anyhow::{bail, Context, Result};
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;
    use std::sync::{LazyLock, Mutex};
    use tracing::debug;
    use windows::core::HSTRING;
    use windows::Data::Xml::Dom::XmlDocument;
    use windows::UI::Notifications::{ToastNotification, ToastNotificationManager};
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::System::Environment::{
        CreateEnvironmentBlock, DestroyEnvironmentBlock,
    };
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegCreateKeyExW, RegSetValueExW, HKEY, HKEY_CURRENT_USER, KEY_SET_VALUE,
        REG_SZ,
    };
    use windows_sys::Win32::System::RemoteDesktop::{
        WTSActive, WTSEnumerateSessionsW, WTSFreeMemory, WTSQueryUserToken,
        WTS_CURRENT_SERVER_HANDLE, WTS_SESSION_INFOW,
    };
    use windows_sys::Win32::System::Threading::{
        CreateProcessAsUserW, CREATE_NO_WINDOW, CREATE_UNICODE_ENVIRONMENT, PROCESS_INFORMATION,
        STARTUPINFOW,
    };

    const APP_ID: &str = "TRAPD.Agent";

    static LIMITER: LazyLock<Mutex<RateLimiter>> = LazyLock::new(Mutex::default);

    fn wide(text: &std::ffi::OsStr) -> Vec<u16> {
        text.encode_wide().chain(Some(0)).collect()
    }

    /// Never blocks and never fails the response action it reports on.
    pub fn notify(action: &EventAction, kind: &str, success: bool, details: &serde_json::Value) {
        let Some(message) = Message::for_event(action, kind, success, details) else {
            return;
        };
        let allowed = LIMITER
            .lock()
            .map(|mut limiter| limiter.allow(message, Instant::now()))
            .unwrap_or(false);
        if allowed {
            std::thread::spawn(move || {
                if let Err(error) = start_in_active_sessions(message) {
                    debug!(error = %format!("{error:#}"), "user notification not shown");
                }
            });
        }
    }

    fn start_in_active_sessions(message: Message) -> Result<()> {
        let exe = std::env::current_exe().context("locate agent binary")?;
        let directory = exe.parent().context("agent binary has no directory")?;
        let mut sessions: *mut WTS_SESSION_INFOW = std::ptr::null_mut();
        let mut count = 0u32;
        // SAFETY: out-pointers are valid; the list is freed below.
        if unsafe {
            WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &mut sessions, &mut count)
        } == 0
        {
            bail!(
                "WTSEnumerateSessionsW failed: {}",
                std::io::Error::last_os_error()
            );
        }
        // SAFETY: the call returned `count` entries at `sessions`.
        let active: Vec<u32> = unsafe { std::slice::from_raw_parts(sessions, count as usize) }
            .iter()
            .filter(|session| session.State == WTSActive)
            .map(|session| session.SessionId)
            .collect();
        // SAFETY: pointer returned by WTSEnumerateSessionsW and not used again.
        unsafe { WTSFreeMemory(sessions.cast()) };
        for session in active {
            if let Err(error) = start_in_session(session, &exe, directory, message) {
                debug!(session, error = %format!("{error:#}"), "session not notified");
            }
        }
        Ok(())
    }

    fn start_in_session(
        session: u32,
        exe: &Path,
        directory: &Path,
        message: Message,
    ) -> Result<()> {
        let mut token: HANDLE = std::ptr::null_mut();
        // SAFETY: valid out-pointer; requires the LocalSystem service identity.
        if unsafe { WTSQueryUserToken(session, &mut token) } == 0 {
            bail!(
                "WTSQueryUserToken failed: {}",
                std::io::Error::last_os_error()
            );
        }
        let mut environment = std::ptr::null_mut();
        // SAFETY: token is valid; the block is destroyed below.
        if unsafe { CreateEnvironmentBlock(&mut environment, token, 0) } == 0 {
            // SAFETY: token was opened above and is not used again.
            unsafe { CloseHandle(token) };
            bail!(
                "CreateEnvironmentBlock failed: {}",
                std::io::Error::last_os_error()
            );
        }
        let application = wide(exe.as_os_str());
        let current_directory = wide(directory.as_os_str());
        let mut desktop = wide(std::ffi::OsStr::new("winsta0\\default"));
        let mut command_line = wide(std::ffi::OsStr::new(&format!(
            "\"{}\" {NOTIFY_FLAG} {}",
            exe.display(),
            message.id()
        )));
        // SAFETY: zeroed is valid for these plain C structs.
        let mut startup: STARTUPINFOW = unsafe { std::mem::zeroed() };
        startup.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
        startup.lpDesktop = desktop.as_mut_ptr();
        // SAFETY: as above.
        let mut process: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
        // SAFETY: an explicit application path is passed so the command line
        // is never searched; all buffers are NUL-terminated and outlive the call.
        let created = unsafe {
            CreateProcessAsUserW(
                token,
                application.as_ptr(),
                command_line.as_mut_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                0,
                CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW,
                environment,
                current_directory.as_ptr(),
                &startup,
                &mut process,
            )
        };
        let error = std::io::Error::last_os_error();
        // SAFETY: each handle and block is owned here and not used again.
        unsafe {
            DestroyEnvironmentBlock(environment);
            CloseHandle(token);
            if created != 0 {
                CloseHandle(process.hThread);
                CloseHandle(process.hProcess);
            }
        }
        if created == 0 {
            bail!("CreateProcessAsUserW failed: {error}");
        }
        Ok(())
    }

    /// Entry point of the helper, running as the signed-in user.
    pub fn run_helper(id: Option<&str>) -> Result<()> {
        let message = id
            .and_then(Message::parse)
            .context("unknown notification id")?;
        register_app_id()?;
        // SAFETY: first COM call on this thread; never uninitialised because
        // the process exits right after showing the toast.
        unsafe {
            windows::Win32::System::Com::CoInitializeEx(
                None,
                windows::Win32::System::Com::COINIT_MULTITHREADED,
            )
        }
        .ok()
        .context("initialise COM")?;
        let document = XmlDocument::new()?;
        document.LoadXml(&HSTRING::from(message.toast_xml()))?;
        let toast = ToastNotification::CreateToastNotification(&document)?;
        ToastNotificationManager::CreateToastNotifierWithId(&HSTRING::from(APP_ID))?
            .Show(&toast)?;
        Ok(())
    }

    /// Windows attributes the toast through this per-user registration.
    fn register_app_id() -> Result<()> {
        let key_path = wide(std::ffi::OsStr::new(&format!(
            "SOFTWARE\\Classes\\AppUserModelId\\{APP_ID}"
        )));
        let name = wide(std::ffi::OsStr::new("DisplayName"));
        let value = wide(std::ffi::OsStr::new("TRAPD"));
        let mut key: HKEY = std::ptr::null_mut();
        // SAFETY: NUL-terminated strings and valid out-pointer.
        let status = unsafe {
            RegCreateKeyExW(
                HKEY_CURRENT_USER,
                key_path.as_ptr(),
                0,
                std::ptr::null(),
                0,
                KEY_SET_VALUE,
                std::ptr::null(),
                &mut key,
                std::ptr::null_mut(),
            )
        };
        if status != 0 {
            bail!("register notification app id failed: {status}");
        }
        // SAFETY: key opened above; value is a NUL-terminated UTF-16 buffer.
        let status = unsafe {
            let status = RegSetValueExW(
                key,
                name.as_ptr(),
                0,
                REG_SZ,
                value.as_ptr().cast(),
                (value.len() * 2) as u32,
            );
            RegCloseKey(key);
            status
        };
        if status != 0 {
            bail!("register notification display name failed: {status}");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_message_round_trips_through_its_id() {
        for message in ALL {
            assert_eq!(Message::parse(message.id()), Some(message));
        }
    }

    #[test]
    fn anything_but_a_known_id_is_rejected() {
        for id in ["", "0", "6", "1 ", "01", "<toast/>", "HostIsolated"] {
            assert_eq!(Message::parse(id), None, "{id}");
        }
    }

    #[test]
    fn only_successful_visible_actions_notify() {
        let none = serde_json::Value::Null;
        assert_eq!(
            Message::for_event(
                &EventAction::NetworkIsolated,
                "network_isolate",
                true,
                &none
            ),
            Some(Message::HostIsolated)
        );
        assert_eq!(
            Message::for_event(
                &EventAction::NetworkIsolated,
                "network_isolate",
                false,
                &none
            ),
            None
        );
        assert_eq!(
            Message::for_event(&EventAction::ProcessFrozen, "process_block", true, &none),
            None
        );
    }

    #[test]
    fn an_alert_only_rule_never_claims_a_program_was_stopped() {
        let none = serde_json::Value::Null;
        assert_eq!(
            Message::for_event(&EventAction::ProcessBlocked, "process_alert", true, &none),
            None
        );
        assert_eq!(
            Message::for_event(&EventAction::ProcessBlocked, "process_block", true, &none),
            Some(Message::ProcessStopped)
        );
    }

    #[test]
    fn an_automatic_response_only_reports_the_step_that_worked() {
        let details =
            serde_json::json!({ "killed": true, "isolated": false, "quarantined": false });
        assert_eq!(
            Message::for_event(
                &EventAction::NetworkIsolated,
                "auto_response",
                true,
                &details
            ),
            None
        );
        assert_eq!(
            Message::for_event(
                &EventAction::ProcessBlocked,
                "auto_response",
                true,
                &details
            ),
            Some(Message::ProcessStopped)
        );
        assert_eq!(
            Message::for_event(
                &EventAction::FileQuarantined,
                "auto_response",
                true,
                &serde_json::Value::Null
            ),
            None
        );
    }

    #[test]
    fn every_template_has_a_title_and_body_and_nothing_to_escape() {
        for message in ALL {
            let xml = message.toast_xml();
            assert!(xml.starts_with("<toast>") && xml.ends_with("</toast>"));
            assert_eq!(xml.matches("<text>").count(), 2);
            assert_eq!(xml.matches("</text>").count(), 2);
            assert!(!xml.contains('&'));
        }
    }

    #[test]
    fn a_repeated_message_waits_for_its_interval() {
        let mut limiter = RateLimiter::default();
        let start = Instant::now();
        assert!(limiter.allow(Message::ProcessStopped, start));
        assert!(!limiter.allow(Message::ProcessStopped, start + Duration::from_secs(29)));
        assert!(limiter.allow(Message::ProcessStopped, start + SAME_MESSAGE_INTERVAL));
    }

    #[test]
    fn different_messages_share_a_window_limit_that_recovers() {
        let mut limiter = RateLimiter::default();
        let start = Instant::now();
        for index in 0..MAX_PER_WINDOW {
            let at = start + SAME_MESSAGE_INTERVAL * index as u32;
            assert!(limiter.allow(Message::ProcessStopped, at));
        }
        let later = start + SAME_MESSAGE_INTERVAL * MAX_PER_WINDOW as u32;
        assert!(!limiter.allow(Message::FileQuarantined, later));
        assert!(limiter.allow(Message::FileQuarantined, start + WINDOW));
    }
}
