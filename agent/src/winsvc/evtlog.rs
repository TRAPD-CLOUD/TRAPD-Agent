//! Windows Application event log entries for service lifecycle events.
//!
//! `agent.log` is the detailed channel; administrators and SIEM forwarders
//! also expect service start, stop and fatal errors in the Event Viewer under
//! the source `TRAPD Agent`.
//!
//! Source registration is done by the service itself at startup (it runs as
//! LocalSystem) rather than by the MSI, so the installer is untouched and a
//! failure here can never block install, upgrade or removal. The message file
//! is `EventCreate.exe`, whose message table renders insertion string 1 for
//! event ids 1..=1000; that gives readable entries without shipping a message
//! DLL. The Application log is readable by ordinary users, so messages carry a
//! short summary only and point to `agent.log` for detail.

use windows_sys::Win32::System::EventLog::{
    DeregisterEventSource, RegisterEventSourceW, ReportEventW, EVENTLOG_ERROR_TYPE,
    EVENTLOG_INFORMATION_TYPE,
};
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegCreateKeyExW, RegSetValueExW, HKEY, HKEY_LOCAL_MACHINE, KEY_WOW64_64KEY,
    KEY_WRITE, REG_DWORD, REG_EXPAND_SZ,
};

const SOURCE: &str = "TRAPD Agent";
const SOURCE_KEY: &str = "SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application\\TRAPD Agent";
const MESSAGE_FILE: &str = "%SystemRoot%\\System32\\EventCreate.exe";
/// EventLogType bits: error | warning | information.
const TYPES_SUPPORTED: u32 = 7;
/// Longest summary written to the log.
const MAX_MESSAGE_CHARS: usize = 400;

#[derive(Clone, Copy)]
pub enum Event {
    Started,
    Stopped,
    Fatal,
}

impl Event {
    fn id(self) -> u32 {
        match self {
            Event::Started => 1,
            Event::Stopped => 2,
            Event::Fatal => 3,
        }
    }
    fn kind(self) -> u16 {
        match self {
            Event::Fatal => EVENTLOG_ERROR_TYPE,
            _ => EVENTLOG_INFORMATION_TYPE,
        }
    }
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

/// Single-line, bounded message text (control characters would corrupt the
/// Event Viewer rendering).
pub fn sanitize(msg: &str) -> String {
    msg.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(MAX_MESSAGE_CHARS)
        .collect()
}

/// Create the event source registration if it is missing. Best effort.
pub fn register_source() -> Result<(), u32> {
    let key = wide(SOURCE_KEY);
    let mut hkey: HKEY = std::ptr::null_mut();
    // SAFETY: NUL-terminated key name; `hkey` is a valid out pointer.
    let status = unsafe {
        RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            key.as_ptr(),
            0,
            std::ptr::null(),
            0,
            KEY_WRITE | KEY_WOW64_64KEY,
            std::ptr::null(),
            &mut hkey,
            std::ptr::null_mut(),
        )
    };
    if status != 0 {
        return Err(status);
    }
    let file = wide(MESSAGE_FILE);
    let types = TYPES_SUPPORTED.to_le_bytes();
    let set = |name: &str, kind: u32, data: &[u8]| {
        let name = wide(name);
        // SAFETY: `hkey` is open for writing; the buffers outlive the call.
        unsafe {
            RegSetValueExW(
                hkey,
                name.as_ptr(),
                0,
                kind,
                data.as_ptr(),
                data.len() as u32,
            )
        }
    };
    let file_bytes: Vec<u8> = file.iter().flat_map(|c| c.to_le_bytes()).collect();
    let mut status = set("EventMessageFile", REG_EXPAND_SZ, &file_bytes);
    if status == 0 {
        status = set("TypesSupported", REG_DWORD, &types);
    }
    // SAFETY: closing the key opened above.
    unsafe { RegCloseKey(hkey) };
    if status == 0 {
        Ok(())
    } else {
        Err(status)
    }
}

/// Write one entry to the Application log. Failures are returned, never
/// panicked on; callers log and continue.
pub fn report(event: Event, message: &str) -> Result<(), u32> {
    let source = wide(SOURCE);
    let text = wide(&sanitize(message));
    // SAFETY: NUL-terminated source name.
    let handle = unsafe { RegisterEventSourceW(std::ptr::null(), source.as_ptr()) };
    if handle.is_null() {
        return Err(unsafe { windows_sys::Win32::Foundation::GetLastError() });
    }
    let strings = [text.as_ptr()];
    // SAFETY: `handle` is a live event source; `strings` holds one valid
    // NUL-terminated string matching the count passed.
    let ok = unsafe {
        ReportEventW(
            handle,
            event.kind(),
            0,
            event.id(),
            std::ptr::null_mut(),
            1,
            0,
            strings.as_ptr(),
            std::ptr::null(),
        )
    };
    let err = if ok == 0 {
        Err(unsafe { windows_sys::Win32::Foundation::GetLastError() })
    } else {
        Ok(())
    };
    // SAFETY: closing the handle opened above.
    unsafe { DeregisterEventSource(handle) };
    err
}

/// Register (idempotent) and write, logging failures instead of surfacing them.
pub fn notify(event: Event, message: &str) {
    if let Err(code) = register_source() {
        tracing::debug!(code, "event source registration failed");
    }
    if let Err(code) = report(event, message) {
        tracing::warn!(code, "could not write Application event log entry");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_strips_control_characters_and_bounds_length() {
        assert_eq!(sanitize("a\r\nb\tc"), "a  b c");
        assert_eq!(
            sanitize(&"x".repeat(5000)).chars().count(),
            MAX_MESSAGE_CHARS
        );
    }
}
