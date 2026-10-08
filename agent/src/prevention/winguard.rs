//! Windows processes the agent must never terminate or suspend.
//!
//! Killing the session manager, CSRSS, WININIT, WINLOGON, the service control
//! manager, LSASS or an `svchost` host is not a response, it is an outage: most
//! of them force a bugcheck or a reboot within seconds. The decision is made on
//! the **image path**, not the process name, because a binary called
//! `lsass.exe` that lives anywhere other than `%SystemRoot%\System32` is the
//! classic masquerade and is exactly what a response action should be allowed
//! to kill.
//!
//! Pure string logic, compiled everywhere so it is unit-tested on every CI
//! platform; `winproc.rs` supplies the real image path on Windows.

// Pure logic compiled everywhere so it is tested on every CI platform; only the
// Windows build calls it.
#![cfg_attr(not(windows), allow(dead_code))]

/// Image names (under `%SystemRoot%\System32`) that are never a valid target.
const PROTECTED: [&str; 8] = [
    "smss.exe",
    "csrss.exe",
    "wininit.exe",
    "winlogon.exe",
    "services.exe",
    "lsass.exe",
    "lsm.exe",
    "svchost.exe",
];

/// PIDs that are never valid on Windows: the idle process (0) and `System` (4).
pub fn is_reserved_pid(pid: i32) -> bool {
    pid <= 0 || pid == 4
}

fn normalize(path: &str) -> String {
    let mut p = path.replace('/', "\\").to_ascii_lowercase();
    if let Some(rest) = p.strip_prefix("\\\\?\\") {
        p = rest.to_string();
    }
    p.trim_end_matches('\\').to_string()
}

/// Whether `image_path` is one of the protected system binaries, given the
/// host's `%SystemRoot%`.
pub fn is_protected_image(image_path: &str, system_root: &str) -> bool {
    let image = normalize(image_path);
    let system32 = format!("{}\\system32\\", normalize(system_root));
    image
        .strip_prefix(&system32)
        .is_some_and(|name| PROTECTED.contains(&name))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOT: &str = "C:\\Windows";

    #[test]
    fn real_system_binaries_are_protected_regardless_of_case_and_separators() {
        for p in [
            "C:\\Windows\\System32\\lsass.exe",
            "c:\\windows\\system32\\LSASS.EXE",
            "C:/Windows/System32/csrss.exe",
            "\\\\?\\C:\\Windows\\System32\\svchost.exe",
            "C:\\Windows\\System32\\services.exe",
        ] {
            assert!(is_protected_image(p, ROOT), "{p} must be protected");
        }
    }

    #[test]
    fn a_masquerading_binary_outside_system32_is_not_protected() {
        for p in [
            "C:\\Users\\Public\\lsass.exe",
            "C:\\Windows\\Temp\\svchost.exe",
            "C:\\Windows\\System32\\evil\\lsass.exe",
            "C:\\Windows\\System32.bak\\lsass.exe",
            "D:\\Windows\\System32\\lsass.exe",
        ] {
            assert!(!is_protected_image(p, ROOT), "{p} must be killable");
        }
    }

    #[test]
    fn ordinary_system_tools_remain_valid_targets() {
        assert!(!is_protected_image("C:\\Windows\\System32\\cmd.exe", ROOT));
        assert!(!is_protected_image(
            "C:\\Windows\\System32\\powershell.exe",
            ROOT
        ));
    }

    #[test]
    fn reserved_pids() {
        for pid in [-1, 0, 4] {
            assert!(is_reserved_pid(pid));
        }
        assert!(!is_reserved_pid(1234));
    }
}
