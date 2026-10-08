//! Loaded kernel drivers — the Windows counterpart of the Linux module list.
//!
//! Drivers are the Windows rootkit and BYOVD ("bring your own vulnerable
//! driver") surface, so the backend gets the same diffable list it gets for
//! kernel modules on Linux.
//!
//! The `signature` field is `signed` only when the file's embedded Authenticode
//! signature verifies. Most Microsoft drivers are catalog-signed, which this
//! check does not follow, so a driver that does not verify is reported as
//! `unknown` — never as `unsigned`, which would be a claim the check cannot make.

// Compiled everywhere so the path logic is tested on every CI platform.
#![cfg_attr(not(windows), allow(dead_code))]

use std::path::PathBuf;

/// Convert the NT-style path `GetDeviceDriverFileName` returns into a DOS path.
///
/// Forms seen in practice: `\SystemRoot\System32\drivers\x.sys`,
/// `\??\C:\Windows\System32\drivers\x.sys` and `\Windows\System32\...` (rooted
/// at the system drive). Anything else is refused rather than guessed.
pub fn dos_path(raw: &str, system_root: &str, system_drive: &str) -> Option<PathBuf> {
    let raw = raw.trim();
    let lower = raw.to_ascii_lowercase();
    if let Some(rest) = lower.strip_prefix("\\systemroot\\") {
        // Keep the original casing of the remainder.
        let rest = &raw[raw.len() - rest.len()..];
        return Some(PathBuf::from(format!(
            "{}\\{}",
            system_root.trim_end_matches('\\'),
            rest
        )));
    }
    if let Some(rest) = raw.strip_prefix("\\??\\") {
        let b = rest.as_bytes();
        if b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && b[2] == b'\\' {
            return Some(PathBuf::from(rest));
        }
        return None;
    }
    if raw.starts_with('\\') && !raw.starts_with("\\\\") {
        return Some(PathBuf::from(format!(
            "{}{}",
            system_drive.trim_end_matches('\\'),
            raw
        )));
    }
    if raw.len() >= 3 && raw.as_bytes()[1] == b':' {
        return Some(PathBuf::from(raw));
    }
    None
}

/// Loaded drivers of this host.
#[cfg(windows)]
pub fn loaded() -> Vec<super::KernelModule> {
    use windows_sys::Win32::System::ProcessStatus::{EnumDeviceDrivers, GetDeviceDriverFileNameW};

    let system_root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into());
    let system_drive = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".into());

    let mut bases = vec![std::ptr::null_mut::<core::ffi::c_void>(); 2048];
    let mut needed = 0u32;
    // SAFETY: `bases` has `cb` bytes of capacity; the API writes at most that
    // many and reports the full requirement in `needed`.
    let ok = unsafe {
        EnumDeviceDrivers(
            bases.as_mut_ptr(),
            (bases.len() * std::mem::size_of::<*mut core::ffi::c_void>()) as u32,
            &mut needed,
        )
    };
    if ok == 0 {
        tracing::warn!("driver inventory unavailable: EnumDeviceDrivers failed");
        return Vec::new();
    }
    let count = (needed as usize / std::mem::size_of::<*mut core::ffi::c_void>()).min(bases.len());

    let mut modules = Vec::with_capacity(count);
    for &base in &bases[..count] {
        let mut name = [0u16; 1024];
        // SAFETY: `name` is 1024 writable UTF-16 units.
        let len = unsafe { GetDeviceDriverFileNameW(base, name.as_mut_ptr(), name.len() as u32) };
        if len == 0 {
            continue;
        }
        let raw = String::from_utf16_lossy(&name[..len as usize]);
        let path = dos_path(&raw, &system_root, &system_drive);
        let file_name = raw.rsplit('\\').next().unwrap_or(&raw).to_string();
        let (size, signature) = match &path {
            Some(p) => (
                std::fs::metadata(p).map(|m| m.len()).unwrap_or(0),
                if embedded_signature_valid(p) {
                    "signed"
                } else {
                    "unknown"
                },
            ),
            None => (0, "unknown"),
        };
        modules.push(super::KernelModule {
            name: file_name,
            size,
            state: "Live".into(),
            signature: signature.into(),
        });
    }
    modules.sort_by(|a, b| a.name.cmp(&b.name));
    modules
}

/// Verify the embedded Authenticode signature without UI or network access.
#[cfg(windows)]
fn embedded_signature_valid(path: &std::path::Path) -> bool {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Security::WinTrust::{
        WinVerifyTrust, WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_DATA_0,
        WINTRUST_FILE_INFO, WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_FILE, WTD_REVOKE_NONE,
        WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE,
    };

    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    // SAFETY: the structures and the NUL-terminated path outlive the synchronous
    // trust call, and the verification state is closed on every path.
    unsafe {
        let mut file = WINTRUST_FILE_INFO {
            cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
            pcwszFilePath: wide.as_ptr(),
            ..Default::default()
        };
        let mut data = WINTRUST_DATA {
            cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
            dwUIChoice: WTD_UI_NONE,
            fdwRevocationChecks: WTD_REVOKE_NONE,
            dwUnionChoice: WTD_CHOICE_FILE,
            Anonymous: WINTRUST_DATA_0 { pFile: &mut file },
            dwStateAction: WTD_STATEACTION_VERIFY,
            dwProvFlags: WTD_CACHE_ONLY_URL_RETRIEVAL,
            ..Default::default()
        };
        let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        let rc = WinVerifyTrust(
            windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE,
            &mut action,
            (&mut data as *mut WINTRUST_DATA).cast(),
        );
        data.dwStateAction = WTD_STATEACTION_CLOSE;
        let _ = WinVerifyTrust(
            windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE,
            &mut action,
            (&mut data as *mut WINTRUST_DATA).cast(),
        );
        rc == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nt_driver_paths_become_dos_paths() {
        let p = |raw| dos_path(raw, "C:\\Windows", "C:");
        assert_eq!(
            p("\\SystemRoot\\System32\\drivers\\Wdf01000.sys"),
            Some(PathBuf::from(
                "C:\\Windows\\System32\\drivers\\Wdf01000.sys"
            ))
        );
        assert_eq!(
            p("\\??\\C:\\Windows\\System32\\drivers\\x.sys"),
            Some(PathBuf::from("C:\\Windows\\System32\\drivers\\x.sys"))
        );
        assert_eq!(
            p("\\WINDOWS\\system32\\ntoskrnl.exe"),
            Some(PathBuf::from("C:\\WINDOWS\\system32\\ntoskrnl.exe"))
        );
        assert_eq!(
            p("D:\\drivers\\y.sys"),
            Some(PathBuf::from("D:\\drivers\\y.sys"))
        );
    }

    #[test]
    fn unrecognised_or_remote_forms_are_refused() {
        let p = |raw| dos_path(raw, "C:\\Windows", "C:");
        assert_eq!(p("\\\\server\\share\\x.sys"), None);
        assert_eq!(p("\\??\\GLOBALROOT\\Device\\x"), None);
        assert_eq!(p("x.sys"), None);
        assert_eq!(p(""), None);
    }
}

#[cfg(all(test, windows))]
mod native_tests {
    #[test]
    fn the_loaded_driver_list_contains_the_kernel() {
        let drivers = super::loaded();
        assert!(!drivers.is_empty(), "EnumDeviceDrivers returned nothing");
        assert!(
            drivers
                .iter()
                .any(|d| d.name.eq_ignore_ascii_case("ntoskrnl.exe")),
            "ntoskrnl.exe must be loaded: {:?}",
            drivers.iter().map(|d| &d.name).take(10).collect::<Vec<_>>()
        );
        assert!(drivers
            .iter()
            .all(|d| d.signature == "signed" || d.signature == "unknown"));
    }
}
