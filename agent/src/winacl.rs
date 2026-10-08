//! Windows file/directory DACL helpers (the `chmod` / `chattr` analogue).
//!
//! Used to lock down quarantined payloads and the agent's state directory to
//! `SYSTEM` + `Administrators`, and to capture / re-apply a file's original DACL
//! so a quarantine restore returns the file exactly as it was.

use std::os::windows::ffi::OsStrExt;
use std::path::Path;

use anyhow::{anyhow, bail, Result};
use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorW,
    ConvertStringSecurityDescriptorToSecurityDescriptorW, GetNamedSecurityInfoW,
    SetNamedSecurityInfoW, SDDL_REVISION_1, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    GetSecurityDescriptorDacl, ACL, DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR, UNPROTECTED_DACL_SECURITY_INFORMATION,
};

/// Directory readable and writable only by `SYSTEM` and `Administrators`, with
/// inheritance cut so a permissive parent (`ProgramData`) cannot leak in.
pub const PRIVATE_DIR_SDDL: &str = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";
/// The same for a single file.
pub const PRIVATE_FILE_SDDL: &str = "D:P(A;;FA;;;SY)(A;;FA;;;BA)";

fn wide(path: &Path) -> Vec<u16> {
    path.as_os_str().encode_wide().chain(Some(0)).collect()
}

fn wide_str(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

/// Whether an SDDL string describes a protected DACL (inheritance cut).
pub fn sddl_is_protected(sddl: &str) -> bool {
    sddl.trim_start().starts_with("D:P") || sddl.contains("D:PAI") || sddl.contains("D:PAR")
}

/// Whether this process runs with an elevated (administrator / SYSTEM) token.
/// Used to avoid locking a directory down to `SYSTEM` + `Administrators` from a
/// non-elevated console run, where that would lock the caller out of it.
pub fn is_elevated() -> bool {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::Security::{
        GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    // SAFETY: the token handle is closed on every path; the out-buffer is a
    // TOKEN_ELEVATION and its byte length is passed.
    unsafe {
        let mut token = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut returned = 0u32;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            (&mut elevation as *mut TOKEN_ELEVATION).cast(),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        );
        CloseHandle(token);
        ok != 0 && elevation.TokenIsElevated != 0
    }
}

/// Replace the DACL of `path` with the one described by `sddl`.
pub fn set_dacl(path: &Path, sddl: &str) -> Result<()> {
    let wpath = wide(path);
    let wsddl = wide_str(sddl);
    let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: NUL-terminated inputs; `sd` is a valid out-pointer freed below.
    unsafe {
        if ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wsddl.as_ptr(),
            SDDL_REVISION_1,
            &mut sd,
            std::ptr::null_mut(),
        ) == 0
        {
            bail!(
                "invalid security descriptor: {}",
                std::io::Error::last_os_error()
            );
        }
        let mut present = 0;
        let mut defaulted = 0;
        let mut dacl: *mut ACL = std::ptr::null_mut();
        let got = GetSecurityDescriptorDacl(sd, &mut present, &mut dacl, &mut defaulted);
        let result = if got == 0 || present == 0 {
            Err(anyhow!("security descriptor carries no DACL"))
        } else {
            let protection = if sddl_is_protected(sddl) {
                PROTECTED_DACL_SECURITY_INFORMATION
            } else {
                UNPROTECTED_DACL_SECURITY_INFORMATION
            };
            let status = SetNamedSecurityInfoW(
                wpath.as_ptr() as *mut u16,
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | protection,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                dacl,
                std::ptr::null_mut(),
            );
            if status == 0 {
                Ok(())
            } else {
                Err(anyhow!(
                    "SetNamedSecurityInfo({}) failed: {}",
                    path.display(),
                    std::io::Error::from_raw_os_error(status as i32)
                ))
            }
        };
        LocalFree(sd);
        result
    }
}

/// The DACL of `path` as an SDDL string.
pub fn get_dacl(path: &Path) -> Result<String> {
    let wpath = wide(path);
    let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    let mut dacl: *mut ACL = std::ptr::null_mut();
    // SAFETY: valid out-pointers; the descriptor is freed on every path.
    unsafe {
        let status = GetNamedSecurityInfoW(
            wpath.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut dacl,
            std::ptr::null_mut(),
            &mut sd,
        );
        if status != 0 {
            bail!(
                "GetNamedSecurityInfo({}) failed: {}",
                path.display(),
                std::io::Error::from_raw_os_error(status as i32)
            );
        }
        let mut text: *mut u16 = std::ptr::null_mut();
        let mut len = 0u32;
        let ok = ConvertSecurityDescriptorToStringSecurityDescriptorW(
            sd,
            SDDL_REVISION_1,
            DACL_SECURITY_INFORMATION,
            &mut text,
            &mut len,
        );
        let result = if ok == 0 || text.is_null() {
            Err(anyhow!(
                "cannot render DACL: {}",
                std::io::Error::last_os_error()
            ))
        } else {
            let slice = std::slice::from_raw_parts(text, len as usize);
            let s = String::from_utf16_lossy(slice);
            Ok(s.trim_end_matches('\0').to_string())
        };
        if !text.is_null() {
            LocalFree(text.cast());
        }
        LocalFree(sd);
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protected_dacls_are_recognised() {
        assert!(sddl_is_protected(PRIVATE_DIR_SDDL));
        assert!(sddl_is_protected(PRIVATE_FILE_SDDL));
        assert!(sddl_is_protected("D:PAI(A;;FA;;;SY)"));
        assert!(!sddl_is_protected("D:AI(A;ID;FA;;;SY)"));
    }
}

#[cfg(test)]
mod native_tests {
    use super::*;

    fn temp_file(tag: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("trapd-acl-{tag}-{}", std::process::id()));
        std::fs::write(&p, b"payload").unwrap();
        p
    }

    #[test]
    fn locking_a_file_down_and_restoring_its_dacl_round_trips() {
        let path = temp_file("roundtrip");
        let original = get_dacl(&path).expect("read the original DACL");

        set_dacl(&path, PRIVATE_FILE_SDDL).expect("lock down");
        let locked = get_dacl(&path).expect("read the locked DACL");
        assert!(
            locked.starts_with("D:P"),
            "inheritance must be cut: {locked}"
        );
        assert!(
            locked.contains(";;;SY)") && locked.contains(";;;BA)"),
            "{locked}"
        );
        assert!(!locked.contains(";;;WD)"), "no Everyone ACE: {locked}");

        set_dacl(&path, &original).expect("restore");
        let restored = get_dacl(&path).unwrap();
        // Inherited ACEs are recomputed from the parent, so compare the access
        // entries as a set (order and the AI/AR header flags may differ).
        let aces = |sddl: &str| -> std::collections::BTreeSet<String> {
            sddl.split('(')
                .skip(1)
                .map(|a| a.trim_end_matches(')').to_string())
                .collect()
        };
        assert_eq!(aces(&restored), aces(&original), "{restored} vs {original}");
        assert!(
            !restored.starts_with("D:P"),
            "inheritance must be back on: {restored}"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn an_invalid_descriptor_is_rejected_cleanly() {
        let path = temp_file("invalid");
        assert!(set_dacl(&path, "not an sddl").is_err());
        let _ = std::fs::remove_file(&path);
    }
}
