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
    GetSecurityDescriptorDacl, GetSecurityDescriptorOwner, ACL, DACL_SECURITY_INFORMATION,
    OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
    UNPROTECTED_DACL_SECURITY_INFORMATION,
};

/// Directory readable and writable only by `SYSTEM` and `Administrators`, with
/// inheritance cut so a permissive parent (`ProgramData`) cannot leak in.
pub const PRIVATE_DIR_SDDL: &str = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";
/// The same for a single file.
pub const PRIVATE_FILE_SDDL: &str = "D:P(A;;FA;;;SY)(A;;FA;;;BA)";
/// Quarantined objects must lose their original owner's implicit WRITE_DAC.
pub const QUARANTINE_FILE_SDDL: &str = "O:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)";

fn wide(path: &Path) -> Vec<u16> {
    path.as_os_str().encode_wide().chain(Some(0)).collect()
}

fn wide_str(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

/// Whether an SDDL string describes a protected DACL (inheritance cut).
pub fn sddl_is_protected(sddl: &str) -> bool {
    sddl.contains("D:P")
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
    set_security(path, sddl, false)
}

/// Apply an original owner and DACL, or a DACL-only legacy record. Ownership
/// assignment requires SeRestorePrivilege (even administrators cannot normally
/// assign SYSTEM or an arbitrary previous owner). Scope it to this thread.
pub fn set_file_security(path: &Path, sddl: &str) -> Result<()> {
    if sddl.contains("O:") {
        with_restore_privilege(|| set_security(path, sddl, true))
    } else {
        set_dacl(path, sddl)
    }
}

fn set_security(path: &Path, sddl: &str, include_owner: bool) -> Result<()> {
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
        let mut owner = std::ptr::null_mut();
        let got_owner = !include_owner
            || (GetSecurityDescriptorOwner(sd, &mut owner, &mut defaulted) != 0
                && !owner.is_null());
        let result = if got == 0 || present == 0 || !got_owner {
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
                DACL_SECURITY_INFORMATION
                    | protection
                    | if include_owner {
                        OWNER_SECURITY_INFORMATION
                    } else {
                        0
                    },
                owner,
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
    get_security(path, DACL_SECURITY_INFORMATION)
}

/// Capture ownership and DACL together so a restored quarantine preserves both.
pub fn get_file_security(path: &Path) -> Result<String> {
    get_security(path, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION)
}

fn get_security(path: &Path, information: u32) -> Result<String> {
    let wpath = wide(path);
    let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    let mut dacl: *mut ACL = std::ptr::null_mut();
    // SAFETY: valid out-pointers; the descriptor is freed on every path.
    unsafe {
        let status = GetNamedSecurityInfoW(
            wpath.as_ptr(),
            SE_FILE_OBJECT,
            information,
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
            information,
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

/// Execute using a duplicate of the effective token, preserving any existing
/// impersonation and never enabling a privilege on the shared process token.
fn with_restore_privilege<T>(action: impl FnOnce() -> Result<T>) -> Result<T> {
    use windows_sys::Win32::Foundation::{
        CloseHandle, GetLastError, ERROR_NO_TOKEN, ERROR_SUCCESS, HANDLE, LUID,
    };
    use windows_sys::Win32::Security::{
        AdjustTokenPrivileges, DuplicateTokenEx, LookupPrivilegeValueW, SecurityImpersonation,
        TokenImpersonation, LUID_AND_ATTRIBUTES, SE_PRIVILEGE_ENABLED, SE_RESTORE_NAME,
        TOKEN_ADJUST_PRIVILEGES, TOKEN_DUPLICATE, TOKEN_IMPERSONATE, TOKEN_PRIVILEGES, TOKEN_QUERY,
    };
    use windows_sys::Win32::System::Threading::{
        GetCurrentProcess, GetCurrentThread, OpenProcessToken, OpenThreadToken, SetThreadToken,
    };
    struct Token(HANDLE);
    impl Drop for Token {
        fn drop(&mut self) {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
    struct Impersonation {
        previous: HANDLE,
        active: bool,
    }
    impl Drop for Impersonation {
        fn drop(&mut self) {
            // SAFETY: saved token remains alive until after this guard drops.
            if self.active && unsafe { SetThreadToken(std::ptr::null(), self.previous) } == 0 {
                tracing::error!("cannot restore thread impersonation after file security update");
            }
        }
    }
    // SAFETY: all token handles are owned and closed; descriptors and privilege
    // arrays have their declared lengths. This scope contains no awaits.
    unsafe {
        let mut original = std::ptr::null_mut();
        let had_thread_token = OpenThreadToken(
            GetCurrentThread(),
            TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE,
            1,
            &mut original,
        ) != 0;
        if !had_thread_token && GetLastError() != ERROR_NO_TOKEN {
            return Err(std::io::Error::last_os_error().into());
        }
        let original_thread = had_thread_token.then(|| Token(original));
        let process_token = if had_thread_token {
            None
        } else {
            if OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_QUERY | TOKEN_DUPLICATE,
                &mut original,
            ) == 0
            {
                return Err(std::io::Error::last_os_error().into());
            }
            Some(Token(original))
        };
        let source = original_thread.as_ref().or(process_token.as_ref()).unwrap();
        let mut duplicate = std::ptr::null_mut();
        if DuplicateTokenEx(
            source.0,
            TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES | TOKEN_IMPERSONATE,
            std::ptr::null(),
            SecurityImpersonation,
            TokenImpersonation,
            &mut duplicate,
        ) == 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        let duplicate = Token(duplicate);
        let mut luid = LUID {
            LowPart: 0,
            HighPart: 0,
        };
        if LookupPrivilegeValueW(std::ptr::null(), SE_RESTORE_NAME, &mut luid) == 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let privileges = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };
        if AdjustTokenPrivileges(
            duplicate.0,
            0,
            &privileges,
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        ) == 0
            || GetLastError() != ERROR_SUCCESS
        {
            return Err(std::io::Error::last_os_error().into());
        }
        if SetThreadToken(std::ptr::null(), duplicate.0) == 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let mut restore = Impersonation {
            previous: original_thread
                .as_ref()
                .map_or(std::ptr::null_mut(), |t| t.0),
            active: true,
        };
        let result = action();
        if SetThreadToken(std::ptr::null(), restore.previous) == 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        restore.active = false;
        drop(restore);
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
    fn quarantine_security_changes_owner_and_restores_it() {
        let path = temp_file("owner");
        let original = get_file_security(&path).expect("capture owner and DACL");
        set_file_security(&path, "O:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)").expect("transfer ownership");
        let locked = get_file_security(&path).unwrap();
        assert!(locked.starts_with("O:SY"), "{locked}");
        assert!(locked.contains("D:P"), "{locked}");
        set_file_security(&path, &original).expect("restore owner and DACL");
        let restored = get_file_security(&path).unwrap();
        assert_eq!(restored.split("D:").next(), original.split("D:").next());
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn an_invalid_descriptor_is_rejected_cleanly() {
        let path = temp_file("invalid");
        assert!(set_dacl(&path, "not an sddl").is_err());
        let _ = std::fs::remove_file(&path);
    }
}
