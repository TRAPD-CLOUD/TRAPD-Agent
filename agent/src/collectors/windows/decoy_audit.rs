//! Make a decoy file auditable: resolve its owner SID and put a read-audit
//! SACL on it, so a content read produces Security event 4663 with the
//! accessing process and account (see `detection::windows_decoy`).
//!
//! Setting a SACL needs `SeSecurityPrivilege`, which the LocalSystem service
//! holds but must enable in its token. Everything here is best-effort: a
//! failure logs and leaves the decoy watched by the `ReadDirectoryChangesW` /
//! last-access fallback — it never takes the collector down.
//!
//! The 4663 events only actually fire when the "Audit File System" subcategory
//! (success) is enabled. On managed fleets that is usually a GPO setting; the
//! agent reports the effective detection mode through `telemetry::coverage`
//! rather than forcing the policy (that is operator-owned — the
//! `windows_audit_policy_managed` config switch is reserved for it).

use std::iter::once;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;

use windows_sys::core::{PCWSTR, PWSTR};
use windows_sys::Win32::Foundation::{CloseHandle, LocalFree, ERROR_SUCCESS, HANDLE, LUID};
use windows_sys::Win32::Security::Authorization::{
    BuildTrusteeWithSidW, ConvertSidToStringSidW, ConvertStringSidToSidW, GetNamedSecurityInfoW,
    SetEntriesInAclW, SetNamedSecurityInfoW, EXPLICIT_ACCESS_W, SET_AUDIT_SUCCESS, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    AdjustTokenPrivileges, LookupPrivilegeValueW, ACL, LUID_AND_ATTRIBUTES, PSID,
    SACL_SECURITY_INFORMATION, SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

const OWNER_SECURITY_INFORMATION: u32 = 0x0000_0001;
/// FILE_READ_DATA | FILE_EXECUTE: a content read or an exec of the decoy.
const AUDIT_MASK: u32 = 0x0001 | 0x0020;

fn wide(s: &str) -> Vec<u16> {
    std::ffi::OsStr::new(s)
        .encode_wide()
        .chain(once(0))
        .collect()
}

/// The owner SID of `path` as a string (`S-1-5-21-…`), or `None`.
pub fn owner_sid(path: &Path) -> Option<String> {
    let wpath = wide(&path.to_string_lossy());
    let mut owner: PSID = std::ptr::null_mut();
    let mut sd = std::ptr::null_mut();
    // SAFETY: wpath is NUL-terminated; out-params receive the owner SID and the
    // descriptor we LocalFree below.
    let rc = unsafe {
        GetNamedSecurityInfoW(
            wpath.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut sd,
        )
    };
    if rc != ERROR_SUCCESS || owner.is_null() {
        return None;
    }
    let mut str_ptr: PWSTR = std::ptr::null_mut();
    let out = unsafe {
        if ConvertSidToStringSidW(owner, &mut str_ptr) != 0 && !str_ptr.is_null() {
            let s = pwstr_to_string(str_ptr);
            LocalFree(str_ptr as _);
            Some(s)
        } else {
            None
        }
    };
    unsafe { LocalFree(sd as _) };
    out
}

unsafe fn pwstr_to_string(p: PWSTR) -> String {
    let mut len = 0;
    while *p.add(len) != 0 {
        len += 1;
    }
    String::from_utf16_lossy(std::slice::from_raw_parts(p, len))
}

/// Enable `SeSecurityPrivilege` in the current process token (needed to write
/// a SACL). Idempotent; returns whether the privilege is now held.
fn enable_security_privilege() -> bool {
    let name = wide("SeSecurityPrivilege");
    unsafe {
        let mut token: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &mut token) == 0 {
            return false;
        }
        let mut luid = LUID {
            LowPart: 0,
            HighPart: 0,
        };
        let ok = LookupPrivilegeValueW(std::ptr::null(), name.as_ptr(), &mut luid) != 0;
        let tp = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };
        let adjusted = ok
            && AdjustTokenPrivileges(token, 0, &tp, 0, std::ptr::null_mut(), std::ptr::null_mut())
                != 0
            && windows_sys::Win32::Foundation::GetLastError() == ERROR_SUCCESS;
        CloseHandle(token);
        adjusted
    }
}

/// Put a success-audit ACE for Everyone (read/execute) on `path`'s SACL so a
/// read raises 4663. Returns whether the SACL was set.
pub fn set_read_audit_sacl(path: &Path) -> bool {
    if !enable_security_privilege() {
        tracing::warn!("could not enable SeSecurityPrivilege; decoy read auditing unavailable");
        return false;
    }
    let everyone = wide("S-1-1-0");
    unsafe {
        let mut sid: PSID = std::ptr::null_mut();
        if ConvertStringSidToSidW(everyone.as_ptr(), &mut sid) == 0 || sid.is_null() {
            return false;
        }
        // Retrieve existing audit policy; failing to read it must never replace it.
        let mut old: *mut ACL = std::ptr::null_mut();
        let mut descriptor = std::ptr::null_mut();
        let read = GetNamedSecurityInfoW(
            wide(&path.to_string_lossy()).as_ptr(),
            SE_FILE_OBJECT,
            SACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut old,
            &mut descriptor,
        );
        let mut entry: EXPLICIT_ACCESS_W = std::mem::zeroed();
        entry.grfAccessPermissions = AUDIT_MASK;
        entry.grfAccessMode = SET_AUDIT_SUCCESS;
        BuildTrusteeWithSidW(&mut entry.Trustee, sid);
        let mut merged = std::ptr::null_mut();
        let merged_ok =
            read == ERROR_SUCCESS && SetEntriesInAclW(1, &entry, old, &mut merged) == ERROR_SUCCESS;
        let result = merged_ok
            && SetNamedSecurityInfoW(
                wide(&path.to_string_lossy()).as_ptr() as PCWSTR as *mut _,
                SE_FILE_OBJECT,
                SACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null(),
                merged,
            ) == ERROR_SUCCESS;
        if !merged.is_null() {
            LocalFree(merged as _);
        }
        if !descriptor.is_null() {
            LocalFree(descriptor as _);
        }
        LocalFree(sid as _);
        if !result {
            tracing::warn!(path = %path.display(), "could not set decoy read-audit SACL");
        }
        result
    }
}

/// Query effective machine policy without changing operator-owned audit settings.
pub fn file_audit_enabled() -> Option<bool> {
    use windows_sys::Win32::Security::Authentication::Identity::{
        AuditFree, AuditQuerySystemPolicy,
    };
    let guid = windows_sys::core::GUID::from_u128(0x0cce921d_69ae_11d9_bed3_505054503030);
    unsafe {
        let mut policy = std::ptr::null_mut();
        if !AuditQuerySystemPolicy(&guid, 1, &mut policy) || policy.is_null() {
            return None;
        }
        let enabled = (*policy).AuditingInformation & 1 != 0;
        AuditFree(policy as _);
        Some(enabled)
    }
}

#[cfg(test)]
mod native_tests {
    use super::*;

    /// Elevated native test: an unrelated audit ACE survives repeated deployment.
    #[test]
    #[ignore = "requires native Windows SeSecurityPrivilege"]
    fn native_audit_sacl_preserves_existing_ace() {
        use windows_sys::Win32::Security::{GetAce, ACE_HEADER};
        let path =
            std::env::temp_dir().join(format!("trapd-audit-test-{}.txt", uuid::Uuid::new_v4()));
        std::fs::write(&path, b"test bait").unwrap();
        assert!(
            enable_security_privilege(),
            "run native audit test elevated"
        );
        unsafe {
            let mut users: PSID = std::ptr::null_mut();
            assert_ne!(
                ConvertStringSidToSidW(wide("S-1-5-32-545").as_ptr(), &mut users),
                0
            );
            let mut ace: EXPLICIT_ACCESS_W = std::mem::zeroed();
            ace.grfAccessPermissions = 0x0001_0000; // unrelated delete-audit policy
            ace.grfAccessMode = SET_AUDIT_SUCCESS;
            BuildTrusteeWithSidW(&mut ace.Trustee, users);
            let mut original = std::ptr::null_mut();
            assert_eq!(
                SetEntriesInAclW(1, &ace, std::ptr::null(), &mut original),
                ERROR_SUCCESS
            );
            assert_eq!(
                SetNamedSecurityInfoW(
                    wide(&path.to_string_lossy()).as_ptr() as *mut _,
                    SE_FILE_OBJECT,
                    SACL_SECURITY_INFORMATION,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    original
                ),
                ERROR_SUCCESS
            );
            let mut entry = std::ptr::null_mut();
            assert_ne!(GetAce(original, 0, &mut entry), 0);
            let header = &*entry.cast::<ACE_HEADER>();
            let expected =
                std::slice::from_raw_parts(entry.cast::<u8>(), header.AceSize as usize).to_vec();
            LocalFree(original.cast());
            LocalFree(users.cast());
            for _ in 0..2 {
                assert!(set_read_audit_sacl(&path));
                let mut actual: *mut ACL = std::ptr::null_mut();
                let mut descriptor = std::ptr::null_mut();
                assert_eq!(
                    GetNamedSecurityInfoW(
                        wide(&path.to_string_lossy()).as_ptr(),
                        SE_FILE_OBJECT,
                        SACL_SECURITY_INFORMATION,
                        std::ptr::null_mut(),
                        std::ptr::null_mut(),
                        std::ptr::null_mut(),
                        &mut actual,
                        &mut descriptor
                    ),
                    ERROR_SUCCESS
                );
                let mut preserved = false;
                for i in 0..(*actual).AceCount {
                    let mut entry = std::ptr::null_mut();
                    assert_ne!(GetAce(actual, i as u32, &mut entry), 0);
                    let header = &*entry.cast::<ACE_HEADER>();
                    preserved |=
                        std::slice::from_raw_parts(entry.cast::<u8>(), header.AceSize as usize)
                            == expected;
                }
                LocalFree(descriptor.cast());
                assert!(preserved, "deploy replaced unrelated audit policy");
            }
        }
        std::fs::remove_file(path).unwrap();
    }
}
