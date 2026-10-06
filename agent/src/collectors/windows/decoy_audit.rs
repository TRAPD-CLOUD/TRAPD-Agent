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
    ConvertSidToStringSidW, ConvertStringSidToSidW, GetNamedSecurityInfoW, SetNamedSecurityInfoW,
    SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    AddAuditAccessAceEx, AdjustTokenPrivileges, GetLengthSid, InitializeAcl, LookupPrivilegeValueW,
    ACL, ACL_REVISION, CONTAINER_INHERIT_ACE, LUID_AND_ATTRIBUTES, OBJECT_INHERIT_ACE, PSID,
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
        let sid_len = GetLengthSid(sid) as usize;
        // ACL buffer: header + one audit ACE (ACE header + mask + SID body).
        let acl_size = std::mem::size_of::<ACL>() + 16 + sid_len;
        let mut buf = vec![0u8; acl_size];
        let acl = buf.as_mut_ptr() as *mut ACL;
        let ok = InitializeAcl(acl, acl_size as u32, ACL_REVISION) != 0
            && AddAuditAccessAceEx(
                acl,
                ACL_REVISION,
                OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE,
                AUDIT_MASK,
                sid,
                1, // audit success
                0, // not failure (a denied read is already logged elsewhere)
            ) != 0;
        let result = if ok {
            SetNamedSecurityInfoW(
                wide(&path.to_string_lossy()).as_ptr() as PCWSTR as *mut _,
                SE_FILE_OBJECT,
                SACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null(),
                acl,
            ) == ERROR_SUCCESS
        } else {
            false
        };
        LocalFree(sid as _);
        if !result {
            tracing::warn!(path = %path.display(), "could not set decoy read-audit SACL");
        }
        result
    }
}
