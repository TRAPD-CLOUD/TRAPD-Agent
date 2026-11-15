//! Protected DACL on the agent's own process object (Windows service only).
//!
//! `SYSTEM` keeps full access. Administrators may only query limited
//! information, wait on the process and read its security descriptor, so
//! `taskkill /f`, `TerminateProcess`, memory writes, thread injection, handle
//! duplication and DACL rewrites from an elevated admin shell are denied.
//!
//! This is defence in depth, not a security boundary:
//! - A caller holding `SeDebugPrivilege` (any admin who enables it, incl.
//!   Task Manager / Process Hacker / `sc`-less tooling running elevated with
//!   that privilege) bypasses the DACL; so does `SYSTEM` and anything in the
//!   kernel. The value is against non-debug administrators, misconfigured
//!   tooling and casual `taskkill`; the defence against a determined admin is
//!   detection (WP7), not prevention.
//! - SCM stop/recovery, the MSI and the update helper act through the Service
//!   Control Manager or run as `SYSTEM`, never via a handle to this process
//!   that the DACL would refuse.
//! - Thread objects are deliberately NOT restricted: tokio and the blocking
//!   pool create threads dynamically, each new thread would need its DACL set
//!   (racy), and changing the token default DACL instead would also change the
//!   security of every file, pipe and event the agent creates. Residual: an
//!   admin without `SeDebugPrivilege` can still open individual threads
//!   (`THREAD_SUSPEND_RESUME`/`THREAD_TERMINATE`) under their default DACL.
//! - Failure is logged and never fatal: hardening must not stop telemetry.

/// `PROCESS_ALL_ACCESS` on Windows Vista and later.
pub const PROCESS_ALL_ACCESS: u32 = 0x001F_FFFF;
/// `PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE | READ_CONTROL`.
pub const ADMIN_PROCESS_RIGHTS: u32 = 0x0000_1000 | 0x0010_0000 | 0x0002_0000;

/// Protected DACL: `SYSTEM` full access, `Administrators` read-only subset,
/// nobody else (no owner/creator, no Everyone, no inheritance).
pub const PROCESS_DACL_SDDL: &str = "D:P(A;;0x1fffff;;;SY)(A;;0x121000;;;BA)";

/// Parse `(A;;<hex mask>;;;<sid>)` entries of a protected-DACL SDDL string.
#[cfg(test)]
fn parse_allow_aces(sddl: &str) -> Vec<(u32, String)> {
    sddl.trim_start_matches("D:P")
        .split('(')
        .skip(1)
        .map(|ace| {
            let parts: Vec<&str> = ace.trim_end_matches(')').split(';').collect();
            assert_eq!(parts.len(), 6, "malformed ACE {ace}");
            assert_eq!(parts[0], "A", "only allow ACEs expected");
            assert!(parts[1].is_empty(), "no inheritance flags expected");
            let mask = u32::from_str_radix(parts[2].trim_start_matches("0x"), 16).unwrap();
            (mask, parts[5].to_string())
        })
        .collect()
}

/// Apply the DACL when running as `LocalSystem`; log and continue on failure.
#[cfg(target_os = "windows")]
pub fn apply() {
    use tracing::{info, warn};
    if !crate::winacl::is_local_system() {
        info!("process DACL not applied: not running as LocalSystem");
        return;
    }
    match crate::winacl::set_current_process_dacl(PROCESS_DACL_SDDL) {
        Ok(()) => info!("process object DACL applied"),
        Err(error) => warn!(%error, "process object DACL not applied"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dacl_is_protected_and_grants_only_system_and_administrators() {
        assert!(PROCESS_DACL_SDDL.starts_with("D:P"));
        let aces = parse_allow_aces(PROCESS_DACL_SDDL);
        let sids: Vec<_> = aces.iter().map(|(_, s)| s.as_str()).collect();
        assert_eq!(sids, ["SY", "BA"]);
        assert_eq!(aces[0].0, PROCESS_ALL_ACCESS);
        assert_eq!(aces[1].0, ADMIN_PROCESS_RIGHTS);
        assert_eq!(ADMIN_PROCESS_RIGHTS, 0x121000);
    }

    #[test]
    fn administrators_cannot_terminate_modify_or_take_over_the_process() {
        const TERMINATE: u32 = 0x0001;
        const CREATE_THREAD: u32 = 0x0002;
        const VM_OPERATION: u32 = 0x0008;
        const VM_READ: u32 = 0x0010;
        const VM_WRITE: u32 = 0x0020;
        const DUP_HANDLE: u32 = 0x0040;
        const SET_INFORMATION: u32 = 0x0200;
        const SUSPEND_RESUME: u32 = 0x0800;
        const QUERY_INFORMATION: u32 = 0x0400;
        const WRITE_DAC: u32 = 0x0004_0000;
        const WRITE_OWNER: u32 = 0x0008_0000;
        const DELETE: u32 = 0x0001_0000;
        const QUERY_LIMITED: u32 = 0x1000;
        const READ_CONTROL: u32 = 0x0002_0000;
        const SYNCHRONIZE: u32 = 0x0010_0000;
        let admin = parse_allow_aces(PROCESS_DACL_SDDL)[1].0;
        let forbidden = TERMINATE
            | CREATE_THREAD
            | VM_OPERATION
            | VM_READ
            | VM_WRITE
            | DUP_HANDLE
            | SET_INFORMATION
            | SUSPEND_RESUME
            | QUERY_INFORMATION
            | WRITE_DAC
            | WRITE_OWNER
            | DELETE;
        assert_eq!(admin & forbidden, 0, "admin mask {admin:#x}");
        assert_eq!(admin, QUERY_LIMITED | READ_CONTROL | SYNCHRONIZE);
    }

    #[test]
    fn no_other_principal_is_granted_access() {
        let aces = parse_allow_aces(PROCESS_DACL_SDDL);
        assert_eq!(aces.len(), 2);
        for forbidden in ["WD", "AU", "BU", "OW", "CO", "IU", "S-1-1-0"] {
            assert!(!PROCESS_DACL_SDDL.contains(&format!(";;;{forbidden})")));
        }
    }
}
