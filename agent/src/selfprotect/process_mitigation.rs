//! Process mitigation policies for the Windows service.
//!
//! Each policy sits behind its own switch (`agent.env` / environment) and a
//! failure to apply one is logged and never fatal: hardening must not stop
//! telemetry. Defaults are chosen so that nothing the agent itself does can
//! break:
//!
//! | Policy | Variable | Default | Why |
//! |---|---|---|---|
//! | Extension points disabled (AppInit DLLs, LSPs, global hooks, legacy IME) | `TRAPD_MITIGATION_EXTENSION_POINTS` | `on` | the agent uses none |
//! | No remote / low-integrity images | `TRAPD_MITIGATION_IMAGE_LOAD` | `on` | the agent loads only local system DLLs |
//! | Binary signature: `audit` logs unsigned/third-party loads to the *Security-Mitigations* event log, `enforce` blocks anything not Microsoft-signed | `TRAPD_MITIGATION_SIGNATURE` = `off`/`audit`/`enforce` | `audit` | see below |
//! | Strict handle checks (invalid handle use raises an exception) | `TRAPD_MITIGATION_STRICT_HANDLE` | `off` | see below |
//!
//! Signature policy: the agent is one executable and loads no DLL of its own,
//! so `MicrosoftSignedOnly` would not break it. It can still break the host's
//! other software (an AV/EDR or accessibility tool that injects a third-party
//! signed DLL is refused), and the policy applies from the moment it is set,
//! not retroactively. Hence `audit` first: operators read the audit events,
//! then switch to `enforce`. Strict handle checks turn any latent invalid-handle
//! bug in the agent or a dependency into a process crash (SCM restarts it); that
//! is a stability risk this change cannot measure on a field host, so it is
//! opt-in.
//!
//! Deliberately NOT enabled: child-process restriction (response actions and
//! the update helper spawn children), dynamic-code prohibition and
//! win32k/system-call filtering.

#![cfg_attr(not(windows), allow(dead_code))]

#[cfg(target_os = "windows")]
use tracing::{info, warn};

/// `PROCESS_MITIGATION_POLICY` values (winnt.h).
pub const POLICY_STRICT_HANDLE_CHECK: i32 = 3;
pub const POLICY_EXTENSION_POINT_DISABLE: i32 = 6;
pub const POLICY_BINARY_SIGNATURE: i32 = 8;
pub const POLICY_IMAGE_LOAD: i32 = 10;

/// `DisableExtensionPoints`.
const DISABLE_EXTENSION_POINTS: u32 = 1 << 0;
/// Image load: `NoRemoteImages`, `NoLowMandatoryLabelImages`.
const NO_REMOTE_IMAGES: u32 = 1 << 0;
const NO_LOW_LABEL_IMAGES: u32 = 1 << 1;
/// Signature: `MicrosoftSignedOnly`, `AuditMicrosoftSignedOnly`.
const MICROSOFT_SIGNED_ONLY: u32 = 1 << 0;
const AUDIT_MICROSOFT_SIGNED_ONLY: u32 = 1 << 3;
/// Strict handle check: raise on invalid handle, and keep it on.
const RAISE_ON_INVALID_HANDLE: u32 = 1 << 0;
const HANDLE_EXCEPTIONS_PERMANENT: u32 = 1 << 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureMode {
    Off,
    Audit,
    Enforce,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MitigationConfig {
    pub extension_points: bool,
    pub image_load: bool,
    pub signature: SignatureMode,
    pub strict_handle: bool,
}

impl Default for MitigationConfig {
    fn default() -> Self {
        Self {
            extension_points: true,
            image_load: true,
            signature: SignatureMode::Audit,
            strict_handle: false,
        }
    }
}

impl MitigationConfig {
    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Self {
        use super::process_integrity::parse_switch;
        let d = Self::default();
        let signature = match get("TRAPD_MITIGATION_SIGNATURE")
            .map(|v| v.trim().to_ascii_lowercase())
            .as_deref()
        {
            Some("off" | "0" | "false" | "no") => SignatureMode::Off,
            Some("enforce" | "on" | "1" | "true" | "yes") => SignatureMode::Enforce,
            Some("audit") => SignatureMode::Audit,
            _ => d.signature,
        };
        Self {
            extension_points: parse_switch(
                get("TRAPD_MITIGATION_EXTENSION_POINTS").as_deref(),
                d.extension_points,
            ),
            image_load: parse_switch(get("TRAPD_MITIGATION_IMAGE_LOAD").as_deref(), d.image_load),
            signature,
            strict_handle: parse_switch(
                get("TRAPD_MITIGATION_STRICT_HANDLE").as_deref(),
                d.strict_handle,
            ),
        }
    }

    /// `(name, policy id, flag word)` for every policy to apply, in order.
    pub fn plan(&self) -> Vec<(&'static str, i32, u32)> {
        let mut plan = Vec::new();
        if self.extension_points {
            plan.push((
                "extension_points",
                POLICY_EXTENSION_POINT_DISABLE,
                DISABLE_EXTENSION_POINTS,
            ));
        }
        if self.image_load {
            plan.push((
                "image_load",
                POLICY_IMAGE_LOAD,
                NO_REMOTE_IMAGES | NO_LOW_LABEL_IMAGES,
            ));
        }
        match self.signature {
            SignatureMode::Off => {}
            SignatureMode::Audit => plan.push((
                "signature_audit",
                POLICY_BINARY_SIGNATURE,
                AUDIT_MICROSOFT_SIGNED_ONLY,
            )),
            SignatureMode::Enforce => plan.push((
                "signature_enforce",
                POLICY_BINARY_SIGNATURE,
                MICROSOFT_SIGNED_ONLY,
            )),
        }
        if self.strict_handle {
            plan.push((
                "strict_handle",
                POLICY_STRICT_HANDLE_CHECK,
                RAISE_ON_INVALID_HANDLE | HANDLE_EXCEPTIONS_PERMANENT,
            ));
        }
        plan
    }
}

/// Apply the policies to the current process. Call early in service start-up,
/// before worker threads load further modules.
#[cfg(target_os = "windows")]
pub fn apply() {
    use windows_sys::Win32::System::Threading::SetProcessMitigationPolicy;
    let cfg = MitigationConfig::from_lookup(|k| std::env::var(k).ok());
    for (name, policy, flags) in cfg.plan() {
        // SAFETY: every policy structure used here is a single DWORD of bit
        // flags; the buffer is a valid u32 and its size is passed.
        let ok = unsafe {
            SetProcessMitigationPolicy(
                policy,
                (&flags as *const u32).cast(),
                std::mem::size_of::<u32>(),
            )
        };
        if ok == 0 {
            warn!(
                policy = name,
                error = %std::io::Error::last_os_error(),
                "process mitigation policy not applied"
            );
        } else {
            info!(policy = name, "process mitigation policy applied");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn cfg(env: &[(&str, &str)]) -> MitigationConfig {
        let m: HashMap<String, String> = env
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        MitigationConfig::from_lookup(|k| m.get(k).cloned())
    }

    #[test]
    fn defaults_apply_the_safe_policies_and_audit_the_signature() {
        let names: Vec<_> = cfg(&[]).plan().iter().map(|p| p.0).collect();
        assert_eq!(names, ["extension_points", "image_load", "signature_audit"]);
    }

    #[test]
    fn child_process_and_dynamic_code_policies_are_never_requested() {
        // ProcessDynamicCodePolicy = 2, ProcessChildProcessPolicy = 13.
        let all = cfg(&[
            ("TRAPD_MITIGATION_SIGNATURE", "enforce"),
            ("TRAPD_MITIGATION_STRICT_HANDLE", "on"),
        ]);
        assert!(all.plan().iter().all(|(_, id, _)| *id != 2 && *id != 13));
    }

    #[test]
    fn signature_modes_map_to_the_documented_flag_bits() {
        let sig = |v| {
            cfg(&[("TRAPD_MITIGATION_SIGNATURE", v)])
                .plan()
                .into_iter()
                .find(|p| p.1 == POLICY_BINARY_SIGNATURE)
        };
        assert_eq!(sig("off"), None);
        assert_eq!(sig("audit").unwrap().2, 0b1000);
        assert_eq!(sig("enforce").unwrap().2, 0b0001);
        assert_eq!(sig("nonsense").unwrap().2, 0b1000, "unknown keeps audit");
    }

    #[test]
    fn strict_handle_is_opt_in_and_each_switch_turns_a_policy_off() {
        assert!(!cfg(&[])
            .plan()
            .iter()
            .any(|p| p.1 == POLICY_STRICT_HANDLE_CHECK));
        let on = cfg(&[("TRAPD_MITIGATION_STRICT_HANDLE", "1")]).plan();
        assert_eq!(
            on.iter()
                .find(|p| p.1 == POLICY_STRICT_HANDLE_CHECK)
                .unwrap()
                .2,
            0b11
        );
        let off = cfg(&[
            ("TRAPD_MITIGATION_EXTENSION_POINTS", "off"),
            ("TRAPD_MITIGATION_IMAGE_LOAD", "off"),
            ("TRAPD_MITIGATION_SIGNATURE", "off"),
        ]);
        assert!(off.plan().is_empty());
    }

    #[test]
    fn image_load_blocks_remote_and_low_integrity_images() {
        let p = cfg(&[]).plan();
        let img = p.iter().find(|p| p.1 == POLICY_IMAGE_LOAD).unwrap();
        assert_eq!(img.2, 0b11);
    }
}
