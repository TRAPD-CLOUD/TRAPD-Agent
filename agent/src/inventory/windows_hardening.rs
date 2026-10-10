//! Windows host-hardening checks — the counterpart of the Linux CIS checks.
//!
//! The evaluation is pure: it reads DWORDs through the [`Registry`] trait and
//! returns [`CisFinding`]s, so every rule is unit-tested on every CI platform
//! against a fake registry. Only the reader ([`LocalMachine`]) touches Windows.
//!
//! Principles, shared with the Linux checks:
//!
//!   * A finding states what was **observed**. A value that is absent is judged
//!     against the documented Windows default, and when the default is not
//!     knowable from the registry alone (an optional feature, legacy BIOS) the
//!     check is `not_applicable`, never a guessed pass.
//!   * Nothing here claims a CIS benchmark score; ids are `WIN-*` so a report
//!     can never be mistaken for an audited CIS profile.

// Compiled everywhere so the rules are tested on every CI platform; only the
// Windows build reads a real registry.
#![cfg_attr(not(windows), allow(dead_code))]

use super::compliance::CisFinding;
use crate::prevention::firewall;

/// Read-only access to `HKLM` DWORD values.
pub trait Registry {
    fn dword(&self, key: &str, name: &str) -> Option<u32>;
}

fn pass(id: &str, title: &str, level: u8, detail: impl Into<String>) -> CisFinding {
    CisFinding {
        id: id.into(),
        title: title.into(),
        level,
        status: "pass".into(),
        detail: detail.into(),
    }
}

fn fail(id: &str, title: &str, level: u8, detail: impl Into<String>) -> CisFinding {
    CisFinding {
        status: "fail".into(),
        ..pass(id, title, level, detail)
    }
}

fn not_applicable(id: &str, title: &str, level: u8, detail: impl Into<String>) -> CisFinding {
    CisFinding {
        status: "not_applicable".into(),
        ..pass(id, title, level, detail)
    }
}

const SYSTEM_POLICIES: &str = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System";
const LSA: &str = "SYSTEM\\CurrentControlSet\\Control\\Lsa";
const DEFENDER_POLICY: &str = "SOFTWARE\\Policies\\Microsoft\\Windows Defender";
const DEFENDER_RT_POLICY: &str =
    "SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection";

/// Evaluate every check against `reg`.
pub fn evaluate(reg: &dyn Registry) -> Vec<CisFinding> {
    let mut out = Vec::new();

    // User Account Control. Absent EnableLUA means the default: enabled.
    match reg.dword(SYSTEM_POLICIES, "EnableLUA") {
        Some(0) => out.push(fail(
            "WIN-UAC",
            "User Account Control is enabled",
            1,
            "EnableLUA=0: administrators run every process with a full token",
        )),
        _ => out.push(pass(
            "WIN-UAC",
            "User Account Control is enabled",
            1,
            "enabled",
        )),
    }
    match reg.dword(SYSTEM_POLICIES, "ConsentPromptBehaviorAdmin") {
        Some(0) => out.push(fail(
            "WIN-UAC-PROMPT",
            "Administrators are prompted before elevation",
            1,
            "ConsentPromptBehaviorAdmin=0: elevation without any prompt",
        )),
        _ => out.push(pass(
            "WIN-UAC-PROMPT",
            "Administrators are prompted before elevation",
            1,
            "elevation requires consent or credentials",
        )),
    }

    // Windows Defender Firewall, per profile (group policy overrides local).
    let mut off = Vec::new();
    for profile in firewall::FIREWALL_PROFILES {
        let policy = reg.dword(
            &format!("{}\\{profile}", firewall::FIREWALL_POLICY_PROFILES),
            "EnableFirewall",
        );
        let local = reg.dword(
            &format!("{}\\{profile}", firewall::FIREWALL_LOCAL_PROFILES),
            "EnableFirewall",
        );
        if !firewall::profile_enforcing(policy, local) {
            off.push(profile);
        }
    }
    if off.is_empty() {
        out.push(pass(
            "WIN-FIREWALL",
            "Windows Defender Firewall is on for every profile",
            1,
            "domain, private and public profiles are enforcing",
        ));
    } else {
        out.push(fail(
            "WIN-FIREWALL",
            "Windows Defender Firewall is on for every profile",
            1,
            format!("disabled: {}", off.join(", ")),
        ));
    }

    // Defender real-time protection, judged only by what policy disables: a
    // host protected by another vendor's product legitimately turns Defender off
    // through the Security Center, which the registry alone cannot attest.
    let defender_off = reg.dword(DEFENDER_RT_POLICY, "DisableRealtimeMonitoring") == Some(1)
        || reg.dword(DEFENDER_POLICY, "DisableAntiSpyware") == Some(1);
    if defender_off {
        out.push(fail(
            "WIN-DEFENDER",
            "Defender real-time protection is not disabled by policy",
            1,
            "a policy disables Defender; confirm another endpoint product is active",
        ));
    } else {
        out.push(pass(
            "WIN-DEFENDER",
            "Defender real-time protection is not disabled by policy",
            1,
            "no policy disables it",
        ));
    }

    // Credential exposure.
    if reg.dword(
        "SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest",
        "UseLogonCredential",
    ) == Some(1)
    {
        out.push(fail(
            "WIN-WDIGEST",
            "WDigest does not keep cleartext credentials in memory",
            1,
            "UseLogonCredential=1",
        ));
    } else {
        out.push(pass(
            "WIN-WDIGEST",
            "WDigest does not keep cleartext credentials in memory",
            1,
            "cleartext caching is off",
        ));
    }
    match reg.dword(LSA, "RunAsPPL") {
        Some(1) | Some(2) => out.push(pass(
            "WIN-LSA-PPL",
            "LSASS runs as a protected process",
            2,
            "RunAsPPL is set",
        )),
        _ => out.push(fail(
            "WIN-LSA-PPL",
            "LSASS runs as a protected process",
            2,
            "RunAsPPL is not set: credential dumping from LSASS is not blocked by the OS",
        )),
    }
    match reg.dword(LSA, "LmCompatibilityLevel") {
        Some(level) if level < 3 => out.push(fail(
            "WIN-NTLM",
            "Only NTLMv2 responses are sent",
            1,
            format!("LmCompatibilityLevel={level}: LM/NTLMv1 responses are allowed"),
        )),
        _ => out.push(pass(
            "WIN-NTLM",
            "Only NTLMv2 responses are sent",
            1,
            "LmCompatibilityLevel is at least 3 (the Windows default)",
        )),
    }

    // Legacy network protocols.
    match reg.dword(
        "SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters",
        "SMB1",
    ) {
        Some(0) => out.push(pass("WIN-SMB1", "SMBv1 server is disabled", 1, "SMB1=0")),
        Some(_) => out.push(fail(
            "WIN-SMB1",
            "SMBv1 server is disabled",
            1,
            "SMB1 is enabled",
        )),
        None => out.push(not_applicable(
            "WIN-SMB1",
            "SMBv1 server is disabled",
            1,
            "not configured; the state depends on the optional SMB1 Windows feature",
        )),
    }
    if reg.dword(
        "SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient",
        "EnableMulticast",
    ) == Some(0)
    {
        out.push(pass(
            "WIN-LLMNR",
            "LLMNR name resolution is disabled",
            2,
            "disabled by policy",
        ));
    } else {
        out.push(fail(
            "WIN-LLMNR",
            "LLMNR name resolution is disabled",
            2,
            "LLMNR is on (spoofable name resolution)",
        ));
    }

    // Remote Desktop: only meaningful when it is enabled.
    let rdp_enabled = reg.dword(
        "SYSTEM\\CurrentControlSet\\Control\\Terminal Server",
        "fDenyTSConnections",
    ) == Some(0);
    if rdp_enabled {
        let nla = reg.dword(
            "SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp",
            "UserAuthentication",
        );
        if nla == Some(1) {
            out.push(pass(
                "WIN-RDP-NLA",
                "Remote Desktop requires Network Level Authentication",
                1,
                "NLA required",
            ));
        } else {
            out.push(fail(
                "WIN-RDP-NLA",
                "Remote Desktop requires Network Level Authentication",
                1,
                "Remote Desktop is enabled without NLA",
            ));
        }
    } else {
        out.push(not_applicable(
            "WIN-RDP-NLA",
            "Remote Desktop requires Network Level Authentication",
            1,
            "Remote Desktop is not enabled",
        ));
    }

    // Visibility the detections depend on.
    if reg.dword(
        "SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging",
        "EnableScriptBlockLogging",
    ) == Some(1)
    {
        out.push(pass(
            "WIN-PS-LOGGING",
            "PowerShell script block logging is enabled",
            2,
            "enabled by policy",
        ));
    } else {
        out.push(fail(
            "WIN-PS-LOGGING",
            "PowerShell script block logging is enabled",
            2,
            "not enabled: script content is not recorded for investigation",
        ));
    }

    // Command lines of short-lived processes: ETW reads them from the live
    // process and misses ones that exit first; 4688 carries them regardless.
    if reg.dword(
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit",
        "ProcessCreationIncludeCmdLine_Enabled",
    ) == Some(1)
    {
        out.push(pass(
            "WIN-AUDIT-CMDLINE",
            "Process-creation events include the command line",
            2,
            "enabled by policy (also needs Audit Process Creation = Success)",
        ));
    } else {
        out.push(fail(
            "WIN-AUDIT-CMDLINE",
            "Process-creation events include the command line",
            2,
            "not enabled: short-lived processes (certutil, bitsadmin) reach detection without a command line",
        ));
    }

    // Platform integrity and patching.
    match reg.dword(
        "SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State",
        "UEFISecureBootEnabled",
    ) {
        Some(1) => out.push(pass(
            "WIN-SECUREBOOT",
            "Secure Boot is enabled",
            1,
            "enabled",
        )),
        Some(_) => out.push(fail(
            "WIN-SECUREBOOT",
            "Secure Boot is enabled",
            1,
            "disabled",
        )),
        None => out.push(not_applicable(
            "WIN-SECUREBOOT",
            "Secure Boot is enabled",
            1,
            "no UEFI Secure Boot state (legacy BIOS or virtual machine without it)",
        )),
    }
    if reg.dword(
        "SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU",
        "NoAutoUpdate",
    ) == Some(1)
    {
        out.push(fail(
            "WIN-AUTOUPDATE",
            "Automatic Windows updates are not disabled by policy",
            1,
            "NoAutoUpdate=1",
        ));
    } else {
        out.push(pass(
            "WIN-AUTOUPDATE",
            "Automatic Windows updates are not disabled by policy",
            1,
            "not disabled",
        ));
    }
    out
}

/// Registry reader over `HKLM` (64-bit view).
#[cfg(windows)]
pub struct LocalMachine;

#[cfg(windows)]
impl Registry for LocalMachine {
    fn dword(&self, key: &str, name: &str) -> Option<u32> {
        crate::collectors::windows::registry::dword(
            key,
            name,
            windows_sys::Win32::System::Registry::RRF_SUBKEY_WOW6464KEY,
        )
    }
}

/// The checks for this host.
pub fn checks() -> Vec<CisFinding> {
    #[cfg(windows)]
    {
        evaluate(&LocalMachine)
    }
    #[cfg(not(windows))]
    {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[derive(Default)]
    struct Fake(HashMap<(String, String), u32>);

    impl Fake {
        fn with(mut self, key: &str, name: &str, value: u32) -> Self {
            self.0.insert((key.into(), name.into()), value);
            self
        }
    }

    impl Registry for Fake {
        fn dword(&self, key: &str, name: &str) -> Option<u32> {
            self.0.get(&(key.to_string(), name.to_string())).copied()
        }
    }

    #[test]
    fn command_line_auditing_is_judged_from_the_policy_value() {
        let key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit";
        let on = Fake(HashMap::new()).with(key, "ProcessCreationIncludeCmdLine_Enabled", 1);
        assert_eq!(status(&evaluate(&on), "WIN-AUDIT-CMDLINE"), "pass");
        assert_eq!(
            status(&evaluate(&Fake(HashMap::new())), "WIN-AUDIT-CMDLINE"),
            "fail"
        );
        let off = Fake(HashMap::new()).with(key, "ProcessCreationIncludeCmdLine_Enabled", 0);
        assert_eq!(status(&evaluate(&off), "WIN-AUDIT-CMDLINE"), "fail");
    }

    fn status(findings: &[CisFinding], id: &str) -> String {
        findings
            .iter()
            .find(|f| f.id == id)
            .unwrap_or_else(|| panic!("missing check {id}"))
            .status
            .clone()
    }

    #[test]
    fn a_fresh_default_host_has_no_false_failures_on_defaults() {
        let f = evaluate(&Fake::default());
        // Windows defaults that are secure must not be reported as failures just
        // because the value is absent from the registry.
        for id in [
            "WIN-UAC",
            "WIN-UAC-PROMPT",
            "WIN-FIREWALL",
            "WIN-DEFENDER",
            "WIN-WDIGEST",
            "WIN-NTLM",
            "WIN-AUTOUPDATE",
        ] {
            assert_eq!(status(&f, id), "pass", "{id}");
        }
        // Unknowable from the registry: reported as such, not guessed.
        assert_eq!(status(&f, "WIN-SMB1"), "not_applicable");
        assert_eq!(status(&f, "WIN-SECUREBOOT"), "not_applicable");
        assert_eq!(status(&f, "WIN-RDP-NLA"), "not_applicable");
        // Opt-in hardening is a failure when absent.
        assert_eq!(status(&f, "WIN-LSA-PPL"), "fail");
        assert_eq!(status(&f, "WIN-PS-LOGGING"), "fail");
        assert_eq!(status(&f, "WIN-LLMNR"), "fail");
    }

    #[test]
    fn explicitly_weakened_settings_fail() {
        let f = evaluate(
            &Fake::default()
                .with(SYSTEM_POLICIES, "EnableLUA", 0)
                .with(SYSTEM_POLICIES, "ConsentPromptBehaviorAdmin", 0)
                .with(DEFENDER_RT_POLICY, "DisableRealtimeMonitoring", 1)
                .with(
                    "SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest",
                    "UseLogonCredential",
                    1,
                )
                .with(LSA, "LmCompatibilityLevel", 1)
                .with(
                    "SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters",
                    "SMB1",
                    1,
                )
                .with(
                    "SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU",
                    "NoAutoUpdate",
                    1,
                ),
        );
        for id in [
            "WIN-UAC",
            "WIN-UAC-PROMPT",
            "WIN-DEFENDER",
            "WIN-WDIGEST",
            "WIN-NTLM",
            "WIN-SMB1",
            "WIN-AUTOUPDATE",
        ] {
            assert_eq!(status(&f, id), "fail", "{id}");
        }
    }

    #[test]
    fn group_policy_firewall_off_beats_a_local_on_and_names_the_profile() {
        let f = evaluate(&Fake::default().with(
            &format!("{}\\PublicProfile", firewall::FIREWALL_POLICY_PROFILES),
            "EnableFirewall",
            0,
        ));
        let fw = f.iter().find(|c| c.id == "WIN-FIREWALL").unwrap();
        assert_eq!(fw.status, "fail");
        assert!(fw.detail.contains("PublicProfile"));
        assert!(!fw.detail.contains("DomainProfile"));
    }

    #[test]
    fn rdp_without_nla_fails_only_when_rdp_is_enabled() {
        let rdp = "SYSTEM\\CurrentControlSet\\Control\\Terminal Server";
        let nla = "SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp";
        let on_without = evaluate(&Fake::default().with(rdp, "fDenyTSConnections", 0));
        assert_eq!(status(&on_without, "WIN-RDP-NLA"), "fail");
        let on_with = evaluate(&Fake::default().with(rdp, "fDenyTSConnections", 0).with(
            nla,
            "UserAuthentication",
            1,
        ));
        assert_eq!(status(&on_with, "WIN-RDP-NLA"), "pass");
        let off = evaluate(&Fake::default().with(rdp, "fDenyTSConnections", 1));
        assert_eq!(status(&off, "WIN-RDP-NLA"), "not_applicable");
    }

    #[test]
    fn protected_lsass_and_logging_pass_when_configured() {
        let f = evaluate(&Fake::default().with(LSA, "RunAsPPL", 2).with(
            "SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging",
            "EnableScriptBlockLogging",
            1,
        ));
        assert_eq!(status(&f, "WIN-LSA-PPL"), "pass");
        assert_eq!(status(&f, "WIN-PS-LOGGING"), "pass");
    }

    #[test]
    fn ids_never_claim_to_be_a_cis_benchmark() {
        let f = evaluate(&Fake::default());
        assert!(f.iter().all(|c| c.id.starts_with("WIN-")));
        let unique: std::collections::HashSet<_> = f.iter().map(|c| &c.id).collect();
        assert_eq!(unique.len(), f.len());
    }
}

#[cfg(all(test, windows))]
mod native_tests {
    #[test]
    fn the_real_registry_yields_a_complete_set_of_findings() {
        let findings = super::checks();
        assert!(findings.len() >= 12, "{findings:?}");
        // A real host always has a definite firewall verdict.
        let fw = findings.iter().find(|f| f.id == "WIN-FIREWALL").unwrap();
        assert!(fw.status == "pass" || fw.status == "fail");
        assert!(findings
            .iter()
            .all(|f| matches!(f.status.as_str(), "pass" | "fail" | "not_applicable")));
    }
}
