//! Windows platform posture.
//!
//! Evaluation is pure over [`Probe`] (registry DWORDs plus two native queries),
//! so the rules are tested on every platform; only [`HostProbe`] touches
//! Windows.
//!
//! Sources, and what they do not prove:
//!   * Secure Boot: `State\UEFISecureBootEnabled` (set by the kernel at boot).
//!   * HVCI: the registry value is the *configured* state; the running state is
//!     `CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED` from
//!     `NtQuerySystemInformation(SystemCodeIntegrityInformation)`.
//!   * Test signing / CI debug mode: the same code-integrity option flags.
//!   * Kernel debugger: `SystemKernelDebuggerInformation`.
//!   * Vulnerable driver blocklist: `CI\Config\VulnerableDriverBlocklistEnable`;
//!     absent means the OS default, which depends on the Windows build, so it
//!     is reported as unknown rather than guessed.
//!   * LSASS PPL: `Lsa\RunAsPPL` (1 or 2; absent = OS default, unknown). Configured state; it needs a reboot
//!     to take effect.
//!   * Defender tamper protection: `Windows Defender\Features\TamperProtection`
//!     (5/1 on, 4/0 off). Tamper-protected by Defender itself.

#![cfg_attr(not(windows), allow(dead_code))]

use std::collections::BTreeMap;

use super::snapshot::Setting;
use crate::inventory::windows_hardening::Registry;

pub const CI_ENABLED: u32 = 0x1;
pub const CI_TESTSIGN: u32 = 0x2;
pub const CI_DEBUGMODE: u32 = 0x80;
pub const CI_HVCI_KMCI_ENABLED: u32 = 0x400;

const SECURE_BOOT_KEY: &str = "SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State";
const HVCI_KEY: &str =
    "SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity";
const CI_CONFIG_KEY: &str = "SYSTEM\\CurrentControlSet\\Control\\CI\\Config";
const LSA_KEY: &str = "SYSTEM\\CurrentControlSet\\Control\\Lsa";
const DEFENDER_FEATURES_KEY: &str = "SOFTWARE\\Microsoft\\Windows Defender\\Features";

pub trait Probe: Registry {
    /// `SYSTEM_CODE_INTEGRITY_INFORMATION.CodeIntegrityOptions`.
    fn code_integrity_options(&self) -> Option<u32>;
    /// `(KernelDebuggerEnabled, KernelDebuggerNotPresent)`.
    fn kernel_debugger(&self) -> Option<(bool, bool)>;
}

pub fn evaluate(p: &dyn Probe) -> BTreeMap<String, Setting> {
    let mut m = BTreeMap::new();

    m.insert(
        "secure_boot".into(),
        match p.dword(SECURE_BOOT_KEY, "UEFISecureBootEnabled") {
            Some(v) => Setting::flag(v == 1),
            None => Setting::unknown("not_uefi_or_unreadable"),
        },
    );
    m.insert(
        "hvci_configured".into(),
        match p.dword(HVCI_KEY, "Enabled") {
            Some(v) => Setting::flag(v == 1),
            None => Setting::unknown("not_configured"),
        },
    );
    m.insert(
        "driver_blocklist".into(),
        match p.dword(CI_CONFIG_KEY, "VulnerableDriverBlocklistEnable") {
            Some(v) => Setting::flag(v != 0),
            None => Setting::unknown("os_default"),
        },
    );
    m.insert(
        "lsass_ppl".into(),
        match p.dword(LSA_KEY, "RunAsPPL") {
            Some(v) => Setting::flag(v == 1 || v == 2),
            None => Setting::unknown("os_default"),
        },
    );
    m.insert(
        "defender_tamper_protection".into(),
        match p.dword(DEFENDER_FEATURES_KEY, "TamperProtection") {
            Some(5) | Some(1) => Setting::flag(true),
            Some(4) | Some(0) => Setting::flag(false),
            Some(other) => Setting::new(format!("unrecognized:{other}"), None),
            None => Setting::unknown("unreadable"),
        },
    );

    match p.code_integrity_options() {
        Some(o) => {
            m.insert("code_integrity".into(), Setting::flag(o & CI_ENABLED != 0));
            m.insert(
                "hvci_running".into(),
                Setting::flag(o & CI_HVCI_KMCI_ENABLED != 0),
            );
            let off =
                |bit| Setting::new(if o & bit != 0 { "on" } else { "off" }, Some(o & bit == 0));
            m.insert("test_signing".into(), off(CI_TESTSIGN));
            m.insert("ci_debug_mode".into(), off(CI_DEBUGMODE));
        }
        None => {
            for k in [
                "code_integrity",
                "hvci_running",
                "test_signing",
                "ci_debug_mode",
            ] {
                m.insert(k.into(), Setting::unknown("query_failed"));
            }
        }
    }
    m.insert(
        "kernel_debugger".into(),
        match p.kernel_debugger() {
            // Enabled with no debugger attached is still a debug-enabled boot.
            Some((enabled, _not_present)) => {
                Setting::new(if enabled { "on" } else { "off" }, Some(!enabled))
            }
            None => Setting::unknown("query_failed"),
        },
    );
    m
}

#[cfg(windows)]
pub struct HostProbe;

#[cfg(windows)]
impl Registry for HostProbe {
    fn dword(&self, key: &str, name: &str) -> Option<u32> {
        crate::inventory::windows_hardening::LocalMachine.dword(key, name)
    }
}

#[cfg(windows)]
impl Probe for HostProbe {
    fn code_integrity_options(&self) -> Option<u32> {
        use windows_sys::Wdk::System::SystemInformation::{
            NtQuerySystemInformation, SystemCodeIntegrityInformation,
        };
        #[repr(C)]
        struct CodeIntegrityInfo {
            length: u32,
            options: u32,
        }
        let mut info = CodeIntegrityInfo {
            length: std::mem::size_of::<CodeIntegrityInfo>() as u32,
            options: 0,
        };
        let mut ret = 0u32;
        // SAFETY: `info` is a live, correctly sized out buffer for this class.
        let status = unsafe {
            NtQuerySystemInformation(
                SystemCodeIntegrityInformation,
                &mut info as *mut _ as *mut _,
                info.length,
                &mut ret,
            )
        };
        (status >= 0).then_some(info.options)
    }

    fn kernel_debugger(&self) -> Option<(bool, bool)> {
        use windows_sys::Wdk::System::SystemInformation::NtQuerySystemInformation;
        const SYSTEM_KERNEL_DEBUGGER_INFORMATION: i32 = 35;
        #[repr(C)]
        struct KernelDebuggerInfo {
            enabled: u8,
            not_present: u8,
        }
        let mut info = KernelDebuggerInfo {
            enabled: 0,
            not_present: 1,
        };
        let mut ret = 0u32;
        // SAFETY: `info` is a live, correctly sized out buffer for this class.
        let status = unsafe {
            NtQuerySystemInformation(
                SYSTEM_KERNEL_DEBUGGER_INFORMATION,
                &mut info as *mut _ as *mut _,
                std::mem::size_of::<KernelDebuggerInfo>() as u32,
                &mut ret,
            )
        };
        (status >= 0).then_some((info.enabled != 0, info.not_present != 0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[derive(Default)]
    struct Fake {
        regs: HashMap<(String, String), u32>,
        ci: Option<u32>,
        dbg: Option<(bool, bool)>,
    }
    impl Fake {
        fn reg(mut self, k: &str, n: &str, v: u32) -> Self {
            self.regs.insert((k.into(), n.into()), v);
            self
        }
    }
    impl Registry for Fake {
        fn dword(&self, key: &str, name: &str) -> Option<u32> {
            self.regs.get(&(key.into(), name.into())).copied()
        }
    }
    impl Probe for Fake {
        fn code_integrity_options(&self) -> Option<u32> {
            self.ci
        }
        fn kernel_debugger(&self) -> Option<(bool, bool)> {
            self.dbg
        }
    }

    fn good() -> Fake {
        Fake {
            ci: Some(CI_ENABLED | CI_HVCI_KMCI_ENABLED | 0x1000),
            dbg: Some((false, true)),
            ..Default::default()
        }
        .reg(SECURE_BOOT_KEY, "UEFISecureBootEnabled", 1)
        .reg(HVCI_KEY, "Enabled", 1)
        .reg(CI_CONFIG_KEY, "VulnerableDriverBlocklistEnable", 1)
        .reg(LSA_KEY, "RunAsPPL", 2)
        .reg(DEFENDER_FEATURES_KEY, "TamperProtection", 5)
    }

    #[test]
    fn hardened_host_is_all_secure() {
        let m = evaluate(&good());
        for (k, s) in &m {
            assert_eq!(s.secure, Some(true), "{k}: {s:?}");
        }
        assert_eq!(m.len(), 10);
    }

    #[test]
    fn testsigning_and_debugger_and_debugmode() {
        let mut f = good();
        f.ci = Some(CI_ENABLED | CI_TESTSIGN | CI_DEBUGMODE);
        f.dbg = Some((true, false));
        let m = evaluate(&f);
        assert_eq!(m["test_signing"], Setting::new("on", Some(false)));
        assert_eq!(m["ci_debug_mode"].secure, Some(false));
        assert_eq!(m["kernel_debugger"], Setting::new("on", Some(false)));
        assert_eq!(m["hvci_running"].secure, Some(false));
        assert_eq!(m["code_integrity"].secure, Some(true));
    }

    #[test]
    fn registry_weakening() {
        let f = good()
            .reg(SECURE_BOOT_KEY, "UEFISecureBootEnabled", 0)
            .reg(HVCI_KEY, "Enabled", 0)
            .reg(CI_CONFIG_KEY, "VulnerableDriverBlocklistEnable", 0)
            .reg(LSA_KEY, "RunAsPPL", 0)
            .reg(DEFENDER_FEATURES_KEY, "TamperProtection", 4);
        let m = evaluate(&f);
        for k in [
            "secure_boot",
            "hvci_configured",
            "driver_blocklist",
            "lsass_ppl",
            "defender_tamper_protection",
        ] {
            assert_eq!(m[k].secure, Some(false), "{k}");
        }
    }

    #[test]
    fn absent_values_and_failed_queries() {
        let m = evaluate(&Fake::default());
        assert_eq!(m["secure_boot"].secure, None);
        assert_eq!(m["driver_blocklist"].secure, None);
        assert_eq!(m["defender_tamper_protection"].secure, None);
        assert_eq!(m["test_signing"].secure, None);
        assert_eq!(m["kernel_debugger"].secure, None);
        // Absent RunAsPPL: default depends on the Windows build, not guessed.
        assert_eq!(m["lsass_ppl"].secure, None);
        let weird = evaluate(&good().reg(DEFENDER_FEATURES_KEY, "TamperProtection", 9));
        assert_eq!(weird["defender_tamper_protection"].secure, None);
    }
}
