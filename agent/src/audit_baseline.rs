//! Installer-owned audit baseline for process command lines.
//!
//! ETW reads a command line from the live process, so a one-shot `cmd /c ...`
//! that exits first has none (field test F3). Windows delivers it reliably only
//! in event 4688, which needs two machine settings: "Audit Process Creation:
//! Success" and `ProcessCreationIncludeCmdLine_Enabled=1`.
//!
//! The running agent never changes audit policy (see `decoy_audit`: it only
//! queries operator-owned settings). This module is the installer's one-time,
//! reversible exception, called from MSI custom actions (`trapd-agent.exe
//! audit-baseline apply|restore`) and switched off with `AUDITBASELINE=0`.
//!
//! Ownership rule: only what this module changed is ever reverted. A setting an
//! administrator had already enabled is left alone on install and on removal.
//!
//! The decisions are pure and tested against a fake host on every platform; the
//! Windows host shells out to `auditpol.exe` / `reg.exe` by absolute path and
//! subcategory GUID, so nothing depends on the OS language.

// Compiled everywhere so the decisions are tested on every CI platform; only the
// Windows entry point calls them.
#![cfg_attr(not(windows), allow(dead_code))]

use anyhow::Result;
use serde::{Deserialize, Serialize};

/// What this module changed, persisted between install and removal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Receipt {
    /// We switched "Audit Process Creation: Success" on.
    pub set_audit_success: bool,
    /// We wrote the command-line policy value.
    pub set_cmdline: bool,
    /// The command-line value before we wrote it (`None` = it did not exist).
    pub prev_cmdline: Option<u32>,
}

/// The two machine settings, abstracted so the decisions are testable.
pub trait Host {
    /// Whether "Audit Process Creation" currently audits success.
    fn audit_success(&self) -> Result<bool>;
    fn set_audit_success(&mut self, on: bool) -> Result<()>;
    /// `ProcessCreationIncludeCmdLine_Enabled`, `None` when absent.
    fn cmdline(&self) -> Result<Option<u32>>;
    fn set_cmdline(&mut self, value: Option<u32>) -> Result<()>;
}

/// Turn on whatever is missing. Safe to repeat (upgrade, repair): ownership
/// recorded by an earlier run is kept while the setting is still on.
pub fn apply(host: &mut dyn Host, prior: Receipt) -> Result<Receipt> {
    let mut receipt = Receipt::default();

    if host.audit_success()? {
        receipt.set_audit_success = prior.set_audit_success;
    } else {
        host.set_audit_success(true)?;
        receipt.set_audit_success = true;
    }

    let current = host.cmdline()?;
    if current == Some(1) {
        receipt.set_cmdline = prior.set_cmdline;
        receipt.prev_cmdline = prior.prev_cmdline;
    } else {
        host.set_cmdline(Some(1))?;
        receipt.set_cmdline = true;
        receipt.prev_cmdline = current;
    }
    Ok(receipt)
}

/// Undo exactly what [`apply`] did, and only while the setting is still as we
/// left it. Both reverts are attempted; the first error is returned.
pub fn restore(host: &mut dyn Host, receipt: Receipt) -> Result<()> {
    let audit = if receipt.set_audit_success && host.audit_success()? {
        host.set_audit_success(false)
    } else {
        Ok(())
    };
    let cmdline = if receipt.set_cmdline && host.cmdline()? == Some(1) {
        host.set_cmdline(receipt.prev_cmdline)
    } else {
        Ok(())
    };
    audit.and(cmdline)
}

#[cfg(windows)]
pub use windows_host::run_cli;

#[cfg(windows)]
mod windows_host {
    use super::{apply, restore, Host, Receipt};
    use anyhow::{anyhow, bail, Context, Result};
    use std::path::PathBuf;
    use std::process::Command;

    const PROCESS_CREATION_GUID: &str = "{0CCE922B-69AE-11D9-BED3-505054503030}";
    const AUDIT_KEY: &str = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit";
    const CMDLINE_VALUE: &str = "ProcessCreationIncludeCmdLine_Enabled";

    fn system32(tool: &str) -> PathBuf {
        let root = std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into());
        PathBuf::from(root).join("System32").join(tool)
    }

    fn run(tool: &str, args: &[&str]) -> Result<()> {
        let out = Command::new(system32(tool))
            .args(args)
            .output()
            .with_context(|| format!("start {tool}"))?;
        if !out.status.success() {
            bail!("{tool} exited with {}", out.status);
        }
        Ok(())
    }

    struct WindowsHost;

    impl Host for WindowsHost {
        fn audit_success(&self) -> Result<bool> {
            crate::collectors::windows::decoy_audit::process_audit_enabled()
                .ok_or_else(|| anyhow!("cannot query the process-creation audit policy"))
        }

        fn set_audit_success(&mut self, on: bool) -> Result<()> {
            let flag = if on {
                "/success:enable"
            } else {
                "/success:disable"
            };
            run(
                "auditpol.exe",
                &[
                    "/set",
                    &format!("/subcategory:{PROCESS_CREATION_GUID}"),
                    flag,
                ],
            )
        }

        fn cmdline(&self) -> Result<Option<u32>> {
            use crate::inventory::windows_hardening::{LocalMachine, Registry};
            Ok(LocalMachine.dword(AUDIT_KEY, CMDLINE_VALUE))
        }

        fn set_cmdline(&mut self, value: Option<u32>) -> Result<()> {
            let key = format!("HKLM\\{AUDIT_KEY}");
            match value {
                Some(v) => run(
                    "reg.exe",
                    &[
                        "add",
                        &key,
                        "/v",
                        CMDLINE_VALUE,
                        "/t",
                        "REG_DWORD",
                        "/d",
                        &v.to_string(),
                        "/f",
                        "/reg:64",
                    ],
                ),
                None => run(
                    "reg.exe",
                    &["delete", &key, "/v", CMDLINE_VALUE, "/f", "/reg:64"],
                ),
            }
        }
    }

    fn receipt_path() -> PathBuf {
        crate::paths::state_dir().join("audit_baseline.json")
    }

    fn load_receipt() -> Receipt {
        std::fs::read(receipt_path())
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default()
    }

    /// `trapd-agent.exe audit-baseline apply|restore`
    pub fn run_cli(verb: Option<&str>) -> Result<()> {
        crate::paths::init_state_dir();
        let mut host = WindowsHost;
        match verb {
            Some("apply") => {
                let receipt = apply(&mut host, load_receipt())?;
                std::fs::write(receipt_path(), serde_json::to_vec(&receipt)?)
                    .context("record audit baseline receipt")
            }
            Some("restore") => {
                restore(&mut host, load_receipt())?;
                match std::fs::remove_file(receipt_path()) {
                    Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e.into()),
                    _ => Ok(()),
                }
            }
            _ => bail!("usage: trapd-agent.exe audit-baseline apply|restore"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::anyhow;

    #[derive(Default)]
    struct Fake {
        audit: bool,
        cmdline: Option<u32>,
        fail_audit_set: bool,
        writes: Vec<String>,
    }

    impl Host for Fake {
        fn audit_success(&self) -> Result<bool> {
            Ok(self.audit)
        }
        fn set_audit_success(&mut self, on: bool) -> Result<()> {
            self.writes.push(format!("audit={on}"));
            if self.fail_audit_set {
                return Err(anyhow!("denied"));
            }
            self.audit = on;
            Ok(())
        }
        fn cmdline(&self) -> Result<Option<u32>> {
            Ok(self.cmdline)
        }
        fn set_cmdline(&mut self, value: Option<u32>) -> Result<()> {
            self.writes.push(format!("cmdline={value:?}"));
            self.cmdline = value;
            Ok(())
        }
    }

    #[test]
    fn fresh_host_gets_both_settings_and_a_full_receipt() {
        let mut host = Fake::default();
        let receipt = apply(&mut host, Receipt::default()).unwrap();
        assert!(host.audit && host.cmdline == Some(1));
        assert_eq!(
            receipt,
            Receipt {
                set_audit_success: true,
                set_cmdline: true,
                prev_cmdline: None,
            }
        );
    }

    #[test]
    fn settings_the_admin_already_enabled_are_not_touched_or_claimed() {
        let mut host = Fake {
            audit: true,
            cmdline: Some(1),
            ..Default::default()
        };
        let receipt = apply(&mut host, Receipt::default()).unwrap();
        assert!(host.writes.is_empty());
        assert_eq!(receipt, Receipt::default());
        restore(&mut host, receipt).unwrap();
        assert!(
            host.writes.is_empty(),
            "must not revert the admin's setting"
        );
        assert!(host.audit && host.cmdline == Some(1));
    }

    #[test]
    fn a_previous_explicit_zero_is_restored_not_deleted() {
        let mut host = Fake {
            cmdline: Some(0),
            ..Default::default()
        };
        let receipt = apply(&mut host, Receipt::default()).unwrap();
        assert_eq!(host.cmdline, Some(1));
        restore(&mut host, receipt).unwrap();
        assert_eq!(host.cmdline, Some(0));
        assert!(!host.audit);
    }

    #[test]
    fn restore_returns_a_fresh_host_to_its_original_state() {
        let mut host = Fake::default();
        let receipt = apply(&mut host, Receipt::default()).unwrap();
        restore(&mut host, receipt).unwrap();
        assert!(!host.audit);
        assert_eq!(host.cmdline, None);
    }

    #[test]
    fn upgrade_keeps_ownership_recorded_by_the_first_install() {
        let mut host = Fake::default();
        let first = apply(&mut host, Receipt::default()).unwrap();
        // A second apply (upgrade/repair) sees both settings on already.
        let second = apply(&mut host, first).unwrap();
        assert_eq!(second, first);
        restore(&mut host, second).unwrap();
        assert!(!host.audit && host.cmdline.is_none());
    }

    #[test]
    fn restore_leaves_a_setting_the_admin_changed_since() {
        let mut host = Fake::default();
        let receipt = apply(&mut host, Receipt::default()).unwrap();
        host.cmdline = Some(0); // admin deliberately turned it off afterwards
        host.writes.clear();
        restore(&mut host, receipt).unwrap();
        assert!(!host.writes.iter().any(|w| w.starts_with("cmdline")));
        assert_eq!(host.cmdline, Some(0));
    }

    #[test]
    fn failed_audit_change_does_not_pretend_to_own_it_and_stops_before_cmdline() {
        let mut host = Fake {
            fail_audit_set: true,
            ..Default::default()
        };
        assert!(apply(&mut host, Receipt::default()).is_err());
        assert_eq!(host.cmdline, None, "no half-applied command-line policy");
    }

    #[test]
    fn restore_attempts_both_reverts_and_reports_the_first_error() {
        let mut host = Fake {
            audit: true,
            cmdline: Some(1),
            fail_audit_set: true,
            ..Default::default()
        };
        let receipt = Receipt {
            set_audit_success: true,
            set_cmdline: true,
            prev_cmdline: None,
        };
        assert!(restore(&mut host, receipt).is_err());
        assert_eq!(host.cmdline, None, "command-line revert must still run");
    }
}
