//! Installer-owned audit baseline: command lines and honeytoken accessors.
//!
//! Two detections depend on Windows audit settings the agent must not change at
//! runtime:
//!
//! * Command lines of short-lived processes. ETW reads a command line from the
//!   live process, so a one-shot `cmd /c ...` that exits first has none (field
//!   test F3). Event 4688 carries it reliably but needs "Audit Process
//!   Creation: Success" and `ProcessCreationIncludeCmdLine_Enabled=1`.
//! * Who opened a honeytoken. The decoy carries a read-audit SACL, but Security
//!   event 4663 (process and account) only fires when "Audit File System:
//!   Success" is on; otherwise the accessor stays `unknown` and the detection
//!   falls back to the last-access timestamp. The setting only produces events
//!   for objects that carry a SACL, i.e. our decoys.
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

/// The audit subcategories this module may turn on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Audit {
    ProcessCreation,
    FileSystem,
}

const AUDITS: [Audit; 2] = [Audit::ProcessCreation, Audit::FileSystem];

/// What this module changed, persisted between install and removal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Receipt {
    /// We switched "Audit Process Creation: Success" on.
    #[serde(alias = "set_audit_success")]
    pub set_process_audit: bool,
    /// We switched "Audit File System: Success" on (absent in older receipts).
    #[serde(default)]
    pub set_file_audit: bool,
    /// We wrote the command-line policy value.
    pub set_cmdline: bool,
    /// The command-line value before we wrote it (`None` = it did not exist).
    pub prev_cmdline: Option<u32>,
}

impl Receipt {
    fn owns(&self, audit: Audit) -> bool {
        match audit {
            Audit::ProcessCreation => self.set_process_audit,
            Audit::FileSystem => self.set_file_audit,
        }
    }

    fn set_owned(&mut self, audit: Audit, owned: bool) {
        match audit {
            Audit::ProcessCreation => self.set_process_audit = owned,
            Audit::FileSystem => self.set_file_audit = owned,
        }
    }
}

/// The machine settings, abstracted so the decisions are testable.
pub trait Host {
    /// Whether the subcategory currently audits success.
    fn audit_success(&self, audit: Audit) -> Result<bool>;
    fn set_audit_success(&mut self, audit: Audit, on: bool) -> Result<()>;
    /// `ProcessCreationIncludeCmdLine_Enabled`, `None` when absent.
    fn cmdline(&self) -> Result<Option<u32>>;
    fn set_cmdline(&mut self, value: Option<u32>) -> Result<()>;
}

/// Turn on whatever is missing. Safe to repeat (upgrade, repair): ownership
/// recorded by an earlier run is kept while the setting is still on.
pub fn apply(host: &mut dyn Host, prior: Receipt) -> Result<Receipt> {
    let mut receipt = Receipt::default();

    for audit in AUDITS {
        if host.audit_success(audit)? {
            receipt.set_owned(audit, prior.owns(audit));
        } else {
            host.set_audit_success(audit, true)?;
            receipt.set_owned(audit, true);
        }
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
    let mut first_error = None;
    let mut note = |result: Result<()>| {
        if let Err(e) = result {
            first_error.get_or_insert(e);
        }
    };
    for audit in AUDITS {
        note((|| {
            if receipt.owns(audit) && host.audit_success(audit)? {
                host.set_audit_success(audit, false)?;
            }
            Ok(())
        })());
    }
    note((|| {
        if receipt.set_cmdline && host.cmdline()? == Some(1) {
            host.set_cmdline(receipt.prev_cmdline)?;
        }
        Ok(())
    })());
    match first_error {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

#[cfg(windows)]
pub use windows_host::run_cli;

#[cfg(windows)]
mod windows_host {
    use super::{apply, restore, Host, Receipt};
    use anyhow::{anyhow, bail, Context, Result};
    use std::path::PathBuf;
    use std::process::Command;

    use super::Audit;

    fn guid(audit: Audit) -> &'static str {
        match audit {
            Audit::ProcessCreation => "{0CCE922B-69AE-11D9-BED3-505054503030}",
            Audit::FileSystem => "{0CCE921D-69AE-11D9-BED3-505054503030}",
        }
    }

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
        fn audit_success(&self, audit: Audit) -> Result<bool> {
            use crate::collectors::windows::decoy_audit;
            match audit {
                Audit::ProcessCreation => decoy_audit::process_audit_enabled(),
                Audit::FileSystem => decoy_audit::file_audit_enabled(),
            }
            .ok_or_else(|| anyhow!("cannot query the {audit:?} audit policy"))
        }

        fn set_audit_success(&mut self, audit: Audit, on: bool) -> Result<()> {
            let flag = if on {
                "/success:enable"
            } else {
                "/success:disable"
            };
            run(
                "auditpol.exe",
                &["/set", &format!("/subcategory:{}", guid(audit)), flag],
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
        process_audit: bool,
        file_audit: bool,
        cmdline: Option<u32>,
        /// Fail every change to this subcategory.
        fail_on: Option<Audit>,
        writes: Vec<String>,
    }

    impl Fake {
        fn flag(&mut self, audit: Audit) -> &mut bool {
            match audit {
                Audit::ProcessCreation => &mut self.process_audit,
                Audit::FileSystem => &mut self.file_audit,
            }
        }
    }

    impl Host for Fake {
        fn audit_success(&self, audit: Audit) -> Result<bool> {
            Ok(match audit {
                Audit::ProcessCreation => self.process_audit,
                Audit::FileSystem => self.file_audit,
            })
        }
        fn set_audit_success(&mut self, audit: Audit, on: bool) -> Result<()> {
            self.writes.push(format!("{audit:?}={on}"));
            if self.fail_on == Some(audit) {
                return Err(anyhow!("denied"));
            }
            *self.flag(audit) = on;
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

    fn everything_on() -> Fake {
        Fake {
            process_audit: true,
            file_audit: true,
            cmdline: Some(1),
            ..Default::default()
        }
    }

    #[test]
    fn fresh_host_gets_every_setting_and_a_full_receipt() {
        let mut host = Fake::default();
        let receipt = apply(&mut host, Receipt::default()).unwrap();
        assert!(host.process_audit && host.file_audit && host.cmdline == Some(1));
        assert_eq!(
            receipt,
            Receipt {
                set_process_audit: true,
                set_file_audit: true,
                set_cmdline: true,
                prev_cmdline: None,
            }
        );
    }

    #[test]
    fn honeytoken_accessors_need_file_system_auditing() {
        // The decoy's read-audit SACL only produces event 4663 (process and
        // account) when this subcategory is on.
        let mut host = Fake {
            process_audit: true,
            cmdline: Some(1),
            ..Default::default()
        };
        let receipt = apply(&mut host, Receipt::default()).unwrap();
        assert!(host.file_audit);
        assert_eq!(host.writes, vec!["FileSystem=true"]);
        assert!(receipt.set_file_audit && !receipt.set_process_audit);
    }

    #[test]
    fn settings_the_admin_already_enabled_are_not_touched_or_claimed() {
        let mut host = everything_on();
        let receipt = apply(&mut host, Receipt::default()).unwrap();
        assert!(host.writes.is_empty());
        assert_eq!(receipt, Receipt::default());
        restore(&mut host, receipt).unwrap();
        assert!(
            host.writes.is_empty(),
            "must not revert the admin's setting"
        );
        assert!(host.process_audit && host.file_audit && host.cmdline == Some(1));
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
        assert!(!host.process_audit && !host.file_audit);
    }

    #[test]
    fn restore_returns_a_fresh_host_to_its_original_state() {
        let mut host = Fake::default();
        let receipt = apply(&mut host, Receipt::default()).unwrap();
        restore(&mut host, receipt).unwrap();
        assert!(!host.process_audit && !host.file_audit);
        assert_eq!(host.cmdline, None);
    }

    #[test]
    fn upgrade_keeps_ownership_recorded_by_the_first_install() {
        let mut host = Fake::default();
        let first = apply(&mut host, Receipt::default()).unwrap();
        // A second apply (upgrade/repair) sees every setting on already.
        let second = apply(&mut host, first).unwrap();
        assert_eq!(second, first);
        restore(&mut host, second).unwrap();
        assert!(!host.process_audit && !host.file_audit && host.cmdline.is_none());
    }

    #[test]
    fn restore_leaves_a_setting_the_admin_changed_since() {
        let mut host = Fake::default();
        let receipt = apply(&mut host, Receipt::default()).unwrap();
        host.cmdline = Some(0); // admin deliberately turned it off afterwards
        host.file_audit = false;
        host.writes.clear();
        restore(&mut host, receipt).unwrap();
        assert!(!host.writes.iter().any(|w| w.starts_with("cmdline")));
        assert!(!host.writes.iter().any(|w| w.starts_with("FileSystem")));
        assert_eq!(host.cmdline, Some(0));
    }

    #[test]
    fn failed_audit_change_does_not_pretend_to_own_it_and_stops_before_cmdline() {
        let mut host = Fake {
            fail_on: Some(Audit::ProcessCreation),
            ..Default::default()
        };
        assert!(apply(&mut host, Receipt::default()).is_err());
        assert_eq!(host.cmdline, None, "no half-applied command-line policy");
    }

    #[test]
    fn restore_attempts_every_revert_and_reports_the_first_error() {
        let mut host = everything_on();
        host.fail_on = Some(Audit::ProcessCreation);
        let receipt = Receipt {
            set_process_audit: true,
            set_file_audit: true,
            set_cmdline: true,
            prev_cmdline: None,
        };
        assert!(restore(&mut host, receipt).is_err());
        assert!(!host.file_audit, "file-system revert must still run");
        assert_eq!(host.cmdline, None, "command-line revert must still run");
    }

    #[test]
    fn a_receipt_written_before_file_auditing_existed_still_loads() {
        let old = r#"{"set_audit_success":true,"set_cmdline":true,"prev_cmdline":null}"#;
        let receipt: Receipt = serde_json::from_str(old).unwrap();
        assert!(receipt.set_process_audit && !receipt.set_file_audit && receipt.set_cmdline);
    }
}
