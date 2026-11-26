//! `kernel.perf_event_paranoid` handling for package install and removal.
//!
//! Ubuntu kernels default to level 4, a distribution patch that refuses every
//! `perf_event_open` without CAP_SYS_ADMIN. aya attaches tracepoints and
//! kprobes through `perf_event_open`, so under the packaged unit (CAP_BPF and
//! CAP_PERFMON, no CAP_SYS_ADMIN) every eBPF collector fails with EACCES
//! (issue #216). Level 3 still blocks perf for unprivileged users entirely but
//! accepts CAP_PERFMON, which is what the agent holds. Lowering 4 to 3 is
//! therefore preferred over granting the agent CAP_SYS_ADMIN.
//!
//! `trapd-agent perf-sysctl apply` runs from the package postinst and
//! `install.sh`; `trapd-agent perf-sysctl revert` runs from the prerm on
//! removal. Only a host at level 4 or higher is changed, the previous value is
//! recorded in the drop-in, and revert restores it.

use std::fs;
use std::io::Write;
use std::path::Path;

use anyhow::{bail, Context, Result};

pub const PROC_PATH: &str = "/proc/sys/kernel/perf_event_paranoid";
pub const DROPIN_PATH: &str = "/etc/sysctl.d/60-trapd-perf.conf";

/// Highest level at which CAP_PERFMON is enough to attach.
const TARGET_LEVEL: i32 = 3;
const PREVIOUS_MARKER: &str = "# trapd-previous-value: ";

#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Host already allows CAP_PERFMON; nothing written.
    Unchanged,
    /// Drop-in written (or kept) and the running value set to 3.
    Lowered { previous: i32 },
    /// Drop-in written, but the running value could not be changed (read-only
    /// /proc, for example in a container); applies at next boot.
    PersistedOnly { previous: i32 },
    /// Drop-in removed, running value restored.
    Restored { value: i32 },
    /// Drop-in removed, running value left as it was.
    Removed,
}

fn read_level(proc_path: &Path) -> Result<i32> {
    let raw =
        fs::read_to_string(proc_path).with_context(|| format!("read {}", proc_path.display()))?;
    raw.trim()
        .parse()
        .with_context(|| format!("parse {}: {raw:?}", proc_path.display()))
}

/// Refuse to follow or replace anything but a regular file at the drop-in path.
fn dropin_exists(dropin: &Path) -> Result<bool> {
    match fs::symlink_metadata(dropin) {
        Ok(m) if m.file_type().is_file() => Ok(true),
        Ok(_) => bail!(
            "{} is not a regular file; refusing to touch it",
            dropin.display()
        ),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e).with_context(|| format!("stat {}", dropin.display())),
    }
}

fn previous_value(dropin: &Path) -> Option<i32> {
    let text = fs::read_to_string(dropin).ok()?;
    text.lines()
        .find_map(|l| l.strip_prefix(PREVIOUS_MARKER))
        .and_then(|v| v.trim().parse().ok())
        // Only a value this module would have replaced is restored.
        .filter(|v| (TARGET_LEVEL + 1..=10).contains(v))
}

fn write_dropin(dropin: &Path, previous: i32) -> Result<()> {
    let dir = dropin.parent().context("drop-in path has no parent")?;
    let tmp = dir.join(format!(".60-trapd-perf.conf.{}", std::process::id()));
    let body = format!(
        "# Written by the TRAPD agent package. The agent attaches eBPF tracepoints\n\
         # with CAP_PERFMON; level {previous} requires CAP_SYS_ADMIN instead. Level 3\n\
         # still denies perf to unprivileged users. Removed again on uninstall.\n\
         {PREVIOUS_MARKER}{previous}\n\
         kernel.perf_event_paranoid = {TARGET_LEVEL}\n"
    );
    let result = (|| -> Result<()> {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)
            .with_context(|| format!("create {}", tmp.display()))?;
        f.write_all(body.as_bytes())?;
        f.sync_all()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&tmp, fs::Permissions::from_mode(0o644))?;
        }
        fs::rename(&tmp, dropin).with_context(|| format!("install {}", dropin.display()))
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

/// Lower a level of 4 or more to 3, persistently. Idempotent.
pub fn apply(proc_path: &Path, dropin: &Path) -> Result<Outcome> {
    let current = read_level(proc_path)?;
    if dropin_exists(dropin)? {
        // Re-run (upgrade): the drop-in is already in place. The running value
        // is left alone so an operator who overrides it with a later sysctl.d
        // file (to keep level 4) is not overruled on every upgrade.
        return Ok(Outcome::Unchanged);
    }
    if current <= TARGET_LEVEL {
        return Ok(Outcome::Unchanged);
    }
    write_dropin(dropin, current)?;
    let previous = current;
    match fs::write(proc_path, format!("{TARGET_LEVEL}\n")) {
        Ok(()) => Ok(Outcome::Lowered { previous }),
        Err(_) => Ok(Outcome::PersistedOnly { previous }),
    }
}

/// Remove the drop-in and restore the recorded level if nobody changed the
/// running value since. Idempotent.
pub fn revert(proc_path: &Path, dropin: &Path) -> Result<Outcome> {
    if !dropin_exists(dropin)? {
        return Ok(Outcome::Unchanged);
    }
    let previous = previous_value(dropin);
    fs::remove_file(dropin).with_context(|| format!("remove {}", dropin.display()))?;
    let current = read_level(proc_path).ok();
    match previous {
        Some(value) if current == Some(TARGET_LEVEL) => {
            match fs::write(proc_path, format!("{value}\n")) {
                Ok(()) => Ok(Outcome::Restored { value }),
                Err(_) => Ok(Outcome::Removed),
            }
        }
        _ => Ok(Outcome::Removed),
    }
}

/// Entry point for `trapd-agent perf-sysctl <apply|revert>`.
pub fn run(args: &[String]) -> Result<()> {
    let proc_path = Path::new(PROC_PATH);
    let dropin = Path::new(DROPIN_PATH);
    let outcome = match args.first().map(String::as_str) {
        Some("apply") => apply(proc_path, dropin)?,
        Some("revert") => revert(proc_path, dropin)?,
        _ => bail!("usage: trapd-agent perf-sysctl <apply|revert>"),
    };
    let msg = match outcome {
        Outcome::Unchanged => "kernel.perf_event_paranoid: no change needed".to_string(),
        Outcome::Lowered { previous } => format!(
            "kernel.perf_event_paranoid: lowered from {previous} to {TARGET_LEVEL} ({DROPIN_PATH})"
        ),
        Outcome::PersistedOnly { previous } => format!(
            "kernel.perf_event_paranoid: {DROPIN_PATH} written (from {previous} to {TARGET_LEVEL}); \
             the running value could not be changed and applies at next boot"
        ),
        Outcome::Restored { value } => {
            format!("kernel.perf_event_paranoid: restored to {value}, {DROPIN_PATH} removed")
        }
        Outcome::Removed => format!("kernel.perf_event_paranoid: {DROPIN_PATH} removed"),
    };
    println!("{msg}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Host {
        dir: std::path::PathBuf,
        proc_path: std::path::PathBuf,
        dropin: std::path::PathBuf,
    }

    impl Drop for Host {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.dir);
        }
    }

    fn host(level: &str) -> Host {
        let dir = std::env::temp_dir().join(format!("trapd-perf-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&dir).unwrap();
        let proc_path = dir.join("perf_event_paranoid");
        fs::write(&proc_path, level).unwrap();
        let dropin = dir.join("60-trapd-perf.conf");
        Host {
            dir,
            proc_path,
            dropin,
        }
    }

    fn level(h: &Host) -> String {
        fs::read_to_string(&h.proc_path).unwrap().trim().to_string()
    }

    #[test]
    fn hosts_that_already_allow_perfmon_are_left_alone() {
        for l in ["-1", "1", "2", "3"] {
            let h = host(l);
            assert_eq!(apply(&h.proc_path, &h.dropin).unwrap(), Outcome::Unchanged);
            assert!(!h.dropin.exists());
            assert_eq!(level(&h), l);
        }
    }

    #[test]
    fn level_four_is_lowered_and_restored_on_revert() {
        let h = host("4\n");
        assert_eq!(
            apply(&h.proc_path, &h.dropin).unwrap(),
            Outcome::Lowered { previous: 4 }
        );
        assert_eq!(level(&h), "3");
        let text = fs::read_to_string(&h.dropin).unwrap();
        assert!(text.contains("kernel.perf_event_paranoid = 3"));
        assert!(text.contains("# trapd-previous-value: 4"));

        // Upgrade: runs again with the value already lowered.
        assert_eq!(apply(&h.proc_path, &h.dropin).unwrap(), Outcome::Unchanged);
        assert!(fs::read_to_string(&h.dropin)
            .unwrap()
            .contains("previous-value: 4"));

        assert_eq!(
            revert(&h.proc_path, &h.dropin).unwrap(),
            Outcome::Restored { value: 4 }
        );
        assert!(!h.dropin.exists());
        assert_eq!(level(&h), "4");
        assert_eq!(revert(&h.proc_path, &h.dropin).unwrap(), Outcome::Unchanged);
    }

    #[test]
    fn an_upgrade_does_not_overrule_an_operator_who_kept_level_four() {
        let h = host("4");
        apply(&h.proc_path, &h.dropin).unwrap();
        // Operator: a later sysctl.d file sets 4 again, applied at boot.
        fs::write(&h.proc_path, "4").unwrap();
        assert_eq!(apply(&h.proc_path, &h.dropin).unwrap(), Outcome::Unchanged);
        assert_eq!(level(&h), "4");
    }

    #[test]
    fn revert_keeps_an_operator_change() {
        let h = host("4");
        apply(&h.proc_path, &h.dropin).unwrap();
        fs::write(&h.proc_path, "2").unwrap();
        assert_eq!(revert(&h.proc_path, &h.dropin).unwrap(), Outcome::Removed);
        assert_eq!(level(&h), "2");
    }

    #[test]
    fn a_tampered_previous_value_is_not_restored() {
        let h = host("3");
        fs::write(
            &h.dropin,
            "# trapd-previous-value: -1\nkernel.perf_event_paranoid = 3\n",
        )
        .unwrap();
        assert_eq!(revert(&h.proc_path, &h.dropin).unwrap(), Outcome::Removed);
        assert_eq!(level(&h), "3");
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_at_the_dropin_path_is_refused() {
        let h = host("4");
        let target = h.dropin.with_file_name("elsewhere");
        fs::write(&target, "keep").unwrap();
        std::os::unix::fs::symlink(&target, &h.dropin).unwrap();
        assert!(apply(&h.proc_path, &h.dropin).is_err());
        assert!(revert(&h.proc_path, &h.dropin).is_err());
        assert_eq!(fs::read_to_string(&target).unwrap(), "keep");
        assert_eq!(level(&h), "4");
    }

    #[test]
    fn unparsable_level_is_an_error_not_a_change() {
        let h = host("garbage");
        assert!(apply(&h.proc_path, &h.dropin).is_err());
        assert!(!h.dropin.exists());
    }
}
