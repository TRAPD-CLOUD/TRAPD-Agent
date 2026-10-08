//! Process termination + post-exec policy enforcement.
//!
//! Two roles:
//!
//!   1. **Active kill** — `kill_pid()` sends SIGKILL to a PID, used by both
//!      operator-issued `kill_pid` commands and IoC-rule hits.
//!   2. **Post-exec enforcement** — on every `ExecEventData` we evaluate the
//!      current `PolicyStore`.  A `Block` match means the process is killed
//!      *immediately*; an `Alert` match emits an event but lets it run.
//!
//! Real-time kernel-side blocking (before execve completes) is handled
//! separately by the eBPF program in `trapd-agent-ebpf/src/process_block.rs`
//! via `bpf_send_signal(SIGKILL)`.  This userspace path is a defence-in-depth
//! backup: it catches any rule that the kernel-side map didn't have indexed
//! (e.g. SHA256 rules where the userspace hash hadn't been resolved to an
//! inode yet) and is the only path on kernels < 5.3.

#[cfg(target_os = "linux")]
use anyhow::Context;
use anyhow::Result;
use tracing::{debug, info, warn};

use crate::schema::ExecEventData;

use super::audit::AuditEmitter;
use super::policy::{Match, PolicyHandle, RuleAction};

/// Send SIGKILL to the given PID.  Errors if the process is gone or we lack
/// permission (in which case the audit event records `success=false`).
#[cfg(target_os = "linux")]
pub fn kill_pid(pid: i32) -> Result<()> {
    use nix::sys::signal::{kill, Signal};
    use nix::unistd::Pid;
    kill(Pid::from_raw(pid), Signal::SIGKILL).with_context(|| format!("SIGKILL pid={pid} failed"))
}

#[cfg(windows)]
pub fn kill_pid(pid: i32) -> Result<()> {
    super::winproc::terminate(pid, crate::telemetry::identity::process_start_time(pid))
}

#[cfg(not(any(target_os = "linux", windows)))]
pub fn kill_pid(_pid: i32) -> Result<()> {
    anyhow::bail!("process kill is not implemented on this platform")
}

/// Kill the process an exec event describes. Where the event carries the
/// process start time (Windows) the kill is bound to that identity, so a PID
/// reused since the event cannot be hit.
fn kill_exec(exec: &ExecEventData) -> Result<()> {
    kill_observed(exec.pid, exec.process_start_time)
}

/// Control exactly the observed process generation. Unknown identity fails closed.
pub fn kill_observed(pid: i32, observed_start: Option<u64>) -> Result<()> {
    #[cfg(windows)]
    {
        super::winproc::terminate(pid, observed_start)
    }
    #[cfg(target_os = "linux")]
    {
        signal_observed(pid, observed_start, libc::SIGKILL)
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        let _ = (pid, observed_start);
        anyhow::bail!("process control unsupported")
    }
}

pub fn freeze_observed(pid: i32, observed_start: Option<u64>) -> Result<()> {
    #[cfg(windows)]
    {
        super::winproc::suspend(pid, observed_start)
    }
    #[cfg(target_os = "linux")]
    {
        signal_observed(pid, observed_start, libc::SIGSTOP)
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        let _ = (pid, observed_start);
        anyhow::bail!("process control unsupported")
    }
}

#[cfg(target_os = "linux")]
fn signal_observed(pid: i32, observed_start: Option<u64>, signal: i32) -> Result<()> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    let expected = observed_start
        .filter(|t| *t > 0)
        .ok_or_else(|| anyhow::anyhow!("unknown observed identity for pid {pid}; refusing"))?;
    anyhow::ensure!(
        pid > 1 && pid != std::process::id() as i32,
        "unsafe target pid {pid}"
    );
    // Open the generation-stable kernel reference BEFORE the comparison. If
    // reuse occurs before opening the start check rejects it; after opening the
    // pidfd cannot address a replacement. Old kernels fail closed.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error()).context("pidfd_open");
    }
    // SAFETY: successful pidfd_open transferred one valid owned descriptor.
    let fd = unsafe { OwnedFd::from_raw_fd(fd as i32) };
    anyhow::ensure!(
        crate::telemetry::identity::process_start_time(pid) == Some(expected),
        "pid {pid} belongs to a different or unknown process; refusing"
    );
    // SAFETY: valid pidfd, signal, no siginfo and no flags.
    if unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            fd.as_raw_fd(),
            signal,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        )
    } < 0
    {
        return Err(std::io::Error::last_os_error()).context("pidfd_send_signal");
    }
    Ok(())
}

/// Freeze a process by sending SIGSTOP — the "jail" response. The process is
/// suspended (not killed), so it cannot react or destroy evidence while a
/// snapshot is taken and an operator decides what to do ("freeze, snapshot, then
/// decide" — issue #32, point 5). Resume with [`thaw_pid`].
#[cfg(target_os = "linux")]
pub fn freeze_pid(pid: i32) -> Result<()> {
    use nix::sys::signal::{kill, Signal};
    use nix::unistd::Pid;
    kill(Pid::from_raw(pid), Signal::SIGSTOP).with_context(|| format!("SIGSTOP pid={pid} failed"))
}

#[cfg(windows)]
pub fn freeze_pid(pid: i32) -> Result<()> {
    super::winproc::suspend(pid, crate::telemetry::identity::process_start_time(pid))
}

#[cfg(not(any(target_os = "linux", windows)))]
pub fn freeze_pid(_pid: i32) -> Result<()> {
    anyhow::bail!("process freeze is not implemented on this platform")
}

/// Resume a previously-frozen process by sending SIGCONT.
#[cfg(target_os = "linux")]
pub fn thaw_pid(pid: i32) -> Result<()> {
    use nix::sys::signal::{kill, Signal};
    use nix::unistd::Pid;
    kill(Pid::from_raw(pid), Signal::SIGCONT).with_context(|| format!("SIGCONT pid={pid} failed"))
}

#[cfg(windows)]
pub fn thaw_pid(pid: i32) -> Result<()> {
    super::winproc::resume(pid, crate::telemetry::identity::process_start_time(pid))
}

#[cfg(not(any(target_os = "linux", windows)))]
pub fn thaw_pid(_pid: i32) -> Result<()> {
    anyhow::bail!("process thaw is not implemented on this platform")
}

/// Look up the parent's comm by PPID.
fn parent_comm(ppid: i32) -> Option<String> {
    if ppid <= 0 {
        return None;
    }
    #[cfg(windows)]
    {
        super::winproc::image_name(ppid)
    }
    #[cfg(not(windows))]
    {
        let raw = std::fs::read_to_string(format!("/proc/{ppid}/comm")).ok()?;
        Some(raw.trim().to_string())
    }
}

/// Digest for a policy check when the collector supplied none. Linux can hash
/// the image on demand; on Windows the process sensor already hashes every image
/// it reports (size-capped, cached per path and mtime), so a missing digest
/// means "unhashable" and an on-demand re-read would only race the process.
fn fallback_digest(exe: &str) -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        crate::collectors::linux::exehash::hash_for_policy(exe)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = exe;
        None
    }
}

/// View a Windows process-creation event as an exec event, so the policy engine
/// has exactly one enforcement path on both platforms. `comm` is the image file
/// name, the Windows analogue of the Linux process name.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn exec_from_create(create: &crate::schema::ProcessCreateData) -> ExecEventData {
    ExecEventData {
        pid: create.pid,
        ppid: create.ppid,
        uid: create.uid,
        username: create.username.clone(),
        comm: create.name.clone(),
        exe: create.exe.clone(),
        cmdline: create.cmdline.clone(),
        exe_sha256: create.exe_sha256.clone(),
        process_start_time: create.process_start_time,
        ..Default::default()
    }
}

/// Enforce the current policy against a freshly-execed process.  Returns
/// `Some(rule_id)` if the process was killed.
pub fn enforce_exec(
    exec: &ExecEventData,
    policy: &PolicyHandle,
    audit: &AuditEmitter,
) -> Option<String> {
    let needs_hash = policy.read().has_sha256_rules();
    let sha = if needs_hash {
        // The collector's digest identifies the executable observed at exec;
        // reopening its path can race an exit, unlink or replacement.
        exec.exe_sha256
            .as_ref()
            .filter(|hash| hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit()))
            .cloned()
            .or_else(|| fallback_digest(&exec.exe))
    } else {
        None
    };

    // The parent's name is only needed to evaluate parent/child rules; look it up
    // before matching just when such a rule exists, and for the audit record
    // after a match otherwise.
    let mut parent = if policy.read().has_parent_child_rules() {
        parent_comm(exec.ppid)
    } else {
        None
    };

    let m: Option<Match> =
        policy
            .read()
            .match_exec(&exec.exe, &exec.comm, parent.as_deref(), sha.as_deref());

    let m = m?;
    if parent.is_none() {
        parent = parent_comm(exec.ppid);
    }

    let details = serde_json::json!({
        "pid":     exec.pid,
        "ppid":    exec.ppid,
        "uid":     exec.uid,
        "comm":    exec.comm,
        "exe":     exec.exe,
        "cmdline": exec.cmdline,
        "sha256":  sha,
        "parent_comm": parent,
    });

    match m.action {
        RuleAction::Block => {
            let killed = kill_exec(exec).is_ok();
            if killed {
                info!(pid = exec.pid, exe = %exec.exe, rule = %m.rule_id, "blocked process by policy");
            } else {
                warn!(pid = exec.pid, exe = %exec.exe, rule = %m.rule_id, "kill failed (process may already be gone)");
            }
            audit.emit(
                crate::schema::EventAction::ProcessBlocked,
                if killed {
                    crate::schema::Severity::High
                } else {
                    crate::schema::Severity::Medium
                },
                "process_block",
                exec.pid.to_string(),
                killed,
                m.reason.clone(),
                Some(m.rule_id.clone()),
                None,
                details,
            );
            Some(m.rule_id)
        }
        RuleAction::Alert => {
            debug!(pid = exec.pid, exe = %exec.exe, rule = %m.rule_id, "exec alert (no block)");
            audit.emit(
                crate::schema::EventAction::ProcessBlocked,
                crate::schema::Severity::Medium,
                "process_alert",
                exec.pid.to_string(),
                true,
                m.reason.clone(),
                Some(m.rule_id.clone()),
                None,
                details,
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::policy::{IocRule, PolicyStore};
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn observed_kill_rejects_unknown_and_stale_generations() {
        let mut child = std::process::Command::new("sleep")
            .arg("60")
            .spawn()
            .unwrap();
        let pid = child.id() as i32;
        let start = crate::telemetry::identity::process_start_time(pid).unwrap();
        assert!(kill_observed(pid, None).is_err());
        assert!(kill_observed(pid, Some(start + 1)).is_err());
        assert!(
            child.try_wait().unwrap().is_none(),
            "unrelated generation must survive"
        );
        kill_observed(pid, Some(start)).expect("terminate exact generation using pidfd");
        assert!(!child.wait().unwrap().success());
    }

    #[test]
    fn comm_only_policy_does_not_hash_executables() {
        let policy = PolicyHandle::new(
            PolicyStore::from_rules(vec![IocRule::Comm {
                id: "comm-alert".into(),
                value: "fixture".into(),
                action: RuleAction::Alert,
            }])
            .unwrap(),
        );
        let (tx, mut rx) = tokio::sync::mpsc::channel(4);
        let audit = AuditEmitter::new(tx, "agent".into(), "host".into());
        let exec = ExecEventData {
            pid: i32::MAX,
            comm: "fixture".into(),
            exe: std::env::current_exe()
                .unwrap()
                .to_string_lossy()
                .into_owned(),
            ..Default::default()
        };
        enforce_exec(&exec, &policy, &audit);
        match rx.try_recv().expect("comm rule should audit").data {
            crate::schema::EventData::Prevention(data) => assert!(
                data.details["sha256"].is_null(),
                "comm-only policy must not perform a redundant disk hash"
            ),
            other => panic!("unexpected event: {other:?}"),
        }
    }

    #[test]
    fn hash_policy_uses_collected_digest_when_executable_has_exited() {
        let policy = PolicyHandle::new(
            PolicyStore::from_rules(vec![IocRule::Sha256 {
                id: "hash-alert".into(),
                value: "ab".repeat(32),
                action: RuleAction::Alert,
            }])
            .unwrap(),
        );
        let (tx, mut rx) = tokio::sync::mpsc::channel(4);
        let audit = AuditEmitter::new(tx, "agent".into(), "host".into());
        let exec = ExecEventData {
            pid: i32::MAX,
            exe: "/nonexistent/trapd-digest-fixture".into(),
            exe_sha256: Some("ab".repeat(32)),
            ..Default::default()
        };
        assert!(enforce_exec(&exec, &policy, &audit).is_none());
        let event = rx
            .try_recv()
            .expect("collected SHA256 must still match the policy");
        match event.data {
            crate::schema::EventData::Prevention(data) => {
                assert_eq!(data.kind, "process_alert");
                assert_eq!(data.rule_id.as_deref(), Some("hash-alert"));
            }
            other => panic!("unexpected event: {other:?}"),
        }
    }
}

#[cfg(all(test, windows))]
mod windows_tests {
    use super::super::policy::{IocRule, PolicyStore};
    use super::*;
    use std::process::{Command, Stdio};

    /// End to end on a real process: a Block rule written the way a Linux
    /// operator would (lower-case name) kills the Windows image, bound to the
    /// creation identity the process sensor reported.
    #[test]
    fn a_block_rule_kills_the_matching_process_and_audits_it() {
        let mut child = Command::new("ping")
            .args(["-n", "60", "127.0.0.1"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let pid = child.id() as i32;
        let policy = PolicyHandle::new(
            PolicyStore::from_rules(vec![IocRule::Comm {
                id: "block-ping".into(),
                value: "ping.exe".into(),
                action: RuleAction::Block,
            }])
            .unwrap(),
        );
        let (tx, mut rx) = tokio::sync::mpsc::channel(4);
        let audit = AuditEmitter::new(tx, "agent".into(), "host".into());
        let create = crate::schema::ProcessCreateData {
            pid,
            name: "PING.EXE".into(), // sensors report the on-disk casing
            exe: "C:\\Windows\\System32\\PING.EXE".into(),
            process_start_time: crate::telemetry::identity::process_start_time(pid),
            ..Default::default()
        };
        let exec = exec_from_create(&create);
        assert_eq!(
            enforce_exec(&exec, &policy, &audit).as_deref(),
            Some("block-ping")
        );
        assert!(child.wait().is_ok(), "the child must have been terminated");
        match rx.try_recv().expect("audit event").data {
            crate::schema::EventData::Prevention(d) => {
                assert!(d.success, "kill must be reported as successful");
                assert_eq!(d.kind, "process_block");
            }
            other => panic!("unexpected event {other:?}"),
        }
    }

    #[test]
    fn a_recycled_pid_is_not_killed() {
        let mut child = Command::new("ping")
            .args(["-n", "60", "127.0.0.1"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let pid = child.id() as i32;
        let policy = PolicyHandle::new(
            PolicyStore::from_rules(vec![IocRule::Comm {
                id: "block-ping".into(),
                value: "ping.exe".into(),
                action: RuleAction::Block,
            }])
            .unwrap(),
        );
        let (tx, mut rx) = tokio::sync::mpsc::channel(4);
        let audit = AuditEmitter::new(tx, "agent".into(), "host".into());
        // The event describes an older process that had this PID.
        let stale_start = crate::telemetry::identity::process_start_time(pid).map(|t| t + 10_000);
        let exec = exec_from_create(&crate::schema::ProcessCreateData {
            pid,
            name: "ping.exe".into(),
            process_start_time: stale_start,
            ..Default::default()
        });
        enforce_exec(&exec, &policy, &audit);
        assert!(
            child.try_wait().unwrap().is_none(),
            "bystander must survive"
        );
        match rx.try_recv().unwrap().data {
            crate::schema::EventData::Prevention(d) => assert!(!d.success),
            other => panic!("unexpected event {other:?}"),
        }
        let _ = child.kill();
        let _ = child.wait();
    }
}
