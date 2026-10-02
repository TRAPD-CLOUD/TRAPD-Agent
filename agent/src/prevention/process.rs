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

#[cfg(not(target_os = "linux"))]
pub fn kill_pid(_pid: i32) -> Result<()> {
    anyhow::bail!("process kill only implemented on Linux")
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

#[cfg(not(target_os = "linux"))]
pub fn freeze_pid(_pid: i32) -> Result<()> {
    anyhow::bail!("process freeze only implemented on Linux")
}

/// Resume a previously-frozen process by sending SIGCONT.
#[cfg(target_os = "linux")]
pub fn thaw_pid(pid: i32) -> Result<()> {
    use nix::sys::signal::{kill, Signal};
    use nix::unistd::Pid;
    kill(Pid::from_raw(pid), Signal::SIGCONT).with_context(|| format!("SIGCONT pid={pid} failed"))
}

#[cfg(not(target_os = "linux"))]
pub fn thaw_pid(_pid: i32) -> Result<()> {
    anyhow::bail!("process thaw only implemented on Linux")
}

/// Look up the parent's comm by PPID.
fn parent_comm(ppid: i32) -> Option<String> {
    if ppid <= 0 {
        return None;
    }
    let raw = std::fs::read_to_string(format!("/proc/{ppid}/comm")).ok()?;
    Some(raw.trim().to_string())
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
            .or_else(|| {
                #[cfg(target_os = "linux")]
                {
                    crate::collectors::linux::exehash::hash_for_policy(&exec.exe)
                }
                #[cfg(not(target_os = "linux"))]
                {
                    None
                }
            })
    } else {
        None
    };

    let parent = parent_comm(exec.ppid);

    let m: Option<Match> =
        policy
            .read()
            .match_exec(&exec.exe, &exec.comm, parent.as_deref(), sha.as_deref());

    let m = m?;

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
            let killed = kill_pid(exec.pid).is_ok();
            if killed {
                info!(pid = exec.pid, exe = %exec.exe, rule = %m.rule_id, "blocked process by SIGKILL");
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
