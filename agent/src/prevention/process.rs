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

use std::path::Path;

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
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
    kill(Pid::from_raw(pid), Signal::SIGKILL)
        .with_context(|| format!("SIGKILL pid={pid} failed"))
}

#[cfg(not(target_os = "linux"))]
pub fn kill_pid(_pid: i32) -> Result<()> {
    anyhow::bail!("process kill only implemented on Linux")
}

/// Best-effort SHA256 of a file.  Returns `None` if the file is unreadable
/// (short-lived process, deleted between exec and our hash attempt, …).
fn hash_file(path: &Path) -> Option<String> {
    use std::io::Read;
    let mut f = std::fs::File::open(path).ok()?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = f.read(&mut buf).ok()?;
        if n == 0 { break; }
        hasher.update(&buf[..n]);
    }
    Some(hex::encode(hasher.finalize()))
}

/// Look up the parent's comm by PPID.
fn parent_comm(ppid: i32) -> Option<String> {
    if ppid <= 0 { return None; }
    let raw = std::fs::read_to_string(format!("/proc/{ppid}/comm")).ok()?;
    Some(raw.trim().to_string())
}

/// Enforce the current policy against a freshly-execed process.  Returns
/// `Some(rule_id)` if the process was killed.
pub fn enforce_exec(
    exec:    &ExecEventData,
    policy:  &PolicyHandle,
    audit:   &AuditEmitter,
) -> Option<String> {
    let needs_hash = !policy.read().rules().is_empty();
    let sha = if needs_hash {
        hash_file(Path::new(&exec.exe))
    } else {
        None
    };

    let parent = parent_comm(exec.ppid);

    let m: Option<Match> = policy.read().match_exec(
        &exec.exe,
        &exec.comm,
        parent.as_deref(),
        sha.as_deref(),
    );

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
                if killed { crate::schema::Severity::High } else { crate::schema::Severity::Medium },
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
