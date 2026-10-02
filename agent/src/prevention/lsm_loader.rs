//! eBPF kernel-side process blocker loader.
//!
//! Loads the `process_block_exec` tracepoint program from the shared eBPF
//! binary (`/usr/lib/trapd-agent/trapd-agent-exec`) and populates two maps:
//!
//!   - `BLOCKED_COMMS`  — set of 16-byte process names to SIGKILL on exec
//!   - `BLOCKED_INODES` — set of inodes identifying blocked executables
//!
//! The eBPF program calls `bpf_send_signal(SIGKILL)` from the
//! `sched/sched_process_exec` tracepoint, killing the process before its
//! first userspace instruction.  Requires kernel ≥ 5.3.
//!
//! If the binary or kernel doesn't support kernel-side blocking the loader
//! returns a `Disabled` handle; the userspace post-exec fallback in
//! `process::enforce_exec` still works.

#[cfg(target_os = "linux")]
use std::collections::BTreeSet;
#[cfg(target_os = "linux")]
use std::path::Path;

use tokio::sync::Mutex;
#[cfg(target_os = "linux")]
use tracing::info;
use tracing::warn;

use super::policy::PolicyHandle;
#[cfg(target_os = "linux")]
use super::policy::{IocRule, RuleAction};

/// Handle to the in-kernel block-maps.
pub struct LsmHandle {
    state: Mutex<Option<LsmState>>,
}

#[cfg(target_os = "linux")]
struct LsmState {
    _bpf: aya::Ebpf,
    blocked_comms: aya::maps::HashMap<aya::maps::MapData, [u8; 16], u8>,
    blocked_inodes: aya::maps::HashMap<aya::maps::MapData, u64, u8>,
}

#[cfg(not(target_os = "linux"))]
struct LsmState;

impl LsmHandle {
    /// A runtime-owned handle which does not attach until prevention is enabled.
    pub fn disabled() -> Self {
        Self {
            state: Mutex::new(None),
        }
    }

    /// Detach immediately on disable; attach on enable if the kernel supports it.
    pub async fn set_enabled(&self, enabled: bool) {
        let mut state = self.state.lock().await;
        if !enabled {
            *state = None;
            return;
        }
        if state.is_some() {
            return;
        }
        *state = Self::do_load().unwrap_or_else(|e| {
            warn!(
                error = %e,
                "kernel-side exec blocker not loaded — falling back to userspace post-exec kill",
            );
            None
        });
    }

    #[cfg(target_os = "linux")]
    fn do_load() -> anyhow::Result<Option<LsmState>> {
        use anyhow::Context;
        use aya::{maps::HashMap as BpfHashMap, programs::TracePoint, Ebpf};

        let candidates = [
            std::env::var("TRAPD_EBPF_PATH").ok(),
            Some("/usr/lib/trapd-agent/trapd-agent-exec".into()),
            Some("/usr/local/lib/trapd-agent/trapd-agent-exec".into()),
            Some("../../target/bpfel-unknown-none/release/trapd-agent-exec".into()),
        ];
        let path = candidates
            .into_iter()
            .flatten()
            .find(|p| Path::new(p).exists())
            .ok_or_else(|| anyhow::anyhow!("eBPF binary not installed"))?;

        let bytes = std::fs::read(&path).with_context(|| format!("read eBPF binary: {path}"))?;
        let mut bpf = Ebpf::load(&bytes).context("load eBPF binary")?;

        let prog = match bpf.program_mut("process_block_exec") {
            Some(p) => p,
            None => {
                return Err(anyhow::anyhow!(
                    "eBPF binary lacks 'process_block_exec' — rebuild trapd-agent-ebpf"
                ));
            }
        };
        let prog: &mut TracePoint = prog
            .try_into()
            .context("process_block_exec is not a tracepoint")?;
        prog.load()
            .context("BPF verifier rejected process_block_exec")?;
        prog.attach("sched", "sched_process_exec")
            .context("attach process_block_exec to sched/sched_process_exec")?;

        let blocked_comms: BpfHashMap<_, [u8; 16], u8> = BpfHashMap::try_from(
            bpf.take_map("BLOCKED_COMMS")
                .context("BLOCKED_COMMS map missing")?,
        )?;
        let blocked_inodes: BpfHashMap<_, u64, u8> = BpfHashMap::try_from(
            bpf.take_map("BLOCKED_INODES")
                .context("BLOCKED_INODES map missing")?,
        )?;

        info!(
            path,
            "kernel-side exec blocker loaded — sched_process_exec attached"
        );
        Ok(Some(LsmState {
            _bpf: bpf,
            blocked_comms,
            blocked_inodes,
        }))
    }

    #[cfg(not(target_os = "linux"))]
    fn do_load() -> anyhow::Result<Option<LsmState>> {
        anyhow::bail!("kernel exec blocker only on Linux")
    }

    /// Replace kernel block lists, removing revoked and alert-only rules first.
    pub async fn sync(&self, policy: &PolicyHandle) {
        let mut guard = self.state.lock().await;
        let state = match guard.as_mut() {
            Some(s) => s,
            None => return,
        };
        #[cfg(target_os = "linux")]
        {
            let rules = policy.read().rules().to_vec();
            let comms = block_comm_keys(&rules);
            let inodes = rules
                .iter()
                .filter_map(|r| match r {
                    IocRule::Sha256 {
                        value,
                        action: RuleAction::Block,
                        ..
                    } => resolve_inode_for_hash(value),
                    _ => None,
                })
                .collect();
            let result = reconcile_map(&mut state.blocked_comms, &comms)
                .and_then(|()| reconcile_map(&mut state.blocked_inodes, &inodes));
            if let Err(error) = result {
                // A failed removal must never leave a revoked rule armed.
                warn!(%error, "kernel policy reconciliation failed — detaching blocker and using userspace enforcement");
                *guard = None;
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = policy;
            let _ = state;
        }
    }
}

#[cfg(target_os = "linux")]
fn block_comm_keys(rules: &[IocRule]) -> BTreeSet<[u8; 16]> {
    rules
        .iter()
        .filter_map(|r| match r {
            // Kernel comm cannot represent longer or embedded-NUL names. Do not
            // silently broaden an exact match by truncating a backend rule.
            IocRule::Comm {
                value,
                action: RuleAction::Block,
                ..
            } if value.len() <= 15 && !value.as_bytes().contains(&0) => Some(comm_key(value)),
            _ => None,
        })
        .collect()
}

#[cfg(target_os = "linux")]
fn key_changes<K: Copy + Ord>(current: &BTreeSet<K>, desired: &BTreeSet<K>) -> (Vec<K>, Vec<K>) {
    (
        current.difference(desired).copied().collect(),
        desired.difference(current).copied().collect(),
    )
}

#[cfg(target_os = "linux")]
fn reconcile_map<K: aya::Pod + Copy + Ord>(
    map: &mut aya::maps::HashMap<aya::maps::MapData, K, u8>,
    desired: &BTreeSet<K>,
) -> anyhow::Result<()> {
    let current = map.keys().collect::<Result<BTreeSet<_>, _>>()?;
    let (removed, added) = key_changes(&current, desired);
    for key in removed {
        map.remove(&key)?;
    }
    for key in added {
        map.insert(key, 1, 0)?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn comm_key(s: &str) -> [u8; 16] {
    let mut out = [0u8; 16];
    let bytes = s.as_bytes();
    let n = bytes.len().min(15);
    out[..n].copy_from_slice(&bytes[..n]);
    out
}

/// Find a file on disk whose SHA256 matches `hash`.
///
/// Resolving SHA256 → inode in the general case requires hashing every
/// executable on disk.  We leave this as an explicit no-op so the
/// kernel-side path only catches `comm` rules; userspace post-exec
/// still enforces SHA256 rules via `process::enforce_exec`.
#[cfg(target_os = "linux")]
fn resolve_inode_for_hash(_hash: &str) -> Option<u64> {
    None
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn kernel_block_list_excludes_alert_and_unrepresentable_names() {
        let rules = vec![
            IocRule::Comm {
                id: "a".into(),
                value: "bash".into(),
                action: RuleAction::Alert,
            },
            IocRule::Comm {
                id: "b".into(),
                value: "curl".into(),
                action: RuleAction::Block,
            },
            IocRule::Comm {
                id: "c".into(),
                value: "1234567890123456".into(),
                action: RuleAction::Block,
            },
        ];
        assert_eq!(
            block_comm_keys(&rules),
            BTreeSet::from([*b"curl\0\0\0\0\0\0\0\0\0\0\0\0"])
        );
    }

    #[test]
    fn policy_replacement_removes_revoked_block_keys() {
        let current = BTreeSet::from([
            *b"bash\0\0\0\0\0\0\0\0\0\0\0\0",
            *b"curl\0\0\0\0\0\0\0\0\0\0\0\0",
        ]);
        let desired = block_comm_keys(&[
            IocRule::Comm {
                id: "a".into(),
                value: "bash".into(),
                action: RuleAction::Alert,
            },
            IocRule::Comm {
                id: "c".into(),
                value: "wget".into(),
                action: RuleAction::Block,
            },
        ]);
        let (removed, added) = key_changes(&current, &desired);
        assert_eq!(
            removed,
            vec![
                *b"bash\0\0\0\0\0\0\0\0\0\0\0\0",
                *b"curl\0\0\0\0\0\0\0\0\0\0\0\0"
            ]
        );
        assert_eq!(added, vec![*b"wget\0\0\0\0\0\0\0\0\0\0\0\0"]);
        assert_eq!(key_changes(&desired, &BTreeSet::new()).0, added);
    }
}
