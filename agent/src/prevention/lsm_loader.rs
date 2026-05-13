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

use std::path::Path;
use std::sync::Arc;

use tokio::sync::Mutex;
use tracing::{info, warn};

use super::policy::{IocRule, PolicyHandle};

/// Handle to the in-kernel block-maps.
pub struct LsmHandle {
    state: Arc<Mutex<Option<LsmState>>>,
}

#[cfg(target_os = "linux")]
struct LsmState {
    _bpf:           aya::Ebpf,
    blocked_comms:  aya::maps::HashMap<aya::maps::MapData, [u8; 16], u8>,
    blocked_inodes: aya::maps::HashMap<aya::maps::MapData, u64, u8>,
}

#[cfg(not(target_os = "linux"))]
struct LsmState;

impl LsmHandle {
    /// Try to load the kernel-side blocker.  Returns a disabled handle on
    /// any failure (missing binary, missing CAP_BPF, kernel too old, …).
    pub fn try_load() -> Self {
        let inner = Self::do_load().unwrap_or_else(|e| {
            warn!(
                error = %e,
                "kernel-side exec blocker not loaded — falling back to userspace post-exec kill",
            );
            None
        });
        Self { state: Arc::new(Mutex::new(inner)) }
    }

    #[cfg(target_os = "linux")]
    fn do_load() -> anyhow::Result<Option<LsmState>> {
        use anyhow::Context;
        use aya::{
            maps::HashMap as BpfHashMap,
            programs::TracePoint,
            Ebpf,
        };

        let candidates = [
            std::env::var("TRAPD_EBPF_PATH").ok(),
            Some("/usr/lib/trapd-agent/trapd-agent-exec".into()),
            Some("/usr/local/lib/trapd-agent/trapd-agent-exec".into()),
            Some("../../target/bpfel-unknown-none/release/trapd-agent-exec".into()),
        ];
        let path = candidates.into_iter().flatten()
            .find(|p| Path::new(p).exists())
            .ok_or_else(|| anyhow::anyhow!("eBPF binary not installed"))?;

        let bytes = std::fs::read(&path)
            .with_context(|| format!("read eBPF binary: {path}"))?;
        let mut bpf = Ebpf::load(&bytes).context("load eBPF binary")?;

        let prog = match bpf.program_mut("process_block_exec") {
            Some(p) => p,
            None => {
                return Err(anyhow::anyhow!(
                    "eBPF binary lacks 'process_block_exec' — rebuild trapd-agent-ebpf"
                ));
            }
        };
        let prog: &mut TracePoint = prog.try_into()
            .context("process_block_exec is not a tracepoint")?;
        prog.load().context("BPF verifier rejected process_block_exec")?;
        prog.attach("sched", "sched_process_exec")
            .context("attach process_block_exec to sched/sched_process_exec")?;

        let blocked_comms: BpfHashMap<_, [u8; 16], u8> = BpfHashMap::try_from(
            bpf.take_map("BLOCKED_COMMS").context("BLOCKED_COMMS map missing")?,
        )?;
        let blocked_inodes: BpfHashMap<_, u64, u8> = BpfHashMap::try_from(
            bpf.take_map("BLOCKED_INODES").context("BLOCKED_INODES map missing")?,
        )?;

        info!(path, "kernel-side exec blocker loaded — sched_process_exec attached");
        Ok(Some(LsmState { _bpf: bpf, blocked_comms, blocked_inodes }))
    }

    #[cfg(not(target_os = "linux"))]
    fn do_load() -> anyhow::Result<Option<LsmState>> {
        anyhow::bail!("kernel exec blocker only on Linux")
    }

    /// Re-sync the kernel maps with the current policy.  Cheap to call.
    pub async fn sync(&self, policy: &PolicyHandle) {
        let mut guard = self.state.lock().await;
        let state = match guard.as_mut() {
            Some(s) => s,
            None    => return,
        };
        #[cfg(target_os = "linux")]
        {
            let rules: Vec<IocRule> = policy.read().rules().to_vec();
            for r in &rules {
                if let IocRule::Comm { value, .. } = r {
                    let key = comm_key(value);
                    let _ = state.blocked_comms.insert(key, 1, 0);
                }
            }
            for r in &rules {
                if let IocRule::Sha256 { value, .. } = r {
                    if let Some(ino) = resolve_inode_for_hash(value) {
                        let _ = state.blocked_inodes.insert(ino, 1, 0);
                    }
                }
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
