//! eBPF-backed exec tracer for Linux.
//!
//! Attaches to the `sched/sched_process_exec` tracepoint and delivers one
//! [`ExecEventData`] per successful `execve(2)` call — catching short-lived
//! processes (reverse shells, loaders, one-shot scripts) that the 3-second
//! polling collector would miss entirely.
//!
//! ## Setup
//!
//! 1. Build the eBPF program:  `cargo xtask build-ebpf --release`
//! 2. Install the binary:       `cp target/bpfel-unknown-none/release/trapd-agent-exec /usr/lib/trapd-agent/`
//! 3. Run the agent as root (or grant CAP_BPF + CAP_PERFMON).
//!
//! The collector logs a warning and exits cleanly if the eBPF binary is not
//! found or if the required capabilities are missing — all other collectors
//! continue running.
//!
//! ## Kernel requirements
//!
//! | Feature             | Minimum kernel |
//! |---------------------|---------------|
//! | sched_process_exec  | 4.11          |
//! | RingBuf map         | 5.8           |
//! | CAP_BPF (unprivileged) | 5.8        |

use std::fs;

use anyhow::{Context, Result};
use async_trait::async_trait;
use aya::{
    maps::RingBuf,
    programs::TracePoint,
    Ebpf,
};
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc::Sender;
use tracing::{info, warn};

use crate::collectors::Collector;
use crate::schema::{
    AgentEvent, EventAction, EventClass, EventData, ExecEventData, Severity,
};

// ── Kernel↔Userspace struct layout ───────────────────────────────────────────
// Must be kept in sync with `ExecEvent` in trapd-agent-ebpf/src/main.rs.

const COMM_LEN: usize = 16;
const FILENAME_LEN: usize = 256;

#[repr(C)]
struct RawExecEvent {
    pid:          u32,
    ppid:         u32,
    uid:          u32,
    gid:          u32,
    comm:         [u8; COMM_LEN],
    filename:     [u8; FILENAME_LEN],
    filename_len: u32,
}

// ── Collector ─────────────────────────────────────────────────────────────────

/// eBPF exec tracer.
///
/// Call [`EbpfExecCollector::is_available`] before spawning to check whether
/// the eBPF binary has been installed. The binary is searched in order:
///
/// 1. `$TRAPD_EBPF_PATH` (env override)
/// 2. `/usr/lib/trapd-agent/trapd-agent-exec` (system install)
/// 3. `/usr/local/lib/trapd-agent/trapd-agent-exec`
/// 4. Next to the agent binary (`trapd-agent-exec` sibling)
/// 5. `../../target/bpfel-unknown-none/release/trapd-agent-exec` (dev workspace)
pub struct EbpfExecCollector {
    ebpf_path: Option<String>,
}

impl EbpfExecCollector {
    pub fn new() -> Self {
        Self {
            ebpf_path: Self::locate_binary(),
        }
    }

    /// Returns `true` when the eBPF binary was found at one of the search paths.
    ///
    /// Capability checks happen lazily at load time — if the binary is present
    /// but CAP_BPF is missing, [`Collector::run`] will return an error with a
    /// clear message.
    pub fn is_available(&self) -> bool {
        self.ebpf_path.is_some()
    }

    fn locate_binary() -> Option<String> {
        // Sibling of the running agent binary (installed layout)
        let sibling = std::env::current_exe().ok().and_then(|p| {
            p.parent()
                .map(|d| d.join("trapd-agent-exec").to_string_lossy().into_owned())
        });

        let candidates: &[Option<String>] = &[
            std::env::var("TRAPD_EBPF_PATH").ok(),
            Some("/usr/lib/trapd-agent/trapd-agent-exec".into()),
            Some("/usr/local/lib/trapd-agent/trapd-agent-exec".into()),
            sibling,
            // Workspace dev path (relative to agent/ crate root)
            Some("../../target/bpfel-unknown-none/release/trapd-agent-exec".into()),
        ];

        candidates
            .iter()
            .flatten()
            .find(|p| std::path::Path::new(p).exists())
            .cloned()
    }
}

impl Default for EbpfExecCollector {
    fn default() -> Self {
        Self::new()
    }
}

// ── /proc enrichment helpers ─────────────────────────────────────────────────

/// Extract a NUL-terminated C-style string from a byte slice.
fn cstr(buf: &[u8]) -> &str {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    std::str::from_utf8(&buf[..end]).unwrap_or("")
}

/// Read PPid from /proc/<pid>/status (best-effort; returns 0 if unavailable).
fn proc_ppid(pid: u32) -> u32 {
    fs::read_to_string(format!("/proc/{pid}/status"))
        .unwrap_or_default()
        .lines()
        .find_map(|l| {
            l.strip_prefix("PPid:")
                .map(|v| v.trim().parse().unwrap_or(0))
        })
        .unwrap_or(0)
}

/// Read full argv from /proc/<pid>/cmdline (NUL-separated, joined with spaces).
fn proc_cmdline(pid: u32) -> String {
    fs::read(format!("/proc/{pid}/cmdline"))
        .map(|bytes| {
            bytes
                .split(|&b| b == 0)
                .filter_map(|part| std::str::from_utf8(part).ok().filter(|s| !s.is_empty()))
                .collect::<Vec<_>>()
                .join(" ")
        })
        .unwrap_or_default()
}

/// Resolve /proc/<pid>/cwd symlink to the absolute working directory path.
fn proc_cwd(pid: u32) -> String {
    fs::read_link(format!("/proc/{pid}/cwd"))
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// Extract a short (12-char) container ID from /proc/<pid>/cgroup, if any.
///
/// Handles Docker, containerd, and Kubernetes cgroup paths:
///   `/docker/<64hex>`
///   `/system.slice/docker-<64hex>.scope`
///   `/kubepods/…/<64hex>`
fn proc_container_id(pid: u32) -> Option<String> {
    let cgroup = fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()?;
    for line in cgroup.lines() {
        // Format: `<hierarchy>:<subsystems>:<path>`
        let path = line.splitn(3, ':').nth(2)?;

        // Skip root cgroup (no container)
        if path == "/" {
            continue;
        }

        // Walk path segments looking for 12–64 char hex strings.
        // Strip common prefixes used by runtimes.
        for segment in path.split('/') {
            let candidate = segment
                .trim_end_matches(".scope")
                .trim_start_matches("docker-")
                .trim_start_matches("containerd-")
                .trim_start_matches("crio-");

            if candidate.len() >= 12
                && candidate.len() <= 64
                && candidate.chars().all(|c| c.is_ascii_hexdigit())
            {
                return Some(candidate[..12].to_string());
            }
        }
    }
    None
}

/// Resolve UID to username via /etc/passwd.
fn proc_username(uid: u32) -> String {
    fs::read_to_string("/etc/passwd")
        .unwrap_or_default()
        .lines()
        .find_map(|line| {
            let mut fields = line.splitn(7, ':');
            let name = fields.next()?;
            let _    = fields.next(); // password
            let u    = fields.next()?.parse::<u32>().ok()?;
            (u == uid).then(|| name.to_string())
        })
        .unwrap_or_else(|| format!("uid:{uid}"))
}

// ── Collector impl ────────────────────────────────────────────────────────────

#[async_trait]
impl Collector for EbpfExecCollector {
    fn name(&self) -> &'static str {
        "EbpfExecCollector"
    }

    async fn run(
        &mut self,
        tx: Sender<AgentEvent>,
        agent_id: String,
        hostname: String,
    ) -> Result<()> {
        let path = self
            .ebpf_path
            .as_deref()
            .context("eBPF binary not found — run `cargo xtask build-ebpf --release` and copy to /usr/lib/trapd-agent/")?;

        let bytes = fs::read(path)
            .with_context(|| format!("cannot read eBPF binary: {path}"))?;

        // Load ELF bytecode into the kernel
        let mut bpf = Ebpf::load(&bytes).context(
            "failed to load eBPF program — requires Linux ≥ 5.8 and CAP_BPF (run as root)",
        )?;

        // Load + attach the tracepoint program
        let prog: &mut TracePoint = bpf
            .program_mut("sched_process_exec")
            .context("sched_process_exec not found in eBPF binary")?
            .try_into()
            .context("program is not a TracePoint")?;
        prog.load().context("BPF verifier rejected the program")?;
        prog.attach("sched", "sched_process_exec")
            .context("failed to attach to sched/sched_process_exec")?;

        // Open the ring buffer map
        let ring_buf = RingBuf::try_from(
            bpf.map_mut("EXEC_EVENTS")
                .context("EXEC_EVENTS map not found in eBPF binary")?,
        )
        .context("failed to open EXEC_EVENTS ring buffer")?;

        // Wrap in AsyncFd so we can await readability without busy-polling
        let mut async_fd =
            AsyncFd::new(ring_buf).context("failed to create AsyncFd for ring buffer")?;

        info!(
            path = %path,
            "eBPF exec tracer attached to sched/sched_process_exec"
        );

        loop {
            // Sleep until the kernel signals data in the ring buffer
            let mut guard = async_fd.readable_mut().await?;
            let rb = guard.get_inner_mut();

            while let Some(item) = rb.next() {
                let bytes: &[u8] = &item;

                if bytes.len() < std::mem::size_of::<RawExecEvent>() {
                    warn!(
                        got  = bytes.len(),
                        want = std::mem::size_of::<RawExecEvent>(),
                        "short eBPF event — skipping"
                    );
                    continue;
                }

                // SAFETY: eBPF program writes a correctly-sized, C-repr struct.
                let raw: RawExecEvent =
                    unsafe { std::ptr::read_unaligned(bytes.as_ptr() as *const RawExecEvent) };

                let pid      = raw.pid;
                let exe      = cstr(&raw.filename).to_string();
                let comm     = cstr(&raw.comm).to_string();

                // Enrich from /proc — best-effort; short-lived processes may
                // already be gone, in which case these return empty strings.
                let ppid         = proc_ppid(pid);
                let cmdline      = proc_cmdline(pid);
                let cwd          = proc_cwd(pid);
                let container_id = proc_container_id(pid);
                let username     = proc_username(raw.uid);

                let event = AgentEvent::new(
                    agent_id.clone(),
                    hostname.clone(),
                    EventClass::Process,
                    EventAction::Exec,
                    Severity::Info,
                    EventData::ProcessExec(ExecEventData {
                        pid: pid as i32,
                        ppid: ppid as i32,
                        uid: raw.uid,
                        gid: raw.gid,
                        username,
                        comm,
                        exe,
                        cmdline,
                        cwd,
                        container_id,
                    }),
                );

                if tx.send(event).await.is_err() {
                    // Pipeline shut down — exit cleanly
                    return Ok(());
                }
            }

            guard.clear_ready();
        }
    }
}
