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
use aya::{maps::RingBuf, programs::TracePoint, Ebpf};
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc::Sender;
use tracing::{info, warn};

use crate::collectors::Collector;
use crate::schema::{AgentEvent, EventAction, EventClass, EventData, ExecEventData, Severity};
use crate::telemetry::limits::{truncate_str, Truncation, MAX_CMDLINE_BYTES};
use crate::telemetry::metrics::{metrics, CollectorMode};
use crate::telemetry::{Enrichment, EnrichmentError};

/// Source name stamped on every event this collector produces.
const SOURCE: &str = "ebpf_exec";

// ── Kernel↔Userspace struct layout ───────────────────────────────────────────
// Must be kept in sync with `ExecEvent` in trapd-agent-ebpf/src/main.rs.

const COMM_LEN: usize = 16;
const FILENAME_LEN: usize = 256;
const PRELOAD_LEN: usize = 256;

#[repr(C)]
struct RawExecEvent {
    pid: u32,
    ppid: u32,
    uid: u32,
    gid: u32,
    comm: [u8; COMM_LEN],
    filename: [u8; FILENAME_LEN],
    filename_len: u32,
    ld_preload_len: u32,
    ld_preload: [u8; PRELOAD_LEN],
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

/// Read PPid from `/proc/<pid>/status`.
///
/// Returns why the read failed rather than a bare `0`, because `0` is
/// indistinguishable from "the kernel reported PPid 0" and would quietly
/// reparent an orphan onto the swapper task.
fn proc_ppid(pid: u32) -> Result<u32, EnrichmentError> {
    let status =
        fs::read_to_string(format!("/proc/{pid}/status")).map_err(|e| EnrichmentError::from_io(&e))?;
    status
        .lines()
        .find_map(|l| l.strip_prefix("PPid:"))
        .and_then(|v| v.trim().parse().ok())
        .ok_or(EnrichmentError::ParseFailed)
}

/// Read full argv from `/proc/<pid>/cmdline` (NUL-separated, joined with spaces).
///
/// Capped at [`MAX_CMDLINE_BYTES`]; the returned [`Truncation`] is `Some` when
/// the command line was longer, so a consumer can tell a complete command line
/// from its prefix.
fn proc_cmdline(pid: u32) -> Result<(String, Option<Truncation>), EnrichmentError> {
    let bytes = fs::read(format!("/proc/{pid}/cmdline")).map_err(|e| EnrichmentError::from_io(&e))?;
    let joined = bytes
        .split(|&b| b == 0)
        .filter_map(|part| std::str::from_utf8(part).ok().filter(|s| !s.is_empty()))
        .collect::<Vec<_>>()
        .join(" ");
    Ok(truncate_str(&joined, MAX_CMDLINE_BYTES))
}

/// Resolve the `/proc/<pid>/cwd` symlink to an absolute path.
fn proc_cwd(pid: u32) -> Result<String, EnrichmentError> {
    fs::read_link(format!("/proc/{pid}/cwd"))
        .map(|p| p.to_string_lossy().into_owned())
        .map_err(|e| EnrichmentError::from_io(&e))
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
            let _ = fields.next(); // password
            let u = fields.next()?.parse::<u32>().ok()?;
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

        let bytes = fs::read(path).with_context(|| format!("cannot read eBPF binary: {path}"))?;

        // Load ELF bytecode into the kernel
        let mut bpf = Ebpf::load(&bytes).context(
            "failed to load eBPF program — requires Linux ≥ 5.8 and CAP_BPF (run as root)",
        )?;

        // Load + attach sched_process_exec (fires after successful exec)
        {
            let prog: &mut TracePoint = bpf
                .program_mut("sched_process_exec")
                .context("sched_process_exec not found in eBPF binary")?
                .try_into()
                .context("sched_process_exec is not a TracePoint")?;
            prog.load()
                .context("BPF verifier rejected sched_process_exec")?;
            prog.attach("sched", "sched_process_exec")
                .context("failed to attach to sched/sched_process_exec")?;
        }

        // Load + attach sys_enter_execve (fires before exec; scans envp for LD_PRELOAD)
        {
            let prog: &mut TracePoint = bpf
                .program_mut("sys_enter_execve")
                .context("sys_enter_execve not found in eBPF binary")?
                .try_into()
                .context("sys_enter_execve is not a TracePoint")?;
            prog.load()
                .context("BPF verifier rejected sys_enter_execve")?;
            prog.attach("syscalls", "sys_enter_execve")
                .context("failed to attach to syscalls/sys_enter_execve")?;
        }

        // Open the ring buffer map (shared by both tracepoints above)
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
        metrics().add_collector_mode(CollectorMode::Ebpf);

        // Self-exclusion: drop the agent's own exec events.
        let agent_pid = std::process::id();

        loop {
            // Sleep until the kernel signals data in the ring buffer
            let mut guard = async_fd.readable_mut().await?;
            let rb = guard.get_inner_mut();

            while let Some(item) = rb.next() {
                let bytes: &[u8] = &item;

                if bytes.len() < std::mem::size_of::<RawExecEvent>() {
                    warn!(
                        got = bytes.len(),
                        want = std::mem::size_of::<RawExecEvent>(),
                        "short eBPF event — skipping"
                    );
                    continue;
                }

                // SAFETY: eBPF program writes a correctly-sized, C-repr struct.
                let raw: RawExecEvent =
                    unsafe { std::ptr::read_unaligned(bytes.as_ptr() as *const RawExecEvent) };

                metrics().ebpf_event_received();

                let pid = raw.pid;
                if pid == agent_pid {
                    continue;
                } // self-exclusion
                let exe = cstr(&raw.filename).to_string();
                let comm = cstr(&raw.comm).to_string();

                // The kernel's own answer to "this PID exists", recorded before
                // any /proc read, so the rootkit sweep can compare it against
                // what procfs is willing to admit later.
                crate::rootkit::kernel_view::kernel_view().record_process(pid as i32, &comm);

                // The kernel record is already complete and will ship whatever
                // happens below. Everything from here is /proc enrichment, and a
                // short-lived process — exactly the kind the eBPF tracer exists
                // to catch — may well be gone already. Each failure is recorded
                // against its field instead of discarding the event.
                let enrich_started = std::time::Instant::now();
                let mut notes = Enrichment::new();

                // Read the start time first: it is what distinguishes this
                // process from a later one that reuses its PID, and it is only
                // readable while the process still exists.
                let process_start_time = crate::telemetry::identity::process_start_time(pid as i32);
                if process_start_time.is_none() {
                    notes.fail("process_start_time", EnrichmentError::ProcessExited);
                }

                let ppid = match proc_ppid(pid) {
                    Ok(v) => v,
                    Err(e) => {
                        notes.fail("ppid", e);
                        0
                    }
                };
                let parent_start_time = (ppid > 0)
                    .then(|| crate::telemetry::identity::process_start_time(ppid as i32))
                    .flatten();

                let cmdline = match proc_cmdline(pid) {
                    Ok((value, truncation)) => {
                        notes.truncated("cmdline", truncation);
                        value
                    }
                    Err(e) => {
                        notes.fail("cmdline", e);
                        String::new()
                    }
                };

                let cwd = match proc_cwd(pid) {
                    Ok(v) => v,
                    Err(e) => {
                        notes.fail("cwd", e);
                        String::new()
                    }
                };

                let container_id = proc_container_id(pid);
                let username = proc_username(raw.uid);

                let ld_preload = if raw.ld_preload_len > 0 {
                    Some(cstr(&raw.ld_preload).to_string())
                } else {
                    None
                };

                // Telemetry-depth enrichment (P1): loaded-library inventory,
                // curated environment, decoded interpreter scripts and
                // container/K8s context — best-effort from /proc, on the blocking
                // pool. The eBPF-supplied container_id is a fallback if the
                // process exited before /proc could be read.
                let enrich = {
                    let comm = comm.clone();
                    let exe = exe.clone();
                    let cmdline = cmdline.clone();
                    tokio::task::spawn_blocking(move || {
                        crate::collectors::linux::proc_enrich::enrich_exec(
                            pid, &comm, &exe, &cmdline,
                        )
                    })
                    .await
                    .unwrap_or_default()
                };

                // Canonical image hash (cached, size-capped) — also feeds IOC
                // hash-matching and the IOA process-tree lineage.
                let exe_sha256 = super::exehash::hash_executable(&exe);

                metrics().enrichment_attempt(enrich_started.elapsed().as_millis() as u64);

                let event = AgentEvent::new(
                    agent_id.clone(),
                    hostname.clone(),
                    EventClass::Process,
                    EventAction::Exec,
                    Severity::Info,
                    EventData::ProcessExec(Box::new(ExecEventData {
                        pid: pid as i32,
                        ppid: ppid as i32,
                        uid: raw.uid,
                        gid: raw.gid,
                        username,
                        comm,
                        exe,
                        cmdline,
                        cwd,
                        process_start_time,
                        parent_start_time,
                        // Four fields were attempted from /proc: start time,
                        // ppid, cmdline and cwd.
                        enrichment: notes.finish(4),
                        container_id: enrich.container_id.or(container_id),
                        ld_preload,
                        exe_sha256,
                        loaded_libraries: enrich.loaded_libraries,
                        env: enrich.env,
                        interpreter: enrich.interpreter,
                        container_runtime: enrich.container_runtime,
                        container_image: enrich.container_image,
                        container_image_digest: enrich.container_image_digest,
                        k8s: enrich.k8s,
                    })),
                )
                .with_source(SOURCE);

                // Deliberately non-blocking: awaiting a full pipeline would stop
                // this loop draining the kernel ring buffer, turning a countable
                // userspace drop into an opaque kernel one.
                if tx.is_closed() {
                    // Pipeline shut down — exit cleanly.
                    return Ok(());
                }
                crate::pipeline::try_emit(&tx, event, SOURCE);
            }

            guard.clear_ready();
        }
    }
}
