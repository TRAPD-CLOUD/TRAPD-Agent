//! Periodic process-memory sweep for code injection — the Windows counterpart
//! of the Linux `/proc/<pid>/maps` scanner.
//!
//! Every interval, each process's address space is walked with `VirtualQueryEx`
//! and its executable, non-image regions are classified by the shared rules
//! ([`crate::collectors::win_mem_rules`]): RWX private/mapped memory, and PE
//! images sitting in memory a process allocated itself (reflective injection).
//! Only region metadata and the first KiB of candidate regions are read.
//! Findings are first-class detections carrying the pid in `evidence`, so the
//! response engine can act on them exactly as it does for Linux.

use std::collections::HashSet;
use std::sync::{Arc, RwLock};

use anyhow::Result;
use async_trait::async_trait;
use sysinfo::{ProcessRefreshKind, System};
use tokio::sync::mpsc::Sender;
use tokio::time::{interval, Duration};
use tracing::info;

use crate::collectors::mem_finding::{finding_to_detection, MemFinding};
use crate::collectors::win_mem_rules::{classify, is_jit_module, is_jit_process, RegionContext};
use crate::collectors::Collector;
use crate::config::AgentConfig;
use crate::prevention::winproc;
use crate::schema::{AgentEvent, EventAction, EventClass, EventData, Severity};

/// Upper bound on candidate regions inspected per process per sweep.
const MAX_REGIONS_PER_PROCESS: usize = 256;

pub struct MemScanCollector {
    cfg: Arc<RwLock<AgentConfig>>,
    /// Already-reported `pid:rule:key` findings, so a standing condition is
    /// reported once rather than every interval.
    seen: HashSet<String>,
}

impl MemScanCollector {
    pub fn new(cfg: Arc<RwLock<AgentConfig>>) -> Self {
        Self {
            cfg,
            seen: HashSet::new(),
        }
    }
}

/// Dedup key: anonymous RWX is reported once per process (a JIT-like allocator
/// keeps creating fresh regions); an injected PE is reported per image base.
fn dedup_key(pid: i32, finding: &MemFinding, base: u64, writable: bool) -> String {
    // A running-thread finding is specific to its region; context findings are
    // grouped per process.
    if finding.rule_id == "memory.anon_exec" && finding.confidence < 50 {
        format!("{pid}:{}:{writable}", finding.rule_id)
    } else {
        format!("{pid}:{}:{base:#x}", finding.rule_id)
    }
}

/// One blocking sweep over every process. Returns the new findings and the set
/// of live pids (to forget findings of processes that have exited).
fn sweep(
    own_pid: i32,
    seen: &mut HashSet<String>,
) -> (Vec<(Severity, crate::schema::DetectionData)>, HashSet<i32>) {
    let mut sys = System::new();
    sys.refresh_processes_specifics(ProcessRefreshKind::new());
    let mut findings = Vec::new();
    let mut live = HashSet::new();
    // One snapshot of every thread's start address for the whole sweep.
    let thread_starts = winproc::thread_start_addresses();

    for (pid, process) in sys.processes() {
        let pid = pid.as_u32() as i32;
        live.insert(pid);
        // Idle, System, and ourselves.
        if pid <= 4 || pid == own_pid {
            continue;
        }
        let name = process.name().to_string();
        // Unreadable (protected / exited) processes are skipped silently: a
        // sweep that fails per process must not fail as a whole.
        let Ok(regions) = winproc::inspect_unbacked_executable(pid, MAX_REGIONS_PER_PROCESS) else {
            continue;
        };
        if regions.is_empty() {
            continue;
        }
        let starts = thread_starts.get(&pid).map(Vec::as_slice).unwrap_or(&[]);
        // Resolve the (more expensive) module list only when a rule would
        // actually fire for the process name alone.
        let mut jit = is_jit_process(&name);
        let mut modules_checked = jit;
        for r in &regions {
            let mut ctx = RegionContext {
                header_is_pe: r.header_is_pe,
                thread_started_here: starts.iter().any(|a| r.region.contains(*a)),
                jit_runtime: jit,
            };
            let mut finding = classify(&r.region, ctx);
            if finding.is_some()
                && !modules_checked
                && !ctx.header_is_pe
                && !ctx.thread_started_here
            {
                modules_checked = true;
                jit = winproc::module_names(pid).iter().any(|m| is_jit_module(m));
                ctx.jit_runtime = jit;
                finding = classify(&r.region, ctx);
            }
            let Some(f) = finding else { continue };
            let key = dedup_key(pid, &f, r.region.base, r.region.is_writable_executable());
            if seen.insert(key) {
                findings.push((f.severity, finding_to_detection(pid, &name, &f)));
            }
        }
    }
    (findings, live)
}

#[async_trait]
impl Collector for MemScanCollector {
    fn name(&self) -> &'static str {
        "WindowsMemScanCollector"
    }

    async fn run(
        &mut self,
        tx: Sender<AgentEvent>,
        agent_id: String,
        hostname: String,
    ) -> Result<()> {
        let (enabled, interval_secs) = {
            let c = self.cfg.read().expect("config lock");
            (c.memory_scan_enabled, c.memory_scan_interval_secs)
        };
        if !enabled {
            info!("Windows memscan: disabled by config");
            return Ok(());
        }
        let own_pid = std::process::id() as i32;
        let mut ticker = interval(Duration::from_secs(interval_secs.max(30)));
        loop {
            ticker.tick().await;
            // Re-check the toggle so a hot config reload can switch us off.
            if !self
                .cfg
                .read()
                .map(|c| c.memory_scan_enabled)
                .unwrap_or(false)
            {
                continue;
            }

            let mut seen = std::mem::take(&mut self.seen);
            let swept = tokio::task::spawn_blocking(move || {
                let (findings, live) = sweep(own_pid, &mut seen);
                (findings, live, seen)
            })
            .await;
            let Ok((findings, live, mut seen)) = swept else {
                continue; // the sweep panicked: skip this interval, keep running
            };
            // Forget findings for processes that have since exited.
            seen.retain(|k| {
                k.split_once(':')
                    .and_then(|(p, _)| p.parse::<i32>().ok())
                    .map(|p| live.contains(&p))
                    .unwrap_or(false)
            });
            self.seen = seen;

            for (severity, det) in findings {
                let event = AgentEvent::new(
                    agent_id.clone(),
                    hostname.clone(),
                    EventClass::Detection,
                    EventAction::Detected,
                    severity,
                    EventData::Detection(Box::new(det)),
                );
                if tx.send(event).await.is_err() {
                    return Ok(());
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::System::Memory::{
        VirtualAlloc, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE,
    };

    #[test]
    fn dedup_key_groups_context_per_process_and_alerts_per_region() {
        let rwx = MemFinding {
            rule_id: "memory.anon_exec",
            title: "",
            technique: "T1055",
            confidence: 48,
            severity: Severity::High,
            region: String::new(),
        };
        assert_eq!(
            dedup_key(7, &rwx, 0x1000, true),
            dedup_key(7, &rwx, 0x9000, true)
        );
        let pe = MemFinding {
            rule_id: "memory.injected_pe",
            ..rwx.clone()
        };
        assert_ne!(
            dedup_key(7, &pe, 0x1000, true),
            dedup_key(7, &pe, 0x9000, true)
        );
    }

    /// Native, end to end: this very test process allocates RWX memory and
    /// plants a PE header in it; the sweep's own primitives must see both.
    #[test]
    fn inspection_finds_rwx_memory_and_a_planted_pe_header_in_a_live_process() {
        // SAFETY: a private RWX allocation owned by this test, written within
        // its bounds and intentionally leaked for the process lifetime.
        let base = unsafe {
            VirtualAlloc(
                std::ptr::null(),
                0x2000,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            )
        } as *mut u8;
        assert!(!base.is_null(), "VirtualAlloc failed");
        let mut image = vec![0u8; 0x200];
        image[0] = b'M';
        image[1] = b'Z';
        image[0x3c] = 0x80;
        image[0x80..0x84].copy_from_slice(b"PE\0\0");
        unsafe { std::ptr::copy_nonoverlapping(image.as_ptr(), base, image.len()) };

        let regions =
            winproc::inspect_unbacked_executable(std::process::id() as i32, 4096).unwrap();
        let ours = regions
            .iter()
            .find(|r| r.region.base == base as u64)
            .expect("the allocation must be reported");
        assert!(ours.region.is_writable_executable());
        assert!(
            ours.header_is_pe,
            "the planted PE header must be recognised"
        );
        let f = classify(
            &ours.region,
            RegionContext {
                header_is_pe: ours.header_is_pe,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(f.rule_id, "memory.injected_pe");
    }

    /// Native, end to end: a thread whose start address is inside a private RWX
    /// allocation of this process (the shape of `CreateRemoteThread` shellcode)
    /// must be visible to the sweep and classified as injected code running.
    #[test]
    fn a_thread_started_in_rwx_memory_is_detected_as_running_injected_code() {
        use windows_sys::Win32::System::Threading::{CreateThread, TerminateThread};
        // SAFETY: a private RWX allocation owned by this test containing `jmp $`
        // (EB FE), an endless loop; the thread is terminated before returning.
        unsafe {
            let base = VirtualAlloc(
                std::ptr::null(),
                0x1000,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            ) as *mut u8;
            assert!(!base.is_null());
            *base = 0xEB;
            *base.add(1) = 0xFE;
            let entry: unsafe extern "system" fn(*mut core::ffi::c_void) -> u32 =
                std::mem::transmute(base);
            let thread = CreateThread(
                std::ptr::null(),
                0,
                Some(entry),
                std::ptr::null(),
                0,
                std::ptr::null_mut(),
            );
            assert!(!thread.is_null(), "CreateThread failed");

            let starts = winproc::thread_start_addresses();
            let mine = starts
                .get(&(std::process::id() as i32))
                .expect("this process has threads");
            let seen = mine.contains(&(base as u64));
            TerminateThread(thread, 0);
            windows_sys::Win32::Foundation::CloseHandle(thread);
            assert!(
                seen,
                "the shellcode thread's start address must be reported"
            );

            let regions =
                winproc::inspect_unbacked_executable(std::process::id() as i32, 4096).unwrap();
            let ours = regions
                .iter()
                .find(|r| r.region.base == base as u64)
                .expect("region reported");
            let f = classify(
                &ours.region,
                RegionContext {
                    thread_started_here: true,
                    ..Default::default()
                },
            )
            .unwrap();
            assert!(f.confidence >= 90, "{f:?}");
        }
    }
}
