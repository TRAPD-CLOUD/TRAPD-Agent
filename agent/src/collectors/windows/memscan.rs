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
use sysinfo::{ProcessRefreshKind, System, UpdateKind};
use tokio::sync::mpsc::Sender;
use tokio::time::{interval, Duration};
use tracing::info;

use crate::collectors::mem_finding::{finding_to_detection, MemFindingKey};
use crate::collectors::win_mem_rules::{
    classify, is_jit_module, is_jit_process, is_protected_image_path, RegionContext,
};
use crate::collectors::Collector;
use crate::config::AgentConfig;
use crate::prevention::winproc;
use crate::schema::{AgentEvent, EventAction, EventClass, EventData, Severity};

/// Upper bound on candidate regions inspected per process per sweep.
const MAX_REGIONS_PER_PROCESS: usize = 256;
type SweepFindings = Vec<(Severity, crate::schema::DetectionData)>;
type LiveGenerations = HashSet<(i32, u64)>;

pub struct MemScanCollector {
    cfg: Arc<RwLock<AgentConfig>>,
    /// Already-reported generation/rule/region findings, so a standing condition is
    /// reported once rather than every interval.
    seen: HashSet<MemFindingKey>,
}

impl MemScanCollector {
    pub fn new(cfg: Arc<RwLock<AgentConfig>>) -> Self {
        Self {
            cfg,
            seen: HashSet::new(),
        }
    }
}

// The snapshot must include image paths used by the shared confidence rules.
fn snapshot_processes() -> System {
    let mut sys = System::new();
    sys.refresh_processes_specifics(ProcessRefreshKind::new().with_exe(UpdateKind::OnlyIfNotSet));
    sys
}

/// One blocking sweep over every process. Returns the new findings and the set
/// of live generations (to forget findings of exited or reused PIDs).
fn sweep(own_pid: i32, seen: &mut HashSet<MemFindingKey>) -> (SweepFindings, LiveGenerations) {
    let sys = snapshot_processes();
    let mut findings = Vec::new();
    let mut live = HashSet::new();
    // Capture generations before the thread snapshot: a recycled PID must not
    // combine the old process's thread addresses with the new process's memory.
    let generations: std::collections::HashMap<i32, u64> = sys
        .processes()
        .keys()
        .filter_map(|pid| {
            let pid = pid.as_u32() as i32;
            crate::telemetry::identity::process_start_time(pid).map(|start| (pid, start))
        })
        .collect();
    // One snapshot of every thread's start address for the whole sweep.
    let thread_starts = winproc::thread_start_addresses();

    for (pid, process) in sys.processes() {
        let pid = pid.as_u32() as i32;
        // Idle, System, and ourselves.
        if pid <= 4 || pid == own_pid {
            continue;
        }
        let Some(&process_start_time) = generations.get(&pid) else {
            continue;
        };
        live.insert((pid, process_start_time));
        let name = process.name().to_string();
        // Unreadable (protected / exited) processes are skipped silently: a
        // sweep that fails per process must not fail as a whole.
        let Ok(regions) = winproc::inspect_unbacked_executable(pid, MAX_REGIONS_PER_PROCESS) else {
            continue;
        };
        if regions.is_empty() {
            continue;
        }
        let protected_image = process
            .exe()
            .is_some_and(|exe| is_protected_image_path(&exe.to_string_lossy()));
        let mut process_findings = Vec::new();
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
                protected_image,
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
            let key = MemFindingKey::new(
                pid,
                process_start_time,
                &f,
                r.region.base,
                r.region.is_writable_executable(),
            );
            let mut det = finding_to_detection(pid, &name, &f);
            det.evidence["process_start_time"] = process_start_time.into();
            process_findings.push((key, f.severity, det));
        }
        // The helper queries open their own process handles. Never attach
        // findings from one generation to a PID that changed during the sweep.
        if crate::telemetry::identity::process_start_time(pid) != Some(process_start_time) {
            live.remove(&(pid, process_start_time));
            continue;
        }
        for (key, severity, det) in process_findings {
            if seen.insert(key) {
                findings.push((severity, det));
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
        if !self
            .cfg
            .read()
            .map(|c| c.memory_scan_enabled)
            .unwrap_or(false)
        {
            info!("Windows memscan: disabled by config");
        }
        let own_pid = std::process::id() as i32;
        let mut ticker = interval(Duration::from_secs(1));
        let mut last_sweep: Option<tokio::time::Instant> = None;
        loop {
            tokio::select! {
                _ = tx.closed() => return Ok(()),
                _ = ticker.tick() => {}
            }
            let (enabled, interval_secs) = self
                .cfg
                .read()
                .map(|c| (c.memory_scan_enabled, c.memory_scan_interval_secs))
                .unwrap_or((false, 30));
            if !enabled {
                last_sweep = None;
                continue;
            }
            if last_sweep
                .is_some_and(|last| last.elapsed() < Duration::from_secs(interval_secs.max(30)))
            {
                continue;
            }
            last_sweep = Some(tokio::time::Instant::now());

            let mut seen = std::mem::take(&mut self.seen);
            let swept = tokio::task::spawn_blocking(move || {
                let (findings, live) = sweep(own_pid, &mut seen);
                (findings, live, seen)
            })
            .await;
            let Ok((findings, live, mut seen)) = swept else {
                continue; // the sweep panicked: skip this interval, keep running
            };
            seen.retain(|key| live.contains(&(key.pid, key.process_start_time)));
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
    use crate::collectors::mem_finding::MemFinding;
    use windows_sys::Win32::System::Memory::{
        VirtualAlloc, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE,
    };

    #[test]
    fn sweep_snapshot_contains_the_current_process_image_path() {
        let sys = snapshot_processes();
        let own_pid = sysinfo::Pid::from_u32(std::process::id());
        let process = sys
            .process(own_pid)
            .expect("current process must be listed");
        let executable = process.exe().expect("sweep must request executable paths");
        assert_eq!(executable, std::env::current_exe().unwrap());
    }

    #[tokio::test]
    async fn initially_disabled_collector_waits_for_config_activation() {
        let config = AgentConfig {
            memory_scan_enabled: false,
            ..AgentConfig::default()
        };
        let cfg = Arc::new(RwLock::new(config));
        let mut collector = MemScanCollector::new(cfg.clone());
        let (tx, rx) = tokio::sync::mpsc::channel(16);
        let task = tokio::spawn(async move { collector.run(tx, "a".into(), "h".into()).await });
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(
            !task.is_finished(),
            "disabled collectors must remain available to config updates"
        );
        cfg.write().unwrap().memory_scan_enabled = true;
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(!task.is_finished());
        drop(rx);
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }

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
            MemFindingKey::new(7, 100, &rwx, 0x1000, true),
            MemFindingKey::new(7, 100, &rwx, 0x9000, true)
        );
        let pe = MemFinding {
            rule_id: "memory.injected_pe",
            ..rwx.clone()
        };
        assert_ne!(
            MemFindingKey::new(7, 100, &pe, 0x1000, true),
            MemFindingKey::new(7, 100, &pe, 0x9000, true)
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
            let seen = starts
                .get(&(std::process::id() as i32))
                .is_some_and(|mine| mine.contains(&(base as u64)));
            // Clean up the busy-loop fixture before any assertion can panic.
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
