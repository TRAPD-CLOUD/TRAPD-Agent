//! Userspace ptrace self-detection.
//!
//! Every `CHECK_INTERVAL_SECS` seconds the monitor reads `/proc/self/status`
//! and checks the `TracerPid` field.  A non-zero value indicates that another
//! process has attached to the agent via ptrace(2) — a strong indicator of
//! live debugging or memory-inspection attempts.
//!
//! When a new tracer is detected a `severity: critical` `AgentTamper` event
//! is emitted and a warning is logged.  The event is NOT deduplicated across
//! polls so that every new attachment produces a fresh alert.
//!
//! Note: kernel-level ptrace DETECTION via eBPF tracepoint is handled by
//! `EbpfSyscallCollector` (sys_enter_ptrace).  This module provides a
//! defence-in-depth fallback that works even when eBPF is unavailable.

use std::time::Duration;

use tokio::sync::mpsc::Sender;
use tokio::time::interval;
use tracing::warn;

use crate::schema::{AgentEvent, AgentTamperData, EventAction, EventClass, EventData, Severity};

const CHECK_INTERVAL_SECS: u64 = 10;

/// Async task — runs indefinitely, polling `/proc/self/status`.
pub async fn run(tx: Sender<AgentEvent>, agent_id: String, hostname: String) {
    let mut ticker     = interval(Duration::from_secs(CHECK_INTERVAL_SECS));
    let mut prev_tracer: u32 = 0;

    loop {
        ticker.tick().await;

        let tracer = read_tracer_pid();

        if tracer != 0 && tracer != prev_tracer {
            warn!(
                tracer_pid = tracer,
                agent_pid  = std::process::id(),
                "ANTI-TAMPER: ptrace attachment detected on agent process"
            );

            let ev = AgentEvent::new(
                agent_id.clone(),
                hostname.clone(),
                EventClass::Process,
                EventAction::AgentTamper,
                Severity::Critical,
                EventData::AgentTamper(AgentTamperData {
                    path: format!(
                        "/proc/{}/status [TracerPid={}]",
                        std::process::id(),
                        tracer
                    ),
                    action: "ptrace_attach_detected".to_string(),
                }),
            );
            let _ = tx.send(ev).await;
        }

        prev_tracer = tracer;
    }
}

/// Read `TracerPid` from `/proc/self/status`.
/// Returns 0 if the field is absent or the file cannot be read.
fn read_tracer_pid() -> u32 {
    std::fs::read_to_string("/proc/self/status")
        .unwrap_or_default()
        .lines()
        .find_map(|line| {
            line.trim()
                .strip_prefix("TracerPid:")
                .and_then(|s| s.trim().parse::<u32>().ok())
        })
        .unwrap_or(0)
}
