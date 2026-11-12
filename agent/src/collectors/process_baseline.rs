//! Bounded baseline of the processes that were already running when the agent
//! started.
//!
//! Process creation events only exist for processes that *started after* the
//! agent. A shell, `sshd` or `explorer.exe` launched before the agent therefore
//! never produced one, and the backend cannot resolve the parent of anything
//! they spawn (`parent_not_found`). The baseline closes that gap by emitting
//! each already-running process once, as an `EventClass::Process` /
//! `EventAction::Snapshot` event carrying the ordinary [`ProcessCreateData`].
//!
//! `Snapshot` (not `Create`) is the marker: these processes were not *created*
//! by anything we observed, so creation-driven detection and enforcement must
//! not treat them as new executions. Agent-side consumers that key on
//! `ProcessCreate` (Windows exec prevention, the flight recorder) skip them.
//!
//! Identity follows the repository rule: a process is `(pid, start time)`. An
//! entry without a start time can never be correlated, so it is not emitted,
//! and `parent_start_time` is only set when the parent generation is provably
//! older than the child ([`parent_generation_before_child`]); a recycled PID or
//! a missing start time leaves it unknown.
//!
//! Pure selection ([`build_baseline`]) is separated from I/O ([`emit_baseline`])
//! so both bounds (count cap, emission rate) are testable with fakes.

use std::collections::HashMap;
use std::time::Duration;

use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::mpsc::Sender;
use tracing::{info, warn};

use crate::schema::{AgentEvent, EventAction, EventClass, EventData, ProcessCreateData, Severity};
use crate::telemetry::identity::parent_generation_before_child;
use crate::telemetry::metrics::metrics;
use crate::telemetry::DropReason;

/// Upper bound on baseline events per agent start.
pub const MAX_BASELINE_PROCESSES: usize = 4096;
/// Events sent back to back before pausing.
pub const EMIT_BATCH: usize = 64;
/// Pause between batches: 4096 events take roughly 3 s, so startup cannot
/// flood the channel shared with live collectors.
pub const EMIT_PAUSE: Duration = Duration::from_millis(50);

/// Result of selecting which running processes become baseline events.
#[derive(Debug, Default)]
pub struct Baseline {
    /// Sorted by pid, `parent_start_time` filled where provable.
    pub processes: Vec<ProcessCreateData>,
    /// Skipped because no start time could be read (cannot be correlated).
    pub skipped_unknown_start: usize,
    /// Skipped because of the count cap.
    pub dropped_over_cap: usize,
}

/// Select and annotate the baseline from one process-table read.
///
/// Lowest pids win when the cap is hit: parents are overwhelmingly older than
/// their children, so the cap sheds the most recently started processes, which
/// the live collectors are about to observe anyway.
pub fn build_baseline(table: Vec<ProcessCreateData>, cap: usize) -> Baseline {
    let mut by_pid: HashMap<i32, ProcessCreateData> = HashMap::with_capacity(table.len());
    let mut skipped_unknown_start = 0;
    for p in table {
        // Start time 0 is "unknown" on every platform we read it from.
        if p.process_start_time.is_none_or(|s| s == 0) {
            skipped_unknown_start += 1;
            continue;
        }
        by_pid.insert(p.pid, p);
    }

    let starts: HashMap<i32, u64> = by_pid
        .iter()
        .filter_map(|(pid, p)| p.process_start_time.map(|s| (*pid, s)))
        .collect();

    let mut processes: Vec<ProcessCreateData> = by_pid.into_values().collect();
    processes.sort_unstable_by_key(|p| p.pid);
    let dropped_over_cap = processes.len().saturating_sub(cap);
    processes.truncate(cap);

    for p in &mut processes {
        p.parent_start_time = starts
            .get(&p.ppid)
            .and_then(|parent| parent_generation_before_child(p.process_start_time, Some(*parent)));
    }

    Baseline {
        processes,
        skipped_unknown_start,
        dropped_over_cap,
    }
}

/// What [`emit_baseline`] managed to hand to the channel.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct EmitReport {
    pub sent: usize,
    pub dropped_channel_full: usize,
    /// The receiver is gone; the remaining events were not attempted.
    pub channel_closed: bool,
}

/// Send the baseline in rate-limited batches.
///
/// Uses `try_send`: a full channel means live telemetry is competing, and the
/// baseline is the lower-priority stream, so it is shed and counted
/// ([`DropReason::UserspaceChannelFull`]) instead of blocking.
pub async fn emit_baseline(
    tx: &Sender<AgentEvent>,
    agent_id: &str,
    hostname: &str,
    baseline: Baseline,
    batch: usize,
    pause: Duration,
) -> EmitReport {
    let mut report = EmitReport::default();
    metrics().events_dropped(
        DropReason::RateLimitApplied,
        baseline.dropped_over_cap as u64,
    );
    if baseline.dropped_over_cap > 0 {
        warn!(
            dropped = baseline.dropped_over_cap,
            cap = MAX_BASELINE_PROCESSES,
            "process baseline capped; newest pids omitted"
        );
    }

    let total = baseline.processes.len();
    for (i, data) in baseline.processes.into_iter().enumerate() {
        if i > 0 && batch > 0 && i % batch == 0 && !pause.is_zero() {
            tokio::time::sleep(pause).await;
        }
        let event = AgentEvent::new(
            agent_id.to_string(),
            hostname.to_string(),
            EventClass::Process,
            EventAction::Snapshot,
            Severity::Info,
            EventData::ProcessCreate(data),
        );
        match tx.try_send(event) {
            Ok(()) => report.sent += 1,
            Err(TrySendError::Full(_)) => {
                metrics().event_dropped(DropReason::UserspaceChannelFull);
                report.dropped_channel_full += 1;
            }
            Err(TrySendError::Closed(_)) => {
                report.channel_closed = true;
                break;
            }
        }
    }
    info!(
        sent = report.sent,
        total,
        skipped_unknown_start = baseline.skipped_unknown_start,
        "process baseline emitted"
    );
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(pid: i32, ppid: i32, start: Option<u64>) -> ProcessCreateData {
        ProcessCreateData {
            pid,
            ppid,
            name: format!("p{pid}"),
            process_start_time: start,
            ..Default::default()
        }
    }

    #[test]
    fn links_parent_generation_when_older_than_child() {
        let b = build_baseline(vec![p(1, 0, Some(10)), p(50, 1, Some(20))], 100);
        let child = b.processes.iter().find(|x| x.pid == 50).unwrap();
        assert_eq!(child.parent_start_time, Some(10));
        let root = b.processes.iter().find(|x| x.pid == 1).unwrap();
        assert_eq!(root.parent_start_time, None);
    }

    #[test]
    fn recycled_parent_pid_is_not_linked() {
        // Child (start 20) names ppid 7, but pid 7 now belongs to a process
        // that started later (30): a different generation than the real parent.
        let b = build_baseline(vec![p(7, 1, Some(30)), p(50, 7, Some(20))], 100);
        let child = b.processes.iter().find(|x| x.pid == 50).unwrap();
        assert_eq!(child.parent_start_time, None);
    }

    #[test]
    fn equal_start_times_are_not_provable() {
        let b = build_baseline(vec![p(7, 1, Some(20)), p(50, 7, Some(20))], 100);
        assert_eq!(b.processes[1].parent_start_time, None);
    }

    #[test]
    fn missing_or_zero_start_time_is_skipped_and_never_a_parent_link() {
        let b = build_baseline(
            vec![p(7, 1, None), p(8, 1, Some(0)), p(50, 7, Some(20))],
            100,
        );
        assert_eq!(b.skipped_unknown_start, 2);
        assert_eq!(b.processes.len(), 1);
        assert_eq!(b.processes[0].parent_start_time, None);
    }

    #[test]
    fn cap_keeps_lowest_pids_and_counts_the_rest() {
        let table: Vec<_> = (1..=10).map(|i| p(i, 0, Some(i as u64))).collect();
        let b = build_baseline(table, 4);
        assert_eq!(
            b.processes.iter().map(|x| x.pid).collect::<Vec<_>>(),
            vec![1, 2, 3, 4]
        );
        assert_eq!(b.dropped_over_cap, 6);
    }

    #[test]
    fn capped_out_parent_is_still_used_for_the_link_of_kept_children() {
        // Parent pid 9 (older) is capped out; the kept child must still
        // resolve its generation from the full table.
        let b = build_baseline(vec![p(2, 9, Some(20)), p(9, 0, Some(5))], 1);
        assert_eq!(b.processes.len(), 1);
        assert_eq!(b.processes[0].parent_start_time, Some(5));
    }

    #[tokio::test]
    async fn emits_snapshot_action_with_process_create_payload() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        let b = build_baseline(vec![p(1, 0, Some(1))], 10);
        let r = emit_baseline(&tx, "a", "h", b, EMIT_BATCH, Duration::ZERO).await;
        assert_eq!(r.sent, 1);
        let ev = rx.recv().await.unwrap();
        assert!(matches!(ev.action, EventAction::Snapshot));
        assert!(matches!(ev.class, EventClass::Process));
        assert!(matches!(ev.data, EventData::ProcessCreate(_)));
    }

    #[tokio::test]
    async fn full_channel_sheds_and_counts_without_blocking() {
        let (tx, _rx) = tokio::sync::mpsc::channel(2);
        let table: Vec<_> = (1..=5).map(|i| p(i, 0, Some(i as u64))).collect();
        let b = build_baseline(table, 10);
        let r = emit_baseline(&tx, "a", "h", b, 2, Duration::ZERO).await;
        assert_eq!(r.sent, 2);
        assert_eq!(r.dropped_channel_full, 3);
    }

    #[tokio::test]
    async fn closed_channel_stops_early() {
        let (tx, rx) = tokio::sync::mpsc::channel(2);
        drop(rx);
        let b = build_baseline(vec![p(1, 0, Some(1)), p(2, 0, Some(2))], 10);
        let r = emit_baseline(&tx, "a", "h", b, 1, Duration::ZERO).await;
        assert!(r.channel_closed);
        assert_eq!(r.sent, 0);
    }

    #[tokio::test]
    async fn emission_is_paced_in_batches() {
        let (tx, _rx) = tokio::sync::mpsc::channel(64);
        let table: Vec<_> = (1..=10).map(|i| p(i, 0, Some(i as u64))).collect();
        let b = build_baseline(table, 10);
        let t0 = std::time::Instant::now();
        emit_baseline(&tx, "a", "h", b, 4, Duration::from_millis(30)).await;
        // 10 events / batch 4 => pauses before events 4 and 8.
        assert!(t0.elapsed() >= Duration::from_millis(60));
    }
}
