//! Pipeline health model.
//!
//! Health is *derived*, never stored: [`HealthState::evaluate`] is a pure
//! function of a [`super::metrics::MetricsSnapshot`], so the reported state can
//! never drift from the counters it claims to summarise, and the whole state
//! machine is testable without running an agent.
//!
//! The variants are ordered by severity and evaluated most-severe-first, so a
//! host that is both backpressured and has a corrupt journal reports the
//! condition that needs an operator (`recovery_required`), not the one that may
//! resolve itself.

use serde::{Deserialize, Serialize};

use super::metrics::MetricsSnapshot;

/// Spool fill at which the queue is reported as nearing capacity.  Chosen to
/// leave room to act: at typical event rates the remaining 20 % is minutes, not
/// seconds, of headroom.
pub const QUEUE_NEAR_CAPACITY: f64 = 0.80;

/// Spool fill at which the queue is treated as full.
pub const QUEUE_FULL: f64 = 0.98;

/// How long the backend may go without acknowledging before the agent reports
/// `offline`.  Six flush intervals, so a couple of transient failures do not
/// flap the state.
pub const ACK_STALE_MS: u64 = 30_000;

/// Overall pipeline state, most severe first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthState {
    /// Operator action needed: the journal held records that failed checksum
    /// validation, so telemetry was lost to corruption rather than to policy.
    RecoveryRequired,
    /// Every process collector failed to start; the host is not being observed.
    CollectorFailed,
    /// The persistent queue is at capacity — new events are now being dropped.
    QueueFull,
    /// The queue is filling and will overflow if the trend continues.
    QueueNearCapacity,
    /// Events are being shed because a downstream stage cannot keep up.
    Backpressured,
    /// No backend acknowledgement within [`ACK_STALE_MS`]; events are
    /// accumulating locally.  Expected and harmless in offline mode.
    Offline,
    /// Running, but with losses or failures recorded that do not yet threaten
    /// delivery.
    Degraded,
    /// Everything nominal.
    Healthy,
}

impl HealthState {
    pub const fn as_str(self) -> &'static str {
        match self {
            HealthState::RecoveryRequired => "recovery_required",
            HealthState::CollectorFailed => "collector_failed",
            HealthState::QueueFull => "queue_full",
            HealthState::QueueNearCapacity => "queue_near_capacity",
            HealthState::Backpressured => "backpressured",
            HealthState::Offline => "offline",
            HealthState::Degraded => "degraded",
            HealthState::Healthy => "healthy",
        }
    }

    /// True when the agent needs a human.
    pub const fn needs_attention(self) -> bool {
        matches!(
            self,
            HealthState::RecoveryRequired | HealthState::CollectorFailed | HealthState::QueueFull
        )
    }

    /// Derive the state from a metrics snapshot.
    ///
    /// `offline_mode` suppresses the `offline` verdict: with no backend
    /// configured, "not acknowledging" is the design, not a fault.
    /// `now_unix_ms` is passed in rather than read so the model is testable.
    pub fn evaluate(snap: &MetricsSnapshot, offline_mode: bool, now_unix_ms: u64) -> Self {
        // Corruption first: it means telemetry was destroyed, and unlike a full
        // queue it will not clear on its own.
        if snap.spool_corrupt_records_total > 0 {
            return HealthState::RecoveryRequired;
        }

        // A drop with no reason attached breaks the pipeline's core promise, so
        // it is escalated to the same tier as corruption.
        if !snap.drops_fully_attributed() {
            return HealthState::RecoveryRequired;
        }

        if snap.collector_mode == "failed" || snap.collector_failures_total > 0 {
            return HealthState::CollectorFailed;
        }

        let utilization = snap.spool_utilization();
        if utilization >= QUEUE_FULL {
            return HealthState::QueueFull;
        }

        // Shedding for capacity reasons is backpressure; other drop reasons are
        // faults and only reach `degraded`.
        let backpressure_drops = snap
            .collector_events_dropped_by_reason
            .get("userspace_channel_full")
            .copied()
            .unwrap_or(0)
            + snap
                .collector_events_dropped_by_reason
                .get("persistent_queue_full")
                .copied()
                .unwrap_or(0)
            + snap
                .collector_events_dropped_by_reason
                .get("rate_limit_applied")
                .copied()
                .unwrap_or(0);

        if utilization >= QUEUE_NEAR_CAPACITY {
            return HealthState::QueueNearCapacity;
        }

        if backpressure_drops > 0 {
            return HealthState::Backpressured;
        }

        if !offline_mode {
            let stale = match snap.last_ack_unix_ms {
                // Nothing acknowledged yet, but events are queued and waiting.
                None => snap.spool_events > 0,
                Some(ts) => now_unix_ms.saturating_sub(ts) > ACK_STALE_MS,
            };
            if stale || !snap.backend_connected {
                return HealthState::Offline;
            }
        }

        if snap.collector_events_dropped_total > 0
            || snap.ebpf_events_lost_total > 0
            || snap.transport_batches_failed_total > 0
            || enrichment_is_unhealthy(snap)
        {
            return HealthState::Degraded;
        }

        HealthState::Healthy
    }
}

/// Fraction of enrichment attempts that may fail before it is treated as a
/// fault rather than normal operation.
pub const ENRICHMENT_FAILURE_RATIO: f64 = 0.5;

/// Whether enrichment failures indicate an actual problem.
///
/// Some failures are unavoidable and expected: an event is enriched from
/// `/proc` *after* the exec, and short-lived processes — the ones the eBPF
/// tracer exists to catch — routinely exit first. On a busy host that count is
/// never zero, so treating any failure as degradation would pin health at
/// "degraded" permanently and train operators to ignore it.
///
/// A *majority* of attempts failing is different: that is `hidepid`, missing
/// capabilities, or a broken `/proc` mount, and it does warrant attention.
fn enrichment_is_unhealthy(snap: &MetricsSnapshot) -> bool {
    if snap.enrichment_failures_total == 0 || snap.enrichment_attempts_total == 0 {
        return false;
    }
    let ratio = snap.enrichment_failures_total as f64 / snap.enrichment_attempts_total as f64;
    ratio > ENRICHMENT_FAILURE_RATIO
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nominal() -> MetricsSnapshot {
        MetricsSnapshot {
            collector_mode: "ebpf".into(),
            backend_connected: true,
            last_ack_unix_ms: Some(1_000_000),
            spool_capacity_events: 1_000,
            spool_capacity_bytes: 1_000_000,
            ..Default::default()
        }
    }

    const NOW: u64 = 1_000_000;

    #[test]
    fn nominal_snapshot_is_healthy() {
        assert_eq!(
            HealthState::evaluate(&nominal(), false, NOW),
            HealthState::Healthy
        );
    }

    #[test]
    fn corrupt_records_demand_recovery() {
        let mut s = nominal();
        s.spool_corrupt_records_total = 1;
        assert_eq!(
            HealthState::evaluate(&s, false, NOW),
            HealthState::RecoveryRequired
        );
    }

    #[test]
    fn unattributed_drops_demand_recovery() {
        // The pipeline's core promise: every drop names a reason.  A total that
        // exceeds the sum of the per-reason counters means something lost an
        // event silently.
        let mut s = nominal();
        s.collector_events_dropped_total = 5;
        // ...with no per-reason breakdown recorded.
        assert!(!s.drops_fully_attributed());
        assert_eq!(
            HealthState::evaluate(&s, false, NOW),
            HealthState::RecoveryRequired
        );
    }

    #[test]
    fn attributed_drops_are_only_degraded() {
        let mut s = nominal();
        s.collector_events_dropped_total = 5;
        s.collector_events_dropped_by_reason
            .insert("event_too_large".into(), 5);
        assert_eq!(
            HealthState::evaluate(&s, false, NOW),
            HealthState::Degraded,
            "a fully-explained loss is degraded, not a recovery case"
        );
    }

    #[test]
    fn collector_failure_outranks_queue_pressure() {
        let mut s = nominal();
        s.collector_failures_total = 1;
        s.spool_events = 990; // also queue-full territory
        assert_eq!(
            HealthState::evaluate(&s, false, NOW),
            HealthState::CollectorFailed,
            "an unobserved host is worse than a full queue"
        );
    }

    #[test]
    fn failed_collector_mode_is_detected() {
        let mut s = nominal();
        s.collector_mode = "failed".into();
        assert_eq!(
            HealthState::evaluate(&s, false, NOW),
            HealthState::CollectorFailed
        );
    }

    #[test]
    fn queue_thresholds_escalate_in_order() {
        let mut s = nominal();

        s.spool_events = 700; // 70 %
        assert_eq!(HealthState::evaluate(&s, true, NOW), HealthState::Healthy);

        s.spool_events = 850; // 85 %
        assert_eq!(
            HealthState::evaluate(&s, true, NOW),
            HealthState::QueueNearCapacity
        );

        s.spool_events = 990; // 99 %
        assert_eq!(HealthState::evaluate(&s, true, NOW), HealthState::QueueFull);
    }

    #[test]
    fn byte_capacity_alone_can_fill_the_queue() {
        let mut s = nominal();
        s.spool_events = 1; // trivially small by count
        s.spool_bytes = 999_000; // but nearly out of bytes
        assert_eq!(HealthState::evaluate(&s, true, NOW), HealthState::QueueFull);
    }

    #[test]
    fn capacity_shedding_is_backpressure() {
        let mut s = nominal();
        s.collector_events_dropped_total = 3;
        s.collector_events_dropped_by_reason
            .insert("userspace_channel_full".into(), 3);
        assert_eq!(
            HealthState::evaluate(&s, false, NOW),
            HealthState::Backpressured
        );
    }

    #[test]
    fn rate_limiting_is_backpressure_too() {
        let mut s = nominal();
        s.collector_events_dropped_total = 2;
        s.collector_events_dropped_by_reason
            .insert("rate_limit_applied".into(), 2);
        assert_eq!(
            HealthState::evaluate(&s, false, NOW),
            HealthState::Backpressured
        );
    }

    #[test]
    fn a_stale_acknowledgement_reads_as_offline() {
        let mut s = nominal();
        s.last_ack_unix_ms = Some(NOW - ACK_STALE_MS - 1);
        assert_eq!(HealthState::evaluate(&s, false, NOW), HealthState::Offline);
    }

    #[test]
    fn a_recent_acknowledgement_is_not_offline() {
        let mut s = nominal();
        s.last_ack_unix_ms = Some(NOW - ACK_STALE_MS + 1);
        assert_eq!(HealthState::evaluate(&s, false, NOW), HealthState::Healthy);
    }

    #[test]
    fn queued_events_with_no_ack_yet_read_as_offline() {
        let mut s = nominal();
        s.last_ack_unix_ms = None;
        s.spool_events = 42;
        assert_eq!(HealthState::evaluate(&s, false, NOW), HealthState::Offline);
    }

    #[test]
    fn a_freshly_started_idle_agent_is_not_offline() {
        // No acknowledgement yet, but nothing is waiting either.
        let mut s = nominal();
        s.last_ack_unix_ms = None;
        s.spool_events = 0;
        assert_eq!(HealthState::evaluate(&s, false, NOW), HealthState::Healthy);
    }

    #[test]
    fn offline_mode_never_reports_offline() {
        let mut s = nominal();
        s.last_ack_unix_ms = None;
        s.backend_connected = false;
        s.spool_events = 500;
        assert_eq!(
            HealthState::evaluate(&s, true, NOW),
            HealthState::Healthy,
            "with no backend configured, not acknowledging is the design"
        );
    }

    #[test]
    fn kernel_losses_degrade_but_do_not_alarm() {
        let mut s = nominal();
        s.ebpf_events_lost_total = 12;
        s.collector_events_dropped_total = 12;
        s.collector_events_dropped_by_reason
            .insert("kernel_ringbuffer_full".into(), 12);
        assert_eq!(HealthState::evaluate(&s, false, NOW), HealthState::Degraded);
    }

    #[test]
    fn routine_enrichment_races_do_not_degrade_health() {
        // Short-lived processes exiting before /proc can be read is normal on a
        // busy host. If that degraded health, the signal would be permanently
        // stuck and therefore useless.
        let mut s = nominal();
        s.enrichment_attempts_total = 10_000;
        s.enrichment_failures_total = 300;
        assert_eq!(
            HealthState::evaluate(&s, false, NOW),
            HealthState::Healthy,
            "a 3% enrichment race rate is normal operation"
        );
    }

    #[test]
    fn a_majority_of_enrichment_failures_degrades() {
        // This is hidepid or missing capabilities, not a process race.
        let mut s = nominal();
        s.enrichment_attempts_total = 1_000;
        s.enrichment_failures_total = 900;
        assert_eq!(HealthState::evaluate(&s, false, NOW), HealthState::Degraded);
    }

    #[test]
    fn enrichment_failures_never_look_like_event_loss() {
        let mut s = nominal();
        s.enrichment_attempts_total = 100;
        s.enrichment_failures_total = 100;
        assert_eq!(
            HealthState::evaluate(&s, false, NOW),
            HealthState::Degraded,
            "the events still shipped — this is degraded, never queue_full or worse"
        );
        assert!(!HealthState::Degraded.needs_attention());
    }

    #[test]
    fn enrichment_ratio_without_attempts_is_not_a_fault() {
        // Guards the division: failures recorded before any attempt was.
        let mut s = nominal();
        s.enrichment_attempts_total = 0;
        s.enrichment_failures_total = 5;
        assert_eq!(HealthState::evaluate(&s, false, NOW), HealthState::Healthy);
    }

    #[test]
    fn severity_ordering_is_most_severe_first() {
        assert!(HealthState::RecoveryRequired < HealthState::CollectorFailed);
        assert!(HealthState::CollectorFailed < HealthState::QueueFull);
        assert!(HealthState::QueueFull < HealthState::Backpressured);
        assert!(HealthState::Degraded < HealthState::Healthy);
    }

    #[test]
    fn only_actionable_states_need_attention() {
        assert!(HealthState::RecoveryRequired.needs_attention());
        assert!(HealthState::CollectorFailed.needs_attention());
        assert!(HealthState::QueueFull.needs_attention());
        assert!(!HealthState::Degraded.needs_attention());
        assert!(!HealthState::Healthy.needs_attention());
        assert!(!HealthState::Offline.needs_attention());
    }

    #[test]
    fn every_state_has_a_stable_label_and_round_trips() {
        for (state, label) in [
            (HealthState::Healthy, "healthy"),
            (HealthState::Degraded, "degraded"),
            (HealthState::Backpressured, "backpressured"),
            (HealthState::Offline, "offline"),
            (HealthState::QueueNearCapacity, "queue_near_capacity"),
            (HealthState::QueueFull, "queue_full"),
            (HealthState::CollectorFailed, "collector_failed"),
            (HealthState::RecoveryRequired, "recovery_required"),
        ] {
            assert_eq!(state.as_str(), label);
            assert_eq!(serde_json::to_value(state).unwrap(), label);
            let back: HealthState =
                serde_json::from_value(serde_json::Value::String(label.into())).unwrap();
            assert_eq!(back, state);
        }
    }
}
