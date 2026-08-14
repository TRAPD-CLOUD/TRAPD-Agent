//! The process-telemetry metric registry.
//!
//! One global, lock-free registry of counters and gauges covering the whole
//! path `eBPF → collector → enrichment → detection → spool → transport → ack`.
//! Every stage that can lose, retry or acknowledge an event bumps a counter
//! here, which is what turns "an event vanished" into "an event was dropped at
//! stage X for reason Y".
//!
//! Names mirror the Prometheus metrics in the telemetry contract
//! (`trapd_*_total` for counters, bare names for gauges); [`Metrics::snapshot`]
//! renders them into the serializable [`MetricsSnapshot`] that backs both the
//! on-disk diagnostics file and `trapd-agent diagnostics telemetry`.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};

use super::drops::DropReason;
use super::histogram::{LatencyHistogram, LatencySnapshot};

/// Which telemetry source the process pipeline is actually running on.
///
/// Recorded as a number so it can live in an atomic; rendered as a string in
/// the snapshot.  `Ebpf` is the intended production mode — a fleet reporting
/// `ProcPolling` has a blind spot for short-lived processes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CollectorMode {
    /// Neither source has reported in yet.
    Unknown,
    /// eBPF tracepoints attached — full short-lived-process coverage.
    Ebpf,
    /// `/proc` polling only; the eBPF object was missing or failed to load.
    ProcPolling,
    /// Both are running (eBPF for exec, polling for create/terminate).
    Hybrid,
    /// Every process collector failed to start.
    Failed,
}

impl CollectorMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            CollectorMode::Unknown => "unknown",
            CollectorMode::Ebpf => "ebpf",
            CollectorMode::ProcPolling => "proc_polling",
            CollectorMode::Hybrid => "hybrid",
            CollectorMode::Failed => "failed",
        }
    }

    const fn from_u64(v: u64) -> Self {
        match v {
            1 => CollectorMode::Ebpf,
            2 => CollectorMode::ProcPolling,
            3 => CollectorMode::Hybrid,
            4 => CollectorMode::Failed,
            _ => CollectorMode::Unknown,
        }
    }

    const fn to_u64(self) -> u64 {
        match self {
            CollectorMode::Unknown => 0,
            CollectorMode::Ebpf => 1,
            CollectorMode::ProcPolling => 2,
            CollectorMode::Hybrid => 3,
            CollectorMode::Failed => 4,
        }
    }
}

/// Global registry.  All fields are atomics so this is a plain `static` with no
/// initialisation race and no lock on the hot path.
pub struct Metrics {
    // ── Kernel / eBPF ────────────────────────────────────────────────────────
    ebpf_events_received: AtomicU64,
    ebpf_events_lost: AtomicU64,

    // ── Userspace collectors ─────────────────────────────────────────────────
    collector_events_received: AtomicU64,
    collector_first_event_unix_ms: AtomicU64,
    collector_events_dropped: AtomicU64,
    drops_by_reason: [AtomicU64; DropReason::COUNT],
    collector_failures: AtomicU64,
    collector_mode: AtomicU64,

    // ── Enrichment ───────────────────────────────────────────────────────────
    enrichment_attempts: AtomicU64,
    enrichment_failures: AtomicU64,
    enrichment_partial: AtomicU64,
    enrichment_truncations: AtomicU64,
    enrichment_duration: LatencyHistogram,

    // ── Detection ────────────────────────────────────────────────────────────
    detection_queue_depth: AtomicU64,

    // ── Persistent queue ─────────────────────────────────────────────────────
    spool_events: AtomicU64,
    spool_bytes: AtomicU64,
    spool_capacity_bytes: AtomicU64,
    spool_capacity_events: AtomicU64,
    spool_corrupt_records: AtomicU64,
    spool_truncated_tail_records: AtomicU64,
    spool_recovered_records: AtomicU64,
    spool_oldest_age_ms: AtomicU64,

    // ── Transport ────────────────────────────────────────────────────────────
    transport_batches_sent: AtomicU64,
    transport_batches_failed: AtomicU64,
    transport_events_acknowledged: AtomicU64,
    transport_first_ack_unix_ms: AtomicU64,
    transport_events_retried: AtomicU64,
    backend_rejected_events: AtomicU64,
    last_ack_unix_ms: AtomicU64,
    backend_connected: AtomicU64,
    transport_last_batch_size: AtomicU64,
    transport_request_latency_ms: AtomicU64,
    transport_catching_up: AtomicU64,

    // ── End to end ───────────────────────────────────────────────────────────
    end_to_end_latency: LatencyHistogram,
}

impl Metrics {
    #[allow(clippy::declare_interior_mutable_const)]
    const ZERO: AtomicU64 = AtomicU64::new(0);

    pub const fn new() -> Self {
        Self {
            ebpf_events_received: AtomicU64::new(0),
            ebpf_events_lost: AtomicU64::new(0),
            collector_events_received: AtomicU64::new(0),
            collector_first_event_unix_ms: AtomicU64::new(0),
            collector_events_dropped: AtomicU64::new(0),
            drops_by_reason: [Self::ZERO; DropReason::COUNT],
            collector_failures: AtomicU64::new(0),
            collector_mode: AtomicU64::new(0),
            enrichment_attempts: AtomicU64::new(0),
            enrichment_failures: AtomicU64::new(0),
            enrichment_partial: AtomicU64::new(0),
            enrichment_truncations: AtomicU64::new(0),
            enrichment_duration: LatencyHistogram::new(),
            detection_queue_depth: AtomicU64::new(0),
            spool_events: AtomicU64::new(0),
            spool_bytes: AtomicU64::new(0),
            spool_capacity_bytes: AtomicU64::new(0),
            spool_capacity_events: AtomicU64::new(0),
            spool_corrupt_records: AtomicU64::new(0),
            spool_truncated_tail_records: AtomicU64::new(0),
            spool_recovered_records: AtomicU64::new(0),
            spool_oldest_age_ms: AtomicU64::new(0),
            transport_batches_sent: AtomicU64::new(0),
            transport_batches_failed: AtomicU64::new(0),
            transport_events_acknowledged: AtomicU64::new(0),
            transport_first_ack_unix_ms: AtomicU64::new(0),
            transport_events_retried: AtomicU64::new(0),
            backend_rejected_events: AtomicU64::new(0),
            last_ack_unix_ms: AtomicU64::new(0),
            backend_connected: AtomicU64::new(0),
            transport_last_batch_size: AtomicU64::new(0),
            transport_request_latency_ms: AtomicU64::new(0),
            transport_catching_up: AtomicU64::new(0),
            end_to_end_latency: LatencyHistogram::new(),
        }
    }

    // ── Kernel / eBPF ────────────────────────────────────────────────────────

    /// One event successfully read out of a kernel ring buffer.
    pub fn ebpf_event_received(&self) {
        self.ebpf_events_received.fetch_add(1, Ordering::Relaxed);
    }

    /// Absolute kernel-drop total, as read from the eBPF `DROPPED` map.
    ///
    /// The map counters are monotonic since agent start, so this is a `set`
    /// rather than an `add`; the delta is also folded into the per-reason drop
    /// breakdown under [`DropReason::KernelRingbufferFull`].
    pub fn set_ebpf_events_lost(&self, total: u64) {
        let prev = self.ebpf_events_lost.swap(total, Ordering::Relaxed);
        if let Some(delta) = total.checked_sub(prev) {
            if delta > 0 {
                self.drops_by_reason[DropReason::KernelRingbufferFull.index()]
                    .fetch_add(delta, Ordering::Relaxed);
            }
        }
    }

    // ── Collectors ───────────────────────────────────────────────────────────

    /// An event was produced by a collector and handed to the pipeline.
    pub fn collector_event_received(&self) {
        let _ = self.collector_first_event_unix_ms.compare_exchange(
            0,
            now_unix_ms(),
            Ordering::Relaxed,
            Ordering::Relaxed,
        );
        self.collector_events_received
            .fetch_add(1, Ordering::Relaxed);
    }

    /// An event was discarded.  This is the single choke point for *every*
    /// deliberate loss, which is what lets the diagnostics command assert that
    /// the per-reason breakdown sums to the total.
    pub fn event_dropped(&self, reason: DropReason) {
        self.collector_events_dropped
            .fetch_add(1, Ordering::Relaxed);
        self.drops_by_reason[reason.index()].fetch_add(1, Ordering::Relaxed);
    }

    /// Bulk variant for stages that discover several losses at once.
    pub fn events_dropped(&self, reason: DropReason, n: u64) {
        if n == 0 {
            return;
        }
        self.collector_events_dropped
            .fetch_add(n, Ordering::Relaxed);
        self.drops_by_reason[reason.index()].fetch_add(n, Ordering::Relaxed);
    }

    pub fn drops_for(&self, reason: DropReason) -> u64 {
        self.drops_by_reason[reason.index()].load(Ordering::Relaxed)
    }

    /// A collector task exited with an error.
    pub fn collector_failed(&self) {
        self.collector_failures.fetch_add(1, Ordering::Relaxed);
    }

    pub fn set_collector_mode(&self, mode: CollectorMode) {
        self.collector_mode.store(mode.to_u64(), Ordering::Relaxed);
    }

    pub fn collector_mode(&self) -> CollectorMode {
        CollectorMode::from_u64(self.collector_mode.load(Ordering::Relaxed))
    }

    /// Promote the recorded mode when a second source comes online, so the
    /// order collectors start in does not change the reported mode.
    pub fn add_collector_mode(&self, mode: CollectorMode) {
        let combined = match (self.collector_mode(), mode) {
            (CollectorMode::Unknown, m) => m,
            (m, CollectorMode::Unknown) => m,
            (a, b) if a == b => a,
            (CollectorMode::Failed, m) | (m, CollectorMode::Failed) => m,
            _ => CollectorMode::Hybrid,
        };
        self.set_collector_mode(combined);
    }

    // ── Enrichment ───────────────────────────────────────────────────────────

    pub fn enrichment_attempt(&self, duration_ms: u64) {
        self.enrichment_attempts.fetch_add(1, Ordering::Relaxed);
        self.enrichment_duration.observe_ms(duration_ms);
    }

    /// One enrichment field could not be resolved.  Deliberately *not* a drop:
    /// the raw kernel record still ships.
    pub fn enrichment_failure(&self) {
        self.enrichment_failures.fetch_add(1, Ordering::Relaxed);
    }

    pub fn enrichment_partial(&self) {
        self.enrichment_partial.fetch_add(1, Ordering::Relaxed);
    }

    pub fn enrichment_truncation(&self) {
        self.enrichment_truncations.fetch_add(1, Ordering::Relaxed);
    }

    // ── Detection ────────────────────────────────────────────────────────────

    pub fn set_detection_queue_depth(&self, depth: u64) {
        self.detection_queue_depth.store(depth, Ordering::Relaxed);
    }

    // ── Spool ────────────────────────────────────────────────────────────────

    /// Publish the queue's live gauges.  Called after every mutation so the
    /// diagnostics snapshot never shows a stale depth.
    pub fn set_spool_state(&self, events: u64, bytes: u64) {
        self.spool_events.store(events, Ordering::Relaxed);
        self.spool_bytes.store(bytes, Ordering::Relaxed);
    }

    pub fn set_spool_oldest_age_ms(&self, age: u64) {
        self.spool_oldest_age_ms.store(age, Ordering::Relaxed);
    }

    pub fn set_spool_capacity(&self, events: u64, bytes: u64) {
        self.spool_capacity_events.store(events, Ordering::Relaxed);
        self.spool_capacity_bytes.store(bytes, Ordering::Relaxed);
    }

    pub fn spool_corrupt_record(&self, n: u64) {
        self.spool_corrupt_records.fetch_add(n, Ordering::Relaxed);
    }

    pub fn spool_truncated_tail_record(&self, n: u64) {
        self.spool_truncated_tail_records
            .fetch_add(n, Ordering::Relaxed);
    }

    pub fn spool_recovered_records(&self, n: u64) {
        self.spool_recovered_records.fetch_add(n, Ordering::Relaxed);
    }

    pub fn spool_events(&self) -> u64 {
        self.spool_events.load(Ordering::Relaxed)
    }

    pub fn spool_bytes(&self) -> u64 {
        self.spool_bytes.load(Ordering::Relaxed)
    }

    pub fn spool_capacity_bytes(&self) -> u64 {
        self.spool_capacity_bytes.load(Ordering::Relaxed)
    }

    // ── Transport ────────────────────────────────────────────────────────────

    pub fn transport_batch_sent(&self) {
        self.transport_batches_sent.fetch_add(1, Ordering::Relaxed);
    }

    pub fn set_transport_activity(&self, batch_size: u64, latency_ms: u64, catching_up: bool) {
        self.transport_last_batch_size
            .store(batch_size, Ordering::Relaxed);
        self.transport_request_latency_ms
            .store(latency_ms, Ordering::Relaxed);
        self.transport_catching_up
            .store(u64::from(catching_up), Ordering::Relaxed);
    }

    pub fn set_transport_catching_up(&self, catching_up: bool) {
        self.transport_catching_up
            .store(u64::from(catching_up), Ordering::Relaxed);
    }

    pub fn transport_batch_failed(&self) {
        self.transport_batches_failed
            .fetch_add(1, Ordering::Relaxed);
    }

    /// `n` events were confirmed durable by the backend.  Also stamps the
    /// last-acknowledgement clock the health model uses to detect a stalled
    /// control channel.
    pub fn transport_events_acknowledged(&self, n: u64) {
        let _ = self.transport_first_ack_unix_ms.compare_exchange(
            0,
            now_unix_ms(),
            Ordering::Relaxed,
            Ordering::Relaxed,
        );
        self.transport_events_acknowledged
            .fetch_add(n, Ordering::Relaxed);
        self.last_ack_unix_ms
            .store(now_unix_ms(), Ordering::Relaxed);
    }

    pub fn transport_events_retried(&self, n: u64) {
        self.transport_events_retried
            .fetch_add(n, Ordering::Relaxed);
    }

    pub fn backend_rejected_events(&self, n: u64) {
        self.backend_rejected_events.fetch_add(n, Ordering::Relaxed);
        self.events_dropped(DropReason::BackendRejected, n);
    }

    pub fn set_backend_connected(&self, connected: bool) {
        self.backend_connected
            .store(u64::from(connected), Ordering::Relaxed);
    }

    pub fn backend_connected(&self) -> bool {
        self.backend_connected.load(Ordering::Relaxed) == 1
    }

    pub fn last_ack_unix_ms(&self) -> Option<u64> {
        let v = self.last_ack_unix_ms.load(Ordering::Relaxed);
        (v > 0).then_some(v)
    }

    // ── End to end ───────────────────────────────────────────────────────────

    /// Latency from event creation to backend acknowledgement.
    pub fn observe_end_to_end_ms(&self, ms: u64) {
        self.end_to_end_latency.observe_ms(ms);
    }

    // ── Snapshot ─────────────────────────────────────────────────────────────

    pub fn snapshot(&self) -> MetricsSnapshot {
        let now = now_unix_ms();
        let generated = self.collector_events_received.load(Ordering::Relaxed);
        let acknowledged = self.transport_events_acknowledged.load(Ordering::Relaxed);
        let mut drops = BTreeMap::new();
        for reason in DropReason::ALL {
            let v = self.drops_for(reason);
            if v > 0 {
                drops.insert(reason.as_str().to_string(), v);
            }
        }
        MetricsSnapshot {
            ebpf_events_received_total: self.ebpf_events_received.load(Ordering::Relaxed),
            ebpf_events_lost_total: self.ebpf_events_lost.load(Ordering::Relaxed),
            collector_events_received_total: generated,
            generated_events_per_second: rate_since(
                generated,
                self.collector_first_event_unix_ms.load(Ordering::Relaxed),
                now,
            ),
            collector_events_dropped_total: self.collector_events_dropped.load(Ordering::Relaxed),
            collector_events_dropped_by_reason: drops,
            collector_failures_total: self.collector_failures.load(Ordering::Relaxed),
            collector_mode: self.collector_mode().as_str().to_string(),
            enrichment_attempts_total: self.enrichment_attempts.load(Ordering::Relaxed),
            enrichment_failures_total: self.enrichment_failures.load(Ordering::Relaxed),
            enrichment_partial_total: self.enrichment_partial.load(Ordering::Relaxed),
            enrichment_truncations_total: self.enrichment_truncations.load(Ordering::Relaxed),
            enrichment_duration: self.enrichment_duration.snapshot(),
            detection_queue_depth: self.detection_queue_depth.load(Ordering::Relaxed),
            spool_events: self.spool_events.load(Ordering::Relaxed),
            spool_bytes: self.spool_bytes.load(Ordering::Relaxed),
            spool_capacity_events: self.spool_capacity_events.load(Ordering::Relaxed),
            spool_capacity_bytes: self.spool_capacity_bytes.load(Ordering::Relaxed),
            spool_corrupt_records_total: self.spool_corrupt_records.load(Ordering::Relaxed),
            spool_truncated_tail_records_total: self
                .spool_truncated_tail_records
                .load(Ordering::Relaxed),
            spool_recovered_records_total: self.spool_recovered_records.load(Ordering::Relaxed),
            spool_oldest_event_age_ms: self.spool_oldest_age_ms.load(Ordering::Relaxed),
            transport_batches_sent_total: self.transport_batches_sent.load(Ordering::Relaxed),
            transport_batches_failed_total: self.transport_batches_failed.load(Ordering::Relaxed),
            transport_events_acknowledged_total: self
                .transport_events_acknowledged
                .load(Ordering::Relaxed),
            sent_events_per_second: rate_since(
                acknowledged,
                self.transport_first_ack_unix_ms.load(Ordering::Relaxed),
                now,
            ),
            transport_events_retried_total: self.transport_events_retried.load(Ordering::Relaxed),
            backend_rejected_events_total: self.backend_rejected_events.load(Ordering::Relaxed),
            backend_connected: self.backend_connected(),
            transport_last_batch_size: self.transport_last_batch_size.load(Ordering::Relaxed),
            transport_request_latency_ms: self.transport_request_latency_ms.load(Ordering::Relaxed),
            transport_catching_up: self.transport_catching_up.load(Ordering::Relaxed) == 1,
            last_ack_unix_ms: self.last_ack_unix_ms(),
            end_to_end_latency: self.end_to_end_latency.snapshot(),
        }
    }

    /// Reset every counter.  Test-only: the production registry is a `static`
    /// that lives for the process lifetime.
    #[cfg(test)]
    pub fn reset(&self) {
        self.ebpf_events_received.store(0, Ordering::Relaxed);
        self.ebpf_events_lost.store(0, Ordering::Relaxed);
        self.collector_events_received.store(0, Ordering::Relaxed);
        self.collector_first_event_unix_ms
            .store(0, Ordering::Relaxed);
        self.collector_events_dropped.store(0, Ordering::Relaxed);
        for c in &self.drops_by_reason {
            c.store(0, Ordering::Relaxed);
        }
        self.collector_failures.store(0, Ordering::Relaxed);
        self.collector_mode.store(0, Ordering::Relaxed);
        self.enrichment_attempts.store(0, Ordering::Relaxed);
        self.enrichment_failures.store(0, Ordering::Relaxed);
        self.enrichment_partial.store(0, Ordering::Relaxed);
        self.enrichment_truncations.store(0, Ordering::Relaxed);
        self.detection_queue_depth.store(0, Ordering::Relaxed);
        self.spool_events.store(0, Ordering::Relaxed);
        self.spool_bytes.store(0, Ordering::Relaxed);
        self.spool_capacity_events.store(0, Ordering::Relaxed);
        self.spool_capacity_bytes.store(0, Ordering::Relaxed);
        self.spool_corrupt_records.store(0, Ordering::Relaxed);
        self.spool_truncated_tail_records
            .store(0, Ordering::Relaxed);
        self.spool_recovered_records.store(0, Ordering::Relaxed);
        self.spool_oldest_age_ms.store(0, Ordering::Relaxed);
        self.transport_batches_sent.store(0, Ordering::Relaxed);
        self.transport_batches_failed.store(0, Ordering::Relaxed);
        self.transport_events_acknowledged
            .store(0, Ordering::Relaxed);
        self.transport_first_ack_unix_ms.store(0, Ordering::Relaxed);
        self.transport_events_retried.store(0, Ordering::Relaxed);
        self.backend_rejected_events.store(0, Ordering::Relaxed);
        self.last_ack_unix_ms.store(0, Ordering::Relaxed);
        self.backend_connected.store(0, Ordering::Relaxed);
        self.transport_last_batch_size.store(0, Ordering::Relaxed);
        self.transport_request_latency_ms
            .store(0, Ordering::Relaxed);
        self.transport_catching_up.store(0, Ordering::Relaxed);
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Wall-clock milliseconds since the Unix epoch, saturating at 0 if the system
/// clock is before 1970 (which a deliberately-skewed clock can produce).
pub fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Serializable view of the whole registry — the payload of the on-disk
/// diagnostics snapshot.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MetricsSnapshot {
    pub ebpf_events_received_total: u64,
    pub ebpf_events_lost_total: u64,
    pub collector_events_received_total: u64,
    #[serde(default)]
    pub generated_events_per_second: f64,
    pub collector_events_dropped_total: u64,
    #[serde(default)]
    pub collector_events_dropped_by_reason: BTreeMap<String, u64>,
    pub collector_failures_total: u64,
    pub collector_mode: String,
    pub enrichment_attempts_total: u64,
    pub enrichment_failures_total: u64,
    pub enrichment_partial_total: u64,
    pub enrichment_truncations_total: u64,
    #[serde(default)]
    pub enrichment_duration: LatencySnapshot,
    pub detection_queue_depth: u64,
    pub spool_events: u64,
    pub spool_bytes: u64,
    pub spool_capacity_events: u64,
    pub spool_capacity_bytes: u64,
    pub spool_corrupt_records_total: u64,
    pub spool_truncated_tail_records_total: u64,
    pub spool_recovered_records_total: u64,
    #[serde(default)]
    pub spool_oldest_event_age_ms: u64,
    pub transport_batches_sent_total: u64,
    pub transport_batches_failed_total: u64,
    pub transport_events_acknowledged_total: u64,
    #[serde(default)]
    pub sent_events_per_second: f64,
    pub transport_events_retried_total: u64,
    pub backend_rejected_events_total: u64,
    pub backend_connected: bool,
    #[serde(default)]
    pub transport_last_batch_size: u64,
    #[serde(default)]
    pub transport_request_latency_ms: u64,
    #[serde(default)]
    pub transport_catching_up: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_ack_unix_ms: Option<u64>,
    #[serde(default)]
    pub end_to_end_latency: LatencySnapshot,
}

fn rate_since(total: u64, first_ms: u64, now_ms: u64) -> f64 {
    let elapsed_ms = now_ms.saturating_sub(first_ms);
    if first_ms == 0 || elapsed_ms == 0 {
        0.0
    } else {
        total as f64 * 1000.0 / elapsed_ms as f64
    }
}

impl MetricsSnapshot {
    /// Spool fill as a fraction of whichever limit (events or bytes) is closer.
    /// `0.0` when the queue has no configured capacity yet.
    pub fn spool_utilization(&self) -> f64 {
        let by_events = ratio(self.spool_events, self.spool_capacity_events);
        let by_bytes = ratio(self.spool_bytes, self.spool_capacity_bytes);
        by_events.max(by_bytes)
    }

    /// Every drop this agent has recorded, whatever the reason.  The invariant
    /// the pipeline maintains is that this equals
    /// `collector_events_dropped_total` — a mismatch means some stage lost an
    /// event without naming a reason.
    pub fn total_attributed_drops(&self) -> u64 {
        self.collector_events_dropped_by_reason.values().sum()
    }

    /// True when every recorded drop carries a reason.
    pub fn drops_fully_attributed(&self) -> bool {
        self.total_attributed_drops() == self.collector_events_dropped_total
    }
}

fn ratio(used: u64, capacity: u64) -> f64 {
    if capacity == 0 {
        0.0
    } else {
        used as f64 / capacity as f64
    }
}

/// The process-wide registry.
pub static METRICS: Metrics = Metrics::new();

/// Convenience accessor so call sites read `metrics().event_dropped(...)`.
#[inline]
pub fn metrics() -> &'static Metrics {
    &METRICS
}

#[cfg(test)]
mod tests {
    use super::*;

    // The registry is a process-wide static, so these tests use a local
    // instance rather than `METRICS` to stay independent of execution order.
    fn fresh() -> Metrics {
        Metrics::new()
    }

    #[test]
    fn drops_are_counted_both_in_total_and_per_reason() {
        let m = fresh();
        m.event_dropped(DropReason::UserspaceChannelFull);
        m.event_dropped(DropReason::UserspaceChannelFull);
        m.event_dropped(DropReason::EventTooLarge);

        let snap = m.snapshot();
        assert_eq!(snap.collector_events_dropped_total, 3);
        assert_eq!(
            snap.collector_events_dropped_by_reason["userspace_channel_full"],
            2
        );
        assert_eq!(
            snap.collector_events_dropped_by_reason["event_too_large"],
            1
        );
        assert!(
            snap.drops_fully_attributed(),
            "every drop must carry a reason"
        );
    }

    #[test]
    fn bulk_drop_of_zero_is_a_noop() {
        let m = fresh();
        m.events_dropped(DropReason::InternalError, 0);
        assert_eq!(m.snapshot().collector_events_dropped_total, 0);
        assert!(m.snapshot().collector_events_dropped_by_reason.is_empty());
    }

    #[test]
    fn kernel_drop_totals_are_set_not_accumulated() {
        let m = fresh();
        // The eBPF map counters are monotonic since agent start.
        m.set_ebpf_events_lost(10);
        m.set_ebpf_events_lost(25);
        let snap = m.snapshot();
        assert_eq!(snap.ebpf_events_lost_total, 25, "gauge, not a sum");
        assert_eq!(
            snap.collector_events_dropped_by_reason["kernel_ringbuffer_full"], 25,
            "the delta of each read must reach the per-reason breakdown"
        );
    }

    #[test]
    fn kernel_drop_counter_reset_does_not_underflow() {
        let m = fresh();
        m.set_ebpf_events_lost(100);
        // A reloaded eBPF program restarts its counters from zero.
        m.set_ebpf_events_lost(5);
        let snap = m.snapshot();
        assert_eq!(snap.ebpf_events_lost_total, 5);
        // The pre-reset total stays attributed; no negative delta is applied.
        assert_eq!(
            snap.collector_events_dropped_by_reason["kernel_ringbuffer_full"],
            100
        );
    }

    #[test]
    fn backend_rejection_counts_as_an_attributed_drop() {
        let m = fresh();
        m.backend_rejected_events(7);
        let snap = m.snapshot();
        assert_eq!(snap.backend_rejected_events_total, 7);
        assert_eq!(snap.collector_events_dropped_total, 7);
        assert!(snap.drops_fully_attributed());
    }

    #[test]
    fn acknowledgement_stamps_the_clock() {
        let m = fresh();
        assert_eq!(m.last_ack_unix_ms(), None);
        m.transport_events_acknowledged(5);
        assert!(m.last_ack_unix_ms().is_some());
        assert_eq!(m.snapshot().transport_events_acknowledged_total, 5);
    }

    #[test]
    fn spool_utilization_tracks_the_tighter_limit() {
        let m = fresh();
        m.set_spool_capacity(1_000, 1_000_000);
        // 50 % by events, 10 % by bytes → the event limit governs.
        m.set_spool_state(500, 100_000);
        let snap = m.snapshot();
        assert!((snap.spool_utilization() - 0.5).abs() < 1e-9);

        // Now bytes are the tighter constraint.
        m.set_spool_state(100, 900_000);
        let snap = m.snapshot();
        assert!((snap.spool_utilization() - 0.9).abs() < 1e-9);
    }

    #[test]
    fn spool_utilization_is_zero_without_capacity() {
        let m = fresh();
        m.set_spool_state(10, 10);
        assert_eq!(m.snapshot().spool_utilization(), 0.0);
    }

    #[test]
    fn collector_mode_promotes_to_hybrid() {
        let m = fresh();
        assert_eq!(m.collector_mode(), CollectorMode::Unknown);
        m.add_collector_mode(CollectorMode::Ebpf);
        assert_eq!(m.collector_mode(), CollectorMode::Ebpf);
        m.add_collector_mode(CollectorMode::ProcPolling);
        assert_eq!(m.collector_mode(), CollectorMode::Hybrid);
        // Idempotent.
        m.add_collector_mode(CollectorMode::ProcPolling);
        assert_eq!(m.collector_mode(), CollectorMode::Hybrid);
    }

    #[test]
    fn collector_mode_order_does_not_matter() {
        let a = fresh();
        a.add_collector_mode(CollectorMode::Ebpf);
        a.add_collector_mode(CollectorMode::ProcPolling);

        let b = fresh();
        b.add_collector_mode(CollectorMode::ProcPolling);
        b.add_collector_mode(CollectorMode::Ebpf);

        assert_eq!(a.collector_mode(), b.collector_mode());
    }

    #[test]
    fn collector_mode_round_trips_through_the_atomic() {
        for mode in [
            CollectorMode::Unknown,
            CollectorMode::Ebpf,
            CollectorMode::ProcPolling,
            CollectorMode::Hybrid,
            CollectorMode::Failed,
        ] {
            let m = fresh();
            m.set_collector_mode(mode);
            assert_eq!(m.collector_mode(), mode);
        }
    }

    #[test]
    fn enrichment_failures_are_not_drops() {
        let m = fresh();
        m.enrichment_attempt(3);
        m.enrichment_failure();
        m.enrichment_partial();
        let snap = m.snapshot();
        assert_eq!(snap.enrichment_failures_total, 1);
        assert_eq!(snap.enrichment_partial_total, 1);
        assert_eq!(
            snap.collector_events_dropped_total, 0,
            "a failed enrichment must never discard the raw event"
        );
        assert_eq!(snap.enrichment_duration.count, 1);
    }

    #[test]
    fn snapshot_round_trips_through_json() {
        let m = fresh();
        m.collector_event_received();
        m.event_dropped(DropReason::PersistentQueueFull);
        m.set_spool_capacity(100, 1024);
        m.set_spool_state(3, 300);
        m.observe_end_to_end_ms(42);

        let json = serde_json::to_string(&m.snapshot()).unwrap();
        let back: MetricsSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(back.collector_events_received_total, 1);
        assert_eq!(
            back.collector_events_dropped_by_reason["persistent_queue_full"],
            1
        );
        assert_eq!(back.spool_events, 3);
        assert!(back.end_to_end_latency.p99_ms.unwrap() >= 42);
    }

    #[test]
    fn reset_clears_every_counter() {
        let m = fresh();
        m.collector_event_received();
        m.event_dropped(DropReason::InternalError);
        m.transport_events_acknowledged(2);
        m.reset();
        let snap = m.snapshot();
        assert_eq!(snap.collector_events_received_total, 0);
        assert_eq!(snap.collector_events_dropped_total, 0);
        assert!(snap.collector_events_dropped_by_reason.is_empty());
        assert_eq!(snap.last_ack_unix_ms, None);
    }
}
