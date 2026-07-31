//! Drop reasons — the vocabulary that makes every discarded event *explicable*.
//!
//! The pipeline's contract is not "never lose an event" but "never lose an
//! event **silently**".  Every place that can discard telemetry must name one
//! of these reasons, which is both counted (`trapd_collector_events_dropped_total`
//! broken down per reason) and logged.  A drop that cannot be attributed to a
//! variant here is a bug, not a category — [`DropReason::InternalError`] exists
//! so such a case is still counted rather than vanishing.

use std::fmt;

/// Why a single event did not make it to the next pipeline stage.
///
/// The discriminants are stable: they are used as metric label values and are
/// parsed back out of the diagnostics snapshot, so renaming one is a breaking
/// change for dashboards.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DropReason {
    /// The kernel could not reserve a ring-buffer slot; the event never reached
    /// userspace.  Sourced from the eBPF `DROPPED` per-CPU counters.
    KernelRingbufferFull,
    /// The bounded userspace mpsc channel between a collector and the pipeline
    /// consumer was full.  Dropping here is deliberate: blocking a ring-buffer
    /// consumer would push the loss into the kernel instead, where it is far
    /// less observable.
    UserspaceChannelFull,
    /// The serialized event exceeded [`crate::telemetry::limits::MAX_EVENT_BYTES`].
    /// Field-level truncation is preferred; this fires only when the whole
    /// envelope is still oversized afterwards.
    EventTooLarge,
    /// `/proc` enrichment exceeded its deadline.  Note this drops the *enrichment*,
    /// not the event — an event is only dropped for this reason when the raw
    /// kernel record itself could not be recovered.
    EnrichmentTimeout,
    /// `serde_json` refused to serialize the event.
    SerializationFailed,
    /// The persistent queue was at its event or byte capacity and the incoming
    /// event could not displace anything.
    PersistentQueueFull,
    /// A journal record failed checksum validation on replay and was discarded.
    PersistentQueueCorrupt,
    /// The backend answered with a permanent (4xx) status for this batch.
    BackendRejected,
    /// A journal record carried a schema/format version this build cannot read.
    UnsupportedEventVersion,
    /// A local rate limiter shed the event to protect downstream stages.
    RateLimitApplied,
    /// Catch-all so an unattributed failure is still counted.  Any sustained
    /// non-zero value here warrants a bug report.
    InternalError,
}

impl DropReason {
    /// Every variant, in discriminant order.  Used to render per-reason
    /// breakdowns and to size the metric array.
    pub const ALL: [DropReason; 11] = [
        DropReason::KernelRingbufferFull,
        DropReason::UserspaceChannelFull,
        DropReason::EventTooLarge,
        DropReason::EnrichmentTimeout,
        DropReason::SerializationFailed,
        DropReason::PersistentQueueFull,
        DropReason::PersistentQueueCorrupt,
        DropReason::BackendRejected,
        DropReason::UnsupportedEventVersion,
        DropReason::RateLimitApplied,
        DropReason::InternalError,
    ];

    /// Number of variants — the width of the per-reason counter array.
    pub const COUNT: usize = Self::ALL.len();

    /// Stable metric-label spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            DropReason::KernelRingbufferFull => "kernel_ringbuffer_full",
            DropReason::UserspaceChannelFull => "userspace_channel_full",
            DropReason::EventTooLarge => "event_too_large",
            DropReason::EnrichmentTimeout => "enrichment_timeout",
            DropReason::SerializationFailed => "serialization_failed",
            DropReason::PersistentQueueFull => "persistent_queue_full",
            DropReason::PersistentQueueCorrupt => "persistent_queue_corrupt",
            DropReason::BackendRejected => "backend_rejected",
            DropReason::UnsupportedEventVersion => "unsupported_event_version",
            DropReason::RateLimitApplied => "rate_limit_applied",
            DropReason::InternalError => "internal_error",
        }
    }

    /// Index into the per-reason counter array.
    pub const fn index(self) -> usize {
        self as usize
    }

    /// Parse a metric-label spelling back into a variant (diagnostics reader).
    pub fn from_str(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|r| r.as_str() == s)
    }
}

impl fmt::Display for DropReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn index_matches_position_in_all() {
        for (i, reason) in DropReason::ALL.iter().enumerate() {
            assert_eq!(reason.index(), i, "{reason} index must match ALL order");
        }
    }

    #[test]
    fn labels_are_unique_and_round_trip() {
        let mut seen = std::collections::BTreeSet::new();
        for reason in DropReason::ALL {
            assert!(seen.insert(reason.as_str()), "duplicate label {reason}");
            assert_eq!(DropReason::from_str(reason.as_str()), Some(reason));
        }
        assert_eq!(seen.len(), DropReason::COUNT);
    }

    #[test]
    fn every_mandated_reason_exists() {
        // The reasons the telemetry contract requires by name.  A rename that
        // breaks a dashboard fails here first.
        for required in [
            "kernel_ringbuffer_full",
            "userspace_channel_full",
            "event_too_large",
            "enrichment_timeout",
            "serialization_failed",
            "persistent_queue_full",
            "persistent_queue_corrupt",
            "backend_rejected",
            "unsupported_event_version",
            "rate_limit_applied",
            "internal_error",
        ] {
            assert!(
                DropReason::from_str(required).is_some(),
                "mandated drop reason {required} is missing"
            );
        }
    }

    #[test]
    fn unknown_label_does_not_parse() {
        assert_eq!(DropReason::from_str("nope"), None);
        assert_eq!(DropReason::from_str(""), None);
    }
}
