use serde::{Deserialize, Serialize};
/// Provenance stamped on every event.
///
/// Carried alongside `event_id` so a receiver can reconstruct the agent's
/// ordered event stream, detect gaps, and reason about timing without trusting
/// the wall clock.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventOrigin {
    /// System boot this event belongs to; scopes `sequence` and every
    /// process identity.
    pub boot_id: String,
    /// Position in this run's totally-ordered event stream, starting at 1.
    pub sequence_number: u64,
    /// Monotonic clock reading at event creation, in nanoseconds.
    pub monotonic_timestamp_ns: u64,
    /// Collector that produced the event (`ebpf_exec`, `proc_poll`, …).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

impl EventOrigin {
    /// Stamp a new origin, consuming the next sequence number.
    pub fn new(source: impl Into<String>) -> Self {
        Self {
            source: Some(source.into()),
            ..Self::unsourced()
        }
    }

    /// Stamp an origin without naming a source; the collector fills it in via
    /// [`crate::AgentEvent::with_source`].
    pub fn unsourced() -> Self {
        Self {
            boot_id: crate::runtime::runtime().boot_id(),
            sequence_number: crate::runtime::next_sequence(),
            monotonic_timestamp_ns: crate::runtime::runtime().monotonic_ns(),
            source: None,
        }
    }
}
