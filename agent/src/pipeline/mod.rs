//! The event pipeline: the in-process channel, the durable queue behind backend
//! delivery, and the accounting that makes every loss explicable.
//!
//! Collectors push [`AgentEvent`]s into a bounded mpsc channel. A single
//! consumer drains it, writes each event locally, runs the detection engine, and
//! appends to the [`Spool`] that the transport ships from.
//!
//! The channel is bounded on purpose. An unbounded channel converts a downstream
//! stall into unbounded memory growth and eventually an OOM kill, which loses
//! *everything* including the journal's in-flight state. A bounded channel turns
//! the same stall into a small, counted, attributable loss — see [`try_emit`].

use tokio::sync::mpsc;
use tracing::warn;

use crate::schema::AgentEvent;
use crate::telemetry::{metrics::metrics, DropReason};

pub mod backoff;
pub mod journal;
pub mod spool;

// The env-override helpers are called from the Linux `main` only; the Windows
// runtime builds its spool through `winsvc::run`.
#[allow(unused_imports)]
pub use spool::{
    spool_max_bytes_from_env, spool_max_from_env, Spool, SpoolEntry, SPOOL_MAX_MEMORY,
};

/// Depth of the collector→consumer channel.
///
/// Sized to absorb a burst (a build, a container start-up storm) without
/// dropping, while still bounding worst-case memory to a few MiB.
pub const CHANNEL_CAPACITY: usize = 1_000;

pub fn create_pipeline() -> (mpsc::Sender<AgentEvent>, mpsc::Receiver<AgentEvent>) {
    mpsc::channel(CHANNEL_CAPACITY)
}

/// Send an event, dropping it *with attribution* if the channel is full.
///
/// Used from ring-buffer consumers, where awaiting a full channel is the wrong
/// choice: blocking stops draining the kernel ring buffer, so the loss simply
/// moves into the kernel where the agent can only count it in aggregate. Dropping
/// here keeps the loss in userspace where it is attributable to a source.
///
/// Returns `true` when the event was accepted.
///
/// Accepted events are counted by the consumer, not here — see [`accepted`].
pub fn try_emit(tx: &mpsc::Sender<AgentEvent>, event: AgentEvent, source: &str) -> bool {
    match tx.try_send(event) {
        Ok(()) => true,
        Err(mpsc::error::TrySendError::Full(ev)) => {
            metrics().event_dropped(DropReason::UserspaceChannelFull);
            warn_throttled(source, &ev);
            false
        }
        Err(mpsc::error::TrySendError::Closed(_)) => {
            // The consumer is gone — shutdown, or a panicked task.
            metrics().event_dropped(DropReason::InternalError);
            false
        }
    }
}

/// Forward an event to a secondary consumer (prevention, detection tee).
///
/// Same accounting as [`try_emit`] but without counting the event as newly
/// received — it was already counted when it entered the pipeline, and counting
/// it twice would make the received total meaningless.
pub fn try_tee(tx: &mpsc::Sender<AgentEvent>, event: AgentEvent, source: &str) -> bool {
    match tx.try_send(event) {
        Ok(()) => true,
        Err(mpsc::error::TrySendError::Full(ev)) => {
            metrics().event_dropped(DropReason::UserspaceChannelFull);
            warn_throttled(source, &ev);
            false
        }
        Err(mpsc::error::TrySendError::Closed(_)) => {
            metrics().event_dropped(DropReason::InternalError);
            false
        }
    }
}

/// Record that an event was drained from the channel and is now the pipeline's
/// responsibility.
///
/// Counted here — at the single point every event must pass through — rather
/// than in each collector. A collector that forgets to call a producer-side
/// counter would silently understate the received total and make the drop
/// accounting unverifiable; there is no equivalent way to bypass the consumer.
pub fn accepted() {
    metrics().collector_event_received();
}

/// Log the first overflow and then roughly every 1000th, so a sustained stall
/// does not turn the log into the next bottleneck.
fn warn_throttled(source: &str, event: &AgentEvent) {
    let dropped = metrics().drops_for(DropReason::UserspaceChannelFull);
    if dropped == 1 || dropped.is_multiple_of(1_000) {
        warn!(
            source,
            dropped_total = dropped,
            event_id = %event.event_id,
            "pipeline channel full — event dropped (userspace_channel_full)"
        );
    }
}

#[cfg(test)]
mod tests;
