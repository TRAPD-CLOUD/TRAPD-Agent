//! Loss-transparent process telemetry.
//!
//! The pipeline `eBPF → collector → enrichment → detection → spool → transport
//! → ack` deliberately does **not** promise that no event is ever lost — under
//! a burst that promise could only be kept by blocking a kernel ring-buffer
//! consumer, which pushes the loss into the kernel where it is invisible.  The
//! promise it does make is stronger in practice: *nothing is lost silently*.
//! For every event the agent accepted, one of three things is true and
//! provable:
//!
//! 1. the backend acknowledged it,
//! 2. it is still in the persistent queue, or
//! 3. it was dropped with a named [`DropReason`] and a counter to prove it.
//!
//! This module holds the machinery that makes the third case impossible to
//! skip:
//!
//! - [`identity`] — `event_id`, `(boot_id, sequence_number)` for gap detection,
//!   a monotonic clock, and `(boot_id, pid, start_time)` process keys that
//!   survive PID reuse.
//! - [`drops`] — the closed vocabulary of drop reasons.
//! - [`metrics`] — the lock-free counter registry every stage reports into.
//! - [`histogram`] — latency percentiles at fixed memory cost.
//! - [`enrichment`] — partial-enrichment markers, so a missing `/proc` read
//!   degrades an event instead of discarding it.
//! - [`limits`] — size ceilings and explicit truncation markers.
//! - [`health`] — the derived health state.
//! - [`snapshot`] — the on-disk report behind `trapd-agent diagnostics telemetry`.

// This module is a self-contained instrumentation library that happens to live
// inside a binary crate, so `pub` does not suppress `dead_code` the way it would
// in a lib target. Its accessors and parsers form one coherent API and are
// exercised by the unit tests in each submodule; allowing the lint here avoids
// littering individual items with attributes. It is scoped to this module only,
// so dead code elsewhere in the agent is still reported.
#![allow(dead_code)]

pub mod diagnostics;
pub mod drops;
pub mod enrichment;
pub mod health;
pub mod histogram;
pub mod identity;
pub mod limits;
pub mod metrics;
pub mod snapshot;

// Re-exported because they appear in the shared event schema and in collector
// code; everything else is reached through its own module path, which keeps the
// call site's dependency on this module visible.
//
// `allow(unused_imports)`: which of these has a caller depends on the target —
// `ProcessKey` and `TelemetryReport` are Linux-only today, while the schema
// needs `EventOrigin` and `Enrichment` everywhere. The alternative is a thicket
// of `cfg(target_os)` on re-exports of one cohesive module.
#[allow(unused_imports)]
pub use drops::DropReason;
#[allow(unused_imports)]
pub use enrichment::{Enrichment, EnrichmentError};
#[allow(unused_imports)]
pub use identity::{EventOrigin, ProcessKey};
#[allow(unused_imports)]
pub use snapshot::TelemetryReport;
