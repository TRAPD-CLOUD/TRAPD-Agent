//! Windows-specific collectors.
//!
//! The Windows agent shares the OS-neutral event schema, transport, enrollment,
//! heartbeat and signed-config channel with the Linux agent — only the
//! collectors gathering raw telemetry differ. They emit the exact same
//! [`crate::schema`] event shapes the Linux agent produces, so the backend
//! ingest path is byte-compatible with the Linux agent's NDJSON stream:
//!
//! | Collector            | Events                                           |
//! |----------------------|--------------------------------------------------|
//! | [`process`]          | `process/create` + `process/terminate`           |
//! | [`users`]            | `user/session_open` + `user/session_close`       |
//! | [`honeytokens`]      | filesystem decoys + registry decoys (deception)  |
//!
//! OS-neutral `system/snapshot` telemetry (CPU, RAM, OS version, uptime) is
//! provided by the shared [`crate::collectors::system`] collector.

pub mod honeytokens;
pub mod process;
pub mod users;
