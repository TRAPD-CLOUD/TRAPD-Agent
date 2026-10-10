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
//! | [`regwatch`]         | `registry/{create,modify,delete}` persistence    |
//! | [`memscan`]          | code-injection detections (RWX / injected PE)    |
//!
//! OS-neutral `system/snapshot` telemetry (CPU, RAM, OS version, uptime) is
//! provided by the shared [`crate::collectors::system`] collector.

pub mod decoy_audit;
pub mod etw;
pub mod eventlog;
pub mod filesystem;
pub mod honeytokens;
pub mod memscan;
pub mod network;
pub mod process;
pub mod regwatch;
pub mod registry;
pub mod users;

pub mod sensor_supervisor;

pub mod sweeper_identity;
