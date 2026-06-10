//! Windows-specific collectors.
//!
//! The Windows agent shares the OS-neutral event schema, transport, enrollment,
//! heartbeat and signed-config channel with the Linux agent — only the
//! collectors gathering raw telemetry differ. Today that is the honeytoken
//! sentinel (filesystem decoys + registry decoys); further collectors (ETW
//! process/network telemetry) follow the same `Collector` trait.

pub mod honeytokens;
