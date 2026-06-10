//! Windows telemetry collectors.
//!
//! The Windows MVP mirrors the polling half of the Linux collector set using
//! the cross-platform `sysinfo` crate plus built-in OS tooling, emitting the
//! exact same [`crate::schema`] event shapes so the backend ingest path is
//! byte-compatible with the Linux agent's NDJSON stream:
//!
//! | Collector            | Events                                          |
//! |----------------------|-------------------------------------------------|
//! | [`system`]           | `system/snapshot` (CPU, RAM, OS version, uptime) |
//! | [`process`]          | `process/create` + `process/terminate`          |
//! | [`users`]            | `user/session_open` + `user/session_close`      |

pub mod process;
pub mod system;
pub mod users;
