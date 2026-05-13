//! Active prevention / response subsystem — the "EDR" half of TRAPD.
//!
//! Where the collectors and self-protection modules are read-only telemetry,
//! this module *takes action*: kills processes, quarantines files, sets
//! firewall rules and isolates the host from the network.  Every action is
//!
//!   1. authorised — either by a locally-loaded IoC rule (boot config) or by
//!      a signed command from the backend (Ed25519 signature verified against
//!      `/etc/trapd/command_signing.pub`),
//!   2. audited    — emitted as an `EventClass::Prevention` event into the
//!      regular telemetry pipeline so the backend has a tamper-evident record,
//!   3. reversible — every quarantine has a `restore`, every isolation has a
//!      `deisolate`, every IP block has an `ip_unblock`.
//!
//! See `engine.rs` for the orchestration loop.

pub mod audit;
pub mod commands;
pub mod command_puller;
pub mod engine;
pub mod lsm_loader;
pub mod network;
pub mod policy;
pub mod process;
pub mod quarantine;

use std::path::PathBuf;

/// Root directory for all prevention-owned on-disk state.
pub const STATE_DIR: &str = "/var/lib/trapd";
/// Directory holding quarantined file payloads.
pub const QUARANTINE_DIR: &str = "/var/lib/trapd/quarantine";
/// Quarantine index — JSON list of `QuarantineRecord`s.
pub const QUARANTINE_INDEX: &str = "/var/lib/trapd/quarantine/index.json";
/// Replay-protection store — JSON list of accepted command-nonces.
pub const NONCE_STORE: &str = "/var/lib/trapd/command_nonces.json";
/// Public key used to verify backend-issued response commands.
pub const COMMAND_PUBKEY_PATH: &str = "/etc/trapd/command_signing.pub";
/// Local boot-time IoC policy file (optional).
pub const LOCAL_POLICY_PATH: &str = "/etc/trapd/policy.json";

/// Ensure the on-disk state hierarchy exists.  Best-effort; logs but never
/// fails the agent because prevention is opt-in.
pub fn ensure_state_dirs() {
    for p in [STATE_DIR, QUARANTINE_DIR] {
        let path = PathBuf::from(p);
        if let Err(e) = std::fs::create_dir_all(&path) {
            tracing::warn!(path = %path.display(), error = %e, "cannot create prevention state dir");
        }
    }
}
