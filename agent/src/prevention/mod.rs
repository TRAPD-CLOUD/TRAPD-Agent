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
pub mod command_puller;
pub mod commands;
pub mod engine;
pub mod lsm_loader;
pub mod network;
pub mod policy;
pub mod process;
pub mod quarantine;
pub mod response;
pub mod rtr;
pub mod software;

use std::path::PathBuf;

// Prevention paths derive from the shared, $HOME-independent layout in
// [`crate::paths`], so they honour TRAPD_STATE_DIR / TRAPD_CONFIG_DIR exactly
// like device_id, credentials and the FIM baseline.  Under systemd-as-root they
// resolve to /var/lib/trapd and /etc/trapd; in a non-root test run they follow
// the overrides, so quarantine and the command verifier work there too.

/// Directory holding quarantined file payloads.
pub fn quarantine_dir() -> PathBuf {
    crate::paths::state_dir().join("quarantine")
}
/// Quarantine index — JSON list of `QuarantineRecord`s.
pub fn quarantine_index() -> PathBuf {
    quarantine_dir().join("index.json")
}
/// Replay-protection store — JSON list of accepted command-nonces.
pub fn nonce_store() -> PathBuf {
    crate::paths::state_dir().join("command_nonces.json")
}
/// Public key used to verify backend-issued response commands.
pub fn command_pubkey_path() -> PathBuf {
    crate::paths::config_dir().join("command_signing.pub")
}
/// Local boot-time IoC policy file (optional).
pub fn local_policy_path() -> PathBuf {
    crate::paths::config_dir().join("policy.json")
}

/// Ensure the on-disk state hierarchy exists.  Best-effort; logs but never
/// fails the agent because prevention is opt-in.
pub fn ensure_state_dirs() {
    for path in [crate::paths::state_dir().to_path_buf(), quarantine_dir()] {
        if let Err(e) = std::fs::create_dir_all(&path) {
            tracing::warn!(path = %path.display(), error = %e, "cannot create prevention state dir");
        }
    }
}
