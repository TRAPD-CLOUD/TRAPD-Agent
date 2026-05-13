//! Signed response commands.
//!
//! The backend issues commands wrapped in a `SignedCommand` envelope that we
//! verify against the operator-provisioned Ed25519 public key at
//! `/etc/trapd/command_signing.pub` (32 raw bytes).  No unsigned command is
//! ever executed.
//!
//! ## Wire format
//! ```json
//! {
//!   "envelope": {
//!     "command_id": "uuid",
//!     "issued_at":  "RFC3339",
//!     "expires_at": "RFC3339",
//!     "agent_id":   "this-agent",
//!     "nonce":      "uuid",
//!     "payload":    { "kind": "kill_pid", "pid": 1234 }
//!   },
//!   "signature": "base64(ed25519(canonical_json(envelope)))"
//! }
//! ```
//!
//! Signature input is the **canonical** JSON serialisation of `envelope`
//! (sorted keys, no whitespace) — both ends MUST produce the identical byte
//! sequence.  We rely on `serde_json::to_vec` which is deterministic for our
//! struct definitions, *and* re-serialise the deserialised envelope before
//! verification so attackers cannot smuggle extra fields.
//!
//! ## Replay protection
//! Every accepted command's nonce is appended to
//! `/var/lib/trapd/command_nonces.json` along with `expires_at`.  A nonce
//! seen before is rejected.  Stale entries (`expires_at` in the past) are
//! pruned on every accept.

use std::collections::HashSet;
use std::net::IpAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use base64::Engine as _;
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};
use uuid::Uuid;

use super::policy::IocRule;

/// Discriminated union of all response commands the backend can request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CommandPayload {
    /// Send SIGKILL to the given PID.
    KillPid { pid: i32 },
    /// Enable full host isolation. `allowlist_ips` are the only destinations
    /// reachable in addition to the management channel.
    IsolateNetwork {
        #[serde(default)]
        allowlist_ips: Vec<IpAddr>,
    },
    /// Lift host isolation.
    DeisolateNetwork,
    /// Move the file to quarantine.
    QuarantineFile { path: String },
    /// Restore a previously quarantined file back to its original path.
    RestoreFile { quarantine_id: String },
    /// Add an IP or CIDR to the persistent deny-list.
    BlockIp { ip: String, #[serde(default)] ttl_secs: Option<u64> },
    /// Remove an IP/CIDR from the deny-list.
    UnblockIp { ip: String },
    /// Replace the entire IoC rule set.
    UpdatePolicy { rules: Vec<IocRule> },
}

/// Envelope signed by the backend.  All fields are part of the signed body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandEnvelope {
    pub command_id: Uuid,
    pub issued_at:  DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub agent_id:   String,
    pub nonce:      Uuid,
    pub payload:    CommandPayload,
}

/// Wire-level signed command.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedCommand {
    pub envelope:  CommandEnvelope,
    /// Base64-encoded 64-byte Ed25519 signature over canonical_json(envelope).
    pub signature: String,
}

/// All possible verification outcomes.
#[derive(Debug)]
pub enum Verdict {
    Ok(CommandEnvelope),
    Rejected(String),
}

/// Loads + caches the Ed25519 verifying key.  Cheap to clone.
#[derive(Clone)]
pub struct Verifier {
    key:    VerifyingKey,
    agent_id: String,
    nonces: Arc<Mutex<NonceStore>>,
}

impl Verifier {
    pub fn new(pubkey_path: &Path, agent_id: String, nonce_store_path: &Path) -> Result<Self> {
        let raw = std::fs::read(pubkey_path)
            .with_context(|| format!("cannot read command signing pubkey from {}", pubkey_path.display()))?;
        let key_bytes: [u8; 32] = raw
            .try_into()
            .map_err(|_| anyhow::anyhow!(
                "command signing pubkey must be exactly 32 raw bytes (Ed25519 verifying key)"
            ))?;
        let key = VerifyingKey::from_bytes(&key_bytes)
            .context("invalid Ed25519 verifying key")?;
        let nonces = Arc::new(Mutex::new(NonceStore::load(nonce_store_path)));
        info!(path = %pubkey_path.display(), "Response-command verifier loaded");
        Ok(Self { key, agent_id, nonces })
    }

    /// Verify a `SignedCommand` end-to-end.  Failure reasons are returned so
    /// the caller can emit a `CommandRejected` audit event with context.
    pub fn verify(&self, cmd: &SignedCommand) -> Verdict {
        let sig_bytes = match base64::engine::general_purpose::STANDARD.decode(&cmd.signature) {
            Ok(b)  => b,
            Err(e) => return Verdict::Rejected(format!("bad base64 signature: {e}")),
        };
        let sig_arr: [u8; 64] = match sig_bytes.try_into() {
            Ok(a)  => a,
            Err(_) => return Verdict::Rejected("signature must be 64 bytes".into()),
        };
        let signature = Signature::from_bytes(&sig_arr);

        // Re-serialise canonically: discard whatever extra fields the wire
        // may have carried so the verifier sees exactly the same bytes the
        // signer produced.
        let canonical = match serde_json::to_vec(&cmd.envelope) {
            Ok(v)  => v,
            Err(e) => return Verdict::Rejected(format!("canonicalisation failed: {e}")),
        };
        if let Err(e) = self.key.verify_strict(&canonical, &signature) {
            return Verdict::Rejected(format!("Ed25519 verification failed: {e}"));
        }

        if cmd.envelope.agent_id != self.agent_id {
            return Verdict::Rejected(format!(
                "command addressed to {}, not us ({})",
                cmd.envelope.agent_id, self.agent_id
            ));
        }

        let now = Utc::now();
        if cmd.envelope.expires_at < now {
            return Verdict::Rejected(format!(
                "command expired at {} (now {})", cmd.envelope.expires_at, now
            ));
        }
        if cmd.envelope.issued_at > now + chrono::Duration::minutes(5) {
            return Verdict::Rejected(format!(
                "command issued in the future ({})", cmd.envelope.issued_at
            ));
        }

        let mut store = self.nonces.lock().expect("nonce store poisoned");
        if !store.try_insert(cmd.envelope.nonce, cmd.envelope.expires_at) {
            return Verdict::Rejected(format!(
                "replay: nonce {} already seen", cmd.envelope.nonce
            ));
        }
        drop(store);

        debug!(
            command_id = %cmd.envelope.command_id,
            kind = ?cmd.envelope.payload,
            "signed command verified",
        );

        Verdict::Ok(cmd.envelope.clone())
    }
}

#[derive(Debug, Serialize, Deserialize, Default)]
struct NonceRecord {
    nonce:      Uuid,
    expires_at: DateTime<Utc>,
}

struct NonceStore {
    path:    std::path::PathBuf,
    seen:    HashSet<Uuid>,
    records: Vec<NonceRecord>,
}

impl NonceStore {
    fn load(path: &Path) -> Self {
        let records: Vec<NonceRecord> = std::fs::read(path)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        let seen = records.iter().map(|r| r.nonce).collect();
        Self {
            path: path.to_path_buf(),
            seen,
            records,
        }
    }

    fn try_insert(&mut self, nonce: Uuid, expires_at: DateTime<Utc>) -> bool {
        if self.seen.contains(&nonce) {
            return false;
        }
        let now = Utc::now();
        self.records.retain(|r| r.expires_at > now);
        self.seen.clear();
        for r in &self.records {
            self.seen.insert(r.nonce);
        }

        self.records.push(NonceRecord { nonce, expires_at });
        self.seen.insert(nonce);

        if let Ok(bytes) = serde_json::to_vec(&self.records) {
            if let Err(e) = atomic_write(&self.path, &bytes) {
                warn!(error = %e, "cannot persist nonce store");
            }
        }
        true
    }
}

/// Write a file atomically — write to a sibling temp file, fsync, rename.
fn atomic_write(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("tmp");
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)
}
