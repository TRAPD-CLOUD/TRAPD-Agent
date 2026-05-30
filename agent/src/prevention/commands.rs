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
    // ── Software / asset management ──────────────────────────────────────────
    /// Install a package via the host package manager (apt/dnf/yum/zypper).
    InstallPackage { name: String },
    /// Remove a package.
    RemovePackage { name: String },
    /// Upgrade a single package, or all packages when `name` is omitted.
    UpgradePackage {
        #[serde(default)]
        name: Option<String>,
    },
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

#[cfg(test)]
mod cross_lang_tests {
    //! Proves the TypeScript signer in the backend
    //! (`services/web/lib/api/commands/sign.ts`) produces signatures this
    //! verifier accepts. The vectors below are generated by signing canonical
    //! envelopes with a fixed Ed25519 seed (bytes 0x01..=0x20); regenerate with
    //! `services/web/scripts/gen-command-signing-key.mjs` logic if the wire
    //! format ever changes. A mismatch here means the two ends disagree on the
    //! canonical byte sequence — the exact bug this test exists to catch.
    use super::*;

    // Public key derived from the fixed test seed.
    const PUB_HEX: &str = "79b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664";

    // install_package "nginx"
    const ENV1: &str = r#"{"command_id":"11111111-1111-1111-1111-111111111111","issued_at":"2020-01-01T00:00:00Z","expires_at":"2099-12-31T23:59:59Z","agent_id":"agent-test","nonce":"22222222-2222-2222-2222-222222222222","payload":{"kind":"install_package","name":"nginx"}}"#;
    const SIG1: &str = "ttR686hugcf021c/y7KgsQMK59CSwkGUK3NVlsVLEtFXxt373BeMcMhTC1gKSfljYb+SVVV4uCG4H61kkrJwBw==";

    // upgrade_package, name=null (upgrade-all)
    const ENV2: &str = r#"{"command_id":"11111111-1111-1111-1111-111111111111","issued_at":"2020-01-01T00:00:00Z","expires_at":"2099-12-31T23:59:59Z","agent_id":"agent-test","nonce":"33333333-3333-3333-3333-333333333333","payload":{"kind":"upgrade_package","name":null}}"#;
    const SIG2: &str = "uT+YB5dgXErGwNAgxYmxM0D8tR/YxTVg+jximA8SABzjLu1BD8PQ37Am4M2gfFl1ywV+h3uAmdatRozsRUqVAg==";

    fn temp_path(suffix: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("trapd_xlang_{nanos}_{suffix}"))
    }

    fn verifier() -> (Verifier, std::path::PathBuf, std::path::PathBuf) {
        let pub_path = temp_path("pub");
        let nonce_path = temp_path("nonces.json");
        std::fs::write(&pub_path, hex::decode(PUB_HEX).unwrap()).unwrap();
        let v = Verifier::new(&pub_path, "agent-test".into(), &nonce_path).unwrap();
        (v, pub_path, nonce_path)
    }

    #[test]
    fn accepts_ts_signed_install() {
        let (v, p, n) = verifier();
        let cmd: SignedCommand = serde_json::from_str(
            &format!(r#"{{"envelope":{ENV1},"signature":"{SIG1}"}}"#),
        )
        .unwrap();
        match v.verify(&cmd) {
            Verdict::Ok(env) => assert_eq!(env.agent_id, "agent-test"),
            Verdict::Rejected(why) => panic!("install vector rejected: {why}"),
        }
        let _ = std::fs::remove_file(p);
        let _ = std::fs::remove_file(n);
    }

    #[test]
    fn accepts_ts_signed_upgrade_all() {
        let (v, p, n) = verifier();
        let cmd: SignedCommand = serde_json::from_str(
            &format!(r#"{{"envelope":{ENV2},"signature":"{SIG2}"}}"#),
        )
        .unwrap();
        assert!(matches!(v.verify(&cmd), Verdict::Ok(_)), "upgrade-all vector rejected");
        let _ = std::fs::remove_file(p);
        let _ = std::fs::remove_file(n);
    }

    #[test]
    fn rejects_tampered_payload() {
        let (v, p, n) = verifier();
        // Flip the package name; signature must no longer verify.
        let tampered = ENV1.replace("nginx", "evilpkg");
        let cmd: SignedCommand = serde_json::from_str(
            &format!(r#"{{"envelope":{tampered},"signature":"{SIG1}"}}"#),
        )
        .unwrap();
        assert!(matches!(v.verify(&cmd), Verdict::Rejected(_)), "tampered payload accepted");
        let _ = std::fs::remove_file(p);
        let _ = std::fs::remove_file(n);
    }
}
