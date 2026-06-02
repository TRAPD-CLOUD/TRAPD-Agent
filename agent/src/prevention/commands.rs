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

/// One cross-linking breadcrumb in a `DeployHoneytoken` command: an artefact
/// placed next to the token to make it discoverable (a config that names the
/// key, a "forgotten" `.bash_history` line, …).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BreadcrumbSpec {
    /// Absolute path of the breadcrumb artefact.
    pub path: String,
    /// Base64 of the breadcrumb's bytes.
    pub content_b64: String,
    /// Octal file mode applied when the breadcrumb is *created* (0 → 0o600).
    #[serde(default)]
    pub mode: u32,
    /// When true, append to an existing file (e.g. shell history) instead of
    /// creating a new one — done safely, without truncation.
    #[serde(default)]
    pub append: bool,
}

/// Out-of-band canary declaration in a `DeployHoneytoken` command (issue #32,
/// point 2): the second, independent signal channel that fires when the token is
/// *used* off-host (a fake AWS key → CloudTrail alarm, a tracking DNS/HTTP domain,
/// a kube/SSH credential aimed at honeypot infra). Recorded locally and
/// republished in the deploy audit so the backend can correlate an inbound
/// foreign signal (the CloudTrail event, the domain hit, the honeypot login)
/// back to this token and host.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutOfBandSpec {
    /// Channel that fires on use — `aws_cloudtrail` / `dns` / `http` / `kube_api`
    /// / `ssh_honeypot`. Validated by the agent before placement.
    pub channel: String,
    /// Stable id the backend assigned to this canary, echoed back in the foreign
    /// signal so it can be matched to this registration.
    pub tracking_id: String,
    /// Observable token(s) in the bait that trip the channel (fake AWS key id,
    /// tracking FQDN/URL, key fingerprint, kube endpoint).
    #[serde(default)]
    pub markers: Vec<String>,
}

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
    // ── Deception / honeytokens ──────────────────────────────────────────────
    /// Place a host-tailored honeytoken whose content the backend generated.
    ///
    /// The agent writes `base64_decode(content_b64)` to `path` with camouflage:
    /// it refuses to overwrite an existing file, applies `mode`, and — when
    /// `mimic_neighbor` is set — copies owner/group + atime/mtime from a sibling
    /// so the bait blends in. `canary_marker`, when present, is the out-of-band
    /// tracking marker embedded in the content (recorded locally for later
    /// correlation; the agent does not parse it out of the content itself).
    DeployHoneytoken {
        path: String,
        content_b64: String,
        /// Octal file mode (e.g. 384 = 0o600). `0` means "mimic the neighbour".
        #[serde(default)]
        mode: u32,
        #[serde(default)]
        mimic_neighbor: bool,
        #[serde(default)]
        canary_marker: Option<String>,
        /// Optional structured out-of-band canary — the second, independent
        /// signal channel for this token (issue #32, point 2). Validated and
        /// recorded; its registration is published so the backend can correlate
        /// a foreign signal back to this token and host. Boxed so this rarely-set
        /// field does not inflate every `CommandPayload` variant.
        #[serde(default)]
        out_of_band: Option<Box<OutOfBandSpec>>,
        /// Optional token family echoed back from the recon candidate. Named
        /// `token_kind` because `kind` is the enum's own serde tag.
        #[serde(default)]
        token_kind: Option<String>,
        /// Optional cross-linking breadcrumbs placed alongside the token to make
        /// it discoverable (issue #32, point 3).
        #[serde(default)]
        breadcrumbs: Vec<BreadcrumbSpec>,
    },
    /// Remove a previously-deployed honeytoken. The agent only deletes a path
    /// that is present in its local register, so this can never remove a real
    /// file the agent did not plant.
    RevokeHoneytoken { path: String },
    // ── Forensic response (issue #32, point 5) ───────────────────────────────
    /// Freeze a process by SIGSTOP — suspend it (without killing) so it cannot
    /// react or destroy evidence while it is investigated. A forensic snapshot is
    /// captured and audited. Resume with `ThawPid` or terminate with `KillPid`.
    FreezePid { pid: i32 },
    /// Resume a previously-frozen process (SIGCONT).
    ThawPid { pid: i32 },
    // ── Real-Time Response (RTR) ─────────────────────────────────────────────
    /// Execute a signed remediation script. `script_b64` is base64 of the script
    /// body, run via `interpreter` (default `/bin/sh -c`). Gated by `rtr_enabled`.
    /// Output (capped) is returned in the audited result event.
    RunScript {
        #[serde(default)]
        interpreter: Option<String>,
        script_b64: String,
        #[serde(default)]
        timeout_secs: Option<u64>,
    },
    /// Read a file and return its (capped) contents as a base64 artifact.
    CollectFile {
        path: String,
        #[serde(default)]
        max_bytes: Option<u64>,
    },
    /// List a directory for triage (names, types, sizes).
    ListDirectory { path: String },
    /// Dump a process's readable memory regions (anonymous-executable first) as
    /// a capped base64 artifact, for offline analysis.
    CollectProcessMemory {
        pid: i32,
        #[serde(default)]
        max_bytes: Option<u64>,
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

/// Load the operator-provisioned **raw 32-byte** Ed25519 verifying key from
/// `path`. Shared by the response-command channel and the (equally
/// security-critical) remote-config channel so both trust the exact same key
/// provisioned at `<config>/command_signing.pub`.
pub fn load_verifying_key(path: &Path) -> Result<VerifyingKey> {
    let raw = std::fs::read(path)
        .with_context(|| format!("cannot read signing pubkey from {}", path.display()))?;
    let key_bytes: [u8; 32] = raw.try_into().map_err(|_| {
        anyhow::anyhow!("signing pubkey must be exactly 32 raw bytes (Ed25519 verifying key)")
    })?;
    VerifyingKey::from_bytes(&key_bytes).context("invalid Ed25519 verifying key")
}

/// Verify a **detached** base64 Ed25519 signature over the *canonical* JSON
/// serialisation of `value` (sorted-key, whitespace-free `serde_json::to_vec`),
/// returning the rejection reason on failure so the caller can audit it.
///
/// This is the exact canonicalise-then-`verify_strict` routine the command
/// channel uses; the config channel reuses it so an unsigned/tampered config is
/// rejected identically to an unsigned/tampered command. Re-serialising `value`
/// here (rather than verifying received bytes) discards any extra wire fields an
/// attacker might smuggle in — the verifier sees exactly what the signer signed.
pub fn verify_canonical<T: Serialize>(
    key: &VerifyingKey,
    value: &T,
    signature_b64: &str,
) -> std::result::Result<(), String> {
    let sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(signature_b64)
        .map_err(|e| format!("bad base64 signature: {e}"))?;
    let sig_arr: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| "signature must be 64 bytes".to_string())?;
    let signature = Signature::from_bytes(&sig_arr);
    let canonical = serde_json::to_vec(value).map_err(|e| format!("canonicalisation failed: {e}"))?;
    key.verify_strict(&canonical, &signature)
        .map_err(|e| format!("Ed25519 verification failed: {e}"))
}

impl Verifier {
    pub fn new(pubkey_path: &Path, agent_id: String, nonce_store_path: &Path) -> Result<Self> {
        let key = load_verifying_key(pubkey_path)?;
        let nonces = Arc::new(Mutex::new(NonceStore::load(nonce_store_path)));
        info!(path = %pubkey_path.display(), "Response-command verifier loaded");
        Ok(Self { key, agent_id, nonces })
    }

    /// Verify a `SignedCommand` end-to-end.  Failure reasons are returned so
    /// the caller can emit a `CommandRejected` audit event with context.
    pub fn verify(&self, cmd: &SignedCommand) -> Verdict {
        // Signature check (canonical-JSON, re-serialised) is shared with the
        // remote-config channel via `verify_canonical`.
        if let Err(reason) = verify_canonical(&self.key, &cmd.envelope, &cmd.signature) {
            return Verdict::Rejected(reason);
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
///
/// The temp file is created owner-only (`0600`) before any bytes are written so
/// the nonce store is never momentarily world-readable: a local attacker must
/// not be able to learn which command nonces have been processed.
fn atomic_write(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("tmp");
    {
        let mut f = create_owner_only(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)
}

#[cfg(unix)]
fn create_owner_only(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
}

#[cfg(not(unix))]
fn create_owner_only(path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::File::create(path)
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

    // ── Deception + forensic command vectors (backend P2) ────────────────────
    // Generated by services/web/scripts/command-canonical-vectors.ts with the
    // same fixed seed. Each pair proves the agent re-serialises the envelope to
    // the exact bytes the TS signer signed (byte-identical canonicalisation) and
    // that the signature verifies against PUB_HEX. The honeytoken fields use
    // serde `#[serde(default)]` without skip, so every field is present on the
    // wire (absent Options as `null`, empty Vecs as `[]`).

    // deploy_honeytoken (full: out_of_band + breadcrumb + all options set)
    const ENV3: &str = r#"{"command_id":"11111111-1111-1111-1111-111111111111","issued_at":"2020-01-01T00:00:00Z","expires_at":"2099-12-31T23:59:59Z","agent_id":"agent-test","nonce":"44444444-4444-4444-4444-444444444444","payload":{"kind":"deploy_honeytoken","path":"/home/alice/.aws/credentials","content_b64":"QUtJQUVYQU1QTEU=","mode":384,"mimic_neighbor":true,"canary_marker":"AKIAEXAMPLE","out_of_band":{"channel":"aws_cloudtrail","tracking_id":"trk-abc-123","markers":["AKIAEXAMPLE"]},"token_kind":"aws_credentials","breadcrumbs":[{"path":"/home/alice/.bash_history","content_b64":"ZXhwb3J0IEFXUw==","mode":0,"append":true}]}}"#;
    const SIG3: &str = "Vl1FjZi7v4RNvJX78TJUdtden3QqNal63oM9/964AWqDBJxLUgYl/BrrHYyuhh1Ny2gey6fe5BbUQoC+MTP+CQ==";

    // deploy_honeytoken (minimal: null options, empty breadcrumbs)
    const ENV4: &str = r#"{"command_id":"11111111-1111-1111-1111-111111111111","issued_at":"2020-01-01T00:00:00Z","expires_at":"2099-12-31T23:59:59Z","agent_id":"agent-test","nonce":"55555555-5555-5555-5555-555555555555","payload":{"kind":"deploy_honeytoken","path":"/srv/app/.env","content_b64":"U0VDUkVUPTE=","mode":0,"mimic_neighbor":false,"canary_marker":null,"out_of_band":null,"token_kind":null,"breadcrumbs":[]}}"#;
    const SIG4: &str = "Xdyyif3hh34vzvm6Hjo6IVoqR2o2AqeiNEIMKyEiD5248N61Jy17mbmWEnWQEoffPgZC2Paql/nEcL9xEFdKCA==";

    // revoke_honeytoken
    const ENV5: &str = r#"{"command_id":"11111111-1111-1111-1111-111111111111","issued_at":"2020-01-01T00:00:00Z","expires_at":"2099-12-31T23:59:59Z","agent_id":"agent-test","nonce":"66666666-6666-6666-6666-666666666666","payload":{"kind":"revoke_honeytoken","path":"/srv/app/.env"}}"#;
    const SIG5: &str = "fmkRmTUnMf72VJ6RBfNH3RtBxbJMY2O3OY8KTGcaOPFq/lUbggBm8SGs0LIeziURHhHySMMuP9hGlFlRSSWCCg==";

    // freeze_pid
    const ENV6: &str = r#"{"command_id":"11111111-1111-1111-1111-111111111111","issued_at":"2020-01-01T00:00:00Z","expires_at":"2099-12-31T23:59:59Z","agent_id":"agent-test","nonce":"77777777-7777-7777-7777-777777777777","payload":{"kind":"freeze_pid","pid":4242}}"#;
    const SIG6: &str = "n48rafHUR6F7qhwsyuih6QHZcDFx3DkpxQ63M5mBbBivMcdtJrVcBHpJ/eYb2MrXux3hd/qICkuhCQuATx4kBA==";

    // thaw_pid
    const ENV7: &str = r#"{"command_id":"11111111-1111-1111-1111-111111111111","issued_at":"2020-01-01T00:00:00Z","expires_at":"2099-12-31T23:59:59Z","agent_id":"agent-test","nonce":"88888888-8888-8888-8888-888888888888","payload":{"kind":"thaw_pid","pid":4242}}"#;
    const SIG7: &str = "O7Vabjri9hBQ/hkq46bjUUdz0ugzJ3Vk93DcV4zUH6ugK2fNAsdApkOcrYnBopfzt/zIyIkQ/m7PzQeQMY/0Aw==";

    // kill_pid
    const ENV8: &str = r#"{"command_id":"11111111-1111-1111-1111-111111111111","issued_at":"2020-01-01T00:00:00Z","expires_at":"2099-12-31T23:59:59Z","agent_id":"agent-test","nonce":"99999999-9999-9999-9999-999999999999","payload":{"kind":"kill_pid","pid":4242}}"#;
    const SIG8: &str = "6ysMGbqRLHq5NmtBrKiWLOJjIyyFxM/2pFsk3HfhopTLRdd4Gh395DkZydPWzbuQ3FkPG22QJjCO8ee0JpxaAg==";

    #[test]
    fn accepts_ts_signed_deception_and_forensic_vectors() {
        for (label, env, sig) in [
            ("deploy_honeytoken/full", ENV3, SIG3),
            ("deploy_honeytoken/minimal", ENV4, SIG4),
            ("revoke_honeytoken", ENV5, SIG5),
            ("freeze_pid", ENV6, SIG6),
            ("thaw_pid", ENV7, SIG7),
            ("kill_pid", ENV8, SIG8),
        ] {
            // Fresh verifier per vector so each (distinct) nonce is unseen.
            let (v, p, n) = verifier();
            let cmd: SignedCommand =
                serde_json::from_str(&format!(r#"{{"envelope":{env},"signature":"{sig}"}}"#))
                    .unwrap_or_else(|e| panic!("{label}: envelope parse failed: {e}"));
            match v.verify(&cmd) {
                Verdict::Ok(_) => {}
                Verdict::Rejected(why) => panic!("{label} vector rejected: {why}"),
            }
            let _ = std::fs::remove_file(p);
            let _ = std::fs::remove_file(n);
        }
    }
}
