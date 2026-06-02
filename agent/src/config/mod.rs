use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use anyhow::{Context, Result};
use base64::Engine as _;
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use tokio::time::{interval, Duration};
use tracing::{debug, info, warn};

fn default_poll_interval() -> u64 { 60 }
fn default_fs_watch_paths() -> Vec<String> {
    vec!["/etc".into(), "/bin".into(), "/tmp".into()]
}
fn default_enabled_collectors() -> Vec<String> {
    vec![
        "process".into(),
        "network".into(),
        "system".into(),
        "authlog".into(),
        "filesystem".into(),
    ]
}
fn default_prevention_enabled() -> bool { true }
fn default_fim_enabled() -> bool { true }
fn default_fim_interval() -> u64 { 900 }
fn default_fim_paths() -> Vec<String> {
    vec![
        "/etc".into(),
        "/usr/bin".into(),
        "/usr/sbin".into(),
        "/bin".into(),
        "/sbin".into(),
        "/boot".into(),
    ]
}
fn default_command_poll_interval() -> u64 { 10 }
fn default_inventory_enabled() -> bool { true }
fn default_honeytoken_detection_enabled() -> bool { true }
fn default_honeytoken_response() -> String { "alert".into() }
fn default_honeytoken_deception_escalation() -> bool { false }
fn default_auto_response_enabled() -> bool { false }
fn default_auto_response_action() -> String { "alert".into() }
fn default_auto_response_min_severity() -> String { "critical".into() }
fn default_auto_response_min_confidence() -> u8 { 90 }
fn default_memory_scan_enabled() -> bool { true }
fn default_memory_scan_interval_secs() -> u64 { 120 }
fn default_rtr_enabled() -> bool { false }
fn default_rtr_max_artifact_bytes() -> u64 { 32_768 }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    #[serde(default = "default_poll_interval")]
    pub poll_interval_secs:   u64,
    #[serde(default = "default_enabled_collectors")]
    pub enabled_collectors:   Vec<String>,
    #[serde(default = "default_fs_watch_paths")]
    pub fs_watch_paths:       Vec<String>,

    // ── Prevention (active response) ────────────────────────────────────────────────────────────────────
    /// Master switch for the prevention subsystem.  When `false` the engine
    /// never spawns and the agent behaves as pure telemetry.
    #[serde(default = "default_prevention_enabled")]
    pub prevention_enabled:   bool,
    /// Interval between calls to `GET /api/v1/agents/{id}/commands`.
    #[serde(default = "default_command_poll_interval")]
    pub command_poll_interval_secs: u64,
    /// Additional IPs that remain reachable when the host is in `isolate`
    /// mode (the management channel is always on the allow-list).
    #[serde(default)]
    pub isolation_allowlist_ips: Vec<String>,

    // ── File Integrity Monitoring (SHA256 FIM) ──────────────────────────────
    /// Master switch for SHA256-based file-integrity monitoring.
    #[serde(default = "default_fim_enabled")]
    pub fim_enabled: bool,
    /// Roots (files or directories) whose contents are baselined and watched
    /// for cryptographic changes.
    #[serde(default = "default_fim_paths")]
    pub fim_paths: Vec<String>,
    /// Seconds between FIM rescans (floored at 60).
    #[serde(default = "default_fim_interval")]
    pub fim_interval_secs: u64,

    // ── Asset inventory ─────────────────────────────────────────────────────
    /// Master switch for periodic asset-inventory reporting (hardware, OS,
    /// installed software, users).  When `false` no inventory is collected.
    #[serde(default = "default_inventory_enabled")]
    pub inventory_enabled: bool,

    // ── Deception / honeytoken detection (step 2) ───────────────────────────
    /// Master switch for honeytoken-access detection. When `false` the eBPF
    /// match table is not armed and accesses are not raised as detections.
    #[serde(default = "default_honeytoken_detection_enabled")]
    pub honeytoken_detection_enabled: bool,
    /// Automatic response to a honeytoken access, escalating:
    /// `none` < `alert` < `freeze` < `kill` < `isolate`. Default `alert` (emit a
    /// critical detection only); operators opt in to active response. `freeze`
    /// (alias `jail`) suspends the accessor with SIGSTOP and snapshots it instead
    /// of killing — "freeze, snapshot, then decide" (issue #32, point 5).
    #[serde(default = "default_honeytoken_response")]
    pub honeytoken_response: String,
    /// Extra accessor comms to treat as benign sweepers, on top of the built-in
    /// indexer/AV/backup allowlist (false-positive hardening).
    #[serde(default)]
    pub honeytoken_accessor_allowlist: Vec<String>,
    /// When `true`, a confirmed honeytoken hit also emits a `deception_escalation`
    /// event — the agent's signal for the backend to deploy more bait, redirect
    /// the session into a honeypot, or tarpit it (issue #32, point 5). Default
    /// `false`; escalation is an opt-in, backend-coordinated action.
    #[serde(default = "default_honeytoken_deception_escalation")]
    pub honeytoken_deception_escalation: bool,

    // ── Automated response to local detections (P0 response playbooks) ──────
    /// Master opt-in for automatically responding to *local detections* — IOC
    /// hash hits, reverse shells, IOA attack-chains, ransomware indicators,
    /// `setuid(0)` privilege escalation and credential-store access. Off by
    /// default: operators opt in so a false positive cannot kill a legitimate
    /// process unattended. Honeytoken hits keep their own `honeytoken_response`.
    #[serde(default = "default_auto_response_enabled")]
    pub auto_response_enabled: bool,
    /// Action when a detection clears the thresholds, escalating:
    /// `none` < `alert` < `kill` < `quarantine` < `isolate`. `kill` SIGKILLs the
    /// offending process; `quarantine` also locks the offending file; `isolate`
    /// additionally cuts host networking. Degrades safely when no target is
    /// known (e.g. `kill` without a PID becomes `alert`). Default `alert`.
    #[serde(default = "default_auto_response_action")]
    pub auto_response_action: String,
    /// Minimum event severity that may trigger an action:
    /// `info` < `low` < `medium` < `high` < `critical`. Default `critical`.
    #[serde(default = "default_auto_response_min_severity")]
    pub auto_response_min_severity: String,
    /// Minimum detection confidence (0–100) required to act. Default `90`.
    #[serde(default = "default_auto_response_min_confidence")]
    pub auto_response_min_confidence: u8,
    /// Detection `rule_id`s or `category`s that are never auto-actioned
    /// (false-positive guard, matched case-insensitively).
    #[serde(default)]
    pub auto_response_allowlist: Vec<String>,

    // ── Process-memory scanning ─────────────────────────────────────────────
    /// Master switch for the periodic `/proc/<pid>/maps` + `environ` scan that
    /// flags anonymous-executable / memfd / deleted-image execution and runtime
    /// `LD_PRELOAD` injection. Reads only `maps`/`environ` (cheap), default on.
    #[serde(default = "default_memory_scan_enabled")]
    pub memory_scan_enabled: bool,
    /// Seconds between memory sweeps (floored at 30).
    #[serde(default = "default_memory_scan_interval_secs")]
    pub memory_scan_interval_secs: u64,

    // ── Real-Time Response (RTR) ────────────────────────────────────────────
    /// Master opt-in for RTR commands (signed remediation script execution and
    /// artifact collection: file read, directory listing, process-memory dump).
    /// Off by default; every RTR command is still Ed25519-signed by the backend
    /// like any other response command. Operators opt in to live response.
    #[serde(default = "default_rtr_enabled")]
    pub rtr_enabled: bool,
    /// Maximum bytes returned per RTR artifact (file/memory dump). Larger
    /// payloads are truncated; the result records the original length. Keeps a
    /// single audit event within the backend's per-event size cap.
    #[serde(default = "default_rtr_max_artifact_bytes")]
    pub rtr_max_artifact_bytes: u64,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            poll_interval_secs: default_poll_interval(),
            enabled_collectors: default_enabled_collectors(),
            fs_watch_paths:     default_fs_watch_paths(),
            prevention_enabled: default_prevention_enabled(),
            command_poll_interval_secs: default_command_poll_interval(),
            isolation_allowlist_ips:    Vec::new(),
            fim_enabled:        default_fim_enabled(),
            fim_paths:          default_fim_paths(),
            fim_interval_secs:  default_fim_interval(),
            inventory_enabled:  default_inventory_enabled(),
            honeytoken_detection_enabled: default_honeytoken_detection_enabled(),
            honeytoken_response: default_honeytoken_response(),
            honeytoken_accessor_allowlist: Vec::new(),
            honeytoken_deception_escalation: default_honeytoken_deception_escalation(),
            auto_response_enabled: default_auto_response_enabled(),
            auto_response_action: default_auto_response_action(),
            auto_response_min_severity: default_auto_response_min_severity(),
            auto_response_min_confidence: default_auto_response_min_confidence(),
            auto_response_allowlist: Vec::new(),
            memory_scan_enabled: default_memory_scan_enabled(),
            memory_scan_interval_secs: default_memory_scan_interval_secs(),
            rtr_enabled: default_rtr_enabled(),
            rtr_max_artifact_bytes: default_rtr_max_artifact_bytes(),
        }
    }
}

// ── Signed config delivery ──────────────────────────────────────────────────
//
// The backend wraps `AgentConfig` in a `ConfigEnvelope` and signs it with the
// *same* operator-held Ed25519 key the agent already pins for response commands
// (`<config>/command_signing.pub`). The agent re-serialises the deserialised
// envelope to canonical JSON, verifies the signature against that pinned key,
// and rejects anything unsigned or badly-signed — keeping its last-known-good
// config rather than trusting a control plane it cannot authenticate. The
// envelope's `issued_at` MUST increase strictly monotonically per agent, so a
// stale or replayed envelope (a rollback to an older, more-permissive config)
// is refused. This is the config-channel analogue of the command nonce store
// and is documented in AGENTS.md → Backend Implementation Notes → "Signed
// config delivery". It is deliberately distinct from release-artifact signing
// (#30): that anchors trust in the shipped binary, this in the runtime config.

/// Signed body returned by `GET /api/v1/agents/{agent_id}/config`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedConfig {
    pub envelope: ConfigEnvelope,
    /// Base64-encoded 64-byte Ed25519 signature over `canonical_json(envelope)`.
    pub signature: String,
}

/// Everything the backend signs. All fields are part of the signed body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigEnvelope {
    /// Issue time; MUST be strictly greater than the previously accepted value.
    pub issued_at: DateTime<Utc>,
    /// Agent this config is addressed to; MUST match the local agent id.
    pub agent_id: String,
    /// The delivered configuration.
    pub config: AgentConfig,
}

/// Verifies `SignedConfig` envelopes against the pinned command-signing key and
/// enforces a strictly increasing `issued_at` high-water mark.
pub struct ConfigVerifier {
    key:       VerifyingKey,
    agent_id:  String,
    watermark: IssuedAtStore,
}

impl ConfigVerifier {
    /// Load the Ed25519 verifying key (raw 32 bytes) and the persisted
    /// `issued_at` high-water mark. Fails only when the key cannot be read or is
    /// malformed — the caller then keeps its last-known-good config rather than
    /// trusting an unauthenticatable channel.
    pub fn new(pubkey_path: &Path, agent_id: String, watermark_path: &Path) -> Result<Self> {
        let raw = std::fs::read(pubkey_path).with_context(|| {
            format!("cannot read config signing pubkey from {}", pubkey_path.display())
        })?;
        let key_bytes: [u8; 32] = raw.try_into().map_err(|_| {
            anyhow::anyhow!(
                "config signing pubkey must be exactly 32 raw bytes (Ed25519 verifying key)"
            )
        })?;
        let key = VerifyingKey::from_bytes(&key_bytes).context("invalid Ed25519 verifying key")?;
        let watermark = IssuedAtStore::load(watermark_path);
        info!(path = %pubkey_path.display(), "Signed-config verifier loaded");
        Ok(Self { key, agent_id, watermark })
    }

    /// Verify a signed config end-to-end. Returns the inner `AgentConfig` only
    /// when the signature, recipient and monotonic `issued_at` all check out;
    /// the `Err` string explains the rejection for the caller's log.
    pub fn verify(&mut self, signed: &SignedConfig) -> std::result::Result<AgentConfig, String> {
        let sig_bytes = base64::engine::general_purpose::STANDARD
            .decode(&signed.signature)
            .map_err(|e| format!("bad base64 signature: {e}"))?;
        let sig_arr: [u8; 64] = sig_bytes
            .try_into()
            .map_err(|_| "signature must be 64 bytes".to_string())?;
        let signature = Signature::from_bytes(&sig_arr);

        // Re-serialise canonically so extra wire fields cannot smuggle past the
        // signature: the verifier sees exactly the bytes the signer produced.
        let canonical = serde_json::to_vec(&signed.envelope)
            .map_err(|e| format!("canonicalisation failed: {e}"))?;
        self.key
            .verify_strict(&canonical, &signature)
            .map_err(|e| format!("Ed25519 verification failed: {e}"))?;

        if signed.envelope.agent_id != self.agent_id {
            return Err(format!(
                "config addressed to {}, not us ({})",
                signed.envelope.agent_id, self.agent_id
            ));
        }

        // Monotonic issued_at: reject stale / replayed (rollback) envelopes.
        let issued_at = signed.envelope.issued_at;
        if let Some(last) = self.watermark.last() {
            if issued_at <= last {
                return Err(format!(
                    "stale config: issued_at {issued_at} not newer than last accepted {last}"
                ));
            }
        }
        self.watermark.advance(issued_at);

        debug!(%issued_at, "signed config verified");
        Ok(signed.envelope.config.clone())
    }
}

#[derive(Debug, Serialize, Deserialize, Default)]
struct IssuedAtRecord {
    issued_at: DateTime<Utc>,
}

/// Persisted high-water mark of the most recent `issued_at` accepted, so a
/// restart cannot be tricked into re-accepting a stale config (rollback).
struct IssuedAtStore {
    path: PathBuf,
    last: Option<DateTime<Utc>>,
}

impl IssuedAtStore {
    fn load(path: &Path) -> Self {
        let last = std::fs::read(path)
            .ok()
            .and_then(|b| serde_json::from_slice::<IssuedAtRecord>(&b).ok())
            .map(|r| r.issued_at);
        Self { path: path.to_path_buf(), last }
    }

    fn last(&self) -> Option<DateTime<Utc>> {
        self.last
    }

    fn advance(&mut self, issued_at: DateTime<Utc>) {
        self.last = Some(issued_at);
        let rec = IssuedAtRecord { issued_at };
        if let Ok(bytes) = serde_json::to_vec(&rec) {
            if let Err(e) = crate::paths::write_atomic(&self.path, &bytes, 0o600) {
                warn!(error = %e, "cannot persist config issued_at high-water mark");
            }
        }
    }
}

/// State file holding the accepted-config `issued_at` high-water mark.
fn config_watermark_path() -> PathBuf {
    crate::paths::state_dir().join("config_issued_at.json")
}

pub struct ConfigPuller {
    config:     Arc<RwLock<AgentConfig>>,
    client:     reqwest::Client,
    config_url: String,
    token:      String,
    etag:       Option<String>,
    verifier:   Option<ConfigVerifier>,
}

impl ConfigPuller {
    pub fn new(
        config:      Arc<RwLock<AgentConfig>>,
        backend_url: &str,
        agent_id:    &str,
        token:       String,
    ) -> Self {
        let base = crate::http::normalize_base_url(backend_url);
        // Config updates must be signed with the pinned command-signing key. If
        // the key is absent/malformed we keep last-known-good rather than trust
        // an unauthenticatable channel — matching the response-command path.
        let verifier = match ConfigVerifier::new(
            &crate::prevention::command_pubkey_path(),
            agent_id.to_string(),
            &config_watermark_path(),
        ) {
            Ok(v) => Some(v),
            Err(e) => {
                warn!(
                    error = %e,
                    "signed-config verifier unavailable — backend config updates will be \
                     ignored (keeping last-known-good)"
                );
                None
            }
        };
        Self {
            config,
            client:     crate::http::control_client(),
            config_url: format!("{base}/api/v1/agents/{agent_id}/config"),
            token,
            etag:       None,
            verifier,
        }
    }

    pub async fn run(mut self) {
        let mut ticker = interval(Duration::from_secs(60));
        loop {
            ticker.tick().await;
            self.pull().await;
        }
    }

    async fn pull(&mut self) {
        let mut req = self
            .client
            .get(&self.config_url)
            .bearer_auth(&self.token);

        if let Some(etag) = &self.etag {
            req = req.header("If-None-Match", etag.as_str());
        }

        let resp = match req.send().await {
            Ok(r)  => r,
            Err(e) => { warn!("Config pull failed: {e}"); return; }
        };

        match resp.status().as_u16() {
            304 => {
                debug!("Config unchanged (304 Not Modified)");
            }
            200 => {
                // Capture (but don't yet cache) the ETag: it is only adopted
                // once the body verifies, so a transiently bad/unsigned config
                // can't latch us into 304s and block a later good update.
                let new_etag = resp
                    .headers()
                    .get("etag")
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_string);
                let body = match resp.bytes().await {
                    Ok(b)  => b,
                    Err(e) => { warn!("Failed to read config response body: {e}"); return; }
                };
                if self.apply_body(&body) {
                    self.etag = new_etag;
                }
            }
            s => warn!("Config pull returned unexpected status {s}"),
        }
    }

    /// Verify and apply a config response body. Returns `true` only when a new
    /// config was actually adopted, so the caller knows whether to cache the
    /// ETag.
    fn apply_body(&mut self, body: &[u8]) -> bool {
        let verifier = match self.verifier.as_mut() {
            Some(v) => v,
            None => {
                warn!(
                    "received config update but no signing key is provisioned — ignoring \
                     (keeping last-known-good)"
                );
                return false;
            }
        };
        let signed: SignedConfig = match serde_json::from_slice(body) {
            Ok(s)  => s,
            Err(e) => { warn!("Failed to parse signed config response: {e}"); return false; }
        };
        match verifier.verify(&signed) {
            Ok(new_cfg) => match self.config.write() {
                Ok(mut cfg) => {
                    *cfg = new_cfg;
                    info!("Agent config updated from backend (signature + issued_at verified)");
                    true
                }
                Err(e) => { warn!("Config RwLock poisoned: {e}"); false }
            },
            Err(why) => {
                warn!("Rejected backend config: {why} — keeping last-known-good");
                false
            }
        }
    }
}

#[cfg(test)]
mod signed_config_tests {
    //! Exercises the agent-side `SignedConfig` contract: an Ed25519-signed
    //! `ConfigEnvelope` is accepted only when the signature verifies against the
    //! pinned key, is addressed to this agent, and carries a strictly increasing
    //! `issued_at`. The signing here mirrors what the backend must do
    //! (`serde_json::to_vec(envelope)` → Ed25519 sign), proving both ends agree
    //! on the canonical byte sequence.
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn tmp(suffix: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("trapd_cfg_{nanos}_{suffix}"))
    }

    fn signing_key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    fn make_signed(key: &SigningKey, agent_id: &str, issued_at: DateTime<Utc>) -> SignedConfig {
        let envelope = ConfigEnvelope {
            issued_at,
            agent_id: agent_id.into(),
            config: AgentConfig::default(),
        };
        let canonical = serde_json::to_vec(&envelope).unwrap();
        let signature = base64::engine::general_purpose::STANDARD.encode(key.sign(&canonical).to_bytes());
        SignedConfig { envelope, signature }
    }

    fn verifier(key: &SigningKey, agent_id: &str) -> (ConfigVerifier, PathBuf, PathBuf) {
        let pub_path = tmp("pub");
        let wm_path = tmp("issued.json");
        std::fs::write(&pub_path, key.verifying_key().to_bytes()).unwrap();
        let v = ConfigVerifier::new(&pub_path, agent_id.into(), &wm_path).unwrap();
        (v, pub_path, wm_path)
    }

    fn cleanup(p: PathBuf, w: PathBuf) {
        let _ = std::fs::remove_file(p);
        let _ = std::fs::remove_file(w);
    }

    #[test]
    fn accepts_valid_signed_config() {
        let key = signing_key();
        let (mut v, p, w) = verifier(&key, "agent-1");
        let signed = make_signed(&key, "agent-1", Utc::now());
        assert!(v.verify(&signed).is_ok(), "valid signed config rejected");
        cleanup(p, w);
    }

    #[test]
    fn rejects_tampered_config() {
        let key = signing_key();
        let (mut v, p, w) = verifier(&key, "agent-1");
        let mut signed = make_signed(&key, "agent-1", Utc::now());
        // Flip a field after signing — the signature must no longer verify.
        signed.envelope.config.prevention_enabled = false;
        signed.envelope.config.poll_interval_secs = 999_999;
        assert!(v.verify(&signed).is_err(), "tampered config accepted");
        cleanup(p, w);
    }

    #[test]
    fn rejects_wrong_signing_key() {
        let key = signing_key();
        let attacker = SigningKey::from_bytes(&[9u8; 32]);
        let (mut v, p, w) = verifier(&key, "agent-1");
        let signed = make_signed(&attacker, "agent-1", Utc::now());
        assert!(v.verify(&signed).is_err(), "config signed by wrong key accepted");
        cleanup(p, w);
    }

    #[test]
    fn rejects_wrong_recipient() {
        let key = signing_key();
        let (mut v, p, w) = verifier(&key, "agent-1");
        let signed = make_signed(&key, "another-agent", Utc::now());
        assert!(v.verify(&signed).is_err(), "config for another agent accepted");
        cleanup(p, w);
    }

    #[test]
    fn enforces_monotonic_issued_at() {
        let key = signing_key();
        let (mut v, p, w) = verifier(&key, "agent-1");
        let t1 = Utc::now();
        assert!(v.verify(&make_signed(&key, "agent-1", t1)).is_ok());
        // Older issue time -> rollback, rejected.
        assert!(v.verify(&make_signed(&key, "agent-1", t1 - chrono::Duration::seconds(60))).is_err());
        // Same issue time -> replay, rejected.
        assert!(v.verify(&make_signed(&key, "agent-1", t1)).is_err());
        // Strictly newer -> accepted.
        assert!(v.verify(&make_signed(&key, "agent-1", t1 + chrono::Duration::seconds(1))).is_ok());
        cleanup(p, w);
    }

    #[test]
    fn watermark_persists_across_reload() {
        let key = signing_key();
        let pub_path = tmp("pub");
        let wm_path = tmp("issued.json");
        std::fs::write(&pub_path, key.verifying_key().to_bytes()).unwrap();
        let t1 = Utc::now();
        {
            let mut v = ConfigVerifier::new(&pub_path, "agent-1".into(), &wm_path).unwrap();
            assert!(v.verify(&make_signed(&key, "agent-1", t1)).is_ok());
        }
        // A fresh verifier must load the persisted high-water mark and still
        // refuse a replay of the same issue time.
        let mut v2 = ConfigVerifier::new(&pub_path, "agent-1".into(), &wm_path).unwrap();
        assert!(v2.verify(&make_signed(&key, "agent-1", t1)).is_err(), "watermark not persisted");
        assert!(v2.verify(&make_signed(&key, "agent-1", t1 + chrono::Duration::seconds(1))).is_ok());
        cleanup(pub_path, wm_path);
    }
}
