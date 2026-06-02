use std::sync::{Arc, RwLock};

use anyhow::Result;
use chrono::{DateTime, Utc};
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use tokio::time::{interval, Duration};
use tracing::{debug, info, warn};

use crate::prevention::{command_pubkey_path, commands::{load_verifying_key, verify_canonical}};

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

/// Signed remote-config envelope. The backend MUST wrap the live [`AgentConfig`]
/// in this envelope and sign `canonical_json(envelope)` with the **same** Ed25519
/// key it uses for response commands (`<config>/command_signing.pub`). The agent
/// rejects any config whose signature, target `agent_id` or freshness does not
/// check out: the config controls `prevention_enabled`, the `auto_response_*`
/// switches, `fim_paths`, `honeytoken_response` and `isolation_allowlist_ips`,
/// so it is at least as security-critical as a signed command and must not be
/// applied unsigned (issue #47, H-A).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigEnvelope {
    /// Agent this config is addressed to; rejected if it is not us.
    pub agent_id:  String,
    /// When the backend issued this config. Used to reject rollback (an old,
    /// validly-signed config replayed to silently re-enable a weaker posture).
    pub issued_at: DateTime<Utc>,
    /// The configuration to apply once the envelope verifies.
    pub config:    AgentConfig,
}

/// Wire-level signed config: an envelope plus its detached signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedConfig {
    pub envelope:  ConfigEnvelope,
    /// Base64-encoded 64-byte Ed25519 signature over `canonical_json(envelope)`.
    pub signature: String,
}

/// Verify a [`SignedConfig`] against the provisioned key, the expected
/// `agent_id`, and freshness/rollback rules. Pure (no I/O, no locks) so the
/// accept/reject decision is unit-testable. Returns the rejection reason on
/// failure; `Ok(())` means the envelope's `config` is safe to apply.
fn evaluate_config(
    key:               Option<&VerifyingKey>,
    expected_agent_id: &str,
    last_issued_at:    Option<DateTime<Utc>>,
    signed:            &SignedConfig,
    now:               DateTime<Utc>,
) -> std::result::Result<(), String> {
    // Fail-closed: with no provisioned signing key we cannot verify anything,
    // so no remote config is ever applied.
    let key = key.ok_or_else(|| {
        format!(
            "no signing key provisioned at {} — cannot verify remote config (fail-closed)",
            command_pubkey_path().display()
        )
    })?;

    verify_canonical(key, &signed.envelope, &signed.signature)?;

    if signed.envelope.agent_id != expected_agent_id {
        return Err(format!(
            "config addressed to {}, not us ({expected_agent_id})",
            signed.envelope.agent_id
        ));
    }

    // Guard against an absurd future timestamp (clock skew tolerance: 5 min).
    if signed.envelope.issued_at > now + chrono::Duration::minutes(5) {
        return Err(format!(
            "config issued in the future ({})",
            signed.envelope.issued_at
        ));
    }

    // Rollback protection: never apply a config older than the last one applied.
    if let Some(prev) = last_issued_at {
        if signed.envelope.issued_at < prev {
            return Err(format!(
                "config issued_at {} is older than last applied {prev} (rollback)",
                signed.envelope.issued_at
            ));
        }
    }

    Ok(())
}

pub struct ConfigPuller {
    config:         Arc<RwLock<AgentConfig>>,
    client:         reqwest::Client,
    config_url:     String,
    agent_id:       String,
    token:          String,
    etag:           Option<String>,
    /// Ed25519 verifying key (`<config>/command_signing.pub`). `None` when no key
    /// is provisioned — in which case every remote config is rejected.
    key:            Option<VerifyingKey>,
    /// `issued_at` of the last successfully-applied config (rollback guard).
    last_issued_at: Option<DateTime<Utc>>,
}

impl ConfigPuller {
    pub fn new(
        config:      Arc<RwLock<AgentConfig>>,
        backend_url: &str,
        agent_id:    &str,
        token:       String,
    ) -> Result<Self> {
        let base = crate::http::normalize_base_url(backend_url);
        // Reuse the response-command signing key for the config channel.
        let key = match load_verifying_key(&command_pubkey_path()) {
            Ok(k) => Some(k),
            Err(e) => {
                warn!(
                    error = %e,
                    "config signing key unavailable — remote config will be rejected (fail-closed). \
                     Provision {}",
                    command_pubkey_path().display()
                );
                None
            }
        };
        Ok(Self {
            config,
            client:         crate::http::control_client()?,
            config_url:     format!("{base}/api/v1/agents/{agent_id}/config"),
            agent_id:       agent_id.to_string(),
            token,
            etag:           None,
            key,
            last_issued_at: None,
        })
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
                // Only cache the ETag once a config is *applied*, so a rejected
                // (unsigned/tampered) payload is re-fetched and re-evaluated
                // rather than masked behind a 304 forever.
                let etag = resp
                    .headers()
                    .get("etag")
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_string);
                match resp.json::<SignedConfig>().await {
                    Ok(signed) => {
                        if self.accept(signed) {
                            self.etag = etag;
                        }
                    }
                    Err(e) => warn!("Failed to parse signed config response: {e}"),
                }
            }
            s => warn!("Config pull returned unexpected status {s}"),
        }
    }

    /// Verify and apply a signed config. Returns `true` only when it was applied.
    fn accept(&mut self, signed: SignedConfig) -> bool {
        if let Err(reason) = evaluate_config(
            self.key.as_ref(),
            &self.agent_id,
            self.last_issued_at,
            &signed,
            Utc::now(),
        ) {
            warn!(reason = %reason, "remote config rejected");
            return false;
        }

        match self.config.write() {
            Ok(mut cfg) => {
                *cfg = signed.envelope.config;
                self.last_issued_at = Some(signed.envelope.issued_at);
                info!("Agent config updated from backend (signature verified)");
                true
            }
            Err(e) => {
                warn!("Config RwLock poisoned: {e}");
                false
            }
        }
    }
}

#[cfg(test)]
mod signed_config_tests {
    use super::*;
    use base64::Engine as _;
    use ed25519_dalek::{Signer, SigningKey};

    const AGENT_ID: &str = "agent-under-test";

    fn signing_key() -> SigningKey {
        // Fixed seed → deterministic key; no rng feature required.
        let seed: [u8; 32] = [7u8; 32];
        SigningKey::from_bytes(&seed)
    }

    fn sign(envelope: &ConfigEnvelope, sk: &SigningKey) -> String {
        let canonical = serde_json::to_vec(envelope).unwrap();
        let sig = sk.sign(&canonical);
        base64::engine::general_purpose::STANDARD.encode(sig.to_bytes())
    }

    fn envelope(issued_at: DateTime<Utc>) -> ConfigEnvelope {
        ConfigEnvelope {
            agent_id:  AGENT_ID.to_string(),
            issued_at,
            config:    AgentConfig::default(),
        }
    }

    fn now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-06-02T10:00:00Z").unwrap().with_timezone(&Utc)
    }

    #[test]
    fn accepts_a_valid_signed_config() {
        let sk = signing_key();
        let env = envelope(now());
        let signed = SignedConfig { signature: sign(&env, &sk), envelope: env };
        assert!(evaluate_config(Some(&sk.verifying_key()), AGENT_ID, None, &signed, now()).is_ok());
    }

    #[test]
    fn rejects_when_no_key_provisioned() {
        let sk = signing_key();
        let env = envelope(now());
        let signed = SignedConfig { signature: sign(&env, &sk), envelope: env };
        // Fail-closed: a perfectly-signed config is still rejected with no key.
        assert!(evaluate_config(None, AGENT_ID, None, &signed, now()).is_err());
    }

    #[test]
    fn rejects_unsigned_or_garbage_signature() {
        let sk = signing_key();
        let env = envelope(now());
        let signed = SignedConfig { envelope: env, signature: "not-a-signature".into() };
        assert!(evaluate_config(Some(&sk.verifying_key()), AGENT_ID, None, &signed, now()).is_err());
    }

    #[test]
    fn rejects_tampered_config_after_signing() {
        let sk = signing_key();
        let env = envelope(now());
        let signature = sign(&env, &sk);
        // Flip a security-critical switch *after* signing → signature must fail.
        let mut tampered = env.clone();
        tampered.config.prevention_enabled = false;
        tampered.config.auto_response_enabled = true;
        let signed = SignedConfig { envelope: tampered, signature };
        assert!(evaluate_config(Some(&sk.verifying_key()), AGENT_ID, None, &signed, now()).is_err());
    }

    #[test]
    fn rejects_config_addressed_to_another_agent() {
        let sk = signing_key();
        let mut env = envelope(now());
        env.agent_id = "some-other-agent".into();
        let signed = SignedConfig { signature: sign(&env, &sk), envelope: env };
        assert!(evaluate_config(Some(&sk.verifying_key()), AGENT_ID, None, &signed, now()).is_err());
    }

    #[test]
    fn rejects_future_dated_config() {
        let sk = signing_key();
        let env = envelope(now() + chrono::Duration::minutes(30));
        let signed = SignedConfig { signature: sign(&env, &sk), envelope: env };
        assert!(evaluate_config(Some(&sk.verifying_key()), AGENT_ID, None, &signed, now()).is_err());
    }

    #[test]
    fn rejects_rollback_to_older_config() {
        let sk = signing_key();
        let last = now();
        let env = envelope(now() - chrono::Duration::hours(1));
        let signed = SignedConfig { signature: sign(&env, &sk), envelope: env };
        assert!(evaluate_config(Some(&sk.verifying_key()), AGENT_ID, Some(last), &signed, now()).is_err());
    }

    #[test]
    fn accepts_reapplying_same_issued_at() {
        // Idempotent re-pull of the current config (equal issued_at) is allowed.
        let sk = signing_key();
        let env = envelope(now());
        let signed = SignedConfig { signature: sign(&env, &sk), envelope: env };
        assert!(evaluate_config(Some(&sk.verifying_key()), AGENT_ID, Some(now()), &signed, now()).is_ok());
    }
}
