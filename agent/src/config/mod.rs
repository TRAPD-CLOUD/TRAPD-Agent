use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use anyhow::Result;
use chrono::{DateTime, Utc};
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use tokio::time::Duration;
use tracing::{debug, info, warn};

use crate::prevention::{
    command_pubkey_path,
    commands::{load_verifying_key, verify_canonical},
};

pub mod logs;
pub use logs::{LogSourceConfig, MultilineConfig, SourceKind};

fn default_poll_interval() -> u64 {
    60
}
fn default_heartbeat_interval() -> u64 {
    30
}
fn default_config_poll_interval() -> u64 {
    60
}
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
        "logs".into(),
    ]
}

fn default_logs_enabled() -> bool {
    true
}
fn default_logs_include_builtins() -> bool {
    false
}
fn skip_if_true(v: &bool) -> bool {
    *v
}
fn skip_if_false(v: &bool) -> bool {
    !*v
}
fn default_prevention_enabled() -> bool {
    true
}
fn default_fim_enabled() -> bool {
    true
}
fn default_fim_interval() -> u64 {
    900
}
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
fn default_command_poll_interval() -> u64 {
    5
}
fn default_inventory_enabled() -> bool {
    true
}
fn default_honeytoken_detection_enabled() -> bool {
    true
}
fn default_honeytoken_response() -> String {
    "alert".into()
}
fn default_honeytoken_deception_escalation() -> bool {
    false
}
/// Decoy files the *Windows* agent plants and watches. Linux honeytokens are
/// deployed over the signed command channel instead, so Linux ignores this.
/// Kept platform-independent so the canonical signed-config bytes are identical
/// on every OS.
fn default_honeytoken_paths() -> Vec<String> {
    vec![
        "C:\\Users\\Public\\passwords.txt".into(),
        "C:\\Users\\Public\\credentials.xlsx".into(),
        "C:\\ProgramData\\backup_keys.txt".into(),
    ]
}
fn default_auto_response_enabled() -> bool {
    false
}
fn default_auto_response_action() -> String {
    "alert".into()
}
fn default_auto_response_min_severity() -> String {
    "critical".into()
}
fn default_auto_response_min_confidence() -> u8 {
    90
}
fn default_memory_scan_enabled() -> bool {
    true
}
fn default_memory_scan_interval_secs() -> u64 {
    120
}
fn default_rtr_enabled() -> bool {
    false
}
fn default_rtr_max_artifact_bytes() -> u64 {
    32_768
}
fn default_sigma_enabled() -> bool {
    true
}
fn default_anomaly_enabled() -> bool {
    true
}
fn default_vuln_scan_enabled() -> bool {
    true
}
fn default_cis_enabled() -> bool {
    true
}
fn default_siem_format() -> String {
    "cef".into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    #[serde(default = "default_poll_interval")]
    pub poll_interval_secs: u64,
    /// Seconds between heartbeats (`POST /agents/{id}/heartbeat`). Floored at 5.
    #[serde(default = "default_heartbeat_interval")]
    pub heartbeat_interval_secs: u64,
    /// Seconds between config pulls (`GET /agents/{id}/config`). Floored at 10.
    #[serde(default = "default_config_poll_interval")]
    pub config_poll_interval_secs: u64,
    #[serde(default = "default_enabled_collectors")]
    pub enabled_collectors: Vec<String>,
    #[serde(default = "default_fs_watch_paths")]
    pub fs_watch_paths: Vec<String>,

    // ── Prevention (active response) ────────────────────────────────────────────────────────────────────
    /// Master switch for the prevention subsystem.  When `false` the engine
    /// never spawns and the agent behaves as pure telemetry.
    #[serde(default = "default_prevention_enabled")]
    pub prevention_enabled: bool,
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
    /// Decoy file paths the Windows agent plants and monitors (filesystem
    /// honeytokens). Empty entries are ignored; Linux agents ignore the field
    /// entirely (their tokens arrive over the signed command channel).
    #[serde(default = "default_honeytoken_paths")]
    pub honeytoken_paths: Vec<String>,

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

    // ── Sigma detection rules ───────────────────────────────────────────────
    /// Master switch for the local Sigma detection engine. Default on; the
    /// engine is a no-op until rules are provided (disk `<config>/sigma/` or
    /// the inline `sigma_rules` below).
    #[serde(default = "default_sigma_enabled")]
    pub sigma_enabled: bool,
    /// Inline Sigma rule documents (YAML), delivered over the signed config
    /// channel. Merged with the on-disk `<config>/sigma/` baseline and
    /// recompiled whenever a new config is applied — the backend can ship
    /// detections without an agent restart. Bad rules are skipped, not fatal.
    #[serde(default)]
    pub sigma_rules: Vec<String>,

    // ── Behavioural anomaly baseline ────────────────────────────────────────
    /// Master switch for the statistical anomaly baseline (per-process/user
    /// rolling profiles + z-score scoring). Default on; learns silently and
    /// only scores once a baseline has formed.
    #[serde(default = "default_anomaly_enabled")]
    pub anomaly_detection_enabled: bool,

    // ── Vulnerability & compliance ──────────────────────────────────────────
    /// Correlate the installed-package inventory against the local CVE feed
    /// (`<config>/cve_feed.json`) and emit an SBOM (CycloneDX) in the inventory
    /// snapshot. Default on.
    #[serde(default = "default_vuln_scan_enabled")]
    pub vuln_scan_enabled: bool,
    /// Run the built-in CIS-style host-hardening checks in the inventory
    /// snapshot. Default on.
    #[serde(default = "default_cis_enabled")]
    pub cis_benchmark_enabled: bool,

    // ── SIEM forwarding ─────────────────────────────────────────────────────
    /// Master switch for forwarding every event to external SIEM
    /// infrastructure (in parallel with native backend ingest). Default off.
    #[serde(default)]
    pub siem_enabled: bool,
    /// Wire format: `cef` (ArcSight), `leef` (QRadar) or `json`. Default `cef`.
    #[serde(default = "default_siem_format")]
    pub siem_format: String,
    /// Syslog destination: `unix:///dev/log`, `/dev/log` or `udp://host:514`.
    /// Empty disables the syslog sink.
    #[serde(default)]
    pub siem_syslog_address: String,
    /// Splunk HEC collector URL (e.g. `https://splunk:8088/services/collector`).
    /// Empty disables the HEC sink.
    #[serde(default)]
    pub siem_hec_url: String,
    /// Splunk HEC authentication token. Empty disables the HEC sink.
    #[serde(default)]
    pub siem_hec_token: String,

    // ── Vulnerability feed ──────────────────────────────────────────────────
    /// CVE feed entries delivered over the signed config channel, merged with
    /// the on-disk `<config>/cve_feed.json` for the inventory CVE correlation.
    /// Lets the backend (e.g. the `cve-sync` service) drive the feed without
    /// writing to the host filesystem.
    #[serde(default)]
    pub cve_feed: Vec<crate::inventory::compliance::CveEntry>,

    // ── Generic log collector ───────────────────────────────────────────────
    /// Master switch for the file/journal/syslog collector. Default on; with
    /// an empty `logs` list the collector auto-discovers the built-in Linux
    /// security catalogue (sshd, sudo, auditd, nginx, apache, postgres,
    /// mysql, docker) and only arms sources whose paths actually exist.
    #[serde(default = "default_logs_enabled", skip_serializing_if = "skip_if_true")]
    pub logs_enabled: bool,
    /// When `logs` is non-empty, also arm the built-in catalogue. Default
    /// `false`: an explicit list is exclusive. Empty `logs` always discovers
    /// builtins (subject to `logs_enabled`).
    #[serde(
        default = "default_logs_include_builtins",
        skip_serializing_if = "skip_if_false"
    )]
    pub logs_include_builtins: bool,
    /// Explicit log sources. Empty means "use the built-in catalogue".
    /// See [`LogSourceConfig`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub logs: Vec<LogSourceConfig>,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            poll_interval_secs: default_poll_interval(),
            heartbeat_interval_secs: default_heartbeat_interval(),
            config_poll_interval_secs: default_config_poll_interval(),
            enabled_collectors: default_enabled_collectors(),
            fs_watch_paths: default_fs_watch_paths(),
            prevention_enabled: default_prevention_enabled(),
            command_poll_interval_secs: default_command_poll_interval(),
            isolation_allowlist_ips: Vec::new(),
            fim_enabled: default_fim_enabled(),
            fim_paths: default_fim_paths(),
            fim_interval_secs: default_fim_interval(),
            inventory_enabled: default_inventory_enabled(),
            honeytoken_detection_enabled: default_honeytoken_detection_enabled(),
            honeytoken_response: default_honeytoken_response(),
            honeytoken_accessor_allowlist: Vec::new(),
            honeytoken_deception_escalation: default_honeytoken_deception_escalation(),
            honeytoken_paths: default_honeytoken_paths(),
            auto_response_enabled: default_auto_response_enabled(),
            auto_response_action: default_auto_response_action(),
            auto_response_min_severity: default_auto_response_min_severity(),
            auto_response_min_confidence: default_auto_response_min_confidence(),
            auto_response_allowlist: Vec::new(),
            memory_scan_enabled: default_memory_scan_enabled(),
            memory_scan_interval_secs: default_memory_scan_interval_secs(),
            rtr_enabled: default_rtr_enabled(),
            rtr_max_artifact_bytes: default_rtr_max_artifact_bytes(),
            sigma_enabled: default_sigma_enabled(),
            sigma_rules: Vec::new(),
            anomaly_detection_enabled: default_anomaly_enabled(),
            vuln_scan_enabled: default_vuln_scan_enabled(),
            cis_benchmark_enabled: default_cis_enabled(),
            siem_enabled: false,
            siem_format: default_siem_format(),
            siem_syslog_address: String::new(),
            siem_hec_url: String::new(),
            siem_hec_token: String::new(),
            cve_feed: Vec::new(),
            logs_enabled: default_logs_enabled(),
            logs_include_builtins: default_logs_include_builtins(),
            logs: Vec::new(),
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
    key: VerifyingKey,
    agent_id: String,
    watermark: IssuedAtStore,
}

impl ConfigVerifier {
    /// Load the Ed25519 verifying key (raw 32 bytes) and the persisted
    /// `issued_at` high-water mark. Fails only when the key cannot be read or is
    /// malformed — the caller then keeps its last-known-good config rather than
    /// trusting an unauthenticatable channel.
    pub fn new(pubkey_path: &Path, agent_id: String, watermark_path: &Path) -> Result<Self> {
        // Reuse the response-command key loader so both channels trust the exact
        // same raw 32-byte key provisioned at `<config>/command_signing.pub`.
        let key = load_verifying_key(pubkey_path)?;
        let watermark = IssuedAtStore::load(watermark_path);
        info!(path = %pubkey_path.display(), "Signed-config verifier loaded");
        Ok(Self {
            key,
            agent_id,
            watermark,
        })
    }

    /// Verify a signed config end-to-end. Returns the inner `AgentConfig` only
    /// when the signature, recipient and monotonic `issued_at` all check out;
    /// the `Err` string explains the rejection for the caller's log.
    pub fn verify(&mut self, signed: &SignedConfig) -> std::result::Result<AgentConfig, String> {
        // Signature check (canonical-JSON, re-serialised) is shared verbatim with
        // the response-command channel via `verify_canonical`, so an unsigned or
        // tampered config is rejected identically to an unsigned/tampered command.
        verify_canonical(&self.key, &signed.envelope, &signed.signature)?;

        if signed.envelope.agent_id != self.agent_id {
            return Err(format!(
                "config addressed to {}, not us ({})",
                signed.envelope.agent_id, self.agent_id
            ));
        }

        let issued_at = signed.envelope.issued_at;
        // Guard against an absurd future timestamp (clock-skew tolerance: 5 min),
        // mirroring the response-command freshness check.
        if issued_at > Utc::now() + chrono::Duration::minutes(5) {
            return Err(format!("config issued in the future ({issued_at})"));
        }

        // Monotonic issued_at: reject stale / replayed (rollback) envelopes.
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
        Self {
            path: path.to_path_buf(),
            last,
        }
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

/// State file holding the last verified config, so the agent keeps its
/// real configuration across restarts.
fn persisted_config_path() -> PathBuf {
    crate::paths::state_dir().join("agent_config.json")
}

/// Load the last verified config from disk, falling back to defaults. Loading
/// the persisted config (rather than starting from defaults) is what makes the
/// strictly-monotonic `issued_at` rule safe across restarts: the backend
/// re-serves the *current* config with the same `issued_at` the agent already
/// accepted, which the verifier correctly refuses as a replay — but because the
/// agent already holds that config from disk, refusing the re-delivery does not
/// strand it on compiled defaults.
pub fn load_persisted() -> AgentConfig {
    match std::fs::read(persisted_config_path()) {
        Ok(bytes) => match serde_json::from_slice::<AgentConfig>(&bytes) {
            Ok(cfg) => {
                info!("Loaded last-known-good config from disk");
                cfg
            }
            Err(e) => {
                warn!(error = %e, "persisted config is unreadable — using defaults");
                AgentConfig::default()
            }
        },
        Err(_) => AgentConfig::default(),
    }
}

/// Persist the accepted config to disk (`0600`, atomic). Best-effort: a failure
/// here only costs us the last-known-good cache on the next restart.
fn persist_config(cfg: &AgentConfig) {
    match serde_json::to_vec(cfg) {
        Ok(bytes) => {
            if let Err(e) = crate::paths::write_atomic(&persisted_config_path(), &bytes, 0o600) {
                warn!(error = %e, "cannot persist last-known-good config");
            }
        }
        Err(e) => warn!(error = %e, "cannot serialise config for persistence"),
    }
}

/// Callback invoked with the freshly-adopted config after every successful
/// apply. Used to recompile config-delivered artifacts (e.g. Sigma rules) the
/// moment a signed config is verified, without coupling the puller to them.
type ApplyHook = Arc<dyn Fn(&AgentConfig) + Send + Sync>;

pub struct ConfigPuller {
    config: Arc<RwLock<AgentConfig>>,
    client: reqwest::Client,
    config_url: String,
    token: String,
    etag: Option<String>,
    verifier: Option<ConfigVerifier>,
    on_apply: Option<ApplyHook>,
}

impl ConfigPuller {
    pub fn new(
        config: Arc<RwLock<AgentConfig>>,
        backend_url: &str,
        agent_id: &str,
        token: String,
    ) -> Result<Self> {
        let base = crate::http::normalize_base_url(backend_url);
        // Config updates must be signed with the pinned command-signing key. If
        // the key is absent/malformed we keep last-known-good rather than trust
        // an unauthenticatable channel — matching the response-command path.
        let verifier = match ConfigVerifier::new(
            &command_pubkey_path(),
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
        Ok(Self {
            config,
            // Fail-closed TLS-pinned control client (#47, H-B): refuses to build
            // without a provisioned `<config>/ca.crt`.
            client: crate::http::control_client()?,
            config_url: format!("{base}/api/v1/agents/{agent_id}/config"),
            token,
            etag: None,
            verifier,
            on_apply: None,
        })
    }

    /// Register a hook run with the new config after every successful apply.
    pub fn with_apply_hook(mut self, hook: ApplyHook) -> Self {
        self.on_apply = Some(hook);
        self
    }

    pub async fn run(mut self) {
        // First pull immediately on startup, then on the configured cadence.
        // The interval is re-read each round so a backend-delivered change to
        // `config_poll_interval_secs` takes effect without a restart. Floored
        // at 10s so a bad config cannot hammer the backend.
        loop {
            self.pull().await;
            let secs = self
                .config
                .read()
                .map(|c| c.config_poll_interval_secs)
                .unwrap_or_else(|_| default_config_poll_interval())
                .max(10);
            tokio::time::sleep(Duration::from_secs(secs)).await;
        }
    }

    async fn pull(&mut self) {
        let mut req = self.client.get(&self.config_url).bearer_auth(&self.token);

        if let Some(etag) = &self.etag {
            req = req.header("If-None-Match", etag.as_str());
        }

        let resp = match req.send().await {
            Ok(r) => r,
            Err(e) => {
                warn!("Config pull failed: {e}");
                return;
            }
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
                    Ok(b) => b,
                    Err(e) => {
                        warn!("Failed to read config response body: {e}");
                        return;
                    }
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
            Ok(s) => s,
            Err(e) => {
                warn!("Failed to parse signed config response: {e}");
                return false;
            }
        };
        match verifier.verify(&signed) {
            Ok(new_cfg) => match self.config.write() {
                Ok(mut cfg) => {
                    *cfg = new_cfg.clone();
                    drop(cfg);
                    persist_config(&new_cfg);
                    if let Some(hook) = &self.on_apply {
                        hook(&new_cfg);
                    }
                    info!("Agent config updated from backend (signature + issued_at verified)");
                    true
                }
                Err(e) => {
                    warn!("Config RwLock poisoned: {e}");
                    false
                }
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
    use base64::Engine as _;
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
        let signature =
            base64::engine::general_purpose::STANDARD.encode(key.sign(&canonical).to_bytes());
        SignedConfig {
            envelope,
            signature,
        }
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
        assert!(
            v.verify(&signed).is_err(),
            "config signed by wrong key accepted"
        );
        cleanup(p, w);
    }

    #[test]
    fn rejects_wrong_recipient() {
        let key = signing_key();
        let (mut v, p, w) = verifier(&key, "agent-1");
        let signed = make_signed(&key, "another-agent", Utc::now());
        assert!(
            v.verify(&signed).is_err(),
            "config for another agent accepted"
        );
        cleanup(p, w);
    }

    #[test]
    fn rejects_future_issued_at() {
        let key = signing_key();
        let (mut v, p, w) = verifier(&key, "agent-1");
        // Beyond the 5-minute clock-skew tolerance → rejected.
        let signed = make_signed(&key, "agent-1", Utc::now() + chrono::Duration::minutes(10));
        assert!(
            v.verify(&signed).is_err(),
            "config issued far in the future accepted"
        );
        cleanup(p, w);
    }

    #[test]
    fn enforces_monotonic_issued_at() {
        let key = signing_key();
        let (mut v, p, w) = verifier(&key, "agent-1");
        let t1 = Utc::now();
        assert!(v.verify(&make_signed(&key, "agent-1", t1)).is_ok());
        // Older issue time -> rollback, rejected.
        assert!(v
            .verify(&make_signed(
                &key,
                "agent-1",
                t1 - chrono::Duration::seconds(60)
            ))
            .is_err());
        // Same issue time -> replay, rejected.
        assert!(v.verify(&make_signed(&key, "agent-1", t1)).is_err());
        // Strictly newer -> accepted.
        assert!(v
            .verify(&make_signed(
                &key,
                "agent-1",
                t1 + chrono::Duration::seconds(1)
            ))
            .is_ok());
        cleanup(p, w);
    }

    // ── Cross-language vector ────────────────────────────────────────────────
    // Proves the TypeScript signer in the backend
    // (`services/web/lib/api/config/sign.ts`) produces a `SignedConfig` this
    // verifier accepts — i.e. both ends agree on the canonical byte sequence for
    // the *full* default `AgentConfig`. Generated by signing the canonical
    // envelope with the fixed Ed25519 seed (bytes 0x01..=0x20), the same seed the
    // command cross-lang vectors use (hence the identical PUB_HEX). A mismatch
    // here means the backend's `canonicalConfig` field order/contents drifted
    // from the Rust `AgentConfig` re-serialisation — the exact bug to catch.
    const XLANG_PUB_HEX: &str = "79b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664";
    const XLANG_ENV: &str = r#"{"issued_at":"2020-01-01T00:00:00Z","agent_id":"agent-test","config":{"poll_interval_secs":60,"heartbeat_interval_secs":30,"config_poll_interval_secs":60,"enabled_collectors":["process","network","system","authlog","filesystem"],"fs_watch_paths":["/etc","/bin","/tmp"],"prevention_enabled":true,"command_poll_interval_secs":10,"isolation_allowlist_ips":[],"fim_enabled":true,"fim_paths":["/etc","/usr/bin","/usr/sbin","/bin","/sbin","/boot"],"fim_interval_secs":900,"inventory_enabled":true,"honeytoken_detection_enabled":true,"honeytoken_response":"alert","honeytoken_accessor_allowlist":[],"honeytoken_deception_escalation":false,"honeytoken_paths":["C:\\Users\\Public\\passwords.txt","C:\\Users\\Public\\credentials.xlsx","C:\\ProgramData\\backup_keys.txt"],"auto_response_enabled":false,"auto_response_action":"alert","auto_response_min_severity":"critical","auto_response_min_confidence":90,"auto_response_allowlist":[],"memory_scan_enabled":true,"memory_scan_interval_secs":120,"rtr_enabled":false,"rtr_max_artifact_bytes":32768,"sigma_enabled":true,"sigma_rules":[],"anomaly_detection_enabled":true,"vuln_scan_enabled":true,"cis_benchmark_enabled":true,"siem_enabled":false,"siem_format":"cef","siem_syslog_address":"","siem_hec_url":"","siem_hec_token":"","cve_feed":[]}}"#;
    const XLANG_SIG: &str =
        "vNQjV2iY9neNY/0Pf5HY8MetMPA8R2ZELyURSAqkdmv6izcCAAl1wXUNAOQfGUsztNdCpc2AXmasCde5R9Q4AQ==";

    #[test]
    fn accepts_ts_signed_default_config() {
        let pub_path = tmp("xlang_pub");
        let wm_path = tmp("xlang_issued.json");
        std::fs::write(&pub_path, hex::decode(XLANG_PUB_HEX).unwrap()).unwrap();
        let mut v = ConfigVerifier::new(&pub_path, "agent-test".into(), &wm_path).unwrap();
        let signed: SignedConfig = serde_json::from_str(&format!(
            r#"{{"envelope":{XLANG_ENV},"signature":"{XLANG_SIG}"}}"#
        ))
        .unwrap();
        match v.verify(&signed) {
            Ok(cfg) => {
                // Spot-check a few fields, incl. ones not stored in the DB and
                // only present via Rust defaults (rtr_*, memory_scan_*).
                assert_eq!(cfg.poll_interval_secs, 60);
                assert_eq!(cfg.honeytoken_response, "alert");
                assert_eq!(cfg.rtr_max_artifact_bytes, 32_768);
                assert_eq!(cfg.memory_scan_interval_secs, 120);
            }
            Err(why) => panic!("TS-signed default config rejected: {why}"),
        }
        cleanup(pub_path, wm_path);
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
        assert!(
            v2.verify(&make_signed(&key, "agent-1", t1)).is_err(),
            "watermark not persisted"
        );
        assert!(v2
            .verify(&make_signed(
                &key,
                "agent-1",
                t1 + chrono::Duration::seconds(1)
            ))
            .is_ok());
        cleanup(pub_path, wm_path);
    }
}
