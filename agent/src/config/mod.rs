use std::sync::{Arc, RwLock};

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
        }
    }
}

pub struct ConfigPuller {
    config:     Arc<RwLock<AgentConfig>>,
    client:     reqwest::Client,
    config_url: String,
    token:      String,
    etag:       Option<String>,
}

impl ConfigPuller {
    pub fn new(
        config:      Arc<RwLock<AgentConfig>>,
        backend_url: &str,
        agent_id:    &str,
        token:       String,
    ) -> Self {
        let base = crate::http::normalize_base_url(backend_url);
        Self {
            config,
            client:     crate::http::control_client(),
            config_url: format!("{base}/api/v1/agents/{agent_id}/config"),
            token,
            etag:       None,
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
                if let Some(val) = resp.headers().get("etag") {
                    self.etag = val.to_str().ok().map(str::to_string);
                }
                match resp.json::<AgentConfig>().await {
                    Ok(new_cfg) => match self.config.write() {
                        Ok(mut cfg) => {
                            *cfg = new_cfg;
                            info!("Agent config updated from backend");
                        }
                        Err(e) => warn!("Config RwLock poisoned: {e}"),
                    },
                    Err(e) => warn!("Failed to parse config response: {e}"),
                }
            }
            s => warn!("Config pull returned unexpected status {s}"),
        }
    }
}
