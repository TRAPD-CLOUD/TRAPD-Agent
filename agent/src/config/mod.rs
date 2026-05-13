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
fn default_command_poll_interval() -> u64 { 10 }

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
        Self {
            config,
            client:     reqwest::Client::new(),
            config_url: format!("{backend_url}/api/v1/agents/{agent_id}/config"),
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
