use std::sync::{Arc, RwLock};

use serde::{Deserialize, Serialize};
use tokio::time::{interval, Duration};
use tracing::{debug, info, warn};
use uuid::Uuid;

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    #[serde(default = "default_poll_interval")]
    pub poll_interval_secs:   u64,
    #[serde(default = "default_enabled_collectors")]
    pub enabled_collectors:   Vec<String>,
    #[serde(default = "default_fs_watch_paths")]
    pub fs_watch_paths:       Vec<String>,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            poll_interval_secs: default_poll_interval(),
            enabled_collectors: default_enabled_collectors(),
            fs_watch_paths:     default_fs_watch_paths(),
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
        agent_id:    Uuid,
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
