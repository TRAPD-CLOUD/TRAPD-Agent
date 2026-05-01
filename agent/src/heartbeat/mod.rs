use chrono::Utc;
use serde::Serialize;
use tokio::time::{interval, Duration};
use tracing::{debug, warn};

#[derive(Serialize)]
struct HeartbeatPayload {
    agent_id:  String,
    hostname:  String,
    timestamp: chrono::DateTime<Utc>,
}

pub struct Heartbeat {
    client:        reqwest::Client,
    heartbeat_url: String,
    token:         String,
    agent_id:      String,
    hostname:      String,
}

impl Heartbeat {
    pub fn new(
        backend_url: &str,
        agent_id:    String,
        token:       String,
        hostname:    String,
    ) -> Self {
        Self {
            client:        reqwest::Client::new(),
            heartbeat_url: format!("{backend_url}/api/v1/agents/{agent_id}/heartbeat"),
            token,
            agent_id,
            hostname,
        }
    }

    pub async fn run(self) {
        let mut ticker = interval(Duration::from_secs(30));
        loop {
            ticker.tick().await;
            self.send().await;
        }
    }

    async fn send(&self) {
        let payload = HeartbeatPayload {
            agent_id:  self.agent_id.clone(),
            hostname:  self.hostname.clone(),
            timestamp: Utc::now(),
        };
        match self
            .client
            .post(&self.heartbeat_url)
            .bearer_auth(&self.token)
            .json(&payload)
            .send()
            .await
        {
            Ok(resp) if resp.status().is_success() => {
                debug!("Heartbeat sent successfully");
            }
            Ok(resp) => {
                warn!("Heartbeat rejected by backend: HTTP {}", resp.status());
            }
            Err(e) => {
                warn!("Heartbeat request failed: {e}");
            }
        }
    }
}
