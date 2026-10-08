//! Own one ETW attempt and the pollers that cover its unavailable providers.
use crate::{collectors::Collector, config::AgentConfig, schema::AgentEvent};
use anyhow::Result;
use async_trait::async_trait;
use std::sync::{Arc, RwLock};
use tokio::sync::mpsc::Sender;

pub struct SensorSupervisor {
    config: Arc<RwLock<AgentConfig>>,
}
impl SensorSupervisor {
    pub fn new(config: Arc<RwLock<AgentConfig>>) -> Self {
        Self { config }
    }
}

#[async_trait]
impl Collector for SensorSupervisor {
    fn name(&self) -> &'static str {
        "WindowsSensorSupervisor"
    }
    async fn run(
        &mut self,
        tx: Sender<AgentEvent>,
        agent_id: String,
        hostname: String,
    ) -> Result<()> {
        let mut pollers = tokio::task::JoinSet::new();
        let ptx = tx.clone();
        let aid = agent_id.clone();
        let host = hostname.clone();
        pollers.spawn(async move {
            super::process::ProcessCollector::new()
                .run(ptx, aid, host)
                .await
        });
        let ntx = tx.clone();
        let aid = agent_id.clone();
        let host = hostname.clone();
        pollers.spawn(async move { super::network::NetworkCollector.run(ntx, aid, host).await });
        loop {
            let enabled = self.config.read().map(|c| c.etw_enabled).unwrap_or(false);
            if enabled {
                let mut etw = super::etw::EtwCollector;
                let attempt = etw.run(tx.clone(), agent_id.clone(), hostname.clone());
                tokio::pin!(attempt);
                loop {
                    tokio::select! {
                        result = &mut attempt => {
                            if let Err(error) = result { tracing::warn!(%error, "ETW unavailable; polling remains active"); }
                            break;
                        }
                        _ = tx.closed() => return Ok(()),
                        result = pollers.join_next() => return Err(anyhow::anyhow!("sensor fallback exited: {result:?}")),
                        _ = tokio::time::sleep(std::time::Duration::from_secs(1)) => {
                            if !self.config.read().map(|c| c.etw_enabled).unwrap_or(false) { break; }
                        }
                    }
                }
            }
            crate::telemetry::coverage::update(|c| {
                c.etw_session = Some(false);
                c.process_sensor = Some("polling".into());
            });
            tokio::select! {
                _ = tx.closed() => return Ok(()),
                result = pollers.join_next() => return Err(anyhow::anyhow!("sensor fallback exited: {result:?}")),
                _ = tokio::time::sleep(std::time::Duration::from_secs(5)) => {}
            }
        }
    }
}
