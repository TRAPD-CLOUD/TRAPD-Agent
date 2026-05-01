use anyhow::Result;
use async_trait::async_trait;
use tokio::sync::mpsc::Sender;

use crate::schema::AgentEvent;

#[async_trait]
pub trait Collector: Send + Sync + 'static {
    fn name(&self) -> &'static str;

    async fn run(
        &mut self,
        tx:       Sender<AgentEvent>,
        agent_id: String,
        hostname: String,
    ) -> Result<()>;
}

pub mod linux;
