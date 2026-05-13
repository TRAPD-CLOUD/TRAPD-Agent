//! Tiny helper that funnels prevention actions back through the normal
//! telemetry pipeline so the backend gets a tamper-evident record of every
//! enforcement decision.

use serde_json::Value;
use tokio::sync::mpsc::Sender;
use tracing::warn;

use crate::schema::{
    AgentEvent, EventAction, EventClass, EventData, PreventionEventData, Severity,
};

#[derive(Clone)]
pub struct AuditEmitter {
    tx:       Sender<AgentEvent>,
    agent_id: String,
    hostname: String,
}

impl AuditEmitter {
    pub fn new(tx: Sender<AgentEvent>, agent_id: String, hostname: String) -> Self {
        Self { tx, agent_id, hostname }
    }

    /// Emit one prevention event.  Best-effort — if the pipeline is full or
    /// shut down the event is dropped and a warning is logged so we never
    /// stall the response path on telemetry backpressure.
    #[allow(clippy::too_many_arguments)]
    pub fn emit(
        &self,
        action:    EventAction,
        severity:  Severity,
        kind:      &str,
        target:    impl Into<String>,
        success:   bool,
        reason:    impl Into<String>,
        rule_id:   Option<String>,
        command_id: Option<String>,
        details:   Value,
    ) {
        let event = AgentEvent::new(
            self.agent_id.clone(),
            self.hostname.clone(),
            EventClass::Prevention,
            action,
            severity,
            EventData::Prevention(PreventionEventData {
                kind:    kind.into(),
                target:  target.into(),
                success,
                reason:  reason.into(),
                rule_id,
                command_id,
                details,
            }),
        );

        if let Err(e) = self.tx.try_send(event) {
            warn!(kind, error = %e, "prevention audit event dropped");
        }
    }
}
