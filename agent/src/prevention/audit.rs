//! Tiny helper that funnels prevention actions back through the normal
//! telemetry pipeline so the backend gets a tamper-evident record of every
//! enforcement decision.

use super::journal::{CommandJournal, CommandResult};
use serde_json::Value;
use std::sync::Arc;
use tokio::sync::mpsc::Sender;
use tracing::warn;

use crate::schema::{
    AgentEvent, EventAction, EventClass, EventData, PreventionEventData, Severity,
};

#[derive(Clone)]
pub struct AuditEmitter {
    tx: Sender<AgentEvent>,
    agent_id: String,
    hostname: String,
    journal: Option<Arc<CommandJournal>>,
}

impl AuditEmitter {
    pub fn new(tx: Sender<AgentEvent>, agent_id: String, hostname: String) -> Self {
        Self {
            tx,
            agent_id,
            hostname,
            journal: None,
        }
    }

    pub fn with_journal(mut self, journal: Arc<CommandJournal>) -> Self {
        self.journal = Some(journal);
        self
    }

    /// Emit one prevention event.  Best-effort — if the pipeline is full or
    /// shut down the event is dropped and a warning is logged so we never
    /// stall the response path on telemetry backpressure.
    #[allow(clippy::too_many_arguments)]
    pub fn emit(
        &self,
        action: EventAction,
        severity: Severity,
        kind: &str,
        target: impl Into<String>,
        success: bool,
        reason: impl Into<String>,
        rule_id: Option<String>,
        command_id: Option<String>,
        details: Value,
    ) {
        let event = AgentEvent::new(
            self.agent_id.clone(),
            self.hostname.clone(),
            EventClass::Prevention,
            action,
            severity,
            EventData::Prevention(PreventionEventData {
                kind: kind.into(),
                target: target.into(),
                success,
                reason: reason.into(),
                rule_id,
                command_id,
                details,
            }),
        );

        // Response results must be durable before best-effort telemetry. The
        // puller retries the receipt independently of telemetry backpressure.
        if let (Some(journal), EventData::Prevention(data)) = (&self.journal, &event.data) {
            if let Some(id) = data.command_id.as_deref().and_then(|id| id.parse().ok()) {
                let result = CommandResult {
                    action: serde_json::to_value(&event.action)
                        .ok()
                        .and_then(|v| v.as_str().map(str::to_owned))
                        .unwrap_or_else(|| "command_rejected".into()),
                    kind: data.kind.clone(),
                    success: data.success,
                    reason: Some(data.reason.clone()),
                    details: data.details.clone(),
                    reported_at: event.timestamp,
                };
                if let Err(error) = journal.complete(id, result) {
                    warn!(%error, "cannot persist command result; execution remains uncertain in journal");
                }
            }
        }
        if let Err(e) = self.tx.try_send(event) {
            warn!(kind, error = %e, "prevention audit event dropped");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prevention::commands::{CommandEnvelope, CommandPayload};
    #[tokio::test]
    async fn command_result_remains_durable_when_telemetry_channel_is_full() {
        let dir = std::env::temp_dir().join(format!("trapd-audit-test-{}", uuid::Uuid::new_v4()));
        let journal = Arc::new(CommandJournal::open(&dir).unwrap());
        let env = CommandEnvelope {
            command_id: uuid::Uuid::new_v4(),
            nonce: uuid::Uuid::new_v4(),
            issued_at: chrono::Utc::now(),
            expires_at: chrono::Utc::now() + chrono::Duration::minutes(1),
            agent_id: "test".into(),
            payload: CommandPayload::DeisolateNetwork,
        };
        journal.accept(&env).unwrap();
        journal.start(env.command_id).unwrap();
        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        let audit =
            AuditEmitter::new(tx, "test".into(), "host".into()).with_journal(Arc::clone(&journal));
        audit.emit(
            EventAction::CommandAccepted,
            Severity::Info,
            "other",
            "test",
            true,
            "fill",
            None,
            None,
            Value::Null,
        );
        audit.emit(
            EventAction::NetworkDeisolated,
            Severity::Info,
            "network_deisolate",
            "host",
            true,
            "done",
            None,
            Some(env.command_id.to_string()),
            Value::Null,
        );
        let pending = journal.pending_results().unwrap();
        assert_eq!(pending.len(), 1);
        assert!(pending[0].1.success);
        assert_eq!(pending[0].1.kind, "network_deisolate");
        assert!(rx.try_recv().is_ok());
        assert!(rx.try_recv().is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
