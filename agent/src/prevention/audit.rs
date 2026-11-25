//! Tiny helper that funnels prevention actions back through the normal
//! telemetry pipeline so the backend gets a tamper-evident record of every
//! enforcement decision.

use serde_json::Value;
use tokio::sync::mpsc::{OwnedPermit, Sender};

tokio::task_local! {
    /// A signed command holds a queue slot from dispatch until its result.
    /// Background events and TTL callbacks run in separate tasks.
    static RESULT_SLOT: std::cell::RefCell<Option<OwnedPermit<AgentEvent>>>;
    /// The durable outbox entry the command's first result also goes to.
    static RESULT_RECORD: Option<(std::sync::Arc<super::result_outbox::ResultOutbox>, uuid::Uuid)>;
}
use tracing::warn;

use crate::schema::{
    AgentEvent, EventAction, EventClass, EventData, PreventionEventData, Severity,
};

#[derive(Clone)]
pub struct AuditEmitter {
    tx: Sender<AgentEvent>,
    agent_id: String,
    hostname: String,
    #[cfg(windows)]
    user_notifications: Option<std::sync::Arc<std::sync::RwLock<crate::config::AgentConfig>>>,
}

impl AuditEmitter {
    pub fn new(tx: Sender<AgentEvent>, agent_id: String, hostname: String) -> Self {
        Self {
            tx,
            agent_id,
            hostname,
            #[cfg(windows)]
            user_notifications: None,
        }
    }

    pub(super) async fn reserve_result(&self) -> Option<OwnedPermit<AgentEvent>> {
        self.tx.clone().reserve_owned().await.ok()
    }

    pub(super) async fn with_result_slot(
        permit: OwnedPermit<AgentEvent>,
        record: Option<(
            std::sync::Arc<super::result_outbox::ResultOutbox>,
            uuid::Uuid,
        )>,
        action: impl std::future::Future<Output = ()>,
    ) {
        RESULT_SLOT
            .scope(
                std::cell::RefCell::new(Some(permit)),
                RESULT_RECORD.scope(record, action),
            )
            .await;
    }

    /// Follow the signed config's user-notification setting. Without this call
    /// the emitter never notifies.
    #[cfg(windows)]
    pub fn with_user_notifications(
        mut self,
        config: std::sync::Arc<std::sync::RwLock<crate::config::AgentConfig>>,
    ) -> Self {
        self.user_notifications = Some(config);
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
        #[cfg(windows)]
        if self.user_notifications.as_ref().is_some_and(|config| {
            config
                .read()
                .map(|c| c.user_response_notifications_enabled)
                .unwrap_or(false)
        }) {
            super::usernotify::notify(&action, kind, success, &details);
        }
        let reason = reason.into();
        if let Some(id) = command_id.as_deref() {
            let _ = RESULT_RECORD.try_with(|record| {
                if let Some((outbox, expected)) = record {
                    if expected.to_string() == id {
                        outbox.finish(*expected, success, &reason, &details);
                    }
                }
            });
        }
        let slot = command_id.as_ref().and_then(|_| {
            RESULT_SLOT
                .try_with(|slot| slot.borrow_mut().take())
                .ok()
                .flatten()
        });
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
                reason,
                rule_id,
                command_id,
                details,
            }),
        );

        if let Some(slot) = slot {
            slot.send(event);
        } else if let Err(e) = self.tx.try_send(event) {
            warn!(kind, error = %e, "prevention audit event dropped");
        }
    }
}
