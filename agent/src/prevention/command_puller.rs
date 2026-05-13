//! Long-poll loop that fetches signed response commands from the backend.
//!
//! Backend endpoint:
//!   `GET /api/v1/agents/{agent_id}/commands`  →  `[SignedCommand, ...]`
//!
//! Each command is verified by `Verifier`; accepted commands are dispatched
//! through `mpsc::Sender<CommandEnvelope>` to the `engine::Engine` which
//! actually executes them.  Rejected commands emit a `CommandRejected`
//! audit event but never crash the loop.

use std::sync::Arc;

use tokio::sync::mpsc::Sender;
use tokio::time::{interval, Duration};
use tracing::{debug, warn};

use super::audit::AuditEmitter;
use super::commands::{SignedCommand, Verdict, Verifier, CommandEnvelope};

pub struct CommandPuller {
    client:    reqwest::Client,
    url:       String,
    token:     String,
    verifier:  Arc<Verifier>,
    audit:     AuditEmitter,
    out:       Sender<CommandEnvelope>,
    interval:  Duration,
}

impl CommandPuller {
    pub fn new(
        backend_url: &str,
        agent_id:    &str,
        token:       String,
        verifier:    Arc<Verifier>,
        audit:       AuditEmitter,
        out:         Sender<CommandEnvelope>,
        poll_secs:   u64,
    ) -> Self {
        Self {
            client:   reqwest::Client::new(),
            url:      format!("{backend_url}/api/v1/agents/{agent_id}/commands"),
            token,
            verifier,
            audit,
            out,
            interval: Duration::from_secs(poll_secs.max(2)),
        }
    }

    pub async fn run(self) {
        let mut ticker = interval(self.interval);
        loop {
            ticker.tick().await;
            self.poll_once().await;
        }
    }

    async fn poll_once(&self) {
        let resp = match self.client
            .get(&self.url)
            .bearer_auth(&self.token)
            .send()
            .await
        {
            Ok(r)  => r,
            Err(e) => { debug!("command poll failed: {e}"); return; }
        };

        if !resp.status().is_success() {
            if resp.status().is_server_error() {
                warn!(status = %resp.status(), "backend command endpoint error");
            }
            return;
        }

        let commands: Vec<SignedCommand> = match resp.json().await {
            Ok(v)  => v,
            Err(e) => { warn!("malformed command payload: {e}"); return; }
        };

        for cmd in commands {
            match self.verifier.verify(&cmd) {
                Verdict::Ok(envelope) => {
                    debug!(command_id = %envelope.command_id, "command verified");
                    if self.out.send(envelope).await.is_err() {
                        warn!("engine channel closed — dropping command");
                        return;
                    }
                }
                Verdict::Rejected(reason) => {
                    self.audit.emit(
                        crate::schema::EventAction::CommandRejected,
                        crate::schema::Severity::High,
                        "command_rejected",
                        cmd.envelope.command_id.to_string(),
                        false,
                        reason,
                        None,
                        Some(cmd.envelope.command_id.to_string()),
                        serde_json::to_value(&cmd.envelope.payload).unwrap_or(serde_json::Value::Null),
                    );
                }
            }
        }
    }
}
