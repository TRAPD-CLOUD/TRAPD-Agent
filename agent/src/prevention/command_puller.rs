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

/// Number of consecutive failed polls before the puller emits a tamper-evident
/// audit event that the command channel may be severed.
const POLL_FAILURE_ALERT_THRESHOLD: u32 = 5;

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
        let base = crate::http::normalize_base_url(backend_url);
        Self {
            client:   crate::http::control_client(),
            url:      format!("{base}/api/v1/agents/{agent_id}/commands"),
            token,
            verifier,
            audit,
            out,
            interval: Duration::from_secs(poll_secs.max(2)),
        }
    }

    pub async fn run(self) {
        let mut ticker = interval(self.interval);
        let mut consecutive_failures: u32 = 0;
        loop {
            ticker.tick().await;
            if self.poll_once().await {
                consecutive_failures = 0;
            } else {
                consecutive_failures += 1;
                // Escalate exactly once when crossing the threshold. A sustained
                // command-channel outage — e.g. an attacker severing it to block
                // an isolate_network command during an active incident — must
                // leave a tamper-evident audit record instead of being silently
                // swallowed at debug level.
                if consecutive_failures == POLL_FAILURE_ALERT_THRESHOLD {
                    warn!(
                        failures = consecutive_failures,
                        "command channel unreachable for {consecutive_failures} consecutive polls"
                    );
                    self.audit.emit(
                        crate::schema::EventAction::AgentTamper,
                        crate::schema::Severity::High,
                        "command_channel_unreachable",
                        self.url.clone(),
                        false,
                        format!(
                            "{consecutive_failures} consecutive command-poll failures — \
                             control channel may be severed"
                        ),
                        None,
                        None,
                        serde_json::json!({ "consecutive_failures": consecutive_failures }),
                    );
                }
            }
        }
    }

    /// Perform one poll round-trip. Returns `true` only when the backend was
    /// reached and returned a success status (commands, if any, dispatched);
    /// `false` on any transport error or non-2xx response so the caller can
    /// count consecutive failures.
    async fn poll_once(&self) -> bool {
        let resp = match self.client
            .get(&self.url)
            .bearer_auth(&self.token)
            .send()
            .await
        {
            Ok(r)  => r,
            Err(e) => { warn!("command poll failed: {e}"); return false; }
        };

        if !resp.status().is_success() {
            if resp.status().is_server_error() {
                warn!(status = %resp.status(), "backend command endpoint error");
            }
            return false;
        }

        let commands: Vec<SignedCommand> = match resp.json().await {
            Ok(v)  => v,
            Err(e) => { warn!("malformed command payload: {e}"); return false; }
        };

        for cmd in commands {
            match self.verifier.verify(&cmd) {
                Verdict::Ok(envelope) => {
                    debug!(command_id = %envelope.command_id, "command verified");
                    if self.out.send(envelope).await.is_err() {
                        warn!("engine channel closed — dropping command");
                        return true;
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
        true
    }
}
