//! Long-poll loop that fetches signed response commands from the backend.
//!
//! Backend endpoint:
//!   `GET /api/v1/agents/{agent_id}/commands?wait=25`  →  `[SignedCommand, ...]`
//!
//! `wait` asks the backend to hold the request until a command is queued (or
//! 25 s pass), so a response command arrives in about one round trip. A backend
//! that predates it ignores the parameter and answers at once; the loop then
//! paces itself to the configured poll interval like before, so it can never
//! turn into a tight request loop. See [`next_pause`].
//!
//! Each command is verified by `Verifier`; accepted commands are dispatched
//! through `mpsc::Sender<CommandEnvelope>` to the `engine::Engine` which
//! actually executes them.  Rejected commands emit a `CommandRejected`
//! audit event but never crash the loop.
//!
//! A batch is decoded one command at a time. A command this agent cannot
//! decode, such as a kind added by a newer backend, is rejected on its own and
//! never holds back an isolation or release queued next to it.

use std::sync::Arc;

use tokio::sync::mpsc::Sender;
use tokio::time::{Duration, Instant};
use tracing::{debug, warn};

use super::audit::AuditEmitter;
use super::commands::{CommandEnvelope, SignedCommand, Verdict, Verifier};

/// Number of consecutive failed polls before the puller emits a tamper-evident
/// audit event that the command channel may be severed.
const POLL_FAILURE_ALERT_THRESHOLD: u32 = 5;

/// How long the backend is asked to hold an empty poll open.
const LONG_POLL_WAIT_SECS: u64 = 25;
/// Request timeout for a held poll: the hold plus slack for the round trip. The
/// shared control client's 30 s would sit too close to the 25 s hold.
const LONG_POLL_TIMEOUT: Duration = Duration::from_secs(LONG_POLL_WAIT_SECS + 15);

/// What one poll round-trip achieved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PollOutcome {
    /// Transport error, non-2xx or malformed body.
    Failed,
    /// Reached the backend, nothing to run.
    Empty,
    /// At least one command was received (and dispatched or audited).
    Delivered,
}

/// How long to pause before the next poll.
///
/// A poll that took at least one interval was a genuine long-poll hold, so the
/// next one starts at once. One that returned sooner with nothing to do came
/// from a backend that does not hold requests; waiting out the rest of the
/// interval keeps that case at the old polling rate. After a delivery the loop
/// re-polls immediately: more commands may already be queued.
fn next_pause(outcome: PollOutcome, took: Duration, interval: Duration) -> Duration {
    match outcome {
        PollOutcome::Delivered => Duration::ZERO,
        PollOutcome::Empty => interval.saturating_sub(took),
        // Never retry a failing backend sooner than the normal interval.
        PollOutcome::Failed => interval,
    }
}

/// One element of a polled batch.
#[derive(Debug)]
enum Decoded {
    Command(Box<SignedCommand>),
    /// Not a command this agent understands. `command_id` is set when the
    /// element still carries a well-formed one.
    Undecodable {
        command_id: Option<String>,
        reason: String,
    },
}

/// Decode a polled batch element by element. Only a body that is not a JSON
/// array fails as a whole.
fn decode_batch(body: &[u8]) -> Result<Vec<Decoded>, serde_json::Error> {
    let items: Vec<serde_json::Value> = serde_json::from_slice(body)?;
    Ok(items
        .into_iter()
        .map(|item| {
            let command_id = item
                .pointer("/envelope/command_id")
                .and_then(serde_json::Value::as_str)
                .and_then(|id| uuid::Uuid::parse_str(id).ok())
                .map(|id| id.to_string());
            match serde_json::from_value::<SignedCommand>(item) {
                Ok(command) => Decoded::Command(Box::new(command)),
                Err(error) => Decoded::Undecodable {
                    command_id,
                    reason: error.to_string(),
                },
            }
        })
        .collect())
}

pub struct CommandPuller {
    client: reqwest::Client,
    url: String,
    token: String,
    verifier: Arc<Verifier>,
    audit: AuditEmitter,
    out: Sender<CommandEnvelope>,
    interval: Duration,
}

impl CommandPuller {
    pub fn new(
        backend_url: &str,
        agent_id: &str,
        token: String,
        verifier: Arc<Verifier>,
        audit: AuditEmitter,
        out: Sender<CommandEnvelope>,
        poll_secs: u64,
    ) -> anyhow::Result<Self> {
        let base = crate::http::normalize_base_url(backend_url);
        Ok(Self {
            client: crate::http::control_client()?,
            url: format!("{base}/api/v1/agents/{agent_id}/commands"),
            token,
            verifier,
            audit,
            out,
            interval: Duration::from_secs(poll_secs.max(2)),
        })
    }

    pub async fn run(self) {
        let mut consecutive_failures: u32 = 0;
        loop {
            let started = Instant::now();
            let outcome = self.poll_once().await;
            if outcome != PollOutcome::Failed {
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
            let pause = next_pause(outcome, started.elapsed(), self.interval);
            if !pause.is_zero() {
                tokio::time::sleep(pause).await;
            }
        }
    }

    /// Perform one poll round-trip. `Failed` on any transport error, non-2xx or
    /// malformed response so the caller can count consecutive failures;
    /// otherwise `Empty` or `Delivered` (commands dispatched or audited).
    async fn poll_once(&self) -> PollOutcome {
        let resp = match self
            .client
            .get(&self.url)
            .query(&[("wait", LONG_POLL_WAIT_SECS)])
            .timeout(LONG_POLL_TIMEOUT)
            .bearer_auth(&self.token)
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                warn!("command poll failed: {e}");
                return PollOutcome::Failed;
            }
        };

        if !resp.status().is_success() {
            if resp.status().is_server_error() {
                warn!(status = %resp.status(), "backend command endpoint error");
            }
            return PollOutcome::Failed;
        }

        let body = match resp.bytes().await {
            Ok(body) => body,
            Err(e) => {
                warn!("command poll body failed: {e}");
                return PollOutcome::Failed;
            }
        };
        let commands = match decode_batch(&body) {
            Ok(v) => v,
            Err(e) => {
                warn!("malformed command payload: {e}");
                return PollOutcome::Failed;
            }
        };
        if commands.is_empty() {
            return PollOutcome::Empty;
        }

        for decoded in commands {
            let cmd = match decoded {
                Decoded::Command(cmd) => *cmd,
                Decoded::Undecodable { command_id, reason } => {
                    warn!(command_id = ?command_id, "undecodable command skipped: {reason}");
                    self.audit.emit(
                        crate::schema::EventAction::CommandRejected,
                        crate::schema::Severity::Medium,
                        "command_rejected",
                        command_id.clone().unwrap_or_else(|| "<unknown>".into()),
                        false,
                        format!("command could not be decoded by this agent version: {reason}"),
                        None,
                        command_id,
                        serde_json::Value::Null,
                    );
                    continue;
                }
            };
            match self.verifier.verify(&cmd) {
                Verdict::Ok(envelope) => {
                    debug!(command_id = %envelope.command_id, "command verified");
                    if self.out.send(envelope).await.is_err() {
                        warn!("engine channel closed — dropping command");
                        return PollOutcome::Delivered;
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
                        serde_json::to_value(&cmd.envelope.payload)
                            .unwrap_or(serde_json::Value::Null),
                    );
                }
            }
        }
        PollOutcome::Delivered
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const INTERVAL: Duration = Duration::from_secs(10);

    #[test]
    fn a_held_poll_is_followed_by_the_next_one_at_once() {
        let held = Duration::from_secs(25);
        assert_eq!(
            next_pause(PollOutcome::Empty, held, INTERVAL),
            Duration::ZERO
        );
    }

    #[test]
    fn an_instant_empty_answer_falls_back_to_the_poll_interval() {
        // A backend that ignores `wait` must not be hit in a tight loop.
        let pause = next_pause(PollOutcome::Empty, Duration::from_millis(40), INTERVAL);
        assert_eq!(pause, INTERVAL - Duration::from_millis(40));
        let zero = next_pause(PollOutcome::Empty, Duration::ZERO, INTERVAL);
        assert_eq!(zero, INTERVAL);
    }

    #[test]
    fn delivered_commands_trigger_an_immediate_re_poll() {
        assert_eq!(
            next_pause(PollOutcome::Delivered, Duration::from_millis(5), INTERVAL),
            Duration::ZERO
        );
    }

    #[test]
    fn failures_are_never_retried_faster_than_the_interval() {
        assert_eq!(
            next_pause(PollOutcome::Failed, Duration::from_millis(5), INTERVAL),
            INTERVAL
        );
        assert_eq!(
            next_pause(PollOutcome::Failed, Duration::from_secs(40), INTERVAL),
            INTERVAL
        );
    }

    fn command(kind: &str, id: &str) -> serde_json::Value {
        serde_json::json!({
            "envelope": {
                "command_id": id,
                "issued_at": "2026-11-10T08:00:00Z",
                "expires_at": "2026-11-10T08:05:00Z",
                "agent_id": "agent_1",
                "nonce": "7f0c3a1e-5a47-4e0e-9a7e-0d2f6c1b8a11",
                "payload": { "kind": kind },
            },
            "signature": "AA==",
        })
    }

    const RELEASE_ID: &str = "0b6f2f0a-3c1d-4b7e-8f55-2a9d6e4c1b70";
    const UNKNOWN_ID: &str = "c2a9d3b4-6e1f-4a58-9b0c-7d1e2f3a4b5c";

    #[test]
    fn an_unknown_command_does_not_hold_back_its_neighbours() {
        let body = serde_json::to_vec(&serde_json::json!([
            command("kind_from_a_newer_backend", UNKNOWN_ID),
            command("deisolate_network", RELEASE_ID),
        ]))
        .unwrap();
        let decoded = decode_batch(&body).unwrap();
        assert_eq!(decoded.len(), 2);
        match &decoded[0] {
            Decoded::Undecodable { command_id, .. } => {
                assert_eq!(command_id.as_deref(), Some(UNKNOWN_ID));
            }
            other => panic!("expected an undecodable command, got {other:?}"),
        }
        match &decoded[1] {
            Decoded::Command(cmd) => {
                assert_eq!(cmd.envelope.command_id.to_string(), RELEASE_ID);
            }
            other => panic!("expected the release command, got {other:?}"),
        }
    }

    #[test]
    fn a_malformed_element_is_reported_without_an_invented_id() {
        let body = br#"[{"envelope": {"command_id": "<script>"}}, 7, null]"#;
        let decoded = decode_batch(body).unwrap();
        assert_eq!(decoded.len(), 3);
        for item in decoded {
            match item {
                Decoded::Undecodable { command_id, .. } => assert_eq!(command_id, None),
                other => panic!("expected an undecodable command, got {other:?}"),
            }
        }
    }

    #[test]
    fn a_body_that_is_not_a_list_fails_as_a_whole() {
        assert!(decode_batch(br#"{"error":"nope"}"#).is_err());
        assert!(decode_batch(b"<html>").is_err());
        assert!(decode_batch(b"[]").unwrap().is_empty());
    }

    #[test]
    fn the_request_timeout_outlasts_the_hold() {
        assert!(LONG_POLL_TIMEOUT > Duration::from_secs(LONG_POLL_WAIT_SECS));
    }
}
