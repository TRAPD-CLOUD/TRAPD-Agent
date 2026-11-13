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

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use tokio::sync::mpsc::Sender;
use tokio::time::{Duration, Instant};
use tracing::warn;

use super::audit::AuditEmitter;
use super::commands::{CommandEnvelope, SignedCommand, Verdict, Verifier};
use super::journal::{CommandJournal, CommandResult};

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

pub struct CommandPuller {
    client: reqwest::Client,
    url: String,
    token: String,
    verifier: Arc<Verifier>,
    audit: AuditEmitter,
    out: Sender<CommandEnvelope>,
    interval: Duration,
    journal: Arc<CommandJournal>,
    result_offset: AtomicUsize,
}

impl CommandPuller {
    #[allow(clippy::too_many_arguments)] // Explicit runtime trust and storage dependencies.
    pub fn new(
        backend_url: &str,
        agent_id: &str,
        token: String,
        verifier: Arc<Verifier>,
        audit: AuditEmitter,
        out: Sender<CommandEnvelope>,
        poll_secs: u64,
        journal: Arc<CommandJournal>,
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
            journal,
            result_offset: AtomicUsize::new(0),
        })
    }

    pub async fn run(self) {
        let puller = Arc::new(self);
        let reporter = Arc::clone(&puller);
        let mut workers = tokio::task::JoinSet::new();
        workers.spawn(async move {
            loop {
                reporter.flush_results().await;
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        });
        puller.run_polls().await;
        workers.shutdown().await;
    }

    async fn run_polls(&self) {
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
            .header("X-TRAPD-Command-Receipts", "1")
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

        // Bound hostile or misconfigured control-plane responses before decode.
        let mut response = resp;
        let mut body = Vec::new();
        loop {
            match response.chunk().await {
                Ok(Some(chunk)) if body.len().saturating_add(chunk.len()) <= 4 * 1024 * 1024 => {
                    body.extend_from_slice(&chunk)
                }
                Ok(Some(_)) | Err(_) => return PollOutcome::Failed,
                Ok(None) => break,
            }
        }
        let commands: Vec<SignedCommand> = match serde_json::from_slice(&body) {
            Ok(v) => v,
            Err(_) => {
                warn!("malformed command payload");
                return PollOutcome::Failed;
            }
        };
        if commands.len() > 25 {
            return PollOutcome::Failed;
        }
        if commands.is_empty() {
            return PollOutcome::Empty;
        }

        for cmd in commands {
            // Duplicate completed deliveries remain reportable after expiry, but
            // must still have a valid signature and this endpoint identity.
            if let Err(reason) = self.verifier.verify_identity(&cmd) {
                self.reject(&cmd, reason);
                continue;
            }
            match self.journal.contains(&cmd.envelope) {
                Ok(true) => continue,
                Err(error) => {
                    self.reject(&cmd, error.to_string());
                    continue;
                }
                Ok(false) => {}
            }
            // Journal first, then durable nonce, then remote acceptance. A crash
            // in any gap produces an explicit interrupted outcome on restart.
            if let Err(error) = self.journal.accept(&cmd.envelope) {
                self.reject(&cmd, format!("cannot journal command: {error}"));
                continue;
            }
            match self.verifier.verify(&cmd) {
                Verdict::Ok(envelope) => {
                    if !self
                        .receipt(envelope.command_id, &serde_json::json!({"state":"acked"}))
                        .await
                    {
                        let _ = self.journal.complete(
                            envelope.command_id,
                            CommandResult::failure(
                                "delivery acknowledgement failed; no effect executed",
                            ),
                        );
                        continue;
                    }
                    let id = envelope.command_id;
                    if self.out.try_send(envelope).is_err() {
                        let _ = self.journal.complete(
                            id,
                            CommandResult::failure(
                                "execution queue full or closed; no effect executed",
                            ),
                        );
                        continue;
                    }
                }
                Verdict::Rejected(reason) => {
                    let _ = self.journal.complete(
                        cmd.envelope.command_id,
                        CommandResult::failure(reason.clone()),
                    );
                    self.reject(&cmd, reason);
                }
            }
        }
        PollOutcome::Delivered
    }
    fn reject(&self, cmd: &SignedCommand, reason: String) {
        // Never log untrusted script/file bytes or forged response results.
        self.audit.emit(
            crate::schema::EventAction::CommandRejected,
            crate::schema::Severity::High,
            "command_rejected",
            cmd.envelope.command_id.to_string(),
            false,
            reason,
            None,
            None,
            serde_json::Value::Null,
        );
    }
    async fn receipt(&self, id: uuid::Uuid, body: &serde_json::Value) -> bool {
        self.client
            .post(format!("{}/{id}/receipt", self.url))
            .bearer_auth(&self.token)
            .json(body)
            .timeout(Duration::from_secs(5))
            .send()
            .await
            .is_ok_and(|r| r.status().is_success())
    }
    async fn flush_results(&self) {
        let results = match self.journal.pending_results() {
            Ok(results) => results,
            Err(error) => {
                warn!(%error,"cannot read command result outbox");
                return;
            }
        };
        if results.is_empty() {
            return;
        }
        // Bounded concurrent retries keep an unavailable receipt endpoint from
        // delaying new defense commands, and rotate past permanently bad rows.
        let offset = self.result_offset.fetch_add(16, Ordering::Relaxed) % results.len();
        let mut retries = tokio::task::JoinSet::new();
        for (id, result) in results
            .iter()
            .cycle()
            .skip(offset)
            .take(results.len().min(16))
        {
            let id = *id;
            let result = result.clone();
            let client = self.client.clone();
            let url = format!("{}/{id}/receipt", self.url);
            let token = self.token.clone();
            retries.spawn(async move {
                let ok = client
                    .post(url)
                    .bearer_auth(token)
                    .json(&serde_json::json!({"state":"completed","result":result}))
                    .timeout(Duration::from_secs(3))
                    .send()
                    .await
                    .is_ok_and(|r| r.status().is_success());
                (id, ok)
            });
        }
        while let Some(Ok((id, ok))) = retries.join_next().await {
            if ok {
                if let Err(error) = self.journal.mark_reported(id) {
                    warn!(%error,"cannot persist receipt acknowledgement");
                }
            }
        }
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

    #[test]
    fn the_request_timeout_outlasts_the_hold() {
        assert!(LONG_POLL_TIMEOUT > Duration::from_secs(LONG_POLL_WAIT_SECS));
    }
}

#[cfg(test)]
#[path = "command_puller_delivery_tests.rs"]
mod delivery_tests;
