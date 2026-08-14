//! Authenticated event transport.
//!
//! Ships batches from the persistent queue to the backend ingest endpoint and
//! reconciles the result. The TLS posture (rustls, fail-closed CA pinning,
//! optional mTLS) and timeouts come from [`crate::http`], so transport,
//! enrollment, heartbeat and config-pull all behave identically.
//!
//! ## Reconciliation
//!
//! A batch has three possible outcomes, and each maps to a different queue
//! action — collapsing them would either lose events or replay them forever:
//!
//! | Backend response | Meaning | Queue action |
//! |---|---|---|
//! | 2xx | durable server-side | `ack` — remove |
//! | 5xx / timeout / connection error | transient | `nack` — retry with backoff |
//! | 4xx (except 408/425/429) | the backend will never accept it | `ack` + count as `backend_rejected` |
//!
//! The 4xx case is the subtle one. Retrying a permanently-rejected batch forever
//! would block every event behind it, so the events are removed — but they are
//! removed *loudly*, counted under [`DropReason::BackendRejected`], because that
//! is real telemetry loss and has to be visible rather than looking like
//! successful delivery.
//!
//! ## Partial acknowledgement
//!
//! When the backend reports per-event results, only the accepted `event_id`s are
//! acknowledged and the rest stay queued for redelivery. A backend that returns a
//! bare 2xx is treated as having accepted the whole batch, which is the existing
//! contract.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use serde::Deserialize;
use tokio::time::{Duration, Instant};
use tracing::{debug, warn};

use crate::pipeline::{backoff, Spool};
use crate::telemetry::limits::MAX_BATCH_EVENTS;
use crate::telemetry::{metrics::metrics, DropReason};

/// Low latency when the queue is small; successful backlog batches are drained
/// immediately (with a small governor delay) instead of waiting another tick.
const NORMAL_FLUSH_INTERVAL: Duration = Duration::from_secs(1);
const CATCH_UP_THRESHOLD: usize = 200;
const CATCH_UP_PACING: Duration = Duration::from_millis(25);

/// Optional per-event result envelope.
///
/// A backend that partially accepts a batch reports which events it took; one
/// that does not simply returns 2xx with an empty or unparseable body, which is
/// treated as full acceptance.
#[derive(Debug, Default, Deserialize)]
struct IngestResponse {
    /// `event_id`s the backend durably accepted.
    #[serde(default)]
    accepted: Vec<String>,
    /// `event_id`s the backend permanently refused.
    #[serde(default)]
    rejected: Vec<String>,
}

pub struct Transport {
    buffer: Arc<Mutex<Spool>>,
    client: reqwest::Client,
    ingest_url: String,
    token: String,
}

impl Transport {
    pub fn new(
        buffer: Arc<Mutex<Spool>>,
        backend_url: String,
        token: String,
    ) -> anyhow::Result<Self> {
        let base = crate::http::normalize_base_url(&backend_url);
        let ingest_url = format!("{base}/api/v1/ingest/events");
        // Fail-closed: ingest shares the control channel's pinned-TLS posture;
        // no plain-client fall-back.
        let client = crate::http::streaming_client()?;
        Ok(Self {
            buffer,
            client,
            ingest_url,
            token,
        })
    }

    pub async fn run(self) {
        // Consecutive batch failures, used to back the *whole* flush loop off
        // when the backend is down — per-record backoff alone would still have
        // every tick build and attempt a batch.
        let mut consecutive_failures: u32 = 0;

        loop {
            if consecutive_failures > 0 {
                let wait = backoff::jittered_delay(consecutive_failures);
                if !wait.is_zero() {
                    tokio::time::sleep(wait).await;
                }
            }

            let catching_up = self.queue_depth() >= CATCH_UP_THRESHOLD;
            match self.flush(catching_up).await {
                FlushOutcome::Idle => {
                    metrics().set_transport_catching_up(false);
                    tokio::time::sleep(NORMAL_FLUSH_INTERVAL).await;
                }
                FlushOutcome::Delivered => {
                    consecutive_failures = 0;
                    // Sequential requests deliberately bound inflight memory to
                    // one batch. In catch-up mode this still permits up to 40
                    // batches/s while backend latency applies natural pressure.
                    tokio::time::sleep(if catching_up {
                        CATCH_UP_PACING
                    } else {
                        NORMAL_FLUSH_INTERVAL
                    })
                    .await;
                }
                FlushOutcome::Failed => {
                    consecutive_failures = consecutive_failures.saturating_add(1);
                }
            }
        }
    }

    fn queue_depth(&self) -> usize {
        self.buffer.lock().map_or(0, |b| b.len())
    }

    async fn flush(&self, catching_up: bool) -> FlushOutcome {
        let batch = match self.buffer.lock() {
            Ok(buf) => buf.peek_batch(MAX_BATCH_EVENTS),
            Err(e) => {
                warn!("Transport: spool mutex poisoned: {e}");
                metrics().event_dropped(DropReason::InternalError);
                return FlushOutcome::Failed;
            }
        };

        if batch.is_empty() {
            return FlushOutcome::Idle;
        }

        let n = batch.len();
        let seqs: Vec<u64> = batch.iter().map(|e| e.seq).collect();
        let events: Vec<_> = batch.iter().map(|e| e.event.clone()).collect();

        let started = Instant::now();
        let response = self
            .client
            .post(&self.ingest_url)
            .bearer_auth(&self.token)
            .json(&events)
            .send()
            .await;
        metrics().set_transport_activity(
            n as u64,
            started.elapsed().as_millis() as u64,
            catching_up,
        );

        match response {
            Ok(resp) if resp.status().is_success() => {
                metrics().transport_batch_sent();
                metrics().set_backend_connected(true);

                // Read per-event results if the backend provides them.
                let report: IngestResponse = resp.json().await.unwrap_or_default();
                let (acked_seqs, requeue_seqs) = partition_by_report(&batch, &report);

                self.record_latency(&batch, &acked_seqs);

                if let Ok(mut buf) = self.buffer.lock() {
                    let removed = buf.ack(&acked_seqs);
                    metrics().transport_events_acknowledged(removed as u64);
                    if !requeue_seqs.is_empty() {
                        buf.nack(&requeue_seqs);
                    }
                }

                if requeue_seqs.is_empty() {
                    debug!("Transport: delivered {n} events");
                } else {
                    debug!(
                        "Transport: partial acceptance — {} of {n} delivered, {} requeued",
                        acked_seqs.len(),
                        requeue_seqs.len()
                    );
                }
                FlushOutcome::Delivered
            }

            Ok(resp) => {
                let status = resp.status();
                metrics().transport_batch_failed();

                if is_permanent(status.as_u16()) {
                    // Retrying forever would block every event behind this
                    // batch. Remove it, but count the loss.
                    warn!(
                        %status,
                        events = n,
                        "Transport: backend permanently rejected this batch — \
                         dropping it (backend_rejected)"
                    );
                    if let Ok(mut buf) = self.buffer.lock() {
                        buf.ack(&seqs);
                    }
                    metrics().backend_rejected_events(n as u64);
                    FlushOutcome::Failed
                } else {
                    warn!(%status, events = n, "Transport: transient backend error — will retry");
                    if let Ok(mut buf) = self.buffer.lock() {
                        buf.nack(&seqs);
                    }
                    FlushOutcome::Failed
                }
            }

            Err(e) => {
                metrics().transport_batch_failed();
                metrics().set_backend_connected(false);
                warn!(error = %e, events = n, "Transport: request failed — will retry");
                if let Ok(mut buf) = self.buffer.lock() {
                    buf.nack(&seqs);
                }
                FlushOutcome::Failed
            }
        }
    }

    /// Feed acknowledged events into the end-to-end latency histogram.
    fn record_latency(&self, batch: &[crate::pipeline::SpoolEntry], acked: &[u64]) {
        let acked: HashSet<u64> = acked.iter().copied().collect();
        let now = chrono::Utc::now();
        for entry in batch.iter().filter(|e| acked.contains(&e.seq)) {
            let elapsed = now.signed_duration_since(entry.event.timestamp);
            // A negative span means the wall clock stepped backwards between
            // creation and acknowledgement; recording it as a huge unsigned
            // value would poison the percentiles, so it is skipped.
            if let Ok(ms) = u64::try_from(elapsed.num_milliseconds()) {
                metrics().observe_end_to_end_ms(ms);
            }
        }
    }
}

/// Split a batch into acknowledge / requeue sets based on the backend's report.
///
/// An empty report means the backend does not do per-event accounting, so a 2xx
/// covers the whole batch.
fn partition_by_report(
    batch: &[crate::pipeline::SpoolEntry],
    report: &IngestResponse,
) -> (Vec<u64>, Vec<u64>) {
    if report.accepted.is_empty() && report.rejected.is_empty() {
        return (batch.iter().map(|e| e.seq).collect(), Vec::new());
    }

    let accepted: HashSet<&str> = report.accepted.iter().map(String::as_str).collect();
    let rejected: HashSet<&str> = report.rejected.iter().map(String::as_str).collect();

    let mut ack = Vec::new();
    let mut requeue = Vec::new();
    let mut rejected_count = 0u64;

    for entry in batch {
        let id = entry.event.event_id.to_string();
        if rejected.contains(id.as_str()) {
            // Permanently refused: remove it, but count it as loss.
            ack.push(entry.seq);
            rejected_count += 1;
        } else if accepted.contains(id.as_str()) {
            ack.push(entry.seq);
        } else {
            // Not mentioned either way — the backend did not confirm it, so it
            // stays queued. Assuming acceptance here would lose events silently.
            requeue.push(entry.seq);
        }
    }

    if rejected_count > 0 {
        metrics().backend_rejected_events(rejected_count);
    }
    (ack, requeue)
}

/// Whether an HTTP status means "never send this again".
///
/// 408, 425 and 429 are 4xx but explicitly retryable — timeout, too-early and
/// rate-limited all clear on their own.
fn is_permanent(status: u16) -> bool {
    (400..500).contains(&status) && !matches!(status, 408 | 425 | 429)
}

#[derive(Debug, PartialEq, Eq)]
enum FlushOutcome {
    /// Nothing was waiting.
    Idle,
    /// At least part of the batch was accepted.
    Delivered,
    /// The batch was not delivered.
    Failed,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pipeline::SpoolEntry;
    use crate::schema::{
        AgentEvent, EventAction, EventClass, EventData, Severity, SystemSnapshotData,
    };

    fn event() -> AgentEvent {
        AgentEvent::new(
            "agent".into(),
            "host".into(),
            EventClass::System,
            EventAction::Snapshot,
            Severity::Info,
            EventData::SystemSnapshot(SystemSnapshotData {
                os: "Linux".into(),
                kernel: "6.0".into(),
                distro: "T".into(),
                cpu_count: 1,
                cpu_usage_pct: 0.0,
                memory_total_mb: 1,
                memory_used_mb: 1,
                memory_free_mb: 0,
                uptime_secs: 1,
                load_avg: [0.0; 3],
            }),
        )
    }

    fn entry(seq: u64) -> SpoolEntry {
        SpoolEntry {
            seq,
            event: event(),
            attempts: 0,
            bytes: 100,
            not_before: None,
        }
    }

    // ── Retryable vs permanent statuses ─────────────────────────────────────

    #[test]
    fn server_errors_are_retryable() {
        for status in [500, 502, 503, 504] {
            assert!(!is_permanent(status), "{status} must be retried");
        }
    }

    #[test]
    fn explicitly_retryable_4xx_statuses_are_not_permanent() {
        // Retrying these is the documented, correct behaviour.
        for status in [408, 425, 429] {
            assert!(
                !is_permanent(status),
                "{status} must be retried, not dropped"
            );
        }
    }

    #[test]
    fn other_client_errors_are_permanent() {
        for status in [400, 401, 403, 404, 409, 413, 422] {
            assert!(
                is_permanent(status),
                "{status} would otherwise block the queue forever"
            );
        }
    }

    #[test]
    fn success_statuses_are_never_permanent_failures() {
        for status in [200, 201, 202, 204] {
            assert!(!is_permanent(status));
        }
    }

    // ── Partial acknowledgement ─────────────────────────────────────────────

    #[test]
    fn an_empty_report_acknowledges_the_whole_batch() {
        // Backends without per-event accounting: 2xx means "all of it".
        let batch: Vec<_> = (1..=3).map(entry).collect();
        let (ack, requeue) = partition_by_report(&batch, &IngestResponse::default());
        assert_eq!(ack, vec![1, 2, 3]);
        assert!(requeue.is_empty());
    }

    #[test]
    fn only_accepted_events_are_acknowledged() {
        let batch: Vec<_> = (1..=3).map(entry).collect();
        let report = IngestResponse {
            accepted: vec![batch[0].event.event_id.to_string()],
            rejected: vec![],
        };
        let (ack, requeue) = partition_by_report(&batch, &report);
        assert_eq!(ack, vec![1]);
        assert_eq!(
            requeue,
            vec![2, 3],
            "unconfirmed events must stay queued, not be assumed delivered"
        );
    }

    #[test]
    fn rejected_events_are_removed_rather_than_retried_forever() {
        let batch: Vec<_> = (1..=2).map(entry).collect();
        let report = IngestResponse {
            accepted: vec![batch[0].event.event_id.to_string()],
            rejected: vec![batch[1].event.event_id.to_string()],
        };
        let (ack, requeue) = partition_by_report(&batch, &report);
        assert_eq!(ack, vec![1, 2], "both leave the queue");
        assert!(requeue.is_empty(), "a rejected event must not be retried");
    }

    #[test]
    fn an_unknown_event_id_in_the_report_is_ignored() {
        // A confused backend must not be able to acknowledge something that was
        // not in this batch.
        let batch: Vec<_> = (1..=2).map(entry).collect();
        let report = IngestResponse {
            accepted: vec!["00000000-0000-0000-0000-000000000000".into()],
            rejected: vec![],
        };
        let (ack, requeue) = partition_by_report(&batch, &report);
        assert!(ack.is_empty());
        assert_eq!(requeue, vec![1, 2], "nothing was actually confirmed");
    }

    #[test]
    fn a_duplicate_acknowledgement_in_the_report_is_harmless() {
        let batch: Vec<_> = (1..=2).map(entry).collect();
        let id = batch[0].event.event_id.to_string();
        let report = IngestResponse {
            accepted: vec![id.clone(), id],
            rejected: vec![],
        };
        let (ack, requeue) = partition_by_report(&batch, &report);
        assert_eq!(ack, vec![1], "a repeated id must not acknowledge twice");
        assert_eq!(requeue, vec![2]);
    }

    #[test]
    fn an_empty_batch_partitions_to_nothing() {
        let (ack, requeue) = partition_by_report(&[], &IngestResponse::default());
        assert!(ack.is_empty() && requeue.is_empty());
    }

    #[test]
    fn ingest_response_tolerates_a_body_without_the_fields() {
        // Existing backends return `{}` or a bare status object.
        let r: IngestResponse = serde_json::from_str("{}").unwrap();
        assert!(r.accepted.is_empty() && r.rejected.is_empty());
        let r: IngestResponse = serde_json::from_str(r#"{"status":"ok"}"#).unwrap();
        assert!(r.accepted.is_empty());
    }
}
