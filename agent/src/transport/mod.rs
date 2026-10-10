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
use std::io::Write as _;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
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
/// Shortest gap between two priority-triggered flushes, so a detection storm
/// cannot turn into a request per event.
const PRIORITY_MIN_GAP: Duration = Duration::from_millis(50);
/// Bodies below this are sent as-is: gzip overhead outweighs the saving.
const COMPRESS_MIN_BYTES: usize = 1024;
/// Upper bound honoured for a server-sent `Retry-After`, so a bad value cannot
/// park the transport for hours.
const MAX_RETRY_AFTER: Duration = Duration::from_secs(300);

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
    /// Set once the backend has advertised `Accept-Encoding: gzip`. Compressing
    /// before that would hand an older backend a body it cannot parse, which it
    /// rejects with a permanent 4xx, and the batch would be dropped.
    gzip_ok: AtomicBool,
    /// OCSF is used only after an explicit advertisement by the pinned backend.
    ocsf_ok: AtomicBool,
    /// Seconds from the last `Retry-After`, consumed by the flush loop.
    retry_after_secs: AtomicU64,
    /// Fired by the spool when a detection/prevention event is queued; cuts the
    /// idle wait short (never the failure backoff).
    priority_wake: Arc<tokio::sync::Notify>,
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
        let priority_wake = buffer
            .lock()
            .map_err(|e| anyhow::anyhow!("spool mutex poisoned: {e}"))?
            .priority_wake();
        Ok(Self {
            buffer,
            priority_wake,
            client,
            ingest_url,
            token,
            gzip_ok: AtomicBool::new(false),
            ocsf_ok: AtomicBool::new(false),
            retry_after_secs: AtomicU64::new(0),
        })
    }

    pub async fn run(self) {
        // Consecutive batch failures, used to back the *whole* flush loop off
        // when the backend is down — per-record backoff alone would still have
        // every tick build and attempt a batch.
        let mut consecutive_failures: u32 = 0;

        loop {
            if consecutive_failures > 0 {
                // The server's own `Retry-After` is a floor, never shorter than
                // our jittered backoff.
                let server_hint =
                    Duration::from_secs(self.retry_after_secs.swap(0, Ordering::Relaxed));
                let wait = backoff::jittered_delay(consecutive_failures).max(server_hint);
                if !wait.is_zero() {
                    tokio::time::sleep(wait).await;
                }
            }

            let catching_up = self.queue_depth() >= CATCH_UP_THRESHOLD;
            match self.flush(catching_up).await {
                FlushOutcome::Idle => {
                    metrics().set_transport_catching_up(false);
                    self.wait(NORMAL_FLUSH_INTERVAL).await;
                }
                FlushOutcome::Delivered => {
                    consecutive_failures = 0;
                    // Sequential requests deliberately bound inflight memory to
                    // one batch. In catch-up mode this still permits up to 40
                    // batches/s while backend latency applies natural pressure.
                    self.wait(if catching_up {
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

    /// Wait for the next flush: the full interval, or until a priority event
    /// arrives (then only [`PRIORITY_MIN_GAP`] from now, to bound the request
    /// rate under a detection storm).
    async fn wait(&self, interval: Duration) {
        tokio::select! {
            () = tokio::time::sleep(interval) => {}
            () = self.priority_wake.notified() => {
                tokio::time::sleep(PRIORITY_MIN_GAP.min(interval)).await;
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

        let all_seqs: Vec<u64> = batch.iter().map(|e| e.seq).collect();
        let sent_ocsf = self.ocsf_ok.load(Ordering::Relaxed);
        // OCSF adds standard projections alongside source evidence. Bound the
        // actual encoded body, and acknowledge only entries included in it.
        let (batch, raw) = match encode_event_batch(
            &batch,
            sent_ocsf,
            crate::telemetry::limits::MAX_BATCH_BYTES,
        ) {
            Ok(encoded) => encoded,
            Err(e) => {
                warn!(error = %e, "Transport: batch encoding failed — will retry");
                metrics().transport_batch_failed();
                if let Ok(mut buf) = self.buffer.lock() {
                    buf.nack(&all_seqs);
                }
                return FlushOutcome::Failed;
            }
        };
        let n = batch.len();
        let seqs: Vec<u64> = batch.iter().map(|e| e.seq).collect();
        let (body, compressed) = encode_body(raw, self.gzip_ok.load(Ordering::Relaxed));
        let mut request = self
            .client
            .post(&self.ingest_url)
            .bearer_auth(&self.token)
            .header(reqwest::header::CONTENT_TYPE, "application/json");
        if compressed {
            request = request.header(reqwest::header::CONTENT_ENCODING, "gzip");
        }

        let started = Instant::now();
        metrics().transport_events_sent(n as u64);
        let response = request.body(body).send().await;
        metrics().set_transport_activity(
            n as u64,
            started.elapsed().as_millis() as u64,
            catching_up,
        );

        if let Ok(resp) = &response {
            if advertises_gzip(resp.headers()) {
                self.gzip_ok.store(true, Ordering::Relaxed);
            }
            self.ocsf_ok
                .store(advertises_ocsf(resp.headers()), Ordering::Relaxed);
            // Always overwrite (0 when absent) so a stale hint never outlives
            // the response that sent it.
            let hint = parse_retry_after(resp.headers()).map_or(0, |d| d.as_secs());
            self.retry_after_secs.store(hint, Ordering::Relaxed);
        }

        match response {
            Ok(resp) if resp.status().is_success() => {
                metrics().transport_batch_sent();
                metrics().set_backend_connected(true);

                // Read per-event results if the backend provides them.
                let report: IngestResponse = resp.json().await.unwrap_or_default();
                let (acked_seqs, requeue_seqs, rejected_seqs) =
                    partition_by_report(&batch, &report);

                self.record_latency(&batch, &acked_seqs);

                if let Ok(mut buf) = self.buffer.lock() {
                    // Count only records still queued. Overflow may have
                    // already evicted an in-flight record while awaiting HTTP.
                    let rejected = buf.ack(&rejected_seqs);
                    metrics().backend_rejected_events(rejected as u64);
                    let removed = buf.ack(&acked_seqs);
                    if removed > 0 {
                        metrics().transport_events_acknowledged(removed as u64);
                    }
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

                if compressed && status.as_u16() == 415 {
                    // Something on the path refuses gzip. That says nothing
                    // about the events themselves, so keep them and resend
                    // uncompressed instead of dropping them as a permanent 4xx.
                    warn!(
                        events = n,
                        "Transport: gzip refused (415) — disabling compression and retrying"
                    );
                    self.gzip_ok.store(false, Ordering::Relaxed);
                    if let Ok(mut buf) = self.buffer.lock() {
                        buf.nack(&seqs);
                    }
                    FlushOutcome::Failed
                } else if sent_ocsf
                    && !advertises_ocsf(resp.headers())
                    && matches!(status.as_u16(), 400 | 415 | 422)
                {
                    // A rollout may route the next request to an older gateway.
                    // Retry its legacy contract once, preserving every event ID.
                    self.ocsf_ok.store(false, Ordering::Relaxed);
                    if let Ok(mut buf) = self.buffer.lock() {
                        buf.nack(&seqs);
                    }
                    FlushOutcome::Failed
                } else if is_permanent(status.as_u16()) {
                    // Retrying forever would block every event behind this
                    // batch. Remove it, but count the loss.
                    warn!(
                        %status,
                        events = n,
                        "Transport: backend permanently rejected this batch — \
                         dropping it (backend_rejected)"
                    );
                    if let Ok(mut buf) = self.buffer.lock() {
                        let removed = buf.ack(&seqs);
                        metrics().backend_rejected_events(removed as u64);
                    }
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

/// Encode the largest prefix that fits the wire limit after OCSF expansion.
fn encode_event_batch(
    batch: &[crate::pipeline::SpoolEntry],
    ocsf: bool,
    limit: usize,
) -> Result<(Vec<crate::pipeline::SpoolEntry>, Vec<u8>), trapd_schema::ocsf::ContractError> {
    use trapd_schema::ocsf::{to_ocsf, ContractError};
    let mut selected = Vec::new();
    let mut raw = vec![b'['];
    for entry in batch {
        let legacy = serde_json::to_value(&entry.event)
            .map_err(|_| ContractError("event serialization failed"))?;
        let wire = if ocsf { to_ocsf(&legacy)? } else { legacy };
        let encoded =
            serde_json::to_vec(&wire).map_err(|_| ContractError("event serialization failed"))?;
        let comma = usize::from(!selected.is_empty());
        if raw.len() + comma + encoded.len() + 1 > limit {
            if selected.is_empty() {
                return Err(ContractError("encoded event exceeds batch limit"));
            }
            break;
        }
        if comma != 0 {
            raw.push(b',');
        }
        raw.extend_from_slice(&encoded);
        selected.push(entry.clone());
    }
    raw.push(b']');
    Ok((selected, raw))
}
fn advertises_ocsf(headers: &reqwest::header::HeaderMap) -> bool {
    headers
        .get_all(trapd_schema::ocsf::CAPABILITY_HEADER)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .any(|token| token.trim() == "ocsf-1.9.0")
}

/// Split a batch into accepted / retry / rejected sets without counting losses.
///
/// An empty report means the backend does not do per-event accounting, so a 2xx
/// covers the whole batch.
fn partition_by_report(
    batch: &[crate::pipeline::SpoolEntry],
    report: &IngestResponse,
) -> (Vec<u64>, Vec<u64>, Vec<u64>) {
    if report.accepted.is_empty() && report.rejected.is_empty() {
        return (
            batch.iter().map(|e| e.seq).collect(),
            Vec::new(),
            Vec::new(),
        );
    }

    let accepted: HashSet<&str> = report.accepted.iter().map(String::as_str).collect();
    let rejected: HashSet<&str> = report.rejected.iter().map(String::as_str).collect();

    let mut ack = Vec::new();
    let mut requeue = Vec::new();
    let mut rejected_seqs = Vec::new();

    for entry in batch {
        let id = entry.event.event_id.to_string();
        if rejected.contains(id.as_str()) {
            // Loss is counted when this record actually leaves the queue.
            rejected_seqs.push(entry.seq);
        } else if accepted.contains(id.as_str()) {
            ack.push(entry.seq);
        } else {
            // Not mentioned either way — the backend did not confirm it, so it
            // stays queued. Assuming acceptance here would lose events silently.
            requeue.push(entry.seq);
        }
    }

    (ack, requeue, rejected_seqs)
}

/// Whether an HTTP status means "never send this again".
///
/// 408, 425 and 429 are 4xx but explicitly retryable — timeout, too-early and
/// rate-limited all clear on their own.
/// Compress `raw` when the backend is known to accept gzip and the body is big
/// enough to benefit. Returns the bytes to send and whether they are gzip.
fn encode_body(raw: Vec<u8>, gzip_ok: bool) -> (Vec<u8>, bool) {
    if !gzip_ok || raw.len() < COMPRESS_MIN_BYTES {
        return (raw, false);
    }
    let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    match enc.write_all(&raw).and_then(|()| enc.finish()) {
        // Keep the original if compression did not actually help.
        Ok(c) if c.len() < raw.len() => (c, true),
        _ => (raw, false),
    }
}

/// Whether a response's `Accept-Encoding` lists the `gzip` coding.
fn advertises_gzip(headers: &reqwest::header::HeaderMap) -> bool {
    headers
        .get_all(reqwest::header::ACCEPT_ENCODING)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .any(|token| {
            // "gzip;q=0" explicitly forbids it.
            let mut parts = token.trim().split(';');
            let coding = parts.next().unwrap_or("").trim();
            let refused = parts.any(|p| p.trim().replace(' ', "") == "q=0");
            coding.eq_ignore_ascii_case("gzip") && !refused
        })
}

/// `Retry-After` as delta-seconds (HTTP-dates are ignored), capped at
/// [`MAX_RETRY_AFTER`].
fn parse_retry_after(headers: &reqwest::header::HeaderMap) -> Option<Duration> {
    let secs: u64 = headers
        .get(reqwest::header::RETRY_AFTER)?
        .to_str()
        .ok()?
        .trim()
        .parse()
        .ok()?;
    Some(Duration::from_secs(secs).min(MAX_RETRY_AFTER))
}

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

    static RESPONSE_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    async fn flush_with_response(status: &str, partial: bool, evict: bool) -> (u64, u64) {
        let buffer = Arc::new(Mutex::new(Spool::in_memory(if evict { 1 } else { 2 })));
        let rejected = event();
        let rejected_id = rejected.event_id.to_string();
        buffer.lock().unwrap().push(rejected).unwrap();
        if !evict {
            buffer.lock().unwrap().push(event()).unwrap();
        }
        let response_body = if partial {
            serde_json::json!({"rejected": [rejected_id]}).to_string()
        } else {
            "{}".into()
        };
        let response = format!(
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response_body}",
            response_body.len(),
        );
        let server_buffer = Arc::clone(&buffer);
        let (url, backend) = mock_backend_with(vec![response], move || {
            if evict {
                // Deterministic race: replace the in-flight record before replying.
                server_buffer.lock().unwrap().push(event()).unwrap();
            }
        })
        .await;
        let mut transport = transport_for(url, 0);
        transport.priority_wake = buffer.lock().unwrap().priority_wake();
        transport.buffer = Arc::clone(&buffer);
        let before = metrics().snapshot();
        let outcome = transport.flush(false).await;
        assert_eq!(
            outcome,
            if partial {
                FlushOutcome::Delivered
            } else {
                FlushOutcome::Failed
            }
        );
        backend.await.unwrap();
        assert_eq!(buffer.lock().unwrap().len(), 1);
        let after = metrics().snapshot();
        assert_eq!(
            after.last_ack_unix_ms, before.last_ack_unix_ms,
            "a rejection-only response must not advance the acknowledgement clock"
        );
        (
            after.backend_rejected_events_total - before.backend_rejected_events_total,
            after.transport_events_acknowledged_total - before.transport_events_acknowledged_total,
        )
    }

    #[tokio::test]
    async fn permanent_rejection_does_not_double_count_an_evicted_record() {
        let _guard = RESPONSE_TEST_LOCK.lock().await;
        assert_eq!(
            flush_with_response("400 Bad Request", false, true).await.0,
            0
        );
    }

    #[tokio::test]
    async fn partial_rejection_is_not_counted_as_acknowledged() {
        let _guard = RESPONSE_TEST_LOCK.lock().await;
        assert_eq!(flush_with_response("200 OK", true, false).await, (1, 0));
    }

    #[tokio::test]
    async fn partial_rejection_does_not_double_count_an_evicted_record() {
        let _guard = RESPONSE_TEST_LOCK.lock().await;
        assert_eq!(flush_with_response("200 OK", true, true).await.0, 0);
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
        let (ack, requeue, rejected) = partition_by_report(&batch, &IngestResponse::default());
        assert!(rejected.is_empty());
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
        let (ack, requeue, rejected) = partition_by_report(&batch, &report);
        assert!(rejected.is_empty());
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
        let (ack, requeue, rejected) = partition_by_report(&batch, &report);
        assert_eq!(ack, vec![1], "only accepted records are acknowledged");
        assert_eq!(rejected, vec![2], "refused records are tracked separately");
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
        let (ack, requeue, rejected) = partition_by_report(&batch, &report);
        assert!(rejected.is_empty());
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
        let (ack, requeue, rejected) = partition_by_report(&batch, &report);
        assert!(rejected.is_empty());
        assert_eq!(ack, vec![1], "a repeated id must not acknowledge twice");
        assert_eq!(requeue, vec![2]);
    }

    #[test]
    fn an_empty_batch_partitions_to_nothing() {
        let (ack, requeue, rejected) = partition_by_report(&[], &IngestResponse::default());
        assert!(ack.is_empty() && requeue.is_empty() && rejected.is_empty());
    }

    #[test]
    fn ingest_response_tolerates_a_body_without_the_fields() {
        // Existing backends return `{}` or a bare status object.
        let r: IngestResponse = serde_json::from_str("{}").unwrap();
        assert!(r.accepted.is_empty() && r.rejected.is_empty());
        let r: IngestResponse = serde_json::from_str(r#"{"status":"ok"}"#).unwrap();
        assert!(r.accepted.is_empty());
    }

    // ── Compression, Retry-After ────────────────────────────────────────────

    fn headers(pairs: &[(&'static str, &'static str)]) -> reqwest::header::HeaderMap {
        let mut h = reqwest::header::HeaderMap::new();
        for (k, v) in pairs {
            h.append(
                reqwest::header::HeaderName::from_static(k),
                reqwest::header::HeaderValue::from_static(v),
            );
        }
        h
    }

    fn gunzip(bytes: &[u8]) -> Vec<u8> {
        use std::io::Read as _;
        let mut out = Vec::new();
        flate2::read::GzDecoder::new(bytes)
            .read_to_end(&mut out)
            .unwrap();
        out
    }

    #[test]
    fn small_or_unnegotiated_bodies_are_not_compressed() {
        let big = vec![b'a'; 10_000];
        assert_eq!(encode_body(big.clone(), false), (big.clone(), false));
        let small = vec![b'a'; COMPRESS_MIN_BYTES - 1];
        assert_eq!(encode_body(small.clone(), true), (small, false));
    }

    #[test]
    fn negotiated_large_bodies_round_trip_through_gzip() {
        let raw = br#"{"event":"process_exec","data":"abcdefghij"}"#.repeat(200);
        let (body, compressed) = encode_body(raw.clone(), true);
        assert!(compressed);
        assert!(
            body.len() < raw.len() / 4,
            "repetitive JSON must shrink a lot"
        );
        assert_eq!(gunzip(&body), raw);
    }

    #[test]
    fn incompressible_bodies_are_sent_as_is() {
        // xorshift noise: gzip cannot shrink it, so the original must be kept.
        let mut x: u64 = 0x2545_F491_4F6C_DD1D;
        let raw: Vec<u8> = (0..4096)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                (x >> 32) as u8
            })
            .collect();
        assert_eq!(encode_body(raw.clone(), true), (raw, false));
    }

    #[test]
    fn gzip_is_only_assumed_when_the_server_lists_it() {
        assert!(advertises_gzip(&headers(&[("accept-encoding", "gzip")])));
        assert!(advertises_gzip(&headers(&[(
            "accept-encoding",
            "br, GZIP"
        )])));
        assert!(advertises_gzip(&headers(&[
            ("accept-encoding", "identity"),
            ("accept-encoding", "gzip")
        ])));
        assert!(!advertises_gzip(&headers(&[(
            "accept-encoding",
            "gzip;q=0"
        )])));
        assert!(!advertises_gzip(&headers(&[(
            "accept-encoding",
            "gzip; q=0"
        )])));
        assert!(!advertises_gzip(&headers(&[(
            "accept-encoding",
            "identity"
        )])));
        assert!(!advertises_gzip(&headers(&[])));
    }

    #[test]
    fn retry_after_is_delta_seconds_and_capped() {
        let h = |v: &'static str| parse_retry_after(&headers(&[("retry-after", v)]));
        assert_eq!(h("60"), Some(Duration::from_secs(60)));
        assert_eq!(h(" 5 "), Some(Duration::from_secs(5)));
        assert_eq!(h("86400"), Some(MAX_RETRY_AFTER));
        assert_eq!(h("Wed, 21 Oct 2026 07:28:00 GMT"), None);
        assert_eq!(h("soon"), None);
        assert_eq!(parse_retry_after(&headers(&[])), None);
    }

    // ── Wire behaviour against a mock backend ───────────────────────────────

    /// What the mock backend saw for one request.
    struct Seen {
        content_encoding: Option<String>,
        body: Vec<u8>,
    }

    /// Serves one scripted response per connection, in order, and records each
    /// request. `script` entries are full raw HTTP responses.
    async fn mock_backend(script: Vec<String>) -> (String, tokio::task::JoinHandle<Vec<Seen>>) {
        mock_backend_with(script, || {}).await
    }

    async fn mock_backend_with(
        script: Vec<String>,
        mut before_response: impl FnMut() + Send + 'static,
    ) -> (String, tokio::task::JoinHandle<Vec<Seen>>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!(
            "http://{}/api/v1/ingest/events",
            listener.local_addr().unwrap()
        );
        let handle = tokio::spawn(async move {
            let mut seen = Vec::new();
            for response in script {
                let (mut sock, _) = listener.accept().await.unwrap();
                let mut buf = Vec::new();
                let mut chunk = [0u8; 8192];
                let (head_end, content_length) = loop {
                    let n = sock.read(&mut chunk).await.unwrap();
                    assert!(n > 0, "client closed before sending a full request");
                    buf.extend_from_slice(&chunk[..n]);
                    if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        let head = String::from_utf8_lossy(&buf[..pos]).to_ascii_lowercase();
                        let len = head
                            .lines()
                            .find_map(|l| l.strip_prefix("content-length:"))
                            .map(|v| v.trim().parse::<usize>().unwrap())
                            .unwrap_or(0);
                        break (pos + 4, len);
                    }
                };
                while buf.len() < head_end + content_length {
                    let n = sock.read(&mut chunk).await.unwrap();
                    buf.extend_from_slice(&chunk[..n]);
                }
                let head = String::from_utf8_lossy(&buf[..head_end]).to_ascii_lowercase();
                seen.push(Seen {
                    content_encoding: head
                        .lines()
                        .find_map(|l| l.strip_prefix("content-encoding:"))
                        .map(|v| v.trim().to_string()),
                    body: buf[head_end..head_end + content_length].to_vec(),
                });
                before_response();
                sock.write_all(response.as_bytes()).await.unwrap();
            }
            seen
        });
        (url, handle)
    }

    fn http(status: &str, extra: &str) -> String {
        format!("HTTP/1.1 {status}\r\n{extra}Content-Length: 2\r\nConnection: close\r\n\r\n{{}}")
    }

    fn transport_for(url: String, events: usize) -> Transport {
        let mut spool = Spool::in_memory(1000);
        for _ in 0..events {
            spool.push(event()).unwrap();
        }
        let priority_wake = spool.priority_wake();
        Transport {
            priority_wake,
            buffer: Arc::new(Mutex::new(spool)),
            client: reqwest::Client::new(),
            ingest_url: url,
            token: "secret_test".into(),
            gzip_ok: AtomicBool::new(false),
            ocsf_ok: AtomicBool::new(false),
            retry_after_secs: AtomicU64::new(0),
        }
    }

    async fn flush_ready(t: &Transport) -> FlushOutcome {
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let outcome = t.flush(false).await;
                if outcome != FlushOutcome::Idle {
                    break outcome;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("spool retry should become eligible within its backoff bound")
    }

    #[test]
    fn imperfect_auth_address_does_not_poison_a_mixed_batch() {
        let mut batch: Vec<_> = (1..=3).map(entry).collect();
        batch[1].event.class = crate::schema::EventClass::User;
        batch[1].event.action = crate::schema::EventAction::LogonFailed;
        batch[1].event.data = crate::schema::EventData::UserLogon(crate::schema::UserLogonData {
            username: "fixture".into(),
            src_addr: Some("not-an-ip".into()),
            src_port: Some(22),
            auth_method: Some("password".into()),
            success: false,
            ..Default::default()
        });
        let (selected, raw) = encode_event_batch(&batch, true, usize::MAX).unwrap();
        assert_eq!(selected.len(), 3);
        let wire: Vec<serde_json::Value> = serde_json::from_slice(&raw).unwrap();
        assert!(wire[1].get("src_endpoint").is_none());
        assert_eq!(
            wire[1]["unmapped"]["trapd"]["data"]["src_addr"],
            "not-an-ip"
        );
        for (event, original) in wire.iter().zip(&batch) {
            assert_eq!(
                event["metadata"]["uid"],
                original.event.event_id.to_string()
            );
            crate::schema::ocsf::validate(event).unwrap();
        }
    }
    #[test]
    fn ocsf_expansion_respects_wire_limit_and_selected_handles() {
        let batch: Vec<_> = (1..=3).map(entry).collect();
        let (_, one) = encode_event_batch(&batch[..1], true, usize::MAX).unwrap();
        let (selected, raw) = encode_event_batch(&batch, true, one.len() + 1).unwrap();
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].seq, batch[0].seq);
        assert!(raw.len() <= one.len() + 1);
        let wire: Vec<serde_json::Value> = serde_json::from_slice(&raw).unwrap();
        assert_eq!(
            wire[0]["metadata"]["uid"],
            batch[0].event.event_id.to_string()
        );
        assert!(encode_event_batch(&batch, true, one.len() - 1).is_err());
    }

    #[tokio::test]
    async fn older_gateway_after_negotiation_retries_legacy_without_loss() {
        let (url, backend) = mock_backend(vec![
            http(
                "503 Service Unavailable",
                "x-trapd-event-formats: legacy,ocsf-1.9.0\r\n",
            ),
            http("400 Bad Request", ""),
            http("202 Accepted", ""),
        ])
        .await;
        let t = transport_for(url, 1);
        assert_eq!(flush_ready(&t).await, FlushOutcome::Failed);
        assert_eq!(flush_ready(&t).await, FlushOutcome::Failed);
        assert_eq!(flush_ready(&t).await, FlushOutcome::Delivered);
        let seen = backend.await.unwrap();
        let payloads: Vec<Vec<serde_json::Value>> = seen
            .iter()
            .map(|s| serde_json::from_slice(&s.body).unwrap())
            .collect();
        assert_eq!(payloads[0], payloads[2]);
        assert_eq!(
            payloads[1][0]["metadata"]["uid"],
            payloads[0][0]["event_id"]
        );
    }

    #[tokio::test]
    async fn ocsf_negotiation_preserves_identity_across_retries() {
        let (url, backend) = mock_backend(vec![
            http(
                "503 Service Unavailable",
                "x-trapd-event-formats: legacy,ocsf-1.9.0\r\n",
            ),
            http(
                "503 Service Unavailable",
                "x-trapd-event-formats: legacy,ocsf-1.9.0\r\n",
            ),
            http(
                "202 Accepted",
                "x-trapd-event-formats: legacy,ocsf-1.9.0\r\n",
            ),
        ])
        .await;
        let t = transport_for(url, 1);
        assert_eq!(flush_ready(&t).await, FlushOutcome::Failed);
        assert_eq!(flush_ready(&t).await, FlushOutcome::Failed);
        assert_eq!(flush_ready(&t).await, FlushOutcome::Delivered);
        let seen = backend.await.unwrap();
        let legacy: Vec<serde_json::Value> = serde_json::from_slice(&seen[0].body).unwrap();
        let retry: Vec<serde_json::Value> = serde_json::from_slice(&seen[1].body).unwrap();
        let final_batch: Vec<serde_json::Value> = serde_json::from_slice(&seen[2].body).unwrap();
        assert!(retry[0].get("class_uid").is_some());
        assert_eq!(retry[0]["metadata"]["uid"], legacy[0]["event_id"]);
        assert_eq!(retry, final_batch);
        assert_eq!(trapd_schema::ocsf::from_ocsf(&retry[0]).unwrap(), legacy[0]);
    }

    #[tokio::test]
    async fn unsupported_capability_keeps_legacy_wire() {
        let (url, backend) = mock_backend(vec![
            http(
                "503 Service Unavailable",
                "x-trapd-event-formats: ocsf-2.0.0\r\n",
            ),
            http("202 Accepted", ""),
        ])
        .await;
        let t = transport_for(url, 1);
        assert_eq!(flush_ready(&t).await, FlushOutcome::Failed);
        assert_eq!(flush_ready(&t).await, FlushOutcome::Delivered);
        for seen in backend.await.unwrap() {
            let events: Vec<serde_json::Value> = serde_json::from_slice(&seen.body).unwrap();
            assert!(events[0].get("event_id").is_some());
            assert!(events[0].get("class_uid").is_none());
        }
    }

    #[tokio::test]
    async fn compression_starts_only_after_the_backend_advertises_it() {
        let _guard = RESPONSE_TEST_LOCK.lock().await;
        let (url, backend) = mock_backend(vec![
            http("202 Accepted", "Accept-Encoding: gzip\r\n"),
            http("202 Accepted", "Accept-Encoding: gzip\r\n"),
        ])
        .await;
        let t = transport_for(url, 40);

        assert_eq!(t.flush(false).await, FlushOutcome::Delivered);
        assert!(
            t.gzip_ok.load(Ordering::Relaxed),
            "advertisement is remembered"
        );

        for _ in 0..40 {
            t.buffer.lock().unwrap().push(event()).unwrap();
        }
        assert_eq!(t.flush(false).await, FlushOutcome::Delivered);

        let seen = backend.await.unwrap();
        assert_eq!(
            seen[0].content_encoding, None,
            "first request must be plain"
        );
        let first: Vec<serde_json::Value> = serde_json::from_slice(&seen[0].body).unwrap();
        assert_eq!(first.len(), 40);

        assert_eq!(seen[1].content_encoding.as_deref(), Some("gzip"));
        let second: Vec<serde_json::Value> =
            serde_json::from_slice(&gunzip(&seen[1].body)).unwrap();
        assert_eq!(second.len(), 40, "gzip body decodes to the same JSON array");
    }

    #[tokio::test]
    async fn a_backend_that_never_advertises_gzip_never_gets_it() {
        let _guard = RESPONSE_TEST_LOCK.lock().await;
        let (url, backend) =
            mock_backend(vec![http("202 Accepted", ""), http("202 Accepted", "")]).await;
        let t = transport_for(url, 40);
        t.flush(false).await;
        for _ in 0..40 {
            t.buffer.lock().unwrap().push(event()).unwrap();
        }
        t.flush(false).await;
        let seen = backend.await.unwrap();
        assert!(seen.iter().all(|s| s.content_encoding.is_none()));
    }

    #[tokio::test]
    async fn a_415_for_gzip_keeps_the_events_and_turns_compression_off() {
        let _guard = RESPONSE_TEST_LOCK.lock().await;
        let (url, backend) = mock_backend(vec![http("415 Unsupported Media Type", "")]).await;
        let t = transport_for(url, 40);
        t.gzip_ok.store(true, Ordering::Relaxed);

        assert_eq!(t.flush(false).await, FlushOutcome::Failed);

        assert!(!t.gzip_ok.load(Ordering::Relaxed));
        assert_eq!(t.buffer.lock().unwrap().len(), 40, "nothing may be dropped");
        let seen = backend.await.unwrap();
        assert_eq!(seen[0].content_encoding.as_deref(), Some("gzip"));
    }

    #[tokio::test]
    async fn retry_after_from_a_throttled_response_is_recorded_and_events_are_kept() {
        let _guard = RESPONSE_TEST_LOCK.lock().await;
        let (url, _backend) =
            mock_backend(vec![http("429 Too Many Requests", "Retry-After: 7\r\n")]).await;
        let t = transport_for(url, 5);

        assert_eq!(t.flush(false).await, FlushOutcome::Failed);

        assert_eq!(t.retry_after_secs.load(Ordering::Relaxed), 7);
        assert_eq!(t.buffer.lock().unwrap().len(), 5);
    }

    /// Real agent transport against a real ingest gateway (Postgres + Kafka).
    ///
    /// Run manually:
    /// `TRAPD_E2E_INGEST_URL=http://127.0.0.1:8092/api/v1/ingest/events \
    ///  TRAPD_E2E_TOKEN=secret_... TRAPD_E2E_AGENT_ID=agent_... \
    ///  cargo test -p trapd-agent transport::tests::negotiates_gzip_with_a_real_gateway -- --ignored`
    #[tokio::test]
    #[ignore = "needs a running gateway: TRAPD_E2E_INGEST_URL, TRAPD_E2E_TOKEN, TRAPD_E2E_AGENT_ID"]
    async fn negotiates_gzip_with_a_real_gateway() {
        let var = |k: &str| std::env::var(k).unwrap_or_else(|_| panic!("{k} not set"));
        let agent_id = var("TRAPD_E2E_AGENT_ID");
        let mut spool = Spool::in_memory(1000);
        let t = {
            let fill = |spool: &mut Spool| {
                for _ in 0..40 {
                    let mut e = event();
                    e.agent_id = agent_id.clone();
                    spool.push(e).unwrap();
                }
            };
            fill(&mut spool);
            let priority_wake = spool.priority_wake();
            Transport {
                priority_wake,
                buffer: Arc::new(Mutex::new(spool)),
                client: reqwest::Client::new(),
                ingest_url: var("TRAPD_E2E_INGEST_URL"),
                token: var("TRAPD_E2E_TOKEN"),
                gzip_ok: AtomicBool::new(false),
                ocsf_ok: AtomicBool::new(false),
                retry_after_secs: AtomicU64::new(0),
            }
        };

        assert_eq!(t.flush(false).await, FlushOutcome::Delivered, "plain batch");
        assert!(
            t.gzip_ok.load(Ordering::Relaxed),
            "the real gateway must advertise gzip"
        );

        for _ in 0..40 {
            let mut e = event();
            e.agent_id = agent_id.clone();
            t.buffer.lock().unwrap().push(e).unwrap();
        }
        assert_eq!(t.flush(false).await, FlushOutcome::Delivered, "gzip batch");
        assert_eq!(t.buffer.lock().unwrap().len(), 0, "everything acknowledged");
    }
}
