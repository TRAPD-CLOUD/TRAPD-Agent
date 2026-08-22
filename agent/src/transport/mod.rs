//! Authenticated event transport.
//!
//! Pulls batches off the in-memory ring buffer and ships them to the backend
//! ingest endpoint.  The TLS posture (rustls, optional CA pinning, optional
//! mTLS) and timeouts are provided by [`crate::http`] so transport, enrollment,
//! heartbeat and config-pull all behave identically.

use std::sync::{Arc, Mutex};

use tokio::time::Duration;
use tracing::{debug, warn};

use crate::pipeline::Spool;

const FLUSH_INTERVAL: Duration = Duration::from_secs(5);
const BATCH_SIZE: usize = 100;

// ── Retry-after-failure backoff tuning ─────────────────────────────────────
// Steady-state (no failures) cadence stays FLUSH_INTERVAL; only a failed
// flush escalates the wait, mirroring crate::enrollment's capped exponential
// backoff + jitter so a fleet whose backend is down doesn't hammer it on a
// fixed 5s ticker forever.
const RETRY_BACKOFF_BASE: Duration = Duration::from_secs(5);
const RETRY_BACKOFF_MAX: Duration = Duration::from_secs(120);

/// Delay before the next flush attempt, given how many consecutive flushes
/// have just failed (`0` = steady state / just succeeded or nothing to send).
fn next_delay(consecutive_failures: u32) -> Duration {
    if consecutive_failures == 0 {
        FLUSH_INTERVAL
    } else {
        crate::backoff::backoff(consecutive_failures, RETRY_BACKOFF_BASE, RETRY_BACKOFF_MAX)
    }
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
        // A plain sleep-then-flush loop rather than a fixed `interval` ticker:
        // the steady-state wait is still FLUSH_INTERVAL, but a failed flush
        // escalates the wait via `next_delay` instead of retrying on the same
        // fixed 5s cadence forever (which just hammers a downed backend).
        let mut consecutive_failures: u32 = 0;
        loop {
            tokio::time::sleep(next_delay(consecutive_failures)).await;
            if self.flush().await {
                consecutive_failures = 0;
            } else {
                consecutive_failures = consecutive_failures.saturating_add(1);
            }
        }
    }

    /// Attempt one flush. Returns `true` on success (or nothing to send —
    /// there is no failure to back off from), `false` on a failure that
    /// should trigger backoff before the next attempt.
    async fn flush(&self) -> bool {
        let batch = {
            let buf = match self.buffer.lock() {
                Ok(b) => b,
                Err(e) => {
                    warn!("Transport: ring buffer mutex poisoned: {e}");
                    return true;
                }
            };
            buf.peek_batch(BATCH_SIZE)
        };

        if batch.is_empty() {
            return true;
        }

        let n = batch.len();

        match self
            .client
            .post(&self.ingest_url)
            .bearer_auth(&self.token)
            .json(&batch)
            .send()
            .await
        {
            Ok(resp) if resp.status().is_success() => {
                let dropped = match self.buffer.lock() {
                    Ok(mut buf) => {
                        buf.drain(n);
                        buf.dropped_total()
                    }
                    Err(e) => {
                        warn!("Transport: spool mutex poisoned on drain: {e}");
                        0
                    }
                };
                debug!("Transport: flushed {n} events to backend (spool dropped_total={dropped})");
                true
            }
            Ok(resp) => {
                warn!(
                    "Transport: backend returned {status} — leaving {n} events in buffer",
                    status = resp.status()
                );
                false
            }
            Err(e) => {
                warn!("Transport: request failed ({e}) — leaving {n} events in buffer");
                false
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn steady_state_uses_the_fixed_flush_interval() {
        assert_eq!(next_delay(0), FLUSH_INTERVAL);
    }

    #[test]
    fn failure_escalates_beyond_the_flush_interval_and_grows() {
        let d1 = next_delay(1);
        let d2 = next_delay(2);
        let d3 = next_delay(3);
        assert!(
            d1 >= FLUSH_INTERVAL,
            "first retry must be >= steady-state interval"
        );
        assert!(d2 > d1, "backoff must grow between consecutive failures");
        assert!(d3 > d2, "backoff must keep growing");
    }

    #[test]
    fn failure_backoff_is_capped() {
        for n in [10, 50, 1000, u32::MAX] {
            let d = next_delay(n);
            assert!(
                d < RETRY_BACKOFF_MAX + Duration::from_secs(1),
                "attempt {n}: {d:?} must stay within max + jitter"
            );
        }
    }

    #[test]
    fn recovering_resets_to_steady_state() {
        // After some failures, a success brings consecutive_failures back to
        // 0 — the caller (Transport::run) is responsible for that reset; here
        // we just confirm next_delay(0) always returns to steady state.
        let _ = next_delay(5);
        assert_eq!(next_delay(0), FLUSH_INTERVAL);
    }
}
