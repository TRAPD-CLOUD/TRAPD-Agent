//! Authenticated event transport.
//!
//! Pulls batches off the in-memory ring buffer and ships them to the backend
//! ingest endpoint.  The TLS posture (rustls, optional CA pinning, optional
//! mTLS) and timeouts are provided by [`crate::http`] so transport, enrollment,
//! heartbeat and config-pull all behave identically.

use std::sync::{Arc, Mutex};

use tokio::time::{interval, Duration};
use tracing::{debug, warn};

use crate::pipeline::RingBuffer;

const FLUSH_INTERVAL: Duration = Duration::from_secs(5);
const BATCH_SIZE: usize = 100;

pub struct Transport {
    buffer:     Arc<Mutex<RingBuffer>>,
    client:     reqwest::Client,
    ingest_url: String,
    token:      String,
}

impl Transport {
    pub fn new(buffer: Arc<Mutex<RingBuffer>>, backend_url: String, token: String) -> Self {
        let base = crate::http::normalize_base_url(&backend_url);
        let ingest_url = format!("{base}/api/v1/ingest/events");
        let client = crate::http::streaming_client();
        Self { buffer, client, ingest_url, token }
    }

    pub async fn run(self) {
        let mut ticker = interval(FLUSH_INTERVAL);
        loop {
            ticker.tick().await;
            self.flush().await;
        }
    }

    async fn flush(&self) {
        let batch = {
            let buf = match self.buffer.lock() {
                Ok(b) => b,
                Err(e) => {
                    warn!("Transport: ring buffer mutex poisoned: {e}");
                    return;
                }
            };
            buf.peek_batch(BATCH_SIZE)
        };

        if batch.is_empty() {
            return;
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
                match self.buffer.lock() {
                    Ok(mut buf) => buf.drain(n),
                    Err(e) => warn!("Transport: ring buffer mutex poisoned on drain: {e}"),
                }
                debug!("Transport: flushed {n} events to backend");
            }
            Ok(resp) => {
                warn!(
                    "Transport: backend returned {status} — leaving {n} events in buffer",
                    status = resp.status()
                );
            }
            Err(e) => {
                warn!("Transport: request failed ({e}) — leaving {n} events in buffer");
            }
        }
    }
}
