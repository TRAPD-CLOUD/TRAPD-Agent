use std::sync::{Arc, Mutex};

use tokio::time::{interval, Duration};
use tracing::{debug, warn};

use crate::pipeline::RingBuffer;

pub struct Transport {
    buffer:     Arc<Mutex<RingBuffer>>,
    client:     reqwest::Client,
    ingest_url: String,
    token:      String,
}

impl Transport {
    pub fn new(buffer: Arc<Mutex<RingBuffer>>, backend_url: String, token: String) -> Self {
        let ingest_url = format!("{backend_url}/api/v1/ingest/events");
        Self {
            buffer,
            client: reqwest::Client::new(),
            ingest_url,
            token,
        }
    }

    pub async fn run(self) {
        let mut ticker = interval(Duration::from_secs(5));
        loop {
            ticker.tick().await;
            self.flush().await;
        }
    }

    async fn flush(&self) {
        let batch = {
            let buf = match self.buffer.lock() {
                Ok(b)  => b,
                Err(e) => {
                    warn!("Transport: ring buffer mutex poisoned: {e}");
                    return;
                }
            };
            buf.peek_batch(100)
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
