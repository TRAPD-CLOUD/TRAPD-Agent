//! Authenticated event transport — HTTP/HTTPS with optional mTLS.
//!
//! ## TLS configuration (loaded from `/etc/trapd/`)
//!
//! | File              | Purpose                                     |
//! |-------------------|---------------------------------------------|
//! | `ca.crt`          | PEM CA certificate to **pin** the backend   |
//! | `agent.crt`       | PEM client certificate for **mTLS**         |
//! | `agent.key`       | PEM private key for the client certificate  |
//!
//! All three files are optional.  When absent the agent falls back to the
//! system trust store (no certificate pinning) and plain bearer-token auth
//! (no mTLS).  Operators SHOULD provision these files for production.
//!
//! ## Certificate pinning
//! Loading `ca.crt` as the *only* trusted root effectively pins the
//! connection to certificates signed by that CA.  Combined with mTLS this
//! gives mutual authentication equivalent to CrowdStrike's mTLS channel.

use std::sync::{Arc, Mutex};

use tokio::time::{interval, Duration};
use tracing::{debug, info, warn};

use crate::pipeline::RingBuffer;

// ── File-system paths for TLS material ───────────────────────────────────────

const CA_CERT_PATH:     &str = "/etc/trapd/ca.crt";
const CLIENT_CERT_PATH: &str = "/etc/trapd/agent.crt";
const CLIENT_KEY_PATH:  &str = "/etc/trapd/agent.key";

// ── Transport ─────────────────────────────────────────────────────────────────

pub struct Transport {
    buffer:     Arc<Mutex<RingBuffer>>,
    client:     reqwest::Client,
    ingest_url: String,
    token:      String,
}

impl Transport {
    pub fn new(buffer: Arc<Mutex<RingBuffer>>, backend_url: String, token: String) -> Self {
        let ingest_url = format!("{backend_url}/api/v1/ingest/events");
        let client = build_client();
        Self { buffer, client, ingest_url, token }
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

// ── Client construction ───────────────────────────────────────────────────────

/// Build a `reqwest::Client` with:
///   - rustls TLS backend (memory-safe, no OpenSSL dependency)
///   - optional CA certificate pinning (`/etc/trapd/ca.crt`)
///   - optional mTLS client identity (`/etc/trapd/agent.{crt,key}`)
///
/// Falls back to a plain client on any TLS configuration error so the agent
/// can still ship events even on misconfigured deployments.
fn build_client() -> reqwest::Client {
    let builder = reqwest::ClientBuilder::new().use_rustls_tls();

    let builder = apply_ca_pinning(builder);
    let builder = apply_mtls_identity(builder);

    builder.build().unwrap_or_else(|e| {
        warn!("Transport: failed to build TLS client ({e}) — falling back to default");
        reqwest::Client::new()
    })
}

/// Add `/etc/trapd/ca.crt` as the *only* trusted root certificate.
///
/// This pins the backend to the specified CA, rejecting any certificate
/// not signed by it — equivalent to HPKP without the header mechanism.
fn apply_ca_pinning(builder: reqwest::ClientBuilder) -> reqwest::ClientBuilder {
    let path = std::path::Path::new(CA_CERT_PATH);
    if !path.exists() {
        return builder;
    }

    match std::fs::read(path) {
        Ok(pem) => match reqwest::Certificate::from_pem(&pem) {
            Ok(cert) => {
                info!(
                    ca = CA_CERT_PATH,
                    "Certificate pinning: custom CA loaded — backend will be verified against this CA only"
                );
                // `add_root_certificate` + no system roots = strict pinning
                builder
                    .tls_built_in_root_certs(false)
                    .add_root_certificate(cert)
            }
            Err(e) => {
                warn!("Certificate pinning: cannot parse {CA_CERT_PATH}: {e} — using system roots");
                builder
            }
        },
        Err(e) => {
            warn!("Certificate pinning: cannot read {CA_CERT_PATH}: {e} — using system roots");
            builder
        }
    }
}

/// Load PEM client certificate + key for mutual TLS authentication.
///
/// Both files must be present; a missing or unreadable file means mTLS is
/// skipped (the connection still uses TLS, just without a client cert).
fn apply_mtls_identity(builder: reqwest::ClientBuilder) -> reqwest::ClientBuilder {
    let cert_path = std::path::Path::new(CLIENT_CERT_PATH);
    let key_path  = std::path::Path::new(CLIENT_KEY_PATH);

    if !cert_path.exists() || !key_path.exists() {
        return builder;
    }

    let cert_pem = match std::fs::read(cert_path) {
        Ok(b)  => b,
        Err(e) => {
            warn!("mTLS: cannot read client certificate {CLIENT_CERT_PATH}: {e}");
            return builder;
        }
    };

    let key_pem = match std::fs::read(key_path) {
        Ok(b)  => b,
        Err(e) => {
            warn!("mTLS: cannot read client key {CLIENT_KEY_PATH}: {e}");
            return builder;
        }
    };

    // reqwest's `Identity::from_pem` expects a PEM buffer containing both the
    // certificate chain and the private key concatenated in any order.
    let mut combined = cert_pem;
    combined.extend_from_slice(b"\n");
    combined.extend_from_slice(&key_pem);

    match reqwest::Identity::from_pem(&combined) {
        Ok(identity) => {
            info!(
                cert = CLIENT_CERT_PATH,
                key  = CLIENT_KEY_PATH,
                "mTLS: client identity loaded — mutual TLS enabled"
            );
            builder.identity(identity)
        }
        Err(e) => {
            warn!("mTLS: cannot build identity from {CLIENT_CERT_PATH} + {CLIENT_KEY_PATH}: {e}");
            builder
        }
    }
}
