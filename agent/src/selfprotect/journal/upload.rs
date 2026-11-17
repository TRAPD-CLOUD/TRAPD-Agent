//! Upload of the tamper journal: `POST /api/v1/agents/{id}/journal` with the
//! session bearer. Entries stay in the local journal until the backend
//! acknowledges them with its `last_seq`/`last_hash`.

use std::sync::Arc;
use std::time::Duration;

use serde::Deserialize;
use serde_json::json;
use tracing::{debug, error, info, warn};

use super::{AckOutcome, Journal};
use crate::identity::SessionTokens;

/// Entries per request (the backend accepts at most 100).
const BATCH: usize = 100;
/// Coalesces a burst of appends into one request.
const SETTLE: Duration = Duration::from_secs(2);
const IDLE_RECHECK: Duration = Duration::from_secs(60);
const RETRY_MIN: Duration = Duration::from_secs(5);
const RETRY_MAX: Duration = Duration::from_secs(15 * 60);
/// Agent not bound yet (legacy secret): the backend refuses journals.
const UNBOUND_RETRY: Duration = Duration::from_secs(5 * 60);
/// Backend without the journal route (rolled out later).
const UNSUPPORTED_RETRY: Duration = Duration::from_secs(6 * 3600);
/// A rejected chain is a fault, not a transient: do not hammer the backend.
const REJECTED_RETRY: Duration = Duration::from_secs(15 * 60);

#[derive(Debug, Deserialize)]
struct AckBody {
    #[serde(default)]
    last_seq: u64,
    #[serde(default)]
    last_hash: String,
    #[serde(default)]
    error: Option<String>,
}

/// What the loop should do after one response.
#[derive(Debug, PartialEq, Eq)]
pub enum Next {
    /// Acknowledged; send more immediately if anything is pending.
    Continue,
    Wait(Duration),
    /// The session token was refused; renew and retry soon.
    Reauth,
}

/// Interpret one backend response. Pure apart from `journal.ack`, so the whole
/// state machine is testable without a server.
pub fn handle_response(journal: &Journal, status: u16, body: &[u8], fails: &mut u32) -> Next {
    let parsed: Option<AckBody> = serde_json::from_slice(body).ok();
    match status {
        200..=299 => {
            let Some(b) = parsed else {
                *fails += 1;
                warn!("journal upload: success without a usable acknowledgement");
                return Next::Wait(backoff(*fails));
            };
            match journal.ack(b.last_seq, &b.last_hash) {
                AckOutcome::Acked => {
                    *fails = 0;
                    Next::Continue
                }
                AckOutcome::Diverged(why) => {
                    error!(
                        why,
                        backend_seq = b.last_seq,
                        "journal diverged from the backend's record"
                    );
                    Next::Wait(REJECTED_RETRY)
                }
            }
        }
        401 => Next::Reauth,
        403 if parsed.as_ref().and_then(|b| b.error.as_deref()) == Some("identity_not_bound") => {
            debug!("journal upload: identity not bound yet");
            Next::Wait(UNBOUND_RETRY)
        }
        404 | 405 => Next::Wait(UNSUPPORTED_RETRY),
        409 | 422 => {
            error!(
                status,
                "backend rejected the tamper journal (fork, regression or bad signature); entries are kept"
            );
            Next::Wait(REJECTED_RETRY)
        }
        429 => Next::Wait(Duration::from_secs(30)),
        _ => {
            *fails += 1;
            warn!(status, "journal upload failed");
            Next::Wait(backoff(*fails))
        }
    }
}

fn backoff(fails: u32) -> Duration {
    let secs = RETRY_MIN.as_secs().saturating_mul(1u64 << fails.min(8));
    Duration::from_secs(secs).min(RETRY_MAX)
}

pub struct Uploader {
    journal: Arc<Journal>,
    tokens: Arc<SessionTokens>,
    client: reqwest::Client,
    url: String,
}

impl Uploader {
    pub fn new(
        journal: Arc<Journal>,
        tokens: Arc<SessionTokens>,
        backend_url: &str,
        agent_id: &str,
    ) -> anyhow::Result<Self> {
        let base = crate::http::normalize_base_url(backend_url);
        Ok(Self {
            journal,
            tokens,
            client: crate::http::control_client()?,
            url: format!("{base}/api/v1/agents/{agent_id}/journal"),
        })
    }

    pub async fn run(self) {
        let mut fails = 0u32;
        let mut wait = SETTLE;
        loop {
            tokio::select! {
                _ = self.journal.notified() => { tokio::time::sleep(SETTLE).await; }
                _ = tokio::time::sleep(wait) => {}
            }
            wait = IDLE_RECHECK;
            while self.journal.has_pending() {
                match self.send_once(&mut fails).await {
                    Next::Continue => continue,
                    Next::Wait(d) => {
                        wait = d;
                        break;
                    }
                    Next::Reauth => {
                        wait = Duration::from_secs(5);
                        break;
                    }
                }
            }
        }
    }

    async fn send_once(&self, fails: &mut u32) -> Next {
        let entries = self.journal.pending(BATCH);
        if entries.is_empty() {
            return Next::Wait(IDLE_RECHECK);
        }
        let bearer = self.tokens.current().await;
        if bearer.is_empty() {
            *fails += 1;
            return Next::Wait(backoff(*fails));
        }
        let resp = self
            .client
            .post(&self.url)
            .bearer_auth(&bearer)
            .json(&json!({ "entries": entries }))
            .send()
            .await;
        match resp {
            Ok(r) => {
                let status = r.status().as_u16();
                let body = r.bytes().await.unwrap_or_default();
                let next = handle_response(&self.journal, status, &body, fails);
                if next == Next::Reauth {
                    self.tokens.report_unauthorized(&bearer).await;
                } else if next == Next::Continue {
                    info!(sent = entries.len(), "tamper journal acknowledged");
                }
                next
            }
            Err(e) => {
                *fails += 1;
                warn!(error = %e, "journal upload request failed");
                Next::Wait(backoff(*fails))
            }
        }
    }
}

/// Open the journal, install it process-wide, record the start and spawn the
/// uploader. Returns `false` when there is no identity key (offline mode,
/// stopped identity) or the journal cannot be opened: the agent then runs
/// without it, which is logged, never fatal.
pub fn start(tokens: &Arc<SessionTokens>, backend_url: &str, agent_id: &str) -> bool {
    let Some(key) = tokens.identity_key() else {
        info!("tamper journal disabled: no identity key");
        return false;
    };
    let journal = match Journal::open(crate::paths::state_dir(), key, super::Limits::default()) {
        Ok(j) => Arc::new(j),
        Err(e) => {
            error!(error = %e, "tamper journal could not be opened; running without it");
            return false;
        }
    };
    if !super::install(Arc::clone(&journal)) {
        return false;
    }
    let life = crate::heartbeat::lifecycle::begin_process();
    super::record(
        "service_start",
        json!({
            "version": env!("CARGO_PKG_VERSION"),
            "pid": std::process::id(),
            "previous_shutdown": life.previous_shutdown(),
        }),
    );
    match Uploader::new(journal, Arc::clone(tokens), backend_url, agent_id) {
        Ok(u) => {
            tokio::spawn(u.run());
            true
        }
        Err(e) => {
            error!(error = %e, "tamper journal uploader could not start");
            false
        }
    }
}
