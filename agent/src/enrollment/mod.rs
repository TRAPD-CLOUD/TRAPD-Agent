//! Agent enrollment & credential lifecycle.
//!
//! Enrollment is the step most prone to "it won't come online" failures, so it
//! is deliberately defensive:
//!
//! * **Persistent identity** — credentials live in the state directory
//!   (`/var/lib/trapd/credentials.json` by default), resolved via
//!   [`crate::paths`] so it never depends on `$HOME` being set under systemd.
//! * **Transient vs permanent errors** — network errors, timeouts and 5xx /
//!   408 / 429 responses are *retried* with capped exponential backoff; a 4xx
//!   (e.g. an invalid enrollment token) fails fast with a clear message so the
//!   operator fixes the token instead of the agent crash-looping forever.
//! * **No crash-loop** — by retrying transient failures *inside* the process
//!   the agent stays up and waits for the backend to return, rather than
//!   exiting and having systemd restart it every few seconds.
//! * **Atomic, owner-only persistence** — credentials are written via
//!   [`crate::paths::write_atomic`] with mode `0600`; a crash mid-write can
//!   never leave a corrupt credentials file behind.

use std::time::Duration;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tracing::{error, info, warn};

use crate::paths;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credentials {
    pub agent_id: String,
    pub agent_secret: String,
    pub project_id: String,
}

impl Credentials {
    fn is_valid(&self) -> bool {
        !self.agent_id.trim().is_empty() && !self.agent_secret.trim().is_empty()
    }
}

#[derive(Serialize)]
struct EnrollRequest {
    enrollment_token: String,
    device_id: String,
    hostname: String,
    os_version: String,
    arch: String,
    agent_version: String,
}

#[derive(Deserialize)]
struct EnrollResponse {
    agent_id: String,
    agent_secret: String,
    project_id: String,
}

// ── Backoff tuning ──────────────────────────────────────────────────────────
const BACKOFF_BASE: Duration = Duration::from_secs(2);
const BACKOFF_MAX:  Duration = Duration::from_secs(60);

/// Outcome of a single enrollment attempt, used to drive the retry loop.
enum AttemptError {
    /// Worth retrying (network/timeout/5xx/429/parse).  Carries an optional
    /// server-suggested delay (from `Retry-After`).
    Transient { reason: String, retry_after: Option<Duration> },
    /// Not worth retrying (bad token, malformed request, etc.).
    Permanent(String),
}

/// Load persisted credentials, or enroll for the first time.
///
/// Enrollment uses `TRAPD_ENROLL_TOKEN` (one-time token from the dashboard).
/// Transient backend failures are retried with capped exponential backoff;
/// `TRAPD_ENROLL_MAX_ATTEMPTS` bounds the retries (default: unlimited, i.e. the
/// agent waits indefinitely for the backend to come back).
pub async fn load_or_enroll(
    backend_url: &str,
    device_id: &str,
    hostname: &str,
) -> Result<Credentials> {
    // 1. Reuse valid persisted credentials.
    if let Some(creds) = load_persisted().await {
        info!(agent_id = %creds.agent_id, "Loaded persisted credentials");
        return Ok(creds);
    }

    // 2. First-run enrollment requires a token.
    let enroll_token = std::env::var("TRAPD_ENROLL_TOKEN")
        .ok()
        .filter(|t| !t.trim().is_empty())
        .context(
            "No valid credentials in the state directory and TRAPD_ENROLL_TOKEN is not set.\n\
             To enroll this agent set TRAPD_ENROLL_TOKEN=<token from dashboard> \
             (and TRAPD_BACKEND_URL=<url>) and restart.",
        )?;

    let base = crate::http::normalize_base_url(backend_url);
    let enroll_url = format!("{base}/api/v1/agents/enroll");
    let client = crate::http::control_client();
    let max_attempts = max_attempts_from_env();

    info!(backend = %base, "Enrolling agent");

    let mut attempt: u32 = 0;
    loop {
        attempt += 1;
        match try_enroll(&client, &enroll_url, &enroll_token, device_id, hostname).await {
            Ok(creds) => {
                persist(&creds).await?;
                info!(
                    agent_id   = %creds.agent_id,
                    project_id = %creds.project_id,
                    "Agent enrolled successfully — credentials persisted to {}",
                    paths::credentials_file().display()
                );
                return Ok(creds);
            }
            Err(AttemptError::Permanent(msg)) => {
                error!("Enrollment rejected (will not retry): {msg}");
                anyhow::bail!("Enrollment failed permanently: {msg}");
            }
            Err(AttemptError::Transient { reason, retry_after }) => {
                if let Some(max) = max_attempts {
                    if attempt >= max {
                        anyhow::bail!(
                            "Enrollment failed after {attempt} attempts (last: {reason})"
                        );
                    }
                }
                let delay = retry_after.unwrap_or_else(|| backoff(attempt));
                warn!(
                    attempt,
                    retry_in_secs = delay.as_secs(),
                    "Enrollment attempt failed ({reason}) — retrying"
                );
                tokio::time::sleep(delay).await;
            }
        }
    }
}

/// Perform exactly one enrollment HTTP round-trip and classify the outcome.
async fn try_enroll(
    client: &reqwest::Client,
    enroll_url: &str,
    enroll_token: &str,
    device_id: &str,
    hostname: &str,
) -> std::result::Result<Credentials, AttemptError> {
    let req = EnrollRequest {
        enrollment_token: enroll_token.to_string(),
        device_id: device_id.to_string(),
        hostname: hostname.to_string(),
        os_version: read_os_version(),
        arch: std::env::consts::ARCH.to_string(),
        agent_version: env!("CARGO_PKG_VERSION").to_string(),
    };

    let resp = match client.post(enroll_url).json(&req).send().await {
        Ok(r) => r,
        Err(e) => {
            // Connection refused, DNS failure, timeout, TLS error — all transient.
            return Err(AttemptError::Transient {
                reason: format!("request error: {e}"),
                retry_after: None,
            });
        }
    };

    let status = resp.status();
    if status.is_success() {
        return match resp.json::<EnrollResponse>().await {
            Ok(body) => {
                let creds = Credentials {
                    agent_id: body.agent_id,
                    agent_secret: body.agent_secret,
                    project_id: body.project_id,
                };
                if creds.is_valid() {
                    Ok(creds)
                } else {
                    // 200 but empty identity — treat as transient (proxy/LB quirk).
                    Err(AttemptError::Transient {
                        reason: "backend returned empty agent_id/agent_secret".into(),
                        retry_after: None,
                    })
                }
            }
            Err(e) => Err(AttemptError::Transient {
                reason: format!("could not parse enrollment response: {e}"),
                retry_after: None,
            }),
        };
    }

    // Non-2xx: decide transient vs permanent.
    let retry_after = parse_retry_after(&resp);
    let body = resp.text().await.unwrap_or_default();
    let snippet = body.chars().take(300).collect::<String>();
    let code = status.as_u16();

    let transient = status.is_server_error() // 5xx
        || code == 408 // Request Timeout
        || code == 425 // Too Early
        || code == 429; // Too Many Requests

    if transient {
        Err(AttemptError::Transient {
            reason: format!("HTTP {status} — {snippet}"),
            retry_after,
        })
    } else {
        Err(AttemptError::Permanent(format!("HTTP {status} — {snippet}")))
    }
}

// ── Persistence ─────────────────────────────────────────────────────────────

async fn load_persisted() -> Option<Credentials> {
    let path = paths::credentials_file();
    if !path.exists() {
        return None;
    }
    let raw = tokio::fs::read_to_string(&path).await.ok()?;
    match serde_json::from_str::<Credentials>(&raw) {
        Ok(c) if c.is_valid() => Some(c),
        Ok(_) => {
            warn!(path = %path.display(), "credentials file present but invalid — will re-enroll");
            None
        }
        Err(e) => {
            warn!(path = %path.display(), error = %e, "credentials file unparsable — will re-enroll");
            None
        }
    }
}

async fn persist(creds: &Credentials) -> Result<()> {
    let path = paths::credentials_file();
    let content = serde_json::to_vec_pretty(creds).context("serialize credentials")?;
    // Atomic write at mode 0600; run on the blocking pool since it does sync IO.
    let path2 = path.clone();
    tokio::task::spawn_blocking(move || paths::write_atomic(&path2, &content, 0o600))
        .await
        .context("join credential write task")??;
    Ok(())
}

// ── Helpers ─────────────────────────────────────────────────────────────────

fn max_attempts_from_env() -> Option<u32> {
    match std::env::var("TRAPD_ENROLL_MAX_ATTEMPTS") {
        Ok(v) => match v.trim().parse::<u32>() {
            Ok(0) => None, // 0 == unlimited
            Ok(n) => Some(n),
            Err(_) => None,
        },
        Err(_) => None, // default: unlimited (wait for the backend, no crash-loop)
    }
}

/// Capped exponential backoff with deterministic-but-spread jitter.
fn backoff(attempt: u32) -> Duration {
    let exp = BACKOFF_BASE
        .saturating_mul(2u32.saturating_pow(attempt.saturating_sub(1).min(16)));
    let capped = exp.min(BACKOFF_MAX);
    // Add up to ~1s of jitter derived from the wall clock so a fleet of agents
    // restarting together does not hammer the backend in lockstep.
    let jitter_ms = (now_nanos() % 1000) as u64;
    capped + Duration::from_millis(jitter_ms)
}

fn now_nanos() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

fn parse_retry_after(resp: &reqwest::Response) -> Option<Duration> {
    let val = resp.headers().get(reqwest::header::RETRY_AFTER)?;
    let s = val.to_str().ok()?;
    // Only the "delta-seconds" form is supported (the common case for 429/503).
    s.trim().parse::<u64>().ok().map(Duration::from_secs)
}

fn read_os_version() -> String {
    std::fs::read_to_string("/etc/os-release")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("PRETTY_NAME="))
                .map(|l| l["PRETTY_NAME=".len()..].trim_matches('"').to_string())
        })
        .unwrap_or_else(|| "Linux".to_string())
}
