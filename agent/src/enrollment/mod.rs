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
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::paths;

mod pairing;
pub(crate) mod token_file;

/// Persisted agent identity. `agent_secret` is a long-lived bearer credential
/// (equivalent to a password) for every authenticated backend endpoint, so:
/// - [`std::fmt::Debug`] is implemented by hand to redact it — the derived
///   impl would print it verbatim into any `{:?}`-formatted log line.
/// - The struct zeroizes its memory on drop ([`ZeroizeOnDrop`]) so the secret
///   does not linger in freed heap memory for longer than necessary.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Credentials {
    pub agent_id: String,
    /// Legacy bearer secret. Empty once the agent's identity key is bound
    /// (see [`crate::identity`]); then it is omitted from the file entirely.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub agent_secret: String,
    pub project_id: String,
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credentials")
            .field("agent_id", &self.agent_id)
            .field("agent_secret", &"***")
            .field("project_id", &self.project_id)
            .finish()
    }
}

impl Credentials {
    /// An identity needs an id. The secret is optional: a bound agent
    /// authenticates with its identity key and no longer stores one.
    fn is_valid(&self) -> bool {
        !self.agent_id.trim().is_empty()
    }

    /// Whether the legacy secret is still present (not yet bound).
    pub fn has_secret(&self) -> bool {
        !self.agent_secret.trim().is_empty()
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
const BACKOFF_MAX: Duration = Duration::from_secs(60);

/// Outcome of a single enrollment attempt, used to drive the retry loop.
enum AttemptError {
    /// Worth retrying (network/timeout/5xx/429/parse).  Carries an optional
    /// server-suggested delay (from `Retry-After`).
    Transient {
        reason: String,
        retry_after: Option<Duration>,
    },
    /// Not worth retrying (bad token, malformed request, etc.).
    Permanent(String),
}

/// Load persisted credentials, or enroll for the first time.
///
/// Enrollment uses `TRAPD_ENROLL_TOKEN` (one-time token from the dashboard) or,
/// when that is unset, device pairing (see [`pairing`]): the agent shows a short
/// code (log + `pairing.txt`) that a signed-in user confirms in the web UI.
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

    // 2. First-run enrollment: an explicit one-time token (admin path), or —
    //    when none is configured — interactive device pairing, where a person
    //    confirms a short code in the web UI and the backend hands us a token.
    let env_token = std::env::var("TRAPD_ENROLL_TOKEN")
        .ok()
        .filter(|t| !t.trim().is_empty());

    // The one-time enrollment token has now been captured into a local. Remove
    // it from the process environment so it is no longer exposed via
    // /proc/self/environ for the (potentially long) lifetime of the agent. A
    // leaked token would let an attacker enroll a rogue agent against the same
    // project. We hold the copy we need for the retry loop below.
    //
    // SAFETY: called before any collectors/worker tasks are spawned, while the
    // agent is still single-threaded, so no other thread can be reading the
    // environment concurrently.
    if env_token.is_some() {
        unsafe { std::env::remove_var("TRAPD_ENROLL_TOKEN") };
    }

    let base = crate::http::normalize_base_url(backend_url);
    let enroll_url = format!("{base}/api/v1/agents/enroll");
    // Fail-closed: if the control channel cannot be pinned (no ca.crt and no
    // explicit opt-out) we refuse to enroll over the system trust store rather
    // than send the one-time token to a potentially MITM'd endpoint.
    let client = crate::http::control_client()
        .context("cannot build a secured control-channel client for enrollment")?;
    let enroll_token = match env_token {
        Some(token) => token,
        None => {
            info!("No TRAPD_ENROLL_TOKEN set — starting device pairing");
            pairing::obtain_enrollment_token(&client, &base, device_id, hostname)
                .await
                .context("device pairing failed")?
        }
    };
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
            Err(AttemptError::Transient {
                reason,
                retry_after,
            }) => {
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
                if creds.is_valid() && creds.has_secret() {
                    Ok(creds)
                } else {
                    // 200 but empty identity — treat as transient (proxy/LB quirk).
                    Err(AttemptError::Transient {
                        reason: "backend returned empty agent_id/agent_secret".into(),
                        retry_after: None,
                    })
                }
            }
            Err(_) => Err(AttemptError::Transient {
                reason: "could not parse enrollment response".into(),
                retry_after: None,
            }),
        };
    }

    // Non-2xx: decide transient vs permanent.
    let retry_after = parse_retry_after(&resp);
    let code = status.as_u16();

    let transient = status.is_server_error() // 5xx
        || code == 408 // Request Timeout
        || code == 425 // Too Early
        || code == 429; // Too Many Requests

    if transient {
        Err(AttemptError::Transient {
            reason: format!("HTTP {status}"),
            retry_after,
        })
    } else {
        Err(AttemptError::Permanent(format!("HTTP {status}")))
    }
}

// ── Persistence ─────────────────────────────────────────────────────────────

/// Synchronous read of the persisted identity for short-lived CLI verbs that
/// must never enroll. `None` when absent or invalid.
pub(crate) fn load_persisted_blocking() -> Option<Credentials> {
    let raw = std::fs::read_to_string(paths::credentials_file()).ok()?;
    serde_json::from_str::<Credentials>(&raw)
        .ok()
        .filter(Credentials::is_valid)
}

/// Fail-closed read for the uninstall gate. `Ok(None)` only when the file does
/// not exist (genuinely unenrolled); any other failure (locked, unreadable,
/// invalid JSON, invalid identity) is an `Err`, because an administrator can
/// hold the file open exclusively to make an enrolled agent look unenrolled.
/// Read errors are retried briefly to ride out transient sharing violations.
pub(crate) fn load_persisted_strict_blocking() -> anyhow::Result<Option<Credentials>> {
    const ATTEMPTS: u32 = 8;
    let path = paths::credentials_file();
    let mut last = None;
    for attempt in 0..ATTEMPTS {
        match std::fs::read_to_string(&path) {
            Ok(raw) => return parse_persisted_strict(Ok(raw)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => last = Some(e),
        }
        if attempt + 1 < ATTEMPTS {
            std::thread::sleep(std::time::Duration::from_millis(250));
        }
    }
    parse_persisted_strict(Err(last.expect("at least one attempt")))
}

pub(crate) fn parse_persisted_strict(
    read: std::io::Result<String>,
) -> anyhow::Result<Option<Credentials>> {
    let raw = match read {
        Ok(raw) => raw,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => anyhow::bail!("credentials file is unreadable ({e})"),
    };
    let creds: Credentials = serde_json::from_str(&raw)
        .map_err(|e| anyhow::anyhow!("credentials file is not valid JSON ({e})"))?;
    if !creds.is_valid() {
        anyhow::bail!("credentials file holds an invalid identity");
    }
    Ok(Some(creds))
}

pub(crate) async fn load_persisted() -> Option<Credentials> {
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

/// Atomically (re)write the credentials file at `path`, mode 0600. Used to
/// drop the legacy secret after the identity key was bound.
pub(crate) fn write_credentials_at(path: &std::path::Path, creds: &Credentials) -> Result<()> {
    let content = serde_json::to_vec_pretty(creds).context("serialize credentials")?;
    paths::write_atomic(path, &content, 0o600)
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

/// Capped exponential backoff with CSPRNG jitter.
fn backoff(attempt: u32) -> Duration {
    let exp = BACKOFF_BASE.saturating_mul(2u32.saturating_pow(attempt.saturating_sub(1).min(16)));
    let capped = exp.min(BACKOFF_MAX);
    // Add up to ~1s of jitter so a fleet of agents restarting together (e.g.
    // after a power event) does not clump into the same sub-second retry
    // window. Drawn from the OS CSPRNG rather than the wall clock, which would
    // be near-identical across machines that boot together.
    capped + Duration::from_millis(jitter_ms())
}

/// Uniform-ish jitter in `[0, 1000)` ms from the OS CSPRNG, falling back to the
/// wall clock if the RNG is somehow unavailable (never fails the backoff).
fn jitter_ms() -> u64 {
    let mut buf = [0u8; 8];
    let raw = match getrandom::fill(&mut buf) {
        Ok(()) => u64::from_le_bytes(buf),
        Err(_) => now_nanos() as u64,
    };
    raw % 1000
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

#[cfg(target_os = "linux")]
fn read_os_version() -> String {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_to_string("/etc/os-release")
            .ok()
            .and_then(|s| {
                s.lines()
                    .find(|l| l.starts_with("PRETTY_NAME="))
                    .map(|l| l["PRETTY_NAME=".len()..].trim_matches('"').to_string())
            })
            .unwrap_or_else(|| "Linux".to_string())
    }
    // Windows (and any other OS): the long descriptive name from sysinfo,
    // e.g. "Windows 11 Pro" — so the backend can tell agent platforms apart.
    #[cfg(not(target_os = "linux"))]
    {
        sysinfo::System::long_os_version()
            .or_else(sysinfo::System::name)
            .unwrap_or_else(|| std::env::consts::OS.to_string())
    }
}

#[cfg(not(target_os = "linux"))]
fn read_os_version() -> String {
    // e.g. "Windows 11 Pro" — same role as PRETTY_NAME on Linux.
    sysinfo::System::long_os_version().unwrap_or_else(|| std::env::consts::OS.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_read_only_not_found_means_unenrolled() {
        let nf = std::io::Error::from(std::io::ErrorKind::NotFound);
        assert!(parse_persisted_strict(Err(nf)).unwrap().is_none());
    }

    #[test]
    fn strict_read_fails_closed_on_unreadable_or_invalid() {
        let denied = std::io::Error::from(std::io::ErrorKind::PermissionDenied);
        assert!(parse_persisted_strict(Err(denied)).is_err());
        assert!(parse_persisted_strict(Ok("{not json".into())).is_err());
        assert!(parse_persisted_strict(Ok(String::new())).is_err());
        let blank = r#"{"agent_id":"","agent_secret":"","project_id":"p"}"#;
        assert!(parse_persisted_strict(Ok(blank.into())).is_err());
        let ok = r#"{"agent_id":"a","agent_secret":"s","project_id":"p"}"#;
        assert_eq!(
            parse_persisted_strict(Ok(ok.into()))
                .unwrap()
                .unwrap()
                .agent_id,
            "a"
        );
    }

    #[test]
    fn bound_credentials_have_no_secret_and_still_parse() {
        let bound = Credentials {
            agent_id: "a".into(),
            agent_secret: String::new(),
            project_id: "p".into(),
        };
        let json = serde_json::to_string(&bound).unwrap();
        assert!(!json.contains("agent_secret"), "{json}");
        let parsed = parse_persisted_strict(Ok(json)).unwrap().unwrap();
        assert!(!parsed.has_secret());
    }

    fn sample() -> Credentials {
        Credentials {
            agent_id: "agent-123".to_string(),
            agent_secret: "top-secret-value-do-not-leak".to_string(),
            project_id: "project-abc".to_string(),
        }
    }

    #[test]
    fn debug_redacts_agent_secret_but_not_other_fields() {
        let creds = sample();
        let debug = format!("{creds:?}");

        assert!(
            !debug.contains("top-secret-value-do-not-leak"),
            "agent_secret must never appear in Debug output: {debug}"
        );
        assert!(
            debug.contains("agent-123"),
            "agent_id is not secret and should still be visible: {debug}"
        );
        assert!(
            debug.contains("project-abc"),
            "project_id is not secret and should still be visible: {debug}"
        );
        assert!(
            debug.contains("***") || debug.to_lowercase().contains("redacted"),
            "agent_secret field should show a redaction marker: {debug}"
        );
    }
}
