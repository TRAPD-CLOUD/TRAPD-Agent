//! Device pairing (RFC 8628-style device flow): lets a person enroll this agent
//! without creating and copy-pasting a one-time enrollment token.
//!
//! 1. `POST /api/v1/agents/pair/start` returns a short `user_code` (shown to the
//!    person), a verification URL and a secret `device_code`.
//! 2. The person signs in to the web UI and confirms the code.
//! 3. The agent polls `POST /api/v1/agents/pair/poll` and receives a normal
//!    enrollment token exactly once, which the existing enroll path then uses.
//!
//! Secrets: `device_code` and the returned enrollment token are never logged,
//! never written to `pairing.txt`, and zeroized on drop. Everything shown to the
//! person comes from the backend over the pinned control channel, but is still
//! validated before it reaches a log line or a file (no control characters, so a
//! hostile response cannot inject terminal escape sequences).

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use tokio::time::Instant;
use tracing::{info, warn};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::{backoff, parse_retry_after, AttemptError};
use crate::paths;

const DEFAULT_INTERVAL_SECS: u64 = 5;
const MIN_INTERVAL_SECS: u64 = 1;
const MAX_INTERVAL_SECS: u64 = 60;
/// RFC 8628 §3.5: add 5 seconds to the interval on `slow_down`.
const SLOW_DOWN_STEP: Duration = Duration::from_secs(5);
const MIN_TTL_SECS: u64 = 60;
const MAX_TTL_SECS: u64 = 1800;
/// A session that ended sooner than this counts as a failed (rapid) restart and
/// is followed by a backoff, so a misbehaving backend cannot cause a hot loop.
const RAPID_RESTART: Duration = Duration::from_secs(30);

// ── Wire types ──────────────────────────────────────────────────────────────

#[derive(Serialize)]
struct StartRequest<'a> {
    device_id: &'a str,
    hostname: &'a str,
}

// No `Debug` derive on purpose: `device_code` must not be printable by accident.
#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
struct StartResponse {
    device_code: String,
    user_code: String,
    verification_uri: String,
    #[serde(default)]
    verification_uri_complete: Option<String>,
    #[zeroize(skip)]
    expires_in: u64,
    #[zeroize(skip)]
    interval: u64,
}

#[derive(Serialize)]
struct PollRequest<'a> {
    device_code: &'a str,
}

#[derive(Deserialize)]
struct PollSuccess {
    enrollment_token: String,
}

#[derive(Deserialize)]
struct PollError {
    error: String,
}

/// A string that must never be printed. `Debug` is redacted.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub(super) struct Secret(String);

impl Secret {
    fn into_string(mut self) -> String {
        std::mem::take(&mut self.0)
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(***)")
    }
}

// ── Validated session ───────────────────────────────────────────────────────

#[derive(Zeroize, ZeroizeOnDrop)]
struct Session {
    device_code: String,
    #[zeroize(skip)]
    user_code: String,
    /// Plain verification page (shown next to the code).
    #[zeroize(skip)]
    verification_uri: String,
    /// Link that prefills the code when the backend supplied a usable one.
    #[zeroize(skip)]
    link: String,
    #[zeroize(skip)]
    interval: Duration,
    #[zeroize(skip)]
    ttl: Duration,
}

/// `ABCDE-FGHJK` / `ABCDEFGHJK`: upper-case alphanumerics and dashes only.
fn is_safe_user_code(code: &str) -> bool {
    !code.is_empty()
        && code.len() <= 32
        && code
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '-')
}

/// http(s) URL without whitespace/control characters, bounded length.
fn is_safe_url(url: &str) -> bool {
    url.len() <= 512
        && (url.starts_with("https://") || url.starts_with("http://"))
        && !url.chars().any(|c| c.is_control() || c.is_whitespace())
}

fn validate_start(resp: StartResponse, base: &str) -> std::result::Result<Session, String> {
    if !is_safe_user_code(&resp.user_code) {
        return Err("backend returned an invalid user_code".into());
    }
    if resp.device_code.is_empty() || resp.device_code.len() > 256 {
        return Err("backend returned an invalid device_code".into());
    }
    // Never trust the URL blindly: fall back to this backend's own /pair page.
    let fallback = format!("{base}/pair");
    let verification_uri = if is_safe_url(&resp.verification_uri) {
        resp.verification_uri.clone()
    } else {
        fallback
    };
    let link = match resp.verification_uri_complete.as_deref() {
        Some(u) if is_safe_url(u) => u.to_string(),
        _ => verification_uri.clone(),
    };
    let interval = if resp.interval == 0 {
        DEFAULT_INTERVAL_SECS
    } else {
        resp.interval.clamp(MIN_INTERVAL_SECS, MAX_INTERVAL_SECS)
    };
    Ok(Session {
        device_code: resp.device_code.clone(),
        user_code: resp.user_code.clone(),
        verification_uri,
        link,
        interval: Duration::from_secs(interval),
        ttl: Duration::from_secs(resp.expires_in.clamp(MIN_TTL_SECS, MAX_TTL_SECS)),
    })
}

// ── Poll classification and state ───────────────────────────────────────────

#[derive(Debug, PartialEq, Eq)]
pub(super) enum PollOutcome {
    Approved(Secret),
    Pending,
    SlowDown,
    /// `expired_token` / `invalid_grant`: this pairing is dead, start a new one.
    Restart,
    RateLimited(Option<Duration>),
    Transient(String),
}

/// Map one poll response to an outcome. Never includes the body in a reason for
/// a 2xx (it carries the enrollment token).
pub(super) fn classify_poll(status: u16, body: &str, retry_after: Option<Duration>) -> PollOutcome {
    match status {
        200 => match serde_json::from_str::<PollSuccess>(body) {
            Ok(ok) if !ok.enrollment_token.trim().is_empty() => {
                PollOutcome::Approved(Secret(ok.enrollment_token))
            }
            _ => PollOutcome::Transient("unusable pairing approval response".into()),
        },
        400 => match serde_json::from_str::<PollError>(body) {
            Ok(e) => match e.error.as_str() {
                "authorization_pending" => PollOutcome::Pending,
                "slow_down" => PollOutcome::SlowDown,
                "expired_token" | "invalid_grant" => PollOutcome::Restart,
                other => PollOutcome::Transient(format!("HTTP 400 ({})", snippet(other))),
            },
            Err(_) => PollOutcome::Transient("HTTP 400 (unparsable error)".into()),
        },
        429 => PollOutcome::RateLimited(retry_after),
        s => PollOutcome::Transient(format!("HTTP {s}")),
    }
}

fn snippet(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).take(40).collect()
}

enum Step {
    Wait(Duration),
    Approved(Secret),
    Restart,
}

/// Pure poll-loop state: what to do after each outcome.
struct PollState {
    interval: Duration,
    failures: u32,
}

impl PollState {
    fn new(interval: Duration) -> Self {
        Self {
            interval,
            failures: 0,
        }
    }

    fn on_outcome(&mut self, outcome: PollOutcome) -> Step {
        match outcome {
            PollOutcome::Approved(t) => Step::Approved(t),
            PollOutcome::Pending => {
                self.failures = 0;
                Step::Wait(self.interval)
            }
            PollOutcome::SlowDown => {
                self.failures = 0;
                self.interval =
                    (self.interval + SLOW_DOWN_STEP).min(Duration::from_secs(MAX_INTERVAL_SECS));
                Step::Wait(self.interval)
            }
            PollOutcome::Restart => Step::Restart,
            PollOutcome::RateLimited(retry_after) => {
                self.failures += 1;
                Step::Wait(
                    retry_after
                        .unwrap_or_else(|| backoff(self.failures))
                        .max(self.interval),
                )
            }
            PollOutcome::Transient(_) => {
                self.failures += 1;
                Step::Wait(backoff(self.failures).max(self.interval))
            }
        }
    }
}

// ── pairing.txt ─────────────────────────────────────────────────────────────

/// Human-readable pairing instructions in the state directory. Holds only the
/// user code, the URL and the expiry — never the device code. Removed on drop,
/// i.e. after success, expiry, restart, error and task cancellation alike.
struct PairingFile {
    path: PathBuf,
}

impl PairingFile {
    async fn publish(path: &Path, session: &Session) -> Result<Self> {
        let expires = chrono::Utc::now()
            + chrono::Duration::from_std(session.ttl).unwrap_or_else(|_| chrono::Duration::zero());
        let text = format!(
            "TRAPD device pairing\n\n\
             1. Open:  {}\n\
             2. Code:  {}\n\n\
             Direct link: {}\n\
             Valid until: {}\n",
            session.verification_uri,
            session.user_code,
            session.link,
            expires.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        );
        let path_buf = path.to_path_buf();
        let target = path_buf.clone();
        // World-readable on purpose: it holds nothing secret and lets a
        // non-root user read the code. Atomic so a reader never sees a torn file.
        tokio::task::spawn_blocking(move || paths::write_atomic(&target, text.as_bytes(), 0o644))
            .await
            .context("join pairing file write task")??;
        Ok(Self { path: path_buf })
    }
}

impl Drop for PairingFile {
    fn drop(&mut self) {
        // A sync remove is fine in Drop; ignore errors (already gone / no perms).
        let _ = std::fs::remove_file(&self.path);
    }
}

// ── Driver ──────────────────────────────────────────────────────────────────

/// Obtain an enrollment token through the device flow. Waits indefinitely for
/// the person to confirm (new pairings are started when one expires); network
/// errors back off and retry, a permanent rejection of `pair/start` is an error.
pub(super) async fn obtain_enrollment_token(
    client: &reqwest::Client,
    base: &str,
    device_id: &str,
    hostname: &str,
) -> Result<String> {
    obtain_with(client, base, device_id, hostname, &paths::pairing_file()).await
}

async fn obtain_with(
    client: &reqwest::Client,
    base: &str,
    device_id: &str,
    hostname: &str,
    pairing_file: &Path,
) -> Result<String> {
    let mut rapid_restarts: u32 = 0;
    loop {
        let session = start_with_retry(client, base, device_id, hostname).await?;
        let started = Instant::now();

        let guard = match PairingFile::publish(pairing_file, &session).await {
            Ok(g) => Some(g),
            Err(e) => {
                // The log line below still tells the person what to do.
                warn!("could not write {}: {e:#}", pairing_file.display());
                None
            }
        };
        info!(
            user_code = %session.user_code,
            url = %session.verification_uri,
            "Pairing required: open the URL, sign in and enter the code to add this device"
        );

        let outcome = poll_until_done(client, base, &session).await;
        drop(guard);
        match outcome {
            Some(token) => {
                info!("Pairing confirmed — enrolling");
                return Ok(token.into_string());
            }
            None => {
                if started.elapsed() < RAPID_RESTART {
                    rapid_restarts += 1;
                    let delay = backoff(rapid_restarts);
                    warn!(
                        retry_in_secs = delay.as_secs(),
                        "Pairing was rejected right away — starting a new one"
                    );
                    tokio::time::sleep(delay).await;
                } else {
                    rapid_restarts = 0;
                    info!("Pairing expired — starting a new one");
                }
            }
        }
    }
}

/// Poll until approved (`Some`) or the session is over (`None`: expired locally
/// or the backend declared it dead).
async fn poll_until_done(
    client: &reqwest::Client,
    base: &str,
    session: &Session,
) -> Option<Secret> {
    let url = format!("{base}/api/v1/agents/pair/poll");
    let deadline = Instant::now() + session.ttl;
    let mut state = PollState::new(session.interval);
    loop {
        if Instant::now() >= deadline {
            return None;
        }
        let outcome = poll_once(client, &url, &session.device_code).await;
        if let PollOutcome::Transient(reason) = &outcome {
            warn!("pairing poll failed ({reason}) — retrying");
        }
        match state.on_outcome(outcome) {
            Step::Approved(t) => return Some(t),
            Step::Restart => return None,
            Step::Wait(d) => tokio::time::sleep(d).await,
        }
    }
}

async fn poll_once(client: &reqwest::Client, url: &str, device_code: &str) -> PollOutcome {
    let resp = match client
        .post(url)
        .json(&PollRequest { device_code })
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => return PollOutcome::Transient(format!("request error: {e}")),
    };
    let status = resp.status().as_u16();
    let retry_after = parse_retry_after(&resp);
    match resp.text().await {
        Ok(body) => classify_poll(status, &body, retry_after),
        Err(e) => PollOutcome::Transient(format!("could not read response: {e}")),
    }
}

async fn start_with_retry(
    client: &reqwest::Client,
    base: &str,
    device_id: &str,
    hostname: &str,
) -> Result<Session> {
    let url = format!("{base}/api/v1/agents/pair/start");
    let mut attempt: u32 = 0;
    loop {
        attempt += 1;
        match try_start(client, &url, base, device_id, hostname).await {
            Ok(s) => return Ok(s),
            Err(AttemptError::Permanent(msg)) => {
                bail!("Pairing was rejected by the backend: {msg}")
            }
            Err(AttemptError::Transient {
                reason,
                retry_after,
            }) => {
                let delay = retry_after.unwrap_or_else(|| backoff(attempt));
                warn!(
                    attempt,
                    retry_in_secs = delay.as_secs(),
                    "Could not start pairing ({reason}) — retrying"
                );
                tokio::time::sleep(delay).await;
            }
        }
    }
}

async fn try_start(
    client: &reqwest::Client,
    url: &str,
    base: &str,
    device_id: &str,
    hostname: &str,
) -> std::result::Result<Session, AttemptError> {
    let resp = client
        .post(url)
        .json(&StartRequest {
            device_id,
            hostname,
        })
        .send()
        .await
        .map_err(|e| AttemptError::Transient {
            reason: format!("request error: {e}"),
            retry_after: None,
        })?;

    let status = resp.status();
    if status.is_success() {
        // The 200 body holds the device_code: parse errors must not echo it.
        let body = resp
            .json::<StartResponse>()
            .await
            .map_err(|_| AttemptError::Transient {
                reason: "could not parse pairing response".into(),
                retry_after: None,
            })?;
        return validate_start(body, base).map_err(|reason| AttemptError::Transient {
            reason,
            retry_after: None,
        });
    }

    let retry_after = parse_retry_after(&resp);
    let code = status.as_u16();
    let body = resp.text().await.unwrap_or_default();
    let reason = format!("HTTP {status} — {}", snippet(&body));
    if status.is_server_error() || matches!(code, 408 | 425 | 429) {
        Err(AttemptError::Transient {
            reason,
            retry_after,
        })
    } else {
        Err(AttemptError::Permanent(reason))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn start_resp(user_code: &str, uri: &str, complete: Option<&str>) -> StartResponse {
        StartResponse {
            device_code: "pair_SECRET".into(),
            user_code: user_code.into(),
            verification_uri: uri.into(),
            verification_uri_complete: complete.map(str::to_string),
            expires_in: 600,
            interval: 5,
        }
    }

    // ── classify_poll ───────────────────────────────────────────────────────

    #[test]
    fn approved_returns_the_token() {
        let out = classify_poll(
            200,
            r#"{"enrollment_token":"enroll_x","project_id":"p-1"}"#,
            None,
        );
        assert_eq!(out, PollOutcome::Approved(Secret("enroll_x".into())));
    }

    #[test]
    fn approved_with_empty_or_garbled_body_is_transient_and_does_not_echo_it() {
        for body in [r#"{"enrollment_token":"  "}"#, "<html>", "{}"] {
            match classify_poll(200, body, None) {
                PollOutcome::Transient(reason) => assert!(!reason.contains(body)),
                other => panic!("expected transient, got {other:?}"),
            }
        }
    }

    #[test]
    fn rfc8628_errors_map_to_outcomes() {
        let e = |name: &str| classify_poll(400, &format!(r#"{{"error":"{name}"}}"#), None);
        assert_eq!(e("authorization_pending"), PollOutcome::Pending);
        assert_eq!(e("slow_down"), PollOutcome::SlowDown);
        assert_eq!(e("expired_token"), PollOutcome::Restart);
        assert_eq!(e("invalid_grant"), PollOutcome::Restart);
        assert!(matches!(e("invalid_request"), PollOutcome::Transient(_)));
        assert!(matches!(
            classify_poll(400, "nope", None),
            PollOutcome::Transient(_)
        ));
    }

    #[test]
    fn rate_limit_carries_retry_after_and_server_errors_are_transient() {
        let ra = Some(Duration::from_secs(17));
        assert_eq!(
            classify_poll(429, r#"{"error":"slow_down"}"#, ra),
            PollOutcome::RateLimited(ra)
        );
        for s in [401, 404, 500, 502, 503] {
            assert!(matches!(
                classify_poll(s, "", None),
                PollOutcome::Transient(_)
            ));
        }
    }

    #[test]
    fn secret_debug_is_redacted() {
        let dbg = format!("{:?}", PollOutcome::Approved(Secret("enroll_leak".into())));
        assert!(!dbg.contains("enroll_leak"), "{dbg}");
    }

    // ── PollState ───────────────────────────────────────────────────────────

    #[test]
    fn pending_waits_the_interval_and_slow_down_grows_it() {
        let mut st = PollState::new(Duration::from_secs(5));
        assert!(matches!(
            st.on_outcome(PollOutcome::Pending),
            Step::Wait(d) if d == Duration::from_secs(5)
        ));
        assert!(matches!(
            st.on_outcome(PollOutcome::SlowDown),
            Step::Wait(d) if d == Duration::from_secs(10)
        ));
        // The longer interval sticks.
        assert!(matches!(
            st.on_outcome(PollOutcome::Pending),
            Step::Wait(d) if d == Duration::from_secs(10)
        ));
    }

    #[test]
    fn slow_down_is_capped() {
        let mut st = PollState::new(Duration::from_secs(58));
        st.on_outcome(PollOutcome::SlowDown);
        assert!(matches!(
            st.on_outcome(PollOutcome::SlowDown),
            Step::Wait(d) if d == Duration::from_secs(MAX_INTERVAL_SECS)
        ));
    }

    #[test]
    fn restart_and_approval_end_the_session() {
        let mut st = PollState::new(Duration::from_secs(5));
        assert!(matches!(st.on_outcome(PollOutcome::Restart), Step::Restart));
        assert!(matches!(
            st.on_outcome(PollOutcome::Approved(Secret("t".into()))),
            Step::Approved(t) if t == Secret("t".into())
        ));
    }

    #[test]
    fn transient_and_rate_limit_back_off_but_never_below_the_interval() {
        let mut st = PollState::new(Duration::from_secs(5));
        for _ in 0..3 {
            assert!(matches!(
                st.on_outcome(PollOutcome::Transient("x".into())),
                Step::Wait(d) if d >= Duration::from_secs(5)
            ));
        }
        assert!(matches!(
            st.on_outcome(PollOutcome::RateLimited(Some(Duration::from_secs(40)))),
            Step::Wait(d) if d == Duration::from_secs(40)
        ));
        // A Retry-After shorter than the interval does not speed polling up.
        assert!(matches!(
            st.on_outcome(PollOutcome::RateLimited(Some(Duration::from_secs(1)))),
            Step::Wait(d) if d == Duration::from_secs(5)
        ));
    }

    // ── validate_start ──────────────────────────────────────────────────────

    #[test]
    fn valid_start_response_is_accepted_and_clamped() {
        let mut r = start_resp("ABCDE-FGHJK", "https://x.example/pair", None);
        r.interval = 0;
        r.expires_in = 99_999;
        let s = validate_start(r, "https://x.example").unwrap();
        assert_eq!(s.interval, Duration::from_secs(DEFAULT_INTERVAL_SECS));
        assert_eq!(s.ttl, Duration::from_secs(MAX_TTL_SECS));
        assert_eq!(s.link, "https://x.example/pair");
    }

    #[test]
    fn hostile_display_fields_are_rejected_or_replaced() {
        // Escape sequences / lower case / spaces in the code are refused.
        for bad in ["\u{1b}[31mX", "abcde", "AB CD", ""] {
            assert!(validate_start(start_resp(bad, "https://x/pair", None), "https://x").is_err());
        }
        // Unsafe URLs fall back to this backend's own /pair page.
        let s = validate_start(
            start_resp(
                "ABCDEFGHJK",
                "javascript:alert(1)",
                Some("https://evil/\u{1b}[2J"),
            ),
            "https://backend.example",
        )
        .unwrap();
        assert_eq!(s.verification_uri, "https://backend.example/pair");
        assert_eq!(s.link, "https://backend.example/pair");
    }

    // ── pairing.txt ─────────────────────────────────────────────────────────

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "trapd_pairing_test_{}_{}_{tag}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[tokio::test]
    async fn pairing_file_has_code_url_expiry_but_never_the_device_code_and_is_removed() {
        let dir = scratch("file");
        let path = dir.join("pairing.txt");
        let session = validate_start(
            start_resp(
                "ABCDE-FGHJK",
                "https://x.example/pair",
                Some("https://x.example/pair?code=ABCDEFGHJK"),
            ),
            "https://x.example",
        )
        .unwrap();

        let guard = PairingFile::publish(&path, &session).await.unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("ABCDE-FGHJK"));
        assert!(text.contains("https://x.example/pair"));
        assert!(text.contains("Valid until:"));
        assert!(!text.contains("pair_SECRET"), "device_code leaked: {text}");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o644);
        }

        drop(guard);
        assert!(!path.exists(), "pairing.txt must be removed on drop");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ── End to end against a local stub backend ─────────────────────────────

    /// Minimal HTTP/1.1 stub: answers each connection with the next canned
    /// response for its path, recording request bodies.
    async fn stub_backend(
        responses: Vec<(&'static str, u16, &'static str)>,
    ) -> (String, std::sync::Arc<std::sync::Mutex<Vec<String>>>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let bodies = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let seen = bodies.clone();
        tokio::spawn(async move {
            let mut queue: std::collections::VecDeque<_> = responses.into();
            while let Ok((mut sock, _)) = listener.accept().await {
                let mut buf = Vec::new();
                let mut tmp = [0u8; 2048];
                let (head_end, content_len) = loop {
                    let n = sock.read(&mut tmp).await.unwrap_or(0);
                    if n == 0 {
                        break (0, 0);
                    }
                    buf.extend_from_slice(&tmp[..n]);
                    if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        let head = String::from_utf8_lossy(&buf[..pos]).to_lowercase();
                        let len = head
                            .lines()
                            .find_map(|l| l.strip_prefix("content-length:"))
                            .and_then(|v| v.trim().parse::<usize>().ok())
                            .unwrap_or(0);
                        break (pos + 4, len);
                    }
                };
                while buf.len() < head_end + content_len {
                    let n = sock.read(&mut tmp).await.unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    buf.extend_from_slice(&tmp[..n]);
                }
                let req = String::from_utf8_lossy(&buf).to_string();
                let path = req
                    .split_whitespace()
                    .nth(1)
                    .unwrap_or_default()
                    .to_string();
                seen.lock()
                    .unwrap()
                    .push(format!("{path} {}", &req[head_end.min(req.len())..]));
                let pos = queue.iter().position(|(p, _, _)| *p == path);
                let (status, body) = match pos.and_then(|i| queue.remove(i)) {
                    Some((_, s, b)) => (s, b),
                    None => (500, "{}"),
                };
                let reply = format!(
                    "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = sock.write_all(reply.as_bytes()).await;
                let _ = sock.shutdown().await;
            }
        });
        (format!("http://{addr}"), bodies)
    }

    #[tokio::test]
    async fn full_flow_start_pending_approved() {
        let start = r#"{"device_code":"pair_SECRET","user_code":"ABCDE-FGHJK",
            "verification_uri":"http://x/pair","verification_uri_complete":"http://x/pair?code=ABCDEFGHJK",
            "expires_in":600,"interval":1}"#;
        let (base, bodies) = stub_backend(vec![
            ("/api/v1/agents/pair/start", 200, start),
            (
                "/api/v1/agents/pair/poll",
                400,
                r#"{"error":"authorization_pending"}"#,
            ),
            (
                "/api/v1/agents/pair/poll",
                200,
                r#"{"enrollment_token":"enroll_ok","project_id":"p-1"}"#,
            ),
        ])
        .await;

        let dir = scratch("flow");
        let file = dir.join("pairing.txt");
        let client = reqwest::Client::new();
        let token = obtain_with(&client, &base, "dev-1", "host-1", &file)
            .await
            .unwrap();

        assert_eq!(token, "enroll_ok");
        assert!(!file.exists(), "pairing.txt must be gone after success");
        let seen = bodies.lock().unwrap().clone();
        assert!(seen[0].starts_with("/api/v1/agents/pair/start"));
        assert!(
            seen[0].contains(r#""device_id":"dev-1""#)
                && seen[0].contains(r#""hostname":"host-1""#)
        );
        assert!(seen[1].contains(r#""device_code":"pair_SECRET""#));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn permanent_start_rejection_is_an_error_not_a_loop() {
        let (base, _) = stub_backend(vec![(
            "/api/v1/agents/pair/start",
            400,
            r#"{"error":"Invalid pairing request"}"#,
        )])
        .await;
        let dir = scratch("reject");
        let err = obtain_with(
            &reqwest::Client::new(),
            &base,
            "d",
            "h",
            &dir.join("pairing.txt"),
        )
        .await
        .unwrap_err();
        assert!(format!("{err:#}").contains("rejected"), "{err:#}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
