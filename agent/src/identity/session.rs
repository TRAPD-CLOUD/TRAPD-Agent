//! Session tokens: the shared bearer source for every authenticated call.
//!
//! Flow (backend wire contract, Phase 09 WP1):
//!
//! 1. `POST identity/bind` (legacy `agent_secret` as bearer) registers the
//!    public key once. On 200 the backend nulls the secret, and the agent
//!    rewrites `credentials.json` without it.
//! 2. `POST session/challenge` -> nonce; sign
//!    `trapd-agent-session-v1\n{agent_id}\n{nonce_b64}`; `POST session` ->
//!    short-lived bearer token.
//!
//! [`SessionTokens::current`] is what every call site uses per request. It is
//! deliberately the only place that knows which credential is in force:
//!
//! * `Legacy`: not bound (yet). The old secret is the bearer, so new agents
//!   keep working against a backend without the identity routes (bind -> 404).
//! * `Session`: bound. Tokens are renewed at 2/3 of their lifetime, and once
//!   after a call site reports a 401 (rate limited).
//! * `Stopped`: the backend refused the bind (409: another key is bound) or
//!   the local key is gone. There is **no** fallback; the agent must be
//!   re-enrolled. The bearer is empty so requests fail closed.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use tokio::time::Instant;
use tracing::{debug, error, info, warn};
use zeroize::Zeroizing;

use super::{session_message, IdentityKey};
use crate::enrollment::Credentials;
use crate::pipeline::backoff;

/// Renew when this fraction (numerator/denominator) of the lifetime has passed.
const RENEW_NUM: u32 = 2;
const RENEW_DEN: u32 = 3;
/// Defensive clamps for a server-supplied lifetime.
const MIN_LIFETIME: Duration = Duration::from_secs(3);
const MAX_LIFETIME: Duration = Duration::from_secs(24 * 3600);
/// A 401 may force a renewal at most this often (a backend that keeps
/// rejecting fresh tokens must not turn every request into a signing round).
const FORCED_RENEW_MIN_GAP: Duration = Duration::from_secs(30);
/// Re-probe `identity/bind` on a backend that answered 404 (rolled out later).
const BIND_REPROBE: Duration = Duration::from_secs(6 * 3600);
/// Floor for backoff after a failure (jitter alone may be ~0).
const MIN_RETRY: Duration = Duration::from_secs(1);

#[derive(Serialize)]
struct BindRequest<'a> {
    public_key: &'a str,
    protection: &'a str,
}

#[derive(Serialize)]
struct SessionRequest<'a> {
    nonce: &'a str,
    signature: &'a str,
}

#[derive(Deserialize)]
struct ChallengeResponse {
    nonce: String,
}

#[derive(Deserialize)]
struct SessionResponse {
    token: String,
    expires_at: String,
}

struct Token {
    value: Zeroizing<String>,
    renew_at: Instant,
}

enum Bind {
    /// Not attempted yet / transient failure; try when `next_attempt` passes.
    Pending,
    /// Backend has no identity routes; re-probe at the given time.
    Unsupported(Instant),
}

enum Mode {
    Legacy {
        secret: Zeroizing<String>,
        bind: Bind,
    },
    Session,
    Stopped,
}

struct State {
    mode: Mode,
    token: Option<Token>,
    fails: u32,
    next_attempt: Instant,
    last_forced: Option<Instant>,
    /// Bound server-side but `credentials.json` still holds the secret.
    rewrite_pending: bool,
    /// The key pre-dates this run, so a previous run may have bound it and
    /// crashed before rewriting credentials: probe a session before binding.
    probe_session_first: bool,
}

struct Net {
    http: reqwest::Client,
    base: String,
    agent_id: String,
    project_id: String,
    /// Where to rewrite credentials; `None` never persists (CLI helpers, tests).
    creds_path: Option<PathBuf>,
    key: Option<Arc<dyn IdentityKey>>,
}

enum SessionError {
    /// 404/405: the backend has no session routes.
    Unsupported,
    /// 401/403: the backend does not accept our signature.
    Rejected(u16),
    Transient(String),
}

/// Shared bearer source. Cheap to clone via `Arc`.
pub struct SessionTokens {
    net: Option<Net>,
    state: Mutex<State>,
}

/// Renewal delay for a token with `lifetime`: 2/3 of it.
fn renew_after(lifetime: Duration) -> Duration {
    lifetime * RENEW_NUM / RENEW_DEN
}

impl SessionTokens {
    /// The identity key this holder signs with, if any (not in offline mode,
    /// not after the identity was stopped). The tamper journal signs with the
    /// same key the backend has bound.
    pub fn identity_key(&self) -> Option<Arc<dyn IdentityKey>> {
        self.net.as_ref().and_then(|n| n.key.clone())
    }

    /// A static bearer without any network behaviour (offline mode, tests).
    pub fn fixed(token: impl Into<String>) -> Arc<Self> {
        Arc::new(Self {
            net: None,
            state: Mutex::new(State::new(Mode::Legacy {
                secret: Zeroizing::new(token.into()),
                bind: Bind::Unsupported(Instant::now()),
            })),
        })
    }

    /// Set up the holder for the running agent: load/create the key, bind when
    /// the credentials still hold the legacy secret. Network work (bind,
    /// sessions) happens lazily inside [`SessionTokens::current`].
    pub fn bootstrap(backend_url: &str, creds: &Credentials) -> Arc<Self> {
        Self::build(backend_url, creds, true)
    }

    /// Holder for short-lived CLI paths (tamper report, maintenance report):
    /// never binds and never rewrites credentials.
    pub fn for_cli(backend_url: &str, creds: &Credentials) -> Arc<Self> {
        Self::build(backend_url, creds, false)
    }

    fn build(backend_url: &str, creds: &Credentials, allow_bind: bool) -> Arc<Self> {
        let http = match crate::http::control_client() {
            Ok(c) => c,
            Err(e) => {
                error!(error = %e, "identity: no secured HTTP client; using the enrollment secret as is");
                return Self::fixed(creds.agent_secret.clone());
            }
        };
        let creds_path = allow_bind.then(crate::paths::credentials_file);
        let (mode, key, probe) = if creds.has_secret() {
            let mut probe = false;
            let key = if allow_bind {
                // Reuse an existing key (a previous run may already have bound
                // it); only mint one when there is none.
                match super::load_existing() {
                    Ok(Some(k)) => {
                        probe = true;
                        Some(k)
                    }
                    Ok(None) => super::load_or_create().map_err(log_key_error).ok(),
                    Err(e) => {
                        log_key_error(e);
                        None
                    }
                }
            } else {
                None
            };
            (
                Mode::Legacy {
                    secret: Zeroizing::new(creds.agent_secret.clone()),
                    bind: if key.is_some() {
                        Bind::Pending
                    } else {
                        Bind::Unsupported(far_future())
                    },
                },
                key,
                probe,
            )
        } else {
            // Bound agent: the key must still exist. Never mint a replacement.
            match super::load_existing() {
                Ok(Some(k)) => (Mode::Session, Some(k), false),
                Ok(None) => {
                    error!(
                        agent_id = %creds.agent_id,
                        "identity key is missing but the backend holds a bound key: this agent \
                         cannot authenticate and must be re-enrolled"
                    );
                    (Mode::Stopped, None, false)
                }
                Err(e) => {
                    error!(error = %e, "identity key cannot be loaded: re-enroll this agent");
                    (Mode::Stopped, None, false)
                }
            }
        };
        let mut state = State::new(mode);
        state.probe_session_first = probe;
        Arc::new(Self {
            net: Some(Net {
                http,
                base: crate::http::normalize_base_url(backend_url),
                agent_id: creds.agent_id.clone(),
                project_id: creds.project_id.clone(),
                creds_path,
                key: key.map(Arc::from),
            }),
            state: Mutex::new(state),
        })
    }

    /// The bearer for the next request. Renews/binds as needed; never panics
    /// and never blocks longer than one HTTP timeout per round.
    pub async fn current(&self) -> String {
        let mut st = self.state.lock().await;
        if matches!(st.mode, Mode::Legacy { .. }) {
            self.maybe_bind(&mut st).await;
        }
        if matches!(st.mode, Mode::Session) {
            self.maybe_renew(&mut st).await;
            if st.rewrite_pending {
                self.try_rewrite(&mut st);
            }
        }
        match &st.mode {
            Mode::Legacy { secret, .. } => secret.to_string(),
            Mode::Session => st
                .token
                .as_ref()
                .map(|t| t.value.to_string())
                .unwrap_or_default(),
            Mode::Stopped => String::new(),
        }
    }

    /// A call site got HTTP 401 with `used`. Forces one renewal on the next
    /// [`SessionTokens::current`] (at most once per [`FORCED_RENEW_MIN_GAP`]).
    pub async fn report_unauthorized(&self, used: &str) {
        let mut st = self.state.lock().await;
        if !matches!(st.mode, Mode::Session) {
            return;
        }
        let now = Instant::now();
        let recent = st
            .last_forced
            .is_some_and(|t| now.duration_since(t) < FORCED_RENEW_MIN_GAP);
        let is_current = st.token.as_ref().is_some_and(|t| t.value.as_str() == used);
        if recent || !is_current {
            return;
        }
        st.last_forced = Some(now);
        if let Some(t) = st.token.as_mut() {
            t.renew_at = now;
        }
        st.next_attempt = now;
        debug!("identity: 401 from the backend, renewing the session token");
    }

    /// Whether the identity was dropped (409 / key lost): needs re-enrollment.
    #[cfg(test)]
    pub async fn is_stopped(&self) -> bool {
        matches!(self.state.lock().await.mode, Mode::Stopped)
    }

    // ── bind ────────────────────────────────────────────────────────────────

    async fn maybe_bind(&self, st: &mut State) {
        let Some(net) = &self.net else { return };
        let Some(key) = net.key.clone() else { return };
        let now = Instant::now();
        match &st.mode {
            Mode::Legacy {
                bind: Bind::Unsupported(until),
                ..
            } if now < *until => return,
            Mode::Legacy { .. } if now < st.next_attempt => return,
            Mode::Legacy { .. } => {}
            _ => return,
        }

        // A previous run may have bound this key and crashed before dropping
        // the secret. The backend no longer accepts the secret then, so ask
        // for a session first.
        if st.probe_session_first {
            st.probe_session_first = false;
            match self.fetch_session(net, &key).await {
                Ok(token) => {
                    info!("identity: key was already bound; dropping the legacy secret");
                    st.token = Some(token);
                    st.mode = Mode::Session;
                    st.rewrite_pending = true;
                    self.try_rewrite(st);
                    return;
                }
                Err(SessionError::Unsupported) => {
                    self.mark_unsupported(st);
                    return;
                }
                Err(_) => {} // not bound yet (or flaky): bind below
            }
        }

        let Mode::Legacy { secret, .. } = &st.mode else {
            return;
        };
        let secret = secret.clone();
        let spki = B64.encode(key.public_key_spki_der());
        let url = format!("{}/api/v1/agents/{}/identity/bind", net.base, net.agent_id);
        let result = net
            .http
            .post(&url)
            .bearer_auth(secret.as_str())
            .json(&BindRequest {
                public_key: &spki,
                protection: key.protection().as_str(),
            })
            .send()
            .await;
        match result.map(|r| r.status().as_u16()) {
            Ok(200) => {
                info!(
                    protection = key.protection().as_str(),
                    "identity: key bound"
                );
                st.mode = Mode::Session;
                st.token = None;
                st.fails = 0;
                st.next_attempt = Instant::now();
                // The backend dropped the secret in the same transaction; the
                // local copy goes now, the file rewrite is retried until done.
                st.rewrite_pending = true;
                self.try_rewrite(st);
            }
            Ok(404 | 405) => self.mark_unsupported(st),
            Ok(409) => {
                error!(
                    agent_id = %net.agent_id,
                    "identity: backend reports a DIFFERENT key already bound to this agent \
                     (possible clone or tampering). Stopping: this agent must be re-enrolled."
                );
                st.mode = Mode::Stopped;
                st.token = None;
            }
            Ok(code) => self.bind_failed(st, &format!("HTTP {code}")),
            Err(e) => self.bind_failed(st, &format!("request error: {e}")),
        }
    }

    fn mark_unsupported(&self, st: &mut State) {
        info!("identity: backend has no identity routes; staying on the legacy secret");
        if let Mode::Legacy { bind, .. } = &mut st.mode {
            *bind = Bind::Unsupported(Instant::now() + BIND_REPROBE);
        }
    }

    fn bind_failed(&self, st: &mut State, why: &str) {
        // The failure is ambiguous: the backend may have committed the bind (and dropped the legacy
        // secret) while the response got lost or timed out. Ask for a session with the local key
        // before the next bind attempt, otherwise the retries would keep using a dead secret.
        st.probe_session_first = true;
        st.fails = st.fails.saturating_add(1);
        let wait = backoff::jittered_delay(st.fails).max(MIN_RETRY);
        st.next_attempt = Instant::now() + wait;
        warn!(
            reason = why,
            retry_in_secs = wait.as_secs(),
            "identity: bind failed"
        );
    }

    /// Rewrite `credentials.json` without the secret (atomic). Only ever
    /// called after the backend confirmed the bind.
    fn try_rewrite(&self, st: &mut State) {
        let Some(net) = &self.net else {
            st.rewrite_pending = false;
            return;
        };
        let Some(path) = &net.creds_path else {
            st.rewrite_pending = false;
            return;
        };
        let creds = Credentials {
            agent_id: net.agent_id.clone(),
            agent_secret: String::new(),
            project_id: net.project_id.clone(),
        };
        match crate::enrollment::write_credentials_at(path, &creds) {
            Ok(()) => st.rewrite_pending = false,
            Err(e) => {
                warn!(error = %e, "identity: could not rewrite credentials without the secret; will retry")
            }
        }
    }

    // ── session ─────────────────────────────────────────────────────────────

    async fn maybe_renew(&self, st: &mut State) {
        let Some(net) = &self.net else { return };
        let Some(key) = net.key.clone() else { return };
        let now = Instant::now();
        let due = st.token.as_ref().is_none_or(|t| now >= t.renew_at);
        if !due || now < st.next_attempt {
            return;
        }
        match self.fetch_session(net, &key).await {
            Ok(token) => {
                st.token = Some(token);
                st.fails = 0;
            }
            Err(e) => {
                st.fails = st.fails.saturating_add(1);
                let wait = backoff::jittered_delay(st.fails).max(MIN_RETRY);
                st.next_attempt = Instant::now() + wait;
                match e {
                    SessionError::Rejected(code) => error!(
                        code,
                        retry_in_secs = wait.as_secs(),
                        "identity: backend rejected the session signature (key changed or agent revoked?)"
                    ),
                    SessionError::Unsupported => error!(
                        retry_in_secs = wait.as_secs(),
                        "identity: backend has no session routes although this agent is bound"
                    ),
                    SessionError::Transient(why) => {
                        warn!(reason = %why, retry_in_secs = wait.as_secs(), "identity: session renewal failed")
                    }
                }
            }
        }
    }

    async fn fetch_session(
        &self,
        net: &Net,
        key: &Arc<dyn IdentityKey>,
    ) -> Result<Token, SessionError> {
        let t = |e: reqwest::Error| SessionError::Transient(e.to_string());
        let base = format!("{}/api/v1/agents/{}", net.base, net.agent_id);

        let resp = net
            .http
            .post(format!("{base}/session/challenge"))
            .json(&serde_json::json!({}))
            .send()
            .await
            .map_err(t)?;
        classify(resp.status().as_u16())?;
        let challenge: ChallengeResponse = resp.json().await.map_err(t)?;

        let msg = session_message(&net.agent_id, &challenge.nonce);
        let key = Arc::clone(key);
        let sig = tokio::task::spawn_blocking(move || key.sign(&msg))
            .await
            .map_err(|e| SessionError::Transient(format!("sign task: {e}")))?
            .map_err(|e| SessionError::Transient(format!("sign: {e:#}")))?;
        let sig = B64.encode(sig);

        let resp = net
            .http
            .post(format!("{base}/session"))
            .json(&SessionRequest {
                nonce: &challenge.nonce,
                signature: &sig,
            })
            .send()
            .await
            .map_err(t)?;
        classify(resp.status().as_u16())?;
        let body: SessionResponse = resp.json().await.map_err(t)?;
        if body.token.is_empty() {
            return Err(SessionError::Transient("empty session token".into()));
        }
        let expires: DateTime<Utc> = DateTime::parse_from_rfc3339(&body.expires_at)
            .map_err(|e| SessionError::Transient(format!("bad expires_at: {e}")))?
            .with_timezone(&Utc);
        let lifetime = (expires - Utc::now())
            .to_std()
            .unwrap_or(Duration::ZERO)
            .clamp(MIN_LIFETIME, MAX_LIFETIME);
        Ok(Token {
            value: Zeroizing::new(body.token),
            renew_at: Instant::now() + renew_after(lifetime),
        })
    }
}

fn classify(code: u16) -> Result<(), SessionError> {
    match code {
        200 => Ok(()),
        404 | 405 => Err(SessionError::Unsupported),
        401 | 403 => Err(SessionError::Rejected(code)),
        other => Err(SessionError::Transient(format!("HTTP {other}"))),
    }
}

impl State {
    fn new(mode: Mode) -> Self {
        Self {
            mode,
            token: None,
            fails: 0,
            next_attempt: Instant::now(),
            last_forced: None,
            rewrite_pending: false,
            probe_session_first: false,
        }
    }
}

fn far_future() -> Instant {
    Instant::now() + Duration::from_secs(10 * 365 * 24 * 3600)
}

fn log_key_error(e: anyhow::Error) {
    error!(error = %e, "identity: no usable key; continuing on the legacy secret");
}

#[cfg(test)]
mod tests;
