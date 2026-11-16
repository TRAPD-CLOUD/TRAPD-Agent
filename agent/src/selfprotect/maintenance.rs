//! Maintenance tokens: offline-verifiable authorisation for a sanctioned stop,
//! upgrade or uninstall of this agent (phase 08, WP4).
//!
//! Wire format (version 1), produced by the backend
//! (`frontend/lib/api/maintenance/token.ts`):
//!
//! ```text
//! base64url(payload) "." base64url(signature)         (no padding, <= 1024 bytes)
//! payload   = {"v":1,"agent_id":..,"tenant_id":..,"purpose":..,"nonce":..,"iat":..,"exp":..}
//! signature = Ed25519( "trapd-maintenance-token-v1\0" || payload bytes )
//! ```
//!
//! Trust model:
//!   * The verification key is `maintenance_signing.pub`, a **dedicated** key
//!     (never the release or command key), read from the release key dir (Linux
//!     `/etc/trapd-release`, read-only for the agent unit; Windows `config\`).
//!   * The signature is checked over the received payload bytes **before** the
//!     payload is parsed, so unauthenticated JSON never reaches the parser. The
//!     domain prefix stops a signature made for any other purpose being replayed
//!     as a maintenance token.
//!   * A token is bound to this agent id, one purpose and a lifetime of at most
//!     one hour; a small clock skew is tolerated. The backend's expiry check is
//!     authoritative where it can be consulted; offline hosts rely on this one.
//!   * Single use: the nonce is claimed with an atomic `create_new` file in the
//!     private state dir, so concurrent or repeated use is refused offline.
//!     Consumption is reported to the backend when reachable and retried later
//!     (`report_pending`), so the server-side record catches up.
//!   * The token is only ever read from a file (bounded, no links), never from
//!     argv or the environment, and is never logged.
//!
//! The agent does not know its tenant id, so `tenant_id` is covered by the
//! signature but not compared locally; `agent_id` is globally unique and is.

use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::paths;

pub const TOKEN_VERSION: u32 = 1;
/// Hard cap on the token text; the backend never issues more.
pub const MAX_TOKEN_BYTES: usize = 1024;
/// A token file holds the token plus at most a trailing newline.
const MAX_TOKEN_FILE_BYTES: u64 = MAX_TOKEN_BYTES as u64 + 2;
pub const MAX_TTL_SECS: i64 = 3600;
pub const CLOCK_SKEW_SECS: i64 = 120;
const DOMAIN: &[u8] = b"trapd-maintenance-token-v1\0";
const KEY_FILE: &str = "maintenance_signing.pub";
/// Consumed-nonce records are kept this long after the token expired; a
/// replay after that point fails the expiry check on its own.
const RECORD_RETENTION_SECS: i64 = 24 * 3600;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Purpose {
    Uninstall,
    Stop,
    Upgrade,
}

impl Purpose {
    pub fn as_str(self) -> &'static str {
        match self {
            Purpose::Uninstall => "uninstall",
            Purpose::Stop => "stop",
            Purpose::Upgrade => "upgrade",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "uninstall" => Some(Purpose::Uninstall),
            "stop" => Some(Purpose::Stop),
            "upgrade" => Some(Purpose::Upgrade),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Claims {
    pub v: u32,
    pub agent_id: String,
    pub tenant_id: String,
    pub purpose: Purpose,
    pub nonce: String,
    pub iat: i64,
    pub exp: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyError {
    Oversized,
    Malformed,
    BadSignature,
    BadVersion,
    WrongAgent,
    WrongPurpose,
    NotYetValid,
    Expired,
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            VerifyError::Oversized => "token is too large",
            VerifyError::Malformed => "token is malformed",
            VerifyError::BadSignature => "token signature is invalid",
            VerifyError::BadVersion => "token version is not supported",
            VerifyError::WrongAgent => "token was issued for a different agent",
            VerifyError::WrongPurpose => "token was issued for a different purpose",
            VerifyError::NotYetValid => "token is not valid yet (check the device clock)",
            VerifyError::Expired => "token has expired",
        })
    }
}
impl std::error::Error for VerifyError {}

fn is_nonce(s: &str) -> bool {
    s.len() == 32 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Verify `token` for this agent and purpose at `now` (unix seconds). Pure: no
/// I/O, no replay check (see [`ConsumedStore::claim`]).
pub fn verify_token(
    token: &str,
    key: &VerifyingKey,
    agent_id: &str,
    purpose: Purpose,
    now: i64,
) -> std::result::Result<Claims, VerifyError> {
    if token.len() > MAX_TOKEN_BYTES {
        return Err(VerifyError::Oversized);
    }
    let (payload_b64, sig_b64) = token.split_once('.').ok_or(VerifyError::Malformed)?;
    if sig_b64.contains('.') || payload_b64.is_empty() {
        return Err(VerifyError::Malformed);
    }
    // Strict, canonical base64url: no padding, no stray characters.
    let payload = URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|_| VerifyError::Malformed)?;
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(sig_b64)
        .map_err(|_| VerifyError::Malformed)?;
    let sig_arr: [u8; 64] = sig_bytes.try_into().map_err(|_| VerifyError::Malformed)?;
    let signature = Signature::from_bytes(&sig_arr);

    // Authenticate first. `verify_strict` rejects small-order keys and
    // non-canonical signatures; the check itself runs in constant time.
    let mut message = Vec::with_capacity(DOMAIN.len() + payload.len());
    message.extend_from_slice(DOMAIN);
    message.extend_from_slice(&payload);
    key.verify_strict(&message, &signature)
        .map_err(|_| VerifyError::BadSignature)?;

    let claims: Claims = serde_json::from_slice(&payload).map_err(|_| VerifyError::Malformed)?;
    if claims.v != TOKEN_VERSION {
        return Err(VerifyError::BadVersion);
    }
    if !is_nonce(&claims.nonce)
        || claims.exp <= claims.iat
        || claims.exp - claims.iat > MAX_TTL_SECS
    {
        return Err(VerifyError::Malformed);
    }
    if claims.agent_id != agent_id {
        return Err(VerifyError::WrongAgent);
    }
    if claims.purpose != purpose {
        return Err(VerifyError::WrongPurpose);
    }
    if claims.iat.saturating_sub(CLOCK_SKEW_SECS) > now {
        return Err(VerifyError::NotYetValid);
    }
    if claims.exp <= now.saturating_sub(CLOCK_SKEW_SECS) {
        return Err(VerifyError::Expired);
    }
    Ok(claims)
}

// ── Consumed-nonce store ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ConsumedRecord {
    purpose: Purpose,
    consumed_at: i64,
    exp: i64,
    reported: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ClaimError {
    Replayed,
    Io(String),
}

impl std::fmt::Display for ClaimError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClaimError::Replayed => f.write_str("token was already used on this device"),
            ClaimError::Io(e) => write!(f, "cannot record token use: {e}"),
        }
    }
}
impl std::error::Error for ClaimError {}

/// One file per consumed nonce under `<state>/maintenance/consumed/`. Creating
/// the file with `create_new` is the single-use gate: it is atomic across
/// processes, so two concurrent uses of one token cannot both succeed. The
/// nonce is validated as 32 hex characters before it becomes a file name.
pub struct ConsumedStore {
    dir: PathBuf,
}

impl ConsumedStore {
    pub fn new(state_dir: &Path) -> Self {
        Self {
            dir: state_dir.join("maintenance").join("consumed"),
        }
    }

    fn path_for(&self, nonce: &str) -> io::Result<PathBuf> {
        if !is_nonce(nonce) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid nonce"));
        }
        Ok(self.dir.join(nonce))
    }

    pub fn claim(&self, claims: &Claims, now: i64) -> std::result::Result<(), ClaimError> {
        use std::io::Write as _;
        let io_err = |e: io::Error| ClaimError::Io(e.to_string());
        // Directories this call creates must be made durable too, or a crash
        // after "success" could lose the whole consumed-nonce directory.
        #[cfg(unix)]
        let new_dirs: Vec<PathBuf> = self
            .dir
            .ancestors()
            .take_while(|p| !p.as_os_str().is_empty() && !p.exists())
            .map(Path::to_path_buf)
            .collect();
        std::fs::create_dir_all(&self.dir).map_err(io_err)?;
        let path = self.path_for(&claims.nonce).map_err(io_err)?;
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = match options.open(&path) {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => return Err(ClaimError::Replayed),
            Err(e) => return Err(io_err(e)),
        };
        let record = ConsumedRecord {
            purpose: claims.purpose,
            consumed_at: now,
            exp: claims.exp,
            reported: false,
        };
        let bytes = serde_json::to_vec(&record).map_err(|e| ClaimError::Io(e.to_string()))?;
        file.write_all(&bytes).map_err(io_err)?;
        file.sync_all().map_err(io_err)?;
        // The new directory entry is only durable once the directory is synced
        // (and, for directories created above, their parents). Windows has no
        // directory fsync and NTFS journals metadata, so nothing is done there.
        #[cfg(unix)]
        {
            paths::sync_dir(&self.dir).map_err(io_err)?;
            for dir in &new_dirs {
                let parent = match dir.parent() {
                    Some(p) if !p.as_os_str().is_empty() => p,
                    _ => Path::new("."),
                };
                paths::sync_dir(parent).map_err(io_err)?;
            }
        }
        Ok(())
    }

    /// Whether `nonce` was already used on this device (read-only check).
    #[cfg(any(windows, test))]
    pub fn is_consumed(&self, nonce: &str) -> bool {
        self.path_for(nonce).is_ok_and(|p| p.exists())
    }

    fn read(&self, nonce: &str) -> Option<ConsumedRecord> {
        let bytes = std::fs::read(self.path_for(nonce).ok()?).ok()?;
        serde_json::from_slice(&bytes).ok()
    }

    fn mark_reported(&self, nonce: &str) -> Result<()> {
        let mut record = self.read(nonce).context("consumed record unreadable")?;
        record.reported = true;
        let path = self.path_for(nonce)?;
        paths::write_atomic(&path, &serde_json::to_vec(&record)?, 0o600)
    }

    /// Consumed tokens whose use the backend has not been told about yet.
    fn pending(&self) -> Vec<(String, ConsumedRecord)> {
        let Ok(entries) = std::fs::read_dir(&self.dir) else {
            return Vec::new();
        };
        entries
            .flatten()
            .filter_map(|e| {
                let name = e.file_name().to_str()?.to_owned();
                let record = self.read(&name)?;
                (!record.reported).then_some((name, record))
            })
            .collect()
    }

    /// Drop records of long-expired tokens that the backend already knows about.
    pub fn prune(&self, now: i64) {
        let Ok(entries) = std::fs::read_dir(&self.dir) else {
            return;
        };
        for entry in entries.flatten() {
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            if let Some(r) = self.read(&name) {
                if r.reported && r.exp + RECORD_RETENTION_SECS < now {
                    let _ = std::fs::remove_file(entry.path());
                }
            }
        }
    }
}

// ── Token file + key ─────────────────────────────────────────────────────────

/// Read a token from a file: bounded, regular files only (no links, no devices),
/// ASCII, at most one trailing line ending.
pub fn read_token_file(path: &Path) -> Result<String> {
    let bytes = paths::bounded_regular_bytes(path, MAX_TOKEN_FILE_BYTES)
        .with_context(|| format!("cannot read token file {}", path.display()))?;
    let text = std::str::from_utf8(&bytes).context("token file is not text")?;
    let token = text
        .strip_suffix("\r\n")
        .or_else(|| text.strip_suffix('\n'))
        .unwrap_or(text);
    if token.is_empty() || !token.is_ascii() || token.bytes().any(|b| b.is_ascii_whitespace()) {
        bail!("token file does not contain a single token");
    }
    Ok(token.to_owned())
}

/// The pinned maintenance verification key; fails closed when absent.
pub fn load_pinned_key() -> Result<VerifyingKey> {
    let path = crate::update::release_key_dir().join(KEY_FILE);
    crate::prevention::commands::load_verifying_key(&path)
        .context("maintenance signing key is not provisioned on this device")
}

/// Verify + claim a token from `path` for `purpose`, entirely offline. This is
/// the entry point other verbs (the MSI uninstall custom action) call: success
/// means the token is valid for this agent and has now been consumed.
pub fn authorize_from_file(path: &Path, purpose: Purpose) -> Result<Claims> {
    let creds = crate::enrollment::load_persisted_blocking()
        .context("this agent is not enrolled; no maintenance token can apply")?;
    let key = load_pinned_key()?;
    let token = read_token_file(path)?;
    let now = chrono::Utc::now().timestamp();
    let store = ConsumedStore::new(paths::state_dir());
    authorize(&token, &key, &creds.agent_id, purpose, &store, now)
}

pub(crate) fn authorize(
    token: &str,
    key: &VerifyingKey,
    agent_id: &str,
    purpose: Purpose,
    store: &ConsumedStore,
    now: i64,
) -> Result<Claims> {
    let claims = match verify_token(token, key, agent_id, purpose, now) {
        Ok(c) => c,
        Err(e) => {
            warn!(reason = ?e, "maintenance token rejected");
            return Err(e.into());
        }
    };
    store.claim(&claims, now).inspect_err(|e| {
        warn!(error = %e, "maintenance token not accepted");
    })?;
    info!(
        purpose = claims.purpose.as_str(),
        nonce = %claims.nonce,
        "maintenance token accepted"
    );
    Ok(claims)
}

// ── Reporting ────────────────────────────────────────────────────────────────

#[derive(Serialize)]
struct ConsumeRequest<'a> {
    nonce: &'a str,
    purpose: &'a str,
    used_at: String,
}

/// Tell the backend which tokens were used. 201 (recorded) and 409 (already
/// recorded) are final; anything else keeps the record pending for a retry.
pub async fn report_pending(backend_url: &str, agent_id: &str, secret: &str) {
    let store = ConsumedStore::new(paths::state_dir());
    let pending = store.pending();
    if pending.is_empty() {
        return;
    }
    let Ok(client) = crate::http::control_client() else {
        return;
    };
    let url = format!(
        "{}/api/v1/agents/{agent_id}/maintenance-token/consume",
        crate::http::normalize_base_url(backend_url)
    );
    for (nonce, record) in pending {
        let used_at = chrono::DateTime::from_timestamp(record.consumed_at, 0)
            .map(|t| t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
            .unwrap_or_default();
        let body = ConsumeRequest {
            nonce: &nonce,
            purpose: record.purpose.as_str(),
            used_at,
        };
        let result = client
            .post(&url)
            .bearer_auth(secret)
            .json(&body)
            .send()
            .await;
        match result.map(|r| r.status().as_u16()) {
            Ok(201 | 409) => {
                if let Err(e) = store.mark_reported(&nonce) {
                    warn!(error = %e, "could not mark maintenance use as reported");
                }
            }
            Ok(status) => warn!(status, "backend did not accept maintenance use report"),
            Err(e) => warn!(error = %e, "maintenance use report failed; will retry"),
        }
    }
    store.prune(chrono::Utc::now().timestamp());
}

/// Background retry of unreported uses (offline hosts report on reconnect).
pub fn spawn_pending_report(backend_url: String, agent_id: String, secret: String) {
    tokio::spawn(async move {
        loop {
            report_pending(&backend_url, &agent_id, &secret).await;
            tokio::time::sleep(Duration::from_secs(300)).await;
        }
    });
}

// ── CLI ──────────────────────────────────────────────────────────────────────

/// `trapd-agent maintenance --purpose stop --token-file <path>`
///
/// Parsed strictly: only these two options, each exactly once. A token on the
/// command line (or anything else) is refused, so it can never show up in the
/// process list or in command-line auditing.
pub fn parse_cli(args: &[String]) -> Result<(Purpose, PathBuf)> {
    let mut purpose = None;
    let mut file = None;
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        let slot = match arg.as_str() {
            "--purpose" => {
                let value = it.next().context("--purpose needs a value")?;
                if purpose
                    .replace(Purpose::parse(value).context("unknown purpose")?)
                    .is_some()
                {
                    bail!("--purpose given more than once");
                }
                continue;
            }
            "--token-file" => &mut file,
            _ => bail!(
                "unsupported argument; usage: maintenance --purpose <stop> --token-file <path>"
            ),
        };
        let value = it.next().context("--token-file needs a value")?;
        if slot.replace(PathBuf::from(value)).is_some() {
            bail!("--token-file given more than once");
        }
    }
    Ok((
        purpose.context("--purpose is required")?,
        file.context("--token-file is required")?,
    ))
}

/// The backend URL to report a consumed token to right away, or `None` when
/// the host is in explicit offline mode or has no backend configured.
fn immediate_report_url(offline: bool, backend_url: Option<String>) -> Option<String> {
    if offline {
        return None;
    }
    backend_url.filter(|u| !u.trim().is_empty())
}

/// Run the verb. Only `stop` is wired up in this step; `upgrade` and
/// `uninstall` are consumed by the MSI custom action through
/// [`authorize_from_file`].
pub fn run_cli(args: &[String], stop_service: impl FnOnce() -> Result<()>) -> Result<()> {
    let (purpose, token_file) = parse_cli(args)?;
    if purpose != Purpose::Stop {
        bail!(
            "purpose {:?} is not available through this command",
            purpose.as_str()
        );
    }
    authorize_from_file(&token_file, purpose)?;
    println!(
        "Maintenance token accepted (purpose: {}).",
        purpose.as_str()
    );

    // Report the use now if the backend is reachable; otherwise the running
    // service (or the next start) retries. Best effort and bounded.
    // Explicit offline mode (the predicate the startup paths use) skips the
    // attempt: the record stays pending for a later online start.
    let backend = immediate_report_url(
        crate::env_truthy("TRAPD_OFFLINE"),
        std::env::var("TRAPD_BACKEND_URL").ok(),
    );
    if let (Some(url), Some(creds)) = (backend, crate::enrollment::load_persisted_blocking()) {
        // On Linux this runs inside `#[tokio::main]`, where a nested
        // `block_on` panics after the token was already consumed. A dedicated
        // thread with its own runtime works from both sync and async callers.
        let reported =
            std::thread::spawn(move || {
                match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(rt) => {
                        rt.block_on(report_pending(&url, &creds.agent_id, &creds.agent_secret))
                    }
                    Err(e) => tracing::warn!(error = %e, "maintenance report runtime unavailable"),
                }
            })
            .join();
        if reported.is_err() {
            tracing::warn!("maintenance report thread panicked; the service retries");
        }
    }

    stop_service().context("the token was consumed but the agent could not be stopped")?;
    println!("Agent stop requested.");
    Ok(())
}

// ── Delegated stop (Windows) ─────────────────────────────────────────────────
//
// On Windows the service DACL does not let an administrator stop the service
// (WP2), so the sanctioned stop cannot be "authorise, then call the SCM as the
// administrator". Instead:
//
//   1. `maintenance` (admin) pre-checks the token read-only (signature, agent,
//      purpose, expiry, not yet used) so a bad token fails with a reason, then
//      drops it into `<state>/maintenance/requests/`, a directory the
//      administrator may only add files to, and sends the service the
//      user-defined control `STOP_REQUEST_CONTROL` (allowed to Administrators).
//   2. The service (SYSTEM) re-verifies and *claims* the token itself, against
//      the key in `config\`, which an administrator cannot replace. Only then
//      it stops itself. The request file and the control are not trusted: an
//      administrator who forges either gets nothing, because the signature,
//      agent binding, expiry and single use are all checked by the service.

/// User-defined SCM control (128..=255) meaning "look at the pending
/// maintenance requests". Carries no data.
#[cfg(any(windows, test))]
pub const STOP_REQUEST_CONTROL: u32 = 128;
#[cfg(any(windows, test))]
const MAX_PENDING_REQUESTS: usize = 8;

#[cfg(any(windows, test))]
pub fn requests_dir(state_dir: &Path) -> PathBuf {
    state_dir.join("maintenance").join("requests")
}

/// Service start: create the request directory with the add-only ACL.
#[cfg(windows)]
pub fn prepare_requests_dir() {
    let dir = requests_dir(paths::state_dir());
    if let Err(e) = std::fs::create_dir_all(&dir) {
        warn!(error = %e, "could not create the maintenance request directory");
        return;
    }
    if let Err(e) = crate::winacl::set_dacl(&dir, super::acl_policy::REQUESTS_DIR_SDDL) {
        warn!(error = %e, "could not restrict the maintenance request directory");
    }
}

/// Read-only check of a token before it is handed to the service.
#[cfg(any(windows, test))]
pub fn precheck(
    token: &str,
    key: &VerifyingKey,
    agent_id: &str,
    store: &ConsumedStore,
    now: i64,
) -> Result<Claims> {
    let claims = verify_token(token, key, agent_id, Purpose::Stop, now)?;
    if store.is_consumed(&claims.nonce) {
        return Err(ClaimError::Replayed.into());
    }
    Ok(claims)
}

/// Drop `token` into the request directory under an unpredictable name.
#[cfg(any(windows, test))]
pub fn submit_request(dir: &Path, token: &str) -> Result<PathBuf> {
    use std::io::Write as _;
    let path = dir.join(format!("{}.req", uuid::Uuid::new_v4().simple()));
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .with_context(|| {
            format!(
                "cannot place the request in {} (is the agent service running?)",
                dir.display()
            )
        })?;
    f.write_all(token.as_bytes())?;
    f.sync_all()?;
    Ok(path)
}

/// Service side: consume pending request files and return the claims of the
/// first token that verifies and is claimed. Every file is removed whether or
/// not it was valid, and at most `MAX_PENDING_REQUESTS` are looked at, so a
/// flood of junk cannot keep the handler busy.
#[cfg(any(windows, test))]
pub fn process_requests(
    dir: &Path,
    key: &VerifyingKey,
    agent_id: &str,
    store: &ConsumedStore,
    now: i64,
) -> Option<Claims> {
    let entries = std::fs::read_dir(dir).ok()?;
    let mut accepted = None;
    for entry in entries.flatten().take(MAX_PENDING_REQUESTS) {
        let path = entry.path();
        let read = paths::bounded_regular_bytes(&path, MAX_TOKEN_FILE_BYTES);
        // Remove first: a file that cannot be removed must not be replayed.
        if std::fs::remove_file(&path).is_err() {
            warn!("maintenance request could not be removed; ignored");
            continue;
        }
        if accepted.is_some() {
            continue;
        }
        let Ok(bytes) = read else {
            warn!("maintenance request unreadable or oversized; ignored");
            continue;
        };
        let Ok(token) = std::str::from_utf8(&bytes) else {
            continue;
        };
        if let Ok(claims) = authorize(token.trim(), key, agent_id, Purpose::Stop, store, now) {
            accepted = Some(claims);
        }
    }
    accepted
}

/// Service control handler entry: look at pending requests and say whether the
/// service has been authorised to stop.
#[cfg(windows)]
pub fn authorize_pending_stop() -> bool {
    let Some(creds) = crate::enrollment::load_persisted_blocking() else {
        warn!("maintenance request ignored: agent is not enrolled");
        return false;
    };
    let key = match load_pinned_key() {
        Ok(k) => k,
        Err(e) => {
            warn!(error = %e, "maintenance request ignored");
            return false;
        }
    };
    let store = ConsumedStore::new(paths::state_dir());
    process_requests(
        &requests_dir(paths::state_dir()),
        &key,
        &creds.agent_id,
        &store,
        chrono::Utc::now().timestamp(),
    )
    .is_some()
}

/// `maintenance` verb when the stop is delegated to the service (Windows).
/// `request_stop` sends the control to the service and waits for it to stop.
#[cfg(any(windows, test))]
#[cfg_attr(not(windows), allow(dead_code))] // Windows wires it up; tests exercise the rest
pub fn run_cli_delegated(args: &[String], request_stop: impl FnOnce() -> Result<()>) -> Result<()> {
    let (purpose, token_file) = parse_cli(args)?;
    if purpose != Purpose::Stop {
        bail!(
            "purpose {:?} is not available through this command",
            purpose.as_str()
        );
    }
    let creds = crate::enrollment::load_persisted_blocking()
        .context("this agent is not enrolled; no maintenance token can apply")?;
    let key = load_pinned_key()?;
    let token = read_token_file(&token_file)?;
    let store = ConsumedStore::new(paths::state_dir());
    precheck(
        &token,
        &key,
        &creds.agent_id,
        &store,
        chrono::Utc::now().timestamp(),
    )?;
    println!("Maintenance token looks valid; asking the agent service to verify it and stop.");
    submit_request(&requests_dir(paths::state_dir()), &token)?;
    request_stop().context(
        "the service did not stop; it verifies the token itself and logs the reason in agent.log",
    )?;
    println!("Agent stop requested.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    const NOW: i64 = 1_800_000_000;
    const AGENT: &str = "agent_abc";
    /// Per-process random 32-hex nonces; the deterministic interop vector below
    /// is the only fixed one.
    fn nonce() -> &'static str {
        static N: std::sync::OnceLock<String> = std::sync::OnceLock::new();
        N.get_or_init(|| uuid::Uuid::new_v4().simple().to_string())
    }
    fn other_nonce() -> &'static str {
        static N: std::sync::OnceLock<String> = std::sync::OnceLock::new();
        N.get_or_init(|| uuid::Uuid::new_v4().simple().to_string())
    }

    /// Self-cleaning temp dir (no extra dev-dependency).
    struct TempDir(PathBuf);
    impl TempDir {
        fn path(&self) -> &Path {
            &self.0
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn tmp() -> TempDir {
        let p = std::env::temp_dir().join(format!("trapd-maint-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&p).unwrap();
        TempDir(p)
    }

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    fn payload(v: u32, agent: &str, purpose: &str, nonce: &str, iat: i64, exp: i64) -> String {
        format!(
            r#"{{"v":{v},"agent_id":"{agent}","tenant_id":"11111111-1111-4111-8111-111111111111","purpose":"{purpose}","nonce":"{nonce}","iat":{iat},"exp":{exp}}}"#
        )
    }

    fn sign_with(k: &SigningKey, payload: &str, domain: &[u8]) -> String {
        let mut m = domain.to_vec();
        m.extend_from_slice(payload.as_bytes());
        let sig = k.sign(&m);
        format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(payload),
            URL_SAFE_NO_PAD.encode(sig.to_bytes())
        )
    }

    fn token(purpose: &str, iat: i64, exp: i64) -> String {
        sign_with(
            &key(),
            &payload(1, AGENT, purpose, nonce(), iat, exp),
            DOMAIN,
        )
    }

    fn verify(t: &str, purpose: Purpose, now: i64) -> std::result::Result<Claims, VerifyError> {
        verify_token(t, &key().verifying_key(), AGENT, purpose, now)
    }

    #[test]
    fn roundtrip_accepts_a_valid_token() {
        let c = verify(&token("stop", NOW, NOW + 900), Purpose::Stop, NOW + 10).unwrap();
        assert_eq!(c.agent_id, AGENT);
        assert_eq!(c.nonce, nonce());
        assert_eq!(c.purpose, Purpose::Stop);
    }

    #[test]
    fn interoperates_with_the_backend_signer() {
        // Produced by frontend/scripts/test-maintenance-token.ts (seed [7;32]).
        let t = "eyJ2IjoxLCJhZ2VudF9pZCI6ImFnZW50X2FiYyIsInRlbmFudF9pZCI6IjExMTExMTExLTExMTEtNDExMS04MTExLTExMTExMTExMTExMSIsInB1cnBvc2UiOiJzdG9wIiwibm9uY2UiOiIwMTIzNDU2Nzg5YWJjZGVmMDEyMzQ1Njc4OWFiY2RlZiIsImlhdCI6MTgwMDAwMDAwMCwiZXhwIjoxODAwMDAwOTAwfQ.x8lV7chAjVUM-4zHg4xh9XSXznFr8fhO_ihJBv6HJ6XbJi47HZhcaCTDt2ayHTMmH-KBX8qn8HJPw0eHILoGBA";
        let expected_pub = "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c";
        assert_eq!(hex::encode(key().verifying_key().to_bytes()), expected_pub);
        let c = verify(t, Purpose::Stop, NOW + 1).unwrap();
        assert_eq!(c.exp, NOW + 900);
    }

    #[test]
    fn rejects_wrong_agent_and_purpose() {
        let t = token("stop", NOW, NOW + 900);
        assert_eq!(
            verify_token(
                &t,
                &key().verifying_key(),
                "agent_other",
                Purpose::Stop,
                NOW
            ),
            Err(VerifyError::WrongAgent)
        );
        assert_eq!(
            verify(&t, Purpose::Uninstall, NOW),
            Err(VerifyError::WrongPurpose)
        );
        assert_eq!(
            verify(&t, Purpose::Upgrade, NOW),
            Err(VerifyError::WrongPurpose)
        );
    }

    #[test]
    fn rejects_expired_and_not_yet_valid_with_small_skew() {
        let t = token("stop", NOW, NOW + 900);
        assert_eq!(
            verify(&t, Purpose::Stop, NOW + 900 + 121),
            Err(VerifyError::Expired)
        );
        assert!(
            verify(&t, Purpose::Stop, NOW + 900 + 100).is_ok(),
            "skew allowed"
        );
        assert_eq!(
            verify(&t, Purpose::Stop, NOW - 121),
            Err(VerifyError::NotYetValid)
        );
        assert!(verify(&t, Purpose::Stop, NOW - 100).is_ok(), "skew allowed");
    }

    #[test]
    fn rejects_bad_signature_other_key_and_tampered_payload() {
        let t = token("stop", NOW, NOW + 900);
        let other = SigningKey::from_bytes(&[8u8; 32]).verifying_key();
        assert_eq!(
            verify_token(&t, &other, AGENT, Purpose::Stop, NOW),
            Err(VerifyError::BadSignature)
        );
        let (p, s) = t.split_once('.').unwrap();
        let tampered = String::from_utf8(URL_SAFE_NO_PAD.decode(p).unwrap())
            .unwrap()
            .replace("stop", "upgr");
        let forged = format!("{}.{s}", URL_SAFE_NO_PAD.encode(tampered));
        assert_eq!(
            verify(&forged, Purpose::Stop, NOW),
            Err(VerifyError::BadSignature)
        );
        // Bit-flipped signature.
        let mut sig = URL_SAFE_NO_PAD.decode(s).unwrap();
        sig[0] ^= 1;
        let flipped = format!("{p}.{}", URL_SAFE_NO_PAD.encode(sig));
        assert_eq!(
            verify(&flipped, Purpose::Stop, NOW),
            Err(VerifyError::BadSignature)
        );
    }

    #[test]
    fn signature_without_the_domain_prefix_is_rejected() {
        let p = payload(1, AGENT, "stop", nonce(), NOW, NOW + 900);
        let bare = sign_with(&key(), &p, b"");
        assert_eq!(
            verify(&bare, Purpose::Stop, NOW),
            Err(VerifyError::BadSignature)
        );
        let other_domain = sign_with(&key(), &p, b"trapd-command-v1\0");
        assert_eq!(
            verify(&other_domain, Purpose::Stop, NOW),
            Err(VerifyError::BadSignature)
        );
    }

    #[test]
    fn rejects_wrong_version_even_when_correctly_signed() {
        let t = sign_with(
            &key(),
            &payload(2, AGENT, "stop", nonce(), NOW, NOW + 900),
            DOMAIN,
        );
        assert_eq!(verify(&t, Purpose::Stop, NOW), Err(VerifyError::BadVersion));
    }

    #[test]
    fn rejects_oversized_and_malformed_input() {
        assert_eq!(
            verify(&"a".repeat(MAX_TOKEN_BYTES + 1), Purpose::Stop, NOW),
            Err(VerifyError::Oversized)
        );
        for bad in ["", ".", "abc", "a.b", "a.b.c", "!!.!!", "AAAA.", ".AAAA"] {
            assert_eq!(
                verify(bad, Purpose::Stop, NOW),
                Err(VerifyError::Malformed),
                "{bad}"
            );
        }
        let t = token("stop", NOW, NOW + 900);
        let (p, s) = t.split_once('.').unwrap();
        // Padding and a standard-alphabet character are not canonical base64url.
        assert_eq!(
            verify(&format!("{p}=.{s}"), Purpose::Stop, NOW),
            Err(VerifyError::Malformed)
        );
        assert_eq!(
            verify(&format!("{p}.{s}.x"), Purpose::Stop, NOW),
            Err(VerifyError::Malformed)
        );
        // Short signature.
        assert_eq!(
            verify(&format!("{p}.AAAA"), Purpose::Stop, NOW),
            Err(VerifyError::Malformed)
        );
    }

    #[test]
    fn rejects_signed_but_structurally_invalid_claims() {
        let cases = [
            // Not JSON.
            "not json".to_string(),
            // Unknown field.
            format!(
                r#"{{"v":1,"agent_id":"{AGENT}","tenant_id":"t","purpose":"stop","nonce":"{}","iat":{NOW},"exp":{},"admin":true}}"#,
                nonce(),
                NOW + 900
            ),
            // Bad nonce.
            payload(1, AGENT, "stop", "SHORT", NOW, NOW + 900),
            // Unknown purpose.
            payload(1, AGENT, "reboot", nonce(), NOW, NOW + 900),
            // Lifetime over one hour / inverted.
            payload(1, AGENT, "stop", nonce(), NOW, NOW + MAX_TTL_SECS + 1),
            payload(1, AGENT, "stop", nonce(), NOW, NOW),
        ];
        for p in cases {
            let t = sign_with(&key(), &p, DOMAIN);
            assert_eq!(
                verify(&t, Purpose::Stop, NOW + 1),
                Err(VerifyError::Malformed),
                "{p}"
            );
        }
    }

    fn claims_of(t: &str) -> Claims {
        verify(t, Purpose::Stop, NOW + 1).unwrap()
    }

    #[test]
    fn replay_is_refused_offline_and_survives_a_new_store_handle() {
        let dir = tmp();
        let c = claims_of(&token("stop", NOW, NOW + 900));
        let store = ConsumedStore::new(dir.path());
        store.claim(&c, NOW).unwrap();
        assert_eq!(store.claim(&c, NOW + 5), Err(ClaimError::Replayed));
        // A restart (fresh handle on the same state dir) still refuses.
        assert_eq!(
            ConsumedStore::new(dir.path()).claim(&c, NOW + 9),
            Err(ClaimError::Replayed)
        );
    }

    #[test]
    fn authorize_verifies_then_claims_exactly_once() {
        let dir = tmp();
        let store = ConsumedStore::new(dir.path());
        let t = token("stop", NOW, NOW + 900);
        let vk = key().verifying_key();
        assert!(authorize(&t, &vk, AGENT, Purpose::Stop, &store, NOW + 1).is_ok());
        let again = authorize(&t, &vk, AGENT, Purpose::Stop, &store, NOW + 2).unwrap_err();
        assert!(again.to_string().contains("already used"), "{again:#}");
        // A rejected token never burns a nonce.
        let t2 = sign_with(
            &key(),
            &payload(1, AGENT, "stop", other_nonce(), NOW, NOW + 900),
            DOMAIN,
        );
        assert!(authorize(&t2, &vk, "agent_other", Purpose::Stop, &store, NOW + 1).is_err());
        assert!(authorize(&t2, &vk, AGENT, Purpose::Stop, &store, NOW + 1).is_ok());
    }

    #[test]
    fn explicit_offline_mode_skips_the_immediate_report() {
        let url = Some("https://backend.example".to_string());
        assert_eq!(immediate_report_url(true, url.clone()), None);
        assert_eq!(immediate_report_url(false, url.clone()), url);
        assert_eq!(immediate_report_url(false, Some("  ".into())), None);
        assert_eq!(immediate_report_url(false, None), None);
    }

    #[test]
    fn a_claimed_token_stays_pending_until_reported() {
        // Offline: no report is attempted, so the record must still be pending
        // for a later online start.
        let dir = tmp();
        let store = ConsumedStore::new(dir.path());
        store
            .claim(&claims_of(&token("stop", NOW, NOW + 900)), NOW)
            .unwrap();
        assert_eq!(
            immediate_report_url(true, Some("https://b.example".into())),
            None
        );
        let pending = store.pending();
        assert_eq!(pending.len(), 1);
        assert!(!pending[0].1.reported);
    }

    #[cfg(unix)]
    #[test]
    fn claim_creates_missing_directories_and_persists_the_record() {
        let dir = tmp();
        let nested = dir.path().join("a").join("b").join("consumed");
        let store = ConsumedStore::new(&nested);
        store
            .claim(&claims_of(&token("stop", NOW, NOW + 900)), NOW)
            .unwrap();
        assert!(store.read(nonce()).is_some());
    }

    #[test]
    fn concurrent_claims_of_one_nonce_succeed_exactly_once() {
        let dir = tmp();
        let c = claims_of(&token("stop", NOW, NOW + 900));
        let path = dir.path().to_path_buf();
        let wins: usize = (0..8)
            .map(|_| {
                let (path, c) = (path.clone(), c.clone());
                std::thread::spawn(move || ConsumedStore::new(&path).claim(&c, NOW).is_ok())
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|h| usize::from(h.join().unwrap()))
            .sum();
        assert_eq!(wins, 1);
    }

    #[test]
    fn pending_reports_until_marked_and_prune_keeps_unreported() {
        let dir = tmp();
        let store = ConsumedStore::new(dir.path());
        let c = claims_of(&token("stop", NOW, NOW + 900));
        store.claim(&c, NOW).unwrap();
        assert_eq!(store.pending().len(), 1);
        let far = NOW + 900 + RECORD_RETENTION_SECS + 10;
        store.prune(far);
        assert_eq!(
            store.pending().len(),
            1,
            "unreported records are never pruned"
        );
        store.mark_reported(nonce()).unwrap();
        assert!(store.pending().is_empty());
        store.prune(NOW + 1000);
        assert!(store.read(nonce()).is_some(), "recent reported record kept");
        store.prune(far);
        assert!(store.read(nonce()).is_none(), "old reported record pruned");
    }

    #[test]
    fn store_never_builds_paths_from_unvalidated_nonces() {
        let store = ConsumedStore::new(Path::new("/nonexistent"));
        for bad in [
            "../x",
            "",
            "A".repeat(32).as_str(),
            "a/b",
            "0123456789abcdef0123456789abcde",
        ] {
            assert!(store.path_for(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn token_file_is_bounded_regular_and_single_token() {
        let dir = tmp();
        let ok = dir.path().join("t");
        std::fs::write(&ok, "abc.def\n").unwrap();
        assert_eq!(read_token_file(&ok).unwrap(), "abc.def");
        std::fs::write(&ok, "abc.def\r\n").unwrap();
        assert_eq!(read_token_file(&ok).unwrap(), "abc.def");
        for bad in ["", "\n", "a b", "a\nb", "ü"] {
            std::fs::write(&ok, bad).unwrap();
            assert!(read_token_file(&ok).is_err(), "{bad:?}");
        }
        std::fs::write(&ok, "a".repeat(MAX_TOKEN_BYTES + 3)).unwrap();
        assert!(read_token_file(&ok).is_err(), "oversized");
        assert!(read_token_file(&dir.path().join("missing")).is_err());
        assert!(read_token_file(dir.path()).is_err(), "directory");
    }

    #[cfg(unix)]
    #[test]
    fn token_file_refuses_symlinks() {
        let dir = tmp();
        let real = dir.path().join("real");
        std::fs::write(&real, "abc.def").unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(read_token_file(&link).is_err());
    }

    fn args(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn cli_accepts_only_purpose_and_token_file() {
        let (p, f) = parse_cli(&args(&["--purpose", "stop", "--token-file", "/t"])).unwrap();
        assert_eq!((p, f), (Purpose::Stop, PathBuf::from("/t")));
        let (p, _) = parse_cli(&args(&["--token-file", "/t", "--purpose", "uninstall"])).unwrap();
        assert_eq!(p, Purpose::Uninstall);
        for bad in [
            vec![],
            vec!["--purpose", "stop"],
            vec!["--token-file", "/t"],
            vec![
                "--purpose",
                "stop",
                "--token",
                "abc.def",
                "--token-file",
                "/t",
            ],
            vec!["--purpose", "stop", "abc.def", "--token-file", "/t"],
            vec!["--purpose", "reboot", "--token-file", "/t"],
            vec![
                "--purpose",
                "stop",
                "--purpose",
                "stop",
                "--token-file",
                "/t",
            ],
            vec![
                "--purpose",
                "stop",
                "--token-file",
                "/a",
                "--token-file",
                "/b",
            ],
            vec!["--purpose"],
        ] {
            assert!(parse_cli(&args(&bad)).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn run_cli_refuses_other_purposes_without_touching_anything() {
        let called = std::cell::Cell::new(false);
        let r = run_cli(
            &args(&["--purpose", "uninstall", "--token-file", "/nope"]),
            || {
                called.set(true);
                Ok(())
            },
        );
        assert!(r.is_err());
        assert!(!called.get());
    }

    // ── delegated stop ──
    #[test]
    fn service_claims_a_submitted_token_exactly_once() {
        let dir = tmp();
        let requests = requests_dir(dir.path());
        std::fs::create_dir_all(&requests).unwrap();
        let store = ConsumedStore::new(dir.path());
        let vk = key().verifying_key();
        let t = token("stop", NOW, NOW + 900);

        precheck(&t, &vk, AGENT, &store, NOW + 1).expect("fresh token passes the pre-check");
        submit_request(&requests, &t).unwrap();
        let claims = process_requests(&requests, &vk, AGENT, &store, NOW + 2).expect("accepted");
        assert_eq!(claims.purpose, Purpose::Stop);
        assert_eq!(
            std::fs::read_dir(&requests).unwrap().count(),
            0,
            "request removed"
        );

        // The pre-check now refuses it, and a resubmission is not accepted.
        assert!(precheck(&t, &vk, AGENT, &store, NOW + 3).is_err());
        submit_request(&requests, &t).unwrap();
        assert!(process_requests(&requests, &vk, AGENT, &store, NOW + 4).is_none());
        assert_eq!(std::fs::read_dir(&requests).unwrap().count(), 0);
    }

    #[test]
    fn service_ignores_forged_foreign_expired_and_junk_requests() {
        let dir = tmp();
        let requests = requests_dir(dir.path());
        std::fs::create_dir_all(&requests).unwrap();
        let store = ConsumedStore::new(dir.path());
        let vk = key().verifying_key();
        let forger = SigningKey::from_bytes(&[9u8; 32]);

        let forged = sign_with(
            &forger,
            &payload(1, AGENT, "stop", other_nonce(), NOW, NOW + 900),
            DOMAIN,
        );
        let foreign = sign_with(
            &key(),
            &payload(1, "agent_other", "stop", other_nonce(), NOW, NOW + 900),
            DOMAIN,
        );
        let expired = token("stop", NOW - 5000, NOW - 4000);
        for body in [
            forged.as_str(),
            foreign.as_str(),
            expired.as_str(),
            "not a token",
            "",
        ] {
            submit_request(&requests, body).unwrap();
        }
        std::fs::write(requests.join("big.req"), "a".repeat(5000)).unwrap();
        assert!(process_requests(&requests, &vk, AGENT, &store, NOW + 1).is_none());
        assert_eq!(
            std::fs::read_dir(&requests).unwrap().count(),
            0,
            "all removed"
        );
        assert!(!store.is_consumed(other_nonce()), "nothing was consumed");
    }

    #[test]
    fn a_flood_of_requests_is_bounded() {
        let dir = tmp();
        let requests = requests_dir(dir.path());
        std::fs::create_dir_all(&requests).unwrap();
        let store = ConsumedStore::new(dir.path());
        let vk = key().verifying_key();
        for _ in 0..(MAX_PENDING_REQUESTS + 5) {
            submit_request(&requests, "junk").unwrap();
        }
        let _ = process_requests(&requests, &vk, AGENT, &store, NOW);
        assert_eq!(std::fs::read_dir(&requests).unwrap().count(), 5);
    }

    #[test]
    fn stop_request_control_is_in_the_user_defined_range() {
        assert!((128..=255).contains(&STOP_REQUEST_CONTROL));
    }
}
