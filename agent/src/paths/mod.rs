//! Centralised, `$HOME`-independent filesystem layout.
//!
//! Historically the agent stored its `device_id` and `credentials.json` under
//! `~/.trapd`, resolved via `std::env::var("HOME")`.  Under systemd a service
//! started without `User=` frequently has **no `HOME` set**, so that lookup
//! failed, `main()` bailed, and systemd restarted the agent every few seconds
//! — the single biggest source of "enrollment is unstable".
//!
//! This module removes the `HOME` dependency entirely.  The canonical layout
//! matches established Linux EDR agents:
//!
//! | Kind    | Default            | Override env        | Contents                              |
//! |---------|--------------------|---------------------|---------------------------------------|
//! | state   | `/var/lib/trapd`   | `TRAPD_STATE_DIR`   | `device_id`, `credentials.json`, …    |
//! | config  | `/etc/trapd`       | `TRAPD_CONFIG_DIR`  | `agent.env`, `policy.json`, certs     |
//! | logs    | `/var/log/trapd`   | `TRAPD_LOG_DIR`     | `events.ndjson`                       |
//!
//! Resolution is best-effort and **never panics**.  For the state directory we
//! try the canonical location first; if it is not writable (e.g. the agent is
//! run as a non-root developer) we fall back through XDG/`$HOME` and finally a
//! per-uid `/tmp` directory so the agent always has somewhere to persist its
//! identity.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use anyhow::{Context, Result};
use tracing::{info, warn};

#[cfg(not(windows))]
const DEFAULT_STATE_DIR: &str = "/var/lib/trapd";
#[cfg(not(windows))]
const DEFAULT_CONFIG_DIR: &str = "/etc/trapd";
#[cfg(not(windows))]
const DEFAULT_LOG_DIR: &str = "/var/log/trapd";

// Windows: the canonical machine-wide writable location is %ProgramData%
// (services run as LocalSystem, which has no meaningful $HOME either).
#[cfg(windows)]
const DEFAULT_STATE_DIR: &str = r"C:\ProgramData\trapd\state";
#[cfg(windows)]
const DEFAULT_CONFIG_DIR: &str = r"C:\ProgramData\trapd\config";
#[cfg(windows)]
const DEFAULT_LOG_DIR: &str = r"C:\ProgramData\trapd\logs";

static STATE_DIR: OnceLock<PathBuf> = OnceLock::new();
static CONFIG_DIR: OnceLock<PathBuf> = OnceLock::new();
static LOG_DIR: OnceLock<PathBuf> = OnceLock::new();

/// Writable state directory (device identity, credentials, nonces, baselines).
pub fn state_dir() -> &'static Path {
    STATE_DIR.get_or_init(resolve_state_dir).as_path()
}

/// Read-only configuration directory (env file, policy, TLS material).
pub fn config_dir() -> &'static Path {
    CONFIG_DIR
        .get_or_init(|| dir_from_env("TRAPD_CONFIG_DIR", DEFAULT_CONFIG_DIR))
        .as_path()
}

/// Log directory (NDJSON event log).
pub fn log_dir() -> &'static Path {
    LOG_DIR
        .get_or_init(|| dir_from_env("TRAPD_LOG_DIR", DEFAULT_LOG_DIR))
        .as_path()
}

// ── Well-known files ──────────────────────────────────────────────────────────

pub fn device_id_file() -> PathBuf {
    state_dir().join("device_id")
}
pub fn credentials_file() -> PathBuf {
    state_dir().join("credentials.json")
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn dir_from_env(env: &str, default: &str) -> PathBuf {
    std::env::var(env)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(default))
}

/// Resolve the state directory, preferring the canonical location and falling
/// back to a writable alternative so the agent never fails to start merely
/// because it cannot persist its identity.
fn resolve_state_dir() -> PathBuf {
    // 1. Explicit override always wins (set by the systemd unit).
    if let Ok(dir) = std::env::var("TRAPD_STATE_DIR") {
        if !dir.trim().is_empty() {
            let p = PathBuf::from(dir);
            if ensure_writable(&p) {
                return p;
            }
            warn!(dir = %p.display(), "TRAPD_STATE_DIR is not writable — falling back");
        }
    }

    // 2. Canonical system location.
    let canonical = PathBuf::from(DEFAULT_STATE_DIR);
    if ensure_writable(&canonical) {
        return canonical;
    }

    // 3. XDG state home / $HOME (developer / non-root execution).
    for candidate in xdg_fallbacks() {
        if ensure_writable(&candidate) {
            warn!(
                dir = %candidate.display(),
                "using fallback state dir — {DEFAULT_STATE_DIR} not writable (non-root run?)"
            );
            return candidate;
        }
    }

    // 4. Last resort: a per-uid temp directory.  Identity will not survive a
    //    reboot, but the agent still runs.
    let tmp = std::env::temp_dir().join(format!("trapd-{}", current_uid()));
    let _ = std::fs::create_dir_all(&tmp);
    warn!(dir = %tmp.display(), "using ephemeral state dir — identity will not persist across reboots");
    tmp
}

fn xdg_fallbacks() -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(xdg) = std::env::var("XDG_STATE_HOME") {
        if !xdg.is_empty() {
            out.push(PathBuf::from(xdg).join("trapd"));
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        if !home.is_empty() {
            out.push(PathBuf::from(&home).join(".local/state/trapd"));
            out.push(PathBuf::from(&home).join(".trapd"));
        }
    }
    out
}

/// Create `dir` (recursively) if needed and confirm we can actually write into
/// it.  Returns `false` on any failure rather than propagating an error.
fn ensure_writable(dir: &Path) -> bool {
    if std::fs::create_dir_all(dir).is_err() {
        return false;
    }
    // Probe with a temp file; some paths exist but are not writable for us.
    let probe = dir.join(".trapd_write_probe");
    match std::fs::write(&probe, b"") {
        Ok(_) => {
            let _ = std::fs::remove_file(&probe);
            true
        }
        Err(_) => false,
    }
}

fn current_uid() -> u32 {
    #[cfg(target_os = "linux")]
    {
        // Safe: getuid() always succeeds and has no side effects.
        unsafe { libc::getuid() }
    }
    #[cfg(not(target_os = "linux"))]
    {
        0
    }
}

/// Ensure the state directory exists and is owner-only (`0700`).  Called once at
/// startup; logs but does not fail on permission errors.
pub fn init_state_dir() {
    let dir = state_dir();
    if let Err(e) = std::fs::create_dir_all(dir) {
        warn!(dir = %dir.display(), error = %e, "could not create state dir");
        return;
    }
    harden_dir_perms(dir);
    info!(state = %dir.display(), config = %config_dir().display(), "filesystem layout resolved");
}

#[cfg(target_os = "linux")]
fn harden_dir_perms(dir: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = std::fs::metadata(dir) {
        let mut perms = meta.permissions();
        perms.set_mode(0o700);
        let _ = std::fs::set_permissions(dir, perms);
    }
}

#[cfg(not(target_os = "linux"))]
fn harden_dir_perms(_dir: &Path) {}

/// Atomically write `contents` to `path` (write to a temp file in the same
/// directory, then rename).  On unix the file is created with `mode` and the
/// temp file is cleaned up on failure.  A crash mid-write can never leave a
/// half-written credentials/identity file behind.
pub fn write_atomic(path: &Path, contents: &[u8], mode: u32) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("path has no parent: {}", path.display()))?;
    std::fs::create_dir_all(parent).with_context(|| format!("create dir {}", parent.display()))?;

    let tmp = parent.join(format!(
        ".{}.tmp.{}",
        path.file_name().and_then(|s| s.to_str()).unwrap_or("trapd"),
        std::process::id()
    ));

    let write_result = (|| -> Result<()> {
        std::fs::write(&tmp, contents).with_context(|| format!("write temp {}", tmp.display()))?;
        set_file_mode(&tmp, mode);
        std::fs::rename(&tmp, path)
            .with_context(|| format!("rename {} -> {}", tmp.display(), path.display()))?;
        Ok(())
    })();

    if write_result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    write_result
}

#[cfg(target_os = "linux")]
fn set_file_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode));
}

#[cfg(not(target_os = "linux"))]
fn set_file_mode(_path: &Path, _mode: u32) {}
