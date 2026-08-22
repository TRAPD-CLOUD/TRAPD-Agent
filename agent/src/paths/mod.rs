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

#[cfg(not(target_os = "windows"))]
const DEFAULT_STATE_DIR: &str = "/var/lib/trapd";
#[cfg(not(target_os = "windows"))]
const DEFAULT_CONFIG_DIR: &str = "/etc/trapd";
#[cfg(not(target_os = "windows"))]
const DEFAULT_LOG_DIR: &str = "/var/log/trapd";

// Windows: everything lives under `%ProgramData%\TRAPD` (the established
// location for machine-wide agent state), resolved at runtime so a relocated
// ProgramData is honoured. The `TRAPD_*_DIR` overrides work identically.
#[cfg(target_os = "windows")]
fn program_data() -> PathBuf {
    std::env::var("ProgramData")
        .or_else(|_| std::env::var("PROGRAMDATA"))
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("C:\\ProgramData"))
}

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
        .get_or_init(|| dir_from_env("TRAPD_CONFIG_DIR", default_config_dir()))
        .as_path()
}

/// Log directory (NDJSON event log).
pub fn log_dir() -> &'static Path {
    LOG_DIR
        .get_or_init(|| dir_from_env("TRAPD_LOG_DIR", default_log_dir()))
        .as_path()
}

// ── Platform default locations ───────────────────────────────────────────────

fn default_state_dir() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        program_data().join("TRAPD").join("state")
    }
    #[cfg(not(target_os = "windows"))]
    {
        PathBuf::from(DEFAULT_STATE_DIR)
    }
}

fn default_config_dir() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        program_data().join("TRAPD").join("config")
    }
    #[cfg(not(target_os = "windows"))]
    {
        PathBuf::from(DEFAULT_CONFIG_DIR)
    }
}

fn default_log_dir() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        program_data().join("TRAPD").join("logs")
    }
    #[cfg(not(target_os = "windows"))]
    {
        PathBuf::from(DEFAULT_LOG_DIR)
    }
}

// ── Well-known files ──────────────────────────────────────────────────────────

pub fn device_id_file() -> PathBuf {
    state_dir().join("device_id")
}
pub fn credentials_file() -> PathBuf {
    state_dir().join("credentials.json")
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn dir_from_env(env: &str, default: PathBuf) -> PathBuf {
    std::env::var(env).map(PathBuf::from).unwrap_or(default)
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
    let canonical = default_state_dir();
    if ensure_writable(&canonical) {
        return canonical;
    }

    // 3. XDG state home / $HOME (developer / non-root execution).
    for candidate in xdg_fallbacks() {
        if ensure_writable(&candidate) {
            warn!(
                dir = %candidate.display(),
                canonical = %canonical.display(),
                "using fallback state dir — canonical location not writable (non-root run?)"
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
        // The temp file is created *already* restricted to `mode` — never
        // world/group-readable for even an instant. Writing with the default
        // (umask-derived) mode and chmod'ing afterward leaves a window where a
        // co-resident local user can read secrets (e.g. credentials.json)
        // mid-write.
        let mut f = create_secure_tmp(&tmp, mode)
            .with_context(|| format!("create secure temp {}", tmp.display()))?;
        use std::io::Write as _;
        f.write_all(contents)
            .with_context(|| format!("write temp {}", tmp.display()))?;
        f.sync_all()
            .with_context(|| format!("fsync temp {}", tmp.display()))?;
        drop(f);
        std::fs::rename(&tmp, path)
            .with_context(|| format!("rename {} -> {}", tmp.display(), path.display()))?;
        Ok(())
    })();

    if write_result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    write_result
}

/// Create `path` fresh, atomically restricted to `mode` from the moment it
/// comes into existence (a single `open(2)` with `O_CREAT|O_EXCL` and the
/// requested mode — no separate `chmod` step, so no window where the file is
/// readable at the umask-derived default mode).
///
/// Any stale leftover at `path` (e.g. from a previous crashed run) is removed
/// first: reusing an existing file via a plain `create(true)` would silently
/// keep its old — possibly permissive — mode bits, since `mode()` only
/// applies when the file is actually created.
#[cfg(target_os = "linux")]
fn create_secure_tmp(path: &Path, mode: u32) -> std::io::Result<std::fs::File> {
    use std::fs::OpenOptions;
    use std::os::unix::fs::OpenOptionsExt;

    let _ = std::fs::remove_file(path);
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)
}

#[cfg(not(target_os = "linux"))]
fn create_secure_tmp(path: &Path, mode: u32) -> std::io::Result<std::fs::File> {
    let _ = std::fs::remove_file(path);
    let f = std::fs::File::create(path)?;
    let _ = mode; // no portable mode-on-create outside unix targets
    Ok(f)
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    fn scratch_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "trapd_paths_test_{}_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            tag,
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// The whole point of the fix: the temp file must come into existence
    /// already restricted to `mode` (a single create-with-mode syscall), never
    /// created world/group-readable and chmod'd afterward — that two-step
    /// sequence is exactly the race a co-resident local user could win.
    #[test]
    fn create_secure_tmp_sets_mode_atomically_before_any_write() {
        let dir = scratch_dir("atomic_mode");
        let path = dir.join("secret.tmp");

        let f = create_secure_tmp(&path, 0o600).expect("create secure tmp");
        let mode = f.metadata().unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "temp file must be created with the restricted mode directly, not chmod'd afterward"
        );

        drop(f);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A stale temp file left over from a previous crashed run (with looser
    /// permissions) must never be silently reused — `create(true)` without
    /// `create_new` would keep the pre-existing (wrong) mode bits.
    #[test]
    fn create_secure_tmp_discards_stale_leftover_with_wrong_mode() {
        let dir = scratch_dir("stale_leftover");
        let path = dir.join("secret.tmp");

        std::fs::write(&path, b"stale").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        let f = create_secure_tmp(&path, 0o600).expect("create secure tmp");
        let mode = f.metadata().unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "stale leftover mode must not survive");

        drop(f);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_atomic_end_to_end_produces_requested_mode_and_content() {
        let dir = scratch_dir("end_to_end");
        let path = dir.join("credentials.json");

        write_atomic(&path, b"{\"a\":1}", 0o600).expect("write_atomic");

        let meta = std::fs::metadata(&path).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        assert_eq!(std::fs::read(&path).unwrap(), b"{\"a\":1}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_atomic_leaves_no_tmp_file_behind_on_success() {
        let dir = scratch_dir("no_tmp_leftover");
        let path = dir.join("credentials.json");

        write_atomic(&path, b"hello", 0o600).expect("write_atomic");

        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp."))
            .collect();
        assert!(
            leftovers.is_empty(),
            "no tmp file should remain: {leftovers:?}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
