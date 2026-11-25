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
/// Human-readable device-pairing instructions (user code + URL, no secrets).
pub fn pairing_file() -> PathBuf {
    state_dir().join("pairing.txt")
}

/// Shared by startup integrity checks and the cross-platform update helper.
pub(crate) fn binary_baseline_line(hash_hex: &str) -> String {
    format!("sha256:{hash_hex}")
}

/// Open an untrusted on-disk file for bounded reading. Links, reparse points
/// and special files are refused before any content is read.
fn open_bounded_regular(path: &Path, max_bytes: u64) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // Open the reparse point itself rather than its target. Metadata below
        // rejects reparse points, including junctions, before any content read.
        options.custom_flags(0x0020_0000); // FILE_FLAG_OPEN_REPARSE_POINT
    }
    let file = options.open(path)?;
    let meta = file.metadata()?;
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if meta.file_attributes() & 0x400 != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "token is a reparse point",
            ));
        }
    }
    if !meta.is_file() || meta.len() > max_bytes {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "token is not a bounded regular file",
        ));
    }
    Ok(file)
}

/// Read an untrusted on-disk file into memory, bounded by `max_bytes` (same
/// link/special-file refusal as [`bounded_regular_sha256`]).
pub(crate) fn bounded_regular_bytes(path: &Path, max_bytes: u64) -> std::io::Result<Vec<u8>> {
    use std::io::Read;
    let file = open_bounded_regular(path, max_bytes)?;
    let mut out = Vec::new();
    file.take(max_bytes.saturating_add(1))
        .read_to_end(&mut out)?;
    if out.len() as u64 > max_bytes {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "file exceeded read limit",
        ));
    }
    Ok(out)
}

/// Hash an untrusted on-disk token with bounded memory and IO. Links and
/// special files are refused before reading; a concurrent growth is bounded
/// by the reader as well as the initial size check.
pub(crate) fn bounded_regular_sha256(path: &Path, max_bytes: u64) -> std::io::Result<String> {
    use sha2::{Digest, Sha256};
    use std::io::Read;
    let file = open_bounded_regular(path, max_bytes)?;
    let mut reader = file.take(max_bytes.saturating_add(1));
    let mut hasher = Sha256::new();
    let mut bytes = 0u64;
    let mut buf = [0u8; 16 * 1024];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        bytes += n as u64;
        if bytes > max_bytes {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "token exceeded hash limit",
            ));
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

/// [`bounded_regular_sha256`] in the telemetry label form `sha256:<64 hex>`.
/// The inner function already returns hex, so callers must not hex-encode it
/// again (that produced 128-char `exe_sha256` values on Windows).
#[cfg_attr(not(windows), allow(dead_code))] // used by the Windows ETW/honeytoken collectors
pub(crate) fn bounded_regular_sha256_label(path: &Path, max_bytes: u64) -> std::io::Result<String> {
    bounded_regular_sha256(path, max_bytes).map(|hex| format!("sha256:{hex}"))
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn dir_from_env(env: &str, default: PathBuf) -> PathBuf {
    std::env::var(env).map(PathBuf::from).unwrap_or(default)
}

/// Preserve an explicit or existing state location even when it is unavailable.
/// Falling back then would silently discard identity and replay protection.
/// Developer fallbacks are only considered for locations that do not exist.
fn resolve_state_dir() -> PathBuf {
    #[cfg(target_os = "linux")]
    let privileged = nix::unistd::Uid::effective().is_root();
    #[cfg(windows)]
    let privileged = crate::winacl::is_elevated();
    #[cfg(not(any(target_os = "linux", windows)))]
    let privileged = false;
    resolve_state_dir_from(
        privileged,
        std::env::var("TRAPD_STATE_DIR")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .map(PathBuf::from),
        default_state_dir(),
        xdg_fallbacks(),
        std::env::temp_dir().join(format!("trapd-{}", current_uid())),
    )
}

fn resolve_state_dir_from(
    privileged: bool,
    explicit: Option<PathBuf>,
    canonical: PathBuf,
    fallbacks: Vec<PathBuf>,
    tmp: PathBuf,
) -> PathBuf {
    // 1. Explicit override always wins (set by the systemd unit).
    if let Some(p) = explicit {
        return p;
    }

    // 2. Canonical system location.
    if privileged || existing_or_inaccessible(&canonical) || ensure_writable(&canonical) {
        return canonical;
    }

    // 3. XDG state home / $HOME (developer / non-root execution).
    for candidate in fallbacks {
        if existing_or_inaccessible(&candidate) || ensure_writable(&candidate) {
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
    let _ = std::fs::create_dir_all(&tmp);
    warn!(dir = %tmp.display(), "using ephemeral state dir — identity will not persist across reboots");
    tmp
}

fn existing_or_inaccessible(path: &Path) -> bool {
    !matches!(std::fs::symlink_metadata(path), Err(e) if e.kind() == std::io::ErrorKind::NotFound)
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
    match std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&probe)
    {
        Ok(file) => {
            drop(file);
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
#[cfg(target_os = "linux")]
pub fn init_state_dir() -> Result<()> {
    private_directory(state_dir()).context("cannot secure agent state directory")?;
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn init_state_dir() {
    let dir = state_dir();
    if let Err(e) = std::fs::create_dir_all(dir) {
        warn!(dir = %dir.display(), error = %e, "could not create state dir");
        return;
    }
    harden_dir_perms(dir);
    info!(state = %dir.display(), config = %config_dir().display(), "filesystem layout resolved");
}

/// A privileged writer must be able to trust each parent for the lifetime
/// of subsequent pathname opens. A root-owned sticky directory allows an
/// owned child (e.g. a private test/service directory below /tmp).
#[cfg(target_os = "linux")]
pub(crate) fn private_directory(path: &Path) -> Result<std::fs::File> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
    let path = std::path::absolute(path)?;
    anyhow::ensure!(
        path.file_name().is_some()
            && !path
                .components()
                .any(|c| c == std::path::Component::ParentDir),
        "invalid private directory path"
    );
    let uid = nix::unistd::Uid::effective().as_raw();
    let mut current = PathBuf::from("/");
    for component in path.components() {
        let std::path::Component::Normal(part) = component else {
            continue;
        };
        current.push(part);
        let open = || {
            std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
                .open(&current)
        };
        let directory = match open() {
            Ok(dir) => dir,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                match std::fs::DirBuilder::new().mode(0o700).create(&current) {
                    Ok(()) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(e) => return Err(e).context("create private directory component"),
                }
                open()?
            }
            Err(e) => return Err(e).context("open private directory component"),
        };
        let meta = directory.metadata()?;
        if current == path {
            anyhow::ensure!(
                meta.uid() == uid && meta.mode() & 0o1000 == 0,
                "unsafe private directory owner or sticky bit"
            );
            ensure_mode(&directory, 0o700)?;
            return Ok(directory);
        }
        anyhow::ensure!(
            (meta.uid() == 0 || meta.uid() == uid)
                && (meta.mode() & 0o022 == 0 || meta.mode() & 0o1000 != 0),
            "untrusted ancestor of private directory"
        );
    }
    anyhow::bail!("missing private directory component")
}

/// Set `mode` only when it differs. An unconditional `fchmod` raises
/// `IN_ATTRIB` on every write, which the agent's own tamper watch reports as a
/// critical `chmod` of its log (a self-inflicted feedback loop).
#[cfg(target_os = "linux")]
pub(crate) fn ensure_mode(file: &std::fs::File, mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    if file.metadata()?.permissions().mode() & 0o7777 != mode {
        file.set_permissions(std::fs::Permissions::from_mode(mode))?;
    }
    Ok(())
}

/// Windows: restrict the directory to `SYSTEM` + `Administrators`, the analogue
/// of `0700` root. The MSI already does this for its own directories; this
/// covers installs that did not come from the MSI. Skipped when not elevated,
/// where the lock-down would shut the calling user out of their own state.
///
/// The LocalSystem service applies the same descriptor the MSI sets
/// (SYSTEM full, Administrators read and execute): the service writes the state,
/// an administrator only reads it. An elevated administrator running the agent
/// by hand (development) keeps the previous, administrator-writable one, and
/// under the hardened descriptor cannot change it (no WRITE_DAC), which is
/// logged and harmless. A host installed with `TRAPD_LEGACY_ACLS=1` keeps the
/// previous descriptor for the service too.
#[cfg(windows)]
fn harden_dir_perms(dir: &Path) {
    if !crate::winacl::is_elevated() {
        return;
    }
    let sddl = if crate::winacl::is_local_system() && !crate::selfprotect::acl_guard::legacy_mode()
    {
        crate::selfprotect::acl_policy::DIR_SDDL
    } else {
        crate::winacl::PRIVATE_DIR_SDDL
    };
    if let Err(e) = crate::winacl::set_dacl(dir, sddl) {
        warn!(dir = %dir.display(), error = %e, "could not restrict the state directory to SYSTEM/Administrators");
    }
}

#[cfg(not(any(target_os = "linux", windows)))]
fn harden_dir_perms(_dir: &Path) {}

/// How long a path counts as "written by this process" after `write_atomic`.
#[cfg(not(windows))]
pub const SELF_WRITE_WINDOW: std::time::Duration = std::time::Duration::from_secs(3);
#[cfg(not(windows))]
const SELF_WRITE_CAP: usize = 64;

#[cfg(not(windows))]
static SELF_WRITES: std::sync::Mutex<Vec<(PathBuf, std::time::Instant)>> =
    std::sync::Mutex::new(Vec::new());

/// Remember that this process is about to replace `path`. Recorded in memory
/// only (never derived from filesystem names), so another local process cannot
/// forge it; the tamper watcher uses it to tell the agent's own atomic rewrite
/// of an identity file from somebody else's.
#[cfg(not(windows))]
fn note_self_write(path: &Path) {
    if let Ok(mut recent) = SELF_WRITES.lock() {
        recent.retain(|(_, at)| at.elapsed() < SELF_WRITE_WINDOW);
        if recent.len() >= SELF_WRITE_CAP {
            recent.remove(0);
        }
        recent.push((path.to_path_buf(), std::time::Instant::now()));
    }
}

/// Whether this process replaced `path` through [`write_atomic`] within `within`.
#[cfg(not(windows))]
pub fn was_self_written(path: &Path, within: std::time::Duration) -> bool {
    SELF_WRITES
        .lock()
        .map(|recent| {
            recent
                .iter()
                .any(|(p, at)| p == path && at.elapsed() < within)
        })
        .unwrap_or(false)
}

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
        uuid::Uuid::new_v4()
    ));
    let mut f = create_secure_tmp(&tmp, mode)
        .with_context(|| format!("create secure temp {}", tmp.display()))?;

    let write_result = (|| -> Result<()> {
        // The temp file is created *already* restricted to `mode` — never
        // world/group-readable for even an instant. Writing with the default
        // (umask-derived) mode and chmod'ing afterward leaves a window where a
        // co-resident local user can read secrets (e.g. credentials.json)
        // mid-write.
        use std::io::Write as _;
        f.write_all(contents)
            .with_context(|| format!("write temp {}", tmp.display()))?;
        f.sync_all()
            .with_context(|| format!("fsync temp {}", tmp.display()))?;
        drop(f);
        #[cfg(not(windows))]
        note_self_write(path);
        durable_replace(&tmp, path)
            .with_context(|| format!("durable rename {} -> {}", tmp.display(), path.display()))?;
        Ok(())
    })();

    if write_result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    write_result
}

// On Unix, syncing file contents does not persist the renamed directory entry.
#[cfg(not(windows))]
fn durable_replace(tmp: &Path, path: &Path) -> std::io::Result<()> {
    std::fs::rename(tmp, path)?;
    sync_dir(path.parent().unwrap())
}

/// Persist the entries of directory `dir` (new files, renames) to disk.
#[cfg(not(windows))]
pub fn sync_dir(dir: &Path) -> std::io::Result<()> {
    std::fs::File::open(dir)?.sync_all()
}

// Windows has no portable directory fsync. Request a write-through replacement
// explicitly; std::fs::rename only supplies MOVEFILE_REPLACE_EXISTING.
#[cfg(windows)]
fn durable_replace(tmp: &Path, path: &Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
    };
    let wide = |p: &Path| -> std::io::Result<Vec<u16>> {
        let mut value: Vec<u16> = p.as_os_str().encode_wide().collect();
        if value.contains(&0) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "path contains NUL",
            ));
        }
        value.push(0);
        Ok(value)
    };
    let source = wide(tmp)?;
    let destination = wide(path)?;
    // SAFETY: Both paths are live, NUL-terminated UTF-16 buffers.
    if unsafe {
        MoveFileExW(
            source.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Create `path` fresh, atomically restricted to `mode` from the moment it
/// comes into existence (a single `open(2)` with `O_CREAT|O_EXCL` and the
/// requested mode — no separate `chmod` step, so no window where the file is
/// readable at the umask-derived default mode).
///
/// A collision belongs to another writer. Never truncate or unlink its file.
fn create_secure_tmp(path: &Path, mode: u32) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(mode);
    }
    #[cfg(not(unix))]
    let _ = mode;
    options.open(path)
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

    /// Regression (F2): the label was hex-encoded twice (135 chars).
    #[test]
    fn sha256_label_is_prefix_plus_single_64_hex_and_matches_known_digest() {
        let dir = scratch_dir("sha_label");
        let file = dir.join("abc.bin");
        std::fs::write(&file, b"abc").unwrap();
        let label = bounded_regular_sha256_label(&file, 1024).unwrap();
        // NIST test vector for "abc".
        assert_eq!(
            label,
            "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(label.len(), 71);
        assert!(label[7..].bytes().all(|b| b.is_ascii_hexdigit()));
        assert!(bounded_regular_sha256_label(&file, 2).is_err());
    }

    #[test]
    fn replay_state_resolution_never_changes_explicit_or_existing_location() {
        let root = scratch_dir("stable_state");
        let blocked = root.join("blocked");
        std::fs::write(&blocked, b"not a directory").unwrap();
        let fallback = root.join("fallback");
        assert_eq!(
            resolve_state_dir_from(
                false,
                Some(blocked.clone()),
                root.join("canonical"),
                vec![fallback.clone()],
                root.join("tmp")
            ),
            blocked
        );
        assert_eq!(
            resolve_state_dir_from(
                false,
                None,
                blocked.clone(),
                vec![fallback.clone()],
                root.join("tmp")
            ),
            blocked
        );
        let inaccessible = blocked.join("state");
        assert_eq!(
            resolve_state_dir_from(
                false,
                None,
                inaccessible.clone(),
                vec![fallback],
                root.join("tmp")
            ),
            inaccessible
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn privileged_state_resolution_never_uses_developer_paths() {
        let root = scratch_dir("privileged-state");
        let canonical = root.join("missing");
        let fallback = root.join("developer");
        assert_eq!(
            resolve_state_dir_from(
                true,
                None,
                canonical.clone(),
                vec![fallback.clone()],
                root.join("temporary")
            ),
            canonical
        );
        assert!(!fallback.exists());
        std::fs::write(root.join(".trapd_write_probe"), "occupied").unwrap();
        assert!(!ensure_writable(&root));
        assert_eq!(
            std::fs::read(root.join(".trapd_write_probe")).unwrap(),
            b"occupied"
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn linked_state_ancestor_is_rejected_without_creating_or_chmodding_target() {
        let root = scratch_dir("linked-state");
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let real = root.join("real");
        std::fs::create_dir(&real).unwrap();
        std::os::unix::fs::symlink(&real, root.join("alias")).unwrap();
        assert!(private_directory(&root.join("alias/state")).is_err());
        assert!(!real.join("state").exists());
        assert!(private_directory(&root.join("alias")).is_err());
        assert!(private_directory(&root.join("safe/state")).is_ok());
        std::fs::remove_dir_all(root).unwrap();
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
    fn create_secure_tmp_refuses_stale_leftover_with_wrong_mode() {
        let dir = scratch_dir("stale_leftover");
        let path = dir.join("secret.tmp");

        std::fs::write(&path, b"stale").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        assert_eq!(
            create_secure_tmp(&path, 0o600).unwrap_err().kind(),
            std::io::ErrorKind::AlreadyExists
        );
        assert_eq!(std::fs::read(&path).unwrap(), b"stale");
        let dest = dir.join("secret");
        write_atomic(&dest, b"fresh", 0o600).unwrap();
        assert_eq!(
            std::fs::metadata(&dest).unwrap().permissions().mode() & 0o777,
            0o600
        );
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

/// Load `<config>/agent.env` into the process environment without overriding
/// variables that are already set. The services get this file from the
/// service manager (systemd `EnvironmentFile`) or the Windows startup path; CLI
/// verbs that must see the same identity and state dir (e.g. `maintenance`)
/// call this before [`init_state_dir`].
pub fn load_agent_env_file() {
    let path = config_dir().join("agent.env");
    let Ok(contents) = std::fs::read_to_string(&path) else {
        return;
    };
    for (key, value) in parse_agent_env(&contents) {
        if std::env::var_os(&key).is_none() {
            std::env::set_var(key, value);
        }
    }
    tracing::info!(path = %path.display(), "loaded agent.env");
}

/// `KEY=value` lines; blank lines and `#` comments skipped, surrounding quotes trimmed.
fn parse_agent_env(contents: &str) -> Vec<(String, String)> {
    contents
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.trim().to_string(), v.trim().trim_matches('"').to_string()))
        .filter(|(k, _)| !k.is_empty())
        .collect()
}

#[cfg(test)]
mod agent_env_tests {
    use super::parse_agent_env;

    #[test]
    fn parses_keys_skipping_comments_blanks_and_quotes() {
        let got = parse_agent_env("# c\n\nTRAPD_STATE_DIR=\"/srv/trapd\"\n =x\nNOEQ\n A = b \n");
        assert_eq!(
            got,
            vec![
                ("TRAPD_STATE_DIR".to_string(), "/srv/trapd".to_string()),
                ("A".to_string(), "b".to_string())
            ]
        );
    }
}
