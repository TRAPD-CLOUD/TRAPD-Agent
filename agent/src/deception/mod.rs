//! Deception subsystem — honeytoken profiling, placement and lifecycle.
//!
//! Step 1 of the deception capability. It does **not** detect anything yet; it
//! cleanly *places* host-tailored bait and manages its lifecycle:
//!
//!   * [`profiler`] condenses inventory into a recon profile — the token
//!     candidates an attacker would expect on *this* host (MITRE T1552 /
//!     T1083). It only proposes a token where the genuine artefact is
//!     plausible, so the placement never reveals the trap.
//!   * The backend turns a candidate into believable content (its LLM job) and
//!     sends it back as a signed `deploy_honeytoken` command over the existing
//!     Ed25519 pipeline. No LLM ever runs on the endpoint.
//!   * [`deploy`] writes that content with **camouflage** so it does not look
//!     freshly planted, and [`registry`] records it so it can be revoked
//!     safely later.
//!
//! ## Camouflage (on placement)
//!
//!   * file mode is set explicitly (e.g. `0600` for an `id_rsa`);
//!   * with `mimic_neighbor`, owner/group and atime/mtime are copied from a
//!     sibling file in the same directory, so the bait blends in instead of
//!     carrying a tell-tale "created just now, owned by root" signature;
//!   * the out-of-band canary marker (a fake key id / domain tied to a
//!     monitored honeypot) is embedded in the *content* by the backend; the
//!     agent only records that a marker exists for later correlation.
//!
//! ## Out-of-band canaries (issue #32, point 2)
//!
//! A token may carry a [`OutOfBandCanary`]: a *second, independent* signal that
//! fires when the bait is **used** off-host — a fake AWS key whose use trips
//! CloudTrail, a tracking DNS/HTTP domain (Canarytokens-style), or a kube/SSH
//! credential pointed at honeypot infra. The agent never sees that channel
//! itself; it [validates](validate::validate_out_of_band) the descriptor, refuses
//! to share a marker across tokens, records it, and (via the engine's deploy
//! audit) *publishes the registration* so the backend can correlate an inbound
//! foreign signal back to this token and host (Token ↔ Host ↔ attacker).
//!
//! ## Safety invariants
//!
//!   * **never overwrite** an existing file — placement refuses if the target
//!     exists, so a command can never clobber real user data;
//!   * **never follow a symlink / escape** — the target must be absolute with
//!     no `..` components;
//!   * **revoke only what we planted** — `revoke` removes a file only when it
//!     is present in the local register, so a malformed command can never make
//!     the agent delete an arbitrary file.

pub mod profiler;
pub mod registry;
pub mod validate;
#[cfg(any(windows, test))]
pub mod windows_bait;
// Adaptive Windows decoys: local activity learning, naming style and placement.
#[cfg(any(windows, test))]
pub mod activity;
#[cfg(any(windows, test))]
pub mod naming;
#[cfg(any(windows, test))]
pub mod windows_profiler;

use std::fs;
#[cfg(any(test, not(target_os = "linux")))]
use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};
use std::time::SystemTime;

use anyhow::{bail, Context, Result};
use chrono::Utc;
use sha2::{Digest, Sha256};
use tracing::{info, warn};
use uuid::Uuid;

pub use profiler::build_profile_with_host;
pub use profiler::ReconProfile;
pub use registry::{BreadcrumbRecord, HoneytokenRecord, HoneytokenStore, OutOfBandCanary};
pub use validate::{validate_bait, validate_out_of_band};

#[cfg(all(test, unix))]
mod safety_regressions {
    use super::*;

    fn scratch() -> PathBuf {
        let path = std::env::temp_dir().join(format!("trapd-safety-{}", Uuid::new_v4()));
        fs::create_dir(&path).unwrap();
        path
    }

    #[test]
    fn publication_never_overwrites_existing_target() {
        let dir = scratch();
        let path = dir.join("token");
        fs::write(&path, b"real user data").unwrap();
        assert!(write_camouflaged(&path, b"bait", 0o600, None, None).is_err());
        assert_eq!(fs::read(&path).unwrap(), b"real user data");
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn health_does_not_follow_symlinks() {
        let dir = scratch();
        let path = dir.join("token");
        std::os::unix::fs::symlink("/etc/passwd", &path).unwrap();
        let rec = HoneytokenRecord {
            id: Uuid::new_v4(),
            path: path.to_string_lossy().into_owned(),
            kind: "unknown".into(),
            mode: 0o600,
            size_bytes: 4,
            sha256: "known".into(),
            mimic_neighbor: false,
            neighbor_path: None,
            canary_marker: None,
            out_of_band: None,
            deployed_at: Utc::now(),
            command_id: None,
            breadcrumbs: Vec::new(),
        };
        let health = verify_record(&rec);
        assert!(health.actual_sha256.is_none());
        assert!(
            health.modified,
            "an unverifiable replacement must not report healthy"
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn health_hashing_refuses_oversized_and_special_files() {
        let dir = scratch();
        let large = dir.join("large");
        fs::File::create(&large).unwrap().set_len(1 << 34).unwrap();
        assert!(crate::paths::bounded_regular_sha256(&large, 1024 * 1024).is_err());
        let fifo = dir.join("fifo");
        use std::os::unix::ffi::OsStrExt;
        let name = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        assert!(crate::paths::bounded_regular_sha256(&fifo, 1024 * 1024).is_err());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn revoke_preserves_real_file_replacing_decoy() {
        let dir = scratch();
        let path = dir.join("token");
        let store = HoneytokenStore::load_from(dir.join("register.json"));
        let rec = HoneytokenRecord {
            id: Uuid::new_v4(),
            path: path.to_string_lossy().into_owned(),
            kind: "unknown".into(),
            mode: 0o600,
            size_bytes: 4,
            sha256: hex::encode(Sha256::digest(b"bait")),
            mimic_neighbor: false,
            neighbor_path: None,
            canary_marker: None,
            out_of_band: None,
            deployed_at: Utc::now(),
            command_id: None,
            breadcrumbs: Vec::new(),
        };
        store.insert(rec.clone()).unwrap();
        fs::write(&path, b"real user file").unwrap();
        assert!(revoke(&store, &rec.path).is_err());
        assert_eq!(fs::read(&path).unwrap(), b"real user file");
        assert!(store.contains_path(&rec.path));
        fs::remove_dir_all(dir).unwrap();
    }
}

/// Everything needed to place one honeytoken. Built by the engine from a
/// verified `deploy_honeytoken` command.
#[derive(Debug, Clone)]
pub struct DeployRequest {
    /// Absolute destination path.
    pub path: String,
    /// Already-decoded token content (the engine base64-decodes the command).
    pub content: Vec<u8>,
    /// File mode to apply. `0` means "use the mimicked neighbour's mode".
    pub mode: u32,
    /// Copy owner/group + atime/mtime from a neighbouring file for blend-in.
    pub mimic_neighbor: bool,
    /// Optional out-of-band canary marker embedded in `content` by the backend.
    /// Legacy single-string form; prefer [`out_of_band`](Self::out_of_band).
    pub canary_marker: Option<String>,
    /// Optional structured out-of-band canary — the second, independent signal
    /// channel that fires when the bait is *used* off-host (issue #32, point 2).
    /// Validated and recorded so the backend can correlate a foreign signal back
    /// to this token and host.
    pub out_of_band: Option<OutOfBandCanary>,
    /// Token family from the recon candidate, if the backend echoed it back.
    pub kind: Option<String>,
    /// Id of the signed command requesting this deployment.
    pub command_id: Option<String>,
    /// Optional cross-linking artefacts placed alongside the token so an
    /// attacker *finds* it: a config that references the key, a `.bash_history`
    /// line with a "forgotten" `mysql -u root -p…`, etc. (issue #32, point 3).
    pub breadcrumbs: Vec<Breadcrumb>,
}

/// A breadcrumb that points an attacker at a token, raising its discoverability.
///
/// Two placement modes:
///   * **create** (`append == false`) — written like the token itself, refusing
///     to overwrite an existing file;
///   * **append** (`append == true`) — appended *safely* to an existing (or new)
///     file such as `~/.bash_history`, never truncating it and always starting
///     on a fresh line. The exact bytes added are recorded so revoke can remove
///     precisely our addition without corrupting the user's later writes.
#[derive(Debug, Clone)]
pub struct Breadcrumb {
    pub path: String,
    pub content: Vec<u8>,
    pub mode: u32,
    pub append: bool,
}

/// A decoy write that fails with EROFS/EACCES/EPERM on a systemd host is almost
/// always the unit's sandbox (read-only /home, no CAP_DAC_OVERRIDE), not a bad
/// path. Say so, instead of leaving the operator with a bare "Read-only file
/// system".
#[cfg(target_os = "linux")]
fn sandbox_hint(error: &anyhow::Error) -> &'static str {
    let denied = error
        .chain()
        .filter_map(|cause| cause.downcast_ref::<std::io::Error>())
        .filter_map(std::io::Error::raw_os_error)
        .any(|code| code == libc::EROFS || code == libc::EACCES || code == libc::EPERM);
    if denied {
        " (the agent's systemd unit may block this location; enable the honeytoken drop-in, see deploy/trapd-agent-deception.conf)"
    } else {
        ""
    }
}

#[cfg(not(target_os = "linux"))]
fn sandbox_hint(_error: &anyhow::Error) -> &'static str {
    ""
}

/// Place a honeytoken with camouflage and record it in the register.
///
/// Returns the persisted [`HoneytokenRecord`] on success. Fails (without side
/// effects on the target) if a safety invariant is violated.
pub fn deploy(store: &HoneytokenStore, req: DeployRequest) -> Result<HoneytokenRecord> {
    let target = validate_target(&req.path)?;

    // Quality gate (issue #32, point 3): a malformed token, or one carrying a
    // tell-tale shared marker, is worse than no token — it reveals the trap. Run
    // this *before* any filesystem mutation so a rejected deploy is a pure no-op.
    let kind_str = req.kind.clone().unwrap_or_else(|| "unknown".to_string());
    validate_bait(&kind_str, &req.content)
        .map_err(|e| anyhow::anyhow!("refusing to deploy honeytoken: {e}"))?;

    // Out-of-band canary (issue #32, point 2): validate the second-channel
    // descriptor before any mutation, so a malformed/uncorrelatable canary is a
    // pure no-op rather than a planted trap nothing can attribute later.
    if let Some(oob) = req.out_of_band.as_ref() {
        validate_out_of_band(oob)
            .map_err(|e| anyhow::anyhow!("refusing to deploy honeytoken: {e}"))?;
    }

    // Anti-fingerprinting: every canary marker — the legacy single string and
    // each out-of-band marker — must be unique to this token. A marker reused
    // across tokens would let one foreign-signal hit (or one greppy attacker)
    // enumerate every bait at once.
    if let Some(marker) = req.canary_marker.as_deref() {
        if store.canary_in_use(marker) {
            bail!(
                "refusing to deploy honeytoken: canary marker is already in use by another token"
            );
        }
    }
    if let Some(oob) = req.out_of_band.as_ref() {
        for marker in &oob.markers {
            if store.canary_in_use(marker) {
                bail!("refusing to deploy honeytoken: out-of-band canary marker '{marker}' is already in use by another token");
            }
        }
    }

    // Hard safety rule: never clobber an existing file. `symlink_metadata`
    // (lstat) catches a symlink planted at the path too — we treat any
    // existing entry, symlink included, as "occupied" and refuse.
    if target.symlink_metadata().is_ok() {
        bail!(
            "refusing to deploy honeytoken: {} already exists",
            target.display()
        );
    }

    let parent = target
        .parent()
        .ok_or_else(|| anyhow::anyhow!("target has no parent directory: {}", target.display()))?;
    #[cfg(target_os = "linux")]
    let _ = secure_parent(&target, true)?;
    #[cfg(not(target_os = "linux"))]
    fs::create_dir_all(parent)
        .with_context(|| format!("create parent dir {}", parent.display()))?;

    // Resolve camouflage attributes from a neighbour, if requested.
    let mut neighbor_path: Option<String> = None;
    let mut owner: Option<(u32, u32)> = None;
    let mut times: Option<(SystemTime, SystemTime)> = None;
    let mut mode = req.mode;

    if req.mimic_neighbor {
        if let Some(neighbor) = choose_neighbor(parent, &target) {
            if let Ok(meta) = neighbor.metadata() {
                owner = file_owner(&meta);
                times = Some((
                    meta.accessed().unwrap_or_else(|_| SystemTime::now()),
                    meta.modified().unwrap_or_else(|_| SystemTime::now()),
                ));
                if mode == 0 {
                    mode = neighbor_mode(&meta);
                }
                neighbor_path = Some(neighbor.to_string_lossy().into_owned());
            }
        }
    }
    if mode == 0 {
        // No explicit mode and no neighbour to copy from: a conservative,
        // credential-file-appropriate default.
        mode = 0o600;
    }

    let sha = hex::encode(Sha256::digest(&req.content));
    let size = req.content.len() as u64;

    write_camouflaged(&target, &req.content, mode, owner, times).map_err(|e| {
        let hint = sandbox_hint(&e);
        e.context(format!("write honeytoken to {}{hint}", target.display()))
    })?;

    // Place cross-linking breadcrumbs that point at the token. A breadcrumb
    // failure must not unwind a token that is already on disk, so failures are
    // logged and skipped; only the breadcrumbs that landed are recorded.
    let mut breadcrumbs: Vec<BreadcrumbRecord> = Vec::new();
    for bc in &req.breadcrumbs {
        match place_breadcrumb(bc) {
            Ok(rec) => {
                info!(path = %rec.path, appended = rec.appended, "honeytoken breadcrumb placed");
                breadcrumbs.push(rec);
            }
            Err(e) => {
                warn!(path = %bc.path, error = %e, "honeytoken breadcrumb placement failed — skipping")
            }
        }
    }

    let record = HoneytokenRecord {
        id: Uuid::new_v4(),
        path: target.to_string_lossy().into_owned(),
        kind: kind_str,
        mode,
        size_bytes: size,
        sha256: sha,
        mimic_neighbor: req.mimic_neighbor,
        neighbor_path,
        canary_marker: req.canary_marker,
        out_of_band: req.out_of_band,
        deployed_at: Utc::now(),
        command_id: req.command_id,
        breadcrumbs,
    };

    store
        .insert(record.clone())
        .context("record deployed honeytoken")?;

    info!(
        path = %record.path,
        kind = %record.kind,
        mimic = record.mimic_neighbor,
        "honeytoken deployed",
    );
    Ok(record)
}

/// Revoke a previously-deployed honeytoken: delete the file and drop it from
/// the register. Refuses any path that is not in the register — the agent only
/// removes what it planted.
pub fn revoke(store: &HoneytokenStore, path: &str) -> Result<HoneytokenRecord> {
    let existing = store
        .list()
        .into_iter()
        .find(|record| record.path == path)
        .ok_or_else(|| anyhow::anyhow!("refusing to revoke {path}: not a registered honeytoken"))?;
    remove_verified_file(
        Path::new(path),
        &existing.sha256,
        existing.size_bytes.max(1024 * 1024),
    )?;

    let record = store
        .remove_by_path(path)
        .context("update honeytoken register")?
        .ok_or_else(|| {
            anyhow::anyhow!("honeytoken vanished from register during revoke: {path}")
        })?;

    // Tear down any breadcrumbs we planted alongside the token. Created files are
    // removed; appended history lines are removed *only* if the file still ends
    // with exactly our addition, so a user's later writes are never corrupted.
    for bc in &record.breadcrumbs {
        if let Err(e) = remove_breadcrumb(bc) {
            warn!(path = %bc.path, error = %e, "honeytoken breadcrumb cleanup failed");
        }
    }

    info!(path, "honeytoken revoked");
    Ok(record)
}

// ── Health / existence verification ─────────────────────────────────────────────

/// On-disk verification result for a single registered honeytoken.
///
/// Lets the backend distinguish a live token from one that was deleted or
/// tampered with **out-of-band** — i.e. without tripping the eBPF access
/// detector (e.g. removed while the agent was down, or edited by a tool the
/// content-read gate does not cover). The eBPF detector answers "was it
/// *touched*?"; this answers "is it *still there and unchanged*?".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HealthCheck {
    /// The file still exists at the registered path.
    pub present: bool,
    /// The file exists but its content digest no longer matches what we planted.
    /// Only meaningful when `present` and a digest was recorded at deploy time.
    pub modified: bool,
    /// The current content digest, when the file could be read.
    pub actual_sha256: Option<String>,
}

impl HealthCheck {
    /// Compact backend-facing label: `present` | `missing` | `modified`.
    pub fn status_label(&self) -> &'static str {
        if !self.present {
            "missing"
        } else if self.modified {
            "modified"
        } else {
            "present"
        }
    }
}

/// Verify a single registered honeytoken against its on-disk state. Pure (no
/// side effects, no telemetry) so it is unit-testable; the periodic health task
/// wraps it and emits the result.
pub fn verify_record(rec: &HoneytokenRecord) -> HealthCheck {
    match crate::paths::bounded_regular_sha256(
        Path::new(&rec.path),
        rec.size_bytes.max(1024 * 1024),
    ) {
        Ok(actual) => {
            // A recorded digest of "" means none was captured — never flag such a
            // token as modified (we have nothing to compare against).
            let modified = !rec.sha256.is_empty() && actual != rec.sha256;
            HealthCheck {
                present: true,
                modified,
                actual_sha256: Some(actual),
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => HealthCheck {
            present: false,
            modified: false,
            actual_sha256: None,
        },
        // Exists but unreadable (e.g. perms, or a directory at the path): present
        // when an entry is there at all (lstat), missing only when truly absent.
        Err(_) => HealthCheck {
            present: Path::new(&rec.path).symlink_metadata().is_ok(),
            modified: !rec.sha256.is_empty(),
            actual_sha256: None,
        },
    }
}

// ── Breadcrumbs ───────────────────────────────────────────────────────────────

/// Place one breadcrumb and return the record describing what was written.
fn place_breadcrumb(bc: &Breadcrumb) -> Result<BreadcrumbRecord> {
    let target = validate_target(&bc.path)?;
    #[cfg(not(target_os = "linux"))]
    let parent = target
        .parent()
        .ok_or_else(|| anyhow::anyhow!("breadcrumb has no parent dir: {}", target.display()))?;
    #[cfg(target_os = "linux")]
    let _ = secure_parent(&target, true)?;
    #[cfg(not(target_os = "linux"))]
    fs::create_dir_all(parent)
        .with_context(|| format!("create breadcrumb parent dir {}", parent.display()))?;

    if bc.append {
        let (offset, written) = append_safe(&target, &bc.content, bc.mode)
            .with_context(|| format!("append breadcrumb to {}", target.display()))?;
        Ok(BreadcrumbRecord {
            path: target.to_string_lossy().into_owned(),
            appended: true,
            offset: Some(offset),
            len: Some(written.len() as u64),
            sha256: Some(hex::encode(Sha256::digest(&written))),
        })
    } else {
        create_breadcrumb_file(&target, &bc.content, bc.mode)
            .with_context(|| format!("create breadcrumb {}", target.display()))?;
        Ok(BreadcrumbRecord {
            path: target.to_string_lossy().into_owned(),
            appended: false,
            offset: None,
            len: Some(bc.content.len() as u64),
            sha256: Some(hex::encode(Sha256::digest(&bc.content))),
        })
    }
}

/// Create a standalone breadcrumb file, refusing (like the token itself) to
/// overwrite anything that already exists.
fn create_breadcrumb_file(target: &Path, content: &[u8], mode: u32) -> Result<()> {
    if target.symlink_metadata().is_ok() {
        bail!("breadcrumb target already exists: {}", target.display());
    }
    write_camouflaged(
        target,
        content,
        if mode == 0 { 0o600 } else { mode },
        None,
        None,
    )
}

/// Append `content` to `path` without ever truncating it: the file is opened in
/// append mode (created at `mode` if absent), a leading newline is inserted when
/// the existing file does not already end in one, and a trailing newline is
/// guaranteed so the next genuine entry stays on its own line. Returns the
/// pre-append offset and the exact bytes written, so revoke can later remove
/// precisely this addition.
fn append_safe(target: &Path, content: &[u8], mode: u32) -> Result<(u64, Vec<u8>)> {
    let mut f = open_append_handle(target, mode)?;
    let meta = f.metadata()?;
    if !meta.is_file() {
        bail!("breadcrumb target is not a regular file");
    }
    let pre_len = meta.len();

    // Does the existing file already end with a newline?
    let needs_leading_nl = if pre_len > 0 {
        f.seek(SeekFrom::End(-1)).context("seek to tail")?;
        let mut last = [0u8; 1];
        f.read_exact(&mut last).context("read tail byte")?;
        last[0] != b'\n'
    } else {
        false
    };

    let mut payload = Vec::with_capacity(content.len() + 2);
    if needs_leading_nl {
        payload.push(b'\n');
    }
    payload.extend_from_slice(content);
    if !payload.ends_with(b"\n") {
        payload.push(b'\n');
    }

    f.write_all(&payload).context("append breadcrumb bytes")?;
    f.sync_all().ok();
    Ok((pre_len, payload))
}

#[cfg(target_os = "linux")]
fn open_append_handle(target: &Path, mode: u32) -> Result<fs::File> {
    use std::os::fd::{AsRawFd, FromRawFd};
    let (parent, name) = secure_parent(target, true)?;
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDWR
                | libc::O_CREAT
                | libc::O_APPEND
                | libc::O_NOFOLLOW
                | libc::O_NONBLOCK
                | libc::O_CLOEXEC,
            if mode == 0 { 0o600 } else { mode },
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(unsafe { fs::File::from_raw_fd(fd) })
}

#[cfg(all(unix, not(target_os = "linux")))]
fn open_append_handle(target: &Path, mode: u32) -> Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .read(true)
        .create(true)
        .append(true)
        .mode(if mode == 0 { 0o600 } else { mode })
        .open(target)
        .with_context(|| format!("open append {}", target.display()))
}

#[cfg(not(unix))]
fn open_append_handle(target: &Path, _mode: u32) -> Result<fs::File> {
    OpenOptions::new()
        .read(true)
        .create(true)
        .append(true)
        .open(target)
        .with_context(|| format!("open append {}", target.display()))
}

/// Undo a breadcrumb. A created file is deleted; an appended block is removed
/// only when the file still ends with exactly the bytes we added (verified by
/// length and SHA-256), so concurrent/later writes are never clobbered.
fn remove_breadcrumb(bc: &BreadcrumbRecord) -> Result<()> {
    if !bc.appended {
        let Some(sha) = bc.sha256.as_deref() else {
            warn!(path = %bc.path, "legacy breadcrumb has no content ownership proof; preserving file");
            return Ok(());
        };
        return remove_verified_file(
            Path::new(&bc.path),
            sha,
            bc.len.unwrap_or(0).max(1024 * 1024),
        );
    }

    let (Some(offset), Some(len), Some(sha)) = (bc.offset, bc.len, bc.sha256.as_ref()) else {
        return Ok(()); // nothing recorded to remove
    };
    if Path::new(&bc.path).symlink_metadata().is_err() {
        return Ok(());
    }
    let mut f = open_breadcrumb_for_cleanup(Path::new(&bc.path))?;
    let meta = f.metadata()?;
    if !meta.is_file() {
        bail!("breadcrumb cleanup target is not a regular file");
    }
    if meta.len() != offset + len {
        warn!(path = %bc.path, "appended breadcrumb: file grew/shrank since placement — leaving it intact");
        return Ok(());
    }
    f.seek(SeekFrom::Start(offset))
        .context("seek to appended block")?;
    let mut digest = Sha256::new();
    let mut reader = (&mut f).take(len);
    let mut buf = [0u8; 16384];
    let mut consumed = 0u64;
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        consumed += n as u64;
        digest.update(&buf[..n]);
    }
    if consumed != len || hex::encode(digest.finalize()) != *sha {
        warn!(path = %bc.path, "appended breadcrumb: tail no longer matches — leaving it intact");
        return Ok(());
    }
    let after = f.metadata()?;
    if after.len() != meta.len() || after.modified().ok() != meta.modified().ok() {
        warn!(path = %bc.path, "appended breadcrumb changed during cleanup; preserving file");
        return Ok(());
    }
    // The same opened object is truncated, so a replaced pathname/symlink can
    // never redirect this write. Noncooperating writes to the same inode can
    // still race the final metadata check; leave any detected change intact.
    f.set_len(offset).context("truncate appended breadcrumb")?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn open_breadcrumb_for_cleanup(target: &Path) -> Result<fs::File> {
    use std::os::fd::{AsRawFd, FromRawFd};
    let (parent, name) = secure_parent(target, false)?;
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDWR | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(unsafe { fs::File::from_raw_fd(fd) })
}

#[cfg(not(target_os = "linux"))]
fn open_breadcrumb_for_cleanup(target: &Path) -> Result<fs::File> {
    Ok(OpenOptions::new().read(true).write(true).open(target)?)
}

// ── Internals ─────────────────────────────────────────────────────────────────

/// Validate the destination path: absolute, no `..` traversal components.
fn validate_target(path: &str) -> Result<PathBuf> {
    let p = PathBuf::from(path);
    if !p.is_absolute() {
        bail!("honeytoken path must be absolute: {path}");
    }
    if p.components().any(|c| matches!(c, Component::ParentDir)) {
        bail!("honeytoken path must not contain '..': {path}");
    }
    Ok(p)
}

/// Write `content` to `target` atomically, applying mode and (best-effort)
/// owner/timestamps before the rename so the file never appears half-written
/// or freshly-touched once it is visible at its final path.
#[cfg(not(target_os = "linux"))]
fn write_camouflaged(
    target: &Path,
    content: &[u8],
    mode: u32,
    owner: Option<(u32, u32)>,
    times: Option<(SystemTime, SystemTime)>,
) -> Result<()> {
    use std::io::Write;

    let parent = target.parent().expect("validated target has a parent");
    let tmp = parent.join(format!(
        ".{}.htk.{}",
        target
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("token"),
        Uuid::new_v4()
    ));

    let result = (|| -> Result<()> {
        {
            let mut f = create_temp(&tmp)?;
            f.write_all(content).context("write token content")?;
            f.sync_all().ok();
        }
        set_mode(&tmp, mode);
        if let Some((uid, gid)) = owner {
            // Best-effort: chown only succeeds as root; a non-root dev run just
            // keeps the writer's ownership.
            if let Err(e) = chown(&tmp, uid, gid) {
                warn!(error = %e, "honeytoken chown failed (need root) — leaving writer ownership");
            }
        }
        if let Some((atime, mtime)) = times {
            set_times(&tmp, atime, mtime);
        }
        // Atomic no-replace publication. Unlike rename(), hard_link refuses an
        // existing target even if it appeared after the earlier safety check.
        fs::hard_link(&tmp, target).with_context(|| {
            format!(
                "publish {} -> {} without replacement",
                tmp.display(),
                target.display()
            )
        })?;
        if let Err(error) = fs::remove_file(&tmp) {
            warn!(%error, "could not remove published honeytoken staging link");
        }
        Ok(())
    })();

    // A failed create does not establish ownership of the staging path.
    result
}

#[cfg(target_os = "linux")]
fn secure_parent(target: &Path, create_parents: bool) -> Result<(fs::File, std::ffi::CString)> {
    use std::os::{
        fd::{AsRawFd, FromRawFd},
        unix::ffi::OsStrExt,
    };
    let parent = target.parent().context("target has no parent")?;
    let name = std::ffi::CString::new(
        target
            .file_name()
            .context("target has no file name")?
            .as_bytes(),
    )?;
    let root = std::ffi::CString::new("/")?;
    let fd = unsafe {
        libc::open(
            root.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let mut dir = unsafe { fs::File::from_raw_fd(fd) };
    for component in parent.components() {
        let Component::Normal(part) = component else {
            continue;
        };
        let part = std::ffi::CString::new(part.as_bytes())?;
        let flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
        let mut fd = unsafe { libc::openat(dir.as_raw_fd(), part.as_ptr(), flags) };
        if fd < 0
            && create_parents
            && std::io::Error::last_os_error().kind() == std::io::ErrorKind::NotFound
        {
            if unsafe { libc::mkdirat(dir.as_raw_fd(), part.as_ptr(), 0o755) } < 0
                && std::io::Error::last_os_error().kind() != std::io::ErrorKind::AlreadyExists
            {
                return Err(std::io::Error::last_os_error().into());
            }
            fd = unsafe { libc::openat(dir.as_raw_fd(), part.as_ptr(), flags) };
        }
        if fd < 0 {
            return Err(std::io::Error::last_os_error())
                .context("open honeytoken parent without following links");
        }
        dir = unsafe { fs::File::from_raw_fd(fd) };
    }
    Ok((dir, name))
}

#[cfg(target_os = "linux")]
struct PrivateStage {
    parent: fs::File,
    dir: fs::File,
    name: std::ffi::CString,
}

#[cfg(target_os = "linux")]
impl PrivateStage {
    fn new(parent: fs::File) -> Result<Self> {
        use std::os::{
            fd::{AsRawFd, FromRawFd},
            unix::fs::MetadataExt,
        };
        let name = std::ffi::CString::new(format!(".trapd-stage-{}", Uuid::new_v4()))?;
        if unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) } < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let dir = unsafe { fs::File::from_raw_fd(fd) };
        let meta = dir.metadata()?;
        if meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o077 != 0 {
            bail!("honeytoken staging directory was replaced or is not private");
        }
        Ok(Self { parent, dir, name })
    }

    fn leaf() -> &'static std::ffi::CStr {
        c"token"
    }
}

#[cfg(target_os = "linux")]
impl Drop for PrivateStage {
    fn drop(&mut self) {
        use std::os::fd::AsRawFd;
        // Remove only our empty container; never remove a staged object here.
        // A failed restore deliberately retains that object's recovery location.
        let _ = unsafe {
            libc::unlinkat(
                self.parent.as_raw_fd(),
                self.name.as_ptr(),
                libc::AT_REMOVEDIR,
            )
        };
    }
}

/// Remove a registered artifact only after its bounded regular-file digest has
/// been verified. Quarantine the directory entry into private staging and check
/// again there, so a pathname replacement between checking and moving cannot
/// cause a real file to be deleted.
#[cfg(target_os = "linux")]
fn remove_verified_file(target: &Path, sha: &str, max_bytes: u64) -> Result<()> {
    use std::os::fd::AsRawFd;
    match target.symlink_metadata() {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
        Ok(_) => {}
    }
    if sha.is_empty() {
        bail!(
            "artifact has no content ownership proof; preserving {}",
            target.display()
        );
    }
    let (parent, name) = secure_parent(target, false)?;
    let path = PathBuf::from(format!(
        "/proc/self/fd/{}/{}",
        parent.as_raw_fd(),
        name.to_string_lossy()
    ));
    if crate::paths::bounded_regular_sha256(&path, max_bytes)? != sha {
        bail!("artifact content changed; preserving {}", target.display());
    }
    let stage = PrivateStage::new(parent)?;
    if unsafe {
        libc::renameat2(
            stage.parent.as_raw_fd(),
            name.as_ptr(),
            stage.dir.as_raw_fd(),
            PrivateStage::leaf().as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    } < 0
    {
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::NotFound {
            return Ok(());
        }
        return Err(error.into());
    }
    let staged_path = PathBuf::from(format!("/proc/self/fd/{}/token", stage.dir.as_raw_fd()));
    let verified = crate::paths::bounded_regular_sha256(&staged_path, max_bytes)
        .is_ok_and(|actual| actual == sha);
    if !verified {
        let restored = unsafe {
            libc::renameat2(
                stage.dir.as_raw_fd(),
                PrivateStage::leaf().as_ptr(),
                stage.parent.as_raw_fd(),
                name.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        };
        if restored < 0 {
            let recovery = target
                .parent()
                .unwrap_or(Path::new("/"))
                .join(stage.name.to_string_lossy().as_ref())
                .join("token");
            warn!(path = %target.display(), recovery = %recovery.display(), "artifact changed during cleanup and could not be restored without replacing another file; preserved in private staging");
        }
        bail!(
            "artifact changed during cleanup; preserving {}",
            target.display()
        );
    }
    if unsafe { libc::unlinkat(stage.dir.as_raw_fd(), PrivateStage::leaf().as_ptr(), 0) } < 0 {
        // Restore on a deletion failure as well, so normal permission/IO errors
        // do not strand the original object in staging.
        let error = std::io::Error::last_os_error();
        let _ = unsafe {
            libc::renameat2(
                stage.dir.as_raw_fd(),
                PrivateStage::leaf().as_ptr(),
                stage.parent.as_raw_fd(),
                name.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        };
        return Err(error.into());
    }
    let _ = stage.parent.sync_all();
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn remove_verified_file(target: &Path, sha: &str, max_bytes: u64) -> Result<()> {
    match crate::paths::bounded_regular_sha256(target, max_bytes) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Ok(actual) if !sha.is_empty() && actual == sha => {
            fs::remove_file(target)?;
            Ok(())
        }
        _ => bail!(
            "artifact content could not be verified; preserving {}",
            target.display()
        ),
    }
}

#[cfg(target_os = "linux")]
fn write_camouflaged(
    target: &Path,
    content: &[u8],
    mode: u32,
    owner: Option<(u32, u32)>,
    times: Option<(SystemTime, SystemTime)>,
) -> Result<()> {
    use std::os::fd::{AsRawFd, FromRawFd};
    let (parent, name) = secure_parent(target, true)?;
    let stage = PrivateStage::new(parent)?;
    let fd = unsafe {
        libc::openat(
            stage.dir.as_raw_fd(),
            PrivateStage::leaf().as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let mut file = unsafe { fs::File::from_raw_fd(fd) };
    let result = (|| -> Result<()> {
        file.write_all(content).context("write token content")?;
        if unsafe { libc::fchmod(file.as_raw_fd(), mode) } < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        if let Some((uid, gid)) = owner {
            if unsafe { libc::fchown(file.as_raw_fd(), uid, gid) } < 0 {
                warn!(error = %std::io::Error::last_os_error(), "honeytoken ownership alignment failed");
            }
        }
        if let Some((atime, mtime)) = times {
            file.set_times(fs::FileTimes::new().set_accessed(atime).set_modified(mtime))?;
        }
        file.sync_all()?;
        if unsafe {
            libc::linkat(
                stage.dir.as_raw_fd(),
                PrivateStage::leaf().as_ptr(),
                stage.parent.as_raw_fd(),
                name.as_ptr(),
                0,
            )
        } < 0
        {
            return Err(std::io::Error::last_os_error())
                .context("publish honeytoken without replacement");
        }
        // Publication succeeded; cleanup failure must not prevent registration.
        let _ = stage.parent.sync_all();
        Ok(())
    })();
    if unsafe { libc::unlinkat(stage.dir.as_raw_fd(), PrivateStage::leaf().as_ptr(), 0) } < 0 {
        warn!(error = %std::io::Error::last_os_error(), "could not remove honeytoken staging link");
    }
    result
}

/// Pick a sibling regular file to mimic. Deterministic given the directory
/// state: the most recently modified regular file other than the target/temp,
/// so the bait inherits attributes from a file that looks actively used.
fn choose_neighbor(dir: &Path, target: &Path) -> Option<PathBuf> {
    let target_name = target.file_name();
    let mut best: Option<(SystemTime, PathBuf)> = None;
    for entry in fs::read_dir(dir).ok()?.flatten() {
        let path = entry.path();
        if Some(path.file_name()?) == target_name {
            continue;
        }
        // Skip our own temp files and anything that is not a regular file.
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.ends_with(&format!(".htk.{}", std::process::id())) {
            continue;
        }
        let Ok(meta) = entry.metadata() else { continue };
        if !meta.is_file() {
            continue;
        }
        let mtime = meta.modified().unwrap_or(SystemTime::UNIX_EPOCH);
        match &best {
            Some((best_mtime, _)) if *best_mtime >= mtime => {}
            _ => best = Some((mtime, path)),
        }
    }
    best.map(|(_, p)| p)
}

#[cfg(all(unix, not(target_os = "linux")))]
fn create_temp(path: &Path) -> Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("create temp {}", path.display()))
}

#[cfg(not(unix))]
fn create_temp(path: &Path) -> Result<fs::File> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("create temp {}", path.display()))
}

#[cfg(all(unix, not(target_os = "linux")))]
fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(mode));
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) {}

#[cfg(unix)]
fn file_owner(meta: &fs::Metadata) -> Option<(u32, u32)> {
    use std::os::unix::fs::MetadataExt;
    Some((meta.uid(), meta.gid()))
}

#[cfg(not(unix))]
fn file_owner(_meta: &fs::Metadata) -> Option<(u32, u32)> {
    None
}

#[cfg(unix)]
fn neighbor_mode(meta: &fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    meta.permissions().mode() & 0o7777
}

#[cfg(not(unix))]
fn neighbor_mode(_meta: &fs::Metadata) -> u32 {
    0o600
}

/// Align atime/mtime to the mimicked neighbour via the stable std API.
#[cfg(not(target_os = "linux"))]
fn set_times(path: &Path, atime: SystemTime, mtime: SystemTime) {
    let times = fs::FileTimes::new().set_accessed(atime).set_modified(mtime);
    match OpenOptions::new().write(true).open(path) {
        Ok(f) => {
            if let Err(e) = f.set_times(times) {
                warn!(error = %e, "honeytoken timestamp alignment failed");
            }
        }
        Err(e) => warn!(error = %e, "could not reopen honeytoken to set timestamps"),
    }
}

#[cfg(not(target_os = "linux"))]
fn chown(_path: &Path, _uid: u32, _gid: u32) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn sandbox_hint_only_for_permission_style_errors() {
        let erofs = anyhow::Error::from(std::io::Error::from_raw_os_error(libc::EROFS))
            .context("create staging file");
        assert!(sandbox_hint(&erofs).contains("trapd-agent-deception.conf"));
        for code in [libc::EACCES, libc::EPERM] {
            let e = anyhow::Error::from(std::io::Error::from_raw_os_error(code));
            assert!(!sandbox_hint(&e).is_empty());
        }
        let enospc = anyhow::Error::from(std::io::Error::from_raw_os_error(libc::ENOSPC));
        assert_eq!(sandbox_hint(&enospc), "");
        assert_eq!(sandbox_hint(&anyhow::anyhow!("not an io error")), "");
    }

    fn scratch_dir() -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let d = std::env::temp_dir().join(format!("trapd_deception_{nanos}"));
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn store_in(dir: &Path) -> HoneytokenStore {
        HoneytokenStore::load_from(dir.join("honeytokens.json"))
    }

    /// Structurally valid AWS credentials content (passes `validate_bait`).
    const VALID_AWS: &str = "[default]\naws_access_key_id = AKIA2E0AABCDEFGHIJKL\n\
                             aws_secret_access_key = wJalrXUtnFEMIabcdefGHIjklMNOpqrsTUVwxyz1\n";

    fn req(path: &str, content: &str) -> DeployRequest {
        DeployRequest {
            path: path.to_string(),
            content: content.as_bytes().to_vec(),
            mode: 0o600,
            mimic_neighbor: false,
            canary_marker: Some("AKIACANARYTOKEN01".into()),
            out_of_band: None,
            kind: Some("aws_credentials".into()),
            command_id: Some("cmd-1".into()),
            breadcrumbs: Vec::new(),
        }
    }

    #[test]
    fn deploy_then_revoke_roundtrip() {
        let dir = scratch_dir();
        let store = store_in(&dir);
        let path = dir.join(".aws").join("credentials");
        let path_s = path.to_string_lossy().into_owned();

        let rec = deploy(&store, req(&path_s, VALID_AWS)).unwrap();
        assert!(path.exists());
        assert_eq!(rec.kind, "aws_credentials");
        assert_eq!(rec.canary_marker.as_deref(), Some("AKIACANARYTOKEN01"));
        assert!(store.contains_path(&path_s));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let m = fs::metadata(&path).unwrap().permissions().mode() & 0o7777;
            assert_eq!(m, 0o600, "mode must be applied");
        }

        let revoked = revoke(&store, &path_s).unwrap();
        assert_eq!(revoked.id, rec.id);
        assert!(!path.exists());
        assert!(!store.contains_path(&path_s));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn refuses_to_overwrite_existing_file() {
        let dir = scratch_dir();
        let store = store_in(&dir);
        let path = dir.join("real_secret");
        fs::write(&path, b"do not touch").unwrap();

        let err = deploy(&store, req(&path.to_string_lossy(), VALID_AWS)).unwrap_err();
        assert!(err.to_string().contains("already exists"));
        // The real file is untouched.
        assert_eq!(fs::read(&path).unwrap(), b"do not touch");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn revoke_refuses_unregistered_path() {
        let dir = scratch_dir();
        let store = store_in(&dir);
        let victim = dir.join("not_a_token");
        fs::write(&victim, b"important").unwrap();

        let err = revoke(&store, &victim.to_string_lossy()).unwrap_err();
        assert!(err.to_string().contains("not a registered honeytoken"));
        // Crucially, the unregistered file is NOT deleted.
        assert!(victim.exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn rejects_relative_and_traversal_paths() {
        let dir = scratch_dir();
        let store = store_in(&dir);
        assert!(deploy(&store, req("relative/path", "x"))
            .unwrap_err()
            .to_string()
            .contains("absolute"));
        assert!(deploy(&store, req("/tmp/../etc/x", "x"))
            .unwrap_err()
            .to_string()
            .contains(".."));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn mimic_neighbor_copies_mtime() {
        let dir = scratch_dir();
        let store = store_in(&dir);
        // A neighbour with a distinctive old mtime.
        let neighbor = dir.join("id_rsa");
        fs::write(&neighbor, b"-----BEGIN-----").unwrap();
        let old = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_000_000_000);
        let ft = fs::FileTimes::new().set_accessed(old).set_modified(old);
        OpenOptions::new()
            .write(true)
            .open(&neighbor)
            .unwrap()
            .set_times(ft)
            .unwrap();

        let target = dir.join("id_rsa_backup");
        let mut r = req(&target.to_string_lossy(), VALID_AWS);
        r.mimic_neighbor = true;
        let rec = deploy(&store, r).unwrap();

        assert!(rec.neighbor_path.is_some());
        let placed = fs::metadata(&target).unwrap().modified().unwrap();
        assert_eq!(placed, old, "mtime should be aligned to the neighbour");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn rejects_malformed_bait_content() {
        let dir = scratch_dir();
        let store = store_in(&dir);
        let path = dir.join(".aws").join("credentials");
        // aws kind but the content is not shaped like AWS creds → refused, and
        // crucially nothing is written.
        let err = deploy(&store, req(&path.to_string_lossy(), "not aws shaped"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("invalid 'aws_credentials'"), "got: {err}");
        assert!(
            !path.exists(),
            "a rejected deploy must not touch the filesystem"
        );
        assert!(store.is_empty());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn rejects_duplicate_canary_marker() {
        let dir = scratch_dir();
        let store = store_in(&dir);
        let a = deploy(&store, req(&dir.join("a").to_string_lossy(), VALID_AWS));
        assert!(a.is_ok());
        // A second token reusing the same canary marker is refused — no shared
        // watermark across tokens.
        let err = deploy(&store, req(&dir.join("b").to_string_lossy(), VALID_AWS))
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("canary marker is already in use"),
            "got: {err}"
        );
        assert!(!dir.join("b").exists());
        let _ = fs::remove_dir_all(&dir);
    }

    fn oob(channel: &str, tracking_id: &str, marker: &str) -> OutOfBandCanary {
        OutOfBandCanary {
            channel: channel.into(),
            tracking_id: tracking_id.into(),
            markers: vec![marker.into()],
        }
    }

    #[test]
    fn deploy_records_out_of_band_canary() {
        let dir = scratch_dir();
        let store = store_in(&dir);
        let path = dir.join(".aws").join("credentials");
        let mut r = req(&path.to_string_lossy(), VALID_AWS);
        // Distinct from the content's legacy marker so uniqueness holds.
        r.out_of_band = Some(oob("aws_cloudtrail", "trk-1", "AKIA2E0AOOBCDEFGHIJK"));
        let rec = deploy(&store, r).unwrap();
        let stored = rec.out_of_band.expect("oob recorded");
        assert_eq!(stored.channel, "aws_cloudtrail");
        assert_eq!(stored.tracking_id, "trk-1");
        // The token is resolvable from its tracking id for foreign-signal correlation.
        assert!(store.find_by_tracking_id("trk-1").is_some());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn rejects_malformed_out_of_band_canary() {
        let dir = scratch_dir();
        let store = store_in(&dir);
        let path = dir.join(".aws").join("credentials");
        let mut r = req(&path.to_string_lossy(), VALID_AWS);
        // dns channel with a non-host marker → refused, and nothing is written.
        r.out_of_band = Some(oob("dns", "trk-x", "not-a-hostname"));
        let err = deploy(&store, r).unwrap_err().to_string();
        assert!(err.contains("out_of_band_canary"), "got: {err}");
        assert!(
            !path.exists(),
            "a rejected oob deploy must not touch the filesystem"
        );
        assert!(store.is_empty());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn rejects_duplicate_out_of_band_marker() {
        let dir = scratch_dir();
        let store = store_in(&dir);
        let mut a = req(&dir.join("a").to_string_lossy(), VALID_AWS);
        a.canary_marker = None; // isolate the oob-marker uniqueness path
        a.out_of_band = Some(oob("dns", "trk-a", "shared.canary.example.net"));
        assert!(deploy(&store, a).is_ok());

        let mut b = req(&dir.join("b").to_string_lossy(), VALID_AWS);
        b.canary_marker = None;
        b.out_of_band = Some(oob("dns", "trk-b", "shared.canary.example.net"));
        let err = deploy(&store, b).unwrap_err().to_string();
        assert!(err.contains("out-of-band canary marker"), "got: {err}");
        assert!(!dir.join("b").exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn breadcrumb_create_is_placed_and_revoked() {
        let dir = scratch_dir();
        let store = store_in(&dir);
        let token = dir.join(".aws").join("credentials");
        let crumb = dir.join("notes").join("deploy.txt");

        let mut r = req(&token.to_string_lossy(), VALID_AWS);
        r.breadcrumbs = vec![Breadcrumb {
            path: crumb.to_string_lossy().into_owned(),
            content: b"see ~/.aws/credentials for the prod key\n".to_vec(),
            mode: 0o600,
            append: false,
        }];
        let rec = deploy(&store, r).unwrap();
        assert_eq!(rec.breadcrumbs.len(), 1);
        assert!(crumb.exists(), "breadcrumb file must be created");

        revoke(&store, &token.to_string_lossy()).unwrap();
        assert!(!crumb.exists(), "revoke must remove the created breadcrumb");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn breadcrumb_append_is_safe_and_reversible() {
        let dir = scratch_dir();
        let store = store_in(&dir);
        let token = dir.join(".aws").join("credentials");
        let history = dir.join(".bash_history");
        // Pre-existing history WITHOUT a trailing newline — append must not glue
        // its line onto the last command.
        fs::write(&history, b"ls -la\ncat /etc/passwd").unwrap();
        let original = fs::read(&history).unwrap();

        let mut r = req(&token.to_string_lossy(), VALID_AWS);
        r.breadcrumbs = vec![Breadcrumb {
            path: history.to_string_lossy().into_owned(),
            content: b"mysql -u root -psup3rs3cret prod_db".to_vec(),
            mode: 0o600,
            append: true,
        }];
        let rec = deploy(&store, r).unwrap();

        let after = fs::read_to_string(&history).unwrap();
        assert!(
            after.starts_with("ls -la\ncat /etc/passwd\n"),
            "must not clobber prior history: {after:?}"
        );
        assert!(after.contains("mysql -u root -psup3rs3cret prod_db"));
        assert!(rec.breadcrumbs[0].appended);

        // Revoke removes exactly our appended block, restoring the original file.
        revoke(&store, &token.to_string_lossy()).unwrap();
        assert_eq!(
            fs::read(&history).unwrap(),
            original,
            "history must be restored byte-for-byte"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn breadcrumb_append_left_intact_if_file_changed() {
        let dir = scratch_dir();
        let store = store_in(&dir);
        let token = dir.join(".aws").join("credentials");
        let history = dir.join(".bash_history");
        fs::write(&history, b"first\n").unwrap();

        let mut r = req(&token.to_string_lossy(), VALID_AWS);
        r.breadcrumbs = vec![Breadcrumb {
            path: history.to_string_lossy().into_owned(),
            content: b"leaked-cmd --token abc".to_vec(),
            mode: 0o600,
            append: true,
        }];
        deploy(&store, r).unwrap();
        // The user writes more history after our breadcrumb.
        {
            use std::io::Write as _;
            let mut f = OpenOptions::new().append(true).open(&history).unwrap();
            f.write_all(b"later-command\n").unwrap();
        }
        // Revoke must NOT corrupt the file: our block is no longer the tail.
        revoke(&store, &token.to_string_lossy()).unwrap();
        let after = fs::read_to_string(&history).unwrap();
        assert!(
            after.contains("leaked-cmd --token abc"),
            "left intact when tail changed"
        );
        assert!(after.ends_with("later-command\n"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn verify_reports_present_modified_and_missing() {
        let dir = scratch_dir();
        let store = store_in(&dir);
        let path = dir.join(".aws").join("credentials");
        let path_s = path.to_string_lossy().into_owned();
        let rec = deploy(&store, req(&path_s, VALID_AWS)).unwrap();

        // Freshly planted: present, unmodified, digest matches the record.
        let h = verify_record(&rec);
        assert!(
            h.present && !h.modified,
            "fresh token is present & unmodified"
        );
        assert_eq!(h.actual_sha256.as_deref(), Some(rec.sha256.as_str()));
        assert_eq!(h.status_label(), "present");

        // Tampered out-of-band (edited without going through the agent): present
        // but the digest no longer matches → modified.
        fs::write(&path, b"someone edited the bait\n").unwrap();
        let h = verify_record(&rec);
        assert!(h.present && h.modified, "edited token is flagged modified");
        assert_eq!(h.status_label(), "modified");

        // Deleted out-of-band: missing.
        fs::remove_file(&path).unwrap();
        let h = verify_record(&rec);
        assert!(!h.present && !h.modified, "deleted token is missing");
        assert_eq!(h.status_label(), "missing");

        let _ = fs::remove_dir_all(&dir);
    }
}
