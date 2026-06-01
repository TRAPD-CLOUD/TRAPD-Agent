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

use std::fs::{self, OpenOptions};
use std::path::{Component, Path, PathBuf};
use std::time::SystemTime;

use anyhow::{bail, Context, Result};
use chrono::Utc;
use sha2::{Digest, Sha256};
use tracing::{info, warn};
use uuid::Uuid;

pub use profiler::{build_profile, ReconProfile};
pub use registry::{HoneytokenRecord, HoneytokenStore};

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
    pub canary_marker: Option<String>,
    /// Token family from the recon candidate, if the backend echoed it back.
    pub kind: Option<String>,
    /// Id of the signed command requesting this deployment.
    pub command_id: Option<String>,
}

/// Place a honeytoken with camouflage and record it in the register.
///
/// Returns the persisted [`HoneytokenRecord`] on success. Fails (without side
/// effects on the target) if a safety invariant is violated.
pub fn deploy(store: &HoneytokenStore, req: DeployRequest) -> Result<HoneytokenRecord> {
    let target = validate_target(&req.path)?;

    // Hard safety rule: never clobber an existing file. `symlink_metadata`
    // (lstat) catches a symlink planted at the path too — we treat any
    // existing entry, symlink included, as "occupied" and refuse.
    if target.symlink_metadata().is_ok() {
        bail!("refusing to deploy honeytoken: {} already exists", target.display());
    }

    let parent = target
        .parent()
        .ok_or_else(|| anyhow::anyhow!("target has no parent directory: {}", target.display()))?;
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

    write_camouflaged(&target, &req.content, mode, owner, times)
        .with_context(|| format!("write honeytoken to {}", target.display()))?;

    let record = HoneytokenRecord {
        id: Uuid::new_v4(),
        path: target.to_string_lossy().into_owned(),
        kind: req.kind.unwrap_or_else(|| "unknown".to_string()),
        mode,
        size_bytes: size,
        sha256: sha,
        mimic_neighbor: req.mimic_neighbor,
        neighbor_path,
        canary_marker: req.canary_marker,
        deployed_at: Utc::now(),
        command_id: req.command_id,
    };

    store.insert(record.clone()).context("record deployed honeytoken")?;

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
    if !store.contains_path(path) {
        bail!("refusing to revoke {path}: not a registered honeytoken");
    }

    // Remove the file first; tolerate it being already gone (an attacker may
    // have moved/deleted it — that is itself signal, but not an error here).
    match fs::remove_file(path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            warn!(path, "honeytoken file already absent at revoke time");
        }
        Err(e) => return Err(e).with_context(|| format!("remove honeytoken {path}")),
    }

    let record = store
        .remove_by_path(path)
        .context("update honeytoken register")?
        .ok_or_else(|| anyhow::anyhow!("honeytoken vanished from register during revoke: {path}"))?;

    info!(path, "honeytoken revoked");
    Ok(record)
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
        target.file_name().and_then(|s| s.to_str()).unwrap_or("token"),
        std::process::id()
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
        fs::rename(&tmp, target)
            .with_context(|| format!("rename {} -> {}", tmp.display(), target.display()))?;
        Ok(())
    })();

    if result.is_err() {
        let _ = fs::remove_file(&tmp);
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

#[cfg(unix)]
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

#[cfg(unix)]
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

#[cfg(target_os = "linux")]
fn chown(path: &Path, uid: u32, gid: u32) -> Result<()> {
    use nix::unistd::{chown as nix_chown, Gid, Uid};
    nix_chown(path, Some(Uid::from_raw(uid)), Some(Gid::from_raw(gid))).context("chown failed")
}

#[cfg(not(target_os = "linux"))]
fn chown(_path: &Path, _uid: u32, _gid: u32) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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

    fn req(path: &str, content: &str) -> DeployRequest {
        DeployRequest {
            path: path.to_string(),
            content: content.as_bytes().to_vec(),
            mode: 0o600,
            mimic_neighbor: false,
            canary_marker: Some("AKIACANARYEXAMPLE".into()),
            kind: Some("aws_credentials".into()),
            command_id: Some("cmd-1".into()),
        }
    }

    #[test]
    fn deploy_then_revoke_roundtrip() {
        let dir = scratch_dir();
        let store = store_in(&dir);
        let path = dir.join(".aws").join("credentials");
        let path_s = path.to_string_lossy().into_owned();

        let rec = deploy(&store, req(&path_s, "[default]\naws_access_key_id=AKIA...\n")).unwrap();
        assert!(path.exists());
        assert_eq!(rec.kind, "aws_credentials");
        assert_eq!(rec.canary_marker.as_deref(), Some("AKIACANARYEXAMPLE"));
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

        let err = deploy(&store, req(&path.to_string_lossy(), "bait")).unwrap_err();
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
        assert!(deploy(&store, req("relative/path", "x")).unwrap_err().to_string().contains("absolute"));
        assert!(deploy(&store, req("/tmp/../etc/x", "x")).unwrap_err().to_string().contains(".."));
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
        OpenOptions::new().write(true).open(&neighbor).unwrap().set_times(ft).unwrap();

        let target = dir.join("id_rsa_backup");
        let mut r = req(&target.to_string_lossy(), "bait-key");
        r.mimic_neighbor = true;
        let rec = deploy(&store, r).unwrap();

        assert!(rec.neighbor_path.is_some());
        let placed = fs::metadata(&target).unwrap().modified().unwrap();
        assert_eq!(placed, old, "mtime should be aligned to the neighbour");
        let _ = fs::remove_dir_all(&dir);
    }
}
