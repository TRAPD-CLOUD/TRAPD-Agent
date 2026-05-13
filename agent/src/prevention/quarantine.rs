//! File quarantine + restore.
//!
//! Quarantine flow:
//!   1. Hash the file (SHA256) → become its on-disk identifier.
//!   2. Stat original to capture mode/uid/gid/path.
//!   3. Move into `/var/lib/trapd/quarantine/<sha256>.bin` (same filesystem
//!      preferred; falls back to copy+remove across mountpoints).
//!   4. `chmod 000` and `chattr +i` (immutable) so the payload can't run or
//!      be tampered with without explicit root removal of the `+i` flag.
//!   5. Append a `QuarantineRecord` to the JSON index for restoration.
//!
//! Restore reverses every step.  Both write to the index atomically.

use std::fs;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::{info, warn};
use uuid::Uuid;

use super::{QUARANTINE_DIR, QUARANTINE_INDEX};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineRecord {
    pub id:            Uuid,
    pub original_path: String,
    pub stored_path:   String,
    pub sha256:        String,
    pub size_bytes:    u64,
    pub mode:          u32,
    pub uid:           u32,
    pub gid:           u32,
    pub quarantined_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct QuarantineIndex {
    #[serde(default)]
    pub records: Vec<QuarantineRecord>,
}

impl QuarantineIndex {
    pub fn load() -> Self {
        let path = Path::new(QUARANTINE_INDEX);
        if !path.exists() { return Self::default(); }
        match fs::read(path) {
            Ok(b)  => serde_json::from_slice(&b).unwrap_or_default(),
            Err(_) => Self::default(),
        }
    }

    pub fn save(&self) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(self)?;
        let tmp = PathBuf::from(format!("{QUARANTINE_INDEX}.tmp"));
        fs::write(&tmp, bytes).context("write tmp index")?;
        fs::rename(&tmp, QUARANTINE_INDEX).context("rename index")?;
        Ok(())
    }
}

/// Quarantine a file.  Returns the record (also persisted to the index).
pub fn quarantine(path: &Path) -> Result<QuarantineRecord> {
    if !path.exists() {
        bail!("quarantine target does not exist: {}", path.display());
    }
    let meta = fs::metadata(path).context("stat target")?;
    if !meta.is_file() {
        bail!("not a regular file: {}", path.display());
    }
    let size = meta.len();
    let mode = meta.mode();
    let uid  = meta.uid();
    let gid  = meta.gid();

    let sha = sha256_of(path)?;

    fs::create_dir_all(QUARANTINE_DIR).context("create quarantine dir")?;
    let _ = set_mode(Path::new(QUARANTINE_DIR), 0o700);

    let stored = PathBuf::from(format!("{QUARANTINE_DIR}/{sha}.bin"));

    move_or_copy(path, &stored)?;

    if let Err(e) = set_mode(&stored, 0o000) {
        warn!(path = %stored.display(), error = %e, "chmod 000 on quarantined file failed");
    }
    if let Err(e) = chattr_immutable(&stored, true) {
        warn!(path = %stored.display(), error = %e, "chattr +i failed");
    }

    let record = QuarantineRecord {
        id:            Uuid::new_v4(),
        original_path: path.to_string_lossy().into_owned(),
        stored_path:   stored.to_string_lossy().into_owned(),
        sha256:        sha,
        size_bytes:    size,
        mode,
        uid,
        gid,
        quarantined_at: Utc::now(),
    };

    let mut idx = QuarantineIndex::load();
    idx.records.push(record.clone());
    idx.save()?;

    info!(
        original = %record.original_path,
        stored   = %record.stored_path,
        sha256   = %record.sha256,
        "file quarantined",
    );

    Ok(record)
}

/// Reverse quarantine.  Identified by the `QuarantineRecord::id`.
pub fn restore(quarantine_id: &Uuid) -> Result<QuarantineRecord> {
    let mut idx = QuarantineIndex::load();
    let pos = idx.records.iter().position(|r| r.id == *quarantine_id)
        .ok_or_else(|| anyhow!("no quarantine record with id {quarantine_id}"))?;
    let record = idx.records.remove(pos);

    let stored = Path::new(&record.stored_path);
    let original = Path::new(&record.original_path);

    let _ = chattr_immutable(stored, false);

    if let Some(parent) = original.parent() {
        fs::create_dir_all(parent).ok();
    }

    move_or_copy(stored, original)?;

    let _ = set_mode(original, record.mode);
    let _ = chown(original, record.uid, record.gid);

    idx.save()?;
    info!(
        original = %record.original_path,
        sha256   = %record.sha256,
        "file restored from quarantine",
    );
    Ok(record)
}

fn sha256_of(path: &Path) -> Result<String> {
    let mut f = fs::File::open(path).context("open for hashing")?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 65_536];
    loop {
        let n = f.read(&mut buf).context("read for hashing")?;
        if n == 0 { break; }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn move_or_copy(src: &Path, dst: &Path) -> Result<()> {
    if let Err(e) = fs::rename(src, dst) {
        if e.raw_os_error() == Some(libc_exdev()) || cfg!(test) {
            fs::copy(src, dst).with_context(|| format!("copy {} → {}", src.display(), dst.display()))?;
            fs::remove_file(src).with_context(|| format!("remove {}", src.display()))?;
        } else {
            return Err(e).with_context(|| format!("rename {} → {}", src.display(), dst.display()));
        }
    }
    Ok(())
}

fn libc_exdev() -> i32 { 18 } // EXDEV

#[cfg(target_os = "linux")]
fn set_mode(p: &Path, mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = fs::metadata(p)?.permissions();
    perms.set_mode(mode);
    fs::set_permissions(p, perms)
}

#[cfg(not(target_os = "linux"))]
fn set_mode(_p: &Path, _m: u32) -> std::io::Result<()> { Ok(()) }

#[cfg(target_os = "linux")]
fn chown(p: &Path, uid: u32, gid: u32) -> Result<()> {
    use nix::unistd::{chown as nix_chown, Gid, Uid};
    nix_chown(p, Some(Uid::from_raw(uid)), Some(Gid::from_raw(gid)))
        .context("chown failed")
}

#[cfg(not(target_os = "linux"))]
fn chown(_p: &Path, _u: u32, _g: u32) -> Result<()> { Ok(()) }

/// Toggle the ext-family `i` (immutable) attribute via `chattr(1)`.
fn chattr_immutable(p: &Path, set: bool) -> Result<()> {
    let flag = if set { "+i" } else { "-i" };
    let out  = std::process::Command::new("chattr")
        .arg(flag)
        .arg(p)
        .output()
        .context("spawn chattr")?;
    if !out.status.success() {
        bail!("chattr {flag} {} failed: {}", p.display(),
              String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(())
}
