//! File quarantine + restore.
//!
//! Linux uses descriptor-pinned transactions in `quarantine_linux.rs`: it
//! captures the source in private staging, copies to a fresh mode-000 vault
//! inode and commits the index before removing the original. Restore verifies
//! the digest and publishes without replacing an existing destination.
//!
//! Windows quarantine flow:
//!   1. Hash the file (SHA256) → become its on-disk identifier.
//!   2. Stat original to capture mode/uid/gid/path.
//!   3. Move into `/var/lib/trapd/quarantine/<sha256>.bin` (same filesystem
//!      preferred; falls back to copy+remove across mountpoints).
//!   4. `chmod 000` and `chattr +i` (immutable) so the payload can't run or
//!      be tampered with without explicit root removal of the `+i` flag.
//!      On Windows the DACL is replaced by SYSTEM + Administrators only and the
//!      owner is SYSTEM; the original owner and DACL are kept in the record.
//!   5. Append a `QuarantineRecord` to the JSON index for restoration.
//!
//! Restore reverses every step.  Both write to the index atomically.

#[cfg(any(test, not(target_os = "linux")))]
use std::fs;
#[cfg(not(target_os = "linux"))]
use std::io::Read;
#[cfg(all(unix, not(target_os = "linux")))]
use std::os::unix::fs::MetadataExt;
use std::path::Path;
#[cfg(any(test, not(target_os = "linux")))]
use std::path::PathBuf;

#[cfg(not(target_os = "linux"))]
use anyhow::anyhow;
use anyhow::{bail, Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
#[cfg(not(target_os = "linux"))]
use sha2::{Digest, Sha256};
#[cfg(not(target_os = "linux"))]
use tracing::{info, warn};
use uuid::Uuid;

use super::{quarantine_dir, quarantine_index};

#[cfg(target_os = "linux")]
#[path = "quarantine_linux.rs"]
mod linux;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineRecord {
    pub id: Uuid,
    pub original_path: String,
    pub stored_path: String,
    pub sha256: String,
    pub size_bytes: u64,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    /// Windows only: original owner + DACL (SDDL), re-applied on restore.
    /// Older records contain only a DACL and remain compatible.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security_descriptor: Option<String>,
    pub quarantined_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct QuarantineIndex {
    #[serde(default)]
    pub records: Vec<QuarantineRecord>,
}

#[cfg(not(target_os = "linux"))]
impl QuarantineIndex {
    pub fn load() -> Self {
        let index = quarantine_index();
        let path = index.as_path();
        if !path.exists() {
            return Self::default();
        }
        match fs::read(path) {
            Ok(b) => serde_json::from_slice(&b).unwrap_or_default(),
            Err(_) => Self::default(),
        }
    }

    pub fn save(&self) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(self)?;
        let tmp = PathBuf::from(format!("{}.tmp", quarantine_index().display()));
        fs::write(&tmp, bytes).context("write tmp index")?;
        fs::rename(&tmp, quarantine_index()).context("rename index")?;
        Ok(())
    }
}

/// Quarantine a file.  Returns the record (also persisted to the index).
#[cfg(target_os = "linux")]
pub fn quarantine(path: &Path) -> Result<QuarantineRecord> {
    linux::quarantine(path)
}

#[cfg(not(target_os = "linux"))]
pub fn quarantine(path: &Path) -> Result<QuarantineRecord> {
    #[cfg(windows)]
    {
        // An explicitly signed operator target may use aliases. Resolve them
        // before pinning; automatic-only OS exclusions do not apply here.
        let resolved = fs::canonicalize(path).context("resolve signed quarantine target")?;
        let mut source = super::winquarantine::Source::pin(&resolved)?;
        quarantine_inner(&resolved, Some(&mut source))
    }
    #[cfg(not(windows))]
    quarantine_inner(path)
}

/// Windows copies a fresh object to revoke even previously granted source
/// handles. Bound primary + alternate data streams before hashing/copying so
/// sparse or enormous files cannot exhaust the state volume or stall collection.
#[cfg_attr(not(windows), allow(dead_code))]
pub(super) fn checked_windows_copy_size(sizes: impl IntoIterator<Item = u64>) -> Result<u64> {
    const MAX_COPY_BYTES: u64 = 1 << 30;
    let mut total = 0u64;
    for size in sizes {
        total = total
            .checked_add(size)
            .context("quarantine stream sizes overflow")?;
    }
    if total > MAX_COPY_BYTES {
        bail!("Windows quarantine exceeds the aggregate 1 GiB copy limit");
    }
    Ok(total)
}

/// Automatic targets are untrusted. Windows retains all source/parent handles
/// through validation and copying so a junction or leaf replacement cannot
/// redirect privileged file operations after canonicalization.
#[cfg(target_os = "linux")]
pub fn quarantine_automatic(path: &Path) -> Result<QuarantineRecord> {
    linux::quarantine(path)
}

#[cfg(not(target_os = "linux"))]
pub fn quarantine_automatic(path: &Path) -> Result<QuarantineRecord> {
    #[cfg(windows)]
    {
        let mut source = super::winquarantine::Source::pin(path)?;
        let validated = super::response::validated_quarantine_path(
            path.to_str().context("quarantine target is not Unicode")?,
        )
        .context("automatic quarantine target is protected or invalid")?;
        quarantine_inner(Path::new(&validated), Some(&mut source))
    }
    #[cfg(not(windows))]
    {
        quarantine_inner(path)
    }
}

#[cfg(not(target_os = "linux"))]
fn quarantine_inner(
    path: &Path,
    #[cfg(windows)] native: Option<&mut super::winquarantine::Source>,
) -> Result<QuarantineRecord> {
    if !path.exists() {
        bail!("quarantine target does not exist: {}", path.display());
    }
    let meta = fs::metadata(path).context("stat target")?;
    if !meta.is_file() {
        bail!("not a regular file: {}", path.display());
    }
    let size = meta.len();
    #[cfg(unix)]
    let (mode, uid, gid) = (meta.mode(), meta.uid(), meta.gid());
    // Windows has no unix mode/uid/gid; record zeros so the restore path (which
    // only re-applies them on unix) stays schema-compatible.
    #[cfg(not(unix))]
    let (mode, uid, gid) = (0u32, 0u32, 0u32);

    let sha = sha256_of(path)?;
    let original_security = capture_security(path)?;

    fs::create_dir_all(quarantine_dir()).context("create quarantine dir")?;
    let _ = set_mode(&quarantine_dir(), 0o700);
    #[cfg(windows)]
    crate::winacl::set_file_security(&quarantine_dir(), "O:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
        .context("restrict quarantine directory owner and DACL")?;

    let id = Uuid::new_v4();
    #[cfg(windows)]
    let stored = quarantine_dir().join(if native.is_some() {
        format!("{sha}-{id}.bin")
    } else {
        format!("{sha}.bin")
    });
    #[cfg(not(windows))]
    let stored = quarantine_dir().join(format!("{sha}.bin"));

    #[cfg(windows)]
    if let Some(source) = native.as_ref() {
        source.copy_to(&stored)?;
    } else {
        move_into_quarantine(path, &stored, &original_security)?;
    }
    #[cfg(not(windows))]
    move_into_quarantine(path, &stored, &original_security)?;

    let record = QuarantineRecord {
        id,
        original_path: path.to_string_lossy().into_owned(),
        stored_path: stored.to_string_lossy().into_owned(),
        sha256: sha,
        size_bytes: size,
        mode,
        uid,
        gid,
        security_descriptor: original_security,
        quarantined_at: Utc::now(),
    };

    let mut idx = QuarantineIndex::load();
    idx.records.push(record.clone());
    #[cfg(windows)]
    if let Err(error) = idx.save() {
        if let Some(source) = native {
            source
                .cancel(&stored)
                .context("undo unindexed automatic quarantine")?;
        }
        return Err(error);
    }
    #[cfg(not(windows))]
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
#[cfg(target_os = "linux")]
pub fn restore(quarantine_id: &Uuid) -> Result<QuarantineRecord> {
    linux::restore(quarantine_id)
}

#[cfg(not(target_os = "linux"))]
pub fn restore(quarantine_id: &Uuid) -> Result<QuarantineRecord> {
    let mut idx = QuarantineIndex::load();
    let pos = idx
        .records
        .iter()
        .position(|r| r.id == *quarantine_id)
        .ok_or_else(|| anyhow!("no quarantine record with id {quarantine_id}"))?;
    let record = idx.records.remove(pos);

    let stored = Path::new(&record.stored_path);
    let original = Path::new(&record.original_path);

    unlock(stored);

    if let Some(parent) = original.parent() {
        fs::create_dir_all(parent).ok();
    }

    move_or_copy(stored, original)?;

    if let Err(error) = restore_attributes(original, &record) {
        // Preserve the indexed stored location when original security cannot be
        // restored. The index has not yet been removed on disk.
        move_or_copy(original, stored).context("return failed restore to quarantine")?;
        return Err(error);
    }

    idx.save()?;
    info!(
        original = %record.original_path,
        sha256   = %record.sha256,
        "file restored from quarantine",
    );
    Ok(record)
}

#[cfg(not(target_os = "linux"))]
fn sha256_of(path: &Path) -> Result<String> {
    let mut f = fs::File::open(path).context("open for hashing")?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 65_536];
    loop {
        let n = f.read(&mut buf).context("read for hashing")?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

/// Protect the Windows source before publishing a predictable stored path. A
/// same-volume rename preserves that owner/DACL; cross-volume copies receive
/// the protected directory ACL and are explicitly assigned SYSTEM ownership.
#[cfg(not(target_os = "linux"))]
fn move_into_quarantine(src: &Path, dst: &Path, original_security: &Option<String>) -> Result<()> {
    #[cfg(windows)]
    lock_down(src)?;
    let result = move_or_copy(src, dst).and_then(|()| lock_down(dst));
    #[cfg(windows)]
    if let Err(error) = result {
        if !src.exists() && dst.exists() {
            move_or_copy(dst, src).context("undo failed quarantine movement")?;
        }
        if let Some(sddl) = original_security {
            crate::winacl::set_file_security(src, sddl)
                .context("restore original security after failed quarantine movement")?;
        }
        return Err(error);
    }
    #[cfg(not(windows))]
    let _ = original_security;
    result
}

#[cfg(not(target_os = "linux"))]
fn move_or_copy(src: &Path, dst: &Path) -> Result<()> {
    let mut attempts = 0;
    loop {
        match fs::rename(src, dst) {
            Ok(()) => return Ok(()),
            Err(e) if e.raw_os_error() == Some(cross_device_code()) || cfg!(test) => {
                fs::copy(src, dst)
                    .with_context(|| format!("copy {} → {}", src.display(), dst.display()))?;
                fs::remove_file(src).with_context(|| format!("remove {}", src.display()))?;
                return Ok(());
            }
            // Windows keeps a just-terminated executable locked for a moment
            // (and an AV scan may hold it briefly); a short, bounded retry is
            // the difference between quarantining the dropper and failing.
            Err(e) if is_transient_lock(&e) && attempts < 5 => {
                attempts += 1;
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            Err(e) => {
                return Err(e)
                    .with_context(|| format!("rename {} → {}", src.display(), dst.display()))
            }
        }
    }
}

/// `EXDEV` on Unix, `ERROR_NOT_SAME_DEVICE` on Windows.
#[cfg(any(test, not(target_os = "linux")))]
fn cross_device_code() -> i32 {
    if cfg!(windows) {
        17
    } else {
        18
    }
}

/// `ERROR_SHARING_VIOLATION` / `ERROR_LOCK_VIOLATION`.
#[cfg(any(test, not(target_os = "linux")))]
fn is_transient_lock(e: &std::io::Error) -> bool {
    cfg!(windows) && matches!(e.raw_os_error(), Some(32) | Some(33))
}

#[cfg(not(target_os = "linux"))]
fn set_mode(_p: &Path, _m: u32) -> std::io::Result<()> {
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn chown(_p: &Path, _u: u32, _g: u32) -> Result<()> {
    Ok(())
}

/// Make the stored payload unusable and tamper-resistant: `chmod 000` +
/// `chattr +i` on Linux, a SYSTEM/Administrators-only DACL on Windows.
#[cfg(not(target_os = "linux"))]
fn lock_down(stored: &Path) -> Result<()> {
    #[cfg(not(windows))]
    {
        if let Err(e) = set_mode(stored, 0o000) {
            warn!(path = %stored.display(), error = %e, "chmod 000 on quarantined file failed");
        }
        if let Err(e) = chattr_immutable(stored, true) {
            warn!(path = %stored.display(), error = %e, "chattr +i failed");
        }
    }
    #[cfg(windows)]
    {
        crate::winacl::set_file_security(stored, crate::winacl::QUARANTINE_FILE_SDDL)
            .context("assign SYSTEM ownership and restrict quarantined payload")?;
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn unlock(stored: &Path) {
    #[cfg(not(windows))]
    {
        let _ = chattr_immutable(stored, false);
    }
    #[cfg(windows)]
    {
        // SYSTEM already has full control; nothing to lift.
        let _ = stored;
    }
}

/// Original ACL of `path` (Windows); Unix keeps mode/uid/gid instead.
#[cfg(not(target_os = "linux"))]
fn capture_security(path: &Path) -> Result<Option<String>> {
    #[cfg(windows)]
    {
        crate::winacl::get_file_security(path)
            .map(Some)
            .context("capture original owner and DACL before quarantine")
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        Ok(None)
    }
}

#[cfg(not(target_os = "linux"))]
fn restore_attributes(original: &Path, record: &QuarantineRecord) -> Result<()> {
    #[cfg(not(windows))]
    {
        let _ = set_mode(original, record.mode);
        let _ = chown(original, record.uid, record.gid);
    }
    #[cfg(windows)]
    {
        match &record.security_descriptor {
            Some(sddl) => {
                crate::winacl::set_file_security(original, sddl)
                    .context("restore original owner and DACL")?;
            }
            None => warn!(
                path = %original.display(),
                "no original DACL recorded; the restored file keeps its destination ACL"
            ),
        }
    }
    Ok(())
}

/// Toggle the ext-family `i` (immutable) attribute via `chattr(1)`.
#[cfg_attr(windows, allow(dead_code))]
#[cfg(not(target_os = "linux"))]
fn chattr_immutable(p: &Path, set: bool) -> Result<()> {
    let flag = if set { "+i" } else { "-i" };
    // Resolve chattr by absolute path rather than via $PATH: a tampered $PATH
    // or a shadowed `chattr` earlier in the search order could otherwise make
    // quarantine appear to succeed while the immutable flag is never set.
    let out = std::process::Command::new(chattr_bin())
        .arg(flag)
        .arg(p)
        .output()
        .context("spawn chattr")?;
    if !out.status.success() {
        bail!(
            "chattr {flag} {} failed: {}",
            p.display(),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

/// First existing well-known absolute path to `chattr`, defaulting to the most
/// common location so a clear "not found" error surfaces if it is truly absent.
#[cfg(not(target_os = "linux"))]
fn chattr_bin() -> &'static str {
    const CANDIDATES: &[&str] = &["/usr/bin/chattr", "/bin/chattr", "/usr/sbin/chattr"];
    CANDIDATES
        .iter()
        .copied()
        .find(|p| Path::new(p).exists())
        .unwrap_or("/usr/bin/chattr")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_copy_budget_counts_all_streams_and_rejects_overflow() {
        assert_eq!(checked_windows_copy_size([1 << 30]).unwrap(), 1 << 30);
        assert_eq!(checked_windows_copy_size([7, 0, 11]).unwrap(), 18);
        assert!(checked_windows_copy_size([1 << 29, (1 << 29) + 1]).is_err());
        assert!(checked_windows_copy_size([u64::MAX, 1]).is_err());
    }

    #[test]
    fn records_written_before_the_security_descriptor_field_still_load() {
        let legacy = r#"{"records":[{"id":"3f2b6f0e-6e4e-4f0e-9d58-0a1a2b3c4d5e",
            "original_path":"/tmp/x","stored_path":"/var/lib/trapd/quarantine/ab.bin",
            "sha256":"ab","size_bytes":3,"mode":420,"uid":0,"gid":0,
            "quarantined_at":"2026-01-01T00:00:00Z"}]}"#;
        let idx: QuarantineIndex = serde_json::from_str(legacy).expect("legacy index must load");
        assert_eq!(idx.records.len(), 1);
        assert!(idx.records[0].security_descriptor.is_none());
        // A Unix record must not grow a field a downgraded agent would reject.
        let json = serde_json::to_string(&idx.records[0]).unwrap();
        assert!(!json.contains("security_descriptor"));
    }

    #[test]
    fn only_windows_treats_sharing_violations_as_transient() {
        let e = std::io::Error::from_raw_os_error(32);
        assert_eq!(is_transient_lock(&e), cfg!(windows));
        assert_eq!(cross_device_code(), if cfg!(windows) { 17 } else { 18 });
    }
}

#[cfg(all(test, windows))]
mod windows_tests {
    use super::*;

    #[test]
    fn failed_quarantine_move_restores_the_original_owner_and_dacl() {
        let dir = std::env::temp_dir().join(format!("trapd-q-failed-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let victim = dir.join("payload.exe");
        std::fs::write(&victim, b"payload").unwrap();
        let original = crate::winacl::get_file_security(&victim).unwrap();
        let target = dir.join("missing-parent/payload.bin");
        assert!(move_into_quarantine(&victim, &target, &Some(original.clone())).is_err());
        assert!(victim.exists());
        let after = crate::winacl::get_file_security(&victim).unwrap();
        assert_eq!(after.split("D:").next(), original.split("D:").next());
        assert_eq!(after.split('(').count(), original.split('(').count());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn quarantine_locks_the_payload_down_and_restore_brings_it_back() {
        use std::os::windows::fs::OpenOptionsExt;
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Security::Authorization::{SetSecurityInfo, SE_FILE_OBJECT};
        use windows_sys::Win32::Security::{ACL, DACL_SECURITY_INFORMATION};
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
            READ_CONTROL, WRITE_DAC,
        };
        let dir = std::env::temp_dir().join(format!("trapd-q-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let victim = dir.join("dropper.exe");
        std::fs::write(&victim, b"MZ-not-really").unwrap();
        let zone = |path: &Path| {
            let mut p = path.as_os_str().to_os_string();
            p.push(":Zone.Identifier");
            PathBuf::from(p)
        };
        std::fs::write(zone(&victim), b"[ZoneTransfer]\r\nZoneId=3\r\n").unwrap();
        let before = crate::winacl::get_file_security(&victim).unwrap();
        let retained = fs::OpenOptions::new()
            .access_mode(READ_CONTROL | WRITE_DAC | FILE_READ_ATTRIBUTES)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .open(&victim)
            .unwrap();

        // Positively verify the old grant controls the original before it is
        // delete-pending. Restore its descriptor before capturing the record.
        // SAFETY: the retained handle grants WRITE_DAC; null DACL affects only
        // this temporary original file.
        assert_eq!(
            unsafe {
                SetSecurityInfo(
                    retained.as_raw_handle() as _,
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null::<ACL>(),
                    std::ptr::null(),
                )
            },
            0
        );
        assert_ne!(crate::winacl::get_file_security(&victim).unwrap(), before);
        crate::winacl::set_file_security(&victim, &before).unwrap();

        let record = quarantine(&victim).expect("quarantine");
        // A pre-existing handle delays directory-entry removal. Delete-pending
        // must already prevent new data access, even while metadata exists.
        let denied =
            fs::File::open(&victim).expect_err("pending original must reject new data opens");
        assert!(
            matches!(denied.raw_os_error(), Some(5 | 303)),
            "expected ACCESS_DENIED or DELETE_PENDING, got {denied}"
        );
        let stored = Path::new(&record.stored_path);
        assert!(stored.exists());
        assert_eq!(
            std::fs::read(zone(stored)).unwrap(),
            b"[ZoneTransfer]\r\nZoneId=3\r\n"
        );
        let locked = crate::winacl::get_file_security(stored).unwrap();
        assert!(
            locked.starts_with("O:SY"),
            "quarantine owner must be SYSTEM: {locked}"
        );
        assert!(
            locked.contains("D:P") && !locked.contains(";;;WD)"),
            "{locked}"
        );
        assert!(
            record.security_descriptor.is_some(),
            "original DACL recorded"
        );
        // The pre-granted handle still addresses the original generation. A
        // rename would have the same file identity and fail this assertion.
        let stored_handle = fs::OpenOptions::new()
            .access_mode(FILE_READ_ATTRIBUTES)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .open(stored)
            .unwrap();
        assert_ne!(
            super::super::winquarantine::file_identity(&retained).unwrap(),
            super::super::winquarantine::file_identity(&stored_handle).unwrap()
        );
        assert_eq!(crate::winacl::get_file_security(stored).unwrap(), locked);
        drop(stored_handle);
        drop(retained);
        assert!(
            !victim.exists(),
            "the original disappears after its last handle closes"
        );

        let restored = restore(&record.id).expect("restore");
        assert_eq!(restored.sha256, record.sha256);
        assert_eq!(std::fs::read(&victim).unwrap(), b"MZ-not-really");
        assert_eq!(
            std::fs::read(zone(&victim)).unwrap(),
            b"[ZoneTransfer]\r\nZoneId=3\r\n"
        );
        let after = crate::winacl::get_file_security(&victim).unwrap();
        assert_eq!(
            after.split("D:").next(),
            before.split("D:").next(),
            "original owner restored"
        );
        assert_eq!(
            after.split('(').count(),
            before.split('(').count(),
            "ACE count restored: {after} vs {before}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(all(test, target_os = "linux"))]
mod linux_security_tests {
    use super::*;
    use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};

    fn sandbox() -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("trapd-quarantine-security-{}", Uuid::new_v4()));
        fs::create_dir(&dir).unwrap();
        dir
    }

    #[test]
    fn quarantine_rejects_symlink_without_changing_referent() {
        let dir = sandbox();
        let victim = dir.join("victim");
        fs::write(&victim, b"unrelated").unwrap();
        fs::set_permissions(&victim, fs::Permissions::from_mode(0o640)).unwrap();
        let link = dir.join("link");
        symlink(&victim, &link).unwrap();
        let result = move_into_quarantine(&link, &dir.join("stored"), &None);
        assert!(result.is_err(), "a symlink must never be quarantined");
        assert_eq!(fs::metadata(&victim).unwrap().mode() & 0o777, 0o640);
        assert!(link.symlink_metadata().unwrap().file_type().is_symlink());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn restore_move_never_clobbers_existing_file() {
        let dir = sandbox();
        let stored = dir.join("stored");
        let destination = dir.join("destination");
        fs::write(&stored, b"quarantined").unwrap();
        fs::write(&destination, b"replacement").unwrap();
        assert!(move_or_copy(&stored, &destination).is_err());
        assert_eq!(fs::read(&destination).unwrap(), b"replacement");
        assert_eq!(fs::read(&stored).unwrap(), b"quarantined");
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn restore_move_rejects_redirected_parent() {
        let dir = sandbox();
        let destination_dir = dir.join("destination");
        fs::create_dir(&destination_dir).unwrap();
        let alias = dir.join("alias");
        symlink(&destination_dir, &alias).unwrap();
        let stored = dir.join("stored");
        fs::write(&stored, b"quarantined").unwrap();
        assert!(move_or_copy(&stored, &alias.join("payload")).is_err());
        assert!(!destination_dir.join("payload").exists());
        assert_eq!(fs::read(&stored).unwrap(), b"quarantined");
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn quarantine_does_not_chmod_hardlinked_file() {
        let dir = sandbox();
        let original = dir.join("original");
        let alias = dir.join("alias");
        let stored = dir.join("stored");
        fs::write(&original, b"payload").unwrap();
        fs::set_permissions(&original, fs::Permissions::from_mode(0o640)).unwrap();
        fs::hard_link(&original, &alias).unwrap();
        let result = move_into_quarantine(&alias, &stored, &None);
        assert_eq!(fs::metadata(&original).unwrap().mode() & 0o777, 0o640);
        if result.is_ok() {
            assert_ne!(
                fs::metadata(&original).unwrap().ino(),
                fs::metadata(&stored).unwrap().ino()
            );
            unlock(&stored);
        }
        fs::remove_dir_all(dir).unwrap();
    }
}

#[cfg(all(test, target_os = "linux"))]
fn move_or_copy(src: &Path, dst: &Path) -> Result<()> {
    linux::test_move(src, dst, false)
}
#[cfg(all(test, target_os = "linux"))]
fn move_into_quarantine(src: &Path, dst: &Path, _: &Option<String>) -> Result<()> {
    linux::test_move(src, dst, true)
}
#[cfg(all(test, target_os = "linux"))]
fn unlock(_: &Path) {}
