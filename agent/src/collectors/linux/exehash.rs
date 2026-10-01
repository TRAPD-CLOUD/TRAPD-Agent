//! Shared executable hashing — one cached, size-capped SHA256 implementation.
//!
//! Every exec is hashed once, at the point of collection, and the digest then
//! flows into the event (`exe_sha256`), the IOC hash-match in the detection
//! engine, and the IOA process-tree lineage.  Centralising it here means the
//! hot path hashes a given binary at most once per file identity and timestamps — repeated
//! execs of `bash`, `python`, … are cache hits — and never twice across the
//! exec tracer and the `/proc` poller.
//!
//! Bounds, so a busy host can never be stalled or grown without limit:
//!   * only absolute, regular files are hashed (memfd / `(deleted)` → `None`);
//!   * files larger than [`MAX_HASH_BYTES`] are skipped;
//!   * the cache is keyed by path, inode, size and nanosecond change times and cleared wholesale at a cap.
//!
//! Disable entirely with `TRAPD_EXEC_HASH=off`.

use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::sync::{Mutex, OnceLock};

/// Executables larger than this are not hashed (cost bound).
const MAX_HASH_BYTES: u64 = 64 * 1024 * 1024;
/// Cap on the cache before it is cleared wholesale.
const CACHE_CAP: usize = 8_192;

struct Cache {
    enabled: bool,
    entries: HashMap<String, (FileStamp, String)>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct FileStamp {
    dev: u64,
    inode: u64,
    size: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}

impl FileStamp {
    fn from_metadata(meta: &std::fs::Metadata) -> Self {
        Self {
            dev: meta.dev(),
            inode: meta.ino(),
            size: meta.len(),
            modified: (meta.mtime(), meta.mtime_nsec()),
            changed: (meta.ctime(), meta.ctime_nsec()),
        }
    }
}

fn cache() -> &'static Mutex<Cache> {
    static CACHE: OnceLock<Mutex<Cache>> = OnceLock::new();
    CACHE.get_or_init(|| {
        let enabled = !std::env::var("TRAPD_EXEC_HASH")
            .map(|v| {
                matches!(
                    v.trim().to_ascii_lowercase().as_str(),
                    "0" | "false" | "no" | "off"
                )
            })
            .unwrap_or(false);
        Mutex::new(Cache {
            enabled,
            entries: HashMap::new(),
        })
    })
}

/// SHA256 the executable at `path`, hex-encoded.  Returns `None` when hashing is
/// disabled, the path is not an absolute regular file, it exceeds
/// [`MAX_HASH_BYTES`], or the read fails.  Cached by opened-file identity and nanosecond change times.
pub fn hash_executable(path: &str) -> Option<String> {
    hash_executable_inner(path, false)
}

/// Prevention still evaluates configured hash rules when telemetry image
/// hashing is disabled. It shares the same bounded reader and identity cache.
pub(crate) fn hash_for_policy(path: &str) -> Option<String> {
    hash_executable_inner(path, true)
}

fn hash_executable_inner(path: &str, for_policy: bool) -> Option<String> {
    if path.is_empty() || !path.starts_with('/') || path.contains("(deleted)") {
        return None;
    }
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)
        .ok()?;
    let meta = file.metadata().ok()?;
    if !meta.is_file() || meta.len() > MAX_HASH_BYTES {
        return None;
    }
    let stamp = FileStamp::from_metadata(&meta);
    let guard = cache().lock().ok()?;
    if !for_policy && !guard.enabled {
        return None;
    }
    if let Some((cached_stamp, hash)) = guard.entries.get(path) {
        if *cached_stamp == stamp {
            return Some(hash.clone());
        }
    }
    drop(guard);
    let mut limited = (&mut file).take(MAX_HASH_BYTES + 1);
    let mut hasher = Sha256::new();
    let mut count = 0;
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = limited.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        count += n as u64;
        if count > MAX_HASH_BYTES {
            return None;
        }
        hasher.update(&buf[..n]);
    }
    // A concurrent edit is not a trustworthy image identity and must not
    // enter the cache. The opened handle also pins identity across rename.
    if FileStamp::from_metadata(&file.metadata().ok()?) != stamp {
        return None;
    }
    let hash = hex::encode(hasher.finalize());
    if let Ok(mut guard) = cache().lock() {
        if guard.entries.len() >= CACHE_CAP {
            guard.entries.clear();
        }
        guard
            .entries
            .insert(path.to_string(), (stamp, hash.clone()));
    }
    Some(hash)
}

/// Uncached SHA256 (hex) of an arbitrary file's contents.  Used by the FIM
/// collector, which keeps its own on-disk baseline and must not pollute (or be
/// served stale data by) the exec-hash cache.  Returns `None` on read error.
pub fn sha256_file(path: &std::path::Path) -> Option<String> {
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)
        .ok()?;
    let metadata = file.metadata().ok()?;
    if !metadata.is_file() {
        return None;
    }
    let stamp = FileStamp::from_metadata(&metadata);
    // Hash arbitrary stable files without buffering them. Growth while reading
    // cannot turn a scan into an unending stream.
    let mut limited = (&mut file).take(metadata.len().saturating_add(1));
    let mut hasher = Sha256::new();
    let mut bytes = 0u64;
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = limited.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        bytes += n as u64;
        if bytes > metadata.len() {
            return None;
        }
        hasher.update(&buf[..n]);
    }
    if bytes != metadata.len() || FileStamp::from_metadata(&file.metadata().ok()?) != stamp {
        return None;
    }

    Some(hex::encode(hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn replacing_executable_with_same_mtime_invalidates_cache() {
        let mut original = tempfile_in_tmp("trapd_cache_identity");
        original.write_all(b"good").unwrap();
        let path = original.path_str();
        let mtime = original.metadata().unwrap().modified().unwrap();
        let first = hash_executable(&path).unwrap();
        let mut replacement = tempfile_in_tmp("trapd_cache_replacement");
        replacement.write_all(b"evil").unwrap();
        replacement
            .set_times(std::fs::FileTimes::new().set_modified(mtime))
            .unwrap();
        std::fs::rename(replacement.path_str(), &path).unwrap();
        let second = hash_executable(&path).unwrap();
        assert_ne!(
            first, second,
            "same timestamp must not hide a replaced executable"
        );
    }

    #[test]
    fn hashes_a_real_file_and_caches_it() {
        let mut f = tempfile_in_tmp("trapd_exehash_test");
        f.write_all(b"hello trapd").unwrap();
        let path = f.path_str();

        let h1 = hash_executable(&path).expect("a regular file should hash");
        assert_eq!(h1.len(), 64, "SHA256 hex is 64 chars");
        // Second call hits the cache and returns the same digest.
        let h2 = hash_executable(&path).unwrap();
        assert_eq!(h1, h2);
    }

    #[test]
    fn rejects_non_absolute_and_memfd() {
        assert!(hash_executable("").is_none());
        assert!(hash_executable("relative/path").is_none());
        assert!(hash_executable("memfd:payload").is_none());
        assert!(hash_executable("/tmp/x (deleted)").is_none());
        assert!(hash_executable("/nonexistent/trapd/xyz").is_none());
    }

    // Minimal temp-file helper to avoid pulling in a dev-dependency.
    struct TmpFile {
        path: String,
        file: std::fs::File,
    }
    impl TmpFile {
        fn path_str(&self) -> String {
            self.path.clone()
        }
    }
    impl std::ops::Deref for TmpFile {
        type Target = std::fs::File;
        fn deref(&self) -> &std::fs::File {
            &self.file
        }
    }
    impl std::ops::DerefMut for TmpFile {
        fn deref_mut(&mut self) -> &mut std::fs::File {
            &mut self.file
        }
    }
    impl Drop for TmpFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }
    fn tempfile_in_tmp(prefix: &str) -> TmpFile {
        let path = format!(
            "/tmp/{prefix}_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let file = std::fs::File::create(&path).unwrap();
        TmpFile { path, file }
    }
}
