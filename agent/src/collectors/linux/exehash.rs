//! Shared executable hashing — one cached, size-capped SHA256 implementation.
//!
//! Every exec is hashed once, at the point of collection, and the digest then
//! flows into the event (`exe_sha256`), the IOC hash-match in the detection
//! engine, and the IOA process-tree lineage.  Centralising it here means the
//! hot path hashes a given binary at most once per (path, mtime) — repeated
//! execs of `bash`, `python`, … are cache hits — and never twice across the
//! exec tracer and the `/proc` poller.
//!
//! Bounds, so a busy host can never be stalled or grown without limit:
//!   * only absolute, regular files are hashed (memfd / `(deleted)` → `None`);
//!   * files larger than [`MAX_HASH_BYTES`] are skipped;
//!   * the cache is keyed by path+mtime and cleared wholesale at a cap.
//!
//! Disable entirely with `TRAPD_EXEC_HASH=off`.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

/// Executables larger than this are not hashed (cost bound).
const MAX_HASH_BYTES: u64 = 64 * 1024 * 1024;
/// Cap on the cache before it is cleared wholesale.
const CACHE_CAP: usize = 8_192;

struct Cache {
    enabled: bool,
    entries: HashMap<String, (u64, Option<String>)>,
}

fn cache() -> &'static Mutex<Cache> {
    static CACHE: OnceLock<Mutex<Cache>> = OnceLock::new();
    CACHE.get_or_init(|| {
        let enabled = !std::env::var("TRAPD_EXEC_HASH")
            .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "0" | "false" | "no" | "off"))
            .unwrap_or(false);
        Mutex::new(Cache {
            enabled,
            entries: HashMap::new(),
        })
    })
}

/// SHA256 the executable at `path`, hex-encoded.  Returns `None` when hashing is
/// disabled, the path is not an absolute regular file, it exceeds
/// [`MAX_HASH_BYTES`], or the read fails.  Cached by path+mtime.
pub fn hash_executable(path: &str) -> Option<String> {
    if path.is_empty() || !path.starts_with('/') || path.contains("(deleted)") {
        return None;
    }

    let meta = std::fs::metadata(path).ok()?;
    if !meta.is_file() || meta.len() > MAX_HASH_BYTES {
        return None;
    }
    let mtime = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let guard = cache().lock().ok()?;
    if !guard.enabled {
        return None;
    }
    if let Some((cached_mtime, hash)) = guard.entries.get(path) {
        if *cached_mtime == mtime {
            return hash.clone();
        }
    }

    // Release the lock while reading/hashing the file so other collectors are
    // not blocked behind a slow disk read.
    drop(guard);
    let hash = std::fs::read(path).ok().map(|bytes| {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        hex::encode(hasher.finalize())
    });

    if let Ok(mut guard) = cache().lock() {
        if guard.entries.len() >= CACHE_CAP {
            guard.entries.clear();
        }
        guard.entries.insert(path.to_string(), (mtime, hash.clone()));
    }
    hash
}

/// Uncached SHA256 (hex) of an arbitrary file's contents.  Used by the FIM
/// collector, which keeps its own on-disk baseline and must not pollute (or be
/// served stale data by) the exec-hash cache.  Returns `None` on read error.
pub fn sha256_file(path: &std::path::Path) -> Option<String> {
    let bytes = std::fs::read(path).ok()?;
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    Some(hex::encode(hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

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
