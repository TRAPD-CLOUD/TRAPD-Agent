//! Executable-image hashing shared by the Windows process collectors
//! (polling and ETW).
//!
//! One streaming implementation with one process-wide cache, so both
//! collectors hash an unchanged image once and agree on the outcome. Hashing is
//! synchronous file IO: callers on an async worker must run [`hash_image`] via
//! `tokio::task::spawn_blocking`.
//!
//! The outcome is explicit ([`HashOutcome`]): an image that was too large or
//! could not be read is reported as such through the existing
//! `enrichment_errors["exe_sha256"]` marker instead of silently producing no
//! hash, so IOC matching gaps are visible and countable.

use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::SystemTime;

use sha2::{Digest, Sha256};

use super::EnrichmentError;

/// Largest image that is hashed. Electron/Chromium-based applications ship
/// 150-250 MB binaries that IOC matching must still cover; beyond this a
/// single hash would hold a blocking thread for many seconds.
pub const MAX_IMAGE_HASH_BYTES: u64 = 256 * 1024 * 1024;

/// Streaming read size.
const CHUNK: usize = 64 * 1024;

/// Upper bound on cached entries before the cache is reset.
const MAX_CACHE_ENTRIES: usize = 4096;

/// Result of hashing one executable image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HashOutcome {
    /// `sha256:<hex>`.
    Hashed(String),
    /// Not a regular file, or larger than [`MAX_IMAGE_HASH_BYTES`].
    TooLarge,
    /// Missing, locked or otherwise unreadable.
    Unreadable(EnrichmentError),
    /// No image path was available.
    NoPath,
}

impl HashOutcome {
    /// The digest, when one was computed.
    pub fn digest(&self) -> Option<&str> {
        match self {
            HashOutcome::Hashed(h) => Some(h),
            _ => None,
        }
    }

    /// Cause to record under `enrichment_errors["exe_sha256"]`. `NoPath` is
    /// already reported through the `exe` field, so it adds nothing here.
    /// `TooLarge` maps to `unsupported` (the image is outside what this agent
    /// hashes) so the wire vocabulary stays unchanged.
    pub fn failure(&self) -> Option<EnrichmentError> {
        match self {
            HashOutcome::Hashed(_) | HashOutcome::NoPath => None,
            HashOutcome::TooLarge => Some(EnrichmentError::Unsupported),
            HashOutcome::Unreadable(cause) => Some(*cause),
        }
    }
}

fn classify_io(err: &std::io::Error) -> EnrichmentError {
    match err.kind() {
        std::io::ErrorKind::PermissionDenied => EnrichmentError::PermissionDenied,
        std::io::ErrorKind::NotFound => EnrichmentError::ProcessExited,
        _ => EnrichmentError::IoError,
    }
}

/// Hash `reader` in [`CHUNK`]-sized reads; `None` when it yields more than
/// `max` bytes (a file that grew after the size check).
pub(crate) fn stream_sha256<R: Read>(reader: R, max: u64) -> std::io::Result<Option<String>> {
    let mut reader = reader.take(max.saturating_add(1));
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; CHUNK];
    let mut total = 0u64;
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        total += n as u64;
        if total > max {
            return Ok(None);
        }
        hasher.update(&buf[..n]);
    }
    Ok(Some(format!("sha256:{}", hex::encode(hasher.finalize()))))
}

fn hash_uncached(path: &Path, max: u64, len: u64) -> HashOutcome {
    if len > max {
        return HashOutcome::TooLarge;
    }
    let file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) => return HashOutcome::Unreadable(classify_io(&e)),
    };
    match stream_sha256(file, max) {
        Ok(Some(h)) => HashOutcome::Hashed(h),
        Ok(None) => HashOutcome::TooLarge,
        Err(e) => HashOutcome::Unreadable(classify_io(&e)),
    }
}

type CacheKey = (u64, Option<SystemTime>);

#[derive(Default)]
struct Cache(HashMap<PathBuf, (CacheKey, HashOutcome)>);

fn cache() -> &'static Mutex<Cache> {
    static CACHE: OnceLock<Mutex<Cache>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(Cache::default()))
}

/// Hash the image at `path`, cached per path + size + mtime. Blocking.
///
/// `Unreadable` results are not cached: a transient lock must not hide the
/// image for good. The lock is not held while hashing.
pub fn hash_image(path: &Path) -> HashOutcome {
    hash_image_with(path, MAX_IMAGE_HASH_BYTES, cache())
}

fn hash_image_with(path: &Path, max: u64, cache: &Mutex<Cache>) -> HashOutcome {
    if path.as_os_str().is_empty() {
        return HashOutcome::NoPath;
    }
    let meta = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(e) => return HashOutcome::Unreadable(classify_io(&e)),
    };
    if !meta.is_file() {
        return HashOutcome::TooLarge;
    }
    let key: CacheKey = (meta.len(), meta.modified().ok());
    // Without an mtime an in-place rewrite of equal length is undetectable.
    let cacheable = key.1.is_some();
    if cacheable {
        if let Ok(guard) = cache.lock() {
            if let Some((k, outcome)) = guard.0.get(path) {
                if *k == key {
                    return outcome.clone();
                }
            }
        }
    }
    let outcome = hash_uncached(path, max, meta.len());
    if cacheable && !matches!(outcome, HashOutcome::Unreadable(_)) {
        if let Ok(mut guard) = cache.lock() {
            if guard.0.len() >= MAX_CACHE_ENTRIES {
                guard.0.clear();
            }
            guard.0.insert(path.to_path_buf(), (key, outcome.clone()));
        }
    }
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    const ABC: &str = "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    fn temp_file(name: &str, bytes: &[u8]) -> PathBuf {
        let p = std::env::temp_dir().join(format!("trapd-imghash-{}-{name}", std::process::id()));
        std::fs::File::create(&p).unwrap().write_all(bytes).unwrap();
        p
    }

    #[test]
    fn streams_known_digest() {
        assert_eq!(
            stream_sha256(&b"abc"[..], 10).unwrap().as_deref(),
            Some(ABC)
        );
    }

    #[test]
    fn digest_spans_multiple_chunks() {
        let data = vec![7u8; CHUNK * 3 + 5];
        let expect = format!("sha256:{}", hex::encode(Sha256::digest(&data)));
        assert_eq!(
            stream_sha256(&data[..], u64::MAX - 1).unwrap(),
            Some(expect)
        );
    }

    #[test]
    fn growth_past_limit_is_reported() {
        assert_eq!(stream_sha256(&[0u8; 11][..], 10).unwrap(), None);
        assert!(stream_sha256(&[0u8; 10][..], 10).unwrap().is_some());
    }

    #[test]
    fn oversize_missing_and_empty_path_are_explicit() {
        let c = Mutex::new(Cache::default());
        let p = temp_file("big", b"0123456789");
        assert_eq!(hash_image_with(&p, 4, &c), HashOutcome::TooLarge);
        assert_eq!(
            HashOutcome::TooLarge.failure(),
            Some(EnrichmentError::Unsupported)
        );
        let c = Mutex::new(Cache::default()); // max is not part of the cache key
        assert!(hash_image_with(&p, 64, &c).digest().is_some());
        std::fs::remove_file(&p).unwrap();
        assert_eq!(
            hash_image_with(&p, 64, &c),
            HashOutcome::Unreadable(EnrichmentError::ProcessExited)
        );
        assert_eq!(hash_image_with(Path::new(""), 64, &c), HashOutcome::NoPath);
        assert_eq!(HashOutcome::NoPath.failure(), None);
        // A directory is not an image.
        assert_eq!(
            hash_image_with(&std::env::temp_dir(), 64, &c),
            HashOutcome::TooLarge
        );
    }

    #[test]
    fn cache_hits_and_invalidates_on_change() {
        let c = Mutex::new(Cache::default());
        let p = temp_file("cache", b"abc");
        assert_eq!(hash_image_with(&p, 64, &c).digest(), Some(ABC));
        assert_eq!(c.lock().unwrap().0.len(), 1);
        // Different length -> different key -> rehash.
        std::fs::write(&p, b"abcd").unwrap();
        let second = hash_image_with(&p, 64, &c);
        assert_ne!(second.digest(), Some(ABC));
        assert!(second.digest().is_some());
        std::fs::remove_file(&p).unwrap();
    }
}
