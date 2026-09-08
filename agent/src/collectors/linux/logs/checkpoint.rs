//! Persisted read offsets for the log collector.
//!
//! Stored at `<state>/log_offsets.json` (mode `0600`). The record is the
//! identity of a file — `(dev, inode, fingerprint, offset)` — not just a
//! path, so a logrotate rename, a copytruncate, and a brand-new file at the
//! same path are distinguishable after a restart.
//!
//! Delivery is at-least-once: the checkpoint is flushed on a debounce, not
//! per line, so a crash can re-emit the last few records. The backend
//! already deduplicates on `event_id` for other collectors; log events get
//! a fresh `event_id` per emit, so consumers that need exactly-once must
//! key on `(agent_id, source, source_path, inode, offset)` instead.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::warn;

const SCHEMA_VERSION: u32 = 1;

/// On-disk checkpoint document.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CheckpointFile {
    #[serde(default)]
    pub schema_version: u32,
    #[serde(default)]
    pub files: BTreeMap<String, FileCheckpoint>,
    #[serde(default)]
    pub journals: BTreeMap<String, JournalCheckpoint>,
}

/// Identity + position of one tailed file.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileCheckpoint {
    pub path: String,
    pub dev: u64,
    pub inode: u64,
    pub offset: u64,
    pub size: u64,
    /// SHA-256 of the first [`FINGERPRINT_BYTES`] bytes. Distinguishes a
    /// truncated-and-rewritten file from a simple append at the same inode.
    #[serde(default)]
    pub fingerprint: String,
    pub updated_at: DateTime<Utc>,
}

/// systemd-journal cursor, persisted so `--after-cursor` resumes exactly.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JournalCheckpoint {
    pub source: String,
    pub cursor: String,
    pub updated_at: DateTime<Utc>,
}

/// Bytes hashed at the start of a file to detect in-place rewrite.
pub const FINGERPRINT_BYTES: usize = 256;

/// In-memory store with a dirty flag so the collector can debounce flushes.
pub struct CheckpointStore {
    path: PathBuf,
    inner: CheckpointFile,
    dirty: AtomicBool,
    last_flush: Instant,
}

impl CheckpointStore {
    pub fn load(path: PathBuf) -> Self {
        let inner = match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_else(|e| {
                warn!(error = %e, path = %path.display(), "log checkpoint unreadable — starting fresh");
                CheckpointFile {
                    schema_version: SCHEMA_VERSION,
                    ..Default::default()
                }
            }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => CheckpointFile {
                schema_version: SCHEMA_VERSION,
                ..Default::default()
            },
            Err(e) => {
                warn!(error = %e, path = %path.display(), "log checkpoint open failed — starting fresh");
                CheckpointFile {
                    schema_version: SCHEMA_VERSION,
                    ..Default::default()
                }
            }
        };
        Self {
            path,
            inner,
            dirty: AtomicBool::new(false),
            last_flush: Instant::now(),
        }
    }

    pub fn get_file(&self, key: &str) -> Option<&FileCheckpoint> {
        self.inner.files.get(key)
    }

    pub fn get_journal(&self, key: &str) -> Option<&JournalCheckpoint> {
        self.inner.journals.get(key)
    }

    pub fn put_file(&mut self, key: String, cp: FileCheckpoint) {
        self.inner.files.insert(key, cp);
        self.dirty.store(true, Ordering::Relaxed);
    }

    pub fn put_journal(&mut self, key: String, cp: JournalCheckpoint) {
        self.inner.journals.insert(key, cp);
        self.dirty.store(true, Ordering::Relaxed);
    }

    /// Flush if dirty and at least `min_age` has passed (or `force`).
    pub fn flush(&mut self, min_age: Duration, force: bool) {
        if !self.dirty.load(Ordering::Relaxed) {
            return;
        }
        if !force && self.last_flush.elapsed() < min_age {
            return;
        }
        self.inner.schema_version = SCHEMA_VERSION;
        match serde_json::to_vec_pretty(&self.inner) {
            Ok(bytes) => {
                if let Err(e) = crate::paths::write_atomic(&self.path, &bytes, 0o600) {
                    warn!(error = %e, path = %self.path.display(), "log checkpoint flush failed");
                    return;
                }
                self.dirty.store(false, Ordering::Relaxed);
                self.last_flush = Instant::now();
            }
            Err(e) => warn!(error = %e, "log checkpoint serialize failed"),
        }
    }
}

/// Checkpoint map key: source name + path, so two sources tailing the same
/// file (unusual, but allowed) do not share a cursor.
pub fn file_key(source: &str, path: &str) -> String {
    format!("{source}\0{path}")
}

pub fn journal_key(source: &str) -> String {
    source.to_string()
}

/// SHA-256 hex of up to [`FINGERPRINT_BYTES`] leading bytes.
pub fn fingerprint(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let take = bytes.len().min(FINGERPRINT_BYTES);
    let mut h = Sha256::new();
    h.update(&bytes[..take]);
    hex::encode(h.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp() -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("trapd_logcp_{nanos}.json"))
    }

    #[test]
    fn round_trip_file_checkpoint() {
        let path = tmp();
        let mut store = CheckpointStore::load(path.clone());
        store.put_file(
            "nginx\0/var/log/nginx/access.log".into(),
            FileCheckpoint {
                path: "/var/log/nginx/access.log".into(),
                dev: 2050,
                inode: 42,
                offset: 100,
                size: 100,
                fingerprint: "abc".into(),
                updated_at: Utc::now(),
            },
        );
        store.flush(Duration::ZERO, true);
        drop(store);
        let store = CheckpointStore::load(path.clone());
        let cp = store.get_file("nginx\0/var/log/nginx/access.log").unwrap();
        assert_eq!(cp.inode, 42);
        assert_eq!(cp.offset, 100);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn missing_file_starts_empty() {
        let path = tmp();
        let store = CheckpointStore::load(path);
        assert!(store.inner.files.is_empty());
    }

    #[test]
    fn fingerprint_is_stable() {
        let a = fingerprint(b"hello world");
        let b = fingerprint(b"hello world");
        assert_eq!(a, b);
        assert_ne!(a, fingerprint(b"hello World"));
        assert_eq!(a.len(), 64);
    }
}
