//! Persisted harvest cursors: file (dev, inode, offset, fingerprints) and
//! journalctl `--after-cursor` tokens.
//!
//! Written atomically to `<state>/log_offsets.json` (`0600`). A crash mid-write
//! cannot leave a half-applied cursor — the previous file remains. Fingerprints
//! (head of the file + bytes immediately before the cursor) detect inode reuse
//! and silent rewrite, which a bare (dev,ino,offset) triple cannot.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::warn;

use crate::paths;

pub const SCHEMA_VERSION: u32 = 1;
const HEAD_LEN: usize = 256;
const TAIL_LEN: usize = 64;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CheckpointStore {
    #[serde(default = "one")]
    pub schema_version: u32,
    #[serde(default)]
    pub files: BTreeMap<String, FileCheckpoint>,
    #[serde(default)]
    pub journal_cursors: BTreeMap<String, String>,
}

fn one() -> u32 {
    1
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileCheckpoint {
    pub path: String,
    pub dev: u64,
    pub ino: u64,
    pub offset: u64,
    /// SHA-256 of the first `HEAD_LEN` bytes (or the whole file if smaller).
    #[serde(default)]
    pub head_fp: String,
    /// SHA-256 of the `TAIL_LEN` bytes immediately before `offset`.
    #[serde(default)]
    pub tail_fp: String,
}

impl CheckpointStore {
    pub fn path() -> PathBuf {
        paths::state_dir().join("log_offsets.json")
    }

    pub fn load(path: &Path) -> Self {
        match std::fs::read(path) {
            Ok(bytes) => match serde_json::from_slice::<Self>(&bytes) {
                Ok(store) => {
                    if store.schema_version != SCHEMA_VERSION {
                        warn!(
                            version = store.schema_version,
                            "log checkpoint schema mismatch — starting fresh"
                        );
                        return Self::default();
                    }
                    store
                }
                Err(e) => {
                    warn!(error = %e, path = %path.display(), "log checkpoint unreadable — starting fresh");
                    Self::default()
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Self::default(),
            Err(e) => {
                warn!(error = %e, path = %path.display(), "log checkpoint read failed — starting fresh");
                Self::default()
            }
        }
    }

    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        let bytes = serde_json::to_vec_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        paths::write_atomic(path, &bytes, 0o600).map_err(std::io::Error::other)
    }

    pub fn file_key(source: &str, path: &str) -> String {
        format!("{source}::{path}")
    }
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub fn head_fingerprint(bytes: &[u8]) -> String {
    let n = bytes.len().min(HEAD_LEN);
    sha256_hex(&bytes[..n])
}

/// Read the head of an on-disk file for identity checks. Best-effort.
pub fn read_head(path: &Path) -> Option<Vec<u8>> {
    use std::io::Read;
    let mut f = std::fs::File::open(path).ok()?;
    let mut buf = vec![0u8; HEAD_LEN];
    let n = f.read(&mut buf).ok()?;
    buf.truncate(n);
    Some(buf)
}

/// Read `TAIL_LEN` bytes immediately before `offset`.
pub fn read_tail_at(path: &Path, offset: u64) -> Option<Vec<u8>> {
    use std::io::{Read, Seek, SeekFrom};
    if offset == 0 {
        return Some(Vec::new());
    }
    let mut f = std::fs::File::open(path).ok()?;
    let start = offset.saturating_sub(TAIL_LEN as u64);
    f.seek(SeekFrom::Start(start)).ok()?;
    let len = (offset - start) as usize;
    let mut buf = vec![0u8; len];
    let n = f.read(&mut buf).ok()?;
    buf.truncate(n);
    Some(buf)
}

pub const TAIL_BYTES: usize = TAIL_LEN;

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "trapd_log_ckpt_{}_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            tag
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn round_trips_through_atomic_write() {
        let dir = scratch("rt");
        let path = dir.join("log_offsets.json");
        let mut store = CheckpointStore {
            schema_version: SCHEMA_VERSION,
            ..Default::default()
        };
        store.files.insert(
            "nginx::/var/log/nginx/access.log".into(),
            FileCheckpoint {
                path: "/var/log/nginx/access.log".into(),
                dev: 1,
                ino: 42,
                offset: 100,
                head_fp: "aa".into(),
                tail_fp: "bb".into(),
            },
        );
        store.journal_cursors.insert("sshd".into(), "s=abc".into());
        store.save(&path).unwrap();

        let loaded = CheckpointStore::load(&path);
        assert_eq!(loaded.files.len(), 1);
        assert_eq!(loaded.files.values().next().unwrap().ino, 42);
        assert_eq!(loaded.journal_cursors.get("sshd").unwrap(), "s=abc");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_file_is_empty_store() {
        let store = CheckpointStore::load(Path::new("/no/such/log_offsets.json"));
        assert!(store.files.is_empty());
    }

    #[test]
    fn corrupt_file_is_empty_store() {
        let dir = scratch("bad");
        let path = dir.join("log_offsets.json");
        std::fs::write(&path, b"not json").unwrap();
        let store = CheckpointStore::load(&path);
        assert!(store.files.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn fingerprints_are_stable() {
        let bytes = b"abcdefghijklmnopqrstuvwxyz0123456789";
        assert_eq!(
            head_fingerprint(bytes),
            sha256_hex(&bytes[..HEAD_LEN.min(bytes.len())])
        );
        let fp = sha256_hex(&bytes[..20.min(bytes.len())]);
        assert_eq!(fp, sha256_hex(&bytes[0..20])); // 20 < TAIL_LEN
    }
}
