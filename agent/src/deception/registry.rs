//! Local register of honeytokens this agent has deployed.
//!
//! Every successfully placed token is recorded in `<state>/honeytokens.json`
//! (mode `0600`) so the agent can:
//!
//!   * **revoke** a token later — and do so *safely*: `revoke_honeytoken` only
//!     ever removes a file that appears in this register, so a malformed or
//!     malicious command can never trick the agent into deleting a real file
//!     it did not plant itself;
//!   * survive a restart without losing track of what is on disk;
//!   * (in step 2) attribute a detection back to the exact token that fired.
//!
//! The register is the single owner of persistence: deploy/revoke in
//! [`super`] mutate it through [`HoneytokenStore`] and it flushes atomically
//! at `0600` on every change.

use std::path::PathBuf;
use std::sync::Mutex;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::warn;
use uuid::Uuid;

/// On-disk record of one deployed honeytoken.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HoneytokenRecord {
    /// Agent-assigned stable identifier for this placement.
    pub id: Uuid,
    /// Absolute path the token was written to.
    pub path: String,
    /// Token family, propagated from the recon candidate when the backend
    /// supplies it (`ssh_private_key`, `aws_credentials`, …); `"unknown"`
    /// otherwise.
    pub kind: String,
    /// Final file mode the token was given.
    pub mode: u32,
    /// Size of the deployed content in bytes.
    pub size_bytes: u64,
    /// SHA-256 of the deployed content — lets a future detector confirm the
    /// bait is untouched (or notice it was copied/edited).
    pub sha256: String,
    /// Whether neighbouring files were mimicked for camouflage.
    pub mimic_neighbor: bool,
    /// The neighbour whose owner/timestamps were copied, when mimicry ran.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub neighbor_path: Option<String>,
    /// Out-of-band canary marker embedded in the content by the backend (e.g.
    /// the fake AWS key id tied to a monitored honeypot account, or a tracking
    /// domain). Stored so a second-channel hit can be correlated to this token
    /// even if the attacker exfiltrated it past the agent. `None` when the
    /// backend did not declare one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub canary_marker: Option<String>,
    /// When the token was placed.
    pub deployed_at: DateTime<Utc>,
    /// Id of the signed command that requested the deployment, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command_id: Option<String>,
}

/// JSON document persisted at `<state>/honeytokens.json`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HoneytokenRegistry {
    #[serde(default)]
    pub tokens: Vec<HoneytokenRecord>,
}

/// Canonical location of the register.
pub fn registry_path() -> PathBuf {
    crate::paths::state_dir().join("honeytokens.json")
}

/// Thread-safe, self-persisting handle to the honeytoken register.
///
/// Cheap to share behind an `Arc`; every mutation flushes to disk at `0600`.
pub struct HoneytokenStore {
    path: PathBuf,
    inner: Mutex<HoneytokenRegistry>,
}

impl HoneytokenStore {
    /// Load the register from `<state>/honeytokens.json`, tolerating a missing
    /// or corrupt file by starting empty (a corrupt register must never stop
    /// the agent from running).
    pub fn load() -> Self {
        Self::load_from(registry_path())
    }

    pub fn load_from(path: PathBuf) -> Self {
        let registry = std::fs::read(&path)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        Self { path, inner: Mutex::new(registry) }
    }

    /// True if a token is already registered at `path`.
    pub fn contains_path(&self, path: &str) -> bool {
        self.inner
            .lock()
            .map(|r| r.tokens.iter().any(|t| t.path == path))
            .unwrap_or(false)
    }

    /// Number of registered tokens.
    pub fn len(&self) -> usize {
        self.inner.lock().map(|r| r.tokens.len()).unwrap_or(0)
    }

    /// Pairs with [`len`](Self::len) (satisfies `clippy::len_without_is_empty`)
    /// and is exercised by the register's tests.
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Add (or replace, keyed by path) a record and persist.
    pub fn insert(&self, record: HoneytokenRecord) -> Result<()> {
        let mut guard = self.inner.lock().map_err(|_| anyhow::anyhow!("honeytoken registry poisoned"))?;
        guard.tokens.retain(|t| t.path != record.path);
        guard.tokens.push(record);
        Self::persist(&self.path, &guard)
    }

    /// Remove the record at `path` and persist. Returns the removed record, or
    /// `None` when no token was registered there.
    pub fn remove_by_path(&self, path: &str) -> Result<Option<HoneytokenRecord>> {
        let mut guard = self.inner.lock().map_err(|_| anyhow::anyhow!("honeytoken registry poisoned"))?;
        let Some(pos) = guard.tokens.iter().position(|t| t.path == path) else {
            return Ok(None);
        };
        let removed = guard.tokens.remove(pos);
        Self::persist(&self.path, &guard)?;
        Ok(Some(removed))
    }

    fn persist(path: &std::path::Path, registry: &HoneytokenRegistry) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(registry).context("serialize honeytoken registry")?;
        // Owner-only (0600): the register reveals exactly which files are bait,
        // which is precisely what a local attacker must not be able to read.
        crate::paths::write_atomic(path, &bytes, 0o600)
            .with_context(|| format!("persist honeytoken registry to {}", path.display()))?;
        Ok(())
    }
}

impl Drop for HoneytokenStore {
    fn drop(&mut self) {
        // Best-effort final flush; surfaces a warning but never panics.
        if let Ok(guard) = self.inner.lock() {
            if let Err(e) = Self::persist(&self.path, &guard) {
                warn!(error = %e, "final honeytoken registry flush failed");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_registry() -> HoneytokenStore {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        HoneytokenStore::load_from(std::env::temp_dir().join(format!("trapd_htk_{nanos}.json")))
    }

    fn record(path: &str) -> HoneytokenRecord {
        HoneytokenRecord {
            id: Uuid::new_v4(),
            path: path.to_string(),
            kind: "aws_credentials".into(),
            mode: 0o600,
            size_bytes: 42,
            sha256: "deadbeef".into(),
            mimic_neighbor: true,
            neighbor_path: Some("/home/u/.aws/config".into()),
            canary_marker: Some("AKIAEXAMPLECANARY".into()),
            deployed_at: Utc::now(),
            command_id: None,
        }
    }

    #[test]
    fn insert_contains_remove_roundtrip() {
        let store = tmp_registry();
        assert!(store.is_empty());

        store.insert(record("/home/u/.aws/credentials")).unwrap();
        assert!(store.contains_path("/home/u/.aws/credentials"));
        assert_eq!(store.len(), 1);

        let removed = store.remove_by_path("/home/u/.aws/credentials").unwrap();
        assert!(removed.is_some());
        assert!(store.is_empty());

        // Removing a path that is not registered is a no-op, not an error.
        assert!(store.remove_by_path("/nope").unwrap().is_none());
        let _ = std::fs::remove_file(&store.path);
    }

    #[test]
    fn insert_is_idempotent_per_path() {
        let store = tmp_registry();
        store.insert(record("/x")).unwrap();
        store.insert(record("/x")).unwrap();
        assert_eq!(store.len(), 1, "same path must not duplicate");
        let _ = std::fs::remove_file(&store.path);
    }

    #[test]
    fn survives_reload_from_disk() {
        let store = tmp_registry();
        let path = store.path.clone();
        store.insert(record("/a")).unwrap();
        store.insert(record("/b")).unwrap();
        drop(store);

        let reloaded = HoneytokenStore::load_from(path.clone());
        assert_eq!(reloaded.len(), 2);
        assert!(reloaded.contains_path("/a"));
        let _ = std::fs::remove_file(&path);
    }
}
