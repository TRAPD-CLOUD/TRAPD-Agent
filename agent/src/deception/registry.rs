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
    ///
    /// This is the *legacy*, single-string form. Richer second-channel canaries
    /// are described by [`out_of_band`](Self::out_of_band); both are honoured for
    /// marker-uniqueness so no fingerprint is ever shared across tokens.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub canary_marker: Option<String>,
    /// Structured out-of-band canary registered alongside this token (issue #32,
    /// point 2), when the backend declared a second, independent signal channel
    /// for it. `None` for an on-host-only token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub out_of_band: Option<OutOfBandCanary>,
    /// When the token was placed.
    pub deployed_at: DateTime<Utc>,
    /// Id of the signed command that requested the deployment, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command_id: Option<String>,
    /// Cross-linking breadcrumbs placed alongside this token (issue #32, point
    /// 3), recorded so revoke can tear them down precisely.
    #[serde(default)]
    pub breadcrumbs: Vec<BreadcrumbRecord>,
}

/// Known out-of-band canary channels (issue #32, point 2).
///
/// A declared channel is validated against this set before placement, so a typo
/// can never produce a canary whose foreign signal the backend silently fails to
/// correlate. Each value maps to a *second, independent* signal source the
/// attacker trips by **using** (not merely reading) the bait off-host:
///
///   * `aws_cloudtrail` — a fake AWS access key tied to a monitored honeypot
///     account; any API call with it raises a CloudTrail alarm;
///   * `dns` — a unique tracking hostname (Canarytokens-style) whose resolution
///     is logged by an authoritative honeypot resolver;
///   * `http` — a tracking/web-bug URL whose fetch is logged (e.g. a pixel in an
///     Office/PDF lure, or a link in a `.env`);
///   * `kube_api` — a kube-config pointing at a honeypot API server, so any
///     `kubectl` against it is observed;
///   * `ssh_honeypot` — an SSH key whose use against honeypot infra logs a login
///     attempt.
pub const CANARY_CHANNELS: &[&str] = &["aws_cloudtrail", "dns", "http", "kube_api", "ssh_honeypot"];

/// A second, independent signal channel attached to a honeytoken (issue #32,
/// point 2).
///
/// The defining property of an out-of-band canary is that it fires when the bait
/// is **used**, on infrastructure the agent does not control — regardless of
/// whether the on-host eBPF detector ever saw the read. The agent therefore
/// never observes this channel directly. Its job is to *register* the canary so
/// the backend can correlate an inbound foreign signal (a CloudTrail event, a
/// tracking-domain hit, a honeypot login) back to this exact token and host
/// (Token ↔ Host ↔ Angreifer).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OutOfBandCanary {
    /// Which channel fires when the token is used — one of [`CANARY_CHANNELS`].
    pub channel: String,
    /// Stable id the backend assigned to this canary, echoed back inside the
    /// foreign signal so it can be matched to this registration.
    pub tracking_id: String,
    /// The observable token(s) embedded in the bait that trip the channel: the
    /// fake AWS key id, the tracking FQDN/URL, the honeypot SSH key fingerprint
    /// or kube API endpoint. Recorded so the backend can correlate a foreign
    /// signal even when it never saw the on-host read.
    pub markers: Vec<String>,
}

/// A breadcrumb the agent placed to make a token discoverable, recorded so it
/// can be cleaned up on revoke.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BreadcrumbRecord {
    /// Absolute path of the breadcrumb artefact.
    pub path: String,
    /// `true` if the breadcrumb was *appended* to an existing file (e.g. a shell
    /// history line) rather than created as a new file.
    pub appended: bool,
    /// For an appended breadcrumb: byte offset at which our addition began.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<u64>,
    /// For an appended breadcrumb: length of the appended block in bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub len: Option<u64>,
    /// For an appended breadcrumb: SHA-256 of the appended block, so revoke can
    /// confirm the file still ends with exactly our bytes before removing them.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
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
        Self {
            path,
            inner: Mutex::new(registry),
        }
    }

    /// True if a token is already registered at `path`.
    pub fn contains_path(&self, path: &str) -> bool {
        self.inner
            .lock()
            .map(|r| r.tokens.iter().any(|t| t.path == path))
            .unwrap_or(false)
    }

    /// True if `marker` is already in use by some registered token — either as
    /// its legacy [`canary_marker`](HoneytokenRecord::canary_marker) or as one of
    /// its out-of-band [`markers`](OutOfBandCanary::markers). Used to enforce that
    /// no marker is shared across tokens (anti-fingerprint, issue #32 points 2/3):
    /// a reused marker would let one foreign-signal hit — or one greppy attacker —
    /// enumerate every bait at once.
    pub fn canary_in_use(&self, marker: &str) -> bool {
        self.inner
            .lock()
            .map(|r| {
                r.tokens.iter().any(|t| {
                    t.canary_marker.as_deref() == Some(marker)
                        || t.out_of_band
                            .as_ref()
                            .is_some_and(|o| o.markers.iter().any(|m| m == marker))
                })
            })
            .unwrap_or(false)
    }

    /// Find the token registered for an out-of-band `tracking_id`, if any. Lets a
    /// caller (or a test) resolve a backend-reported foreign signal back to the
    /// local token it belongs to. Part of the point-2 correlation contract; not
    /// yet called from the binary (the backend owns foreign-signal ingestion).
    #[allow(dead_code)]
    pub fn find_by_tracking_id(&self, tracking_id: &str) -> Option<HoneytokenRecord> {
        self.inner.lock().ok().and_then(|r| {
            r.tokens
                .iter()
                .find(|t| {
                    t.out_of_band
                        .as_ref()
                        .is_some_and(|o| o.tracking_id == tracking_id)
                })
                .cloned()
        })
    }

    /// Snapshot of all currently-registered tokens (used by the eBPF map
    /// reconciler to learn which paths to arm).
    pub fn list(&self) -> Vec<HoneytokenRecord> {
        self.inner
            .lock()
            .map(|r| r.tokens.clone())
            .unwrap_or_default()
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
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| anyhow::anyhow!("honeytoken registry poisoned"))?;
        guard.tokens.retain(|t| t.path != record.path);
        guard.tokens.push(record);
        Self::persist(&self.path, &guard)
    }

    /// Remove the record at `path` and persist. Returns the removed record, or
    /// `None` when no token was registered there.
    pub fn remove_by_path(&self, path: &str) -> Result<Option<HoneytokenRecord>> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| anyhow::anyhow!("honeytoken registry poisoned"))?;
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
            out_of_band: None,
            deployed_at: Utc::now(),
            command_id: None,
            breadcrumbs: Vec::new(),
        }
    }

    fn record_with_oob(path: &str, oob: OutOfBandCanary) -> HoneytokenRecord {
        HoneytokenRecord {
            out_of_band: Some(oob),
            canary_marker: None,
            ..record(path)
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
    fn canary_in_use_detects_shared_markers() {
        let store = tmp_registry();
        store.insert(record("/home/u/.aws/credentials")).unwrap();
        // record() uses canary marker "AKIAEXAMPLECANARY".
        assert!(store.canary_in_use("AKIAEXAMPLECANARY"));
        assert!(!store.canary_in_use("SOME-OTHER-MARKER"));
        let _ = std::fs::remove_file(&store.path);
    }

    #[test]
    fn canary_in_use_also_covers_out_of_band_markers() {
        let store = tmp_registry();
        let oob = OutOfBandCanary {
            channel: "dns".into(),
            tracking_id: "trk-1".into(),
            markers: vec!["a1b2c3.canary.example.net".into()],
        };
        store
            .insert(record_with_oob("/home/u/.aws/credentials", oob))
            .unwrap();
        // An out-of-band marker is just as "in use" as a legacy canary marker.
        assert!(store.canary_in_use("a1b2c3.canary.example.net"));
        assert!(!store.canary_in_use("other.canary.example.net"));
        let _ = std::fs::remove_file(&store.path);
    }

    #[test]
    fn find_by_tracking_id_resolves_token() {
        let store = tmp_registry();
        let oob = OutOfBandCanary {
            channel: "aws_cloudtrail".into(),
            tracking_id: "trk-aws-42".into(),
            markers: vec!["AKIA2E0AABCDEFGHIJKL".into()],
        };
        store
            .insert(record_with_oob("/home/u/.aws/credentials", oob))
            .unwrap();
        let found = store
            .find_by_tracking_id("trk-aws-42")
            .expect("token resolved");
        assert_eq!(found.path, "/home/u/.aws/credentials");
        assert!(store.find_by_tracking_id("nope").is_none());
        let _ = std::fs::remove_file(&store.path);
    }

    #[test]
    fn out_of_band_survives_reload() {
        let store = tmp_registry();
        let path = store.path.clone();
        let oob = OutOfBandCanary {
            channel: "http".into(),
            tracking_id: "trk-http".into(),
            markers: vec!["https://x.canary.example.net/p.png".into()],
        };
        store
            .insert(record_with_oob("/srv/www/.env", oob.clone()))
            .unwrap();
        drop(store);

        let reloaded = HoneytokenStore::load_from(path.clone());
        let rec = reloaded.find_by_tracking_id("trk-http").expect("reloaded");
        assert_eq!(rec.out_of_band, Some(oob));
        let _ = std::fs::remove_file(&path);
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
