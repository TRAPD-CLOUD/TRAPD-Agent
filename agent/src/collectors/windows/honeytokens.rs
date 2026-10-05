//! Windows honeytoken sentinel: filesystem decoys + registry decoys.
//!
//! Mirrors the Linux deception subsystem's *detection contract* — every trigger
//! is emitted as the same OS-neutral `EventClass::Detection` /
//! `EventAction::HoneytokenAccess` event with a [`HoneytokenAccessData`]
//! payload, so the backend ingests Windows hits through exactly the same path
//! as Linux ones. Only the *sensing* differs:
//!
//!   * **Filesystem** — decoy files at the config-delivered `honeytoken_paths`
//!     are watched via `ReadDirectoryChangesW` (through the `notify` crate) for
//!     modification, rename and deletion. Content *reads* are detected by
//!     polling the NTFS last-access timestamp (`ReadDirectoryChangesW` itself
//!     carries no read notification); on volumes where last-access updates are
//!     disabled (`NtfsDisableLastAccessUpdate`) read detection degrades
//!     gracefully to tamper detection only.
//!   * **Registry** — decoy values under `HKLM\SOFTWARE\TRAPD\Honeytokens`
//!     (`DatabasePassword`, `AdminCredentials`, `BackupKey`) are watched from a
//!     dedicated thread blocking in `RegNotifyChangeKeyValue`; any change is
//!     diffed against the expected values and raised.
//!
//! Resilience: a periodic sweep replants any decoy (file or registry value)
//! that has been deleted, so the bait survives tampering. The agent's own
//! plant/replant writes are suppressed with a short per-path window — Windows
//! change notifications carry no accessor PID, so self-exclusion works on time
//! rather than identity (the accessor lineage in emitted events is likewise
//! `unknown`).
//!
//! `trapd-agent.exe uninstall` calls [`uninstall`] to remove every decoy file
//! and the whole registry key again.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime};

use anyhow::{Context, Result};
use async_trait::async_trait;
use notify::Watcher;
use sha2::{Digest, Sha256};
use tokio::sync::mpsc::Sender;
use tracing::{debug, info, warn};

use crate::collectors::Collector;
use crate::config::AgentConfig;
use crate::schema::{
    AgentEvent, EventAction, EventClass, EventData, HoneytokenAccessData, PreventionEventData,
    ProcessLineage, Severity,
};

/// Registry key (under HKLM) holding the decoy values.
const REGISTRY_SUBKEY: &str = "SOFTWARE\\TRAPD\\Honeytokens";
/// Parent key, removed on uninstall when it has become empty.
const REGISTRY_PARENT_SUBKEY: &str = "SOFTWARE\\TRAPD";

/// Decoy registry values: names an attacker greps for, content that is
/// believable but strictly fake.
const REGISTRY_VALUES: &[(&str, &str)] = &[
    ("DatabasePassword", "Pr0d-MSSQL-2024!xK7q#v"),
    ("AdminCredentials", "CORP\\svc_backup:Sup3rS3cr3t#2024"),
    ("BackupKey", "QmFja3VwLU1hc3Rlci1LZXktMjAyNC0wMS0xNQ=="),
];

/// Events observed within this window after the agent itself wrote a decoy
/// (plant/replant/restore) are treated as self-inflicted and suppressed.
const SELF_WRITE_SUPPRESSION: Duration = Duration::from_secs(3);

/// Cadence of the resilience sweep (replant missing decoys) and of the
/// last-access poll that detects content reads.
const SWEEP_INTERVAL: Duration = Duration::from_secs(15);

/// Honeytoken *health* is reported to the backend every N sweeps (= 60s with
/// the 15s sweep), matching the Linux health verifier's cadence. The backend
/// correlates these `prevention.honeytoken_health` events into the token's
/// `file_status` / `last_verified_at` lifecycle columns.
const HEALTH_EVERY_N_SWEEPS: u32 = 4;

const MAX_TOKEN_HASH_BYTES: u64 = 1024 * 1024;

#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct OwnedFile {
    identity: [u32; 3],
    sha256: String,
}

#[derive(Default, serde::Serialize, serde::Deserialize)]
struct DeploymentRegister {
    #[serde(default)]
    files: HashMap<PathBuf, OwnedFile>,
    #[serde(default)]
    registry_values: HashSet<String>,
}

fn deployment_path() -> PathBuf {
    crate::paths::state_dir().join("windows_honeytoken_deployments.json")
}

fn deployments() -> &'static Mutex<DeploymentRegister> {
    static REGISTER: std::sync::OnceLock<Mutex<DeploymentRegister>> = std::sync::OnceLock::new();
    REGISTER.get_or_init(|| {
        use std::io::Read;
        let loaded = std::fs::File::open(deployment_path())
            .ok()
            .and_then(|file| {
                let mut bytes = Vec::new();
                file.take(MAX_TOKEN_HASH_BYTES + 1)
                    .read_to_end(&mut bytes)
                    .ok()?;
                if bytes.len() as u64 > MAX_TOKEN_HASH_BYTES {
                    return None;
                }
                serde_json::from_slice(&bytes).ok()
            });
        Mutex::new(loaded.unwrap_or_default())
    })
}

fn persist_deployments(register: &DeploymentRegister) -> Result<()> {
    crate::paths::write_atomic(&deployment_path(), &serde_json::to_vec(register)?, 0o600)
}

fn owns_path(path: &Path) -> bool {
    deployments()
        .lock()
        .is_ok_and(|register| register.files.contains_key(path))
}

// Use native identity and disposition on the opened file, so a replacement at
// its pathname cannot be mistaken for an owned decoy during cleanup.
#[repr(C)]
#[derive(Default)]
struct NativeFileInfo {
    attributes: u32,
    created: [u32; 2],
    accessed: [u32; 2],
    written: [u32; 2],
    volume: u32,
    size_high: u32,
    size_low: u32,
    links: u32,
    index_high: u32,
    index_low: u32,
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetFileInformationByHandle(handle: *mut std::ffi::c_void, info: *mut NativeFileInfo) -> i32;
    fn SetFileInformationByHandle(
        handle: *mut std::ffi::c_void,
        class: i32,
        info: *const std::ffi::c_void,
        size: u32,
    ) -> i32;
}

fn file_identity(file: &std::fs::File) -> std::io::Result<[u32; 3]> {
    use std::os::windows::io::AsRawHandle;
    let mut info = NativeFileInfo::default();
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok([info.volume, info.index_high, info.index_low])
}

fn remove_owned_file(path: &Path, owned: &OwnedFile) -> std::io::Result<()> {
    use std::io::Read;
    use std::os::windows::{
        fs::{MetadataExt, OpenOptionsExt},
        io::AsRawHandle,
    };
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .access_mode(0x8000_0000 | 0x0001_0000) // GENERIC_READ | DELETE
        .share_mode(1) // FILE_SHARE_READ: no writer/rename may race this check
        .custom_flags(0x0020_0000) // FILE_FLAG_OPEN_REPARSE_POINT
        .open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file()
        || meta.file_attributes() & 0x400 != 0
        || meta.len() > MAX_TOKEN_HASH_BYTES
        || file_identity(&file)? != owned.identity
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "decoy file identity changed",
        ));
    }
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 16384];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    if format!("sha256:{}", hex::encode(hasher.finalize())) != owned.sha256 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "decoy content changed",
        ));
    }
    // FILE_DISPOSITION_INFO uses a one-byte BOOLEAN. Delete the opened object,
    // not whatever may subsequently appear at the recorded path.
    let delete: u8 = 1;
    if unsafe {
        SetFileInformationByHandle(file.as_raw_handle(), 4, &delete as *const u8 as *const _, 1)
    } == 0
    {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod ownership_regressions {
    use super::*;

    /// The ownership register is process-global, and `reconcile_removed`
    /// retires every owned decoy that is not listed: tests that plant and
    /// reconcile must not interleave.
    static REGISTER_LOCK: Mutex<()> = Mutex::new(());

    fn serialize() -> std::sync::MutexGuard<'static, ()> {
        REGISTER_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn sample() -> (PathBuf, OwnedFile) {
        let path = std::env::temp_dir().join(format!("trapd-win-owned-{}", uuid::Uuid::new_v4()));
        std::fs::write(&path, b"bait").unwrap();
        let file = std::fs::File::open(&path).unwrap();
        let owned = OwnedFile {
            identity: file_identity(&file).unwrap(),
            sha256: sha256_hex(b"bait"),
        };
        (path, owned)
    }

    #[test]
    fn cleanup_removes_owned_unchanged_file() {
        let (path, owned) = sample();
        remove_owned_file(&path, &owned).unwrap();
        assert!(!path.exists());
    }

    #[test]
    fn cleanup_preserves_changed_contents() {
        let (path, owned) = sample();
        std::fs::write(&path, b"real user credentials").unwrap();
        assert!(remove_owned_file(&path, &owned).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"real user credentials");
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn cleanup_preserves_different_file_identity() {
        let (path, owned) = sample();
        let old = std::fs::File::open(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, b"bait").unwrap();
        assert!(remove_owned_file(&path, &owned).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"bait");
        drop(old);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn preexisting_file_is_not_adopted_or_overwritten() {
        let path = std::env::temp_dir().join(format!("trapd-win-decoy-{}", uuid::Uuid::new_v4()));
        std::fs::write(&path, b"real credentials").unwrap();
        let state = FsState::default();
        assert!(plant_missing(std::slice::from_ref(&path), &state).is_empty());
        assert!(!state.sha.lock().unwrap().contains_key(&path));
        assert_eq!(std::fs::read(&path).unwrap(), b"real credentials");
        std::fs::remove_file(path).unwrap();
    }
    fn revoked_events(rx: &mut tokio::sync::mpsc::Receiver<AgentEvent>) -> Vec<(String, bool)> {
        let mut out = Vec::new();
        while let Ok(event) = rx.try_recv() {
            if let EventData::Prevention(p) = event.data {
                if matches!(event.action, EventAction::HoneytokenRevoked) {
                    out.push((p.target, p.success));
                }
            }
        }
        out
    }

    #[test]
    fn decoy_removed_from_config_is_retired_and_reported() {
        let _serial = serialize();
        let path = std::env::temp_dir().join(format!("trapd-win-retire-{}", uuid::Uuid::new_v4()));
        let state = FsState::default();
        assert_eq!(plant_missing(std::slice::from_ref(&path), &state).len(), 1);
        let config = Arc::new(RwLock::new(AgentConfig::default()));
        assert!(config.read().unwrap().honeytoken_paths.is_empty());
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        reconcile_removed(&tx, "agent", "host", &config, &state);
        assert!(!path.exists());
        assert!(!owns_path(&path));
        assert_eq!(
            revoked_events(&mut rx),
            vec![(path.display().to_string(), true)]
        );
    }

    #[test]
    fn listed_decoy_is_not_retired() {
        let _serial = serialize();
        let path = std::env::temp_dir().join(format!("trapd-win-keep-{}", uuid::Uuid::new_v4()));
        let state = FsState::default();
        plant_missing(std::slice::from_ref(&path), &state);
        let config = Arc::new(RwLock::new(AgentConfig::default()));
        config.write().unwrap().honeytoken_paths = vec![path.display().to_string()];
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        reconcile_removed(&tx, "agent", "host", &config, &state);
        assert!(path.exists());
        assert!(revoked_events(&mut rx).is_empty());
        config.write().unwrap().honeytoken_paths.clear();
        reconcile_removed(&tx, "agent", "host", &config, &state);
        assert!(!path.exists());
    }

    #[test]
    fn modified_decoy_is_preserved_when_retired() {
        let _serial = serialize();
        let path = std::env::temp_dir().join(format!("trapd-win-edited-{}", uuid::Uuid::new_v4()));
        let state = FsState::default();
        plant_missing(std::slice::from_ref(&path), &state);
        std::fs::write(&path, b"real user data").unwrap();
        let config = Arc::new(RwLock::new(AgentConfig::default()));
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        reconcile_removed(&tx, "agent", "host", &config, &state);
        assert_eq!(std::fs::read(&path).unwrap(), b"real user data");
        assert!(!owns_path(&path));
        assert_eq!(
            revoked_events(&mut rx),
            vec![(path.display().to_string(), false)]
        );
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn unplantable_path_is_reported_once() {
        let path = std::env::temp_dir().join(format!("trapd-win-exists-{}", uuid::Uuid::new_v4()));
        std::fs::write(&path, b"real credentials").unwrap();
        let state = FsState::default();
        plant_missing(std::slice::from_ref(&path), &state);
        plant_missing(std::slice::from_ref(&path), &state);
        let failures = state.take_failures();
        assert_eq!(failures.len(), 1);
        assert_eq!(failures[0].0, path);
        assert!(state.take_failures().is_empty());
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn unlisted_unmanaged_file_is_left_in_place_and_reported() {
        let _serial = serialize();
        let path = std::env::temp_dir().join(format!("trapd-win-foreign-{}", uuid::Uuid::new_v4()));
        std::fs::write(&path, b"someone else's file").unwrap();
        let state = FsState::default();
        plant_missing(std::slice::from_ref(&path), &state);
        let config = Arc::new(RwLock::new(AgentConfig::default()));
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        reconcile_removed(&tx, "agent", "host", &config, &state);
        assert_eq!(std::fs::read(&path).unwrap(), b"someone else's file");
        assert_eq!(
            revoked_events(&mut rx),
            vec![(path.display().to_string(), false)]
        );
        // Reported once only.
        reconcile_removed(&tx, "agent", "host", &config, &state);
        assert!(revoked_events(&mut rx).is_empty());
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn registry_entries_are_not_treated_as_files() {
        let mut cfg = AgentConfig::default();
        assert!(!registry_decoys_requested(&cfg));
        cfg.honeytoken_paths = vec![
            "C:\\Data\\notes.txt".into(),
            "HKLM\\SOFTWARE\\TRAPD\\Honeytokens".into(),
        ];
        assert!(registry_decoys_requested(&cfg));
        let config = Arc::new(RwLock::new(cfg));
        assert_eq!(
            desired_file_paths(&config),
            vec![PathBuf::from("C:\\Data\\notes.txt")]
        );
    }
}

// ── Shared filesystem-token state ─────────────────────────────────────────────

#[derive(Default)]
struct FsState {
    /// Instant of the agent's own last write per decoy path (suppression).
    planted: Mutex<HashMap<PathBuf, Instant>>,
    /// Last observed access time per decoy path (read-detection baseline).
    atime: Mutex<HashMap<PathBuf, SystemTime>>,
    /// Expected content digest per decoy path (`sha256:<hex>`), captured at
    /// plant time (or from the surviving file on startup) — the baseline the
    /// health verifier diffs against to flag out-of-band tampering.
    sha: Mutex<HashMap<PathBuf, String>>,
    /// Warn once about preexisting/unregistered files. Upgrade migration never
    /// adopts them: their provenance cannot be recovered safely from content.
    ignored: Mutex<HashSet<PathBuf>>,
    /// Plant failures not yet reported to the backend, with the reason.
    failed: Mutex<Vec<(PathBuf, String)>>,
    /// Paths whose failure was already reported (one event per failure, not
    /// one per sweep). Cleared when the path is planted or leaves the config.
    reported: Mutex<HashSet<PathBuf>>,
}

impl FsState {
    fn mark_planted(&self, path: &Path) {
        if let Ok(mut m) = self.planted.lock() {
            m.insert(path.to_path_buf(), Instant::now());
        }
        // A plant rewrites the file, so the access-time baseline must move too.
        if let Some(at) = accessed_time(path) {
            if let Ok(mut m) = self.atime.lock() {
                m.insert(path.to_path_buf(), at);
            }
        }
    }

    /// Queue a plant failure for the backend, once per path.
    fn fail(&self, path: &Path, reason: impl Into<String>) {
        let first = self
            .reported
            .lock()
            .is_ok_and(|mut reported| reported.insert(path.to_path_buf()));
        if first {
            if let Ok(mut failed) = self.failed.lock() {
                failed.push((path.to_path_buf(), reason.into()));
            }
        }
    }

    fn take_failures(&self) -> Vec<(PathBuf, String)> {
        self.failed
            .lock()
            .map(|mut failed| std::mem::take(&mut *failed))
            .unwrap_or_default()
    }

    fn recently_planted(&self, path: &Path) -> bool {
        self.planted
            .lock()
            .ok()
            .and_then(|m| m.get(path).map(|t| t.elapsed() < SELF_WRITE_SUPPRESSION))
            .unwrap_or(false)
    }
}

fn accessed_time(path: &Path) -> Option<SystemTime> {
    std::fs::metadata(path).ok().and_then(|m| m.accessed().ok())
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn sha256_of_file(path: &Path) -> Option<String> {
    crate::paths::bounded_regular_sha256(path, MAX_TOKEN_HASH_BYTES)
        .ok()
        .map(|digest| format!("sha256:{digest}"))
}

// ── Collector ─────────────────────────────────────────────────────────────────

pub struct HoneytokenCollector {
    config: Arc<RwLock<AgentConfig>>,
}

impl HoneytokenCollector {
    pub fn new(config: Arc<RwLock<AgentConfig>>) -> Self {
        Self { config }
    }
}

#[async_trait]
impl Collector for HoneytokenCollector {
    fn name(&self) -> &'static str {
        "WindowsHoneytokenCollector"
    }

    async fn run(
        &mut self,
        tx: Sender<AgentEvent>,
        agent_id: String,
        hostname: String,
    ) -> Result<()> {
        let state = Arc::new(FsState::default());

        // Retire decoys that left the config while the agent was down, then
        // plant so the bait exists before any watcher is armed.
        reconcile_removed(&tx, &agent_id, &hostname, &self.config, &state);
        let initial = configured_paths(&self.config);
        let planted = plant_missing(&initial, &state);
        report_plant_failures(&tx, &agent_id, &hostname, &state);
        info!(
            configured = initial.len(),
            created = planted.len(),
            "filesystem honeytokens ensured"
        );
        // Register every configured decoy with the backend lifecycle mirror
        // (`prevention.honeytoken_deployed` → `honeytokens` row), so the
        // dashboard shows Windows tokens *before* their first trigger.
        for path in &initial {
            if owns_path(path) {
                emit_fs_deployed(&tx, &agent_id, &hostname, path, &state);
            }
        }

        // Registry decoys + blocking RegNotifyChangeKeyValue monitor.
        {
            let tx = tx.clone();
            let agent_id = agent_id.clone();
            let hostname = hostname.clone();
            let config = Arc::clone(&self.config);
            std::thread::Builder::new()
                .name("trapd-reg-honeytokens".into())
                .spawn(move || registry::monitor(tx, agent_id, hostname, config))
                .context("spawn registry honeytoken monitor thread")?;
        }

        // Filesystem watcher (ReadDirectoryChangesW via `notify`), rebuilt when
        // the configured token set changes.
        {
            let tx = tx.clone();
            let agent_id = agent_id.clone();
            let hostname = hostname.clone();
            let config = Arc::clone(&self.config);
            let state = Arc::clone(&state);
            std::thread::Builder::new()
                .name("trapd-fs-honeytokens".into())
                .spawn(move || fs_watch_loop(tx, agent_id, hostname, config, state))
                .context("spawn filesystem honeytoken watcher thread")?;
        }

        // Resilience sweep + read (last-access) detection + periodic health.
        let mut tick: u32 = 0;
        loop {
            tokio::time::sleep(SWEEP_INTERVAL).await;
            tick = tick.wrapping_add(1);
            let report_health = tick.is_multiple_of(HEALTH_EVERY_N_SWEEPS);
            sweep(
                &tx,
                &agent_id,
                &hostname,
                &self.config,
                &state,
                report_health,
            )
            .await;
        }
    }
}

/// A `honeytoken_paths` entry that names a registry location rather than a
/// file. Registry decoys are opt-in: they are planted only while the config
/// lists an entry under [`REGISTRY_SUBKEY`] (`HKLM\SOFTWARE\TRAPD\Honeytokens`).
fn is_registry_entry(entry: &str) -> bool {
    entry.trim().to_ascii_lowercase().starts_with("hklm\\")
}

/// Whether the config asks for the registry decoys.
fn registry_decoys_requested(cfg: &AgentConfig) -> bool {
    cfg.honeytoken_paths
        .iter()
        .any(|entry| is_registry_entry(entry))
}

/// Every decoy *file* the operator listed, trimmed and deduplicated, whether or
/// not detection is currently enabled. This is the ownership boundary: a decoy
/// the agent planted that is no longer listed here is retired.
fn desired_file_paths(config: &Arc<RwLock<AgentConfig>>) -> Vec<PathBuf> {
    let Ok(cfg) = config.read() else {
        return Vec::new();
    };
    let mut seen = HashSet::new();
    cfg.honeytoken_paths
        .iter()
        .map(|p| p.trim())
        .filter(|p| !p.is_empty() && !is_registry_entry(p))
        .map(PathBuf::from)
        .filter(|p| seen.insert(p.clone()))
        .collect()
}

/// The effective decoy-file set: the config-delivered `honeytoken_paths`.
/// Empty when honeytoken detection is disabled.
fn configured_paths(config: &Arc<RwLock<AgentConfig>>) -> Vec<PathBuf> {
    let enabled = config
        .read()
        .map(|cfg| cfg.honeytoken_detection_enabled)
        .unwrap_or(false);
    if enabled {
        desired_file_paths(config)
    } else {
        Vec::new()
    }
}

/// Create every missing decoy file (with believable bait content). Returns the
/// paths that were (re)created. Failures are logged, never fatal: a path on a
/// non-existent drive must not take the sentinel down.
fn plant_missing(paths: &[PathBuf], state: &FsState) -> Vec<PathBuf> {
    use std::io::Write;
    use std::os::windows::fs::OpenOptionsExt;
    let mut created = Vec::new();
    for path in paths {
        if path.symlink_metadata().is_ok() {
            let owned = deployments()
                .lock()
                .ok()
                .and_then(|register| register.files.get(path).cloned());
            let Some(owned) = owned else {
                if state
                    .ignored
                    .lock()
                    .is_ok_and(|mut ignored| ignored.insert(path.clone()))
                {
                    warn!(path = %path.display(), "honeytoken path already exists without a deployment record; preserving file and excluding it from decoy cleanup (including legacy installations)");
                }
                state.fail(
                    path,
                    "a file already exists at this path and is not managed by TRAPD",
                );
                continue;
            };
            if let Ok(mut m) = state.atime.lock() {
                if !m.contains_key(path) {
                    if let Some(at) = accessed_time(path) {
                        m.insert(path.clone(), at);
                    }
                }
            }
            if let Ok(mut m) = state.sha.lock() {
                m.entry(path.clone()).or_insert(owned.sha256);
            }
            continue;
        }
        if let Some(parent) = path.parent() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                warn!(path = %path.display(), error = %e, "honeytoken: cannot create parent dir");
                state.fail(path, format!("cannot create parent directory: {e}"));
                continue;
            }
        }
        let bait = bait_content(path);
        let result = (|| -> Result<()> {
            // Exclusive creation refuses files and reparse points that appeared
            // after the existence check. Deny sharing until ownership is saved.
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .share_mode(0)
                .custom_flags(0x0020_0000)
                .open(path)?;
            file.write_all(&bait)?;
            file.sync_all()?;
            let record = OwnedFile {
                identity: file_identity(&file)?,
                sha256: sha256_hex(&bait),
            };
            let mut register = deployments()
                .lock()
                .map_err(|_| anyhow::anyhow!("deployment register poisoned"))?;
            let previous = register.files.insert(path.clone(), record);
            if let Err(error) = persist_deployments(&register) {
                register.files.remove(path);
                if let Some(previous) = previous {
                    register.files.insert(path.clone(), previous);
                }
                // Leave the exclusively created file in place conservatively;
                // cleanup cannot claim ownership without a durable record.
                return Err(error);
            }
            Ok(())
        })();
        match result {
            Ok(()) => {
                state.mark_planted(path);
                if let Ok(mut m) = state.sha.lock() {
                    m.insert(path.clone(), sha256_hex(&bait));
                }
                if let Ok(mut reported) = state.reported.lock() {
                    reported.remove(path);
                }
                info!(path = %path.display(), "honeytoken decoy file planted");
                created.push(path.clone());
            }
            Err(e) => {
                warn!(path = %path.display(), error = %e, "honeytoken: cannot plant decoy file");
                state.fail(path, format!("cannot plant decoy file: {e}"));
            }
        }
    }
    created
}

/// Believable bait content for a decoy file, themed on its name. Strictly fake.
fn bait_content(path: &Path) -> Vec<u8> {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    let body = if name.contains("password") {
        "# IT service accounts — DO NOT SHARE\r\n\
         vpn.corp.local        svc_vpn      V?n2024!Spr1ng\r\n\
         sql01.corp.local      sa           Pr0d-MSSQL-2024!xK7q\r\n\
         backup01.corp.local   svc_backup   B4ckup#Rot8-2024\r\n\
         fileserver.corp.local administrator Wint3r2024!Adm\r\n"
            .to_string()
    } else if name.contains("credential") {
        "host,username,password,notes\r\n\
         sql01.corp.local,sa,Pr0d-MSSQL-2024!xK7q,production database\r\n\
         vpn.corp.local,svc_vpn,V?n2024!Spr1ng,site-to-site vpn\r\n\
         backup01.corp.local,svc_backup,B4ckup#Rot8-2024,veeam console\r\n"
            .to_string()
    } else if name.contains("key") || name.contains("backup") {
        "-----BEGIN BACKUP MASTER KEY-----\r\n\
         QmFja3VwLU1hc3Rlci1LZXktMjAyNC0wMS0xNS1yb3RhdGVkLXF1YXJ0ZXJseQ==\r\n\
         -----END BACKUP MASTER KEY-----\r\n"
            .to_string()
    } else {
        format!(
            "# {} — internal use only\r\nsee IT vault for rotation schedule\r\n",
            path.display()
        )
    };
    body.into_bytes()
}

// ── Filesystem watch (ReadDirectoryChangesW via `notify`) ─────────────────────

/// Owns the directory watcher for the decoy files' parent directories and turns
/// raw change notifications into detection events. Rebuilds the watcher when
/// the configured token set changes (config-pull delivered a new list).
fn fs_watch_loop(
    tx: Sender<AgentEvent>,
    agent_id: String,
    hostname: String,
    config: Arc<RwLock<AgentConfig>>,
    state: Arc<FsState>,
) {
    loop {
        let paths = configured_paths(&config);
        if paths.is_empty() {
            std::thread::sleep(Duration::from_secs(30));
            continue;
        }
        let tokens: HashSet<PathBuf> = paths
            .iter()
            .filter(|path| owns_path(path))
            .cloned()
            .collect();
        let dirs: HashSet<PathBuf> = paths
            .iter()
            .filter_map(|p| p.parent().map(Path::to_path_buf))
            .collect();

        let (ntx, nrx) = std::sync::mpsc::channel::<notify::Result<notify::Event>>();
        let mut watcher = match notify::recommended_watcher(move |res| {
            let _ = ntx.send(res);
        }) {
            Ok(w) => w,
            Err(e) => {
                warn!(error = %e, "honeytoken: cannot create filesystem watcher — retrying");
                std::thread::sleep(Duration::from_secs(60));
                continue;
            }
        };
        let mut watched = 0usize;
        for dir in &dirs {
            match watcher.watch(dir, notify::RecursiveMode::NonRecursive) {
                Ok(()) => watched += 1,
                Err(e) => {
                    warn!(dir = %dir.display(), error = %e, "honeytoken: cannot watch directory")
                }
            }
        }
        info!(
            files = tokens.len(),
            dirs = watched,
            "filesystem honeytoken watch armed"
        );

        loop {
            match nrx.recv_timeout(Duration::from_secs(5)) {
                Ok(Ok(event)) => {
                    handle_fs_event(&event, &tokens, &tx, &agent_id, &hostname, &state)
                }
                Ok(Err(e)) => warn!(error = %e, "honeytoken: watcher reported an error"),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    // Pick up a config-delivered change to the token set.
                    let current = configured_paths(&config);
                    let current_tokens: HashSet<PathBuf> = current
                        .iter()
                        .filter(|path| owns_path(path))
                        .cloned()
                        .collect();
                    if current != paths || current_tokens != tokens {
                        info!("honeytoken paths changed — rebuilding filesystem watch");
                        break;
                    }
                }
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }
        drop(watcher);
    }
}

/// Map one raw `notify` event onto the decoy set and emit detections.
fn handle_fs_event(
    event: &notify::Event,
    tokens: &HashSet<PathBuf>,
    tx: &Sender<AgentEvent>,
    agent_id: &str,
    hostname: &str,
    state: &FsState,
) {
    use notify::EventKind;

    // The label vocabulary deliberately matches the Linux detector
    // (`detection/honeytoken.rs`) where the semantics line up, so backend
    // routing rules apply to both platforms unchanged.
    let access_kind = match event.kind {
        EventKind::Remove(_) => "unlink",
        EventKind::Modify(notify::event::ModifyKind::Name(_)) => "rename",
        EventKind::Modify(_) => "modify",
        EventKind::Access(_) => "open",
        // Creations are the agent replanting (or the file being restored);
        // never an access signal on their own.
        EventKind::Create(_) | EventKind::Any | EventKind::Other => return,
    };

    for path in &event.paths {
        if !tokens.contains(path) {
            continue;
        }
        if state.recently_planted(path) {
            debug!(path = %path.display(), "honeytoken event suppressed (own plant)");
            continue;
        }
        emit_fs_event(tx, agent_id, hostname, path, access_kind);
    }
}

/// Periodic resilience pass: replant deleted decoys, poll last-access
/// timestamps to detect content reads, and (on the slower health cadence)
/// report each token's on-host status to the backend lifecycle mirror.
async fn sweep(
    tx: &Sender<AgentEvent>,
    agent_id: &str,
    hostname: &str,
    config: &Arc<RwLock<AgentConfig>>,
    state: &Arc<FsState>,
    report_health: bool,
) {
    reconcile_removed(tx, agent_id, hostname, config, state);
    let paths = configured_paths(config);

    // Replant anything missing (deletion itself was already raised by the
    // watcher; the sweep restores the bait so it keeps working) and re-register
    // the restored token with the backend (status back to `active`).
    let recreated = plant_missing(&paths, state);
    report_plant_failures(tx, agent_id, hostname, state);
    if !recreated.is_empty() {
        info!(
            recreated = recreated.len(),
            "honeytoken decoy files replanted"
        );
        for path in &recreated {
            emit_fs_deployed(tx, agent_id, hostname, path, state);
        }
    }

    // Read detection: a moved-on last-access timestamp outside our own write
    // suppression window means something opened the bait.
    for path in &paths {
        if !owns_path(path) {
            continue;
        }
        let Some(now_at) = accessed_time(path) else {
            continue;
        };
        let prev = state.atime.lock().ok().and_then(|m| m.get(path).copied());
        if let Some(prev_at) = prev {
            if now_at > prev_at && !state.recently_planted(path) {
                emit_fs_event(tx, agent_id, hostname, path, "open");
            }
        }
        if let Ok(mut m) = state.atime.lock() {
            m.insert(path.clone(), now_at);
        }
    }

    // Health verification (Linux-parity): is each planted token still there,
    // and does its content digest still match? Catches tampering that happened
    // while the agent was down (no watcher event fired).
    if report_health {
        for path in &paths {
            if !owns_path(path) {
                continue;
            }
            let expected = state.sha.lock().ok().and_then(|m| m.get(path).cloned());
            let actual = sha256_of_file(path);
            // Hashing is an agent content read. Advance the atime baseline
            // after closing that handle so the next poll does not attribute
            // this verification read to an unknown accessor.
            if let Some(atime) = accessed_time(path) {
                if let Ok(mut baseline) = state.atime.lock() {
                    baseline.insert(path.clone(), atime);
                }
            }
            let (present, modified) = match (&expected, &actual) {
                (_, None) => (
                    path.symlink_metadata().is_ok(),
                    path.symlink_metadata().is_ok(),
                ),
                (Some(e), Some(a)) => (true, e != a),
                (None, Some(_)) => (true, false),
            };
            emit_fs_health(
                tx, agent_id, hostname, path, present, modified, expected, actual,
            );
        }
        for (path, present, modified) in registry::health() {
            emit_registry_health(tx, agent_id, hostname, &path, present, modified);
        }
    }
}

/// Retire decoys the operator no longer lists: remove each owned file that has
/// left `honeytoken_paths` and tell the backend (`prevention.honeytoken_revoked`).
///
/// A file is deleted only while its identity and content still match what the
/// agent planted. If someone edited it, it is preserved, ownership is dropped
/// and the backend is told the revoke did not remove it. A transient failure
/// (e.g. a sharing violation) keeps ownership and is retried on the next sweep.
fn reconcile_removed(
    tx: &Sender<AgentEvent>,
    agent_id: &str,
    hostname: &str,
    config: &Arc<RwLock<AgentConfig>>,
    state: &FsState,
) {
    let desired: HashSet<PathBuf> = desired_file_paths(config).into_iter().collect();
    if let Ok(mut reported) = state.reported.lock() {
        reported.retain(|path| desired.contains(path));
    }
    // Unmanaged files (a file already sat at the path when it was listed, or a
    // legacy install planted it without an ownership record) are never touched.
    // Once the operator unlists such a path, tell the backend so the token does
    // not linger: the file is left in place and no longer monitored.
    let released: Vec<PathBuf> = match state.ignored.lock() {
        Ok(mut ignored) => {
            let gone: Vec<PathBuf> = ignored
                .iter()
                .filter(|path| !desired.contains(*path))
                .cloned()
                .collect();
            for path in &gone {
                ignored.remove(path);
            }
            gone
        }
        Err(_) => Vec::new(),
    };
    for path in released {
        info!(path = %path.display(), "unmanaged honeytoken path released; file left in place");
        send_prevention(
            tx,
            agent_id,
            hostname,
            EventAction::HoneytokenRevoked,
            Severity::Info,
            "honeytoken_revoke",
            path.display().to_string(),
            false,
            "file is not managed by TRAPD; left in place and no longer monitored".to_string(),
            serde_json::json!({ "kind": "windows_decoy_file", "preserved": true }),
        );
    }
    let stale: Vec<(PathBuf, OwnedFile)> = match deployments().lock() {
        Ok(register) => register
            .files
            .iter()
            .filter(|(path, _)| !desired.contains(*path))
            .map(|(path, owned)| (path.clone(), owned.clone()))
            .collect(),
        Err(_) => return,
    };
    for (path, owned) in stale {
        let preserved = match remove_owned_file(&path, &owned) {
            Ok(()) => false,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
            Err(e) if e.kind() == std::io::ErrorKind::InvalidData => {
                warn!(path = %path.display(), error = %e, "honeytoken decoy changed; preserving file");
                true
            }
            Err(e) => {
                warn!(path = %path.display(), error = %e, "honeytoken decoy removal failed; will retry");
                continue;
            }
        };
        let persisted = match deployments().lock() {
            Ok(mut register) => {
                register.files.remove(&path);
                match persist_deployments(&register) {
                    Ok(()) => true,
                    Err(error) => {
                        warn!(%error, "could not persist honeytoken retirement; will retry");
                        register.files.insert(path.clone(), owned.clone());
                        false
                    }
                }
            }
            Err(_) => false,
        };
        if !persisted {
            continue;
        }
        if let Ok(mut m) = state.sha.lock() {
            m.remove(&path);
        }
        if let Ok(mut m) = state.atime.lock() {
            m.remove(&path);
        }
        if let Ok(mut m) = state.planted.lock() {
            m.remove(&path);
        }
        info!(path = %path.display(), preserved, "honeytoken decoy retired");
        send_prevention(
            tx,
            agent_id,
            hostname,
            EventAction::HoneytokenRevoked,
            if preserved {
                Severity::Medium
            } else {
                Severity::Info
            },
            "honeytoken_revoke",
            path.display().to_string(),
            !preserved,
            if preserved {
                "decoy file was modified; preserved and no longer monitored".to_string()
            } else {
                "windows decoy file removed".to_string()
            },
            serde_json::json!({ "kind": "windows_decoy_file", "preserved": preserved }),
        );
    }
}

/// Report plant failures (once each) so the backend moves the token to `failed`
/// instead of leaving it in `deploying`.
fn report_plant_failures(
    tx: &Sender<AgentEvent>,
    agent_id: &str,
    hostname: &str,
    state: &FsState,
) {
    for (path, reason) in state.take_failures() {
        send_prevention(
            tx,
            agent_id,
            hostname,
            EventAction::HoneytokenDeployed,
            Severity::Medium,
            "honeytoken_deploy",
            path.display().to_string(),
            false,
            reason,
            serde_json::json!({ "kind": "windows_decoy_file" }),
        );
    }
}

/// Report one decoy file to the backend lifecycle mirror
/// (`prevention.honeytoken_deployed` → upserts the `honeytokens` row).
fn emit_fs_deployed(
    tx: &Sender<AgentEvent>,
    agent_id: &str,
    hostname: &str,
    path: &Path,
    state: &FsState,
) {
    let sha256 = state.sha.lock().ok().and_then(|m| m.get(path).cloned());
    send_prevention(
        tx,
        agent_id,
        hostname,
        EventAction::HoneytokenDeployed,
        Severity::Info,
        "honeytoken_deploy",
        path.display().to_string(),
        true,
        "windows decoy file planted by agent".to_string(),
        serde_json::json!({ "kind": "windows_decoy_file", "sha256": sha256 }),
    );
}

/// Report one decoy file's on-host health
/// (`prevention.honeytoken_health` → token `file_status`/`last_verified_at`).
#[allow(clippy::too_many_arguments)]
fn emit_fs_health(
    tx: &Sender<AgentEvent>,
    agent_id: &str,
    hostname: &str,
    path: &Path,
    present: bool,
    modified: bool,
    expected_sha256: Option<String>,
    actual_sha256: Option<String>,
) {
    let file_status = match (present, modified) {
        (false, _) => "missing",
        (true, true) => "modified",
        (true, false) => "present",
    };
    let healthy = present && !modified;
    send_prevention(
        tx,
        agent_id,
        hostname,
        EventAction::HoneytokenHealth,
        if healthy {
            Severity::Info
        } else {
            Severity::High
        },
        "honeytoken_health",
        path.display().to_string(),
        healthy,
        format!("windows decoy file is {file_status}"),
        serde_json::json!({
            "kind": "windows_decoy_file",
            "present": present,
            "modified": modified,
            "file_status": file_status,
            "expected_sha256": expected_sha256,
            "actual_sha256": actual_sha256,
        }),
    );
}

/// Report one registry decoy's health (same lifecycle contract as files).
fn emit_registry_health(
    tx: &Sender<AgentEvent>,
    agent_id: &str,
    hostname: &str,
    path: &str,
    present: bool,
    modified: bool,
) {
    let file_status = match (present, modified) {
        (false, _) => "missing",
        (true, true) => "modified",
        (true, false) => "present",
    };
    let healthy = present && !modified;
    send_prevention(
        tx,
        agent_id,
        hostname,
        EventAction::HoneytokenHealth,
        if healthy {
            Severity::Info
        } else {
            Severity::High
        },
        "honeytoken_health",
        path.to_string(),
        healthy,
        format!("windows registry decoy is {file_status}"),
        serde_json::json!({
            "kind": "windows_registry_key",
            "present": present,
            "modified": modified,
            "file_status": file_status,
        }),
    );
}

/// Ship one prevention-class lifecycle event (deploy/health) to the pipeline.
#[allow(clippy::too_many_arguments)]
fn send_prevention(
    tx: &Sender<AgentEvent>,
    agent_id: &str,
    hostname: &str,
    action: EventAction,
    severity: Severity,
    kind: &str,
    target: String,
    success: bool,
    reason: String,
    details: serde_json::Value,
) {
    let event = AgentEvent::new(
        agent_id.to_string(),
        hostname.to_string(),
        EventClass::Prevention,
        action,
        severity,
        EventData::Prevention(PreventionEventData {
            kind: kind.to_string(),
            target,
            success,
            reason,
            rule_id: None,
            command_id: None,
            details,
        }),
    );
    if let Err(e) = tx.try_send(event) {
        warn!(error = %e, "honeytoken: lifecycle event dropped (pipeline full/closed)");
    }
}

/// Build and ship one filesystem honeytoken detection event.
fn emit_fs_event(
    tx: &Sender<AgentEvent>,
    agent_id: &str,
    hostname: &str,
    path: &Path,
    access_kind: &str,
) {
    let (severity, confidence, tactic, technique) = describe_fs(access_kind);
    let data = HoneytokenAccessData {
        token_id: format!("winfs:{}", path.display()),
        path: path.display().to_string(),
        kind: "windows_decoy_file".to_string(),
        access_kind: access_kind.to_string(),
        open_flags: 0,
        confidence,
        mitre_tactic: tactic.to_string(),
        mitre_technique: technique.to_string(),
        accessor: unknown_accessor(),
        session: None,
    };
    send_detection(tx, agent_id, hostname, severity, data);
    warn!(path = %path.display(), access_kind, "HONEYTOKEN TRIGGERED (filesystem)");
}

/// Scoring per access kind: `(severity, confidence, mitre_tactic, technique)`.
/// Mirrors the Linux scoring where the semantics match (content read = 100,
/// delete = tamper 90, rename = 85); `modify` is data manipulation.
fn describe_fs(access_kind: &str) -> (Severity, u8, &'static str, &'static str) {
    match access_kind {
        "open" => (
            Severity::Critical,
            100,
            "TA0006 Credential Access",
            "T1552.001",
        ),
        "modify" => (Severity::Critical, 90, "TA0040 Impact", "T1565.001"),
        "unlink" => (Severity::Critical, 90, "TA0040 Impact", "T1070.004"),
        "rename" => (Severity::High, 85, "TA0040 Impact", "T1070.004"),
        _ => (
            Severity::Critical,
            90,
            "TA0006 Credential Access",
            "T1552.001",
        ),
    }
}

/// Windows change notifications carry no accessor identity (no PID/user), so
/// the lineage is explicitly `unknown` — the backend treats the *fact* of the
/// access as the signal, exactly like a Linux hit whose process exited before
/// `/proc` could be read.
fn unknown_accessor() -> ProcessLineage {
    ProcessLineage {
        pid: -1,
        uid: 0,
        gid: 0,
        username: "unknown".to_string(),
        comm: "unknown".to_string(),
        exe: None,
        cmdline: None,
        ancestors: Vec::new(),
    }
}

fn send_detection(
    tx: &Sender<AgentEvent>,
    agent_id: &str,
    hostname: &str,
    severity: Severity,
    data: HoneytokenAccessData,
) {
    let event = AgentEvent::new(
        agent_id.to_string(),
        hostname.to_string(),
        EventClass::Detection,
        EventAction::HoneytokenAccess,
        severity,
        EventData::HoneytokenAccess(Box::new(data)),
    );
    // Called from plain threads and from async context via spawn_blocking-free
    // sync paths; try_send never blocks the watcher on a full pipeline.
    if let Err(e) = tx.try_send(event) {
        warn!(error = %e, "honeytoken: detection event dropped (pipeline full/closed)");
    }
}

// ── Registry honeytokens (HKLM\SOFTWARE\TRAPD\Honeytokens) ────────────────────

mod registry {
    use super::*;

    use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_SUCCESS};
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegCreateKeyExW, RegDeleteValueW, RegNotifyChangeKeyValue, RegQueryValueExW,
        RegSetValueExW, HKEY, HKEY_LOCAL_MACHINE, KEY_NOTIFY, KEY_QUERY_VALUE, KEY_SET_VALUE,
        REG_NOTIFY_CHANGE_ATTRIBUTES, REG_NOTIFY_CHANGE_LAST_SET, REG_NOTIFY_CHANGE_NAME,
        REG_NOTIFY_CHANGE_SECURITY, REG_OPTION_NON_VOLATILE, REG_SZ,
    };

    /// NUL-terminated UTF-16 for the Win32 W-APIs.
    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// Open-or-create the honeytoken key and make sure every decoy value is
    /// present with its expected content. Returns the open key handle.
    fn ensure_key_and_values() -> Result<HKEY, u32> {
        let subkey = wide(super::REGISTRY_SUBKEY);
        let mut hkey: HKEY = std::ptr::null_mut();
        let rc = unsafe {
            RegCreateKeyExW(
                HKEY_LOCAL_MACHINE,
                subkey.as_ptr(),
                0,
                std::ptr::null(),
                REG_OPTION_NON_VOLATILE,
                KEY_QUERY_VALUE | KEY_SET_VALUE | KEY_NOTIFY,
                std::ptr::null(),
                &mut hkey,
                std::ptr::null_mut(),
            )
        };
        if rc != ERROR_SUCCESS {
            return Err(rc);
        }
        restore_values(hkey);
        Ok(hkey)
    }

    /// (Re)write every decoy value that is missing or has been tampered with.
    /// Returns how many values were written.
    fn restore_values(hkey: HKEY) -> usize {
        let mut written = 0;
        for (name, expected) in super::REGISTRY_VALUES {
            let owned = deployments()
                .lock()
                .is_ok_and(|register| register.registry_values.contains(*name));
            match read_value(hkey, name) {
                Some(current) if current == *expected => {}
                // Existing values are never adopted, even if their contents
                // happen to equal our bait. An upgrade cannot prove provenance.
                Some(_) if !owned => {
                    debug!(
                        value = name,
                        "preserving preexisting registry value without a deployment record"
                    );
                }
                None if !owned && !value_is_missing(hkey, name) => {
                    warn!(value = name, "registry value exists or cannot be inspected; refusing to overwrite unowned value");
                }
                _ => {
                    let wname = wide(name);
                    let data: Vec<u16> = wide(expected);
                    let bytes = data.len() * 2;
                    let rc = unsafe {
                        RegSetValueExW(
                            hkey,
                            wname.as_ptr(),
                            0,
                            REG_SZ,
                            data.as_ptr() as *const u8,
                            bytes as u32,
                        )
                    };
                    if rc == ERROR_SUCCESS {
                        if let Ok(mut register) = deployments().lock() {
                            let was_owned = register.registry_values.contains(*name);
                            register.registry_values.insert((*name).to_string());
                            if let Err(error) = persist_deployments(&register) {
                                if !was_owned {
                                    register.registry_values.remove(*name);
                                }
                                warn!(%error, value = name, "could not persist registry decoy ownership; cleanup will preserve unregistered value");
                            } else {
                                written += 1;
                            }
                        }
                    } else {
                        warn!(value = name, rc, "honeytoken: cannot write registry decoy");
                    }
                }
            }
        }
        written
    }

    /// Only an explicit NOT_FOUND establishes absence. The content reader's
    /// None also covers wrong types, access failures and oversized values.
    fn value_is_missing(hkey: HKEY, name: &str) -> bool {
        let wname = wide(name);
        let mut len = 0u32;
        (unsafe {
            RegQueryValueExW(
                hkey,
                wname.as_ptr(),
                std::ptr::null(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut len,
            )
        }) == ERROR_FILE_NOT_FOUND
    }

    /// Read one REG_SZ decoy value. `None` when missing or unreadable.
    fn read_value(hkey: HKEY, name: &str) -> Option<String> {
        let wname = wide(name);
        let mut buf = [0u8; 2048];
        let mut len = buf.len() as u32;
        let mut vtype = 0u32;
        let rc = unsafe {
            RegQueryValueExW(
                hkey,
                wname.as_ptr(),
                std::ptr::null(),
                &mut vtype,
                buf.as_mut_ptr(),
                &mut len,
            )
        };
        if rc != ERROR_SUCCESS {
            if rc != ERROR_FILE_NOT_FOUND {
                debug!(value = name, rc, "honeytoken: registry value read failed");
            }
            return None;
        }
        if len as usize > buf.len() {
            return None;
        }
        decode_value(vtype, &buf[..len as usize])
    }

    fn decode_value(vtype: u32, bytes: &[u8]) -> Option<String> {
        if vtype != REG_SZ
            || bytes.len() > 2048
            || bytes.len() < 2
            || !bytes.len().is_multiple_of(2)
            || !bytes.ends_with(&[0, 0])
        {
            return None;
        }
        // Interpret as UTF-16 (REG_SZ), dropping the trailing NUL.
        let mut units: Vec<u16> = bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes(*c))
            .collect();
        units.pop(); // exactly the required final terminator
        if units.contains(&0) {
            return None;
        }
        String::from_utf16(&units).ok()
    }

    /// What the post-notification diff found per decoy value.
    enum Discrepancy {
        Deleted(&'static str),
        Modified(&'static str),
    }

    fn diff_values(hkey: HKEY) -> Vec<Discrepancy> {
        let mut out = Vec::new();
        for (name, expected) in super::REGISTRY_VALUES {
            if !deployments()
                .lock()
                .is_ok_and(|register| register.registry_values.contains(*name))
            {
                continue;
            }
            match read_value(hkey, name) {
                None => out.push(Discrepancy::Deleted(name)),
                Some(v) if v != *expected => out.push(Discrepancy::Modified(name)),
                Some(_) => {}
            }
        }
        out
    }

    /// Whether the honeytoken key itself still exists.
    fn key_exists() -> bool {
        use windows_sys::Win32::System::Registry::RegOpenKeyExW;
        let subkey = wide(super::REGISTRY_SUBKEY);
        let mut hkey: HKEY = std::ptr::null_mut();
        let rc = unsafe {
            RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                subkey.as_ptr(),
                0,
                KEY_NOTIFY,
                &mut hkey,
            )
        };
        if rc == ERROR_SUCCESS {
            unsafe { RegCloseKey(hkey) };
            true
        } else {
            false
        }
    }

    /// On-host health of every registry decoy: `(path, present, modified)`.
    /// Opens the key read-only; a missing key reports every value as missing.
    pub fn health() -> Vec<(String, bool, bool)> {
        use windows_sys::Win32::System::Registry::RegOpenKeyExW;
        let subkey = wide(super::REGISTRY_SUBKEY);
        let mut hkey: HKEY = std::ptr::null_mut();
        let rc = unsafe {
            RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                subkey.as_ptr(),
                0,
                KEY_QUERY_VALUE,
                &mut hkey,
            )
        };
        let opened = rc == ERROR_SUCCESS;
        let out = super::REGISTRY_VALUES
            .iter()
            .filter(|(name, _)| {
                deployments()
                    .lock()
                    .is_ok_and(|register| register.registry_values.contains(*name))
            })
            .map(|(name, expected)| {
                let path = format!("HKLM\\{}\\{name}", super::REGISTRY_SUBKEY);
                if !opened {
                    return (path, false, false);
                }
                match read_value(hkey, name) {
                    None => (path, false, false),
                    Some(v) if v != *expected => (path, true, true),
                    Some(_) => (path, true, false),
                }
            })
            .collect();
        if opened {
            unsafe { RegCloseKey(hkey) };
        }
        out
    }

    /// Dedicated monitor thread: create the decoys, then block in
    /// `RegNotifyChangeKeyValue` and raise a detection for every change that is
    /// not our own restore. The key and its values are recreated whenever they
    /// go missing (resilient against deletion).
    pub fn monitor(
        tx: Sender<AgentEvent>,
        agent_id: String,
        hostname: String,
        config: Arc<RwLock<AgentConfig>>,
    ) {
        loop {
            if tx.is_closed() {
                return;
            }
            let guard = config.read().unwrap_or_else(|error| error.into_inner());
            if !guard.honeytoken_detection_enabled || !super::registry_decoys_requested(&guard) {
                // Registry decoys are opt-in: retire any planted earlier
                // (config no longer lists them) and stay idle.
                let retire = !super::registry_decoys_requested(&guard);
                drop(guard);
                if retire {
                    for path in cleanup() {
                        super::send_prevention(
                            &tx,
                            &agent_id,
                            &hostname,
                            EventAction::HoneytokenRevoked,
                            Severity::Info,
                            "honeytoken_revoke",
                            path,
                            true,
                            "windows registry decoy removed".to_string(),
                            serde_json::json!({ "kind": "windows_registry_key" }),
                        );
                    }
                }
                std::thread::sleep(Duration::from_secs(1));
                continue;
            }
            let ensured = ensure_key_and_values();
            drop(guard);
            let hkey = match ensured {
                Ok(h) => h,
                Err(rc) => {
                    warn!(
                        rc,
                        "honeytoken: cannot create registry decoys (need admin rights?) — \
                         retrying in 60s"
                    );
                    std::thread::sleep(Duration::from_secs(60));
                    continue;
                }
            };
            info!(
                key = super::REGISTRY_SUBKEY,
                values = super::REGISTRY_VALUES.len(),
                "registry honeytokens ensured"
            );
            // Register each decoy value with the backend lifecycle mirror, so
            // registry tokens show up in the dashboard before any trigger.
            for (name, _) in super::REGISTRY_VALUES {
                if !deployments()
                    .lock()
                    .is_ok_and(|register| register.registry_values.contains(*name))
                {
                    continue;
                }
                super::send_prevention(
                    &tx,
                    &agent_id,
                    &hostname,
                    EventAction::HoneytokenDeployed,
                    Severity::Info,
                    "honeytoken_deploy",
                    format!("HKLM\\{}\\{name}", super::REGISTRY_SUBKEY),
                    true,
                    "windows registry decoy planted by agent".to_string(),
                    serde_json::json!({ "kind": "windows_registry_key" }),
                );
            }
            // Creating/restoring values above counts as a self-write.
            let mut last_restore = Instant::now();

            loop {
                let rc = unsafe {
                    RegNotifyChangeKeyValue(
                        hkey,
                        1, // watch the whole subtree
                        REG_NOTIFY_CHANGE_NAME
                            | REG_NOTIFY_CHANGE_LAST_SET
                            | REG_NOTIFY_CHANGE_ATTRIBUTES
                            | REG_NOTIFY_CHANGE_SECURITY,
                        std::ptr::null_mut(),
                        0, // synchronous: block this thread until a change
                    )
                };
                // A config change while blocked in RegNotify must suppress the
                // pending hit and all repairs before re-entering the outer gate.
                let guard = config.read().unwrap_or_else(|error| error.into_inner());
                if !guard.honeytoken_detection_enabled || !super::registry_decoys_requested(&guard)
                {
                    break;
                }
                if rc != ERROR_SUCCESS {
                    warn!(rc, "honeytoken: RegNotifyChangeKeyValue failed — re-arming");
                    break;
                }

                if !key_exists() {
                    emit(
                        &tx,
                        &agent_id,
                        &hostname,
                        super::REGISTRY_SUBKEY,
                        "registry_key_deleted",
                    );
                    break; // outer loop recreates the key
                }

                let discrepancies = diff_values(hkey);
                if discrepancies.is_empty() {
                    // Everything matches: either our own restore (suppressed) or
                    // a change we cannot attribute to a specific value (e.g. a
                    // value added and removed, or a subkey created).
                    if last_restore.elapsed() > super::SELF_WRITE_SUPPRESSION {
                        emit(
                            &tx,
                            &agent_id,
                            &hostname,
                            super::REGISTRY_SUBKEY,
                            "registry_change",
                        );
                    }
                    continue;
                }
                for d in &discrepancies {
                    let (name, kind) = match d {
                        Discrepancy::Deleted(n) => (*n, "registry_delete"),
                        Discrepancy::Modified(n) => (*n, "registry_modify"),
                    };
                    let path = format!("HKLM\\{}\\{name}", super::REGISTRY_SUBKEY);
                    emit(&tx, &agent_id, &hostname, &path, kind);
                }
                restore_values(hkey);
                last_restore = Instant::now();
            }

            unsafe { RegCloseKey(hkey) };
            std::thread::sleep(Duration::from_secs(1));
        }
    }

    /// Ship one registry honeytoken detection.
    fn emit(tx: &Sender<AgentEvent>, agent_id: &str, hostname: &str, path: &str, kind: &str) {
        let (severity, confidence) = match kind {
            // The watched values only change when someone *writes* them — reads
            // are invisible to RegNotifyChangeKeyValue — so every hit is tamper
            // or recon-with-write, scored high.
            "registry_key_deleted" => (Severity::Critical, 90),
            "registry_delete" => (Severity::Critical, 90),
            "registry_modify" => (Severity::Critical, 90),
            _ => (Severity::High, 75),
        };
        let data = HoneytokenAccessData {
            token_id: format!("winreg:{path}"),
            path: path.to_string(),
            kind: "windows_registry_key".to_string(),
            access_kind: kind.to_string(),
            open_flags: 0,
            confidence,
            mitre_tactic: "TA0006 Credential Access".to_string(),
            mitre_technique: "T1552.002".to_string(),
            accessor: super::unknown_accessor(),
            session: None,
        };
        super::send_detection(tx, agent_id, hostname, severity, data);
        warn!(path, kind, "HONEYTOKEN TRIGGERED (registry)");
    }

    /// Remove the registry decoy values this agent planted (and only those, and
    /// only while unchanged). Returns the paths no longer present. Idle (no
    /// registry access) when nothing is registered.
    pub fn cleanup() -> Vec<String> {
        let mut removed = Vec::new();
        if deployments()
            .lock()
            .is_ok_and(|register| register.registry_values.is_empty())
        {
            return removed;
        }
        use windows_sys::Win32::System::Registry::RegOpenKeyExW;
        let subkey = wide(super::REGISTRY_SUBKEY);
        let mut hkey: HKEY = std::ptr::null_mut();
        let rc = unsafe {
            RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                subkey.as_ptr(),
                0,
                KEY_QUERY_VALUE | KEY_SET_VALUE,
                &mut hkey,
            )
        };
        if rc == ERROR_SUCCESS {
            if let Ok(mut register) = deployments().lock() {
                for (name, expected) in super::REGISTRY_VALUES {
                    if !register.registry_values.contains(*name) {
                        continue;
                    }
                    match read_value(hkey, name) {
                        Some(current) if current == *expected => {
                            let wname = wide(name);
                            if unsafe { RegDeleteValueW(hkey, wname.as_ptr()) } == ERROR_SUCCESS {
                                register.registry_values.remove(*name);
                                removed.push(format!("HKLM\\{}\\{name}", super::REGISTRY_SUBKEY));
                            }
                        }
                        None => {
                            register.registry_values.remove(*name);
                            removed.push(format!("HKLM\\{}\\{name}", super::REGISTRY_SUBKEY));
                        }
                        Some(_) => warn!(
                            value = name,
                            "registry decoy changed; preserving value during cleanup"
                        ),
                    }
                }
                if let Err(error) = persist_deployments(&register) {
                    warn!(%error, "could not persist registry cleanup register");
                }
            }
            unsafe { RegCloseKey(hkey) };
            // Retain the container keys. RegDeleteKeyW deletes keys containing
            // values, and a query-then-delete cannot protect concurrent writers.
            // Removing only recorded values preserves every unowned artifact.
        } else if rc != ERROR_FILE_NOT_FOUND {
            warn!(rc, "could not open registry honeytokens for cleanup");
        }
        removed
    }

    #[cfg(test)]
    mod parsing_regressions {
        use super::*;
        use windows_sys::Win32::System::Registry::{RegDeleteTreeW, HKEY_CURRENT_USER, REG_BINARY};

        #[test]
        fn raw_malformed_registry_strings_are_rejected() {
            // Test raw bytes directly: RegSetValueExW requires terminated strings,
            // so writing an unterminated fixture through it is not reliable.
            for bytes in [
                vec![],
                vec![b'x', 0],
                vec![b'x', 0, 0],
                vec![b'x', 0, 0, 0, b'y', 0, 0, 0],
                vec![0x00, 0xd8, 0, 0],
                vec![0; 4096],
            ] {
                assert!(decode_value(REG_SZ, &bytes).is_none(), "{bytes:?}");
            }
            assert!(decode_value(REG_BINARY, &[b'x', 0, 0, 0]).is_none());
            assert_eq!(decode_value(REG_SZ, &[b'x', 0, 0, 0]), Some("x".into()));
        }

        #[test]
        fn existing_wrong_type_oversized_and_embedded_nul_values_are_preserved() {
            let key = wide(&format!("SOFTWARE\\TRAPD-Test-{}", uuid::Uuid::new_v4()));
            let mut hkey: HKEY = std::ptr::null_mut();
            assert_eq!(
                unsafe {
                    RegCreateKeyExW(
                        HKEY_CURRENT_USER,
                        key.as_ptr(),
                        0,
                        std::ptr::null(),
                        REG_OPTION_NON_VOLATILE,
                        KEY_QUERY_VALUE | KEY_SET_VALUE,
                        std::ptr::null(),
                        &mut hkey,
                        std::ptr::null_mut(),
                    )
                },
                ERROR_SUCCESS
            );
            for (name, kind, bytes) in [
                ("binary", REG_BINARY, vec![b'x', 0, 0, 0]),
                ("oversized", REG_SZ, vec![0; 4096]),
                ("embedded-nul", REG_SZ, vec![b'x', 0, 0, 0, b'y', 0, 0, 0]),
            ] {
                let wname = wide(name);
                assert_eq!(
                    unsafe {
                        RegSetValueExW(
                            hkey,
                            wname.as_ptr(),
                            0,
                            kind,
                            bytes.as_ptr(),
                            bytes.len() as u32,
                        )
                    },
                    ERROR_SUCCESS
                );
                assert!(
                    !value_is_missing(hkey, name),
                    "{name} must not authorize initialization"
                );
                assert!(
                    read_value(hkey, name).is_none(),
                    "{name} cannot be accepted as a valid string decoy"
                );
            }
            assert!(value_is_missing(hkey, "missing"));
            unsafe { RegCloseKey(hkey) };
            assert_eq!(
                unsafe { RegDeleteTreeW(HKEY_CURRENT_USER, key.as_ptr()) },
                ERROR_SUCCESS
            );
        }
    }
}

// ── Uninstall ─────────────────────────────────────────────────────────────────

/// Remove every honeytoken artifact from this host: the decoy files (both the
/// currently-configured set and the built-in defaults, so a config change
/// between install and uninstall cannot strand a decoy) and the registry key.
pub fn uninstall(cfg: &AgentConfig) {
    let _ = cfg; // Cleanup follows persisted ownership, including removed config paths.
    let Ok(mut register) = deployments().lock() else {
        return;
    };
    let files = register.files.clone();
    for (path, owned) in &files {
        match remove_owned_file(path, owned) {
            Ok(()) => info!(path = %path.display(), "honeytoken decoy file removed"),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                warn!(path = %path.display(), error = %e, "could not remove honeytoken decoy file");
                continue;
            }
        }
        register.files.remove(path);
    }
    if let Err(error) = persist_deployments(&register) {
        warn!(%error, "could not persist honeytoken cleanup register");
    }
    drop(register);
    registry::cleanup();
}
