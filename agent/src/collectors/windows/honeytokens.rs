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
    std::fs::read(path).ok().map(|b| sha256_hex(&b))
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

        // Initial plant so the bait exists before any watcher is armed.
        let initial = configured_paths(&self.config);
        let planted = plant_missing(&initial, &state);
        info!(
            configured = initial.len(),
            created = planted.len(),
            "filesystem honeytokens ensured"
        );
        // Register every configured decoy with the backend lifecycle mirror
        // (`prevention.honeytoken_deployed` → `honeytokens` row), so the
        // dashboard shows Windows tokens *before* their first trigger.
        for path in &initial {
            emit_fs_deployed(&tx, &agent_id, &hostname, path, &state);
        }

        // Registry decoys + blocking RegNotifyChangeKeyValue monitor.
        {
            let tx = tx.clone();
            let agent_id = agent_id.clone();
            let hostname = hostname.clone();
            std::thread::Builder::new()
                .name("trapd-reg-honeytokens".into())
                .spawn(move || registry::monitor(tx, agent_id, hostname))
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
            let report_health = tick % HEALTH_EVERY_N_SWEEPS == 0;
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

/// The effective decoy-file set: the config-delivered `honeytoken_paths`,
/// trimmed and deduplicated. Empty when honeytoken detection is disabled.
fn configured_paths(config: &Arc<RwLock<AgentConfig>>) -> Vec<PathBuf> {
    let Ok(cfg) = config.read() else {
        return Vec::new();
    };
    if !cfg.honeytoken_detection_enabled {
        return Vec::new();
    }
    let mut seen = HashSet::new();
    cfg.honeytoken_paths
        .iter()
        .map(|p| p.trim())
        .filter(|p| !p.is_empty())
        .map(PathBuf::from)
        .filter(|p| seen.insert(p.clone()))
        .collect()
}

/// Create every missing decoy file (with believable bait content). Returns the
/// paths that were (re)created. Failures are logged, never fatal: a path on a
/// non-existent drive must not take the sentinel down.
fn plant_missing(paths: &[PathBuf], state: &FsState) -> Vec<PathBuf> {
    let mut created = Vec::new();
    for path in paths {
        if path.exists() {
            // Ensure read-detection + tamper baselines exist even when the
            // file survived a restart (its current content is the baseline).
            if let Ok(mut m) = state.atime.lock() {
                if !m.contains_key(path) {
                    if let Some(at) = accessed_time(path) {
                        m.insert(path.clone(), at);
                    }
                }
            }
            if let Ok(mut m) = state.sha.lock() {
                if !m.contains_key(path) {
                    if let Some(d) = sha256_of_file(path) {
                        m.insert(path.clone(), d);
                    }
                }
            }
            continue;
        }
        if let Some(parent) = path.parent() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                warn!(path = %path.display(), error = %e, "honeytoken: cannot create parent dir");
                continue;
            }
        }
        let bait = bait_content(path);
        match std::fs::write(path, &bait) {
            Ok(()) => {
                state.mark_planted(path);
                if let Ok(mut m) = state.sha.lock() {
                    m.insert(path.clone(), sha256_hex(&bait));
                }
                info!(path = %path.display(), "honeytoken decoy file planted");
                created.push(path.clone());
            }
            Err(e) => {
                warn!(path = %path.display(), error = %e, "honeytoken: cannot plant decoy file")
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
        let tokens: HashSet<PathBuf> = paths.iter().cloned().collect();
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
                    if configured_paths(&config) != paths {
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
    let paths = configured_paths(config);

    // Replant anything missing (deletion itself was already raised by the
    // watcher; the sweep restores the bait so it keeps working) and re-register
    // the restored token with the backend (status back to `active`).
    let recreated = plant_missing(&paths, state);
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
            let expected = state.sha.lock().ok().and_then(|m| m.get(path).cloned());
            let actual = sha256_of_file(path);
            let (present, modified) = match (&expected, &actual) {
                (_, None) => (false, false),
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
        RegCloseKey, RegCreateKeyExW, RegDeleteKeyW, RegDeleteTreeW, RegNotifyChangeKeyValue,
        RegQueryValueExW, RegSetValueExW, HKEY, HKEY_LOCAL_MACHINE, KEY_NOTIFY, KEY_QUERY_VALUE,
        KEY_SET_VALUE, REG_NOTIFY_CHANGE_ATTRIBUTES, REG_NOTIFY_CHANGE_LAST_SET,
        REG_NOTIFY_CHANGE_NAME, REG_NOTIFY_CHANGE_SECURITY, REG_OPTION_NON_VOLATILE, REG_SZ,
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
            match read_value(hkey, name) {
                Some(current) if current == *expected => {}
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
                        written += 1;
                    } else {
                        warn!(value = name, rc, "honeytoken: cannot write registry decoy");
                    }
                }
            }
        }
        written
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
        // Interpret as UTF-16 (REG_SZ), dropping the trailing NUL.
        let units: Vec<u16> = buf[..len as usize]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .take_while(|&u| u != 0)
            .collect();
        Some(String::from_utf16_lossy(&units))
    }

    /// What the post-notification diff found per decoy value.
    enum Discrepancy {
        Deleted(&'static str),
        Modified(&'static str),
    }

    fn diff_values(hkey: HKEY) -> Vec<Discrepancy> {
        let mut out = Vec::new();
        for (name, expected) in super::REGISTRY_VALUES {
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
    pub fn monitor(tx: Sender<AgentEvent>, agent_id: String, hostname: String) {
        loop {
            let hkey = match ensure_key_and_values() {
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

    /// Remove the decoy registry key (and the now-empty parent, best-effort).
    pub fn cleanup() {
        let subkey = wide(super::REGISTRY_SUBKEY);
        let rc = unsafe { RegDeleteTreeW(HKEY_LOCAL_MACHINE, subkey.as_ptr()) };
        if rc == ERROR_SUCCESS {
            info!(key = super::REGISTRY_SUBKEY, "registry honeytokens removed");
        } else if rc != ERROR_FILE_NOT_FOUND {
            warn!(
                rc,
                key = super::REGISTRY_SUBKEY,
                "could not remove registry honeytokens"
            );
        }
        // Only succeeds when SOFTWARE\TRAPD is empty — exactly what we want.
        let parent = wide(super::REGISTRY_PARENT_SUBKEY);
        let _ = unsafe { RegDeleteKeyW(HKEY_LOCAL_MACHINE, parent.as_ptr()) };
    }
}

// ── Uninstall ─────────────────────────────────────────────────────────────────

/// Remove every honeytoken artifact from this host: the decoy files (both the
/// currently-configured set and the built-in defaults, so a config change
/// between install and uninstall cannot strand a decoy) and the registry key.
pub fn uninstall(cfg: &AgentConfig) {
    let mut paths: Vec<PathBuf> = cfg
        .honeytoken_paths
        .iter()
        .map(|p| p.trim())
        .filter(|p| !p.is_empty())
        .map(PathBuf::from)
        .collect();
    for p in AgentConfig::default().honeytoken_paths {
        let p = PathBuf::from(p);
        if !paths.contains(&p) {
            paths.push(p);
        }
    }

    for path in &paths {
        match std::fs::remove_file(path) {
            Ok(()) => info!(path = %path.display(), "honeytoken decoy file removed"),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                warn!(path = %path.display(), error = %e, "could not remove honeytoken decoy file")
            }
        }
    }

    registry::cleanup();
}
