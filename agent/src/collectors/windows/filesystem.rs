//! ReadDirectoryChangesW notifications (notify) plus bounded SHA256 FIM scans.
use std::collections::BTreeMap;
use std::io::Read;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use anyhow::{bail, Result};
use async_trait::async_trait;
use notify::event::{ModifyKind, RenameMode};
use notify::{EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::mpsc::Sender;

use crate::collectors::fs_heuristics as heur;
use crate::collectors::fs_plan::{self, Action, Change, Planner, Roots};
use crate::collectors::Collector;
use crate::config::AgentConfig;
use crate::schema::{
    AgentEvent, AgentTamperData, EventAction, EventClass, EventData, FilesystemEventData,
    FilesystemOperation, FilesystemSource, IntegrityStatus, Severity,
};

const MAX_FILES: usize = 10_000;
const MAX_FILE_BYTES: u64 = 16 * 1024 * 1024;

pub fn windows_paths(configured: &[String], defaults: &[String]) -> Vec<PathBuf> {
    if configured == defaults {
        vec![
            PathBuf::from(std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into()))
                .join("System32\\drivers\\etc"),
            PathBuf::from(std::env::var_os("PUBLIC").unwrap_or_else(|| "C:\\Users\\Public".into()))
                .join("Documents"),
        ]
    } else {
        configured
            .iter()
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
            .collect()
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq)]
struct Fingerprint {
    sha256: String,
    size: u64,
}

#[derive(Default, Serialize, Deserialize)]
struct Baseline {
    paths: Vec<PathBuf>,
    files: BTreeMap<String, Fingerprint>,
}

fn scan(paths: Vec<PathBuf>) -> Result<BTreeMap<String, Fingerprint>> {
    let mut out = BTreeMap::new();
    let started = std::time::Instant::now();
    let mut total_bytes = 0u64;
    for root in paths {
        for entry in walkdir::WalkDir::new(root).follow_links(false) {
            let entry = entry?;
            if started.elapsed().as_secs() >= 10 {
                bail!("Windows FIM scan exceeded time budget");
            }
            if !entry.file_type().is_file() {
                continue;
            }
            if out.len() >= MAX_FILES {
                bail!("Windows FIM scan exceeds {MAX_FILES} files");
            }
            let meta = entry.metadata()?;
            if meta.len() > MAX_FILE_BYTES {
                continue;
            }
            let mut file = std::fs::File::open(entry.path())?.take(MAX_FILE_BYTES + 1);
            let mut sha = Sha256::new();
            let mut buffer = [0u8; 65536];
            let mut size = 0u64;
            loop {
                let count = file.read(&mut buffer)?;
                if count == 0 {
                    break;
                }
                size += count as u64;
                total_bytes += count as u64;
                if total_bytes > 128 * 1024 * 1024 || started.elapsed().as_secs() >= 10 {
                    bail!("Windows FIM scan exceeded read budget");
                }
                if size > MAX_FILE_BYTES {
                    bail!("file grew beyond Windows FIM size limit");
                }
                sha.update(&buffer[..count]);
            }
            out.insert(
                entry.path().to_string_lossy().into_owned(),
                Fingerprint {
                    sha256: format!("sha256:{}", hex::encode(sha.finalize())),
                    size,
                },
            );
        }
    }
    Ok(out)
}

fn event(
    agent_id: &str,
    hostname: &str,
    path: String,
    operation: FilesystemOperation,
    source: FilesystemSource,
    before: Option<&Fingerprint>,
    after: Option<&Fingerprint>,
) -> AgentEvent {
    let violation = before.is_some() && operation != FilesystemOperation::Created;
    let realtime = matches!(source, FilesystemSource::Realtime);
    AgentEvent::new(
        agent_id.into(),
        hostname.into(),
        EventClass::Filesystem,
        match operation {
            FilesystemOperation::Created => EventAction::Create,
            FilesystemOperation::Modified => EventAction::Modify,
            FilesystemOperation::Deleted => EventAction::Delete,
        },
        if violation {
            Severity::High
        } else {
            Severity::Info
        },
        EventData::Filesystem(FilesystemEventData {
            path,
            operation,
            source,
            integrity: if realtime {
                IntegrityStatus::NotChecked
            } else if violation {
                IntegrityStatus::Violation
            } else {
                IntegrityStatus::BaselineAdded
            },
            expected_hash: before.map(|f| f.sha256.clone()),
            actual_hash: after.map(|f| f.sha256.clone()),
            size_delta: before.map(|f| after.map(|a| a.size as i64).unwrap_or(0) - f.size as i64),
        }),
    )
}

/// Locations watched for their named detections, in addition to the configured
/// telemetry paths: user data for ransomware behaviour, backup folders for
/// sabotage, and the agent's own configuration for tamper.
struct DetectionRoots {
    ransom: Vec<PathBuf>,
    backup: Vec<PathBuf>,
    /// The agent's configuration and install directories: any foreign change is
    /// tamper (a replaced binary, a swapped signing key, an edited policy).
    tamper: Vec<PathBuf>,
}

fn detection_roots() -> DetectionRoots {
    let drive = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".into());
    let on_drive = |dir: &str| PathBuf::from(format!("{drive}\\{dir}"));
    let profiles = crate::inventory::collect::windows_user_profiles();
    let (ransom, truncated) = fs_plan::ransom_roots(
        profiles
            .iter()
            .map(|profile| (profile.sid.as_str(), profile.profile_dir.as_str())),
        &on_drive("Users").to_string_lossy(),
    );
    if truncated {
        tracing::warn!(watched_roots = ransom.len(), "Windows ransomware profile watch limit exceeded; some relocated profiles are not monitored");
    }
    DetectionRoots {
        ransom: ransom.into_iter().map(PathBuf::from).collect(),
        backup: vec![on_drive("Backup"), on_drive("Backups")],
        tamper: std::iter::once(crate::paths::config_dir().to_path_buf())
            .chain(
                std::env::current_exe()
                    .ok()
                    .and_then(|exe| exe.parent().map(|p| p.to_path_buf())),
            )
            .collect(),
    }
}

/// Own tamper handles separately from live telemetry and ransomware watches.
/// Parent handles observe replacement of the protected directory; target
/// handles observe only its immediate children and are rearmed at its path.
struct TamperWatches {
    watcher: RecommendedWatcher,
    targets: Vec<PathBuf>,
    scope: Vec<String>,
    watched: BTreeMap<String, PathBuf>,
}

impl TamperWatches {
    fn new(targets: &[PathBuf], tx: Sender<notify::Result<notify::Event>>) -> Result<Self> {
        let filter: Vec<String> = targets
            .iter()
            .map(|p| fs_plan::normalise_root(&p.to_string_lossy()))
            .collect();
        let watcher = RecommendedWatcher::new(
            move |result: notify::Result<notify::Event>| {
                // Parent handles also receive sibling changes (e.g. spool and
                // logs). Reject them before they can consume the bounded queue.
                if result.as_ref().is_ok_and(|event| {
                    !event.paths.iter().any(|path| {
                        fs_plan::is_tamper_path(
                            &fs_plan::normalise(&path.to_string_lossy()),
                            &filter,
                        )
                    })
                }) {
                    return;
                }
                if tx.try_send(result).is_err() {
                    crate::telemetry::metrics::metrics()
                        .event_dropped(crate::telemetry::DropReason::UserspaceChannelFull);
                }
            },
            notify::Config::default(),
        )?;
        let mut watches = Self {
            watcher,
            targets: Vec::new(),
            scope: Vec::new(),
            watched: BTreeMap::new(),
        };
        for target in targets {
            let Some(parent) = target.parent() else {
                continue;
            };
            // Retain direct file monitoring if parent enumeration is denied;
            // watch_directory reports that replacement coverage is unavailable.
            watches.watch_directory(parent);
            let scope = fs_plan::normalise_root(&target.to_string_lossy());
            if watches.scope.contains(&scope) {
                continue;
            }
            watches.scope.push(scope);
            watches.targets.push(target.clone());
            watches.watch_target(target);
        }
        Ok(watches)
    }

    fn watch_target(&mut self, target: &std::path::Path) {
        // An absent directory is still covered by its parent. Its creation
        // will trigger rearming, including a replacement after removal.
        if target.is_dir() {
            self.watch_directory(target);
        }
    }

    fn watch_directory(&mut self, path: &std::path::Path) -> bool {
        let key = fs_plan::normalise_root(&path.to_string_lossy());
        if self.watched.contains_key(&key) {
            return true;
        }
        match self.watcher.watch(path, RecursiveMode::NonRecursive) {
            Ok(()) => {
                self.watched.insert(key, path.to_path_buf());
                true
            }
            Err(e) => {
                tracing::warn!(path = %path.display(), error = %e, "Windows tamper watch unavailable");
                false
            }
        }
    }

    fn rearm(&mut self, change: Change, path: &std::path::Path) {
        if !matches!(
            change,
            Change::Created | Change::Deleted | Change::RenamedFrom | Change::RenamedTo
        ) {
            return;
        }
        let key = fs_plan::normalise_root(&path.to_string_lossy());
        if !self.scope.contains(&key) {
            return;
        }
        // The old handle may have followed a moved directory. Never let it
        // stand in for the original protected path.
        // A config directory can live inside the install directory. Rearm
        // nested targets and shared parent handles if that ancestor is replaced.
        let stale: Vec<String> = self
            .watched
            .keys()
            .filter(|root| root.starts_with(&key))
            .cloned()
            .collect();
        for root in stale {
            if let Some(path) = self.watched.remove(&root) {
                let _ = self.watcher.unwatch(&path);
            }
        }
        let targets: Vec<PathBuf> = self
            .targets
            .iter()
            .filter(|target| fs_plan::normalise_root(&target.to_string_lossy()).starts_with(&key))
            .cloned()
            .collect();
        for target in targets {
            if let Some(parent) = target.parent().filter(|parent| parent.is_dir()) {
                self.watch_directory(parent);
            }
            self.watch_target(&target);
        }
    }
}

fn change_for(kind: &EventKind, paths: &[PathBuf]) -> Vec<(Change, PathBuf)> {
    let first = || paths.first().cloned();
    match kind {
        EventKind::Create(_) => paths.iter().map(|p| (Change::Created, p.clone())).collect(),
        EventKind::Remove(_) => paths.iter().map(|p| (Change::Deleted, p.clone())).collect(),
        EventKind::Modify(ModifyKind::Name(RenameMode::From)) => first()
            .map(|p| (Change::RenamedFrom, p))
            .into_iter()
            .collect(),
        EventKind::Modify(ModifyKind::Name(RenameMode::To)) => first()
            .map(|p| (Change::RenamedTo, p))
            .into_iter()
            .collect(),
        EventKind::Modify(ModifyKind::Name(RenameMode::Both)) => {
            let mut out = Vec::new();
            if let Some(from) = paths.first() {
                out.push((Change::RenamedFrom, from.clone()));
            }
            if let Some(to) = paths.get(1) {
                out.push((Change::RenamedTo, to.clone()));
            }
            out
        }
        EventKind::Modify(ModifyKind::Metadata(_)) => {
            paths.iter().map(|p| (Change::Attrib, p.clone())).collect()
        }
        EventKind::Modify(_) => paths
            .iter()
            .map(|p| (Change::Modified, p.clone()))
            .collect(),
        _ => Vec::new(),
    }
}

fn operation_for(change: Change) -> FilesystemOperation {
    match change {
        Change::Created | Change::RenamedTo => FilesystemOperation::Created,
        Change::Deleted | Change::RenamedFrom => FilesystemOperation::Deleted,
        Change::Modified | Change::Attrib => FilesystemOperation::Modified,
    }
}

pub struct FilesystemCollector {
    config: Arc<RwLock<AgentConfig>>,
}
impl FilesystemCollector {
    pub fn new(config: Arc<RwLock<AgentConfig>>) -> Self {
        Self { config }
    }
}

#[async_trait]
impl Collector for FilesystemCollector {
    fn name(&self) -> &'static str {
        "WindowsFilesystemCollector"
    }
    async fn run(
        &mut self,
        tx: Sender<AgentEvent>,
        agent_id: String,
        hostname: String,
    ) -> Result<()> {
        let (notify_tx, mut notify_rx) = tokio::sync::mpsc::channel(1024);
        let generic_tx = notify_tx.clone();
        let mut watcher = RecommendedWatcher::new(
            move |result: notify::Result<notify::Event>| {
                if generic_tx.try_send(result).is_err() {
                    crate::telemetry::metrics::metrics()
                        .event_dropped(crate::telemetry::DropReason::UserspaceChannelFull);
                }
            },
            notify::Config::default(),
        )?;
        // Fixed detection handles must survive live generic scope changes,
        // even when both scopes contain the same path.
        let detection_tx = notify_tx.clone();
        let mut detection_watcher = RecommendedWatcher::new(
            move |result: notify::Result<notify::Event>| {
                if detection_tx.try_send(result).is_err() {
                    crate::telemetry::metrics::metrics()
                        .event_dropped(crate::telemetry::DropReason::UserspaceChannelFull);
                }
            },
            notify::Config::default(),
        )?;
        let defaults = AgentConfig::default();
        let mut watched: Vec<PathBuf> = Vec::new();

        // Named-detection roots are fixed for the process lifetime. A missing
        // root (no backup folder on this host) is normal and silent.
        let started = std::time::Instant::now();
        let detect = detection_roots();
        let mut roots = Roots::default();
        let mut register = |path: &PathBuf, mode: RecursiveMode, into: &mut Vec<String>| {
            if !path.exists() {
                return;
            }
            match detection_watcher.watch(path, mode) {
                Ok(()) => into.push(fs_plan::normalise_root(&path.to_string_lossy())),
                Err(e) => {
                    tracing::warn!(path = %path.display(), error = %e, "Windows detection watch unavailable")
                }
            }
        };
        for p in &detect.ransom {
            register(p, RecursiveMode::Recursive, &mut roots.ransom);
        }
        for p in &detect.backup {
            register(p, RecursiveMode::Recursive, &mut roots.backup);
        }
        let mut tamper_watches = TamperWatches::new(&detect.tamper, notify_tx)?;
        roots.tamper = tamper_watches.scope.clone();
        let mut planner = Planner::new(roots, std::time::Instant::now());
        let baseline_path = crate::paths::state_dir().join("windows_fim_baseline.json");
        let saved: Baseline = std::fs::metadata(&baseline_path)
            .ok()
            .filter(|m| m.len() <= 8 * 1024 * 1024)
            .and_then(|_| std::fs::read(&baseline_path).ok())
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default();
        let mut baseline = saved.files;
        let mut last_scan = std::time::Instant::now();
        let mut first = true;
        let mut previous_scan_paths = saved.paths;
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(5));
        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    let cfg = self.config.read().map(|c| c.clone()).unwrap_or_default();
                    let roots = windows_paths(&cfg.fs_watch_paths, &defaults.fs_watch_paths);
                    if roots != watched {
                        for root in &watched { let _ = watcher.unwatch(root); }
                        watched.clear();
                        for root in roots {
                            match watcher.watch(&root, RecursiveMode::Recursive) {
                                Ok(()) => watched.push(root),
                                Err(e) => tracing::warn!(path = %root.display(), error = %e, "Windows file watch unavailable"),
                            }
                        }
                        planner.set_generic_roots(
                            watched.iter().map(|p| fs_plan::normalise_root(&p.to_string_lossy())).collect(),
                        );
                    }
                    if cfg.fim_enabled && (first || last_scan.elapsed().as_secs() >= cfg.fim_interval_secs.max(10)) {
                        let roots = windows_paths(&cfg.fim_paths, &defaults.fim_paths);
                        let scanned_roots = roots.clone();
                        match tokio::task::spawn_blocking(move || scan(roots)).await? {
                            Ok(current) => {
                                // Changing the configured scope must not invent deletions.
                                if !previous_scan_paths.is_empty() && previous_scan_paths != scanned_roots { baseline.clear(); }
                                for (path, after) in &current {
                                    let before = baseline.get(path);
                                    if before == Some(after) { continue; }
                                    let operation = if before.is_some() { FilesystemOperation::Modified } else { FilesystemOperation::Created };
                                    if tx.send(event(&agent_id, &hostname, path.clone(), operation, FilesystemSource::PeriodicScan, before, Some(after))).await.is_err() { return Ok(()); }
                                }
                                for (path, before) in &baseline {
                                    if current.contains_key(path) { continue; }
                                    if tx.send(event(&agent_id, &hostname, path.clone(), FilesystemOperation::Deleted, FilesystemSource::PeriodicScan, Some(before), None)).await.is_err() { return Ok(()); }
                                }
                                baseline = current;
                                previous_scan_paths = scanned_roots;
                                let saved = Baseline { paths: previous_scan_paths.clone(), files: baseline.clone() };
                                if let Err(e) = crate::paths::write_atomic(&baseline_path, &serde_json::to_vec(&saved)?, 0o600) {
                                    tracing::warn!(error = %e, "Windows FIM baseline persistence failed");
                                }
                            }
                            Err(e) => tracing::warn!(error = %e, "Windows FIM scan incomplete; keeping prior baseline"),
                        }
                        first = false;
                        last_scan = std::time::Instant::now();
                    }
                }
                Some(result) = notify_rx.recv() => {
                    match result {
                        Ok(notification) => {
                            for (change, path) in change_for(&notification.kind, &notification.paths) {
                                tamper_watches.rearm(change, &path);
                                let path = path.to_string_lossy().into_owned();
                                let actions = planner.plan(
                                    change,
                                    &path,
                                    std::time::Instant::now(),
                                    started.elapsed(),
                                    crate::update::update_in_flight(),
                                );
                                for action in actions {
                                    let event = match action {
                                        Action::Generic { path, change } => Some(event(
                                            &agent_id, &hostname, path, operation_for(change),
                                            FilesystemSource::Realtime, None, None,
                                        )),
                                        Action::Tamper { path, action } => Some(AgentEvent::new(
                                            agent_id.clone(), hostname.clone(),
                                            EventClass::Filesystem, EventAction::AgentTamper, Severity::Critical,
                                            EventData::AgentTamper(AgentTamperData { path, action: action.to_string() }),
                                        )),
                                        Action::RansomExtension { path } => {
                                            Some(heur::suspicious_extension_event(&agent_id, &hostname, &path))
                                        }
                                        Action::BackupDeletion { path } => {
                                            Some(heur::backup_deletion_event(&agent_id, &hostname, &path))
                                        }
                                        Action::WriteRate { rate } => {
                                            Some(heur::high_write_rate_event(&agent_id, &hostname, rate as u64))
                                        }
                                        Action::EntropyCheck { path } => {
                                            // Reading the file is blocking I/O: keep it off the runtime.
                                            let probe = path.clone();
                                            let entropy = tokio::task::spawn_blocking(move || heur::file_entropy(&probe))
                                                .await
                                                .ok()
                                                .flatten();
                                            entropy
                                                .filter(|e| *e >= heur::ENTROPY_THRESHOLD)
                                                .map(|e| heur::high_entropy_event(&agent_id, &hostname, &path, e))
                                        }
                                    };
                                    if let Some(event) = event {
                                        if tx.send(event).await.is_err() { return Ok(()); }
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            crate::telemetry::metrics::metrics().collector_failed();
                            tracing::warn!(error = %e, "Windows filesystem notification failed");
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    struct TestDirectory(PathBuf);
    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    async fn expect_tamper(
        rx: &mut tokio::sync::mpsc::Receiver<notify::Result<notify::Event>>,
        watches: &mut TamperWatches,
        planner: &mut Planner,
        wanted_path: &std::path::Path,
        wanted_action: &str,
    ) {
        let expected = fs_plan::normalise(&wanted_path.to_string_lossy());
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                // Closing a deleted directory's old handle may report an
                // error. Coverage is established by the expected parent/root
                // and replacement-file events, each required below.
                let notification = match rx.recv().await.expect("watcher channel closed") {
                    Ok(notification) => notification,
                    Err(_) => continue,
                };
                for (change, path) in change_for(&notification.kind, &notification.paths) {
                    watches.rearm(change, &path);
                    let actions = planner.plan(
                        change,
                        &path.to_string_lossy(),
                        Instant::now(),
                        Duration::from_secs(3600),
                        false,
                    );
                    if actions.iter().any(|action| {
                        matches!(action,
                            Action::Tamper { path, action }
                            if fs_plan::normalise(path) == expected && *action == wanted_action
                        )
                    }) {
                        return;
                    }
                }
            }
        })
        .await
        .expect("protected path change must be reported as tamper");
    }

    #[tokio::test]
    async fn directory_replacement_rearms_tamper_watch_after_generic_unwatch() {
        let directory =
            TestDirectory(std::env::temp_dir().join(format!("trapd-fs-{}", uuid::Uuid::new_v4())));
        let config = directory.0.join("config");
        let key = config.join("command_signing.pub");
        std::fs::create_dir_all(&config).unwrap();
        std::fs::write(&key, b"original key").unwrap();
        let (tx, mut rx) = tokio::sync::mpsc::channel(64);
        let mut watches = TamperWatches::new(std::slice::from_ref(&config), tx).unwrap();
        let mut planner = Planner::new(
            Roots {
                tamper: watches.scope.clone(),
                ..Roots::default()
            },
            Instant::now(),
        );

        // Live telemetry may watch the same parent and then remove its scope.
        // Its handle must not own or remove the fixed detection watches.
        let mut generic = RecommendedWatcher::new(
            |_: notify::Result<notify::Event>| {},
            notify::Config::default(),
        )
        .unwrap();
        generic
            .watch(&directory.0, RecursiveMode::Recursive)
            .unwrap();
        generic.unwatch(&directory.0).unwrap();

        std::fs::rename(&config, directory.0.join("config-old")).unwrap();
        expect_tamper(&mut rx, &mut watches, &mut planner, &config, "delete").await;
        std::fs::create_dir(&config).unwrap();
        expect_tamper(&mut rx, &mut watches, &mut planner, &config, "create").await;
        std::fs::write(&key, b"replacement key").unwrap();
        expect_tamper(&mut rx, &mut watches, &mut planner, &key, "create").await;
        std::fs::write(&key, b"edited replacement key").unwrap();
        expect_tamper(&mut rx, &mut watches, &mut planner, &key, "modify").await;

        std::fs::remove_dir_all(&config).unwrap();
        expect_tamper(&mut rx, &mut watches, &mut planner, &config, "delete").await;
        std::fs::create_dir(&config).unwrap();
        expect_tamper(&mut rx, &mut watches, &mut planner, &config, "create").await;
        std::fs::write(&key, b"key after deletion").unwrap();
        expect_tamper(&mut rx, &mut watches, &mut planner, &key, "create").await;
    }

    #[tokio::test]
    async fn replacing_install_directory_rearms_nested_config_watch() {
        let directory =
            TestDirectory(std::env::temp_dir().join(format!("trapd-fs-{}", uuid::Uuid::new_v4())));
        let install = directory.0.join("install");
        let config = install.join("config");
        std::fs::create_dir_all(&config).unwrap();
        let (tx, mut rx) = tokio::sync::mpsc::channel(64);
        let mut watches = TamperWatches::new(&[config.clone(), install.clone()], tx).unwrap();
        let mut planner = Planner::new(
            Roots {
                tamper: watches.scope.clone(),
                ..Roots::default()
            },
            Instant::now(),
        );

        std::fs::rename(&install, directory.0.join("install-old")).unwrap();
        expect_tamper(&mut rx, &mut watches, &mut planner, &install, "delete").await;
        std::fs::create_dir_all(&config).unwrap();
        expect_tamper(&mut rx, &mut watches, &mut planner, &install, "create").await;
        let key = config.join("command_signing.pub");
        std::fs::write(&key, b"nested replacement key").unwrap();
        expect_tamper(&mut rx, &mut watches, &mut planner, &key, "create").await;
    }

    #[tokio::test]
    async fn tamper_parent_watch_filters_sibling_state_churn_before_enqueue() {
        let directory =
            TestDirectory(std::env::temp_dir().join(format!("trapd-fs-{}", uuid::Uuid::new_v4())));
        let config = directory.0.join("config");
        std::fs::create_dir_all(&config).unwrap();
        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        let _watches = TamperWatches::new(&[config], tx).unwrap();
        for i in 0..100 {
            std::fs::write(
                directory.0.join(format!("state-{i}.json")),
                b"own state write",
            )
            .unwrap();
        }
        assert!(tokio::time::timeout(Duration::from_millis(250), rx.recv())
            .await
            .is_err());
    }
}
