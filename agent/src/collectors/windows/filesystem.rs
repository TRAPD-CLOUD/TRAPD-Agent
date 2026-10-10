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

use crate::collectors::critical_file as critical;
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
            integrity: if realtime && before.is_none() && after.is_none() {
                IntegrityStatus::NotChecked
            } else if violation {
                IntegrityStatus::Violation
            } else {
                IntegrityStatus::BaselineAdded
            },
            expected_hash: before.map(|f| f.sha256.clone()),
            actual_hash: after.map(|f| f.sha256.clone()),
            size_delta: before.map(|f| after.map(|a| a.size as i64).unwrap_or(0) - f.size as i64),
            actor: None,
            change_summary: None,
        }),
    )
}

/// A real-time event for a path whose content is tracked (the hosts file):
/// hashes before/after, the added/removed lines, and the integrity verdict.
/// Unchanged content (an attribute touch) stays plain telemetry.
fn checked_event(
    agent_id: &str,
    hostname: &str,
    path: String,
    operation: FilesystemOperation,
    verdict: &critical::Verdict,
    before: Option<&critical::Snapshot>,
    after: Option<&critical::Snapshot>,
) -> AgentEvent {
    let fp = |s: &critical::Snapshot| Fingerprint {
        sha256: s.sha256.clone(),
        size: s.size,
    };
    let (b, a) = (before.map(fp), after.map(fp));
    let changed = matches!(verdict, critical::Verdict::Changed { .. });
    let mut ev = event(
        agent_id,
        hostname,
        path,
        operation,
        FilesystemSource::Realtime,
        b.as_ref().filter(|_| changed),
        a.as_ref().filter(|_| changed),
    );
    if let EventData::Filesystem(d) = &mut ev.data {
        if let critical::Verdict::Changed { summary, .. } = verdict {
            // A content verdict takes precedence over the notification kind:
            // atomic replacement arrives as Created (RenamedTo).
            ev.severity = Severity::High;
            d.integrity = IntegrityStatus::Violation;
            d.change_summary = summary.clone();
        } else {
            // Not a content change: report the hash we saw, flag nothing.
            d.actual_hash = a.map(|f| f.sha256);
        }
    }
    ev
}

/// Attach the best-effort actor (a process whose command line named the file).
fn with_actor(mut ev: AgentEvent, path: &str) -> AgentEvent {
    if let (EventData::Filesystem(d), Some(m)) = (
        &mut ev.data,
        crate::detection::accessor_correlation::attribute(path),
    ) {
        d.actor = Some(m.lineage);
    }
    ev
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

type Notification = notify::Result<Vec<(Change, PathBuf)>>;

/// Split rename pairs before filtering so an out-of-scope half cannot change
/// the meaning of the other. Filter parent/sibling churn before the queue.
fn enqueue_relevant(
    result: notify::Result<notify::Event>,
    tx: &Sender<Notification>,
    relevant: impl Fn(&str) -> bool,
) {
    let result = result.map(|event| {
        let mut changes = change_for(&event.kind, &event.paths);
        changes.retain(|(_, path)| relevant(&fs_plan::normalise(&path.to_string_lossy())));
        changes
    });
    if result.as_ref().is_ok_and(Vec::is_empty) {
        return;
    }
    if tx.try_send(result).is_err() {
        crate::telemetry::metrics::metrics()
            .event_dropped(crate::telemetry::DropReason::UserspaceChannelFull);
    }
}

fn relevant_path(path: &str, roots: &Roots) -> bool {
    fs_plan::is_tamper_path(path, &roots.tamper)
        || roots
            .generic
            .iter()
            .chain(&roots.ransom)
            .chain(&roots.backup)
            .any(|root| path == root.trim_end_matches('\\') || path.starts_with(root))
}

/// One physical handle union for independent logical scopes. A recursive
/// ancestor serves overlapping telemetry/detection paths once; nonrecursive
/// fixed parents observe root replacement without watching unrelated trees.
struct FilesystemWatches {
    watcher: RecommendedWatcher,
    scope: Arc<RwLock<Roots>>,
    recursive_targets: Vec<PathBuf>,
    tamper_targets: Vec<PathBuf>,
    generic: Vec<PathBuf>,
    watched: BTreeMap<String, (PathBuf, RecursiveMode)>,
    #[cfg(test)]
    fail_watch: Option<String>,
}

impl FilesystemWatches {
    fn new(
        ransom: &[PathBuf],
        backup: &[PathBuf],
        tamper: &[PathBuf],
        tx: Sender<Notification>,
    ) -> Result<Self> {
        let normalised = |paths: &[PathBuf]| {
            paths
                .iter()
                .map(|p| fs_plan::normalise_root(&p.to_string_lossy()))
                .collect()
        };
        let scope = Arc::new(RwLock::new(Roots {
            ransom: normalised(ransom),
            backup: normalised(backup),
            tamper: normalised(tamper),
            ..Default::default()
        }));
        let filter = Arc::clone(&scope);
        let watcher = RecommendedWatcher::new(
            move |result: notify::Result<notify::Event>| {
                enqueue_relevant(result, &tx, |path| {
                    filter.read().is_ok_and(|roots| relevant_path(path, &roots))
                });
            },
            notify::Config::default(),
        )?;
        let mut watches = Self {
            watcher,
            scope,
            recursive_targets: ransom.iter().chain(backup).cloned().collect(),
            tamper_targets: tamper.to_vec(),
            generic: Vec::new(),
            watched: BTreeMap::new(),
            #[cfg(test)]
            fail_watch: None,
        };
        watches.sync();
        Ok(watches)
    }

    fn set_generic(&mut self, paths: Vec<PathBuf>) {
        self.generic = paths;
        if let Ok(mut roots) = self.scope.write() {
            roots.generic = self
                .generic
                .iter()
                .map(|p| fs_plan::normalise_root(&p.to_string_lossy()))
                .collect();
        }
        self.sync();
    }

    fn sync(&mut self) {
        let mut candidates: BTreeMap<String, (PathBuf, RecursiveMode)> = BTreeMap::new();
        let mut add = |path: &std::path::Path, mode: RecursiveMode| {
            if !path.is_dir() {
                return;
            }
            let key = fs_plan::normalise_root(&path.to_string_lossy());
            candidates
                .entry(key)
                .and_modify(|(_, existing)| {
                    if mode == RecursiveMode::Recursive {
                        *existing = mode;
                    }
                })
                .or_insert((path.to_path_buf(), mode));
        };
        for target in self.recursive_targets.iter().chain(&self.tamper_targets) {
            if let Some(parent) = target.parent() {
                add(parent, RecursiveMode::NonRecursive);
            }
        }
        for target in self.recursive_targets.iter().chain(&self.generic) {
            add(target, RecursiveMode::Recursive);
        }
        for target in &self.tamper_targets {
            add(target, RecursiveMode::NonRecursive);
        }
        let mut candidates: Vec<_> = candidates.into_iter().collect();
        candidates.sort_by_key(|(_, (path, _))| path.components().count());
        let mut required: BTreeMap<String, (PathBuf, RecursiveMode)> = BTreeMap::new();
        let mut failed = Vec::new();
        for (key, (path, mode)) in candidates {
            if required
                .iter()
                .any(|(root, (_, mode))| *mode == RecursiveMode::Recursive && key.starts_with(root))
            {
                continue;
            }
            if self.ensure_watch(&key, &path, mode) {
                required.insert(key, (path, mode));
            } else {
                failed.push(key.clone());
                // A failed recursive upgrade can still retain its previous
                // nonrecursive parent handle; descendants must still be tried.
                if let Some(existing) = self.watched.get(&key) {
                    required.insert(key, existing.clone());
                }
            }
        }
        // If a direct replacement handle fails, keep the working recursive
        // ancestor that still supplies it. Logical filtering already excludes
        // removed telemetry scope; retry can narrow physical coverage later.
        for (root, existing) in &self.watched {
            if existing.1 == RecursiveMode::Recursive
                && failed.iter().any(|path| path.starts_with(root))
            {
                required.insert(root.clone(), existing.clone());
            }
        }
        let recursive: Vec<_> = required
            .iter()
            .filter(|(_, (_, mode))| *mode == RecursiveMode::Recursive)
            .map(|(root, _)| root.clone())
            .collect();
        required.retain(|key, _| {
            !recursive
                .iter()
                .any(|root| root != key && key.starts_with(root))
        });
        // New fixed descendant handles are installed before retiring an old
        // generic ancestor. Fixed detection must not have a reconfiguration gap.
        let obsolete: Vec<_> = self
            .watched
            .keys()
            .filter(|key| !required.contains_key(*key))
            .cloned()
            .collect();
        for key in obsolete {
            if let Some((path, _)) = self.watched.remove(&key) {
                let _ = self.watcher.unwatch(&path);
            }
        }
        // A broad generic handle may now only be needed as a fixed parent.
        // Downgrade after its required child watches have been established.
        for (key, (path, mode)) in required {
            if mode == RecursiveMode::NonRecursive
                && self
                    .watched
                    .get(&key)
                    .is_some_and(|(_, actual)| *actual == RecursiveMode::Recursive)
            {
                self.replace_watch(&key, &path, mode);
            }
        }
    }

    fn ensure_watch(&mut self, key: &str, path: &std::path::Path, mode: RecursiveMode) -> bool {
        if self
            .watched
            .get(key)
            .is_some_and(|(_, actual)| *actual == mode || *actual == RecursiveMode::Recursive)
        {
            return true;
        }
        self.replace_watch(key, path, mode)
    }

    fn replace_watch(&mut self, key: &str, path: &std::path::Path, mode: RecursiveMode) -> bool {
        #[cfg(test)]
        if self.fail_watch.as_deref() == Some(key) {
            return false;
        }
        // Never hold the callback's scope lock across native watch/unwatch:
        // watch waits for a worker that can invoke that callback before its ack.
        let previous = self.watched.remove(key);
        if let Some((old, _)) = &previous {
            let _ = self.watcher.unwatch(old);
        }
        match self.watcher.watch(path, mode) {
            Ok(()) => {
                self.watched.insert(key.into(), (path.to_path_buf(), mode));
                true
            }
            Err(e) => {
                tracing::warn!(path = %path.display(), error = %e, "Windows filesystem watch unavailable");
                if let Some((old, old_mode)) = previous {
                    if self.watcher.watch(&old, old_mode).is_ok() {
                        self.watched.insert(key.into(), (old, old_mode));
                    }
                }
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
        if !self
            .recursive_targets
            .iter()
            .chain(&self.tamper_targets)
            .chain(&self.generic)
            .any(|target| fs_plan::normalise_root(&target.to_string_lossy()).starts_with(&key))
        {
            return;
        }
        let stale: Vec<_> = self
            .watched
            .keys()
            .filter(|root| root.starts_with(&key))
            .cloned()
            .collect();
        for root in stale {
            if let Some((path, _)) = self.watched.remove(&root) {
                let _ = self.watcher.unwatch(&path);
            }
        }
        self.sync();
    }
}

/// Files whose content is tracked: the hosts file under the real system root.
fn critical_files() -> Vec<PathBuf> {
    vec![
        PathBuf::from(std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into()))
            .join("System32\\drivers\\etc\\hosts"),
    ]
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
        let detect = detection_roots();
        let mut watches =
            FilesystemWatches::new(&detect.ransom, &detect.backup, &detect.tamper, notify_tx)?;
        let mut planner = Planner::new(
            watches.scope.read().unwrap().clone(),
            std::time::Instant::now(),
        );
        let defaults = AgentConfig::default();
        // Last known content of the tracked critical files (the hosts file).
        // Seeded now so the first change is a diff, not a "baseline".
        let mut critical_state: BTreeMap<String, critical::Snapshot> = BTreeMap::new();
        for file in critical_files() {
            let key = fs_plan::normalise(&file.to_string_lossy());
            if let Some(snap) = critical::read_snapshot(&file, critical::is_diffable(&key)) {
                critical_state.insert(key, snap);
            }
        }
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
                    if roots != watches.generic {
                        watches.set_generic(roots);
                        planner.set_generic_roots(watches.scope.read().unwrap().generic.clone());
                    } else {
                        // Retry missing/denied paths even without a config
                        // change (the generic target can be created later).
                        watches.sync();
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
                        Ok(changes) => {
                            for (change, path) in changes {
                                watches.rearm(change, &path);
                                let path = path.to_string_lossy().into_owned();
                                let actions = planner.plan(
                                    change,
                                    &path,
                                    std::time::Instant::now(),
                                );
                                for action in actions {
                                    let event = match action {
                                        Action::Generic { path, change } => {
                                            let key = fs_plan::normalise(&path);
                                            if critical::is_hosts_file(&key) && change != Change::Deleted {
                                                // Content check: what changed in the hosts file?
                                                let probe = PathBuf::from(&path);
                                                let keep = critical::is_diffable(&key);
                                                let after = tokio::task::spawn_blocking(move || critical::read_snapshot(&probe, keep))
                                                    .await
                                                    .ok()
                                                    .flatten();
                                                let ev = match after {
                                                    Some(after) => {
                                                        let before = critical_state.get(&key);
                                                        let verdict = critical::compare(before, &after);
                                                        let ev = checked_event(
                                                            &agent_id, &hostname, path.clone(),
                                                            operation_for(change), &verdict, before, Some(&after),
                                                        );
                                                        critical_state.insert(key, after);
                                                        ev
                                                    }
                                                    None => event(
                                                        &agent_id, &hostname, path.clone(), operation_for(change),
                                                        FilesystemSource::Realtime, None, None,
                                                    ),
                                                };
                                                Some(with_actor(ev, &path))
                                            } else {
                                                let ev = event(
                                                    &agent_id, &hostname, path.clone(), operation_for(change),
                                                    FilesystemSource::Realtime, None, None,
                                                );
                                                Some(with_actor(ev, &path))
                                            }
                                        }
                                        Action::Tamper { path, action } => Some(AgentEvent::new(
                                            agent_id.clone(), hostname.clone(),
                                            EventClass::Filesystem, EventAction::AgentTamper, Severity::Critical,
                                            EventData::AgentTamper(AgentTamperData { path, action: action.to_string() }),
                                        )),
                                        Action::RansomExtension { path } => {
                                            Some(heur::suspicious_extension_event(&agent_id, &hostname, &path))
                                        }
                                        Action::RansomBurst { count } => {
                                            Some(heur::rename_burst_event(&agent_id, &hostname, count))
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

    #[test]
    fn changed_hosts_replacement_is_an_integrity_violation() {
        let before = critical::snapshot_of(b"127.0.0.1 localhost\n", true);
        let after = critical::snapshot_of(b"127.0.0.1 localhost\n203.0.113.1 bank.example\n", true);
        let verdict = critical::compare(Some(&before), &after);
        let operation = operation_for(Change::RenamedTo);
        assert_eq!(operation, FilesystemOperation::Created);
        let ev = checked_event(
            "agent",
            "host",
            "C:\\Windows\\System32\\drivers\\etc\\hosts".into(),
            operation,
            &verdict,
            Some(&before),
            Some(&after),
        );
        assert_eq!(ev.severity, Severity::High);
        assert!(matches!(ev.action, EventAction::Create));
        let EventData::Filesystem(data) = ev.data else {
            panic!("expected filesystem event")
        };
        assert_eq!(data.integrity, IntegrityStatus::Violation);
        assert_eq!(data.expected_hash.as_deref(), Some(before.sha256.as_str()));
        assert_eq!(data.actual_hash.as_deref(), Some(after.sha256.as_str()));
        assert_eq!(data.size_delta, Some(25));
        assert!(data
            .change_summary
            .unwrap()
            .contains("203.0.113.1 bank.example"));
    }

    #[test]
    fn unchanged_hosts_replacement_and_first_creation_are_informational() {
        let snapshot = critical::snapshot_of(b"127.0.0.1 localhost\n", true);
        for before in [Some(&snapshot), None] {
            let verdict = critical::compare(before, &snapshot);
            let ev = checked_event(
                "agent",
                "host",
                "hosts".into(),
                FilesystemOperation::Created,
                &verdict,
                before,
                Some(&snapshot),
            );
            assert_eq!(ev.severity, Severity::Info);
            let EventData::Filesystem(data) = ev.data else {
                panic!("expected filesystem event")
            };
            assert_ne!(data.integrity, IntegrityStatus::Violation);
            assert_eq!(data.actual_hash.as_deref(), Some(snapshot.sha256.as_str()));
            assert!(data.change_summary.is_none());
        }
    }

    struct TestDirectory(PathBuf);
    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[tokio::test]
    async fn repeated_real_notifications_are_not_time_coalesced() {
        use notify::event::CreateKind;
        let path = PathBuf::from("C:\\Users\\Public\\Documents\\report.locked");
        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        let roots = Roots {
            ransom: vec![fs_plan::normalise_root("C:\\Users")],
            ..Default::default()
        };
        let mut planner = Planner::new(roots.clone(), Instant::now());
        for _ in 0..2 {
            let event =
                notify::Event::new(EventKind::Create(CreateKind::File)).add_path(path.clone());
            enqueue_relevant(Ok(event), &tx, |p| relevant_path(p, &roots));
            let changes = rx.try_recv().unwrap().unwrap();
            assert_eq!(changes, vec![(Change::Created, path.clone())]);
            let actions = planner.plan(Change::Created, &path.to_string_lossy(), Instant::now());
            assert_eq!(
                actions
                    .iter()
                    .filter(|a| matches!(a, Action::RansomExtension { .. }))
                    .count(),
                1
            );
        }
    }

    #[tokio::test]
    async fn scope_filter_preserves_rename_halves_and_rejects_nested_tamper_siblings() {
        let from = PathBuf::from("D:\\Agent\\nested\\config\\binary.sig");
        let to = PathBuf::from("D:\\Agent\\nested\\state.json");
        let roots = Roots {
            tamper: vec![
                fs_plan::normalise_root("D:\\Agent"),
                fs_plan::normalise_root("D:\\Agent\\nested\\config"),
            ],
            ..Default::default()
        };
        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        let event = notify::Event::new(EventKind::Modify(ModifyKind::Name(RenameMode::Both)))
            .add_path(from.clone())
            .add_path(to.clone());
        enqueue_relevant(Ok(event), &tx, |p| relevant_path(p, &roots));
        assert_eq!(
            rx.try_recv().unwrap().unwrap(),
            vec![(Change::RenamedFrom, from)]
        );
        let event = notify::Event::new(EventKind::Modify(ModifyKind::Name(RenameMode::Both)))
            .add_path(to)
            .add_path(PathBuf::from("D:\\Agent\\nested\\config\\binary.sha256"));
        enqueue_relevant(Ok(event), &tx, |p| relevant_path(p, &roots));
        assert_eq!(
            rx.try_recv().unwrap().unwrap(),
            vec![(
                Change::RenamedTo,
                PathBuf::from("D:\\Agent\\nested\\config\\binary.sha256")
            )]
        );
    }

    async fn ransom_count(
        rx: &mut tokio::sync::mpsc::Receiver<Notification>,
        watches: &mut FilesystemWatches,
        planner: &mut Planner,
    ) -> usize {
        tokio::time::timeout(Duration::from_secs(10), async {
            let mut count = 0;
            loop {
                let received = if count == 0 {
                    rx.recv().await
                } else {
                    match tokio::time::timeout(Duration::from_millis(250), rx.recv()).await {
                        Ok(received) => received,
                        Err(_) => return count,
                    }
                };
                let changes = match received.expect("watcher channel closed") {
                    Ok(changes) => changes,
                    Err(_) => continue,
                };
                for (change, path) in changes {
                    watches.rearm(change, &path);
                    count += planner
                        .plan(change, &path.to_string_lossy(), Instant::now())
                        .iter()
                        .filter(|action| matches!(action, Action::RansomExtension { .. }))
                        .count();
                }
            }
        })
        .await
        .expect("ransomware change must reach the planner")
    }

    #[tokio::test]
    async fn overlapping_native_watchers_emit_one_alarm_per_real_file_creation() {
        let directory =
            TestDirectory(std::env::temp_dir().join(format!("trapd-fs-{}", uuid::Uuid::new_v4())));
        let profile = directory.0.join("Users");
        let generic_root = profile.join("Public\\Documents");
        std::fs::create_dir_all(&generic_root).unwrap();
        let (tx, mut rx) = tokio::sync::mpsc::channel(64);
        let mut fixed =
            FilesystemWatches::new(std::slice::from_ref(&profile), &[], &[], tx).unwrap();
        fixed.set_generic(vec![generic_root.clone()]);
        assert!(
            !fixed
                .watched
                .contains_key(&fs_plan::normalise_root(&generic_root.to_string_lossy())),
            "the existing recursive ancestor must serve both scopes"
        );
        let mut planner = Planner::new(
            Roots {
                ransom: fixed.scope.read().unwrap().ransom.clone(),
                generic: vec![fs_plan::normalise_root(&generic_root.to_string_lossy())],
                ..Default::default()
            },
            Instant::now(),
        );
        let file = generic_root.join("report.locked");
        std::fs::write(&file, b"first creation").unwrap();
        assert_eq!(ransom_count(&mut rx, &mut fixed, &mut planner).await, 1);
        std::fs::remove_file(&file).unwrap();
        std::fs::write(&file, b"second real creation").unwrap();
        assert_eq!(ransom_count(&mut rx, &mut fixed, &mut planner).await, 1);
    }

    #[tokio::test]
    async fn recursive_fixed_scope_survives_root_replacement_under_shared_parent_handle() {
        let directory =
            TestDirectory(std::env::temp_dir().join(format!("trapd-fs-{}", uuid::Uuid::new_v4())));
        let profile = directory.0.join("profile");
        std::fs::create_dir_all(&profile).unwrap();
        let (tx, mut rx) = tokio::sync::mpsc::channel(64);
        let mut fixed =
            FilesystemWatches::new(std::slice::from_ref(&profile), &[], &[], tx).unwrap();
        fixed.set_generic(vec![directory.0.clone()]);
        let mut planner = Planner::new(
            Roots {
                ransom: fixed.scope.read().unwrap().ransom.clone(),
                generic: vec![fs_plan::normalise_root(&directory.0.to_string_lossy())],
                ..Default::default()
            },
            Instant::now(),
        );
        std::fs::rename(&profile, directory.0.join("profile-old")).unwrap();
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let Ok(changes) = rx.recv().await.unwrap() else {
                    continue;
                };
                let removed = changes
                    .iter()
                    .any(|(change, path)| *change == Change::RenamedFrom && path == &profile);
                for (change, path) in changes {
                    fixed.rearm(change, &path);
                }
                if removed {
                    break;
                }
            }
        })
        .await
        .expect("root rename must invalidate and close the old watch");
        std::fs::create_dir(&profile).unwrap();
        // The shared recursive ancestor supplies this change even before
        // the recreated fixed root's notification has been consumed.
        std::fs::write(profile.join("during-replacement.locked"), b"replacement").unwrap();
        assert_eq!(ransom_count(&mut rx, &mut fixed, &mut planner).await, 1);
        std::fs::write(profile.join("after-rearm.locked"), b"later").unwrap();
        assert_eq!(ransom_count(&mut rx, &mut fixed, &mut planner).await, 1);
        fixed.set_generic(Vec::new());
        planner.set_generic_roots(Vec::new());
        std::fs::write(
            profile.join("after-generic-removal.locked"),
            b"still monitored",
        )
        .unwrap();
        assert_eq!(ransom_count(&mut rx, &mut fixed, &mut planner).await, 1);
    }

    #[tokio::test]
    async fn failed_fixed_child_migration_keeps_working_recursive_ancestor() {
        let directory =
            TestDirectory(std::env::temp_dir().join(format!("trapd-fs-{}", uuid::Uuid::new_v4())));
        let config = directory.0.join("config");
        std::fs::create_dir_all(&config).unwrap();
        let (tx, mut rx) = tokio::sync::mpsc::channel(64);
        let mut watches =
            FilesystemWatches::new(&[], &[], std::slice::from_ref(&config), tx).unwrap();
        watches.set_generic(vec![directory.0.clone()]);
        let parent_key = fs_plan::normalise_root(&directory.0.to_string_lossy());
        let config_key = fs_plan::normalise_root(&config.to_string_lossy());
        assert!(!watches.watched.contains_key(&config_key));
        watches.fail_watch = Some(config_key.clone());
        watches.set_generic(Vec::new());
        assert_eq!(
            watches.watched.get(&parent_key).unwrap().1,
            RecursiveMode::Recursive
        );
        let mut planner = Planner::new(watches.scope.read().unwrap().clone(), Instant::now());
        let key = config.join("command_signing.pub");
        std::fs::write(&key, b"while direct handle is unavailable").unwrap();
        expect_tamper(&mut rx, &mut watches, &mut planner, &key, "create").await;
        watches.fail_watch = None;
        watches.sync();
        assert_eq!(
            watches.watched.get(&parent_key).unwrap().1,
            RecursiveMode::NonRecursive
        );
        assert!(watches.watched.contains_key(&config_key));
        std::fs::write(&key, b"after retry recovered").unwrap();
        expect_tamper(&mut rx, &mut watches, &mut planner, &key, "modify").await;
    }

    #[tokio::test]
    async fn initially_missing_generic_roots_can_be_retried_without_config_changes() {
        let directory =
            TestDirectory(std::env::temp_dir().join(format!("trapd-fs-{}", uuid::Uuid::new_v4())));
        let target = directory.0.join("created-later");
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        let mut watches = FilesystemWatches::new(&[], &[], &[], tx).unwrap();
        watches.set_generic(vec![target.clone()]);
        let key = fs_plan::normalise_root(&target.to_string_lossy());
        assert!(!watches.watched.contains_key(&key));
        std::fs::create_dir_all(&target).unwrap();
        watches.sync();
        assert!(watches.watched.contains_key(&key));
        let file = target.join("observed.txt");
        std::fs::write(&file, b"newly watched").unwrap();
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let Ok(changes) = rx.recv().await.unwrap() else {
                    continue;
                };
                if changes
                    .iter()
                    .any(|(change, path)| *change == Change::Created && path == &file)
                {
                    break;
                }
            }
        })
        .await
        .expect("created generic root must be monitored after retry");
    }

    #[tokio::test]
    async fn native_unsigned_staging_cannot_suppress_live_integrity_or_binary_tamper() {
        let directory =
            TestDirectory(std::env::temp_dir().join(format!("trapd-fs-{}", uuid::Uuid::new_v4())));
        std::fs::create_dir_all(&directory.0).unwrap();
        let staging = crate::update::apply::StagingPaths::new(&directory.0);
        std::fs::create_dir_all(&staging.dir).unwrap();
        std::fs::write(staging.offer(), b"unsigned invalid update marker").unwrap();
        let (tx, mut rx) = tokio::sync::mpsc::channel(64);
        let mut watches =
            FilesystemWatches::new(&[], &[], std::slice::from_ref(&directory.0), tx).unwrap();
        let mut planner = Planner::new(
            Roots {
                tamper: watches.scope.read().unwrap().tamper.clone(),
                ..Default::default()
            },
            Instant::now(),
        );
        for name in [
            "binary.sha256",
            "binary.version",
            "binary.sig",
            ".binary.sha256.tmp.42",
            "trapd-agent.exe",
        ] {
            let path = directory.0.join(name);
            std::fs::write(&path, b"foreign creation").unwrap();
            expect_tamper(&mut rx, &mut watches, &mut planner, &path, "create").await;
            std::fs::write(&path, b"foreign modification").unwrap();
            expect_tamper(&mut rx, &mut watches, &mut planner, &path, "modify").await;
            std::fs::remove_file(&path).unwrap();
            expect_tamper(&mut rx, &mut watches, &mut planner, &path, "delete").await;
        }
    }

    async fn expect_tamper(
        rx: &mut tokio::sync::mpsc::Receiver<Notification>,
        watches: &mut FilesystemWatches,
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
                for (change, path) in notification {
                    watches.rearm(change, &path);
                    let actions = planner.plan(change, &path.to_string_lossy(), Instant::now());
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
        let mut watches =
            FilesystemWatches::new(&[], &[], std::slice::from_ref(&config), tx).unwrap();
        let mut planner = Planner::new(
            Roots {
                tamper: watches.scope.read().unwrap().tamper.clone(),
                ..Roots::default()
            },
            Instant::now(),
        );

        // Removing live telemetry must retain the fixed logical scope and
        // install its child handle before downgrading the shared ancestor.
        watches.set_generic(vec![directory.0.clone()]);
        watches.set_generic(Vec::new());

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
        let mut watches =
            FilesystemWatches::new(&[], &[], &[config.clone(), install.clone()], tx).unwrap();
        let mut planner = Planner::new(
            Roots {
                tamper: watches.scope.read().unwrap().tamper.clone(),
                ..Roots::default()
            },
            Instant::now(),
        );

        // Windows rejects an ancestor rename while a descendant has an open
        // handle. Remove the nested directory first, requiring its tamper
        // event to close that old watch, before replacing the ancestor.
        std::fs::remove_dir(&config).unwrap();
        expect_tamper(&mut rx, &mut watches, &mut planner, &config, "delete").await;
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
        let _watches = FilesystemWatches::new(&[], &[], &[config], tx).unwrap();
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
