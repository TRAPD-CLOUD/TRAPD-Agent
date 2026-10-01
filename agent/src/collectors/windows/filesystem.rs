//! ReadDirectoryChangesW notifications (notify) plus bounded SHA256 FIM scans.
use std::collections::BTreeMap;
use std::io::Read;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use anyhow::{bail, Result};
use async_trait::async_trait;
use notify::{EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::mpsc::Sender;

use crate::collectors::Collector;
use crate::config::AgentConfig;
use crate::schema::{
    AgentEvent, EventAction, EventClass, EventData, FilesystemEventData, FilesystemOperation,
    FilesystemSource, IntegrityStatus, Severity,
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
        let mut watcher = RecommendedWatcher::new(
            move |result: notify::Result<notify::Event>| {
                if notify_tx.try_send(result).is_err() {
                    crate::telemetry::metrics::metrics()
                        .event_dropped(crate::telemetry::DropReason::UserspaceChannelFull);
                }
            },
            notify::Config::default(),
        )?;
        let defaults = AgentConfig::default();
        let mut watched: Vec<PathBuf> = Vec::new();
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
                            let operation = match notification.kind {
                                EventKind::Create(_) => FilesystemOperation::Created,
                                EventKind::Remove(_) => FilesystemOperation::Deleted,
                                EventKind::Modify(_) => FilesystemOperation::Modified,
                                _ => continue,
                            };
                            for path in notification.paths {
                                if tx.send(event(&agent_id, &hostname, path.to_string_lossy().into_owned(), operation, FilesystemSource::Realtime, None, None)).await.is_err() { return Ok(()); }
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
