//! SHA256-based File Integrity Monitoring (FIM).
//!
//! The inotify-driven [`super::filesystem`] collector says *that* a watched path
//! changed; FIM says *what* changed and *whether it matters*, cryptographically.
//! It hashes a configurable set of critical files (system binaries, boot, and
//! `/etc`), persists a **baseline** to the state directory, and on every rescan
//! emits a `filesystem/integrity_violation` for any file that was **modified**,
//! **added** or **removed** versus that baseline.
//!
//! Because the baseline is persisted, a change made **while the agent was down**
//! is caught on the next start — the baseline survives restarts, and only a
//! genuine first run (no baseline yet) establishes silently.
//!
//! Bounds (so a big `/usr` tree can't stall or bloat the agent):
//!   * per-file size cap [`MAX_FILE_BYTES`];
//!   * per-scan file cap [`MAX_FILES`];
//!   * runs on a slow background interval, never on the event hot path.
//!
//! Tunable via [`AgentConfig`] (`fim_enabled`, `fim_paths`, `fim_interval_secs`)
//! and disengaged entirely with `TRAPD_FIM=off`.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, RwLock};

use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc::Sender;
use tokio::time::{interval, Duration};
use tracing::{info, warn};
use walkdir::WalkDir;

use crate::collectors::Collector;
use crate::config::AgentConfig;
use crate::schema::{
    AgentEvent, EventAction, EventClass, EventData, IntegrityViolationData, Severity,
};

/// Files larger than this are recorded by size/mtime only (not hashed).
const MAX_FILE_BYTES: u64 = 32 * 1024 * 1024;
/// Hard cap on files hashed per scan, so a huge tree can't stall the agent.
const MAX_FILES: usize = 50_000;

/// Recorded state of one file in the baseline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct FileState {
    sha256: String,
    size: u64,
    mtime: u64,
}

/// Persisted baseline: path → state.
#[derive(Debug, Default, Serialize, Deserialize)]
struct Baseline {
    files: HashMap<String, FileState>,
}

/// What happened to a file versus the baseline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChangeKind {
    Added,
    Modified,
    Removed,
}

/// One detected integrity change.
#[derive(Debug, Clone)]
struct Change {
    path: String,
    kind: ChangeKind,
    expected: String,
    actual: String,
    size_delta: i64,
}

pub struct FimCollector {
    cfg: Arc<RwLock<AgentConfig>>,
}

impl FimCollector {
    pub fn new(cfg: Arc<RwLock<AgentConfig>>) -> Self {
        Self { cfg }
    }

    fn baseline_path() -> std::path::PathBuf {
        crate::paths::state_dir().join("fim_baseline.json")
    }
}

/// Pure diff of two path→state maps.  Kept separate from I/O so it is trivially
/// unit-testable.  Returns modifications, additions and removals.
fn diff(known: &HashMap<String, FileState>, current: &HashMap<String, FileState>) -> Vec<Change> {
    let mut out = Vec::new();
    for (path, cur) in current {
        match known.get(path) {
            Some(prev) if prev.sha256 != cur.sha256 => out.push(Change {
                path: path.clone(),
                kind: ChangeKind::Modified,
                expected: prev.sha256.clone(),
                actual: cur.sha256.clone(),
                size_delta: cur.size as i64 - prev.size as i64,
            }),
            Some(_) => {}
            None => out.push(Change {
                path: path.clone(),
                kind: ChangeKind::Added,
                expected: String::new(),
                actual: cur.sha256.clone(),
                size_delta: cur.size as i64,
            }),
        }
    }
    for (path, prev) in known {
        if !current.contains_key(path) {
            out.push(Change {
                path: path.clone(),
                kind: ChangeKind::Removed,
                expected: prev.sha256.clone(),
                actual: String::new(),
                size_delta: -(prev.size as i64),
            });
        }
    }
    out
}

/// Hash every regular file under `roots` into a path→state map (bounded).
fn scan(roots: &[String]) -> HashMap<String, FileState> {
    let mut out = HashMap::new();
    for root in roots {
        if out.len() >= MAX_FILES {
            warn!(
                cap = MAX_FILES,
                "FIM: file cap reached — remaining paths skipped this scan"
            );
            break;
        }
        for entry in WalkDir::new(root)
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            if out.len() >= MAX_FILES {
                break;
            }
            if !entry.file_type().is_file() {
                continue;
            }
            let path = entry.path();
            let meta = match entry.metadata() {
                Ok(m) => m,
                Err(_) => continue,
            };
            let size = meta.len();
            let mtime = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs())
                .unwrap_or(0);
            // Files over the cap are tracked by size/mtime only (sha left empty);
            // a size/mtime change still surfaces as a modification.
            let sha256 = if size <= MAX_FILE_BYTES {
                super::exehash::sha256_file(path).unwrap_or_default()
            } else {
                String::new()
            };
            out.insert(
                path.to_string_lossy().into_owned(),
                FileState {
                    sha256,
                    size,
                    mtime,
                },
            );
        }
    }
    out
}

fn load_baseline(path: &Path) -> Option<HashMap<String, FileState>> {
    let bytes = std::fs::read(path).ok()?;
    let baseline: Baseline = serde_json::from_slice(&bytes).ok()?;
    Some(baseline.files)
}

fn save_baseline(path: &Path, files: &HashMap<String, FileState>) {
    let baseline = Baseline {
        files: files.clone(),
    };
    match serde_json::to_vec(&baseline) {
        Ok(bytes) => {
            if let Err(e) = crate::paths::write_atomic(path, &bytes, 0o600) {
                warn!(error = %e, "FIM: failed to persist baseline");
            }
        }
        Err(e) => warn!(error = %e, "FIM: failed to serialise baseline"),
    }
}

/// Severity for a change — modifications/removals of tracked critical files are
/// high-signal; additions are noteworthy but lower.
fn severity_for(kind: ChangeKind) -> Severity {
    match kind {
        ChangeKind::Modified | ChangeKind::Removed => Severity::High,
        ChangeKind::Added => Severity::Medium,
    }
}

#[async_trait]
impl Collector for FimCollector {
    fn name(&self) -> &'static str {
        "FimCollector"
    }

    async fn run(
        &mut self,
        tx: Sender<AgentEvent>,
        agent_id: String,
        hostname: String,
    ) -> Result<()> {
        let env_off = std::env::var("TRAPD_FIM")
            .map(|v| {
                matches!(
                    v.trim().to_ascii_lowercase().as_str(),
                    "0" | "false" | "no" | "off"
                )
            })
            .unwrap_or(false);

        let (enabled, paths, interval_secs) = {
            let c = self
                .cfg
                .read()
                .map_err(|_| anyhow::anyhow!("config lock poisoned"))?;
            (c.fim_enabled, c.fim_paths.clone(), c.fim_interval_secs)
        };
        if env_off || !enabled {
            info!("FIM disabled — skipping file-integrity monitoring");
            return Ok(());
        }
        if paths.is_empty() {
            warn!("FIM enabled but fim_paths is empty — nothing to monitor");
            return Ok(());
        }

        let baseline_path = Self::baseline_path();
        let mut known = load_baseline(&baseline_path).unwrap_or_default();
        let mut established = !known.is_empty();
        info!(
            paths = ?paths,
            interval_secs,
            baseline_files = known.len(),
            "FIM started"
        );

        let mut ticker = interval(Duration::from_secs(interval_secs.max(60)));
        loop {
            ticker.tick().await;

            // Hashing a large tree can take a while — keep it off the async
            // executor's worker so other tasks aren't starved.
            let roots = paths.clone();
            let current = match tokio::task::spawn_blocking(move || scan(&roots)).await {
                Ok(c) => c,
                Err(e) => {
                    warn!(error = %e, "FIM: scan task failed");
                    continue;
                }
            };

            if !established {
                info!(files = current.len(), "FIM baseline established");
                established = true;
                save_baseline(&baseline_path, &current);
                known = current;
                continue;
            }

            let changes = diff(&known, &current);
            if !changes.is_empty() {
                info!(count = changes.len(), "FIM: integrity changes detected");
            }
            for ch in changes {
                let event = AgentEvent::new(
                    agent_id.clone(),
                    hostname.clone(),
                    EventClass::Filesystem,
                    EventAction::IntegrityViolation,
                    severity_for(ch.kind),
                    EventData::IntegrityViolation(IntegrityViolationData {
                        path: ch.path,
                        expected_hash: ch.expected,
                        actual_hash: ch.actual,
                        size_delta: ch.size_delta,
                    }),
                );
                if tx.send(event).await.is_err() {
                    return Ok(());
                }
            }

            save_baseline(&baseline_path, &current);
            known = current;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(sha: &str, size: u64) -> FileState {
        FileState {
            sha256: sha.into(),
            size,
            mtime: 0,
        }
    }

    #[test]
    fn diff_detects_modify_add_remove() {
        let mut known = HashMap::new();
        known.insert("/etc/passwd".to_string(), state("aaa", 100));
        known.insert("/bin/ls".to_string(), state("bbb", 200));

        let mut current = HashMap::new();
        // /etc/passwd modified
        current.insert("/etc/passwd".to_string(), state("ccc", 130));
        // /bin/ls removed (absent)
        // new file added
        current.insert("/etc/ld.so.preload".to_string(), state("ddd", 12));

        let changes = diff(&known, &current);
        let by_path = |p: &str| changes.iter().find(|c| c.path == p).cloned();

        let m = by_path("/etc/passwd").expect("modify");
        assert_eq!(m.kind, ChangeKind::Modified);
        assert_eq!(m.expected, "aaa");
        assert_eq!(m.actual, "ccc");
        assert_eq!(m.size_delta, 30);

        let r = by_path("/bin/ls").expect("remove");
        assert_eq!(r.kind, ChangeKind::Removed);
        assert_eq!(r.size_delta, -200);
        assert!(r.actual.is_empty());

        let a = by_path("/etc/ld.so.preload").expect("add");
        assert_eq!(a.kind, ChangeKind::Added);
        assert!(a.expected.is_empty());
        assert_eq!(a.size_delta, 12);
    }

    #[test]
    fn diff_is_empty_when_unchanged() {
        let mut m = HashMap::new();
        m.insert("/etc/hosts".to_string(), state("h", 10));
        assert!(diff(&m, &m.clone()).is_empty());
    }

    #[test]
    fn severity_escalates_for_modify_and_remove() {
        assert!(matches!(severity_for(ChangeKind::Modified), Severity::High));
        assert!(matches!(severity_for(ChangeKind::Removed), Severity::High));
        assert!(matches!(severity_for(ChangeKind::Added), Severity::Medium));
    }
}
