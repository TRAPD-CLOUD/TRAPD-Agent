use std::collections::VecDeque;
use std::io::Read as IoRead;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::Result;
use async_trait::async_trait;
use inotify::{EventMask, Inotify, WatchMask};
use rusqlite::{params, Connection};
use sha2::{Digest, Sha256};
use tokio::sync::mpsc::Sender;
use tracing::{info, warn};
use walkdir::WalkDir;

use crate::collectors::Collector;
use crate::schema::{
    AgentEvent, AgentTamperData, EventAction, EventClass, EventData, FileEventData,
    IntegrityViolationData, RansomwareIndicatorData, Severity,
};

// ── Watched path groups ───────────────────────────────────────────────────────

/// Paths subject to SHA256 integrity baseline (FIM).
const FIM_PATHS: &[&str] = &[
    "/usr/bin", "/usr/sbin", "/lib", "/lib64", "/boot", "/sbin", "/root",
    "/etc", "/bin",
];

/// Paths monitored for ransomware-style mass writes / high-entropy content.
const RANSOM_WATCH_PATHS: &[&str] = &["/tmp", "/home", "/var/www", "/var/data"];

/// Deletion of files under these paths is flagged as backup sabotage.
const BACKUP_PATHS: &[&str] = &["/backup", "/var/backup", "/var/backups"];

/// Agent-owned config paths — any change is severity: critical.
const AGENT_CONFIG_PATHS: &[&str] = &["/etc/trapd"];

const WATCH_MASK: WatchMask = WatchMask::CREATE
    .union(WatchMask::DELETE)
    .union(WatchMask::MODIFY)
    .union(WatchMask::MOVED_FROM)
    .union(WatchMask::MOVED_TO);

// ── Thresholds ────────────────────────────────────────────────────────────────

/// Shannon entropy above this value (bits/byte) is treated as likely encrypted.
const ENTROPY_THRESHOLD: f64 = 7.2;

/// Maximum file size read for entropy analysis (8 MiB).
const MAX_ENTROPY_BYTES: u64 = 8 * 1024 * 1024;

/// Rebuild the SHA256 baseline if the DB is older than this many seconds (24 h).
const BASELINE_MAX_AGE_SECS: i64 = 86_400;

/// Emit a "high_write_rate" ransomware indicator after this many unique-path
/// modifications within MASS_MOD_WINDOW.
const MASS_MOD_THRESHOLD: usize = 50;
const MASS_MOD_WINDOW: Duration = Duration::from_secs(10);

/// Ransomware-associated file extension suffixes (lower-case).
const RANSOM_EXTENSIONS: &[&str] = &[
    ".locked", ".encrypted", ".crypt", ".crypted", ".crypto",
    ".enc", ".locky", ".wannacry", ".ryuk", ".maze",
    ".sodinokibi", ".revil", ".darkside", ".conti", ".lockbit",
    ".babuk", ".blackcat", ".hive", ".alphv",
];

// ── Collector struct ──────────────────────────────────────────────────────────

pub struct FilesystemCollector {
    db_path: PathBuf,
}

impl FilesystemCollector {
    pub fn new() -> Self {
        let db_path = std::env::var("HOME")
            .map(|h| PathBuf::from(h).join(".trapd").join("fim_baseline.db"))
            .unwrap_or_else(|_| PathBuf::from("/var/lib/trapd/fim_baseline.db"));
        Self { db_path }
    }
}

impl Default for FilesystemCollector {
    fn default() -> Self { Self::new() }
}

#[async_trait]
impl Collector for FilesystemCollector {
    fn name(&self) -> &'static str { "FilesystemCollector" }

    async fn run(
        &mut self,
        tx:       Sender<AgentEvent>,
        agent_id: String,
        hostname: String,
    ) -> Result<()> {
        let db_path = self.db_path.clone();
        let (fs_tx, mut fs_rx) = tokio::sync::mpsc::channel::<AgentEvent>(512);

        std::thread::spawn(move || {
            run_sync(fs_tx, agent_id, hostname, db_path);
        });

        while let Some(event) = fs_rx.recv().await {
            if tx.send(event).await.is_err() {
                return Ok(());
            }
        }
        Ok(())
    }
}

// ── Sync thread ───────────────────────────────────────────────────────────────

fn run_sync(
    tx:       tokio::sync::mpsc::Sender<AgentEvent>,
    agent_id: String,
    hostname: String,
    db_path:  PathBuf,
) {
    let conn = match open_db(&db_path) {
        Ok(c)  => c,
        Err(e) => { warn!("FilesystemCollector: SQLite init failed: {e}"); return; }
    };

    // Build or refresh the SHA256 baseline.
    let baseline_count = load_or_build_baseline(&conn);
    info!("FilesystemCollector: baseline ready — {baseline_count} files indexed");

    let mut inotify = match Inotify::init() {
        Ok(i)  => i,
        Err(e) => { warn!("FilesystemCollector: inotify init failed: {e}"); return; }
    };

    let mut wd_map: std::collections::HashMap<inotify::WatchDescriptor, &'static str> =
        std::collections::HashMap::new();

    // Combine all path groups into a single watch list (deduplicated by inotify itself).
    let all_paths: Vec<&'static str> = FIM_PATHS.iter()
        .chain(RANSOM_WATCH_PATHS.iter())
        .chain(BACKUP_PATHS.iter())
        .chain(AGENT_CONFIG_PATHS.iter())
        .copied()
        .collect();

    for &path in &all_paths {
        match inotify.watches().add(path, WATCH_MASK) {
            Ok(wd) => { wd_map.insert(wd, path); }
            Err(e) => warn!("FilesystemCollector: cannot watch {path}: {e}"),
        }
    }

    // Sliding window for mass-modification (ransomware) detection.
    let mut mod_window: VecDeque<Instant> = VecDeque::new();

    let mut buf = [0u8; 4096];
    loop {
        let events = match inotify.read_events_blocking(&mut buf) {
            Ok(e)  => e,
            Err(e) => { warn!("FilesystemCollector: inotify read error: {e}"); break; }
        };

        for event in events {
            let dir = match wd_map.get(&event.wd).copied() {
                Some(d) => d,
                None    => continue,
            };
            let path = match &event.name {
                Some(name) => format!("{dir}/{}", name.to_string_lossy()),
                None       => dir.to_string(),
            };
            let mask = event.mask;

            // ── Agent-config tampering (severity: critical) ───────────────────
            if is_agent_config_path(&path) {
                let action_str = if mask.contains(EventMask::DELETE) || mask.contains(EventMask::MOVED_FROM) {
                    "delete"
                } else if mask.contains(EventMask::CREATE) || mask.contains(EventMask::MOVED_TO) {
                    "create"
                } else {
                    "modify"
                };
                if send(&tx, AgentEvent::new(
                    agent_id.clone(), hostname.clone(),
                    EventClass::Filesystem, EventAction::AgentTamper, Severity::Critical,
                    EventData::AgentTamper(AgentTamperData {
                        path: path.clone(), action: action_str.to_string(),
                    }),
                )) { return; }
            }

            // ── FIM: SHA256 integrity check on MODIFY ─────────────────────────
            if mask.contains(EventMask::MODIFY) && is_fim_path(&path) {
                if let Err(e) = check_fim_integrity(
                    &conn, &path, &agent_id, &hostname, &tx,
                ) {
                    warn!("FilesystemCollector: FIM check error for {path}: {e}");
                }
            }

            // ── Ransomware: Shannon entropy on MODIFY ─────────────────────────
            if mask.contains(EventMask::MODIFY) {
                if let Some(entropy) = compute_file_entropy(&path) {
                    if entropy >= ENTROPY_THRESHOLD
                        && send(&tx, AgentEvent::new(
                            agent_id.clone(), hostname.clone(),
                            EventClass::Filesystem, EventAction::RansomwareIndicator, Severity::High,
                            EventData::RansomwareIndicator(RansomwareIndicatorData {
                                indicator_type: "high_entropy".to_string(),
                                path:           Some(path.clone()),
                                pid:            None,
                                comm:           None,
                                entropy:        Some(entropy),
                                write_rate:     None,
                                details:        format!(
                                    "Shannon entropy {entropy:.2} bits/byte (threshold {ENTROPY_THRESHOLD})"
                                ),
                            }),
                        ))
                    { return; }
                }

                // Track modification rate across the sliding window.
                let now = Instant::now();
                mod_window.push_back(now);
                while mod_window.front().is_some_and(|t| now.duration_since(*t) > MASS_MOD_WINDOW) {
                    mod_window.pop_front();
                }
                if mod_window.len() >= MASS_MOD_THRESHOLD {
                    let rate = mod_window.len() as u64;
                    mod_window.clear(); // reset to avoid alert flooding
                    if send(&tx, AgentEvent::new(
                        agent_id.clone(), hostname.clone(),
                        EventClass::Filesystem, EventAction::RansomwareIndicator, Severity::High,
                        EventData::RansomwareIndicator(RansomwareIndicatorData {
                            indicator_type: "high_write_rate".to_string(),
                            path:           None,
                            pid:            None,
                            comm:           None,
                            entropy:        None,
                            write_rate:     Some(rate),
                            details:        format!(
                                "{rate} file modifications in {}s (threshold {})",
                                MASS_MOD_WINDOW.as_secs(), MASS_MOD_THRESHOLD,
                            ),
                        }),
                    )) { return; }
                }
            }

            // ── Ransomware: suspicious extension on CREATE / RENAME ───────────
            if (mask.contains(EventMask::MOVED_TO) || mask.contains(EventMask::CREATE))
                && has_ransom_extension(&path)
                && send(&tx, AgentEvent::new(
                    agent_id.clone(), hostname.clone(),
                    EventClass::Filesystem, EventAction::RansomwareIndicator, Severity::High,
                    EventData::RansomwareIndicator(RansomwareIndicatorData {
                        indicator_type: "suspicious_extension".to_string(),
                        path:           Some(path.clone()),
                        pid:            None,
                        comm:           None,
                        entropy:        None,
                        write_rate:     None,
                        details:        format!(
                            "File appeared with ransomware-associated extension: {path}"
                        ),
                    }),
                ))
            { return; }

            // ── Ransomware: backup directory deletion ─────────────────────────
            if (mask.contains(EventMask::DELETE) || mask.contains(EventMask::MOVED_FROM))
                && is_backup_path(&path)
                && send(&tx, AgentEvent::new(
                    agent_id.clone(), hostname.clone(),
                    EventClass::Filesystem, EventAction::RansomwareIndicator, Severity::High,
                    EventData::RansomwareIndicator(RansomwareIndicatorData {
                        indicator_type: "backup_deletion".to_string(),
                        path:           Some(path.clone()),
                        pid:            None,
                        comm:           None,
                        entropy:        None,
                        write_rate:     None,
                        details:        format!("Backup path deleted or moved: {path}"),
                    }),
                ))
            { return; }

            // ── Basic inotify event (always emitted) ──────────────────────────
            if let Some(action) = mask_to_action(mask) {
                if send(&tx, AgentEvent::new(
                    agent_id.clone(), hostname.clone(),
                    EventClass::Filesystem, action, Severity::Info,
                    EventData::FileEvent(FileEventData { path }),
                )) { return; }
            }
        }
    }
}

/// Returns `true` if the receiver was dropped (agent shutting down).
#[inline]
fn send(tx: &tokio::sync::mpsc::Sender<AgentEvent>, event: AgentEvent) -> bool {
    tx.blocking_send(event).is_err()
}

// ── SQLite baseline ───────────────────────────────────────────────────────────

fn open_db(db_path: &Path) -> Result<Connection> {
    if let Some(parent) = db_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let conn = Connection::open(db_path)?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS baseline (
            path       TEXT PRIMARY KEY,
            hash       TEXT NOT NULL,
            size       INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        );",
    )?;
    Ok(conn)
}

/// Load existing baseline from DB; rebuild if empty or older than BASELINE_MAX_AGE_SECS.
fn load_or_build_baseline(conn: &Connection) -> usize {
    let now = chrono::Utc::now().timestamp();

    // Check the age of the most recent baseline entry.
    let oldest: Option<i64> = conn
        .query_row("SELECT MIN(updated_at) FROM baseline", [], |r| r.get(0))
        .ok()
        .flatten();

    let needs_rebuild = match oldest {
        None    => true,
        Some(t) => (now - t) > BASELINE_MAX_AGE_SECS,
    };

    if needs_rebuild {
        info!("FilesystemCollector: (re)building SHA256 baseline for FIM paths …");
        build_baseline(conn)
    } else {
        conn.query_row("SELECT COUNT(*) FROM baseline", [], |r| r.get::<_, usize>(0))
            .unwrap_or(0)
    }
}

fn build_baseline(conn: &Connection) -> usize {
    let now = chrono::Utc::now().timestamp();
    let mut count = 0usize;

    for &root in FIM_PATHS {
        if !Path::new(root).exists() { continue; }
        for entry in WalkDir::new(root).follow_links(false).into_iter().flatten() {
            if !entry.file_type().is_file() { continue; }
            let path = entry.path().to_string_lossy().into_owned();
            match sha256_file(&path) {
                Ok((hash, size)) => {
                    let _ = conn.execute(
                        "INSERT OR REPLACE INTO baseline (path, hash, size, updated_at) \
                         VALUES (?1, ?2, ?3, ?4)",
                        params![path, hash, size as i64, now],
                    );
                    count += 1;
                }
                Err(e) => warn!("FilesystemCollector: baseline hash failed for {path}: {e}"),
            }
        }
    }
    count
}

/// Check whether a modified file's hash matches the baseline and emit an event if not.
/// The baseline is intentionally NOT updated here — it stays stable until explicitly rebuilt.
fn check_fim_integrity(
    conn:     &Connection,
    path:     &str,
    agent_id: &str,
    hostname: &str,
    tx:       &tokio::sync::mpsc::Sender<AgentEvent>,
) -> Result<()> {
    let (new_hash, new_size) = match sha256_file(path) {
        Ok(v)  => v,
        Err(_) => return Ok(()), // file gone / unreadable — DELETE event will cover it
    };

    let row: Option<(String, i64)> = conn
        .query_row(
            "SELECT hash, size FROM baseline WHERE path = ?1",
            params![path],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .ok();

    match row {
        None => {
            // File not in baseline yet — add it (new file created after agent start).
            let now = chrono::Utc::now().timestamp();
            let _ = conn.execute(
                "INSERT OR REPLACE INTO baseline (path, hash, size, updated_at) \
                 VALUES (?1, ?2, ?3, ?4)",
                params![path, new_hash, new_size as i64, now],
            );
        }
        Some((expected_hash, old_size)) if expected_hash != new_hash => {
            let size_delta = new_size as i64 - old_size;
            tx.blocking_send(AgentEvent::new(
                agent_id.to_string(), hostname.to_string(),
                EventClass::Filesystem, EventAction::IntegrityViolation, Severity::High,
                EventData::IntegrityViolation(IntegrityViolationData {
                    path:          path.to_string(),
                    expected_hash,
                    actual_hash:   new_hash,
                    size_delta,
                }),
            ))?;
        }
        Some(_) => {} // hash unchanged — no violation
    }

    Ok(())
}

// ── Crypto / entropy helpers ──────────────────────────────────────────────────

fn sha256_file(path: &str) -> Result<(String, u64)> {
    let meta = std::fs::metadata(path)?;
    let size = meta.len();
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 65_536];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 { break; }
        hasher.update(&buf[..n]);
    }
    Ok((format!("sha256:{}", hex::encode(hasher.finalize())), size))
}

fn compute_file_entropy(path: &str) -> Option<f64> {
    let meta = std::fs::metadata(path).ok()?;
    let len = meta.len();
    if len == 0 || len > MAX_ENTROPY_BYTES { return None; }
    let data = std::fs::read(path).ok()?;
    Some(shannon_entropy(&data))
}

fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() { return 0.0; }
    let mut counts = [0u64; 256];
    for &b in data { counts[b as usize] += 1; }
    let len = data.len() as f64;
    counts.iter().filter(|&&c| c > 0).map(|&c| {
        let p = c as f64 / len;
        -p * p.log2()
    }).sum()
}

// ── Path classification helpers ───────────────────────────────────────────────

fn is_fim_path(path: &str) -> bool {
    FIM_PATHS.iter().any(|&p| path.starts_with(p))
}

fn is_backup_path(path: &str) -> bool {
    BACKUP_PATHS.iter().any(|&p| path.starts_with(p))
}

fn is_agent_config_path(path: &str) -> bool {
    AGENT_CONFIG_PATHS.iter().any(|&p| path.starts_with(p))
}

fn has_ransom_extension(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    RANSOM_EXTENSIONS.iter().any(|&ext| lower.ends_with(ext))
}

fn mask_to_action(mask: EventMask) -> Option<EventAction> {
    if mask.contains(EventMask::CREATE) || mask.contains(EventMask::MOVED_TO) {
        Some(EventAction::Create)
    } else if mask.contains(EventMask::DELETE) || mask.contains(EventMask::MOVED_FROM) {
        Some(EventAction::Delete)
    } else if mask.contains(EventMask::MODIFY) {
        Some(EventAction::Modify)
    } else {
        None
    }
}
