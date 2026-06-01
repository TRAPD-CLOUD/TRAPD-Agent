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
    AgentEvent, AgentTamperData, DetectionData, EventAction, EventClass, EventData, FileEventData,
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

/// Credential / secret stores.  A file-open of any of these by an unexpected
/// process is treated as credential theft (MITRE T1555 / T1552.004).
const SENSITIVE_PATHS: &[&str] = &[
    "/etc/shadow", "/etc/gshadow", ".ssh/", ".aws/credentials", ".kube/config",
];

/// Processes legitimately expected to open the sensitive paths above.
const ALLOWED_PROCS: &[&str] = &["sshd", "sudo", "passwd"];

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
        // State lives in the canonical, $HOME-independent state dir (resolved by
        // `crate::paths`) so the FIM baseline DB survives under systemd just like
        // device_id and credentials.
        let db_path = crate::paths::state_dir().join("fim_baseline.db");
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

    // Optional YARA scanner — loads *.yar rules once; inert if none present.
    #[cfg(feature = "yara")]
    let yara_scanner = crate::detection::yara_scanner::YaraScanner::load();

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

            // ── YARA: scan newly-created files (feature `yara`) ───────────────
            #[cfg(feature = "yara")]
            if mask.contains(EventMask::CREATE) {
                if let Some((sev, data)) = yara_scanner.scan_file(&path) {
                    if send(&tx, AgentEvent::new(
                        agent_id.clone(), hostname.clone(),
                        EventClass::Detection, EventAction::Detected, sev,
                        EventData::Detection(data),
                    )) { return; }
                }
            }

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
    // WAL gives crash-consistent reads/writes; restrict the DB (and its WAL/SHM
    // sidecars) to owner-only so a non-root reader cannot lift the pre-computed
    // map of monitored file hashes to help evade FIM detection.
    let _ = conn.pragma_update(None, "journal_mode", "WAL");
    restrict_db_perms(db_path);
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

/// Best-effort `0600` on the SQLite database and its WAL/SHM sidecars.
#[cfg(target_os = "linux")]
fn restrict_db_perms(db_path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let perms = std::fs::Permissions::from_mode(0o600);
    for suffix in ["", "-wal", "-shm"] {
        let p = if suffix.is_empty() {
            db_path.to_path_buf()
        } else {
            let mut s = db_path.as_os_str().to_os_string();
            s.push(suffix);
            PathBuf::from(s)
        };
        if p.exists() {
            let _ = std::fs::set_permissions(&p, perms.clone());
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn restrict_db_perms(_db_path: &Path) {}

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

// ── Sensitive file-access detection ───────────────────────────────────────────

/// Inspect a file-open against the sensitive credential-store list.
///
/// Returns a [`DetectionData`] when `path` is one of [`SENSITIVE_PATHS`] and the
/// accessing process `comm` is **not** in [`ALLOWED_PROCS`].  Pure and
/// unit-testable, mirroring the heuristics in `detection::behavior`; the
/// confidence (95) maps to `Severity::Critical` in the detection engine.
pub fn inspect_sensitive_access(path: &str, comm: &str) -> Option<DetectionData> {
    let matched = SENSITIVE_PATHS.iter().find(|&&p| path.contains(p))?;
    let base = comm.rsplit('/').next().unwrap_or(comm);
    if ALLOWED_PROCS.contains(&base) {
        return None;
    }
    Some(DetectionData {
        rule_id: "creds.sensitive_file_access".into(),
        title: "Sensitive credential store accessed by an unexpected process".into(),
        category: "credential_access".into(),
        mitre_tactic: Some("TA0006 Credential Access".into()),
        mitre_technique: Some("T1555".into()),
        confidence: 95,
        subject: path.to_string(),
        detail: format!(
            "Process {base} opened sensitive path {path} (not in allow-list {ALLOWED_PROCS:?})"
        ),
        evidence: serde_json::json!({
            "path": path,
            "comm": comm,
            "matched": matched,
            "techniques": ["T1555", "T1552.004"],
        }),
    })
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_shadow_read_by_unexpected_proc() {
        let d = inspect_sensitive_access("/etc/shadow", "cat").unwrap();
        assert_eq!(d.category, "credential_access");
        assert_eq!(d.mitre_technique.as_deref(), Some("T1555"));
        assert_eq!(d.confidence, 95); // → Severity::Critical
    }

    #[test]
    fn allows_expected_procs() {
        assert!(inspect_sensitive_access("/etc/shadow", "sshd").is_none());
        assert!(inspect_sensitive_access("/home/u/.ssh/id_rsa", "sudo").is_none());
        assert!(inspect_sensitive_access("/etc/shadow", "/usr/bin/passwd").is_none());
    }

    #[test]
    fn flags_ssh_and_cloud_credentials() {
        assert!(inspect_sensitive_access("/home/u/.ssh/id_ed25519", "scp").is_some());
        assert!(inspect_sensitive_access("/home/u/.aws/credentials", "curl").is_some());
        assert!(inspect_sensitive_access("/root/.kube/config", "python3").is_some());
        assert!(inspect_sensitive_access("/etc/gshadow", "tail").is_some());
    }

    #[test]
    fn ignores_non_sensitive_paths() {
        assert!(inspect_sensitive_access("/etc/hostname", "cat").is_none());
        assert!(inspect_sensitive_access("/home/u/notes.txt", "vim").is_none());
    }
}
