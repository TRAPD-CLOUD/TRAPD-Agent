use std::collections::{HashMap, VecDeque};
use std::io::Read as IoRead;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::Result;
use async_trait::async_trait;
use inotify::{EventMask, Inotify, WatchMask};
use rusqlite::{params, Connection};
use sha2::{Digest, Sha256};
use tokio::sync::mpsc::Sender;
use tracing::{debug, info, warn};
use walkdir::WalkDir;

use crate::collectors::Collector;
use crate::schema::{
    AgentEvent, AgentTamperData, DetectionData, EventAction, EventClass, EventData, FileEventData,
    IntegrityViolationData, RansomwareIndicatorData, Severity,
};

// ── Watched path groups ───────────────────────────────────────────────────────

/// Paths subject to SHA256 integrity baseline (FIM).
const FIM_PATHS: &[&str] = &[
    "/usr/bin",
    "/usr/sbin",
    "/lib",
    "/lib64",
    "/boot",
    "/sbin",
    "/root",
    "/etc",
    "/bin",
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
    "/etc/shadow",
    "/etc/gshadow",
    ".ssh/",
    ".aws/credentials",
    ".kube/config",
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
const GENERIC_COALESCE_WINDOW: Duration = Duration::from_secs(2);

/// Ransomware-associated file extension suffixes (lower-case).
const RANSOM_EXTENSIONS: &[&str] = &[
    ".locked",
    ".encrypted",
    ".crypt",
    ".crypted",
    ".crypto",
    ".enc",
    ".locky",
    ".wannacry",
    ".ryuk",
    ".maze",
    ".sodinokibi",
    ".revil",
    ".darkside",
    ".conti",
    ".lockbit",
    ".babuk",
    ".blackcat",
    ".hive",
    ".alphv",
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
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Collector for FilesystemCollector {
    fn name(&self) -> &'static str {
        "FilesystemCollector"
    }

    async fn run(
        &mut self,
        tx: Sender<AgentEvent>,
        agent_id: String,
        hostname: String,
    ) -> Result<()> {
        let db_path = self.db_path.clone();
        let (fs_tx, mut fs_rx) = tokio::sync::mpsc::channel::<AgentEvent>(512);

        // Honeytoken FIM (issue #32, point 1): watch every deployed bait file for
        // tamper (content/attribute change) on a dedicated inotify instance, so a
        // read-then-modify against a token is caught even if the eBPF gate missed
        // it. Deletion/rename tamper is covered with full lineage by the eBPF
        // unlink/rename honeytoken gates, so this layer deliberately alerts only
        // on MODIFY/ATTRIB — that also sidesteps a false positive when the agent
        // itself revokes (deletes) a token.
        {
            let tok_tx = fs_tx.clone();
            let aid = agent_id.clone();
            let host = hostname.clone();
            std::thread::spawn(move || {
                run_token_fim(tok_tx, aid, host);
            });
        }

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
    tx: tokio::sync::mpsc::Sender<AgentEvent>,
    agent_id: String,
    hostname: String,
    db_path: PathBuf,
) {
    let conn = match open_db(&db_path) {
        Ok(c) => c,
        Err(e) => {
            warn!("FilesystemCollector: SQLite init failed: {e}");
            return;
        }
    };

    // Build or refresh the SHA256 baseline.
    let baseline_count = load_or_build_baseline(&conn);
    info!("FilesystemCollector: baseline ready — {baseline_count} files indexed");

    let mut inotify = match Inotify::init() {
        Ok(i) => i,
        Err(e) => {
            warn!("FilesystemCollector: inotify init failed: {e}");
            return;
        }
    };

    let mut wd_map: std::collections::HashMap<inotify::WatchDescriptor, &'static str> =
        std::collections::HashMap::new();

    // Combine all path groups into a single watch list (deduplicated by inotify itself).
    let all_paths: Vec<&'static str> = FIM_PATHS
        .iter()
        .chain(RANSOM_WATCH_PATHS.iter())
        .chain(BACKUP_PATHS.iter())
        .chain(AGENT_CONFIG_PATHS.iter())
        .copied()
        .collect();

    for &path in &all_paths {
        // Skip optional watch roots that don't exist on this host (e.g. /var/www,
        // /backup on a minimal box) quietly — a missing root is not an error and
        // shouldn't spam WARN. Real failures on existing paths still warn.
        if !std::path::Path::new(path).exists() {
            debug!("FilesystemCollector: watch path {path} absent, skipping");
            continue;
        }
        match inotify.watches().add(path, WATCH_MASK) {
            Ok(wd) => {
                wd_map.insert(wd, path);
            }
            Err(e) => warn!("FilesystemCollector: cannot watch {path}: {e}"),
        }
    }

    // Optional YARA scanner — loads *.yar rules once; inert if none present.
    #[cfg(feature = "yara")]
    let yara_scanner = crate::detection::yara_scanner::YaraScanner::load();

    // Sliding window for mass-modification (ransomware) detection.
    let mut mod_window: VecDeque<Instant> = VecDeque::new();
    let mut recently_emitted: HashMap<(String, &'static str), Instant> = HashMap::new();

    let mut buf = [0u8; 4096];
    loop {
        let events = match inotify.read_events_blocking(&mut buf) {
            Ok(e) => e,
            Err(e) => {
                warn!("FilesystemCollector: inotify read error: {e}");
                break;
            }
        };

        for event in events {
            let dir = match wd_map.get(&event.wd).copied() {
                Some(d) => d,
                None => continue,
            };
            let path = match &event.name {
                Some(name) => format!("{dir}/{}", name.to_string_lossy()),
                None => dir.to_string(),
            };
            let mask = event.mask;

            // ── Agent-config tampering (severity: critical) ───────────────────
            if is_agent_config_path(&path) {
                let action_str = if mask.contains(EventMask::DELETE)
                    || mask.contains(EventMask::MOVED_FROM)
                {
                    "delete"
                } else if mask.contains(EventMask::CREATE) || mask.contains(EventMask::MOVED_TO) {
                    "create"
                } else {
                    "modify"
                };
                if send(
                    &tx,
                    AgentEvent::new(
                        agent_id.clone(),
                        hostname.clone(),
                        EventClass::Filesystem,
                        EventAction::AgentTamper,
                        Severity::Critical,
                        EventData::AgentTamper(AgentTamperData {
                            path: path.clone(),
                            action: action_str.to_string(),
                        }),
                    ),
                ) {
                    return;
                }
            }

            // ── FIM: SHA256 integrity check on MODIFY ─────────────────────────
            if mask.contains(EventMask::MODIFY) && is_fim_path(&path) {
                if let Err(e) = check_fim_integrity(&conn, &path, &agent_id, &hostname, &tx) {
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
                while mod_window
                    .front()
                    .is_some_and(|t| now.duration_since(*t) > MASS_MOD_WINDOW)
                {
                    mod_window.pop_front();
                }
                if mod_window.len() >= MASS_MOD_THRESHOLD {
                    let rate = mod_window.len() as u64;
                    mod_window.clear(); // reset to avoid alert flooding
                    if send(
                        &tx,
                        AgentEvent::new(
                            agent_id.clone(),
                            hostname.clone(),
                            EventClass::Filesystem,
                            EventAction::RansomwareIndicator,
                            Severity::High,
                            EventData::RansomwareIndicator(RansomwareIndicatorData {
                                indicator_type: "high_write_rate".to_string(),
                                path: None,
                                pid: None,
                                comm: None,
                                entropy: None,
                                write_rate: Some(rate),
                                details: format!(
                                    "{rate} file modifications in {}s (threshold {})",
                                    MASS_MOD_WINDOW.as_secs(),
                                    MASS_MOD_THRESHOLD,
                                ),
                            }),
                        ),
                    ) {
                        return;
                    }
                }
            }

            // ── Ransomware: suspicious extension on CREATE / RENAME ───────────
            if (mask.contains(EventMask::MOVED_TO) || mask.contains(EventMask::CREATE))
                && has_ransom_extension(&path)
                && send(
                    &tx,
                    AgentEvent::new(
                        agent_id.clone(),
                        hostname.clone(),
                        EventClass::Filesystem,
                        EventAction::RansomwareIndicator,
                        Severity::High,
                        EventData::RansomwareIndicator(RansomwareIndicatorData {
                            indicator_type: "suspicious_extension".to_string(),
                            path: Some(path.clone()),
                            pid: None,
                            comm: None,
                            entropy: None,
                            write_rate: None,
                            details: format!(
                                "File appeared with ransomware-associated extension: {path}"
                            ),
                        }),
                    ),
                )
            {
                return;
            }

            // ── Ransomware: backup directory deletion ─────────────────────────
            if (mask.contains(EventMask::DELETE) || mask.contains(EventMask::MOVED_FROM))
                && is_backup_path(&path)
                && send(
                    &tx,
                    AgentEvent::new(
                        agent_id.clone(),
                        hostname.clone(),
                        EventClass::Filesystem,
                        EventAction::RansomwareIndicator,
                        Severity::High,
                        EventData::RansomwareIndicator(RansomwareIndicatorData {
                            indicator_type: "backup_deletion".to_string(),
                            path: Some(path.clone()),
                            pid: None,
                            comm: None,
                            entropy: None,
                            write_rate: None,
                            details: format!("Backup path deleted or moved: {path}"),
                        }),
                    ),
                )
            {
                return;
            }

            // ── YARA: scan newly-created files (feature `yara`) ───────────────
            #[cfg(feature = "yara")]
            if mask.contains(EventMask::CREATE) {
                if let Some((sev, data)) = yara_scanner.scan_file(&path) {
                    if send(
                        &tx,
                        AgentEvent::new(
                            agent_id.clone(),
                            hostname.clone(),
                            EventClass::Detection,
                            EventAction::Detected,
                            sev,
                            EventData::Detection(data),
                        ),
                    ) {
                        return;
                    }
                }
            }

            // ── Basic inotify event (always emitted) ──────────────────────────
            if let Some(action) = mask_to_action(mask) {
                if suppress_generic_event(&path, &action, &mut recently_emitted, Instant::now()) {
                    continue;
                }
                if send(
                    &tx,
                    AgentEvent::new(
                        agent_id.clone(),
                        hostname.clone(),
                        EventClass::Filesystem,
                        action,
                        Severity::Info,
                        EventData::FileEvent(FileEventData { path }),
                    ),
                ) {
                    return;
                }
            }
        }
    }
}

/// Reduce low-value write amplification without touching security detections.
/// Critical persistence/credential paths bypass both filtering and coalescing.
fn suppress_generic_event(
    path: &str,
    action: &EventAction,
    recent: &mut HashMap<(String, &'static str), Instant>,
    now: Instant,
) -> bool {
    let critical = is_security_critical_path(path);
    let noisy = path.contains("/__pycache__/")
        || path.contains("/.cache/")
        || path.ends_with('~')
        || path.ends_with(".swp")
        || path.ends_with(".tmp");
    if noisy && !critical {
        return true;
    }
    if critical {
        return false;
    }
    let action_key = match action {
        EventAction::Create => "create",
        EventAction::Delete => "delete",
        EventAction::Modify => "modify",
        _ => "other",
    };
    let key = (path.to_string(), action_key);
    if recent
        .get(&key)
        .is_some_and(|last| now.duration_since(*last) < GENERIC_COALESCE_WINDOW)
    {
        return true;
    }
    recent.insert(key, now);
    if recent.len() > 4096 {
        recent.retain(|_, seen| now.duration_since(*seen) < GENERIC_COALESCE_WINDOW);
    }
    false
}

fn is_security_critical_path(path: &str) -> bool {
    matches!(path, "/etc/passwd" | "/etc/shadow" | "/etc/sudoers")
        || path.starts_with("/etc/ssh/")
        || path.contains("/.ssh/authorized_keys")
        || path.starts_with("/etc/systemd/system/")
        || path.starts_with("/usr/lib/systemd/system/")
        || path.starts_with("/etc/cron")
        || path.starts_with("/var/spool/cron/")
        || path.starts_with("/usr/bin/")
        || path.starts_with("/usr/sbin/")
        || path.starts_with("/etc/trapd/")
}

/// Returns `true` if the receiver was dropped (agent shutting down).
#[inline]
fn send(tx: &tokio::sync::mpsc::Sender<AgentEvent>, event: AgentEvent) -> bool {
    tx.blocking_send(event).is_err()
}

// ── Honeytoken FIM ──────────────────────────────────────────────────────────

/// How often the token-FIM watcher re-reads the honeytoken register to pick up
/// newly-deployed (or revoked) tokens.
const TOKEN_FIM_RELOAD_SECS: u64 = 15;

/// inotify events that mean a *third party* altered a token in place. We watch
/// only MODIFY/ATTRIB: a deployed bait is never modified by the agent again, so
/// either is a tamper signal. Deletion/rename is left to the eBPF unlink/rename
/// honeytoken gates (which carry full process lineage and exclude the agent).
fn token_fim_mask() -> WatchMask {
    WatchMask::MODIFY.union(WatchMask::ATTRIB)
}

/// Read the on-disk honeytoken register (read-only) and return the token paths.
/// We deliberately parse the file directly rather than going through
/// [`crate::deception::HoneytokenStore`], whose `Drop` re-flushes the registry —
/// a side effect we must not trigger from a read-only poller.
fn current_token_paths() -> Vec<String> {
    let path = crate::deception::registry::registry_path();
    std::fs::read(&path)
        .ok()
        .and_then(|b| {
            serde_json::from_slice::<crate::deception::registry::HoneytokenRegistry>(&b).ok()
        })
        .map(|r| r.tokens.into_iter().map(|t| t.path).collect())
        .unwrap_or_default()
}

/// Dedicated watcher that keeps an inotify watch on every deployed honeytoken
/// file and emits a `deception.honeytoken_tamper` detection when one is modified
/// or has its attributes changed. Runs on its own thread for the agent's
/// lifetime, reconciling the watch set from the register every
/// [`TOKEN_FIM_RELOAD_SECS`].
fn run_token_fim(tx: tokio::sync::mpsc::Sender<AgentEvent>, agent_id: String, hostname: String) {
    let mut inotify = match Inotify::init() {
        Ok(i) => i,
        Err(e) => {
            warn!("FilesystemCollector: token-FIM inotify init failed: {e}");
            return;
        }
    };

    // wd → token path, and the set of paths currently watched (for reconcile).
    let mut wd_map: std::collections::HashMap<inotify::WatchDescriptor, String> =
        std::collections::HashMap::new();
    let mut watched: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut last_reload = Instant::now()
        .checked_sub(Duration::from_secs(TOKEN_FIM_RELOAD_SECS + 1))
        .unwrap_or_else(Instant::now);

    let mut buf = [0u8; 4096];
    loop {
        // ── Reconcile the watch set from the register ────────────────────────
        if last_reload.elapsed() >= Duration::from_secs(TOKEN_FIM_RELOAD_SECS) {
            last_reload = Instant::now();
            let desired: std::collections::HashSet<String> =
                current_token_paths().into_iter().collect();
            for p in desired.difference(&watched.clone()) {
                match inotify.watches().add(p, token_fim_mask()) {
                    Ok(wd) => {
                        wd_map.insert(wd, p.clone());
                        watched.insert(p.clone());
                    }
                    // The token file may not exist yet, or be unreadable — retry
                    // on the next reconcile rather than giving up.
                    Err(e) => {
                        tracing::debug!("token-FIM: cannot watch {p}: {e}");
                    }
                }
            }
            // Drop watches for paths no longer registered (revoked).
            let stale: std::collections::HashSet<String> =
                watched.difference(&desired).cloned().collect();
            if !stale.is_empty() {
                let to_remove: Vec<inotify::WatchDescriptor> = wd_map
                    .iter()
                    .filter(|(_, v)| stale.contains(*v))
                    .map(|(k, _)| k.clone())
                    .collect();
                for wd in to_remove {
                    let _ = inotify.watches().remove(wd.clone());
                    wd_map.remove(&wd);
                }
                for p in &stale {
                    watched.remove(p);
                }
            }
        }

        // ── Drain any pending events (non-blocking) ──────────────────────────
        match inotify.read_events(&mut buf) {
            Ok(events) => {
                for event in events {
                    // The kernel auto-removes a watch when the file disappears and
                    // delivers IGNORED — forget it so a re-deploy can re-arm.
                    if event.mask.contains(EventMask::IGNORED) {
                        if let Some(p) = wd_map.remove(&event.wd) {
                            watched.remove(&p);
                        }
                        continue;
                    }
                    let Some(path) = wd_map.get(&event.wd).cloned() else {
                        continue;
                    };

                    let (indicator, technique, tactic) = if event.mask.contains(EventMask::ATTRIB) {
                        ("attribute_change", "T1070.006", "TA0005 Defense Evasion")
                    } else {
                        ("content_modified", "T1565.001", "TA0040 Impact")
                    };

                    if send(
                        &tx,
                        AgentEvent::new(
                            agent_id.clone(),
                            hostname.clone(),
                            EventClass::Detection,
                            EventAction::Detected,
                            Severity::Critical,
                            EventData::Detection(DetectionData {
                                rule_id: "deception.honeytoken_tamper".to_string(),
                                title: "Honeytoken file tampered".to_string(),
                                category: "deception".to_string(),
                                mitre_tactic: Some(tactic.to_string()),
                                mitre_technique: Some(technique.to_string()),
                                confidence: 90,
                                subject: path.clone(),
                                detail: format!(
                                "Deployed honeytoken {path} was altered in place ({indicator}); \
                                 the agent never modifies a placed token, so this is tamper."
                            ),
                                evidence: serde_json::json!({
                                    "indicator": indicator,
                                    "inotify_mask": format!("{:?}", event.mask),
                                }),
                            }),
                        ),
                    ) {
                        return;
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(e) => {
                warn!("FilesystemCollector: token-FIM read error: {e}");
                return;
            }
        }

        // Poll cadence: tamper is rare, sub-second latency is plenty and keeps
        // the thread near-idle.
        std::thread::sleep(Duration::from_millis(500));
    }
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
        None => true,
        Some(t) => (now - t) > BASELINE_MAX_AGE_SECS,
    };

    if needs_rebuild {
        info!("FilesystemCollector: (re)building SHA256 baseline for FIM paths …");
        build_baseline(conn)
    } else {
        conn.query_row("SELECT COUNT(*) FROM baseline", [], |r| {
            r.get::<_, usize>(0)
        })
        .unwrap_or(0)
    }
}

fn build_baseline(conn: &Connection) -> usize {
    let now = chrono::Utc::now().timestamp();
    let mut count = 0usize;

    for &root in FIM_PATHS {
        if !Path::new(root).exists() {
            continue;
        }
        for entry in WalkDir::new(root).follow_links(false).into_iter().flatten() {
            if !entry.file_type().is_file() {
                continue;
            }
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
    conn: &Connection,
    path: &str,
    agent_id: &str,
    hostname: &str,
    tx: &tokio::sync::mpsc::Sender<AgentEvent>,
) -> Result<()> {
    let (new_hash, new_size) = match sha256_file(path) {
        Ok(v) => v,
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
                agent_id.to_string(),
                hostname.to_string(),
                EventClass::Filesystem,
                EventAction::IntegrityViolation,
                Severity::High,
                EventData::IntegrityViolation(IntegrityViolationData {
                    path: path.to_string(),
                    expected_hash,
                    actual_hash: new_hash,
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
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok((format!("sha256:{}", hex::encode(hasher.finalize())), size))
}

fn compute_file_entropy(path: &str) -> Option<f64> {
    let meta = std::fs::metadata(path).ok()?;
    let len = meta.len();
    if len == 0 || len > MAX_ENTROPY_BYTES {
        return None;
    }
    let data = std::fs::read(path).ok()?;
    Some(shannon_entropy(&data))
}

fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
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

    #[test]
    fn repetitive_generic_events_are_coalesced() {
        let now = Instant::now();
        let mut recent = HashMap::new();
        assert!(!suppress_generic_event(
            "/tmp/trapd-detection-test",
            &EventAction::Modify,
            &mut recent,
            now
        ));
        assert!(suppress_generic_event(
            "/tmp/trapd-detection-test",
            &EventAction::Modify,
            &mut recent,
            now + Duration::from_millis(10)
        ));
        assert!(!suppress_generic_event(
            "/tmp/trapd-detection-test",
            &EventAction::Modify,
            &mut recent,
            now + GENERIC_COALESCE_WINDOW
        ));
    }

    #[test]
    fn critical_paths_are_never_coalesced_or_ignored() {
        let now = Instant::now();
        let mut recent = HashMap::new();
        for path in [
            "/etc/shadow",
            "/etc/ssh/sshd_config",
            "/home/alice/.ssh/authorized_keys",
            "/etc/systemd/system/persist.service",
            "/var/spool/cron/root",
            "/usr/bin/sudo",
        ] {
            assert!(!suppress_generic_event(
                path,
                &EventAction::Modify,
                &mut recent,
                now
            ));
            assert!(!suppress_generic_event(
                path,
                &EventAction::Modify,
                &mut recent,
                now
            ));
        }
    }

    #[test]
    fn cache_and_editor_artifacts_are_suppressed() {
        let mut recent = HashMap::new();
        let now = Instant::now();
        for path in ["/home/a/.cache/x", "/tmp/a.swp", "/tmp/a.tmp", "/tmp/a~"] {
            assert!(suppress_generic_event(
                path,
                &EventAction::Modify,
                &mut recent,
                now
            ));
        }
    }
}
