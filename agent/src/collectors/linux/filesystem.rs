use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use anyhow::Result;
use async_trait::async_trait;
use inotify::{EventMask, Inotify, WatchMask};
use tokio::sync::mpsc::Sender;
use tracing::{debug, warn};

use crate::collectors::fs_heuristics::{self as heur, Coalescer, MassModification};
use crate::collectors::Collector;
use crate::config::AgentConfig;
use crate::schema::{
    AgentEvent, AgentTamperData, DetectionData, EventAction, EventClass, EventData,
    FilesystemEventData, FilesystemOperation, FilesystemSource, IntegrityStatus, Severity,
};

// ── Watched path groups ───────────────────────────────────────────────────────

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

// ── Collector struct ──────────────────────────────────────────────────────────

pub struct FilesystemCollector {
    cfg: Arc<RwLock<AgentConfig>>,
}

impl FilesystemCollector {
    pub fn new(cfg: Arc<RwLock<AgentConfig>>) -> Self {
        Self { cfg }
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

        let realtime_tx = fs_tx.clone();
        let realtime_agent_id = agent_id.clone();
        let realtime_hostname = hostname.clone();
        let fim_paths = self
            .cfg
            .read()
            .map(|cfg| cfg.fim_paths.clone())
            .unwrap_or_default();
        std::thread::spawn(move || {
            run_sync(realtime_tx, realtime_agent_id, realtime_hostname, fim_paths);
        });
        // Both sources feed one outward stream and use FilesystemEventData.
        let mut fim = super::fim::FimCollector::new(Arc::clone(&self.cfg));
        tokio::spawn(async move {
            if let Err(error) = fim.run(fs_tx, agent_id, hostname).await {
                warn!(%error, "FilesystemCollector: periodic FIM stopped");
            }
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
    fim_paths: Vec<String>,
) {
    let mut inotify = match Inotify::init() {
        Ok(i) => i,
        Err(e) => {
            warn!("FilesystemCollector: inotify init failed: {e}");
            return;
        }
    };

    let mut wd_map: std::collections::HashMap<inotify::WatchDescriptor, String> =
        std::collections::HashMap::new();

    // FIM configuration governs both periodic hashing and real-time
    // notifications; the remaining roots exist only for their named detections.
    let mut all_paths = fim_paths;
    all_paths.extend(
        RANSOM_WATCH_PATHS
            .iter()
            .chain(BACKUP_PATHS.iter())
            .chain(AGENT_CONFIG_PATHS.iter())
            .map(|path| (*path).to_string()),
    );

    for path in &all_paths {
        // Skip optional watch roots that don't exist on this host (e.g. /var/www,
        // /backup on a minimal box) quietly — a missing root is not an error and
        // shouldn't spam WARN. Real failures on existing paths still warn.
        if !std::path::Path::new(path).exists() {
            debug!("FilesystemCollector: watch path {path} absent, skipping");
            continue;
        }
        match inotify.watches().add(path, WATCH_MASK) {
            Ok(wd) => {
                wd_map.insert(wd, path.clone());
            }
            Err(e) => warn!("FilesystemCollector: cannot watch {path}: {e}"),
        }
    }

    // Optional YARA scanner — loads *.yar rules once; inert if none present.
    #[cfg(feature = "yara")]
    let yara_scanner = crate::detection::yara_scanner::YaraScanner::load();

    // Sliding window for mass-modification (ransomware) detection.
    let mut mod_window = MassModification::default();
    let mut coalescer = Coalescer::default();

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
            let dir = match wd_map.get(&event.wd) {
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

            // ── Ransomware: Shannon entropy on MODIFY ─────────────────────────
            if mask.contains(EventMask::MODIFY) {
                if let Some(entropy) = heur::file_entropy(&path) {
                    if entropy >= heur::ENTROPY_THRESHOLD
                        && send(
                            &tx,
                            heur::high_entropy_event(&agent_id, &hostname, &path, entropy),
                        )
                    {
                        return;
                    }
                }

                // Distinct files modified inside the sliding window.
                if let Some(rate) = mod_window.record(&path, Instant::now()) {
                    if send(
                        &tx,
                        heur::high_write_rate_event(&agent_id, &hostname, rate as u64),
                    ) {
                        return;
                    }
                }
            }

            // ── Ransomware: suspicious extension on CREATE / RENAME ───────────
            if (mask.contains(EventMask::MOVED_TO) || mask.contains(EventMask::CREATE))
                && heur::has_ransom_extension(&path)
                && send(
                    &tx,
                    heur::suspicious_extension_event(&agent_id, &hostname, &path),
                )
            {
                return;
            }

            // ── Ransomware: backup directory deletion ─────────────────────────
            if (mask.contains(EventMask::DELETE) || mask.contains(EventMask::MOVED_FROM))
                && is_backup_path(&path)
                && send(
                    &tx,
                    heur::backup_deletion_event(&agent_id, &hostname, &path),
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
                            EventData::Detection(Box::new(data)),
                        ),
                    ) {
                        return;
                    }
                }
            }

            // ── Basic inotify event (always emitted) ──────────────────────────
            if let Some(action) = mask_to_action(mask) {
                if suppress_generic_event(&path, &action, &mut coalescer, Instant::now()) {
                    continue;
                }
                let operation = match action {
                    EventAction::Create => FilesystemOperation::Created,
                    EventAction::Modify => FilesystemOperation::Modified,
                    EventAction::Delete => FilesystemOperation::Deleted,
                    _ => unreachable!("mask_to_action only returns filesystem actions"),
                };
                if send(
                    &tx,
                    AgentEvent::new(
                        agent_id.clone(),
                        hostname.clone(),
                        EventClass::Filesystem,
                        action,
                        Severity::Info,
                        EventData::Filesystem(FilesystemEventData {
                            path,
                            operation,
                            source: FilesystemSource::Realtime,
                            integrity: IntegrityStatus::NotChecked,
                            expected_hash: None,
                            actual_hash: None,
                            size_delta: None,
                            actor: None,
                            change_summary: None,
                        }),
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
    coalescer: &mut Coalescer,
    now: Instant,
) -> bool {
    let critical = is_security_critical_path(path);
    let noisy = path.contains("/__pycache__/")
        || path.contains("/.cache/")
        || path.ends_with('~')
        || path.ends_with(".swp")
        || path.ends_with(".tmp");
    let action_key = match action {
        EventAction::Create => "create",
        EventAction::Delete => "delete",
        EventAction::Modify => "modify",
        _ => "other",
    };
    coalescer.suppress(path, action_key, critical, noisy, now)
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
                            EventData::Detection(Box::new(DetectionData {
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
                                ..Default::default()
                            })),
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

// ── Path classification helpers ───────────────────────────────────────────────

fn is_backup_path(path: &str) -> bool {
    BACKUP_PATHS.iter().any(|&p| path.starts_with(p))
}

fn is_agent_config_path(path: &str) -> bool {
    AGENT_CONFIG_PATHS.iter().any(|&p| path.starts_with(p))
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
    fn repetitive_generic_events_are_coalesced() {
        let now = Instant::now();
        let mut recent = Coalescer::default();
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
            now + heur::GENERIC_COALESCE_WINDOW
        ));
    }

    #[test]
    fn critical_paths_are_never_coalesced_or_ignored() {
        let now = Instant::now();
        let mut recent = Coalescer::default();
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
        let mut recent = Coalescer::default();
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
