//! Generic Linux log collector.
//!
//! Architecture (one pipeline, many sources — never a per-product collector):
//!
//! ```text
//! LogSource → Reader → Framing / Multiline → Parser → Normalizer → Canonical Event
//! ```
//!
//! Readers: file (inode + rotation + truncation + glob), systemd journal,
//! syslog UDP/unix. Parsers: json, syslog, nginx, apache, postgres, mysql,
//! docker, sshd, sudo, auditd, kv, cef, auto. Offsets persist across
//! restarts; floods are rate-limited with a named drop reason; a full
//! pipeline channel blocks the *log* reader (correct backpressure — logs
//! are not a kernel ring buffer) without stalling eBPF collectors.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::Result;
use async_trait::async_trait;
use chrono::Utc;
use tokio::sync::mpsc::Sender;
use tracing::{debug, info, warn};

use crate::collectors::Collector;
use crate::config::{AgentConfig, LogSourceConfig, SourceKind};
use crate::schema::AgentEvent;
use crate::telemetry::{metrics::metrics, DropReason};

mod catalogue;
mod checkpoint;
mod framing;
mod journal;
mod normalize;
mod parser;
mod reader;
mod syslog;

use checkpoint::{file_key, journal_key, CheckpointStore, JournalCheckpoint};
use framing::{AuditAggregator, MultilineAggregator};
use reader::{expand_paths, FileTail, RateLimiter};

/// Debounce for the on-disk offset file.
const CHECKPOINT_FLUSH: Duration = Duration::from_secs(1);
/// File-tail poll interval. Rotation/truncation are detected on the same
/// cadence; 250 ms is well inside a security-relevant window and does not
/// depend on inotify (which is unavailable on NFS and some containers).
const FILE_POLL: Duration = Duration::from_millis(250);
/// How often globs are re-expanded (new files matching `*.log`).
const GLOB_REFRESH: Duration = Duration::from_secs(15);
/// How often the supervisor re-reads signed config and (re)arms sources.
const SOURCE_SUPERVISE: Duration = Duration::from_secs(15);
/// Back-off before restarting a source that exited (missing journalctl, …).
const SOURCE_COOLDOWN: Duration = Duration::from_secs(30);

pub struct LogCollector {
    cfg: Arc<std::sync::RwLock<AgentConfig>>,
}

impl LogCollector {
    pub fn new(cfg: Arc<std::sync::RwLock<AgentConfig>>) -> Self {
        Self { cfg }
    }
}

impl Default for LogCollector {
    fn default() -> Self {
        Self {
            cfg: Arc::new(std::sync::RwLock::new(AgentConfig::default())),
        }
    }
}

#[async_trait]
impl Collector for LogCollector {
    fn name(&self) -> &'static str {
        "LogCollector"
    }

    async fn run(
        &mut self,
        tx: Sender<AgentEvent>,
        agent_id: String,
        hostname: String,
    ) -> Result<()> {
        let cp_path = crate::paths::state_dir().join("log_offsets.json");
        let store = Arc::new(Mutex::new(CheckpointStore::load(cp_path)));

        let store_flush = Arc::clone(&store);
        let flush_task = tokio::spawn(async move {
            let mut tick = tokio::time::interval(CHECKPOINT_FLUSH);
            loop {
                tick.tick().await;
                if let Ok(mut s) = store_flush.lock() {
                    s.flush(CHECKPOINT_FLUSH, false);
                }
            }
        });

        // Supervisor: signed-config updates can add/remove sources without
        // restarting the agent. File tails themselves never exit; journal/
        // syslog tasks that die are retried after SOURCE_COOLDOWN.
        let mut tasks: HashMap<String, tokio::task::JoinHandle<()>> = HashMap::new();
        let mut cooldown: HashMap<String, Instant> = HashMap::new();
        info!("LogCollector starting");

        loop {
            if tx.is_closed() {
                break;
            }

            let sources = {
                let cfg = self.cfg.read().unwrap_or_else(|e| e.into_inner());
                catalogue::resolve(&cfg)
            };
            let desired: HashSet<String> = sources.iter().map(|s| s.name.clone()).collect();

            let stale: Vec<String> = tasks
                .keys()
                .filter(|n| !desired.contains(*n))
                .cloned()
                .collect();
            for name in stale {
                if let Some(h) = tasks.remove(&name) {
                    h.abort();
                    info!(source = %name, "log source disarmed");
                }
            }

            for src in sources {
                if tasks.contains_key(&src.name) {
                    continue;
                }
                if cooldown
                    .get(&src.name)
                    .is_some_and(|t| t.elapsed() < SOURCE_COOLDOWN)
                {
                    continue;
                }
                let name = src.name.clone();
                cooldown.remove(&name);
                info!(
                    source = %name,
                    kind = src.kind().as_str(),
                    "log source armed"
                );
                let tx = tx.clone();
                let store = Arc::clone(&store);
                let agent_id = agent_id.clone();
                let hostname = hostname.clone();
                tasks.insert(
                    name,
                    tokio::spawn(async move {
                        run_source(src, tx, store, agent_id, hostname).await;
                    }),
                );
            }

            let finished: Vec<String> = tasks
                .iter()
                .filter(|(_, h)| h.is_finished())
                .map(|(n, _)| n.clone())
                .collect();
            for name in finished {
                if let Some(h) = tasks.remove(&name) {
                    let _ = h.await;
                    cooldown.insert(name.clone(), Instant::now());
                    warn!(source = %name, "log source exited — retry after cooldown");
                }
            }

            tokio::select! {
                _ = tx.closed() => break,
                _ = tokio::time::sleep(SOURCE_SUPERVISE) => {}
            }
        }

        for h in tasks.into_values() {
            h.abort();
        }
        flush_task.abort();
        if let Ok(mut s) = store.lock() {
            s.flush(Duration::ZERO, true);
        }
        Ok(())
    }
}

async fn run_source(
    src: LogSourceConfig,
    tx: Sender<AgentEvent>,
    store: Arc<Mutex<CheckpointStore>>,
    agent_id: String,
    hostname: String,
) {
    match src.kind() {
        SourceKind::File => run_file_source(src, tx, store, agent_id, hostname).await,
        SourceKind::Journal => run_journal_source(src, tx, store, agent_id, hostname).await,
        SourceKind::Syslog => run_syslog_source(src, tx, store, agent_id, hostname).await,
    }
}

async fn run_file_source(
    src: LogSourceConfig,
    tx: Sender<AgentEvent>,
    store: Arc<Mutex<CheckpointStore>>,
    agent_id: String,
    hostname: String,
) {
    let mut seen: HashSet<std::path::PathBuf> = HashSet::new();
    let mut watches: Vec<(FileTail, SourceFramer)> = Vec::new();
    let mut limiter = RateLimiter::new(src.max_eps);
    let mut last_glob = std::time::Instant::now() - GLOB_REFRESH;
    let mut ticker = tokio::time::interval(FILE_POLL);

    loop {
        if tx.is_closed() {
            return;
        }
        ticker.tick().await;

        if last_glob.elapsed() >= GLOB_REFRESH || watches.is_empty() {
            last_glob = std::time::Instant::now();
            let paths = expand_paths(&src.path, &src.exclude);
            for p in paths {
                if seen.insert(p.clone()) {
                    let key = file_key(&src.name, &p.to_string_lossy());
                    let cp = store.lock().ok().and_then(|s| s.get_file(&key).cloned());
                    info!(source = %src.name, path = %p.display(), "file tail armed");
                    watches.push((FileTail::new(&src, p, cp.as_ref()), SourceFramer::new(&src)));
                }
            }
        }

        let mut i = 0;
        while i < watches.len() {
            let records = match watches[i].0.poll() {
                Ok(r) => r,
                Err(e) => {
                    debug!(source = %src.name, path = %watches[i].0.path.display(), error = %e, "file poll");
                    i += 1;
                    continue;
                }
            };
            let path = watches[i].0.path.clone();
            let path_s = path.to_string_lossy().into_owned();
            for rec in records {
                let logical = match watches[i].1.push(&rec.line.as_str()) {
                    Some(s) => s,
                    None => continue,
                };
                if !emit_one(
                    &src,
                    &logical,
                    normalize::EmitMeta {
                        source_path: &path_s,
                        offset: Some(rec.offset),
                        inode: Some(rec.inode),
                        truncated: rec.line.truncated,
                        original_len: rec.line.original_len,
                    },
                    &tx,
                    &agent_id,
                    &hostname,
                    &mut limiter,
                )
                .await
                {
                    return;
                }
            }
            while let Some(logical) = watches[i].1.poll_timeout() {
                let (offset, inode) = watches[i]
                    .0
                    .checkpoint()
                    .map(|c| (Some(c.offset), Some(c.inode)))
                    .unwrap_or((None, None));
                if !emit_one(
                    &src,
                    &logical,
                    normalize::EmitMeta {
                        source_path: &path_s,
                        offset,
                        inode,
                        truncated: false,
                        original_len: 0,
                    },
                    &tx,
                    &agent_id,
                    &hostname,
                    &mut limiter,
                )
                .await
                {
                    return;
                }
            }
            if let Some(cp) = watches[i].0.checkpoint() {
                if let Ok(mut s) = store.lock() {
                    s.put_file(file_key(&src.name, &path.to_string_lossy()), cp);
                }
            }
            i += 1;
        }
    }
}

async fn run_journal_source(
    src: LogSourceConfig,
    tx: Sender<AgentEvent>,
    store: Arc<Mutex<CheckpointStore>>,
    agent_id: String,
    hostname: String,
) {
    let key = journal_key(&src.name);
    let cursor = store.lock().ok().and_then(|s| s.get_journal(&key).cloned());
    let Some(mut tail) = journal::JournalTail::spawn(&src, cursor.as_ref()).await else {
        return;
    };
    let mut limiter = RateLimiter::new(src.max_eps);
    while let Some(line) = tail.next_line().await {
        if tx.is_closed() {
            break;
        }
        let Some((mut parsed, cursor)) = journal::parse_journal_json(&line) else {
            continue;
        };
        // Product parser on the MESSAGE (sshd/sudo/json/…).
        if !src.parser.eq_ignore_ascii_case("raw") && !src.parser.eq_ignore_ascii_case("none") {
            let inner = parser::parse(&src.parser, &parsed.message);
            overlay_parsed(&mut parsed, inner);
        }
        if !limiter.allow() {
            metrics().event_dropped(DropReason::RateLimitApplied);
            continue;
        }
        let ev = normalize::to_event(
            &agent_id,
            &hostname,
            &src,
            parsed,
            normalize::EmitMeta {
                source_path: src.units.first().map(String::as_str).unwrap_or("journal"),
                offset: None,
                inode: None,
                truncated: false,
                original_len: 0,
            },
        );
        if tx.send(ev).await.is_err() {
            break;
        }
        if !cursor.is_empty() {
            if let Ok(mut s) = store.lock() {
                s.put_journal(
                    key.clone(),
                    JournalCheckpoint {
                        source: src.name.clone(),
                        cursor,
                        updated_at: Utc::now(),
                    },
                );
            }
        }
    }
    tail.kill().await;
}

async fn run_syslog_source(
    src: LogSourceConfig,
    tx: Sender<AgentEvent>,
    _store: Arc<Mutex<CheckpointStore>>,
    agent_id: String,
    hostname: String,
) {
    let Some(sock) = syslog::SyslogListen::bind(&src).await else {
        return;
    };
    let mut limiter = RateLimiter::new(src.max_eps);
    let mut buf = vec![0u8; src.max_line_bytes.max(2048)];
    loop {
        let n = match sock.recv(&mut buf).await {
            Ok(n) => n,
            Err(e) => {
                warn!(source = %src.name, error = %e, "syslog recv failed");
                tokio::time::sleep(Duration::from_secs(1)).await;
                continue;
            }
        };
        if tx.is_closed() {
            return;
        }
        let raw = String::from_utf8_lossy(&buf[..n]);
        if !emit_one(
            &src,
            raw.trim_end(),
            normalize::EmitMeta {
                source_path: &src.path,
                offset: None,
                inode: None,
                truncated: false,
                original_len: n,
            },
            &tx,
            &agent_id,
            &hostname,
            &mut limiter,
        )
        .await
        {
            return;
        }
    }
}

fn overlay_parsed(dst: &mut parser::ParsedLog, src: parser::ParsedLog) {
    if src.category != "application" && src.category != "syslog" {
        dst.category = src.category;
    }
    if dst.username.is_none() {
        dst.username = src.username;
    }
    if dst.severity_hint.is_none() {
        dst.severity_hint = src.severity_hint;
    }
    if dst.mitre_tactic.is_none() {
        dst.mitre_tactic = src.mitre_tactic;
        dst.mitre_technique = src.mitre_technique;
    }
    for (k, v) in src.fields {
        dst.fields.entry(k).or_insert(v);
    }
}

async fn emit_one(
    src: &LogSourceConfig,
    raw: &str,
    meta: normalize::EmitMeta<'_>,
    tx: &Sender<AgentEvent>,
    agent_id: &str,
    hostname: &str,
    limiter: &mut RateLimiter,
) -> bool {
    if raw.is_empty() {
        return true;
    }
    if !limiter.allow() {
        metrics().event_dropped(DropReason::RateLimitApplied);
        return true;
    }
    let parsed = parser::parse(&src.parser, raw);
    let ev = normalize::to_event(agent_id, hostname, src, parsed, meta);
    tx.send(ev).await.is_ok()
}

/// Per-source logical-record assembler.
enum SourceFramer {
    Pass,
    Multiline(MultilineAggregator),
    Audit(AuditAggregator),
}

impl SourceFramer {
    fn new(src: &LogSourceConfig) -> Self {
        if src.parser.eq_ignore_ascii_case("auditd") || src.parser.eq_ignore_ascii_case("audit") {
            return Self::Audit(AuditAggregator::new(
                src.multiline.as_ref().map(|m| m.max_lines).unwrap_or(64),
            ));
        }
        if let Some(ml) = &src.multiline {
            return Self::Multiline(MultilineAggregator::new(ml));
        }
        Self::Pass
    }

    fn push(&mut self, line: &str) -> Option<String> {
        match self {
            Self::Pass => Some(line.to_string()),
            Self::Multiline(m) => m.push(line),
            Self::Audit(a) => a.push(line),
        }
    }

    fn poll_timeout(&mut self) -> Option<String> {
        match self {
            Self::Multiline(m) => m.poll_timeout(),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{EventAction, EventClass, EventData};

    #[tokio::test]
    async fn file_source_emits_canonical_log_event() {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("trapd_logcol_{nanos}"));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("app.log");
        std::fs::write(&path, "hello world\n").unwrap();

        let src =
            LogSourceConfig::file("app", &path.to_string_lossy(), "raw").read_from_beginning();
        let (tx, mut rx) = tokio::sync::mpsc::channel(16);
        let store = Arc::new(Mutex::new(CheckpointStore::load(dir.join("cp.json"))));
        let src2 = src.clone();
        let store2 = Arc::clone(&store);
        let h = tokio::spawn(async move {
            tokio::time::timeout(
                Duration::from_secs(3),
                run_file_source(src2, tx, store2, "agent".into(), "host".into()),
            )
            .await
            .ok();
        });

        let ev = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("timeout")
            .expect("event");
        assert!(matches!(ev.class, EventClass::Log));
        assert!(matches!(ev.action, EventAction::Log));
        let EventData::Log(d) = ev.data else {
            panic!("expected log payload")
        };
        assert_eq!(d.source, "app");
        assert_eq!(d.message, "hello world");
        h.abort();
        let _ = std::fs::remove_dir_all(&dir);
        let _ = src;
        let _ = store;
    }
}
