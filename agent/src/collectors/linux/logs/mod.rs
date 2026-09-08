//! Generic Linux log collector.
//!
//! ```text
//! LogSource  →  Reader  →  Framing / Multiline  →  Parser  →  Normalizer  →  Canonical Event
//! ```
//!
//! One pipeline, many sources. nginx, apache, postgres, mysql, docker, ssh,
//! sudo, auditd, systemd journal, syslog and custom application logs all
//! collapse onto [`crate::schema::LogEventData`]. Adding a source is a config
//! entry, not a new collector.
//!
//! Reliability that Falcon-class file harvesters typically miss:
//! inode + generation fingerprints, rename *and* copytruncate detection,
//! persisted cursors, true backpressure on the file path, per-source and
//! global rate limits, max-line / multiline ceilings, secret redaction.

use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use anyhow::Result;
use async_trait::async_trait;
use tokio::sync::mpsc::Sender;
use tracing::{info, warn};

use crate::collectors::Collector;
use crate::config::{AgentConfig, LogCollectorConfig, LogSourceConfig};
use crate::schema::AgentEvent;
use crate::telemetry::{metrics::metrics, DropReason};

mod checkpoint;
mod discover;
mod framing;
mod journal;
mod normalize;
mod parser;
mod rate;
mod reader;
mod redact;
mod syslog;

use checkpoint::CheckpointStore;
use rate::TokenBucket;
use reader::FileEngine;

pub struct LogCollector {
    config: Arc<RwLock<AgentConfig>>,
}

impl LogCollector {
    pub fn new(config: Arc<RwLock<AgentConfig>>) -> Self {
        Self { config }
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
        loop {
            let cfg = current_logs_config(&self.config);
            if !cfg.enabled {
                info!("LogCollector: disabled in config — idle");
                tokio::time::sleep(Duration::from_secs(5)).await;
                if tx.is_closed() {
                    return Ok(());
                }
                continue;
            }
            run_session(&tx, &agent_id, &hostname, cfg, Arc::clone(&self.config)).await?;
            if tx.is_closed() {
                return Ok(());
            }
        }
    }
}

fn current_logs_config(cfg: &Arc<RwLock<AgentConfig>>) -> LogCollectorConfig {
    cfg.read()
        .ok()
        .and_then(|c| c.logs.clone())
        .unwrap_or_default()
}

async fn run_session(
    tx: &Sender<AgentEvent>,
    agent_id: &str,
    hostname: &str,
    cfg: LogCollectorConfig,
    live: Arc<RwLock<AgentConfig>>,
) -> Result<()> {
    let sources = discover::resolve_sources(&cfg.sources, cfg.auto_discover);
    if sources.is_empty() {
        warn!("LogCollector: no sources configured or discovered — retrying in 30s");
        tokio::time::sleep(Duration::from_secs(30)).await;
        return Ok(());
    }

    let ckpt_path = CheckpointStore::path();
    let store = Arc::new(Mutex::new(CheckpointStore::load(&ckpt_path)));

    info!(
        sources = sources.len(),
        auto_discover = cfg.auto_discover,
        "LogCollector: starting"
    );
    for s in &sources {
        info!(
            name = %s.name,
            kind = s.kind_label(),
            path = %s.path,
            parser = s.parser_name(),
            "LogCollector: source"
        );
    }

    let file_sources: Vec<LogSourceConfig> = sources
        .iter()
        .filter(|s| s.kind() == crate::config::logs::SourceKind::File)
        .cloned()
        .collect();
    let journal_sources: Vec<LogSourceConfig> = sources
        .iter()
        .filter(|s| s.kind() == crate::config::logs::SourceKind::Journal)
        .cloned()
        .collect();
    let syslog_sources: Vec<LogSourceConfig> = sources
        .iter()
        .filter(|s| s.kind() == crate::config::logs::SourceKind::Syslog)
        .cloned()
        .collect();

    let mut handles = Vec::new();
    for src in journal_sources {
        let cursor = store
            .lock()
            .ok()
            .and_then(|s| s.journal_cursors.get(&src.name).cloned());
        let tx = tx.clone();
        let agent_id = agent_id.to_string();
        let hostname = hostname.to_string();
        let ckpt_path = ckpt_path.clone();
        let rate = src.rate_limit.unwrap_or(cfg.max_events_per_sec());
        handles.push(tokio::spawn(async move {
            journal::run(
                src,
                tx,
                agent_id,
                hostname,
                cursor,
                ckpt_path,
                TokenBucket::new(rate),
            )
            .await;
        }));
    }
    for src in syslog_sources {
        let tx = tx.clone();
        let agent_id = agent_id.to_string();
        let hostname = hostname.to_string();
        let max_line = cfg.max_line_bytes();
        let rate = src.rate_limit.unwrap_or(cfg.max_events_per_sec());
        handles.push(tokio::spawn(async move {
            syslog::run(
                src,
                tx,
                agent_id,
                hostname,
                max_line,
                TokenBucket::new(rate),
            )
            .await;
        }));
    }

    let mut engine = FileEngine::new(
        file_sources,
        cfg.max_line_bytes(),
        cfg.max_open_files(),
        cfg.start_at_beginning(),
        cfg.multiline_max_lines(),
        cfg.multiline_max_bytes(),
    );
    {
        let snapshot = store.lock().unwrap_or_else(|e| e.into_inner()).clone();
        engine.reconcile(&snapshot).await;
    }

    let mut global_limit = TokenBucket::new(cfg.max_events_per_sec());
    let mut last_ckpt = Instant::now();
    let mut last_reconcile = Instant::now();
    let ckpt_every = Duration::from_millis(cfg.checkpoint_interval_ms());
    let mut ticker = tokio::time::interval(Duration::from_millis(250));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        ticker.tick().await;
        if tx.is_closed() {
            persist(&engine, &store, &ckpt_path);
            return Ok(());
        }
        // Hot-reload: a signed config that disables us or rewrites sources
        // tears this session down; the outer loop rebuilds.
        let latest = current_logs_config(&live);
        if !latest.enabled || sources_changed(&cfg, &latest) {
            persist(&engine, &store, &ckpt_path);
            return Ok(());
        }

        if last_reconcile.elapsed() >= Duration::from_secs(5) {
            let snapshot = store.lock().unwrap_or_else(|e| e.into_inner()).clone();
            engine.reconcile(&snapshot).await;
            last_reconcile = Instant::now();
        }

        let mut harvested = engine.poll().await;
        harvested.extend(engine.flush_timeouts());

        for item in harvested {
            if !global_limit.allow() {
                metrics().event_dropped(DropReason::RateLimitApplied);
                continue;
            }
            let parsed = parser::parse(&item.parser, &item.frame.text);
            let src = LogSourceConfig {
                name: item.source_name.clone(),
                source_type: "file".into(),
                path: item.path.to_string_lossy().into_owned(),
                parser: item.parser.clone(),
                unit: String::new(),
                identifier: String::new(),
                multiline: None,
                start_at: String::new(),
                exclude: vec![],
                rate_limit: None,
            };
            let event = normalize::normalize(
                agent_id,
                hostname,
                &src,
                Some(&item.path.to_string_lossy()),
                &item.frame,
                parsed,
            );
            // File logs can wait — blocking here is backpressure, not a
            // kernel-ring-buffer problem. Bound the wait so a wedged consumer
            // cannot pin the reader forever.
            match tokio::time::timeout(Duration::from_millis(500), tx.send(event)).await {
                Ok(Ok(())) => {}
                Ok(Err(_)) => {
                    persist(&engine, &store, &ckpt_path);
                    return Ok(());
                }
                Err(_) => {
                    metrics().event_dropped(DropReason::UserspaceChannelFull);
                }
            }
        }

        if last_ckpt.elapsed() >= ckpt_every {
            persist(&engine, &store, &ckpt_path);
            last_ckpt = Instant::now();
        }

        // Keep journal/syslog tasks from going unnoticed if they all exited.
        handles.retain(|h| !h.is_finished());
    }
}

fn persist(engine: &FileEngine, store: &Arc<Mutex<CheckpointStore>>, path: &std::path::Path) {
    let mut guard = match store.lock() {
        Ok(g) => g,
        Err(e) => e.into_inner(),
    };
    engine.write_checkpoints(&mut guard);
    if let Err(e) = guard.save(path) {
        warn!(error = %e, "LogCollector: checkpoint persist failed");
    }
}

fn sources_changed(a: &LogCollectorConfig, b: &LogCollectorConfig) -> bool {
    a.auto_discover != b.auto_discover || a.sources != b.sources
}
