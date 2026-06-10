//! Windows agent runtime.
//!
//! Reuses the shared, platform-neutral building blocks — [`crate::paths`],
//! [`crate::enrollment`], [`crate::http`], [`crate::config`],
//! [`crate::pipeline`], [`crate::transport`], [`crate::heartbeat`],
//! [`crate::output`] — and wires them to the Windows collector set
//! ([`crate::collectors::windows`]). Online/offline semantics match the Linux
//! agent: no `TRAPD_BACKEND_URL` (or `TRAPD_OFFLINE=1`) means local-only
//! telemetry with every backend channel skipped.

use std::sync::{Arc, Mutex, RwLock};

use anyhow::{Context, Result};
use tracing::{error, info, warn};

use crate::collectors::system::SystemCollector;
use crate::collectors::windows::honeytokens::HoneytokenCollector;
use crate::collectors::windows::process::ProcessCollector;
use crate::collectors::windows::users::UserSessionCollector;
use crate::collectors::Collector;
use crate::config::{self, AgentConfig, ConfigPuller};
use crate::heartbeat::Heartbeat;
use crate::output::OutputMode;
use crate::pipeline::{self, create_pipeline, Spool};
use crate::transport::Transport;
use crate::{env_truthy, handle_event, load_or_create_device_id, paths};

// ── Tracing sinks ─────────────────────────────────────────────────────────────

pub fn init_tracing_stderr() {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("RUST_LOG")
                .unwrap_or_else(|_| "info".into()),
        )
        .init();
}

/// A service has no console, so logs go to `<log_dir>\agent.log` (the NDJSON
/// event log is a separate file, written by [`crate::output`]).
pub fn init_tracing_file() {
    let path = paths::log_dir().join("agent.log");
    let _ = std::fs::create_dir_all(paths::log_dir());
    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path);
    match file {
        Ok(f) => {
            let writer = SharedFile(Arc::new(Mutex::new(f)));
            tracing_subscriber::fmt()
                .with_writer(move || writer.clone())
                .with_ansi(false)
                .with_env_filter(
                    tracing_subscriber::EnvFilter::try_from_env("RUST_LOG")
                        .unwrap_or_else(|_| "info".into()),
                )
                .init();
        }
        // Nowhere to log *that* logging failed; fall back to (invisible)
        // stderr so `tracing` macros stay safe to call.
        Err(_) => init_tracing_stderr(),
    }
}

#[derive(Clone)]
struct SharedFile(Arc<Mutex<std::fs::File>>);

impl std::io::Write for SharedFile {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self.0.lock() {
            Ok(mut f) => f.write(buf),
            Err(_) => Ok(buf.len()),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self.0.lock() {
            Ok(mut f) => f.flush(),
            Err(_) => Ok(()),
        }
    }
}

// ── Environment file ──────────────────────────────────────────────────────────

/// Load `<config_dir>\agent.env` (KEY=VALUE lines, `#` comments) into the
/// process environment. On Linux systemd's `EnvironmentFile=` does this before
/// the agent starts; the SCM has no equivalent, so the agent reads the same
/// file format itself. Existing process/machine environment wins.
fn load_env_file() {
    let path = paths::config_dir().join("agent.env");
    let Ok(contents) = std::fs::read_to_string(&path) else {
        return;
    };
    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            let key = key.trim();
            let value = value.trim().trim_matches('"');
            if !key.is_empty() && std::env::var_os(key).is_none() {
                std::env::set_var(key, value);
            }
        }
    }
    info!(path = %path.display(), "loaded agent.env");
}

// ── Runtime ───────────────────────────────────────────────────────────────────

/// Run the agent until `stop` fires (SCM stop/shutdown or Ctrl-C in console
/// mode) or the event pipeline closes.
pub async fn run_agent(mut stop: tokio::sync::mpsc::UnboundedReceiver<()>) -> Result<()> {
    paths::init_state_dir();
    load_env_file();

    let device_id = load_or_create_device_id()
        .await
        .context("Failed to load/create device_id")?;

    let hostname = hostname::get()
        .map(|h| h.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "unknown".to_string());

    // Online vs offline — same rules as the Linux agent.
    let backend_configured = std::env::var("TRAPD_BACKEND_URL")
        .map(|u| !u.trim().is_empty())
        .unwrap_or(false);
    let offline = env_truthy("TRAPD_OFFLINE") || !backend_configured;

    let (backend_url, agent_id, token) = if offline {
        if !backend_configured {
            warn!(
                "TRAPD_BACKEND_URL is not set — starting in OFFLINE mode. Telemetry is \
                 emitted locally only. Set TRAPD_BACKEND_URL + TRAPD_ENROLL_TOKEN in {}\\agent.env \
                 for a backend-connected agent.",
                paths::config_dir().display()
            );
        } else {
            warn!("TRAPD_OFFLINE set — backend communication disabled (telemetry is local only).");
        }
        (String::new(), device_id.clone(), String::new())
    } else {
        let backend_url = crate::http::normalize_base_url(
            &std::env::var("TRAPD_BACKEND_URL").unwrap_or_default(),
        );
        let creds = crate::enrollment::load_or_enroll(&backend_url, &device_id, &hostname)
            .await
            .context("Failed to obtain agent credentials")?;
        (backend_url, creds.agent_id, creds.agent_secret)
    };

    let output_mode = OutputMode::from_env();

    info!(
        agent_id  = %agent_id,
        device_id = %device_id,
        hostname  = %hostname,
        offline   = offline,
        "TRAPD Agent started (windows)"
    );

    let agent_config: Arc<RwLock<AgentConfig>> = Arc::new(RwLock::new(config::load_persisted()));
    let spool = if offline {
        Spool::in_memory(pipeline::SPOOL_MAX_MEMORY)
    } else {
        Spool::durable(pipeline::spool_max_from_env())
    };
    let ring_buffer: Arc<Mutex<Spool>> = Arc::new(Mutex::new(spool));
    let (tx, mut rx) = create_pipeline();
    let mut handles = Vec::new();

    macro_rules! spawn_collector {
        ($collector:expr) => {{
            let mut c = $collector;
            let tx2 = tx.clone();
            let aid = agent_id.clone();
            let host = hostname.clone();
            let cname = c.name();
            handles.push(tokio::spawn(async move {
                if let Err(e) = c.run(tx2, aid, host).await {
                    error!("{cname} exited with error: {e:#}");
                }
            }));
        }};
    }

    spawn_collector!(SystemCollector::new());
    spawn_collector!(ProcessCollector::new());
    spawn_collector!(UserSessionCollector::new());
    // Honeytoken sentinel: decoy files (ReadDirectoryChangesW) + registry decoys
    // (RegNotifyChangeKeyValue), driven by the signed-config deception policy.
    spawn_collector!(HoneytokenCollector::new(Arc::clone(&agent_config)));

    drop(tx);

    // SIEM forwarder — same best-effort export path as the Linux agent.
    let siem = {
        let cfg = agent_config.read().ok();
        let fwd = cfg
            .map(|c| crate::output::siem::SiemForwarder::from_config(&c, env!("CARGO_PKG_VERSION")))
            .unwrap_or_else(|| {
                crate::output::siem::SiemForwarder::from_config(
                    &AgentConfig::default(),
                    env!("CARGO_PKG_VERSION"),
                )
            });
        if fwd.is_active() {
            info!("SIEM forwarding active");
        }
        fwd
    };

    let buf_for_consumer = Arc::clone(&ring_buffer);
    let mode = output_mode;
    let mut consumer = tokio::spawn(async move {
        while let Some(event) = rx.recv().await {
            handle_event(&event, &mode, &buf_for_consumer).await;
            siem.forward(&event).await;
        }
    });

    if !offline {
        let transport =
            Transport::new(Arc::clone(&ring_buffer), backend_url.clone(), token.clone())?;
        tokio::spawn(async move { transport.run().await });

        let config_puller = ConfigPuller::new(
            Arc::clone(&agent_config),
            &backend_url,
            &agent_id,
            token.clone(),
        )?;
        tokio::spawn(async move { config_puller.run().await });

        let heartbeat = Heartbeat::new(
            &backend_url,
            agent_id.clone(),
            token,
            hostname.clone(),
            Arc::clone(&agent_config),
        )?;
        tokio::spawn(async move { heartbeat.run().await });
    }

    tokio::select! {
        _ = stop.recv() => {
            info!("Stop requested, shutting down");
            for handle in &handles {
                handle.abort();
            }
        }
        _ = &mut consumer => {
            info!("Consumer task exited");
        }
    }

    consumer.await.ok();
    info!("Shutdown complete");
    Ok(())
}
