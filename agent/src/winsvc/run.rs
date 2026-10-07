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
use crate::{emit_finding, env_truthy, handle_event, load_or_create_device_id, paths};

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

fn load_msi_config() {
    use crate::collectors::windows::registry;
    use windows_sys::Win32::System::Registry::RRF_SUBKEY_WOW6464KEY;
    for (value_name, env_name) in [
        ("BackendUrl", "TRAPD_BACKEND_URL"),
        ("EnrollToken", "TRAPD_ENROLL_TOKEN"),
        ("AllowSystemRoots", "TRAPD_TLS_ALLOW_SYSTEM_ROOTS"),
    ] {
        if std::env::var_os(env_name).is_none() {
            if let Some(value) =
                registry::string("SOFTWARE\\TRAPD\\Agent", value_name, RRF_SUBKEY_WOW6464KEY)
            {
                if !value.trim().is_empty() {
                    std::env::set_var(env_name, value);
                }
            }
        }
    }
    if std::env::var_os("TRAPD_OUTPUT").is_none() {
        std::env::set_var("TRAPD_OUTPUT", "file");
    }
}

// ── Runtime ───────────────────────────────────────────────────────────────────

/// Run the agent until `stop` fires (SCM stop/shutdown or Ctrl-C in console
/// mode) or the event pipeline closes.
pub async fn run_agent(mut stop: tokio::sync::mpsc::UnboundedReceiver<()>) -> Result<()> {
    load_env_file();
    load_msi_config();
    paths::init_state_dir();

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
        // Pairing can wait for a person indefinitely. The SCM stop (service
        // stop, MSI upgrade/removal) must still be honoured during that wait,
        // otherwise Windows Installer's ServiceControl hangs on an unpaired
        // agent. Dropping the future cancels pairing and removes pairing.txt.
        let creds = tokio::select! {
            creds = crate::enrollment::load_or_enroll(&backend_url, &device_id, &hostname) => {
                creds.context("Failed to obtain agent credentials")?
            }
            _ = stop.recv() => {
                info!("stop requested before enrollment completed");
                return Ok(());
            }
        };
        (
            backend_url,
            creds.agent_id.clone(),
            creds.agent_secret.clone(),
        )
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
                    crate::telemetry::metrics::metrics().collector_failed();
                    if cname == "WindowsProcessCollector" {
                        crate::telemetry::metrics::metrics()
                            .set_collector_mode(crate::telemetry::metrics::CollectorMode::Failed);
                    }
                    error!("{cname} exited with error: {e:#}");
                }
            }));
        }};
    }

    spawn_collector!(SystemCollector::new());
    // Real-time ETW sensor (process, image load, network, DNS). Falls back to
    // polling when disabled by config or when the session cannot start; the
    // ETW collector returns an error, which the poller's latch then covers.
    let etw_on = agent_config.read().map(|c| c.etw_enabled).unwrap_or(true);
    if etw_on {
        spawn_collector!(crate::collectors::windows::etw::EtwCollector);
    }
    if !etw_on {
        spawn_collector!(ProcessCollector::new());
        spawn_collector!(crate::collectors::windows::network::NetworkCollector);
    }
    spawn_collector!(UserSessionCollector::new());
    spawn_collector!(
        crate::collectors::windows::eventlog::EventLogCollector::new(Arc::clone(&agent_config))
    );
    spawn_collector!(
        crate::collectors::windows::filesystem::FilesystemCollector::new(Arc::clone(&agent_config))
    );
    // Honeytoken sentinel: decoy files (ReadDirectoryChangesW) + registry decoys
    // (RegNotifyChangeKeyValue), driven by the signed-config deception policy.
    spawn_collector!(HoneytokenCollector::new(Arc::clone(&agent_config)));

    drop(tx);

    let engine = Arc::new(crate::detection::DetectionEngine::new(
        agent_id.clone(),
        hostname.clone(),
    ));
    if let Ok(cfg) = agent_config.read() {
        engine.reload_sigma(&cfg.sigma_rules);
        engine.set_sigma_enabled(cfg.sigma_enabled);
        engine.set_anomaly_enabled(cfg.anomaly_detection_enabled);
        engine.set_suppressions(cfg.detection_suppressions.clone());
        engine.set_rule_modes(&cfg.rule_modes);
        crate::deception::activity::set_enabled(cfg.deception_activity_learning_enabled);
    }
    Arc::clone(&engine).spawn_ioc_reloader(300);

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
    let consumer_engine = Arc::clone(&engine);
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel();
    let mut consumer = tokio::spawn(async move {
        let mut shutting_down = false;
        // Aggregate updates for repeated findings are released on this tick.
        let mut flush_tick = tokio::time::interval(std::time::Duration::from_secs(30));
        flush_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            let event = tokio::select! {
                _ = &mut shutdown_rx, if !shutting_down => {
                    rx.close();
                    shutting_down = true;
                    continue;
                }
                event = rx.recv() => match event { Some(event) => event, None => break },
                _ = flush_tick.tick() => {
                    for f in consumer_engine.flush_findings(false) {
                        emit_finding(f, None, &mode, &buf_for_consumer, &siem).await;
                    }
                    continue;
                }
            };
            if matches!(event.class, crate::schema::EventClass::Detection) {
                for f in consumer_engine.admit_external(event) {
                    emit_finding(f, None, &mode, &buf_for_consumer, &siem).await;
                }
                continue;
            }
            handle_event(&event, &mode, &buf_for_consumer).await;
            siem.forward(&event).await;
            for f in consumer_engine.admit(consumer_engine.inspect(&event)) {
                emit_finding(f, None, &mode, &buf_for_consumer, &siem).await;
            }
        }
        for f in consumer_engine.flush_findings(true) {
            emit_finding(f, None, &mode, &buf_for_consumer, &siem).await;
        }
    });

    let started = std::time::Instant::now();
    let telemetry_engine = Arc::clone(&engine);
    handles.push(tokio::spawn(async move {
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(10));
        loop {
            ticker.tick().await;
            crate::deception::activity::persist();
            telemetry_engine.persist_baseline();
            let report =
                crate::telemetry::TelemetryReport::capture(offline, started.elapsed().as_secs());
            if let Err(e) = report.write_atomic(&crate::telemetry::TelemetryReport::default_path())
            {
                warn!(error = %e, "could not publish telemetry report");
            }
        }
    }));

    let inventory = crate::inventory::InventoryReporter::new(
        &backend_url,
        agent_id.clone(),
        device_id.clone(),
        token.clone(),
        hostname.clone(),
        offline,
        Arc::clone(&agent_config),
    )?;
    handles.push(tokio::spawn(async move { inventory.run().await }));

    if !offline {
        let transport =
            Transport::new(Arc::clone(&ring_buffer), backend_url.clone(), token.clone())?;
        handles.push(tokio::spawn(async move { transport.run().await }));

        let config_engine = Arc::clone(&engine);
        let config_puller = ConfigPuller::new(
            Arc::clone(&agent_config),
            &backend_url,
            &agent_id,
            token.clone(),
        )?
        .with_apply_hook(Arc::new(move |cfg: &AgentConfig| {
            config_engine.reload_sigma(&cfg.sigma_rules);
            config_engine.set_sigma_enabled(cfg.sigma_enabled);
            config_engine.set_anomaly_enabled(cfg.anomaly_detection_enabled);
            config_engine.set_suppressions(cfg.detection_suppressions.clone());
            config_engine.set_rule_modes(&cfg.rule_modes);
            crate::deception::activity::set_enabled(cfg.deception_activity_learning_enabled);
        }));
        handles.push(tokio::spawn(async move { config_puller.run().await }));

        let heartbeat = Heartbeat::new(
            &backend_url,
            agent_id.clone(),
            token,
            hostname.clone(),
            Arc::clone(&agent_config),
        )?;
        handles.push(tokio::spawn(async move { heartbeat.run().await }));
    }

    let consumer_finished = tokio::select! {
        _ = stop.recv() => {
            info!("Stop requested, shutting down");
            for handle in &handles {
                handle.abort();
            }
            false
        }
        _ = &mut consumer => {
            info!("Consumer task exited");
            true
        }
    };

    for handle in &handles {
        handle.abort();
    }
    // Close the receiver, reject further sends and drain already received
    // events before checkpointing, even if native monitor threads hold senders.
    let _ = shutdown_tx.send(());
    if !consumer_finished
        && tokio::time::timeout(std::time::Duration::from_secs(10), &mut consumer)
            .await
            .is_err()
    {
        consumer.abort();
        crate::telemetry::metrics::metrics()
            .event_dropped(crate::telemetry::DropReason::InternalError);
        warn!("event consumer did not drain before shutdown deadline");
    }
    if let Ok(mut spool) = ring_buffer.lock() {
        spool.checkpoint();
    }
    info!("Shutdown complete");
    Ok(())
}
