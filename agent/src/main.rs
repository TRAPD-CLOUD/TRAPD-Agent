// Shared modules (deception data model, signed-command verification, inventory
// types) are compiled in full on Windows so the wire formats stay identical to
// the Linux agent, but large parts have no Windows caller yet. Allow the
// dead-code lint there rather than fragmenting shared modules with per-item
// cfg gates.
#![cfg_attr(windows, allow(dead_code))]

#[cfg(target_os = "linux")]
use std::sync::RwLock;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use tokio::fs;
use tracing::{error, info, warn};
use uuid::Uuid;

mod collectors;
mod config;
mod deception;
#[cfg(target_os = "linux")]
mod detection;
mod enrollment;
#[cfg(target_os = "linux")]
mod forensics;
mod heartbeat;
mod http;
mod inventory;
mod output;
mod paths;
mod pipeline;
mod prevention;
mod schema;
#[cfg(target_os = "linux")]
mod selfprotect;
mod telemetry;
mod transport;
#[cfg(windows)]
mod winsvc;

#[cfg(target_os = "linux")]
use collectors::linux::{
    agent_protect::AgentProtectCollector, authlog::AuthLogCollector, ebpf_exec::EbpfExecCollector,
    ebpf_syscalls::EbpfSyscallCollector, filesystem::FilesystemCollector,
    network::NetworkCollector, process::ProcessCollector,
};
// Only consumed by the Linux `async fn main`; the Windows runtime (winsvc::run)
// imports these itself, so gate them to avoid an unused-import warning there.
#[cfg(target_os = "linux")]
use collectors::system::SystemCollector;
#[cfg(target_os = "linux")]
use collectors::Collector;
#[cfg(target_os = "linux")]
use config::{AgentConfig, ConfigPuller};
#[cfg(target_os = "linux")]
use heartbeat::Heartbeat;
use output::{write_event, OutputMode};
#[cfg(target_os = "linux")]
use pipeline::create_pipeline;
use pipeline::Spool;
#[cfg(target_os = "linux")]
use transport::Transport;

/// Windows entry point: CLI verbs (`install` / `uninstall` / `run`) plus the
/// Service Control Manager dispatch path live in [`winsvc`]; the shared
/// telemetry pipeline (enrollment, heartbeat, collectors, transport) is reused
/// from the same modules the Linux agent uses.
#[cfg(windows)]
fn main() -> Result<()> {
    winsvc::entry()
}

#[cfg(target_os = "linux")]
#[tokio::main]
async fn main() -> Result<()> {
    if let Some(monitored_pid) = selfprotect::watchdog::detect() {
        selfprotect::watchdog::run_watchdog(monitored_pid);
    }

    if std::env::args().nth(1).as_deref() == Some("--version") {
        println!("trapd-agent v{}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }

    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("RUST_LOG")
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    // `trapd-agent uninstall` — remove every host artifact the agent planted.
    // On Windows that is the honeytoken decoy files + the registry decoys;
    // Linux honeytokens are deployed/revoked over the signed command channel,
    // so there is nothing to clean up locally.
    if std::env::args().nth(1).as_deref() == Some("uninstall") {
        #[cfg(target_os = "windows")]
        {
            paths::init_state_dir();
            collectors::windows::honeytokens::uninstall(&config::load_persisted());
            info!("Uninstall cleanup complete (honeytoken files + registry decoys removed)");
        }
        #[cfg(not(target_os = "windows"))]
        info!("Uninstall: no local honeytoken artifacts on this platform — nothing to do");
        return Ok(());
    }

    // `trapd-agent diagnostics telemetry` — report on the running agent's
    // pipeline. Read-only and side-effect free, so it must run before any of
    // the start-up work below (which would fight the live agent for the state
    // directory).
    {
        let args: Vec<String> = std::env::args().collect();
        if args.get(1).map(String::as_str) == Some("diagnostics") {
            paths::init_state_dir();
            return match args.get(2).map(String::as_str) {
                Some("telemetry") => {
                    print!("{}", telemetry::diagnostics::run());
                    Ok(())
                }
                other => {
                    eprintln!(
                        "unknown diagnostics topic {:?}\n\nusage: trapd-agent diagnostics telemetry",
                        other.unwrap_or("(none)")
                    );
                    std::process::exit(2);
                }
            };
        }
    }

    selfprotect::kernel_hardening::audit();

    if let Err(e) = selfprotect::binary_integrity::check() {
        error!("{e:#}");
        anyhow::bail!("{e}");
    }

    selfprotect::watchdog::spawn_detached();

    // Resolve & create the (HOME-independent) state directory up front so every
    // later component agrees on where identity/credentials live.
    paths::init_state_dir();

    let device_id = load_or_create_device_id()
        .await
        .context("Failed to load/create device_id")?;

    let hostname = hostname::get()
        .map(|h| h.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "unknown".to_string());

    // ── Online vs offline ────────────────────────────────────────────────────
    // Offline/test mode lets the agent run on any Linux box with no backend:
    // telemetry is emitted locally (stdout/file) and all backend channels
    // (enrollment, ingest, heartbeat, config-pull, command-pull) are skipped.
    // Enabled explicitly with TRAPD_OFFLINE=1, or implicitly when no backend
    // URL is configured (so a bare `trapd-agent` run just works for testing).
    let backend_configured = std::env::var("TRAPD_BACKEND_URL")
        .map(|u| !u.trim().is_empty())
        .unwrap_or(false);
    let offline = env_truthy("TRAPD_OFFLINE") || !backend_configured;

    let (backend_url, agent_id, token, project_id) = if offline {
        if !backend_configured {
            warn!(
                "TRAPD_BACKEND_URL is not set — starting in OFFLINE mode. Telemetry is \
                 emitted locally only. Set TRAPD_BACKEND_URL + TRAPD_ENROLL_TOKEN in {}/agent.env \
                 for a backend-connected agent.",
                paths::config_dir().display()
            );
        } else {
            warn!("TRAPD_OFFLINE set — backend communication disabled (telemetry is local only).");
        }
        (
            String::new(),
            device_id.clone(),
            String::new(),
            "offline".to_string(),
        )
    } else {
        let backend_url =
            http::normalize_base_url(&std::env::var("TRAPD_BACKEND_URL").unwrap_or_default());
        let creds = enrollment::load_or_enroll(&backend_url, &device_id, &hostname)
            .await
            .context("Failed to obtain agent credentials")?;
        let agent_id = creds.agent_id.clone();
        let token = creds.agent_secret.clone();
        let project_id = creds.project_id.clone();
        (backend_url, agent_id, token, project_id)
    };

    let output_mode = OutputMode::from_env();
    let output_label = match output_mode {
        OutputMode::Stdout => "stdout",
        OutputMode::File => "file",
    };

    info!(
        agent_id   = %agent_id,
        device_id  = %device_id,
        hostname   = %hostname,
        project_id = %project_id,
        offline    = offline,
        output     = %output_label,
        "TRAPD Agent started"
    );

    // Start from the last verified config on disk (defaults on first run), so a
    // restart keeps the real configuration even though the signed-config channel
    // re-serves it with an already-accepted (and thus replay-rejected) issued_at.
    let agent_config: Arc<RwLock<AgentConfig>> = Arc::new(RwLock::new(config::load_persisted()));
    // Backend outbox. Online it is disk-backed (survives crash/restart, replays
    // on the next run); offline it is purely in-memory (the NDJSON output is the
    // system of record).
    let spool = if offline {
        Spool::in_memory(pipeline::SPOOL_MAX_MEMORY)
    } else {
        Spool::durable(pipeline::spool_max_from_env())
            .with_max_bytes(pipeline::spool_max_bytes_from_env())
    };
    if spool.is_degraded() {
        warn!("spool has no durable backing — unacknowledged events will not survive a restart");
    }
    let ring_buffer: Arc<Mutex<Spool>> = Arc::new(Mutex::new(spool));
    let (tx, mut rx) = create_pipeline();
    let mut handles = Vec::new();

    // ── Prevention subsystem (active response) ────────────────────────────────
    // Requires the backend (signed command channel), so it is skipped offline.
    let prevention_enabled = agent_config
        .read()
        .map(|c| c.prevention_enabled)
        .unwrap_or(true);
    // Shared kick from the prevention engine to the eBPF reconciler + the
    // honeytoken health checker: pulsed after every deploy/revoke so arming and
    // on-disk verification happen within ms instead of up to a full tick later.
    let reconcile_signal = Arc::new(tokio::sync::Notify::new());
    let prev_event_tx = if prevention_enabled && !offline {
        match start_prevention(
            &backend_url,
            &agent_id,
            &token,
            &hostname,
            tx.clone(),
            Arc::clone(&agent_config),
            Arc::clone(&reconcile_signal),
        )
        .await
        {
            Ok(tx) => {
                info!("Prevention subsystem started");
                Some(tx)
            }
            Err(e) => {
                warn!(error = %e, "prevention subsystem failed to start — continuing in telemetry-only mode");
                None
            }
        }
    } else {
        if offline {
            info!("Prevention subsystem disabled (offline mode)");
        } else {
            info!("Prevention subsystem disabled in config");
        }
        None
    };

    macro_rules! spawn_collector {
        ($collector:expr) => {{
            let mut c = $collector;
            let tx2 = tx.clone();
            let aid = agent_id.clone();
            let host = hostname.clone();
            let cname = c.name();
            handles.push(tokio::spawn(async move {
                if let Err(e) = c.run(tx2, aid, host).await {
                    // A collector that exits is a blind spot, so it is counted
                    // and surfaced in health rather than only logged.
                    error!("{cname} exited with error: {e:#}");
                    telemetry::metrics::metrics().collector_failed();
                }
            }));
        }};
    }

    #[cfg(target_os = "linux")]
    {
        let ebpf_exec = EbpfExecCollector::new();
        if ebpf_exec.is_available() {
            info!("eBPF exec tracer available — spawning EbpfExecCollector");
            spawn_collector!(ebpf_exec);
        } else {
            warn!("eBPF binary not found — exec events will be detected by polling only.");
        }

        let ebpf_syscalls = EbpfSyscallCollector::new()
            .with_config(Arc::clone(&agent_config))
            .with_reconcile_signal(Arc::clone(&reconcile_signal));
        if ebpf_syscalls.is_available() {
            info!("eBPF syscall tracer available — spawning EbpfSyscallCollector");
            spawn_collector!(ebpf_syscalls);
        } else {
            warn!("eBPF binary not found — syscall events unavailable.");
        }

        spawn_collector!(SystemCollector::new());
        spawn_collector!(ProcessCollector::new());
        spawn_collector!(NetworkCollector::new());
        spawn_collector!(AuthLogCollector::new());
        spawn_collector!(FilesystemCollector::new(Arc::clone(&agent_config)));
        spawn_collector!(AgentProtectCollector::new());
        spawn_collector!(collectors::linux::memscan::MemScanCollector::new(
            Arc::clone(&agent_config)
        ));
        // Passive DNS-response + TLS-handshake capture (AF_PACKET). Best-effort:
        // needs CAP_NET_RAW; logs and exits cleanly without it while the rest run.
        spawn_collector!(collectors::linux::packet_capture::PacketCaptureCollector::new());

        let tx_ap = tx.clone();
        let aid = agent_id.clone();
        let host = hostname.clone();
        tokio::spawn(async move {
            selfprotect::anti_ptrace::run(tx_ap, aid, host).await;
        });
    }

    // Windows: OS-neutral system snapshots, a sysinfo-based process collector
    // (create/terminate telemetry feeding the shared detection engine), and the
    // honeytoken sentinel (decoy files via ReadDirectoryChangesW + registry
    // decoys via RegNotifyChangeKeyValue). All of it emits the same OS-neutral
    // events as the Linux agent, through the same pipeline → spool → ingest path.
    #[cfg(target_os = "windows")]
    {
        spawn_collector!(SystemCollector::new());
        spawn_collector!(collectors::windows::process::ProcessCollector::new());
        spawn_collector!(collectors::windows::honeytokens::HoneytokenCollector::new(
            Arc::clone(&agent_config)
        ));
    }

    drop(tx);

    // Local detection engine — behavioural + IOC analytics over every event.
    // Platform-neutral, so the future Windows agent reuses it unchanged.
    let engine = std::sync::Arc::new(detection::DetectionEngine::new(
        agent_id.clone(),
        hostname.clone(),
    ));
    // Compile Sigma rules = on-disk `<config>/sigma/` baseline + any inline
    // rules carried in the (last-known-good) config, so detections are active
    // from boot before the first backend config pull.
    {
        let (docs, anomaly) = agent_config
            .read()
            .map(|c| (c.sigma_rules.clone(), c.anomaly_detection_enabled))
            .unwrap_or_default();
        engine.reload_sigma(&docs);
        engine.set_anomaly_enabled(anomaly);
    }
    info!(
        iocs = engine.ioc_count(),
        sigma = engine.sigma_count(),
        "Detection engine started"
    );
    // Pick up threat-intel feed updates without a restart.
    Arc::clone(&engine).spawn_ioc_reloader(300);

    // SIEM forwarder — best-effort export of every event (and detection) to
    // external syslog/HEC infrastructure, in parallel with backend ingest.
    let siem = {
        let cfg = agent_config.read().ok();
        let fwd = cfg
            .map(|c| output::siem::SiemForwarder::from_config(&c, env!("CARGO_PKG_VERSION")))
            .unwrap_or_else(|| {
                output::siem::SiemForwarder::from_config(
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
    let prev_tx = prev_event_tx.clone();
    let det_engine = Arc::clone(&engine);
    let siem_fwd = siem.clone();
    let mut consumer = tokio::spawn(async move {
        while let Some(event) = rx.recv().await {
            // Forwarding to prevention is best-effort — a stalled enforcement
            // engine must not stall telemetry — but a dropped tee is still
            // counted rather than swallowed.
            if let Some(p) = &prev_tx {
                pipeline::try_tee(p, event.clone(), "prevention_tee");
                telemetry::metrics::metrics()
                    .set_detection_queue_depth(p.max_capacity().saturating_sub(p.capacity()) as u64);
            }
            handle_event(&event, &mode, &buf_for_consumer).await;
            siem_fwd.forward(&event).await;

            // Run detections and treat each finding as a first-class event:
            // persisted, buffered for the backend, and forwarded to prevention.
            for det in det_engine.inspect(&event) {
                if let Some(p) = &prev_tx {
                    pipeline::try_tee(p, det.clone(), "prevention_tee");
                }
                handle_event(&det, &mode, &buf_for_consumer).await;
                siem_fwd.forward(&det).await;
            }
        }
    });

    // Publish the telemetry report the `diagnostics telemetry` command reads.
    // Runs in both modes: an offline agent still needs its queue and drop
    // counters to be inspectable.
    {
        let started = std::time::Instant::now();
        let report_path = telemetry::TelemetryReport::default_path();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(std::time::Duration::from_secs(10));
            loop {
                ticker.tick().await;
                let report =
                    telemetry::TelemetryReport::capture(offline, started.elapsed().as_secs());
                if let Err(e) = report.write_atomic(&report_path) {
                    // Losing the report costs visibility, not telemetry, so it
                    // must never take the agent down with it.
                    warn!(error = %e, "could not publish the telemetry report");
                }
            }
        });
    }

    // Asset inventory reporter — runs in BOTH modes.  Online it POSTs to
    // `/api/v1/agents/{id}/inventory`; offline it writes <state>/inventory.json
    // so the asset profile is still inspectable on a test box.
    {
        let inv = inventory::InventoryReporter::new(
            &backend_url,
            agent_id.clone(),
            device_id.clone(),
            token.clone(),
            hostname.clone(),
            offline,
            Arc::clone(&agent_config),
        )?;
        tokio::spawn(async move { inv.run().await });
    }

    // Backend channels only run when connected; offline = pure local telemetry.
    if !offline {
        // All three open the (fail-closed) pinned control channel; a pinning
        // misconfig surfaces here as a hard error rather than a silent
        // fall-back to the system trust store.
        let transport =
            Transport::new(Arc::clone(&ring_buffer), backend_url.clone(), token.clone())?;
        tokio::spawn(async move { transport.run().await });

        // Recompile Sigma rules whenever a freshly-signed config is applied, so
        // the backend can ship detections over the config channel live.
        let sigma_engine = Arc::clone(&engine);
        let config_puller = ConfigPuller::new(
            Arc::clone(&agent_config),
            &backend_url,
            &agent_id,
            token.clone(),
        )?
        .with_apply_hook(std::sync::Arc::new(move |cfg: &AgentConfig| {
            sigma_engine.reload_sigma(&cfg.sigma_rules);
            sigma_engine.set_anomaly_enabled(cfg.anomaly_detection_enabled);
        }));
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
        _ = tokio::signal::ctrl_c() => {
            info!("Received SIGINT, shutting down");
            for handle in &handles {
                handle.abort();
            }
        }
        _ = &mut consumer => {
            info!("Consumer task exited");
        }
    }

    consumer.await.ok();

    // Reconcile the journal to exactly the un-acknowledged set, so the next
    // start replays those and nothing else.
    match ring_buffer.lock() {
        Ok(mut spool) => {
            spool.checkpoint();
            info!(
                pending = spool.len(),
                "spool checkpointed — pending events will be replayed on the next start"
            );
        }
        Err(e) => error!("could not checkpoint the spool on shutdown: {e}"),
    }

    info!("Shutdown complete");
    Ok(())
}

/// Persist one event locally and enqueue it for the backend.
///
/// This is the single point every event passes through on its way into the
/// pipeline — collector telemetry *and* detection-engine findings alike — so it
/// is where "accepted" is counted. Counting per-collector instead would miss
/// findings, and the accounting invariant (`accepted == acknowledged + queued +
/// dropped`) would silently stop holding.
async fn handle_event(event: &schema::AgentEvent, mode: &OutputMode, buf: &Arc<Mutex<Spool>>) {
    pipeline::accepted();
    if let Err(err) = write_event(event, mode).await {
        error!("Failed to write event: {err}");
    }
    // Spool::push() does synchronous disk I/O (journal append, and
    // periodically an fsync — see pipeline::spool::FSYNC_EVERY). handle_event
    // runs inside the single async consumer task, so doing that inline would
    // block the executor thread and stall every other task on it; offload it
    // to the blocking thread pool instead.
    let buf = Arc::clone(buf);
    let event = event.clone();
    if let Err(e) = tokio::task::spawn_blocking(move || match buf.lock() {
        // A rejected push is already counted against a named drop reason by the
        // spool itself, so there is nothing to attribute here.
        Ok(mut b) => {
            let _ = b.push(event);
        }
        Err(e) => {
            error!("Spool mutex poisoned: {e}");
            telemetry::metrics::metrics().event_dropped(telemetry::DropReason::InternalError);
        }
    })
    .await
    {
        error!("spool push task panicked: {e}");
    }
}

/// Build / spawn the prevention subsystem.  Returns the sender used by the
/// tee in the main consumer to forward events to the enforcement engine.
#[cfg(target_os = "linux")]
async fn start_prevention(
    backend_url: &str,
    agent_id: &str,
    token: &str,
    hostname: &str,
    pipeline_tx: tokio::sync::mpsc::Sender<schema::AgentEvent>,
    cfg_handle: Arc<RwLock<AgentConfig>>,
    reconcile_signal: Arc<tokio::sync::Notify>,
) -> Result<tokio::sync::mpsc::Sender<schema::AgentEvent>> {
    use prevention::{
        audit::AuditEmitter,
        command_pubkey_path,
        command_puller::CommandPuller,
        commands::Verifier,
        engine::{Engine, EngineConfig},
        local_policy_path,
        network::{detect_backend, ensure_chains},
        nonce_store,
        policy::{load_local_policy, PolicyHandle},
    };

    prevention::ensure_state_dirs();

    let (event_tx, event_rx) = tokio::sync::mpsc::channel::<schema::AgentEvent>(1024);

    let audit = AuditEmitter::new(pipeline_tx.clone(), agent_id.into(), hostname.into());

    let store = load_local_policy(&local_policy_path()).context("load /etc/trapd/policy.json")?;
    let policy = PolicyHandle::new(store);

    let backend = detect_backend();
    if let Err(e) = ensure_chains(backend) {
        warn!(error = %e, "could not initialise firewall chains — IP/isolation actions will fail");
    }

    let allowlist = build_isolation_allowlist(backend_url, &cfg_handle);

    let engine_cfg = EngineConfig {
        net_backend: backend,
        default_isolation_allowlist: allowlist,
    };

    let verifier = match Verifier::new(&command_pubkey_path(), agent_id.to_string(), &nonce_store())
    {
        Ok(v) => Some(Arc::new(v)),
        Err(e) => {
            warn!(error = %e, "command verifier unavailable — backend commands will not be processed");
            None
        }
    };

    // Register of honeytokens this host has deployed (deploy/revoke lifecycle).
    let honeytokens = Arc::new(deception::HoneytokenStore::load());
    info!(count = honeytokens.len(), "Honeytoken register loaded");

    // Periodic on-disk verification: confirms each planted token still exists
    // (and is unchanged), so the backend can flag one deleted/tampered
    // out-of-band — i.e. without tripping the eBPF access detector. Also kicked
    // immediately after a deploy/revoke via `reconcile_signal`.
    spawn_honeytoken_health(
        audit.clone(),
        Arc::clone(&honeytokens),
        Arc::clone(&reconcile_signal),
    );

    let engine = Arc::new(
        Engine::new(
            policy.clone(),
            audit.clone(),
            engine_cfg,
            Arc::clone(&honeytokens),
            Arc::clone(&cfg_handle),
        )
        .with_reconcile_signal(reconcile_signal),
    );
    Arc::clone(&engine).spawn_event_loop(event_rx);

    if let Some(v) = verifier {
        let (cmd_tx, cmd_rx) = tokio::sync::mpsc::channel(64);
        let poll_secs = cfg_handle
            .read()
            .map(|c| c.command_poll_interval_secs)
            .unwrap_or(5);
        let puller = CommandPuller::new(
            backend_url,
            agent_id,
            token.to_string(),
            v,
            audit.clone(),
            cmd_tx,
            poll_secs,
        )?;
        tokio::spawn(async move { puller.run().await });
        Arc::clone(&engine).spawn_command_loop(cmd_rx);
    }

    let lsm = prevention::lsm_loader::LsmHandle::try_load();
    lsm.sync(&policy).await;

    Ok(event_tx)
}

/// Periodic honeytoken health/existence verifier.
///
/// Answers a question the eBPF access detector cannot: *is the planted token
/// still there, and unchanged?* — catching a token deleted or edited
/// out-of-band (while the agent was down, or by a tool the content-read gate
/// does not cover). Emits one `prevention.honeytoken_health` audit event per
/// registered token each pass, which the backend correlates into the token's
/// `file_status` / `last_verified_at`. Runs on a modest interval and also fires
/// immediately on a deploy/revoke kick so a fresh token is verified within ms.
#[cfg(target_os = "linux")]
fn spawn_honeytoken_health(
    audit: prevention::audit::AuditEmitter,
    store: Arc<deception::HoneytokenStore>,
    reconcile_signal: Arc<tokio::sync::Notify>,
) {
    use schema::{EventAction, Severity};
    // Slow enough to stay near-silent on a steady host, fresh enough that an
    // out-of-band deletion surfaces within a minute.
    const HEALTH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(HEALTH_INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = ticker.tick() => {}
                _ = reconcile_signal.notified() => {}
            }
            // The engine mutates this same register on deploy/revoke, so the live
            // Arc already reflects the current set of planted tokens.
            for rec in store.list() {
                let health = deception::verify_record(&rec);
                let severity = if health.present && !health.modified {
                    Severity::Info
                } else {
                    Severity::High
                };
                let reason = match health.status_label() {
                    "missing" => format!("honeytoken '{}' is missing from disk", rec.kind),
                    "modified" => {
                        format!("honeytoken '{}' content changed since deployment", rec.kind)
                    }
                    _ => format!("honeytoken '{}' present and unchanged", rec.kind),
                };
                audit.emit(
                    EventAction::HoneytokenHealth,
                    severity,
                    "honeytoken_health",
                    rec.path.clone(),
                    health.present && !health.modified,
                    reason,
                    None,
                    // No command_id: health is autonomous telemetry, not a
                    // command result — leaving it out keeps the backend from
                    // mistaking it for the deploy command's completion.
                    None,
                    serde_json::json!({
                        "id": rec.id,
                        "kind": rec.kind,
                        "present": health.present,
                        "modified": health.modified,
                        "file_status": health.status_label(),
                        "expected_sha256": rec.sha256,
                        "actual_sha256": health.actual_sha256,
                    }),
                );
            }
        }
    });
}

#[cfg(target_os = "linux")]
fn build_isolation_allowlist(
    backend_url: &str,
    cfg: &Arc<RwLock<AgentConfig>>,
) -> Vec<std::net::IpAddr> {
    let mut out: Vec<std::net::IpAddr> = Vec::new();

    if let Some(host) = backend_host(backend_url) {
        if let Ok(ip) = host.parse::<std::net::IpAddr>() {
            out.push(ip);
        } else if let Ok(addrs) = std::net::ToSocketAddrs::to_socket_addrs(&format!("{host}:443")) {
            for a in addrs {
                out.push(a.ip());
            }
        }
    }

    if let Ok(c) = cfg.read() {
        for raw in &c.isolation_allowlist_ips {
            if let Ok(ip) = raw.parse::<std::net::IpAddr>() {
                if !out.contains(&ip) {
                    out.push(ip);
                }
            }
        }
    }

    out
}

#[cfg(target_os = "linux")]
fn backend_host(url: &str) -> Option<String> {
    let s = url.split("://").nth(1).unwrap_or(url);
    let s = s.split('/').next().unwrap_or(s);
    let s = s.split(':').next().unwrap_or(s);
    if s.is_empty() {
        None
    } else {
        Some(s.to_string())
    }
}

/// Interpret an environment variable as a boolean flag.
/// True for `1`, `true`, `yes`, `on` (case-insensitive); false otherwise.
fn env_truthy(key: &str) -> bool {
    std::env::var(key)
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

/// Load the persistent device identity, generating one on first run.
///
/// Stored in the state directory (default `/var/lib/trapd/device_id`) which is
/// resolved independently of `$HOME`, so this works under a hardened systemd
/// unit where `HOME` may be unset.  Written atomically at mode `0600`.
async fn load_or_create_device_id() -> Result<String> {
    let file = paths::device_id_file();

    if file.exists() {
        let raw = fs::read_to_string(&file)
            .await
            .context("Failed to read device_id file")?;
        let trimmed = raw.trim();
        if Uuid::parse_str(trimmed).is_ok() {
            return Ok(trimmed.to_string());
        }
        warn!(path = %file.display(), "device_id file invalid — regenerating");
    }

    let id = Uuid::new_v4().to_string();
    let bytes = id.as_bytes().to_vec();
    let path = file.clone();
    tokio::task::spawn_blocking(move || paths::write_atomic(&path, &bytes, 0o600))
        .await
        .context("join device_id write task")?
        .context("Failed to write device_id file")?;
    info!("Generated new device_id: {id}");
    Ok(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_truthy_recognises_true_values() {
        for v in ["1", "true", "TRUE", "Yes", "on", " on "] {
            std::env::set_var("TRAPD_TEST_FLAG", v);
            assert!(env_truthy("TRAPD_TEST_FLAG"), "expected {v:?} to be truthy");
        }
        std::env::remove_var("TRAPD_TEST_FLAG");
    }

    #[test]
    fn env_truthy_recognises_false_values() {
        for v in ["0", "false", "no", "off", ""] {
            std::env::set_var("TRAPD_TEST_FLAG2", v);
            assert!(
                !env_truthy("TRAPD_TEST_FLAG2"),
                "expected {v:?} to be falsy"
            );
        }
        std::env::remove_var("TRAPD_TEST_FLAG2");
        assert!(!env_truthy("TRAPD_DEFINITELY_UNSET_VAR_XYZ"));
    }

    fn dummy_event() -> schema::AgentEvent {
        schema::AgentEvent::new(
            uuid::Uuid::new_v4().to_string(),
            "test-host".to_string(),
            schema::EventClass::System,
            schema::EventAction::Snapshot,
            schema::Severity::Info,
            schema::EventData::SystemSnapshot(schema::SystemSnapshotData {
                os: "Linux".to_string(),
                kernel: "6.0.0".to_string(),
                distro: "Test".to_string(),
                cpu_count: 1,
                cpu_usage_pct: 0.0,
                memory_total_mb: 1024,
                memory_used_mb: 512,
                memory_free_mb: 512,
                uptime_secs: 100,
                load_avg: [0.0, 0.0, 0.0],
            }),
        )
    }

    /// `handle_event` runs inside the single async consumer task; the spool
    /// journal append is synchronous disk I/O (`std::fs::write`/`sync_all`)
    /// and must not run directly on the async executor thread, or it starves
    /// every other task on a busy agent. On a `current_thread` runtime the
    /// test body and the executor are the same OS thread, so if the push
    /// happened inline it would be observed on `executor_thread`; wrapped in
    /// `spawn_blocking` it runs on a separate blocking-pool thread instead.
    #[tokio::test(flavor = "current_thread")]
    async fn handle_event_offloads_spool_push_off_the_async_executor_thread() {
        let executor_thread = std::thread::current().id();

        let dir = std::env::temp_dir().join(format!(
            "trapd_handle_event_test_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        let spool = Spool::durable_at(dir.join("queue.journal"), 10);
        let buf: Arc<Mutex<Spool>> = Arc::new(Mutex::new(spool));

        let event = dummy_event();
        handle_event(&event, &OutputMode::Stdout, &buf).await;

        let pushed_thread = buf.lock().unwrap().last_push_thread();
        assert_eq!(
            buf.lock().unwrap().len(),
            1,
            "event must still land in the spool"
        );
        assert_ne!(
            pushed_thread,
            Some(executor_thread),
            "spool push must run off the async executor thread (spawn_blocking), not inline"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn backend_host_extracts_hostname() {
        assert_eq!(
            backend_host("https://api.example.com/path"),
            Some("api.example.com".into())
        );
        assert_eq!(
            backend_host("https://api.example.com:8443"),
            Some("api.example.com".into())
        );
        assert_eq!(
            backend_host("http://10.0.0.1:9000"),
            Some("10.0.0.1".into())
        );
        assert_eq!(backend_host(""), None);
    }
}
