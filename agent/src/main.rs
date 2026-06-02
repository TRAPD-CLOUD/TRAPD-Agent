use std::sync::{Arc, Mutex, RwLock};

use anyhow::{Context, Result};
use tokio::fs;
use tracing::{error, info, warn};
use uuid::Uuid;

mod collectors;
mod config;
mod deception;
mod detection;
mod enrollment;
mod forensics;
mod heartbeat;
mod http;
mod inventory;
mod output;
mod paths;
mod pipeline;
mod prevention;
mod schema;
mod selfprotect;
mod transport;

use collectors::linux::agent_protect::AgentProtectCollector;
use collectors::linux::authlog::AuthLogCollector;
use collectors::linux::ebpf_exec::EbpfExecCollector;
use collectors::linux::ebpf_syscalls::EbpfSyscallCollector;
use collectors::linux::filesystem::FilesystemCollector;
use collectors::linux::network::NetworkCollector;
use collectors::linux::process::ProcessCollector;
use collectors::linux::system::SystemCollector;
use collectors::Collector;
use config::{AgentConfig, ConfigPuller};
use heartbeat::Heartbeat;
use output::{write_event, OutputMode};
use pipeline::{create_pipeline, Spool};
use transport::Transport;

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
        (String::new(), device_id.clone(), String::new(), "offline".to_string())
    } else {
        let backend_url =
            http::normalize_base_url(&std::env::var("TRAPD_BACKEND_URL").unwrap_or_default());
        let creds = enrollment::load_or_enroll(&backend_url, &device_id, &hostname)
            .await
            .context("Failed to obtain agent credentials")?;
        let agent_id = creds.agent_id.clone();
        let token = creds.agent_secret.clone();
        (backend_url, agent_id, token, creds.project_id)
    };

    let output_mode  = OutputMode::from_env();
    let output_label = match output_mode {
        OutputMode::Stdout => "stdout",
        OutputMode::File   => "file",
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

    let agent_config: Arc<RwLock<AgentConfig>> = Arc::new(RwLock::new(AgentConfig::default()));
    // Backend outbox. Online it is disk-backed (survives crash/restart, replays
    // on the next run); offline it is purely in-memory (the NDJSON output is the
    // system of record).
    let spool = if offline {
        Spool::in_memory(pipeline::SPOOL_MAX_MEMORY)
    } else {
        Spool::durable(pipeline::spool_max_from_env())
    };
    let ring_buffer: Arc<Mutex<Spool>>         = Arc::new(Mutex::new(spool));
    let (tx, mut rx) = create_pipeline();
    let mut handles = Vec::new();

    // ── Prevention subsystem (active response) ────────────────────────────────
    // Requires the backend (signed command channel), so it is skipped offline.
    let prevention_enabled = agent_config
        .read().map(|c| c.prevention_enabled).unwrap_or(true);
    let prev_event_tx = if prevention_enabled && !offline {
        match start_prevention(
            &backend_url,
            &agent_id,
            &token,
            &hostname,
            tx.clone(),
            Arc::clone(&agent_config),
        ).await {
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
            let mut c  = $collector;
            let tx2    = tx.clone();
            let aid    = agent_id.clone();
            let host   = hostname.clone();
            let cname  = c.name();
            handles.push(tokio::spawn(async move {
                if let Err(e) = c.run(tx2, aid, host).await {
                    error!("{cname} exited with error: {e:#}");
                }
            }));
        }};
    }

    let ebpf_exec = EbpfExecCollector::new();
    if ebpf_exec.is_available() {
        info!("eBPF exec tracer available — spawning EbpfExecCollector");
        spawn_collector!(ebpf_exec);
    } else {
        warn!("eBPF binary not found — exec events will be detected by polling only.");
    }

    let ebpf_syscalls = EbpfSyscallCollector::new().with_config(Arc::clone(&agent_config));
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
    spawn_collector!(FilesystemCollector::new());
    spawn_collector!(AgentProtectCollector::new());
    spawn_collector!(collectors::linux::fim::FimCollector::new(Arc::clone(&agent_config)));
    spawn_collector!(collectors::linux::memscan::MemScanCollector::new(Arc::clone(&agent_config)));

    {
        let tx_ap = tx.clone();
        let aid   = agent_id.clone();
        let host  = hostname.clone();
        tokio::spawn(async move {
            selfprotect::anti_ptrace::run(tx_ap, aid, host).await;
        });
    }

    drop(tx);

    // Local detection engine — behavioural + IOC analytics over every event.
    // Platform-neutral, so the future Windows agent reuses it unchanged.
    let engine = std::sync::Arc::new(detection::DetectionEngine::new(
        agent_id.clone(),
        hostname.clone(),
    ));
    info!(iocs = engine.ioc_count(), "Detection engine started");
    // Pick up threat-intel feed updates without a restart.
    Arc::clone(&engine).spawn_ioc_reloader(300);

    let buf_for_consumer = Arc::clone(&ring_buffer);
    let mode = output_mode;
    let prev_tx = prev_event_tx.clone();
    let det_engine = Arc::clone(&engine);
    let mut consumer = tokio::spawn(async move {
        while let Some(event) = rx.recv().await {
            if let Some(p) = &prev_tx {
                let _ = p.try_send(event.clone());
            }
            handle_event(&event, &mode, &buf_for_consumer).await;

            // Run detections and treat each finding as a first-class event:
            // persisted, buffered for the backend, and forwarded to prevention.
            for det in det_engine.inspect(&event) {
                if let Some(p) = &prev_tx {
                    let _ = p.try_send(det.clone());
                }
                handle_event(&det, &mode, &buf_for_consumer).await;
            }
        }
    });

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
        );
        tokio::spawn(async move { inv.run().await });
    }

    // Backend channels only run when connected; offline = pure local telemetry.
    if !offline {
        let transport =
            Transport::new(Arc::clone(&ring_buffer), backend_url.clone(), token.clone());
        tokio::spawn(async move { transport.run().await });

        let config_puller = ConfigPuller::new(
            Arc::clone(&agent_config),
            &backend_url,
            &agent_id,
            token.clone(),
        );
        tokio::spawn(async move { config_puller.run().await });

        let heartbeat = Heartbeat::new(&backend_url, agent_id.clone(), token, hostname.clone());
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
    info!("Shutdown complete");
    Ok(())
}

async fn handle_event(
    event: &schema::AgentEvent,
    mode:  &OutputMode,
    buf:   &Arc<Mutex<Spool>>,
) {
    if let Err(err) = write_event(event, mode).await {
        error!("Failed to write event: {err}");
    }
    match buf.lock() {
        Ok(mut b) => b.push(event.clone()),
        Err(e)    => error!("Ring buffer mutex poisoned: {e}"),
    }
}

/// Build / spawn the prevention subsystem.  Returns the sender used by the
/// tee in the main consumer to forward events to the enforcement engine.
async fn start_prevention(
    backend_url: &str,
    agent_id:    &str,
    token:       &str,
    hostname:    &str,
    pipeline_tx: tokio::sync::mpsc::Sender<schema::AgentEvent>,
    cfg_handle:  Arc<RwLock<AgentConfig>>,
) -> Result<tokio::sync::mpsc::Sender<schema::AgentEvent>> {
    use prevention::{
        audit::AuditEmitter,
        command_puller::CommandPuller,
        commands::Verifier,
        engine::{Engine, EngineConfig},
        network::{detect_backend, ensure_chains},
        policy::{load_local_policy, PolicyHandle},
        command_pubkey_path, local_policy_path, nonce_store,
    };

    prevention::ensure_state_dirs();

    let (event_tx, event_rx) =
        tokio::sync::mpsc::channel::<schema::AgentEvent>(1024);

    let audit = AuditEmitter::new(pipeline_tx.clone(), agent_id.into(), hostname.into());

    let store = load_local_policy(&local_policy_path())
        .context("load /etc/trapd/policy.json")?;
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

    let verifier = match Verifier::new(
        &command_pubkey_path(),
        agent_id.to_string(),
        &nonce_store(),
    ) {
        Ok(v) => Some(Arc::new(v)),
        Err(e) => {
            warn!(error = %e, "command verifier unavailable — backend commands will not be processed");
            None
        }
    };

    // Register of honeytokens this host has deployed (deploy/revoke lifecycle).
    let honeytokens = Arc::new(deception::HoneytokenStore::load());
    info!(count = honeytokens.len(), "Honeytoken register loaded");

    let engine = Arc::new(Engine::new(
        policy.clone(),
        audit.clone(),
        engine_cfg,
        honeytokens,
        Arc::clone(&cfg_handle),
    ));
    Arc::clone(&engine).spawn_event_loop(event_rx);

    if let Some(v) = verifier {
        let (cmd_tx, cmd_rx) = tokio::sync::mpsc::channel(64);
        let poll_secs = cfg_handle
            .read().map(|c| c.command_poll_interval_secs).unwrap_or(10);
        let puller = CommandPuller::new(
            backend_url,
            agent_id,
            token.to_string(),
            v,
            audit.clone(),
            cmd_tx,
            poll_secs,
        );
        tokio::spawn(async move { puller.run().await });
        Arc::clone(&engine).spawn_command_loop(cmd_rx);
    }

    let lsm = prevention::lsm_loader::LsmHandle::try_load();
    lsm.sync(&policy).await;

    Ok(event_tx)
}

fn build_isolation_allowlist(
    backend_url: &str,
    cfg:         &Arc<RwLock<AgentConfig>>,
) -> Vec<std::net::IpAddr> {
    let mut out: Vec<std::net::IpAddr> = Vec::new();

    if let Some(host) = backend_host(backend_url) {
        if let Ok(ip) = host.parse::<std::net::IpAddr>() {
            out.push(ip);
        } else if let Ok(addrs) =
            std::net::ToSocketAddrs::to_socket_addrs(&format!("{host}:443"))
        {
            for a in addrs { out.push(a.ip()); }
        }
    }

    if let Ok(c) = cfg.read() {
        for raw in &c.isolation_allowlist_ips {
            if let Ok(ip) = raw.parse::<std::net::IpAddr>() {
                if !out.contains(&ip) { out.push(ip); }
            }
        }
    }

    out
}

fn backend_host(url: &str) -> Option<String> {
    let s = url.split("://").nth(1).unwrap_or(url);
    let s = s.split('/').next().unwrap_or(s);
    let s = s.split(':').next().unwrap_or(s);
    if s.is_empty() { None } else { Some(s.to_string()) }
}

/// Interpret an environment variable as a boolean flag.
/// True for `1`, `true`, `yes`, `on` (case-insensitive); false otherwise.
fn env_truthy(key: &str) -> bool {
    std::env::var(key)
        .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
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
        let raw = fs::read_to_string(&file).await.context("Failed to read device_id file")?;
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
            assert!(!env_truthy("TRAPD_TEST_FLAG2"), "expected {v:?} to be falsy");
        }
        std::env::remove_var("TRAPD_TEST_FLAG2");
        assert!(!env_truthy("TRAPD_DEFINITELY_UNSET_VAR_XYZ"));
    }

    #[test]
    fn backend_host_extracts_hostname() {
        assert_eq!(backend_host("https://api.example.com/path"), Some("api.example.com".into()));
        assert_eq!(backend_host("https://api.example.com:8443"), Some("api.example.com".into()));
        assert_eq!(backend_host("http://10.0.0.1:9000"), Some("10.0.0.1".into()));
        assert_eq!(backend_host(""), None);
    }
}
