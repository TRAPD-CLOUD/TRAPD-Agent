use std::sync::{Arc, Mutex, RwLock};

use anyhow::{Context, Result};
use tokio::fs;
use tracing::{error, info, warn};
use uuid::Uuid;

mod collectors;
mod config;
mod enrollment;
mod heartbeat;
mod output;
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
use pipeline::{create_pipeline, RingBuffer};
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

    let device_id = load_or_create_device_id()
        .await
        .context("Failed to load/create device_id")?;

    let hostname = hostname::get()
        .map(|h| h.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "unknown".to_string());

    let backend_url =
        std::env::var("TRAPD_BACKEND_URL").expect("TRAPD_BACKEND_URL env var must be set");

    let creds = enrollment::load_or_enroll(&backend_url, &device_id, &hostname)
        .await
        .context("Failed to obtain agent credentials")?;

    let agent_id = creds.agent_id.clone();
    let token    = creds.agent_secret.clone();

    let output_mode  = OutputMode::from_env();
    let output_label = match output_mode {
        OutputMode::Stdout => "stdout",
        OutputMode::File   => "file",
    };

    info!(
        agent_id   = %agent_id,
        device_id  = %device_id,
        hostname   = %hostname,
        project_id = %creds.project_id,
        output     = %output_label,
        "TRAPD Agent started"
    );

    let agent_config: Arc<RwLock<AgentConfig>> = Arc::new(RwLock::new(AgentConfig::default()));
    let ring_buffer: Arc<Mutex<RingBuffer>>    = Arc::new(Mutex::new(RingBuffer::new()));
    let (tx, mut rx) = create_pipeline();
    let mut handles = Vec::new();

    // ── Prevention subsystem (active response) ────────────────────────────────────────
    let prevention_enabled = agent_config
        .read().map(|c| c.prevention_enabled).unwrap_or(true);
    let prev_event_tx = if prevention_enabled {
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
        info!("Prevention subsystem disabled in config");
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

    let ebpf_syscalls = EbpfSyscallCollector::new();
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

    {
        let tx_ap = tx.clone();
        let aid   = agent_id.clone();
        let host  = hostname.clone();
        tokio::spawn(async move {
            selfprotect::anti_ptrace::run(tx_ap, aid, host).await;
        });
    }

    drop(tx);

    let buf_for_consumer = Arc::clone(&ring_buffer);
    let mode = output_mode;
    let prev_tx = prev_event_tx.clone();
    let mut consumer = tokio::spawn(async move {
        while let Some(event) = rx.recv().await {
            if let Some(p) = &prev_tx {
                let _ = p.try_send(event.clone());
            }
            handle_event(&event, &mode, &buf_for_consumer).await;
        }
    });

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
    buf:   &Arc<Mutex<RingBuffer>>,
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
    use std::path::Path;
    use prevention::{
        audit::AuditEmitter,
        command_puller::CommandPuller,
        commands::Verifier,
        engine::{Engine, EngineConfig},
        network::{detect_backend, ensure_chains},
        policy::{load_local_policy, PolicyHandle},
        COMMAND_PUBKEY_PATH, LOCAL_POLICY_PATH, NONCE_STORE,
    };

    prevention::ensure_state_dirs();

    let (event_tx, event_rx) =
        tokio::sync::mpsc::channel::<schema::AgentEvent>(1024);

    let audit = AuditEmitter::new(pipeline_tx.clone(), agent_id.into(), hostname.into());

    let store = load_local_policy(Path::new(LOCAL_POLICY_PATH))
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
        Path::new(COMMAND_PUBKEY_PATH),
        agent_id.to_string(),
        Path::new(NONCE_STORE),
    ) {
        Ok(v) => Some(Arc::new(v)),
        Err(e) => {
            warn!(error = %e, "command verifier unavailable — backend commands will not be processed");
            None
        }
    };

    let engine = Arc::new(Engine::new(policy.clone(), audit.clone(), engine_cfg));
    engine.spawn_event_loop(event_rx);

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

async fn load_or_create_device_id() -> Result<String> {
    let dir  = device_dir()?;
    let file = dir.join("device_id");

    if file.exists() {
        let raw     = fs::read_to_string(&file).await.context("Failed to read device_id file")?;
        let trimmed = raw.trim();
        let _       = Uuid::parse_str(trimmed).context("device_id file contains invalid UUID")?;
        return Ok(trimmed.to_string());
    }

    fs::create_dir_all(&dir)
        .await
        .context("Failed to create ~/.trapd directory")?;
    let id = Uuid::new_v4().to_string();
    fs::write(&file, &id)
        .await
        .context("Failed to write device_id file")?;
    info!("Generated new device_id: {id}");
    Ok(id)
}

fn device_dir() -> Result<std::path::PathBuf> {
    let home = std::env::var("HOME").context("HOME env var not set")?;
    Ok(std::path::PathBuf::from(home).join(".trapd"))
}
