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
mod schema;
mod transport;

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

    // ── eBPF tracers (real-time, kernel-level) ───────────────────────────────
    // Both collectors load the same eBPF binary and attach independent programs.
    // They fall back gracefully if the binary is not installed.
    let ebpf_exec = EbpfExecCollector::new();
    if ebpf_exec.is_available() {
        info!("eBPF exec tracer available — spawning EbpfExecCollector");
        spawn_collector!(ebpf_exec);
    } else {
        warn!(
            "eBPF binary not found — exec events will be detected by polling only.\n\
             To enable: cargo xtask build-ebpf --release && \
             cp target/bpfel-unknown-none/release/trapd-agent-exec \
             /usr/lib/trapd-agent/"
        );
    }

    let ebpf_syscalls = EbpfSyscallCollector::new();
    if ebpf_syscalls.is_available() {
        info!("eBPF syscall tracer available — spawning EbpfSyscallCollector");
        spawn_collector!(ebpf_syscalls);
    } else {
        warn!(
            "eBPF binary not found — syscall events (open/connect/fork/…) unavailable.\n\
             To enable: cargo xtask build-ebpf --release && \
             cp target/bpfel-unknown-none/release/trapd-agent-exec \
             /usr/lib/trapd-agent/"
        );
    }

    // ── Polling collectors (userspace, all platforms) ────────────────────────
    spawn_collector!(SystemCollector::new());
    spawn_collector!(ProcessCollector::new());
    spawn_collector!(NetworkCollector::new());
    spawn_collector!(AuthLogCollector::new());
    spawn_collector!(FilesystemCollector::new());

    drop(tx);

    let buf_for_consumer = Arc::clone(&ring_buffer);
    let mode = output_mode;
    let mut consumer = tokio::spawn(async move {
        while let Some(event) = rx.recv().await {
            if let Err(err) = write_event(&event, &mode).await {
                error!("Failed to write event: {err}");
            }
            match buf_for_consumer.lock() {
                Ok(mut buf) => buf.push(event),
                Err(e)      => error!("Ring buffer mutex poisoned: {e}"),
            }

            while let Ok(e) = rx.try_recv() {
                if let Err(err) = write_event(&e, &mode).await {
                    error!("Failed to write event: {err}");
                }
                match buf_for_consumer.lock() {
                    Ok(mut buf) => buf.push(e),
                    Err(e)      => error!("Ring buffer mutex poisoned: {e}"),
                }
            }
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
