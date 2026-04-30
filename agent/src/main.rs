use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use tokio::fs;
use tracing::{error, info};
use uuid::Uuid;

mod collectors;
mod output;
mod pipeline;
mod schema;
mod transport;

use collectors::linux::authlog::AuthLogCollector;
use collectors::linux::network::NetworkCollector;
use collectors::linux::process::ProcessCollector;
use collectors::linux::system::SystemCollector;
use collectors::Collector;
use output::{write_event, OutputMode};
use pipeline::{create_pipeline, RingBuffer};
use transport::Transport;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("RUST_LOG")
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let agent_id = load_or_create_agent_id()
        .await
        .context("Failed to load/create agent_id")?;

    let hostname = hostname::get()
        .map(|h| h.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "unknown".to_string());

    let output_mode = OutputMode::from_env();
    let output_label = match output_mode {
        OutputMode::Stdout => "stdout",
        OutputMode::File   => "file",
    };

    let backend_url = std::env::var("TRAPD_BACKEND_URL")
        .expect("TRAPD_BACKEND_URL env var must be set");
    let token = std::env::var("TRAPD_TOKEN")
        .expect("TRAPD_TOKEN env var must be set");

    eprintln!("TRAPD Agent started");
    eprintln!("Agent ID : {agent_id}");
    eprintln!("Hostname  : {hostname}");
    eprintln!("Output    : {output_label}");
    info!("TRAPD Agent started — agent_id={agent_id} hostname={hostname} output={output_label}");

    let ring_buffer: Arc<Mutex<RingBuffer>> = Arc::new(Mutex::new(RingBuffer::new()));

    let (tx, mut rx) = create_pipeline();

    let mut handles = Vec::new();

    macro_rules! spawn_collector {
        ($collector:expr) => {{
            let mut c = $collector;
            let tx2   = tx.clone();
            let aid   = agent_id;
            let host  = hostname.clone();
            let cname = c.name();
            handles.push(tokio::spawn(async move {
                if let Err(e) = c.run(tx2, aid, host).await {
                    error!("{cname} exited with error: {e}");
                }
            }));
        }};
    }

    spawn_collector!(SystemCollector::new());
    spawn_collector!(ProcessCollector::new());
    spawn_collector!(NetworkCollector::new());
    spawn_collector!(AuthLogCollector::new());

    drop(tx);

    // Consumer: write each event to local output AND push to shared buffer for transport.
    let buf_for_consumer = Arc::clone(&ring_buffer);
    let mode = output_mode;
    let mut consumer = tokio::spawn(async move {
        while let Some(event) = rx.recv().await {
            if let Err(err) = write_event(&event, &mode).await {
                error!("Failed to write event: {err}");
            }
            match buf_for_consumer.lock() {
                Ok(mut buf) => buf.push(event),
                Err(e) => error!("Ring buffer mutex poisoned: {e}"),
            }

            // Drain any burst events
            while let Ok(e) = rx.try_recv() {
                if let Err(err) = write_event(&e, &mode).await {
                    error!("Failed to write event: {err}");
                }
                match buf_for_consumer.lock() {
                    Ok(mut buf) => buf.push(e),
                    Err(e) => error!("Ring buffer mutex poisoned: {e}"),
                }
            }
        }
    });

    // Transport: batches events from the shared buffer and POSTs to backend.
    let transport = Transport::new(Arc::clone(&ring_buffer), backend_url, token);
    tokio::spawn(async move { transport.run().await });

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

async fn load_or_create_agent_id() -> Result<Uuid> {
    let dir  = agent_id_dir()?;
    let file = dir.join("agent_id");

    if file.exists() {
        let raw = fs::read_to_string(&file)
            .await
            .context("Failed to read agent_id file")?;
        return Uuid::parse_str(raw.trim()).context("agent_id file contains invalid UUID");
    }

    fs::create_dir_all(&dir)
        .await
        .context("Failed to create ~/.trapd directory")?;
    let id = Uuid::new_v4();
    fs::write(&file, id.to_string())
        .await
        .context("Failed to write agent_id file")?;
    info!("Generated new agent_id: {id}");
    Ok(id)
}

fn agent_id_dir() -> Result<PathBuf> {
    let home = std::env::var("HOME").context("HOME env var not set")?;
    Ok(PathBuf::from(home).join(".trapd"))
}
