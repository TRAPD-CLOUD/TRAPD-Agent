use std::env;

use anyhow::Result;
use tokio::fs::{self, OpenOptions};
use tokio::io::AsyncWriteExt;
use tracing::info;

use crate::schema::AgentEvent;

const LOG_DIR:  &str = "/var/log/trapd";
const LOG_FILE: &str = "/var/log/trapd/events.ndjson";

const MAX_FILE_BYTES:   u64 = 100 * 1024 * 1024; // 100 MB
const MAX_ROTATED_FILES: u32 = 3;

#[derive(Debug, Clone)]
pub enum OutputMode {
    Stdout,
    File,
}

impl OutputMode {
    pub fn from_env() -> Self {
        match env::var("TRAPD_OUTPUT").as_deref() {
            Ok("file") => OutputMode::File,
            _          => OutputMode::Stdout,
        }
    }
}

pub async fn write_event(event: &AgentEvent, mode: &OutputMode) -> Result<()> {
    let line = serde_json::to_string(event)?;
    match mode {
        OutputMode::Stdout => {
            let mut out = tokio::io::stdout();
            out.write_all(line.as_bytes()).await?;
            out.write_all(b"\n").await?;
            out.flush().await?;
        }
        OutputMode::File => {
            ensure_log_dir().await?;
            rotate_if_needed().await?;
            let mut file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(LOG_FILE)
                .await?;
            file.write_all(line.as_bytes()).await?;
            file.write_all(b"\n").await?;
        }
    }
    Ok(())
}

async fn ensure_log_dir() -> Result<()> {
    fs::create_dir_all(LOG_DIR).await?;
    Ok(())
}

async fn rotate_if_needed() -> Result<()> {
    match fs::metadata(LOG_FILE).await {
        Ok(meta) if meta.len() >= MAX_FILE_BYTES => rotate_log().await,
        _ => Ok(()),
    }
}

/// Shift rotated files: .3 deleted, .2→.3, .1→.2, current→.1
async fn rotate_log() -> Result<()> {
    for i in (1..=MAX_ROTATED_FILES).rev() {
        let src = format!("{LOG_FILE}.{i}");
        if fs::try_exists(&src).await.unwrap_or(false) {
            if i == MAX_ROTATED_FILES {
                fs::remove_file(&src).await?;
            } else {
                let dst = format!("{LOG_FILE}.{}", i + 1);
                fs::rename(&src, &dst).await?;
            }
        }
    }
    if fs::try_exists(LOG_FILE).await.unwrap_or(false) {
        fs::rename(LOG_FILE, format!("{LOG_FILE}.1")).await?;
        info!("Log rotated: {LOG_FILE} → {LOG_FILE}.1");
    }
    Ok(())
}
