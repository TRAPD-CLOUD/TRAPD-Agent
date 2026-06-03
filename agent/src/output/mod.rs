use std::env;
use std::path::PathBuf;

use anyhow::Result;
use tokio::fs::{self, OpenOptions};
use tokio::io::AsyncWriteExt;
use tracing::info;

use crate::schema::AgentEvent;

pub mod siem;

const MAX_FILE_BYTES:   u64 = 100 * 1024 * 1024; // 100 MB
const MAX_ROTATED_FILES: u32 = 3;

/// Absolute path to the NDJSON event log, resolved via [`crate::paths`] so it
/// honours `TRAPD_LOG_DIR` (default `/var/log/trapd/events.ndjson`).
fn log_file() -> PathBuf {
    crate::paths::log_dir().join("events.ndjson")
}

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
            let log_file = log_file();
            ensure_log_dir().await?;
            rotate_if_needed(&log_file).await?;
            let mut file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&log_file)
                .await?;
            file.write_all(line.as_bytes()).await?;
            file.write_all(b"\n").await?;
        }
    }
    Ok(())
}

async fn ensure_log_dir() -> Result<()> {
    fs::create_dir_all(crate::paths::log_dir()).await?;
    Ok(())
}

async fn rotate_if_needed(log_file: &std::path::Path) -> Result<()> {
    match fs::metadata(log_file).await {
        Ok(meta) if meta.len() >= MAX_FILE_BYTES => rotate_log(log_file).await,
        _ => Ok(()),
    }
}

/// Shift rotated files: .3 deleted, .2→.3, .1→.2, current→.1
async fn rotate_log(log_file: &std::path::Path) -> Result<()> {
    let base = log_file.display().to_string();
    for i in (1..=MAX_ROTATED_FILES).rev() {
        let src = format!("{base}.{i}");
        if fs::try_exists(&src).await.unwrap_or(false) {
            if i == MAX_ROTATED_FILES {
                fs::remove_file(&src).await?;
            } else {
                let dst = format!("{base}.{}", i + 1);
                fs::rename(&src, &dst).await?;
            }
        }
    }
    if fs::try_exists(log_file).await.unwrap_or(false) {
        fs::rename(log_file, format!("{base}.1")).await?;
        info!("Log rotated: {base} → {base}.1");
    }
    Ok(())
}
