use std::env;

use anyhow::Result;
use tokio::fs::{self, OpenOptions};
use tokio::io::AsyncWriteExt;

use crate::schema::AgentEvent;

const LOG_DIR: &str = "/var/log/trapd";
const LOG_FILE: &str = "/var/log/trapd/events.ndjson";

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
