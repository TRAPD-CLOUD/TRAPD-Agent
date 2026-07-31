use std::env;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use tokio::fs::{self, File, OpenOptions};
use tokio::io::{AsyncWrite, AsyncWriteExt, BufWriter};
use tracing::info;

use crate::schema::AgentEvent;

pub mod siem;

const MAX_FILE_BYTES: u64 = 100 * 1024 * 1024; // 100 MB
const MAX_ROTATED_FILES: u32 = 3;
const WRITE_BUFFER_BYTES: usize = 64 * 1024;

/// Absolute path to the NDJSON event log, resolved via [`crate::paths`] so it
/// honours `TRAPD_LOG_DIR` (default `/var/log/trapd/events.ndjson`).
fn log_file() -> PathBuf {
    crate::paths::log_dir().join("events.ndjson")
}

#[derive(Debug, Clone, Copy)]
pub enum OutputMode {
    Stdout,
    File,
}

impl OutputMode {
    pub fn from_env() -> Self {
        match env::var("TRAPD_OUTPUT").as_deref() {
            Ok("file") => OutputMode::File,
            _ => OutputMode::Stdout,
        }
    }
}

/// Long-lived, buffered NDJSON output.
///
/// Keeping the file descriptor and buffer across events avoids an `open`,
/// `metadata` lookup and (for stdout) a forced flush for every telemetry event.
/// The owner must call [`OutputWriter::flush`] during an orderly shutdown.
pub struct OutputWriter {
    inner: OutputInner,
    dirty: bool,
}

enum OutputInner {
    Stdout(BufWriter<tokio::io::Stdout>),
    File(FileOutput),
}

struct FileOutput {
    path: PathBuf,
    writer: Option<BufWriter<File>>,
    /// Bytes already on disk plus bytes currently buffered by `writer`.
    bytes: u64,
    max_file_bytes: u64,
}

impl OutputWriter {
    pub async fn new(mode: OutputMode) -> Result<Self> {
        match mode {
            OutputMode::Stdout => Ok(Self {
                inner: OutputInner::Stdout(BufWriter::with_capacity(
                    WRITE_BUFFER_BYTES,
                    tokio::io::stdout(),
                )),
                dirty: false,
            }),
            OutputMode::File => Self::file_at(log_file(), MAX_FILE_BYTES).await,
        }
    }

    async fn file_at(path: PathBuf, max_file_bytes: u64) -> Result<Self> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).await.with_context(|| {
                format!("could not create event log directory {}", parent.display())
            })?;
        }
        let bytes = fs::metadata(&path).await.map(|m| m.len()).unwrap_or(0);
        let writer = open_buffered(&path).await?;
        Ok(Self {
            inner: OutputInner::File(FileOutput {
                path,
                writer: Some(writer),
                bytes,
                max_file_bytes,
            }),
            dirty: false,
        })
    }

    pub async fn write_event(&mut self, event: &AgentEvent) -> Result<()> {
        let line = serde_json::to_vec(event)?;
        let record_bytes = line.len() as u64 + 1;

        let result = match &mut self.inner {
            OutputInner::Stdout(out) => write_line(out, &line).await,
            OutputInner::File(file) => {
                // Rotate before the next record would cross the limit. Never
                // rotate an empty file: one oversized event must still be logged.
                if file.bytes > 0 && file.bytes.saturating_add(record_bytes) > file.max_file_bytes {
                    file.rotate().await?;
                }
                let writer = file.writer.as_mut().expect("file writer must be open");
                write_line(writer, &line).await?;
                file.bytes = file.bytes.saturating_add(record_bytes);
                Ok(())
            }
        };
        if result.is_ok() {
            self.dirty = true;
        }
        result
    }

    pub async fn flush(&mut self) -> Result<()> {
        if !self.dirty {
            return Ok(());
        }
        match &mut self.inner {
            OutputInner::Stdout(out) => out.flush().await?,
            OutputInner::File(file) => {
                if let Some(writer) = file.writer.as_mut() {
                    writer.flush().await?;
                }
            }
        }
        self.dirty = false;
        Ok(())
    }
}

impl FileOutput {
    async fn rotate(&mut self) -> Result<()> {
        if let Some(mut writer) = self.writer.take() {
            writer.flush().await?;
            // Close the descriptor before renaming, which is required on Windows.
            drop(writer);
        }
        rotate_log(&self.path).await?;
        self.writer = Some(open_buffered(&self.path).await?);
        self.bytes = 0;
        Ok(())
    }
}

async fn open_buffered(path: &Path) -> Result<BufWriter<File>> {
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .await
        .with_context(|| format!("could not open event log {}", path.display()))?;
    Ok(BufWriter::with_capacity(WRITE_BUFFER_BYTES, file))
}

async fn write_line<W: AsyncWrite + Unpin>(writer: &mut W, line: &[u8]) -> Result<()> {
    writer.write_all(line).await?;
    writer.write_all(b"\n").await?;
    Ok(())
}

/// Shift rotated files: .3 deleted, .2→.3, .1→.2, current→.1.
async fn rotate_log(log_file: &Path) -> Result<()> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{
        AgentEvent, EventAction, EventClass, EventData, Severity, SystemSnapshotData,
    };
    use uuid::Uuid;

    fn event(hostname: &str) -> AgentEvent {
        AgentEvent::new(
            "agent".into(),
            hostname.into(),
            EventClass::System,
            EventAction::Snapshot,
            Severity::Info,
            EventData::SystemSnapshot(SystemSnapshotData {
                os: "linux".into(),
                kernel: "test".into(),
                distro: "test".into(),
                cpu_count: 1,
                cpu_usage_pct: 0.0,
                memory_total_mb: 1,
                memory_used_mb: 0,
                memory_free_mb: 1,
                uptime_secs: 1,
                load_avg: [0.0; 3],
            }),
        )
    }

    #[tokio::test]
    async fn file_writer_buffers_multiple_ndjson_records() {
        let dir = std::env::temp_dir().join(format!("trapd-output-{}", Uuid::new_v4()));
        let path = dir.join("events.ndjson");
        let mut writer = OutputWriter::file_at(path.clone(), MAX_FILE_BYTES)
            .await
            .unwrap();

        writer.write_event(&event("one")).await.unwrap();
        writer.write_event(&event("two")).await.unwrap();
        writer.flush().await.unwrap();

        let contents = fs::read_to_string(&path).await.unwrap();
        let lines: Vec<_> = contents.lines().collect();
        assert_eq!(lines.len(), 2);
        assert_eq!(
            serde_json::from_str::<AgentEvent>(lines[0])
                .unwrap()
                .hostname,
            "one"
        );
        assert_eq!(
            serde_json::from_str::<AgentEvent>(lines[1])
                .unwrap()
                .hostname,
            "two"
        );
        fs::remove_dir_all(dir).await.unwrap();
    }

    #[tokio::test]
    async fn rotates_before_record_crosses_limit() {
        let dir = std::env::temp_dir().join(format!("trapd-output-{}", Uuid::new_v4()));
        let path = dir.join("events.ndjson");
        let first = event("first");
        let limit = serde_json::to_vec(&first).unwrap().len() as u64 + 1;
        let mut writer = OutputWriter::file_at(path.clone(), limit).await.unwrap();

        writer.write_event(&first).await.unwrap();
        writer.write_event(&event("second")).await.unwrap();
        writer.flush().await.unwrap();

        assert!(fs::read_to_string(path.with_extension("ndjson.1"))
            .await
            .unwrap()
            .contains("first"));
        assert!(fs::read_to_string(&path).await.unwrap().contains("second"));
        fs::remove_dir_all(dir).await.unwrap();
    }
}
