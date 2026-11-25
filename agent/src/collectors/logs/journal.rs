//! systemd journal reader.
//!
//! Native `sd_journal` would pull libsystemd into every build — a painful
//! CI/cross-compile story, and a no-op in containers without a journal.
//! `journalctl --output=json --follow` is the same interface Filebeat uses
//! as its fallback: one JSON object per line, `__CURSOR` for resume, no
//! extra native deps. When `journalctl` is missing the source is skipped.

use std::process::Stdio;

use tokio::io::{AsyncBufRead, AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tracing::{info, warn};

use crate::config::LogSourceConfig;
use crate::telemetry::{
    metrics::{metrics, Metrics},
    DropReason,
};

use super::checkpoint::JournalCheckpoint;
use super::parser::ParsedLog;

/// Spawn `journalctl` and stream JSON records.
pub struct JournalTail {
    child: Option<Child>,
    reader: Option<BufReader<tokio::process::ChildStdout>>,
    stderr: tokio::task::JoinHandle<bool>,
    source: String,
    max_line: usize,
}

impl JournalTail {
    pub async fn spawn(
        source: &LogSourceConfig,
        cursor: Option<&JournalCheckpoint>,
    ) -> Option<Self> {
        let bin = ["/usr/bin/journalctl", "/bin/journalctl"]
            .into_iter()
            .find(|p| std::path::Path::new(p).is_file())?;
        let mut cmd = Command::new(bin);
        cmd.env("LC_ALL", "C");
        cmd.arg("--output=json")
            .arg("--no-pager")
            .arg("--utc")
            .arg("--follow")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        if let Some(cp) = cursor.filter(|c| !c.cursor.is_empty()) {
            cmd.arg(format!("--after-cursor={}", cp.cursor));
        } else if source.starts_at_end() {
            cmd.arg("--since=now");
        }
        for unit in &source.units {
            cmd.arg("-u").arg(unit);
        }
        let max_line = source.max_line_bytes.max(4 * 1024);
        match cmd.spawn() {
            Ok(mut child) => {
                let stdout = child.stdout.take()?;
                let stderr = tokio::spawn(rejected_cursor(child.stderr.take()?));
                info!(
                    source = %source.name,
                    units = ?source.units,
                    "journal tail started"
                );
                Some(Self {
                    child: Some(child),
                    stderr,
                    reader: Some(BufReader::with_capacity(max_line.min(256 * 1024), stdout)),
                    source: source.name.clone(),
                    max_line,
                })
            }
            Err(e) => {
                warn!(source = %source.name, error = %e, "journalctl spawn failed");
                None
            }
        }
    }

    /// Read the next JSON record, or `None` on EOF.
    pub async fn next_record(&mut self) -> Option<(ParsedLog, String)> {
        let max_line = self.max_line;
        let reader = self.reader.as_mut()?;
        match read_record(reader, max_line, metrics()).await {
            Ok(v) => v,
            Err(e) => {
                warn!(source = %self.source, error = %e, "journal read failed");
                None
            }
        }
    }

    pub async fn finish(&mut self) -> bool {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill().await;
        }
        (&mut self.stderr).await.unwrap_or(false)
    }
}

/// Account for each physical record once, then continue with the next record.
async fn read_record<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    max: usize,
    counters: &Metrics,
) -> std::io::Result<Option<(ParsedLog, String)>> {
    while let Some(line) = read_line_bounded(reader, max, counters).await? {
        if let Some(record) = parse_journal_json(&line) {
            return Ok(Some(record));
        }
        counters.event_dropped(DropReason::InternalError);
    }
    Ok(None)
}

/// Cap a single journal JSON record. A missing newline cannot grow the
/// buffer without bound; oversized records are dropped as `event_too_large`
/// and we resync on the next newline.
async fn read_line_bounded<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    max: usize,
    counters: &Metrics,
) -> std::io::Result<Option<String>> {
    let mut buf = Vec::new();
    let mut skipping = false;
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            if skipping || buf.is_empty() {
                return Ok(None);
            }
            return Ok(Some(String::from_utf8_lossy(&buf).into_owned()));
        }
        if let Some(pos) = available.iter().position(|&b| b == b'\n') {
            if skipping {
                reader.consume(pos + 1);
                skipping = false;
                continue;
            }
            if buf.len().saturating_add(pos + 1) > max {
                reader.consume(pos + 1);
                counters.event_dropped(DropReason::EventTooLarge);
                buf.clear();
                continue;
            }
            buf.extend_from_slice(&available[..=pos]);
            reader.consume(pos + 1);
            if buf.last() == Some(&b'\n') {
                buf.pop();
            }
            if buf.last() == Some(&b'\r') {
                buf.pop();
            }
            return Ok(Some(String::from_utf8_lossy(&buf).into_owned()));
        }
        let n = available.len();
        if skipping {
            reader.consume(n);
            continue;
        }
        if buf.len().saturating_add(n) > max {
            reader.consume(n);
            counters.event_dropped(DropReason::EventTooLarge);
            skipping = true;
            buf.clear();
            continue;
        }
        buf.extend_from_slice(available);
        reader.consume(n);
    }
}

// Keep a rolling suffix so the diagnostic can straddle two pipe reads.
async fn rejected_cursor(mut stderr: impl tokio::io::AsyncRead + Unpin) -> bool {
    use tokio::io::AsyncReadExt;
    let marker = b"Failed to seek to cursor";
    let mut recent = Vec::new();
    let mut chunk = [0; 1024];
    let mut rejected = false;
    while let Ok(n) = stderr.read(&mut chunk).await {
        if n == 0 {
            break;
        }
        recent.extend_from_slice(&chunk[..n]);
        rejected |= recent.windows(marker.len()).any(|s| s == marker);
        recent.drain(..recent.len().saturating_sub(marker.len() - 1));
    }
    rejected
}

// Pure line parser, kept free of process and I/O code for fuzzing.
#[path = "journal_json.rs"]
mod journal_json;
pub use journal_json::parse_journal_json;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn distinguishes_stale_cursor_from_unrelated_child_failure() {
        assert!(rejected_cursor(&b"Failed to seek to cursor: stale"[..]).await);
        assert!(!rejected_cursor(&b"Permission denied"[..]).await);
    }

    #[tokio::test]
    async fn bounded_read_keeps_short_line() {
        let data = b"{\"MESSAGE\":\"ok\"}\nnext\n";
        let mut r = BufReader::new(&data[..]);
        let got = read_line_bounded(&mut r, 64, &Metrics::new())
            .await
            .unwrap();
        assert_eq!(got.as_deref(), Some("{\"MESSAGE\":\"ok\"}"));
    }

    #[tokio::test]
    async fn bounded_read_drops_oversized_line() {
        let mut data = vec![b'x'; 100];
        data.push(b'\n');
        data.extend_from_slice(b"ok\n");
        let mut r = BufReader::new(&data[..]);
        let counters = Metrics::new();
        let kept = read_line_bounded(&mut r, 16, &counters).await.unwrap();
        assert_eq!(kept.as_deref(), Some("ok"));
        assert_eq!(counters.drops_for(DropReason::EventTooLarge), 1);
    }

    #[tokio::test]
    async fn journal_accounts_for_invalid_json_and_unterminated_oversize() {
        let data = b"missing json\n{\"MESSAGE\":\"ok\"}\n01234567890123456789";
        let mut r = BufReader::with_capacity(4, &data[..]);
        let counters = Metrics::new();
        let limit = b"{\"MESSAGE\":\"ok\"}\n".len();
        let (record, _) = read_record(&mut r, limit, &counters)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(record.message, "ok");
        assert!(read_record(&mut r, limit, &counters)
            .await
            .unwrap()
            .is_none());
        assert_eq!(counters.drops_for(DropReason::InternalError), 1);
        assert_eq!(counters.drops_for(DropReason::EventTooLarge), 1);
    }

    #[test]
    fn parses_journalctl_json_line() {
        let line = r#"{"__CURSOR":"s=abc","MESSAGE":"Failed password for root from 1.2.3.4 port 22 ssh2","SYSLOG_IDENTIFIER":"sshd","_PID":"4242","_HOSTNAME":"victim","PRIORITY":"6","__REALTIME_TIMESTAMP":"1700000000000000","_SYSTEMD_UNIT":"ssh.service"}"#;
        let (p, cursor) = parse_journal_json(line).unwrap();
        assert_eq!(cursor, "s=abc");
        assert_eq!(p.proc.as_deref(), Some("sshd"));
        assert_eq!(p.pid, Some(4242));
        assert!(p.message.contains("Failed password"));
        assert_eq!(p.severity.as_deref(), Some("info"));
        assert_eq!(p.fields["unit"], "ssh.service");
    }
}
