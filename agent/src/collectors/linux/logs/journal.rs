//! systemd journal reader.
//!
//! Native `sd_journal` would pull libsystemd into every build — a painful
//! CI/cross-compile story, and a no-op in containers without a journal.
//! `journalctl --output=json --follow` is the same interface Filebeat uses
//! as its fallback: one JSON object per line, `__CURSOR` for resume, no
//! extra native deps. When `journalctl` is missing the source is skipped.

use std::process::Stdio;

use serde_json::{Map, Value};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tracing::{info, warn};

use crate::config::LogSourceConfig;

use super::checkpoint::JournalCheckpoint;
use super::parser::ParsedLog;

/// Spawn `journalctl` and stream JSON records.
pub struct JournalTail {
    child: Option<Child>,
    reader: Option<BufReader<tokio::process::ChildStdout>>,
    source: String,
}

impl JournalTail {
    pub async fn spawn(
        source: &LogSourceConfig,
        cursor: Option<&JournalCheckpoint>,
    ) -> Option<Self> {
        if !journalctl_available() {
            warn!(
                source = %source.name,
                "journalctl not found — skipping journal source"
            );
            return None;
        }
        let mut cmd = Command::new("journalctl");
        cmd.arg("--output=json")
            .arg("--no-pager")
            .arg("--utc")
            .arg("--follow")
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        if let Some(cp) = cursor.filter(|c| !c.cursor.is_empty()) {
            cmd.arg(format!("--after-cursor={}", cp.cursor));
        } else if source.starts_at_end() {
            cmd.arg("--since=now");
        }
        for unit in &source.units {
            cmd.arg("-u").arg(unit);
        }
        match cmd.spawn() {
            Ok(mut child) => {
                let stdout = child.stdout.take()?;
                info!(
                    source = %source.name,
                    units = ?source.units,
                    "journal tail started"
                );
                Some(Self {
                    child: Some(child),
                    reader: Some(BufReader::new(stdout)),
                    source: source.name.clone(),
                })
            }
            Err(e) => {
                warn!(source = %source.name, error = %e, "journalctl spawn failed");
                None
            }
        }
    }

    /// Read the next JSON record, or `None` on EOF.
    pub async fn next_line(&mut self) -> Option<String> {
        let reader = self.reader.as_mut()?;
        let mut line = String::new();
        match reader.read_line(&mut line).await {
            Ok(0) => None,
            Ok(_) => Some(line),
            Err(e) => {
                warn!(source = %self.source, error = %e, "journal read failed");
                None
            }
        }
    }

    pub async fn kill(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill().await;
        }
    }
}

fn journalctl_available() -> bool {
    std::process::Command::new("journalctl")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Turn a `journalctl --output=json` line into a [`ParsedLog`] plus the cursor.
pub fn parse_journal_json(line: &str) -> Option<(ParsedLog, String)> {
    let mut map: Map<String, Value> = serde_json::from_str(line.trim()).ok()?;
    let cursor = map
        .remove("__CURSOR")
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default();
    let message = json_str(&map, &["MESSAGE", "message"]).unwrap_or_default();
    let mut parsed = ParsedLog {
        message,
        category: "syslog".into(),
        host: json_str(&map, &["_HOSTNAME", "SYSLOG_HOSTNAME"]),
        proc: json_str(&map, &["SYSLOG_IDENTIFIER", "_COMM"]),
        pid: json_str(&map, &["_PID"]).and_then(|s| s.parse().ok()),
        uid: json_str(&map, &["_UID"]).and_then(|s| s.parse().ok()),
        facility: json_str(&map, &["SYSLOG_FACILITY"]),
        timestamp: realtime_ts(&map),
        fields: map,
        ..Default::default()
    };
    if let Some(pri) = json_str(&parsed.fields, &["PRIORITY"]) {
        parsed.severity = Some(priority_name(&pri));
    }
    if let Some(unit) = json_str(&parsed.fields, &["_SYSTEMD_UNIT", "UNIT"]) {
        parsed.fields.insert("unit".into(), Value::String(unit));
    }
    Some((parsed, cursor))
}

fn json_str(map: &Map<String, Value>, keys: &[&str]) -> Option<String> {
    for k in keys {
        match map.get(*k) {
            Some(Value::String(s)) if !s.is_empty() => return Some(s.clone()),
            Some(Value::Array(arr)) => {
                // journald sometimes stores MESSAGE as a byte array.
                let bytes: Vec<u8> = arr
                    .iter()
                    .filter_map(|v| v.as_u64().map(|n| n as u8))
                    .collect();
                if !bytes.is_empty() {
                    return Some(String::from_utf8_lossy(&bytes).into_owned());
                }
            }
            Some(Value::Number(n)) => return Some(n.to_string()),
            _ => {}
        }
    }
    None
}

fn realtime_ts(map: &Map<String, Value>) -> Option<chrono::DateTime<chrono::Utc>> {
    let us: i64 = json_str(map, &["__REALTIME_TIMESTAMP"])?.parse().ok()?;
    chrono::DateTime::from_timestamp(us / 1_000_000, ((us % 1_000_000) * 1000) as u32)
}

fn priority_name(p: &str) -> String {
    match p {
        "0" => "emerg",
        "1" => "alert",
        "2" => "crit",
        "3" => "err",
        "4" => "warning",
        "5" => "notice",
        "6" => "info",
        _ => "debug",
    }
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

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
