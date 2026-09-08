//! systemd journal reader, driven by `journalctl -o json`.
//!
//! We deliberately do not link libsystemd: a missing journal on a container
//! or a stripped image must not fail the link, and `journalctl` is the same
//! tool operators already trust. The cursor (`__CURSOR`) is persisted so a
//! restart neither replays history nor skips the gap. Unit / identifier
//! filters are passed as argv (never a shell) and validated so a signed
//! config cannot turn this into an argument-injection gadget.

use std::process::Stdio;

use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::sync::mpsc::Sender;
use tracing::{debug, info, warn};

use crate::config::LogSourceConfig;
use crate::pipeline;
use crate::schema::AgentEvent;
use crate::telemetry::{metrics::metrics, DropReason};

use super::checkpoint::CheckpointStore;
use super::framing::Frame;
use super::normalize;
use super::parser;
use super::rate::TokenBucket;

/// systemd unit names / syslog identifiers: the set of characters systemd
/// itself accepts. Anything else is refused rather than forwarded to argv.
pub fn valid_journal_token(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 256
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '@' | ':' | '\\'))
}

pub async fn run(
    source: LogSourceConfig,
    tx: Sender<AgentEvent>,
    agent_id: String,
    hostname: String,
    mut cursor: Option<String>,
    checkpoint_path: std::path::PathBuf,
    mut limiter: TokenBucket,
) {
    if which_journalctl().is_none() {
        warn!(
            source = %source.name,
            "log collector: journalctl not found — journal source disabled"
        );
        return;
    }
    if !source.unit.is_empty() && !valid_journal_token(&source.unit) {
        warn!(source = %source.name, unit = %source.unit, "refusing journal unit (invalid characters)");
        return;
    }
    if !source.identifier.is_empty() && !valid_journal_token(&source.identifier) {
        warn!(
            source = %source.name,
            identifier = %source.identifier,
            "refusing journal identifier (invalid characters)"
        );
        return;
    }

    info!(
        source = %source.name,
        unit = %source.unit,
        identifier = %source.identifier,
        "log collector: following systemd journal"
    );

    loop {
        if tx.is_closed() {
            return;
        }
        match follow_once(
            &source,
            &tx,
            &agent_id,
            &hostname,
            &mut cursor,
            &checkpoint_path,
            &mut limiter,
        )
        .await
        {
            Follow::Shutdown => return,
            Follow::Restart => {
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
        }
    }
}

enum Follow {
    Shutdown,
    Restart,
}

async fn follow_once(
    source: &LogSourceConfig,
    tx: &Sender<AgentEvent>,
    agent_id: &str,
    hostname: &str,
    cursor: &mut Option<String>,
    checkpoint_path: &std::path::Path,
    limiter: &mut TokenBucket,
) -> Follow {
    let mut cmd = Command::new("journalctl");
    cmd.arg("--output=json")
        .arg("--no-pager")
        .arg("--show-cursor")
        .arg("--utc")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);

    if let Some(c) = cursor.as_deref() {
        cmd.arg("--after-cursor").arg(c);
        cmd.arg("--follow");
    } else if source.start_at_beginning(false) {
        cmd.arg("--follow");
    } else {
        // Skip history: start following from "now".
        cmd.arg("-n").arg("0").arg("--follow");
    }
    if !source.unit.is_empty() {
        cmd.arg("--unit").arg(&source.unit);
    }
    if !source.identifier.is_empty() {
        cmd.arg("--identifier").arg(&source.identifier);
    }

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            warn!(source = %source.name, error = %e, "journalctl spawn failed");
            return Follow::Restart;
        }
    };
    let stdout = match child.stdout.take() {
        Some(s) => s,
        None => return Follow::Restart,
    };
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    let mut since_ckpt = 0u32;

    loop {
        line.clear();
        match reader.read_line(&mut line).await {
            Ok(0) => {
                let _ = child.wait().await;
                return Follow::Restart;
            }
            Ok(_) => {}
            Err(e) => {
                debug!(source = %source.name, error = %e, "journalctl read failed");
                let _ = child.kill().await;
                return Follow::Restart;
            }
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        if let Ok(val) = serde_json::from_str::<serde_json::Value>(trimmed) {
            if let Some(c) = val.get("__CURSOR").and_then(|v| v.as_str()) {
                *cursor = Some(c.to_string());
            }
            // `--show-cursor` also emits a bare cursor line between records on
            // some versions; skip records that have no MESSAGE.
            let message = journal_message(&val);
            if message.is_empty() {
                continue;
            }
            if !limiter.allow() {
                metrics().event_dropped(DropReason::RateLimitApplied);
                continue;
            }
            let frame = Frame {
                text: message,
                truncated: false,
                multiline: false,
                bytes: trimmed.len() as u64,
            };
            let mut parsed = parser::parse(source.parser_name(), &frame.text);
            enrich_from_journal(&val, &mut parsed);
            let origin = if source.unit.is_empty() {
                None
            } else {
                Some(source.unit.as_str())
            };
            let event = normalize::normalize(agent_id, hostname, source, origin, &frame, parsed);
            if !pipeline::try_emit(tx, event, "log") {
                // Channel full: do not persist the cursor so we retry this
                // record after restart. Backpressure without silent loss.
                return Follow::Restart;
            }
            since_ckpt += 1;
            if since_ckpt >= 32 {
                persist_cursor(checkpoint_path, &source.name, cursor.as_deref());
                since_ckpt = 0;
            }
        }
        if tx.is_closed() {
            let _ = child.kill().await;
            persist_cursor(checkpoint_path, &source.name, cursor.as_deref());
            return Follow::Shutdown;
        }
    }
}

fn journal_message(val: &serde_json::Value) -> String {
    match val.get("MESSAGE") {
        Some(serde_json::Value::String(s)) => s.clone(),
        Some(serde_json::Value::Array(arr)) => {
            // journald may emit MESSAGE as a byte array for non-UTF8.
            let bytes: Vec<u8> = arr
                .iter()
                .filter_map(|v| v.as_u64().map(|n| n as u8))
                .collect();
            String::from_utf8_lossy(&bytes).into_owned()
        }
        _ => String::new(),
    }
}

fn enrich_from_journal(val: &serde_json::Value, parsed: &mut parser::Parsed) {
    if parsed.pid.is_none() {
        parsed.pid = val
            .get("_PID")
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse().ok());
    }
    if parsed.uid.is_none() {
        parsed.uid = val
            .get("_UID")
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse().ok());
    }
    if parsed.app_name.is_none() {
        parsed.app_name = val
            .get("SYSLOG_IDENTIFIER")
            .and_then(|v| v.as_str())
            .map(str::to_string);
    }
    if parsed.hostname.is_none() {
        parsed.hostname = val
            .get("_HOSTNAME")
            .and_then(|v| v.as_str())
            .map(str::to_string);
    }
    if parsed.severity_raw.is_none() {
        if let Some(pri) = val.get("PRIORITY").and_then(|v| v.as_str()) {
            parsed.severity_raw = Some(pri.to_string());
            if let Ok(n) = pri.parse::<u8>() {
                parsed.severity = match n {
                    0..=2 => crate::schema::Severity::Critical,
                    3 => crate::schema::Severity::High,
                    4 => crate::schema::Severity::Medium,
                    5 => crate::schema::Severity::Low,
                    _ => crate::schema::Severity::Info,
                };
            }
        }
    }
    if let Some(exe) = val.get("_EXE").and_then(|v| v.as_str()) {
        parsed.fields.insert("exe".into(), exe.to_string());
    }
    if let Some(comm) = val.get("_COMM").and_then(|v| v.as_str()) {
        parsed.fields.insert("comm".into(), comm.to_string());
    }
}

fn persist_cursor(path: &std::path::Path, name: &str, cursor: Option<&str>) {
    let Some(c) = cursor else { return };
    let mut store = CheckpointStore::load(path);
    store
        .journal_cursors
        .insert(name.to_string(), c.to_string());
    if let Err(e) = store.save(path) {
        debug!(error = %e, "log collector: journal cursor persist failed");
    }
}

fn which_journalctl() -> Option<std::path::PathBuf> {
    for dir in ["/usr/bin", "/bin", "/usr/sbin"] {
        let p = std::path::Path::new(dir).join("journalctl");
        if p.is_file() {
            return Some(p);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_shell_metacharacters_in_unit() {
        assert!(valid_journal_token("sshd.service"));
        assert!(valid_journal_token("user@1000.service"));
        assert!(!valid_journal_token("sshd.service;id"));
        assert!(!valid_journal_token("a b"));
        assert!(!valid_journal_token(""));
        assert!(!valid_journal_token("$(reboot)"));
    }

    #[test]
    fn journal_message_string_and_bytes() {
        let s = serde_json::json!({"MESSAGE": "hello"});
        assert_eq!(journal_message(&s), "hello");
        let b = serde_json::json!({"MESSAGE": [104, 105]});
        assert_eq!(journal_message(&b), "hi");
        let empty = serde_json::json!({"__CURSOR": "x"});
        assert!(journal_message(&empty).is_empty());
    }
}
