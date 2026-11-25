//! Parse one `journalctl --output=json` line.
//!
//! Free of I/O so `fuzz/fuzz_targets/journal_json.rs` can exercise it with
//! arbitrary input.

use serde_json::{Map, Value};

use super::ParsedLog;

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
