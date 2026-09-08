//! Normalizer: [`ParsedLog`] + source metadata → canonical [`AgentEvent`].

use std::collections::BTreeMap;

use crate::config::LogSourceConfig;
use crate::schema::{AgentEvent, EventAction, EventClass, EventData, LogEventData, Severity};
use crate::telemetry::limits::{truncate_str, Truncation};

use super::parser::ParsedLog;

/// Ceiling on the serialized message even after the source's own max. Keeps a
/// single log event from filling the ingest batch on its own.
const MAX_MESSAGE_BYTES: usize = 32 * 1024;

/// Position / truncation metadata attached to a framed record.
pub struct EmitMeta<'a> {
    pub source_path: &'a str,
    pub offset: Option<u64>,
    pub inode: Option<u64>,
    pub truncated: bool,
    pub original_len: usize,
}

pub fn to_event(
    agent_id: &str,
    hostname: &str,
    source: &LogSourceConfig,
    parsed: ParsedLog,
    meta: EmitMeta<'_>,
) -> AgentEvent {
    let severity = parsed
        .severity_hint
        .or_else(|| parsed.severity.as_deref().map(word_severity))
        .unwrap_or(Severity::Info);

    let (message, msg_trunc) = truncate_str(&parsed.message, MAX_MESSAGE_BYTES);
    let mut truncated_fields: BTreeMap<String, Truncation> = BTreeMap::new();
    if let Some(t) = msg_trunc {
        truncated_fields.insert("message".into(), t);
    } else if meta.truncated {
        truncated_fields.insert(
            "message".into(),
            Truncation::new(meta.original_len, message.len()),
        );
    }

    let data = LogEventData {
        source: source.name.clone(),
        source_type: source.kind().as_str().to_string(),
        source_path: meta.source_path.to_string(),
        parser: source.parser.clone(),
        message,
        category: if parsed.category.is_empty() {
            "application".into()
        } else {
            parsed.category
        },
        log_timestamp: parsed.timestamp,
        facility: parsed.facility,
        log_severity: parsed.severity,
        proc: parsed.proc,
        pid: parsed.pid,
        uid: parsed.uid,
        username: parsed.username,
        log_host: parsed.host,
        fields: parsed.fields,
        mitre_tactic: parsed.mitre_tactic,
        mitre_technique: parsed.mitre_technique,
        offset: meta.offset,
        inode: meta.inode,
        truncated_fields: if truncated_fields.is_empty() {
            None
        } else {
            Some(truncated_fields)
        },
    };

    AgentEvent::new(
        agent_id.to_string(),
        hostname.to_string(),
        EventClass::Log,
        EventAction::Log,
        severity,
        EventData::Log(Box::new(data)),
    )
    .with_source(&format!("log:{}", source.name))
}

fn word_severity(s: &str) -> Severity {
    match s.to_ascii_lowercase().as_str() {
        "emerg" | "emergency" | "panic" | "fatal" | "crit" | "critical" | "alert" => {
            Severity::Critical
        }
        "err" | "error" => Severity::High,
        "warning" | "warn" | "notice" => Severity::Medium,
        _ => Severity::Info,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::LogSourceConfig;

    #[test]
    fn stamps_source_and_class() {
        let src = LogSourceConfig::file("nginx", "/var/log/nginx/access.log", "nginx_access");
        let parsed = ParsedLog {
            message: "GET /".into(),
            category: "web".into(),
            severity_hint: Some(Severity::Info),
            ..Default::default()
        };
        let ev = to_event(
            "a",
            "host",
            &src,
            parsed,
            EmitMeta {
                source_path: "/var/log/nginx/access.log",
                offset: Some(12),
                inode: Some(7),
                truncated: false,
                original_len: 0,
            },
        );
        assert!(matches!(ev.class, EventClass::Log));
        assert!(matches!(ev.action, EventAction::Log));
        let EventData::Log(d) = ev.data else {
            panic!("expected log")
        };
        assert_eq!(d.source, "nginx");
        assert_eq!(d.source_type, "file");
        assert_eq!(d.inode, Some(7));
        assert_eq!(d.offset, Some(12));
    }
}
