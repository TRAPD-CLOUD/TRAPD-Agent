//! Parsed record → canonical [`crate::schema::LogEventData`].

use crate::config::LogSourceConfig;
use crate::schema::{AgentEvent, EventAction, EventClass, EventData, LogEventData};
use crate::telemetry::limits::{truncate_str, MAX_EVENT_BYTES};

use super::framing::Frame;
use super::parser::Parsed;
use super::redact;

/// Ceiling on the stored `message` field. Well under [`MAX_EVENT_BYTES`] so the
/// extracted fields still fit next to it.
const MAX_MESSAGE_BYTES: usize = 32 * 1024;

pub fn normalize(
    agent_id: &str,
    hostname: &str,
    source: &LogSourceConfig,
    origin_path: Option<&str>,
    frame: &Frame,
    parsed: Parsed,
) -> AgentEvent {
    let redacted = redact::redact(&frame.text);
    let (message, msg_trunc) = truncate_str(&redacted, MAX_MESSAGE_BYTES);

    let data = LogEventData {
        source: source.name.clone(),
        source_type: source.kind_label().to_string(),
        parser: source.parser_name().to_string(),
        message,
        path: origin_path.map(str::to_string),
        log_timestamp: parsed.timestamp,
        facility: parsed.facility,
        severity_raw: parsed.severity_raw,
        hostname_raw: parsed.hostname,
        app_name: parsed.app_name,
        proc_id: parsed.proc_id,
        pid: parsed.pid,
        uid: parsed.uid,
        username: parsed.username,
        src_addr: parsed.src_addr,
        src_port: parsed.src_port,
        dst_addr: parsed.dst_addr,
        dst_port: parsed.dst_port,
        http_method: parsed.http_method,
        http_status: parsed.http_status,
        http_path: parsed.http_path,
        http_user_agent: parsed.http_user_agent,
        event_category: parsed.event_category,
        event_outcome: parsed.event_outcome,
        mitre_tactic: parsed.mitre_tactic,
        mitre_technique: parsed.mitre_technique,
        fields: parsed.fields,
        truncated: frame.truncated || msg_trunc.is_some(),
        multiline: frame.multiline,
    };

    let event = AgentEvent::new(
        agent_id.to_string(),
        hostname.to_string(),
        EventClass::Log,
        EventAction::Log,
        parsed.severity,
        EventData::Log(Box::new(data)),
    )
    .with_source("log");

    // Defensive: if the envelope still exceeds the event ceiling (a json
    // object with hundreds of fields), trim `fields` rather than dropping —
    // the message itself is the evidence.
    cap_event_size(event)
}

fn cap_event_size(mut event: AgentEvent) -> AgentEvent {
    if let Ok(bytes) = serde_json::to_vec(&event) {
        if bytes.len() <= MAX_EVENT_BYTES {
            return event;
        }
    }
    if let EventData::Log(ref mut log) = event.data {
        log.fields.clear();
        log.truncated = true;
        let (msg, _) = truncate_str(&log.message, 4096);
        log.message = msg;
    }
    event
}

#[cfg(test)]
mod tests {
    use super::super::parser;
    use super::*;
    use crate::config::LogSourceConfig;

    fn src(parser: &str) -> LogSourceConfig {
        LogSourceConfig {
            name: "nginx".into(),
            source_type: "file".into(),
            path: "/var/log/nginx/access.log".into(),
            parser: parser.into(),
            unit: String::new(),
            identifier: String::new(),
            multiline: None,
            start_at: String::new(),
            exclude: vec![],
            rate_limit: None,
        }
    }

    #[test]
    fn builds_canonical_event() {
        let line =
            r#"203.0.113.9 - - [10/Oct/2023:13:55:36 +0000] "GET / HTTP/1.1" 200 12 "-" "curl""#;
        let frame = Frame {
            text: line.into(),
            truncated: false,
            multiline: false,
            bytes: line.len() as u64,
        };
        let parsed = parser::parse("nginx_access", line);
        let event = normalize(
            "agent",
            "host",
            &src("nginx_access"),
            Some("/var/log/nginx/access.log"),
            &frame,
            parsed,
        );
        assert!(matches!(event.class, EventClass::Log));
        assert!(matches!(event.action, EventAction::Log));
        match event.data {
            EventData::Log(d) => {
                assert_eq!(d.source, "nginx");
                assert_eq!(d.parser, "nginx_access");
                assert_eq!(d.http_status, Some(200));
                assert_eq!(d.src_addr.as_deref(), Some("203.0.113.9"));
                assert!(!d.message.contains("AKIA"));
            }
            _ => panic!("expected Log"),
        }
    }

    #[test]
    fn redacts_secrets_in_message() {
        let line = "password=hunter2 AKIAIOSFODNN7EXAMPLE";
        let frame = Frame {
            text: line.into(),
            truncated: false,
            multiline: false,
            bytes: line.len() as u64,
        };
        let event = normalize(
            "a",
            "h",
            &src("plain"),
            None,
            &frame,
            parser::parse("plain", line),
        );
        match event.data {
            EventData::Log(d) => {
                assert!(!d.message.contains("hunter2"));
                assert!(!d.message.contains("AKIAIOSFODNN7EXAMPLE"));
            }
            _ => panic!("expected Log"),
        }
    }
}
