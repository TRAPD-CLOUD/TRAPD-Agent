//! SIEM forwarding: emit each event to existing security infrastructure in a
//! standard wire format, in parallel with the native backend ingest.
//!
//! Three industry formats are produced from the agent's `AgentEvent`:
//!
//!   * **CEF** (ArcSight Common Event Format) — `CEF:0|TRAPD|...`
//!   * **LEEF** (IBM QRadar Log Event Extended Format) — `LEEF:2.0|TRAPD|...`
//!   * **JSON** — the native NDJSON line (for generic collectors)
//!
//! and shipped over either:
//!
//!   * **syslog** (RFC 5424 framing) to a local Unix datagram socket
//!     (`unix:///dev/log`) or a remote `udp://host:port`, or
//!   * **Splunk HEC** (`https://host:8088/services/collector`) via HTTP POST.
//!
//! Forwarding is best-effort and never blocks or fails the telemetry pipeline:
//! a dropped SIEM packet is a forwarding miss, not lost local telemetry (the
//! NDJSON log + backend spool remain the system of record).

use std::sync::Arc;

use tracing::{debug, warn};

use crate::config::AgentConfig;
use crate::schema::{AgentEvent, Severity};

/// Where a syslog line is delivered.
#[derive(Debug, Clone)]
enum SyslogSink {
    /// Local Unix datagram socket, e.g. `/dev/log`.
    Unix(String),
    /// Remote `host:port` over UDP.
    Udp(String),
}

fn parse_syslog_addr(s: &str) -> Option<SyslogSink> {
    let s = s.trim();
    if let Some(path) = s.strip_prefix("unix://") {
        Some(SyslogSink::Unix(path.to_string()))
    } else if let Some(hp) = s.strip_prefix("udp://") {
        Some(SyslogSink::Udp(hp.to_string()))
    } else if s.starts_with('/') {
        Some(SyslogSink::Unix(s.to_string()))
    } else if s.contains(':') {
        Some(SyslogSink::Udp(s.to_string()))
    } else {
        None
    }
}

/// Best-effort, non-blocking SIEM forwarder. Constructed from the live config;
/// a disabled or unconfigured forwarder is a cheap no-op.
#[derive(Clone)]
pub struct SiemForwarder {
    enabled: bool,
    fmt: SiemFormat,
    version: String,
    syslog: Option<SyslogSink>,
    hec_url: Option<String>,
    hec_token: Option<String>,
    http: Arc<reqwest::Client>,
}

impl SiemForwarder {
    /// Build a forwarder from config. Network sinks are resolved lazily on each
    /// send so a transiently-unreachable collector never blocks startup.
    pub fn from_config(cfg: &AgentConfig, version: &str) -> Self {
        let syslog = if cfg.siem_syslog_address.trim().is_empty() {
            None
        } else {
            parse_syslog_addr(&cfg.siem_syslog_address)
        };
        // A plain (non-pinned) client: SIEM/HEC endpoints are operator-trusted
        // infrastructure, not the agent's authenticated control plane.
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .unwrap_or_default();
        Self {
            enabled: cfg.siem_enabled,
            fmt: SiemFormat::parse(&cfg.siem_format),
            version: version.to_string(),
            syslog,
            hec_url: Some(cfg.siem_hec_url.clone()).filter(|s| !s.is_empty()),
            hec_token: Some(cfg.siem_hec_token.clone()).filter(|s| !s.is_empty()),
            http: Arc::new(http),
        }
    }

    pub fn is_active(&self) -> bool {
        self.enabled && (self.syslog.is_some() || self.hec_url.is_some())
    }

    /// Forward one event to every configured sink. Best-effort: each sink's
    /// failure is logged and swallowed.
    pub async fn forward(&self, event: &AgentEvent) {
        if !self.enabled {
            return;
        }
        let line = format_line(event, self.fmt, &self.version);

        if let Some(sink) = &self.syslog {
            let framed = rfc5424(event, &line);
            if let Err(e) = self.send_syslog(sink, framed.as_bytes()).await {
                debug!(error = %e, "syslog forward failed");
            }
        }

        if let (Some(url), Some(token)) = (&self.hec_url, &self.hec_token) {
            if let Err(e) = self.send_hec(url, token, event, &line).await {
                debug!(error = %e, "HEC forward failed");
            }
        }
    }

    async fn send_syslog(&self, sink: &SyslogSink, bytes: &[u8]) -> anyhow::Result<()> {
        match sink {
            #[cfg(unix)]
            SyslogSink::Unix(path) => {
                let sock = tokio::net::UnixDatagram::unbound()?;
                sock.send_to(bytes, path).await?;
            }
            // Unix-domain syslog sockets do not exist on Windows; the sink is
            // refused at configuration time, this arm is unreachable.
            #[cfg(not(unix))]
            SyslogSink::Unix(path) => {
                anyhow::bail!("unix syslog socket {path:?} unsupported on this platform")
            }
            SyslogSink::Udp(addr) => {
                let sock = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
                sock.send_to(bytes, addr).await?;
            }
        }
        Ok(())
    }

    async fn send_hec(
        &self,
        url: &str,
        token: &str,
        event: &AgentEvent,
        line: &str,
    ) -> anyhow::Result<()> {
        let body = serde_json::json!({
            "time": event.timestamp.timestamp_millis() as f64 / 1000.0,
            "host": event.hostname,
            "source": "trapd-agent",
            "sourcetype": "trapd:event",
            "event": match self.fmt {
                SiemFormat::Json => serde_json::to_value(event).unwrap_or_default(),
                _ => serde_json::Value::String(line.to_string()),
            },
        });
        let resp = self
            .http
            .post(url)
            .header("Authorization", format!("Splunk {token}"))
            .json(&body)
            .send()
            .await?;
        if !resp.status().is_success() {
            warn!(status = %resp.status(), "HEC endpoint rejected event");
        }
        Ok(())
    }
}

/// SIEM line format selector (`AgentConfig.siem_format`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SiemFormat {
    Cef,
    Leef,
    Json,
}

impl SiemFormat {
    pub fn parse(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "leef" => SiemFormat::Leef,
            "json" => SiemFormat::Json,
            _ => SiemFormat::Cef,
        }
    }
}

/// Map the agent severity ladder to the CEF 0–10 severity scale.
fn cef_severity(sev: Severity) -> u8 {
    match sev {
        Severity::Info => 1,
        Severity::Low => 3,
        Severity::Medium => 5,
        Severity::High => 8,
        Severity::Critical => 10,
    }
}

/// Lower-case syslog-style severity keyword (used by LEEF and HEC metadata).
fn severity_word(sev: Severity) -> &'static str {
    match sev {
        Severity::Info => "info",
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}

/// Escape a CEF *extension value*: backslash, equals and newlines.
fn cef_escape_ext(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('=', "\\=")
        .replace(['\n', '\r'], " ")
}

/// Escape a CEF *header field*: backslash and pipe.
fn cef_escape_hdr(s: &str) -> String {
    s.replace('\\', "\\\\").replace('|', "\\|")
}

fn action_name(event: &AgentEvent) -> String {
    format!("{:?}", event.action)
}

fn class_name(event: &AgentEvent) -> String {
    format!("{:?}", event.class)
}

/// Render an event as a CEF line (without syslog framing).
pub fn to_cef(event: &AgentEvent, version: &str) -> String {
    let sig = cef_escape_hdr(&action_name(event));
    let name = cef_escape_hdr(&class_name(event));
    let sev = cef_severity(event.severity);

    // Extension: stable, SIEM-parseable key=value pairs plus the full event as
    // a JSON blob for fidelity.
    let json = serde_json::to_string(&event.data).unwrap_or_default();
    let ext = format!(
        "rt={} deviceExternalId={} dvchost={} cs1Label=eventId cs1={} cs2Label=eventClass cs2={} cs3Label=payload cs3={}",
        event.timestamp.timestamp_millis(),
        cef_escape_ext(&event.agent_id),
        cef_escape_ext(&event.hostname),
        cef_escape_ext(&event.event_id.to_string()),
        cef_escape_ext(&name),
        cef_escape_ext(&json),
    );

    format!("CEF:0|TRAPD|trapd-agent|{version}|{sig}|{name}|{sev}|{ext}")
}

/// Render an event as a LEEF 2.0 line (tab-delimited attributes).
pub fn to_leef(event: &AgentEvent, version: &str) -> String {
    let sig = action_name(event);
    let json = serde_json::to_string(&event.data).unwrap_or_default();
    // LEEF 2.0 with an explicit tab delimiter declaration (^|x09 = TAB).
    let attrs = [
        format!("devTime={}", event.timestamp.to_rfc3339()),
        format!("severity={}", severity_word(event.severity)),
        format!("eventId={}", event.event_id),
        format!("cat={}", class_name(event)),
        format!("identSrc={}", event.hostname),
        format!("agent={}", event.agent_id),
        format!("payload={}", json.replace(['\t', '\n'], " ")),
    ]
    .join("\t");
    format!("LEEF:2.0|TRAPD|trapd-agent|{version}|{sig}|\t|{attrs}")
}

/// Render an event in the selected SIEM line format.
pub fn format_line(event: &AgentEvent, fmt: SiemFormat, version: &str) -> String {
    match fmt {
        SiemFormat::Cef => to_cef(event, version),
        SiemFormat::Leef => to_leef(event, version),
        SiemFormat::Json => serde_json::to_string(event).unwrap_or_default(),
    }
}

/// Map agent severity to an RFC 5424 syslog severity code (0–7) combined with
/// the `local0` facility (16) into a PRI value.
fn syslog_pri(sev: Severity) -> u8 {
    const FACILITY_LOCAL0: u8 = 16;
    let severity = match sev {
        Severity::Critical => 2, // critical
        Severity::High => 3,     // error
        Severity::Medium => 4,   // warning
        Severity::Low => 5,      // notice
        Severity::Info => 6,     // informational
    };
    FACILITY_LOCAL0 * 8 + severity
}

/// Wrap a preformatted message in RFC 5424 syslog framing.
pub fn rfc5424(event: &AgentEvent, msg: &str) -> String {
    let pri = syslog_pri(event.severity);
    let ts = event.timestamp.to_rfc3339();
    let host = if event.hostname.is_empty() {
        "-"
    } else {
        event.hostname.as_str()
    };
    // <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
    format!(
        "<{pri}>1 {ts} {host} trapd-agent {} - - {msg}",
        std::process::id()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{AgentEvent, EventAction, EventClass, EventData, SetuidData, Severity};

    fn ev() -> AgentEvent {
        AgentEvent::new(
            "agent-1".into(),
            "host-a".into(),
            EventClass::Process,
            EventAction::Setuid,
            Severity::High,
            EventData::Setuid(SetuidData {
                pid: 42,
                old_uid: 1000,
                new_uid: 0,
                comm: "sudo".into(),
            }),
        )
    }

    #[test]
    fn cef_has_well_formed_header() {
        let line = to_cef(&ev(), "0.4.4");
        assert!(line.starts_with("CEF:0|TRAPD|trapd-agent|0.4.4|Setuid|Process|8|"));
        assert!(line.contains("deviceExternalId=agent-1"));
        assert!(line.contains("dvchost=host-a"));
    }

    #[test]
    fn cef_escapes_extension_specials() {
        // An '=' inside a value must be escaped so the SIEM parser is not fooled.
        assert_eq!(cef_escape_ext("a=b\\c"), "a\\=b\\\\c");
        // A pipe in a header field must be escaped.
        assert_eq!(cef_escape_hdr("a|b"), "a\\|b");
    }

    #[test]
    fn leef_has_version_and_tab_delimiter() {
        let line = to_leef(&ev(), "0.4.4");
        assert!(line.starts_with("LEEF:2.0|TRAPD|trapd-agent|0.4.4|Setuid|"));
        assert!(line.contains("severity=high"));
        assert!(line.contains('\t'));
    }

    #[test]
    fn rfc5424_pri_encodes_local0_and_severity() {
        // local0 (16) * 8 + error (3) for High = 131.
        let line = rfc5424(&ev(), "hello");
        assert!(line.starts_with("<131>1 "));
        assert!(line.ends_with(" hello"));
        assert!(line.contains("host-a trapd-agent"));
    }

    #[test]
    fn format_line_selects_format() {
        assert!(format_line(&ev(), SiemFormat::Cef, "v").starts_with("CEF:0|"));
        assert!(format_line(&ev(), SiemFormat::Leef, "v").starts_with("LEEF:2.0|"));
        assert!(format_line(&ev(), SiemFormat::Json, "v").starts_with('{'));
    }
}
