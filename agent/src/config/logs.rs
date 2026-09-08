//! Configuration for the generic Linux log collector.
//!
//! Lives next to [`crate::config::AgentConfig`] so the signed-config envelope
//! stays OS-neutral: a Windows agent ignores the field, a Linux agent applies
//! it. Absent from a signed envelope (`None` on [`crate::config::AgentConfig::logs`])
//! means "use these defaults" — enabled, auto-discover well-known security
//! logs, conservative rate limits.

use serde::{Deserialize, Serialize};

fn default_true() -> bool {
    true
}
fn default_max_line_bytes() -> usize {
    1024 * 1024
}
fn default_max_events_per_sec() -> u32 {
    2_000
}
fn default_multiline_max_lines() -> usize {
    100
}
fn default_multiline_max_bytes() -> usize {
    64 * 1024
}
fn default_checkpoint_interval_ms() -> u64 {
    1_000
}
fn default_max_open_files() -> usize {
    256
}
fn default_source_type() -> String {
    "file".into()
}
fn default_parser() -> String {
    "auto".into()
}
fn default_start_at() -> String {
    "end".into()
}
fn default_multiline_timeout_ms() -> u64 {
    1_000
}

/// Top-level log-collector settings, nested under `AgentConfig.logs`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LogCollectorConfig {
    /// Master switch. When `false` the collector stays idle (no readers).
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Probe well-known Linux security log paths (nginx, apache, postgres,
    /// mysql, auditd, …) and start tailing any that exist. Custom `sources`
    /// always win on name collision.
    #[serde(default = "default_true")]
    pub auto_discover: bool,
    /// Explicit sources. `type` is `file` (globs ok), `journal` or `syslog`.
    #[serde(default)]
    pub sources: Vec<LogSourceConfig>,
    /// Hard ceiling on a single physical line (or syslog datagram). Oversized
    /// input is cut on a UTF-8 boundary, marked `truncated`, and the reader
    /// resynchronises on the next newline — a hostile log line cannot pin the
    /// process.
    #[serde(default = "default_max_line_bytes")]
    pub max_line_bytes: usize,
    /// Global token-bucket rate. Excess records are dropped as
    /// `rate_limit_applied` rather than stalling every other collector.
    #[serde(default = "default_max_events_per_sec")]
    pub max_events_per_sec: u32,
    /// Multiline: maximum physical lines assembled into one record.
    #[serde(default = "default_multiline_max_lines")]
    pub multiline_max_lines: usize,
    /// Multiline: maximum assembled payload in bytes.
    #[serde(default = "default_multiline_max_bytes")]
    pub multiline_max_bytes: usize,
    /// How often file/journal cursors are fsync'd to
    /// `<state>/log_offsets.json`.
    #[serde(default = "default_checkpoint_interval_ms")]
    pub checkpoint_interval_ms: u64,
    /// Cap on simultaneously-open log files (globs such as docker json-file
    /// logs can otherwise exhaust fds). Least-recently-read files are closed
    /// and reopened on the next write.
    #[serde(default = "default_max_open_files")]
    pub max_open_files: usize,
    /// Default harvest position for files without a checkpoint: `end` (skip
    /// history) or `beginning` (catch-up). Files created *after* the collector
    /// starts are always read from the beginning so a new log is not missed.
    #[serde(default = "default_start_at")]
    pub start_at: String,
}

impl Default for LogCollectorConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            auto_discover: true,
            sources: Vec::new(),
            max_line_bytes: default_max_line_bytes(),
            max_events_per_sec: default_max_events_per_sec(),
            multiline_max_lines: default_multiline_max_lines(),
            multiline_max_bytes: default_multiline_max_bytes(),
            checkpoint_interval_ms: default_checkpoint_interval_ms(),
            max_open_files: default_max_open_files(),
            start_at: default_start_at(),
        }
    }
}

impl LogCollectorConfig {
    pub fn max_line_bytes(&self) -> usize {
        self.max_line_bytes.clamp(1024, 8 * 1024 * 1024)
    }

    pub fn max_events_per_sec(&self) -> u32 {
        self.max_events_per_sec.clamp(1, 100_000)
    }

    pub fn multiline_max_lines(&self) -> usize {
        self.multiline_max_lines.clamp(2, 10_000)
    }

    pub fn multiline_max_bytes(&self) -> usize {
        self.multiline_max_bytes.clamp(1024, 4 * 1024 * 1024)
    }

    pub fn checkpoint_interval_ms(&self) -> u64 {
        self.checkpoint_interval_ms.clamp(100, 60_000)
    }

    pub fn max_open_files(&self) -> usize {
        self.max_open_files.clamp(4, 4_096)
    }

    pub fn start_at_beginning(&self) -> bool {
        matches!(
            self.start_at.trim().to_ascii_lowercase().as_str(),
            "beginning" | "start"
        )
    }
}

/// One log source. Not a per-application collector: the same reader/framing/
/// parser/normalizer pipeline serves every entry.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LogSourceConfig {
    pub name: String,
    /// `file` | `journal` | `syslog`.
    #[serde(rename = "type", default = "default_source_type")]
    pub source_type: String,
    /// File path or glob (`/var/log/nginx/*.log`), syslog listen address
    /// (`unix:///run/trapd/syslog.sock`, `udp://127.0.0.1:1514`), ignored for
    /// `journal`.
    #[serde(default)]
    pub path: String,
    /// Parser name: `auto`, `json`, `syslog`, `nginx_access`, `nginx_error`,
    /// `apache_access`, `apache_error`, `postgresql`, `mysql`, `docker`,
    /// `ssh`, `sudo`, `auditd`, `plain`.
    #[serde(default = "default_parser")]
    pub parser: String,
    /// systemd unit filter (`sshd.service`) for `type: journal`.
    #[serde(default)]
    pub unit: String,
    /// `SYSLOG_IDENTIFIER` filter for `type: journal`.
    #[serde(default)]
    pub identifier: String,
    /// Optional multiline assembly (stack traces, postgres statements, …).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub multiline: Option<MultilineConfig>,
    /// Per-source harvest position; empty inherits the collector default.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub start_at: String,
    /// Globs of paths to skip (rotated compressed files, `*.gz`, …).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exclude: Vec<String>,
    /// Optional per-source events/sec cap, on top of the global bucket.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_limit: Option<u32>,
}

impl LogSourceConfig {
    pub fn kind(&self) -> SourceKind {
        match self.source_type.trim().to_ascii_lowercase().as_str() {
            "journal" | "journald" | "systemd" => SourceKind::Journal,
            "syslog" => SourceKind::Syslog,
            _ => SourceKind::File,
        }
    }

    pub fn kind_label(&self) -> &'static str {
        match self.kind() {
            SourceKind::File => "file",
            SourceKind::Journal => "journal",
            SourceKind::Syslog => "syslog",
        }
    }

    pub fn parser_name(&self) -> &str {
        let p = self.parser.trim();
        if p.is_empty() {
            "auto"
        } else {
            p
        }
    }

    pub fn start_at_beginning(&self, collector_default: bool) -> bool {
        if self.start_at.is_empty() {
            collector_default
        } else {
            matches!(
                self.start_at.trim().to_ascii_lowercase().as_str(),
                "beginning" | "start"
            )
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceKind {
    File,
    Journal,
    Syslog,
}

/// Filebeat-style multiline: a line matching `pattern` starts a new record;
/// subsequent non-matching lines are appended until `timeout_ms`,
/// `multiline_max_lines` or `multiline_max_bytes`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MultilineConfig {
    /// Regex (Rust `regex` crate). Unanchored unless the pattern itself
    /// starts with `^`. Typical: `^[0-9]{4}-[0-9]{2}-[0-9]{2}` for postgres.
    pub pattern: String,
    /// When `true`, lines that *match* are continuations (match-before).
    /// Default `false` is match-after: the pattern marks a *new* record.
    #[serde(default)]
    pub negate: bool,
    #[serde(default = "default_multiline_timeout_ms")]
    pub timeout_ms: u64,
}

impl MultilineConfig {
    pub fn timeout_ms(&self) -> u64 {
        self.timeout_ms.clamp(50, 60_000)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_enabled_with_autodiscover() {
        let c = LogCollectorConfig::default();
        assert!(c.enabled);
        assert!(c.auto_discover);
        assert!(c.sources.is_empty());
        assert!(!c.start_at_beginning());
    }

    #[test]
    fn source_type_aliases_journal() {
        let s = LogSourceConfig {
            name: "sshd".into(),
            source_type: "journald".into(),
            path: String::new(),
            parser: "ssh".into(),
            unit: "sshd.service".into(),
            identifier: String::new(),
            multiline: None,
            start_at: String::new(),
            exclude: vec![],
            rate_limit: None,
        };
        assert_eq!(s.kind(), SourceKind::Journal);
        assert_eq!(s.parser_name(), "ssh");
    }

    #[test]
    fn yaml_file_source_round_trip() {
        let raw = r#"
name: nginx
type: file
path: /var/log/nginx/access.log
parser: nginx_access
"#;
        let s: LogSourceConfig = serde_yaml_ng::from_str(raw).unwrap();
        assert_eq!(s.name, "nginx");
        assert_eq!(s.kind(), SourceKind::File);
        assert_eq!(s.parser, "nginx_access");
        assert_eq!(s.path, "/var/log/nginx/access.log");
    }

    #[test]
    fn yaml_glob_and_json_parser() {
        let raw = r#"
name: app
type: file
path: /var/log/myapp/*.log
parser: json
"#;
        let s: LogSourceConfig = serde_yaml_ng::from_str(raw).unwrap();
        assert_eq!(s.path, "/var/log/myapp/*.log");
        assert_eq!(s.parser_name(), "json");
    }

    #[test]
    fn clamps_reject_zeros_and_absurd_values() {
        let c = LogCollectorConfig {
            max_line_bytes: 1,
            max_events_per_sec: 0,
            multiline_max_lines: 1,
            ..Default::default()
        };
        assert!(c.max_line_bytes() >= 1024);
        assert!(c.max_events_per_sec() >= 1);
        assert!(c.multiline_max_lines() >= 2);
    }
}
