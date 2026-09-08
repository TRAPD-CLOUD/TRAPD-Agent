//! Log-collector source configuration.
//!
//! Lives next to [`super::AgentConfig`] so the signed-config envelope stays
//! OS-neutral: a Windows agent can parse (and ignore) a Linux log catalogue,
//! and the canonical JSON field order is identical on every platform.
//!
//! A source describes *what to read* and *how to interpret it*. The collector
//! pipeline is:
//!
//! ```text
//! LogSource → Reader → Framing / Multiline → Parser → Normalizer → Canonical Event
//! ```
//!
//! Individual products (nginx, sshd, auditd, …) are parsers, not collectors.
//! Adding a new application is a parser + a catalogue entry, not a new
//! collector task.

use serde::{Deserialize, Serialize};

fn default_parser() -> String {
    "auto".into()
}
fn default_read_from() -> String {
    "end".into()
}
fn default_max_eps() -> u32 {
    2_000
}
fn default_max_line_bytes() -> usize {
    64 * 1024
}
fn default_multiline_max_lines() -> usize {
    500
}
fn default_multiline_max_bytes() -> usize {
    64 * 1024
}
fn default_multiline_timeout_ms() -> u64 {
    1_000
}

/// One configured (or auto-discovered) log source.
///
/// ```yaml
/// logs:
///   - name: nginx
///     type: file
///     path: /var/log/nginx/access.log
///     parser: nginx_access
///   - name: app
///     type: file
///     path: /var/log/myapp/*.log
///     parser: json
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LogSourceConfig {
    /// Stable name used in events (`data.source`) and checkpoint keys.
    pub name: String,
    /// Reader kind: `file`, `journal`, or `syslog`.
    #[serde(rename = "type")]
    pub source_type: String,
    /// File path or glob (`file`), unused/empty (`journal`), or listen
    /// address (`syslog`: `udp://127.0.0.1:1514` / `unix:///path`).
    #[serde(default)]
    pub path: String,
    /// Parser: `auto`, `raw`, `json`, `syslog`, `nginx_access`, `nginx_error`,
    /// `apache_access`, `apache_error`, `postgresql`, `mysql`, `docker`,
    /// `sshd`, `sudo`, `auditd`, `kv`, `cef`.
    #[serde(default = "default_parser")]
    pub parser: String,
    /// How to stitch continuation lines (stack traces, SQL, auditd).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub multiline: Option<MultilineConfig>,
    /// Where to start on a file that has no checkpoint: `end` (default,
    /// skip history) or `beginning`.
    #[serde(default = "default_read_from")]
    pub read_from: String,
    /// Per-source token-bucket rate limit in events/second. `0` = unlimited.
    /// Excess lines are dropped as `rate_limit_applied` and the offset still
    /// advances so a flood cannot pin the reader.
    #[serde(default = "default_max_eps")]
    pub max_eps: u32,
    /// Hard ceiling for a single (possibly multiline) record. Longer lines
    /// are cut on a UTF-8 boundary and marked `truncated_fields`.
    #[serde(default = "default_max_line_bytes")]
    pub max_line_bytes: usize,
    /// systemd unit names to follow (`journal` type). Empty = all units,
    /// which is almost never what you want on a busy host.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub units: Vec<String>,
    /// Glob patterns of *file names* to skip when `path` is a glob
    /// (`*.gz`, `*.1`, …).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exclude: Vec<String>,
}

impl LogSourceConfig {
    /// Convenience constructor for tests and the built-in catalogue.
    pub fn file(name: &str, path: &str, parser: &str) -> Self {
        Self {
            name: name.into(),
            source_type: "file".into(),
            path: path.into(),
            parser: parser.into(),
            multiline: None,
            read_from: default_read_from(),
            max_eps: default_max_eps(),
            max_line_bytes: default_max_line_bytes(),
            units: Vec::new(),
            exclude: default_excludes(),
        }
    }

    pub fn journal(name: &str, units: &[&str], parser: &str) -> Self {
        Self {
            name: name.into(),
            source_type: "journal".into(),
            path: String::new(),
            parser: parser.into(),
            multiline: None,
            read_from: default_read_from(),
            max_eps: default_max_eps(),
            max_line_bytes: default_max_line_bytes(),
            units: units.iter().map(|s| (*s).to_string()).collect(),
            exclude: Vec::new(),
        }
    }

    #[allow(dead_code)]
    pub fn syslog(name: &str, listen: &str, parser: &str) -> Self {
        Self {
            name: name.into(),
            source_type: "syslog".into(),
            path: listen.into(),
            parser: parser.into(),
            multiline: None,
            read_from: default_read_from(),
            max_eps: default_max_eps(),
            max_line_bytes: default_max_line_bytes(),
            units: Vec::new(),
            exclude: Vec::new(),
        }
    }

    pub fn with_multiline(mut self, ml: MultilineConfig) -> Self {
        self.multiline = Some(ml);
        self
    }

    #[allow(dead_code)]
    pub fn read_from_beginning(mut self) -> Self {
        self.read_from = "beginning".into();
        self
    }

    /// `file` | `journal` | `syslog`, lower-cased.
    pub fn kind(&self) -> SourceKind {
        SourceKind::parse(&self.source_type)
    }

    pub fn starts_at_end(&self) -> bool {
        !self.read_from.eq_ignore_ascii_case("beginning")
    }
}

fn default_excludes() -> Vec<String> {
    vec![
        "*.gz".into(),
        "*.xz".into(),
        "*.bz2".into(),
        "*.zip".into(),
        "*.zst".into(),
    ]
}

/// Reader backend selected by `LogSourceConfig.source_type`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceKind {
    File,
    Journal,
    Syslog,
}

impl SourceKind {
    pub fn parse(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "journal" | "journald" | "systemd" => SourceKind::Journal,
            "syslog" | "udp" | "rfc5424" | "rfc3164" => SourceKind::Syslog,
            _ => SourceKind::File,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            SourceKind::File => "file",
            SourceKind::Journal => "journal",
            SourceKind::Syslog => "syslog",
        }
    }
}

/// Continuation-line policy. A new record starts when `start` matches.
///
/// Postgres / Java / Python dumps are the usual consumers; auditd uses a
/// dedicated aggregator keyed on `msg=audit(…)` rather than this regex.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MultilineConfig {
    /// Regex evaluated against each physical line. A match starts a new
    /// logical record (unless [`negate`](Self::negate) is set).
    pub start: String,
    #[serde(default = "default_multiline_max_lines")]
    pub max_lines: usize,
    #[serde(default = "default_multiline_max_bytes")]
    pub max_bytes: usize,
    /// Flush an unfinished record after this many milliseconds with no new
    /// line, so a trailing stack trace is not held forever.
    #[serde(default = "default_multiline_timeout_ms")]
    pub timeout_ms: u64,
    /// When `true`, lines that *match* `start` are continuations (Filebeat
    /// `negate` semantics). Default `false`: a match begins a new record.
    #[serde(default)]
    pub negate: bool,
}

impl MultilineConfig {
    pub fn postgres() -> Self {
        Self {
            // `2024-01-15 12:00:00.123 UTC [1234] LOG:` — new statement.
            start: r"^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}".into(),
            max_lines: default_multiline_max_lines(),
            max_bytes: default_multiline_max_bytes(),
            timeout_ms: default_multiline_timeout_ms(),
            negate: false,
        }
    }

    #[allow(dead_code)]
    pub fn java_stack() -> Self {
        Self {
            start: r"^\d{4}-\d{2}-\d{2}[ T]|^\w{3} +\d{1,2} ".into(),
            max_lines: default_multiline_max_lines(),
            max_bytes: default_multiline_max_bytes(),
            timeout_ms: default_multiline_timeout_ms(),
            negate: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_source_round_trips() {
        let src = LogSourceConfig::file("nginx", "/var/log/nginx/access.log", "nginx_access");
        let v = serde_json::to_value(&src).unwrap();
        assert_eq!(v["name"], "nginx");
        assert_eq!(v["type"], "file");
        assert_eq!(v["parser"], "nginx_access");
        let back: LogSourceConfig = serde_json::from_value(v).unwrap();
        assert_eq!(back.name, "nginx");
        assert_eq!(back.kind(), SourceKind::File);
        assert!(back.starts_at_end());
    }

    #[test]
    fn type_aliases_map_to_kind() {
        assert_eq!(SourceKind::parse("JOURNALD"), SourceKind::Journal);
        assert_eq!(SourceKind::parse("rfc5424"), SourceKind::Syslog);
        assert_eq!(SourceKind::parse("file"), SourceKind::File);
    }

    #[test]
    fn missing_optional_fields_take_defaults() {
        let src: LogSourceConfig =
            serde_json::from_str(r#"{"name":"app","type":"file","path":"/var/log/app.log"}"#)
                .unwrap();
        assert_eq!(src.parser, "auto");
        assert_eq!(src.max_eps, 2_000);
        assert_eq!(src.max_line_bytes, 64 * 1024);
        assert_eq!(src.read_from, "end");
    }
}
