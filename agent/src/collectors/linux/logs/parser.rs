//! Parsers: turn a framed line into a structured [`Parsed`] record.
//!
//! One dispatcher, many formats. Adding a source is a new arm — never a new
//! collector. Unknown / failed parses fall back to `plain` so a format drift
//! never silently drops the line.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use chrono::{DateTime, Datelike, TimeZone, Utc};
use regex::Regex;

use crate::schema::Severity;

/// Intermediate parser output. The normalizer maps this onto [`crate::schema::LogEventData`].
#[derive(Debug, Clone)]
pub struct Parsed {
    pub timestamp: Option<DateTime<Utc>>,
    pub facility: Option<String>,
    pub severity_raw: Option<String>,
    pub hostname: Option<String>,
    pub app_name: Option<String>,
    pub proc_id: Option<String>,
    pub pid: Option<i32>,
    pub uid: Option<u32>,
    pub username: Option<String>,
    pub src_addr: Option<String>,
    pub src_port: Option<u16>,
    pub dst_addr: Option<String>,
    pub dst_port: Option<u16>,
    pub http_method: Option<String>,
    pub http_status: Option<u16>,
    pub http_path: Option<String>,
    pub http_user_agent: Option<String>,
    pub event_category: Option<String>,
    pub event_outcome: Option<String>,
    pub mitre_tactic: Option<String>,
    pub mitre_technique: Option<String>,
    pub fields: BTreeMap<String, String>,
    pub severity: Severity,
}

impl Default for Parsed {
    fn default() -> Self {
        Self {
            timestamp: None,
            facility: None,
            severity_raw: None,
            hostname: None,
            app_name: None,
            proc_id: None,
            pid: None,
            uid: None,
            username: None,
            src_addr: None,
            src_port: None,
            dst_addr: None,
            dst_port: None,
            http_method: None,
            http_status: None,
            http_path: None,
            http_user_agent: None,
            event_category: None,
            event_outcome: None,
            mitre_tactic: None,
            mitre_technique: None,
            fields: BTreeMap::new(),
            severity: Severity::Info,
        }
    }
}

impl Parsed {
    fn category(mut self, c: &str) -> Self {
        self.event_category = Some(c.to_string());
        self
    }

    fn put(&mut self, k: &str, v: impl Into<String>) {
        let v = v.into();
        if !v.is_empty() && v != "-" {
            self.fields.insert(k.to_string(), v);
        }
    }
}

pub fn parse(parser: &str, line: &str) -> Parsed {
    let p = parser.trim().to_ascii_lowercase();
    match p.as_str() {
        "json" => parse_json(line),
        "syslog" => parse_syslog(line),
        "nginx_access" => parse_nginx_access(line),
        "nginx_error" => parse_nginx_error(line),
        "apache_access" => parse_apache_access(line),
        "apache_error" => parse_apache_error(line),
        "postgresql" | "postgres" => parse_postgresql(line),
        "mysql" | "mariadb" => parse_mysql(line),
        "docker" => parse_docker(line),
        "ssh" | "sshd" => parse_ssh(line),
        "sudo" => parse_sudo(line),
        "auditd" | "audit" => parse_auditd(line),
        "auto" => parse_auto(line),
        _ => parse_plain(line),
    }
}

pub fn parse_auto(line: &str) -> Parsed {
    let t = line.trim_start();
    if t.starts_with('{') {
        return parse_json(line);
    }
    if t.starts_with('<') {
        return parse_syslog(line);
    }
    if t.starts_with("type=") || t.contains(" msg=audit(") {
        return parse_auditd(line);
    }
    if nginx_access_re().is_match(line) {
        return parse_nginx_access(line);
    }
    parse_plain(line)
}

fn parse_plain(line: &str) -> Parsed {
    Parsed {
        event_category: Some("application".into()),
        severity: Severity::Info,
        ..Default::default()
    }
    .with_app_guess(line)
}

impl Parsed {
    fn with_app_guess(self, _line: &str) -> Self {
        self
    }
}

// ── JSON ────────────────────────────────────────────────────────────────────

fn parse_json(line: &str) -> Parsed {
    let Ok(val) = serde_json::from_str::<serde_json::Value>(line.trim()) else {
        return parse_plain(line);
    };
    let mut p = Parsed {
        event_category: Some("application".into()),
        severity: Severity::Info,
        ..Default::default()
    };
    flatten_json(&val, "", &mut p);
    // Common conventions.
    if let Some(ts) = first_field(&p, &["timestamp", "time", "@timestamp", "ts", "datetime"]) {
        p.timestamp = parse_timestamp(&ts);
    }
    if let Some(lvl) = first_field(&p, &["level", "severity", "log.level", "lvl"]) {
        p.severity_raw = Some(lvl.clone());
        p.severity = severity_from_word(&lvl);
    }
    if let Some(h) = first_field(&p, &["hostname", "host", "host.name"]) {
        p.hostname = Some(h);
    }
    if let Some(a) = first_field(&p, &["app", "application", "service", "syslog_identifier"]) {
        p.app_name = Some(a);
    }
    if let Some(u) = first_field(&p, &["user", "username", "user.name"]) {
        p.username = Some(u);
    }
    if let Some(ip) = first_field(&p, &["src_ip", "source.ip", "client_ip", "remote_addr"]) {
        p.src_addr = Some(ip);
    }
    if let Some(pid) = first_field(&p, &["pid", "process.pid"]) {
        p.pid = pid.parse().ok();
    }
    // Docker json-file driver: {"log":"...","stream":"stdout","time":"..."}
    if p.fields.contains_key("log") && p.fields.contains_key("stream") {
        p.event_category = Some("container".into());
        p.app_name = p.app_name.or(Some("docker".into()));
    }
    p
}

fn flatten_json(val: &serde_json::Value, prefix: &str, p: &mut Parsed) {
    match val {
        serde_json::Value::Object(map) => {
            for (k, v) in map {
                let key = if prefix.is_empty() {
                    k.clone()
                } else {
                    format!("{prefix}.{k}")
                };
                flatten_json(v, &key, p);
            }
        }
        serde_json::Value::Array(arr) => {
            // Cap so a huge array cannot inflate the event.
            for (i, v) in arr.iter().take(16).enumerate() {
                flatten_json(v, &format!("{prefix}.{i}"), p);
            }
        }
        serde_json::Value::String(s) => p.put(prefix, s.clone()),
        serde_json::Value::Number(n) => p.put(prefix, n.to_string()),
        serde_json::Value::Bool(b) => p.put(prefix, b.to_string()),
        serde_json::Value::Null => {}
    }
}

fn first_field(p: &Parsed, names: &[&str]) -> Option<String> {
    for n in names {
        if let Some(v) = p.fields.get(*n) {
            return Some(v.clone());
        }
    }
    None
}

// ── Syslog RFC 5424 / RFC 3164 ──────────────────────────────────────────────

fn parse_syslog(line: &str) -> Parsed {
    let t = line.trim();
    if let Some(p) = parse_rfc5424(t) {
        return p;
    }
    if let Some(p) = parse_rfc3164(t) {
        return p;
    }
    parse_plain(line).category("syslog")
}

/// `<PRI>1 TIMESTAMP HOST APP PROCID MSGID STRUCTURED-DATA MSG`
fn parse_rfc5424(line: &str) -> Option<Parsed> {
    let rest = line.strip_prefix('<')?;
    let (pri_s, rest) = rest.split_once('>')?;
    let pri: u8 = pri_s.parse().ok()?;
    let rest = rest.strip_prefix("1 ")?; // version
    let mut parts = rest.splitn(7, ' ');
    let ts = parts.next()?;
    let host = parts.next()?;
    let app = parts.next()?;
    let procid = parts.next()?;
    let msgid = parts.next()?;
    let sd = parts.next()?;
    let msg = parts.next().unwrap_or("");
    let mut p = pri_to_parsed(pri);
    p.timestamp = parse_timestamp(ts);
    p.hostname = dash(host);
    p.app_name = dash(app);
    p.proc_id = dash(procid);
    p.event_category = Some("syslog".into());
    if msgid != "-" {
        p.put("msgid", msgid);
    }
    if sd != "-" && sd != "[" {
        p.put("structured_data", sd);
    }
    // Remaining may start with more SD; we keep it in the original message.
    let _ = msg;
    Some(p)
}

/// `<PRI>Mmm dd HH:MM:SS HOST TAG: MSG`  (RFC 3164)
fn parse_rfc3164(line: &str) -> Option<Parsed> {
    let rest = line.strip_prefix('<')?;
    let (pri_s, rest) = rest.split_once('>')?;
    let pri: u8 = pri_s.parse().ok()?;
    // "Oct 11 22:14:15 host tag: msg"
    let re = rfc3164_re();
    let caps = re.captures(rest)?;
    let mut p = pri_to_parsed(pri);
    p.timestamp = parse_syslog_3164_ts(caps.get(1)?.as_str());
    p.hostname = Some(caps.get(2)?.as_str().to_string());
    p.app_name = caps.get(3).map(|m| m.as_str().to_string());
    p.pid = caps.get(4).and_then(|m| m.as_str().parse().ok());
    p.event_category = Some("syslog".into());
    Some(p)
}

fn rfc3164_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+([A-Za-z0-9._/-]+)(?:\[(\d+)\])?:\s*",
        )
        .expect("rfc3164")
    })
}

fn pri_to_parsed(pri: u8) -> Parsed {
    let facility = pri >> 3;
    let severity = pri & 0x07;
    Parsed {
        facility: Some(facility_name(facility).into()),
        severity_raw: Some(syslog_severity_name(severity).into()),
        severity: syslog_severity(severity),
        event_category: Some("syslog".into()),
        ..Default::default()
    }
}

fn facility_name(f: u8) -> &'static str {
    match f {
        0 => "kern",
        1 => "user",
        2 => "mail",
        3 => "daemon",
        4 => "auth",
        5 => "syslog",
        6 => "lpr",
        7 => "news",
        8 => "uucp",
        9 => "cron",
        10 => "authpriv",
        11 => "ftp",
        16 => "local0",
        17 => "local1",
        18 => "local2",
        19 => "local3",
        20 => "local4",
        21 => "local5",
        22 => "local6",
        23 => "local7",
        _ => "unknown",
    }
}

fn syslog_severity_name(s: u8) -> &'static str {
    match s {
        0 => "emerg",
        1 => "alert",
        2 => "crit",
        3 => "err",
        4 => "warning",
        5 => "notice",
        6 => "info",
        _ => "debug",
    }
}

fn syslog_severity(s: u8) -> Severity {
    match s {
        0..=2 => Severity::Critical,
        3 => Severity::High,
        4 => Severity::Medium,
        5 => Severity::Low,
        _ => Severity::Info,
    }
}

fn dash(s: &str) -> Option<String> {
    if s == "-" || s.is_empty() {
        None
    } else {
        Some(s.to_string())
    }
}

// ── nginx / apache access ───────────────────────────────────────────────────

fn nginx_access_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        // combined: addr - user [time] "METHOD PATH PROTO" status bytes "ref" "ua"
        Regex::new(
            r#"^(?P<addr>\S+) \S+ (?P<user>\S+) \[(?P<time>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+) (?P<proto>[^"]*)" (?P<status>\d{3}) (?P<bytes>\S+)(?: "(?P<ref>[^"]*)" "(?P<ua>[^"]*)")?"#,
        )
        .expect("nginx_access")
    })
}

fn parse_nginx_access(line: &str) -> Parsed {
    parse_combined_access(line, "nginx")
}

fn parse_apache_access(line: &str) -> Parsed {
    parse_combined_access(line, "apache")
}

fn parse_combined_access(line: &str, app: &str) -> Parsed {
    let mut p = Parsed {
        app_name: Some(app.into()),
        event_category: Some("web".into()),
        severity: Severity::Info,
        ..Default::default()
    };
    let Some(c) = nginx_access_re().captures(line) else {
        return p;
    };
    p.src_addr = cap(&c, "addr");
    p.username = cap(&c, "user").filter(|u| u != "-");
    if let Some(t) = cap(&c, "time") {
        p.timestamp = parse_clf_time(&t);
    }
    p.http_method = cap(&c, "method");
    p.http_path = cap(&c, "path");
    p.http_status = cap(&c, "status").and_then(|s| s.parse().ok());
    p.http_user_agent = cap(&c, "ua");
    if let Some(b) = cap(&c, "bytes") {
        p.put("bytes", b);
    }
    if let Some(r) = cap(&c, "ref") {
        p.put("referer", r);
    }
    if let Some(proto) = cap(&c, "proto") {
        p.put("http_proto", proto);
    }
    if let Some(st) = p.http_status {
        p.severity = http_status_severity(st);
        p.event_outcome = Some(if st >= 400 { "failure" } else { "success" }.into());
        if st == 401 || st == 403 {
            p.mitre_tactic = Some("TA0001".into());
            p.mitre_technique = Some("T1190".into());
        }
    }
    p
}

fn http_status_severity(st: u16) -> Severity {
    match st {
        500..=599 => Severity::High,
        401 | 403 => Severity::Medium,
        400..=499 => Severity::Low,
        _ => Severity::Info,
    }
}

fn cap(c: &regex::Captures<'_>, name: &str) -> Option<String> {
    c.name(name)
        .map(|m| m.as_str().to_string())
        .filter(|s| !s.is_empty())
}

fn parse_clf_time(s: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_str(s, "%d/%b/%Y:%H:%M:%S %z")
        .ok()
        .map(|d| d.with_timezone(&Utc))
}

// ── nginx / apache error ────────────────────────────────────────────────────

fn parse_nginx_error(line: &str) -> Parsed {
    // 2024/01/15 12:00:00 [error] 1234#0: *1 open() "/x" failed (2: No such file)
    let mut p = Parsed {
        app_name: Some("nginx".into()),
        event_category: Some("web".into()),
        severity: Severity::Info,
        ..Default::default()
    };
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        Regex::new(
            r"^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})(?:\.\d+)? \[(?P<lvl>\w+)\] (?P<pid>\d+)#\d+",
        )
        .expect("nginx_error")
    });
    if let Some(c) = re.captures(line) {
        p.timestamp = DateTime::parse_from_str(c.get(1).unwrap().as_str(), "%Y/%m/%d %H:%M:%S")
            .ok()
            .map(|d| d.with_timezone(&Utc));
        if let Some(lvl) = cap(&c, "lvl") {
            p.severity_raw = Some(lvl.clone());
            p.severity = severity_from_word(&lvl);
        }
        p.pid = cap(&c, "pid").and_then(|s| s.parse().ok());
    }
    if let Some(client) = extract_after(line, "client: ") {
        let client = client.split(',').next().unwrap_or(client).trim();
        if client.matches(':').count() == 1 {
            if let Some((ip, port)) = client.rsplit_once(':') {
                p.src_addr = Some(ip.to_string());
                p.src_port = port.parse().ok();
            }
        } else {
            p.src_addr = Some(client.to_string());
        }
    }
    p
}

fn parse_apache_error(line: &str) -> Parsed {
    let mut p = Parsed {
        app_name: Some("apache".into()),
        event_category: Some("web".into()),
        severity: Severity::Info,
        ..Default::default()
    };
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        Regex::new(
            r"^\[(?P<time>[^\]]+)\] \[(?:(?P<mod>[^:\]]+):)?(?P<lvl>\w+)\](?: \[pid (?P<pid>\d+)(?::tid \d+)?\])?(?: \[client (?P<client>[^\]]+)\])?",
        )
        .expect("apache_error")
    });
    if let Some(c) = re.captures(line) {
        if let Some(t) = cap(&c, "time") {
            p.timestamp = parse_apache_error_time(&t);
        }
        if let Some(lvl) = cap(&c, "lvl") {
            p.severity_raw = Some(lvl.clone());
            p.severity = severity_from_word(&lvl);
        }
        p.pid = cap(&c, "pid").and_then(|s| s.parse().ok());
        if let Some(client) = cap(&c, "client") {
            if let Some((ip, port)) = client.rsplit_once(':') {
                p.src_addr = Some(ip.to_string());
                p.src_port = port.parse().ok();
            } else {
                p.src_addr = Some(client);
            }
        }
    }
    p
}

fn parse_apache_error_time(s: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_str(s, "%a %b %d %H:%M:%S%.f %Y")
        .or_else(|_| DateTime::parse_from_str(s, "%a %b %d %H:%M:%S %Y"))
        .ok()
        .map(|d| d.with_timezone(&Utc))
}

// ── postgresql ──────────────────────────────────────────────────────────────

fn parse_postgresql(line: &str) -> Parsed {
    let mut p = Parsed {
        app_name: Some("postgresql".into()),
        event_category: Some("database".into()),
        severity: Severity::Info,
        ..Default::default()
    };
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        Regex::new(
            r"^(?P<time>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)? \S+) \[(?P<pid>\d+)\](?: (?P<user>[^\s@]+)@(?P<db>\S+))? (?P<lvl>[A-Z]+):\s+",
        )
        .expect("postgresql")
    });
    if let Some(c) = re.captures(line) {
        if let Some(t) = cap(&c, "time") {
            p.timestamp = parse_timestamp(&t.replace(" UTC", " +0000").replace("UTC", "+0000"));
            if p.timestamp.is_none() {
                p.timestamp = DateTime::parse_from_str(
                    t.split('.').next().unwrap_or(&t),
                    "%Y-%m-%d %H:%M:%S",
                )
                .ok()
                .map(|d| d.with_timezone(&Utc));
            }
        }
        p.pid = cap(&c, "pid").and_then(|s| s.parse().ok());
        p.username = cap(&c, "user");
        if let Some(db) = cap(&c, "db") {
            p.put("database", db);
        }
        if let Some(lvl) = cap(&c, "lvl") {
            p.severity_raw = Some(lvl.clone());
            p.severity = match lvl.as_str() {
                "PANIC" | "FATAL" => Severity::Critical,
                "ERROR" => Severity::High,
                "WARNING" => Severity::Medium,
                _ => Severity::Info,
            };
            if lvl == "FATAL" || lvl == "PANIC" {
                p.event_outcome = Some("failure".into());
            }
        }
    }
    if line.contains("password authentication failed") || line.contains("authentication failed") {
        p.event_outcome = Some("failure".into());
        p.mitre_tactic = Some("TA0006".into());
        p.mitre_technique = Some("T1110".into());
        p.severity = Severity::Medium;
        p.event_category = Some("auth".into());
    }
    p
}

// ── mysql ───────────────────────────────────────────────────────────────────

fn parse_mysql(line: &str) -> Parsed {
    let mut p = Parsed {
        app_name: Some("mysql".into()),
        event_category: Some("database".into()),
        severity: Severity::Info,
        ..Default::default()
    };
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        Regex::new(
            r"^(?P<time>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)(?:\s+\d+)? \[(?P<lvl>\w+)\]",
        )
        .expect("mysql")
    });
    if let Some(c) = re.captures(line) {
        if let Some(t) = cap(&c, "time") {
            p.timestamp = parse_timestamp(&t);
        }
        if let Some(lvl) = cap(&c, "lvl") {
            p.severity_raw = Some(lvl.clone());
            p.severity = severity_from_word(&lvl);
        }
    }
    if line.to_ascii_lowercase().contains("access denied") {
        p.event_outcome = Some("failure".into());
        p.event_category = Some("auth".into());
        p.mitre_tactic = Some("TA0006".into());
        p.mitre_technique = Some("T1110".into());
        p.severity = Severity::Medium;
        if let Some(user) = extract_between(line, "for user '", "'") {
            p.username = Some(user);
        }
    }
    p
}

// ── docker json-file ────────────────────────────────────────────────────────

fn parse_docker(line: &str) -> Parsed {
    let mut p = parse_json(line);
    p.event_category = Some("container".into());
    p.app_name = p.app_name.or(Some("docker".into()));
    if let Some(stream) = p.fields.get("stream").cloned() {
        if stream == "stderr" && matches!(p.severity, Severity::Info) {
            p.severity = Severity::Low;
        }
    }
    p
}

// ── ssh ─────────────────────────────────────────────────────────────────────

fn parse_ssh(line: &str) -> Parsed {
    let mut p = Parsed {
        app_name: Some("sshd".into()),
        event_category: Some("auth".into()),
        severity: Severity::Info,
        ..Default::default()
    };
    if let Some(ev) = crate::collectors::linux::authlog::parse_failed_line(line) {
        p.username = Some(ev.username);
        p.src_addr = ev.src_addr;
        p.src_port = ev.src_port;
        if let Some(m) = ev.auth_method {
            p.put("auth_method", m);
        }
        p.event_outcome = Some("failure".into());
        p.severity = Severity::Medium;
        p.mitre_tactic = Some("TA0006".into());
        p.mitre_technique = Some("T1110".into());
        return p;
    }
    if let Some(ev) = crate::collectors::linux::authlog::parse_accepted_line(line) {
        p.username = Some(ev.username);
        p.src_addr = ev.src_addr;
        p.src_port = ev.src_port;
        if let Some(m) = ev.auth_method {
            p.put("auth_method", m);
        }
        p.event_outcome = Some("success".into());
        return p;
    }
    p
}

// ── sudo ────────────────────────────────────────────────────────────────────

fn parse_sudo(line: &str) -> Parsed {
    let mut p = Parsed {
        app_name: Some("sudo".into()),
        event_category: Some("auth".into()),
        severity: Severity::Medium,
        mitre_tactic: Some("TA0004".into()),
        mitre_technique: Some("T1548.003".into()),
        ..Default::default()
    };
    // sudo: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/cat /etc/shadow
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(r"sudo:\s+(\S+)\s*:").expect("sudo"));
    if let Some(c) = re.captures(line) {
        if let Some(u) = c.get(1) {
            p.username = Some(u.as_str().to_string());
        }
    }
    if let Some(user) = extract_after(line, "USER=") {
        let user = user
            .split_whitespace()
            .next()
            .unwrap_or("")
            .trim_end_matches(';');
        p.put("target_user", user);
    }
    if let Some(cmd) = extract_after(line, "COMMAND=") {
        p.put("command", cmd.trim());
    }
    if line.contains("NOT in sudoers") || line.contains("incorrect password") {
        p.event_outcome = Some("failure".into());
        p.severity = Severity::High;
    } else if line.contains("COMMAND=") {
        p.event_outcome = Some("success".into());
    }
    p
}

// ── auditd ──────────────────────────────────────────────────────────────────

fn parse_auditd(line: &str) -> Parsed {
    let mut p = Parsed {
        app_name: Some("auditd".into()),
        event_category: Some("audit".into()),
        severity: Severity::Info,
        ..Default::default()
    };
    // type=SYSCALL msg=audit(1700000000.123:456): key=value ...
    static TYPE_RE: OnceLock<Regex> = OnceLock::new();
    let type_re = TYPE_RE.get_or_init(|| Regex::new(r"type=(\S+)").expect("audit_type"));
    if let Some(c) = type_re.captures(line) {
        let ty = c.get(1).unwrap().as_str().to_string();
        p.put("audit_type", &ty);
        match ty.as_str() {
            "AVC" | "SELINUX" | "MAC_STATUS" => p.severity = Severity::High,
            "USER_AUTH" | "USER_LOGIN" | "USER_ERR" => {
                p.event_category = Some("auth".into());
            }
            "SYSCALL" => {}
            "EXECVE" => {
                p.mitre_tactic = Some("TA0002".into());
                p.mitre_technique = Some("T1059".into());
            }
            _ => {}
        }
    }
    static MSG_RE: OnceLock<Regex> = OnceLock::new();
    let msg_re =
        MSG_RE.get_or_init(|| Regex::new(r"msg=audit\(([\d.]+):(\d+)\)").expect("audit_msg"));
    if let Some(c) = msg_re.captures(line) {
        if let Ok(epoch) = c.get(1).unwrap().as_str().parse::<f64>() {
            p.timestamp = Utc
                .timestamp_opt(epoch as i64, ((epoch.fract()) * 1e9) as u32)
                .single();
        }
        p.put("audit_id", c.get(2).unwrap().as_str());
    }
    for (k, v) in audit_kvs(line) {
        match k.as_str() {
            "pid" => p.pid = v.parse().ok(),
            "uid" | "auid" | "euid" => {
                if k == "uid" {
                    p.uid = v.parse().ok();
                }
                p.put(&k, v);
            }
            "comm" | "exe" => p.put(&k, unquote(&v)),
            "success" => {
                p.event_outcome = Some(if v == "yes" { "success" } else { "failure" }.into());
                if v == "no" {
                    p.severity = Severity::Medium;
                }
            }
            "key" => {
                let k = unquote(&v);
                if k != "(null)" {
                    p.put("audit_key", k);
                }
            }
            "syscall" => p.put("syscall", v),
            "addr" => p.src_addr = Some(unquote(&v)),
            "acct" => p.username = Some(unquote(&v)),
            _ => {
                if p.fields.len() < 32 {
                    p.put(&k, unquote(&v));
                }
            }
        }
    }
    p
}

fn audit_kvs(line: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let body = line.split(": ").nth(1).unwrap_or(line);
    for tok in body.split_whitespace() {
        if let Some((k, v)) = tok.split_once('=') {
            out.push((k.to_string(), v.to_string()));
        }
    }
    out
}

fn unquote(s: &str) -> String {
    s.trim_matches('"').to_string()
}

// ── helpers ─────────────────────────────────────────────────────────────────

fn extract_after<'a>(s: &'a str, marker: &str) -> Option<&'a str> {
    s.split_once(marker).map(|(_, rest)| rest)
}

fn extract_between(s: &str, start: &str, end: &str) -> Option<String> {
    let rest = s.split_once(start)?.1;
    let val = rest.split_once(end)?.0;
    Some(val.to_string())
}

fn severity_from_word(w: &str) -> Severity {
    match w.trim().to_ascii_lowercase().as_str() {
        "emerg" | "emergency" | "alert" | "crit" | "critical" | "fatal" | "panic" => {
            Severity::Critical
        }
        "err" | "error" | "high" => Severity::High,
        "warn" | "warning" | "medium" => Severity::Medium,
        "notice" | "low" => Severity::Low,
        _ => Severity::Info,
    }
}

fn parse_timestamp(s: &str) -> Option<DateTime<Utc>> {
    let s = s.trim();
    if let Ok(d) = DateTime::parse_from_rfc3339(s) {
        return Some(d.with_timezone(&Utc));
    }
    const FMTS: &[&str] = &[
        "%Y-%m-%dT%H:%M:%S%.fZ",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S%.f%z",
        "%Y-%m-%d %H:%M:%S%.f %z",
        "%Y-%m-%d %H:%M:%S %z",
        "%Y-%m-%d %H:%M:%S%.f",
        "%Y-%m-%d %H:%M:%S",
        "%Y/%m/%d %H:%M:%S",
    ];
    for f in FMTS {
        if let Ok(d) = DateTime::parse_from_str(s, f) {
            return Some(d.with_timezone(&Utc));
        }
        if let Ok(d) = chrono::NaiveDateTime::parse_from_str(s, f) {
            return Some(Utc.from_utc_datetime(&d));
        }
    }
    None
}

fn parse_syslog_3164_ts(s: &str) -> Option<DateTime<Utc>> {
    let year = Utc::now().year();
    let with_year = format!("{year} {s}");
    chrono::NaiveDateTime::parse_from_str(&with_year, "%Y %b %e %H:%M:%S")
        .or_else(|_| chrono::NaiveDateTime::parse_from_str(&with_year, "%Y %b %d %H:%M:%S"))
        .ok()
        .map(|d| Utc.from_utc_datetime(&d))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_flattens_and_extracts() {
        let line = r#"{"timestamp":"2024-01-15T12:00:00Z","level":"error","user":"alice","nested":{"ip":"10.0.0.1"},"msg":"fail"}"#;
        let p = parse("json", line);
        assert_eq!(p.username.as_deref(), Some("alice"));
        assert_eq!(p.severity, Severity::High);
        assert_eq!(
            p.fields.get("nested.ip").map(String::as_str),
            Some("10.0.0.1")
        );
        assert!(p.timestamp.is_some());
    }

    #[test]
    fn syslog_rfc5424() {
        let line = "<34>1 2024-01-15T12:00:00.000Z host su - ID47 - su failed";
        let p = parse("syslog", line);
        assert_eq!(p.facility.as_deref(), Some("auth"));
        assert_eq!(p.hostname.as_deref(), Some("host"));
        assert_eq!(p.app_name.as_deref(), Some("su"));
        assert_eq!(p.severity, Severity::Critical); // PRI 34 → severity 2 crit
    }

    #[test]
    fn syslog_rfc3164() {
        let line = "<13>Oct 11 22:14:15 mymachine su[99]: 'su root' failed";
        let p = parse("syslog", line);
        assert_eq!(p.hostname.as_deref(), Some("mymachine"));
        assert_eq!(p.app_name.as_deref(), Some("su"));
        assert_eq!(p.pid, Some(99));
    }

    #[test]
    fn nginx_combined() {
        let line = r#"203.0.113.9 - alice [10/Oct/2023:13:55:36 +0000] "GET /admin HTTP/1.1" 403 182 "-" "curl/8.0""#;
        let p = parse("nginx_access", line);
        assert_eq!(p.src_addr.as_deref(), Some("203.0.113.9"));
        assert_eq!(p.username.as_deref(), Some("alice"));
        assert_eq!(p.http_method.as_deref(), Some("GET"));
        assert_eq!(p.http_path.as_deref(), Some("/admin"));
        assert_eq!(p.http_status, Some(403));
        assert_eq!(p.severity, Severity::Medium);
        assert_eq!(p.mitre_technique.as_deref(), Some("T1190"));
        assert!(p.timestamp.is_some());
    }

    #[test]
    fn nginx_error_extracts_pid_and_level() {
        let line = r#"2024/01/15 12:00:00 [error] 4242#0: *1 open() "/x" failed (2: No such file), client: 198.51.100.7, server: _"#;
        let p = parse("nginx_error", line);
        assert_eq!(p.pid, Some(4242));
        assert_eq!(p.severity, Severity::High);
        assert_eq!(p.src_addr.as_deref(), Some("198.51.100.7"));
    }

    #[test]
    fn postgres_fatal_auth_failure() {
        let line = "2024-01-15 12:00:00.123 UTC [1234] alice@app FATAL:  password authentication failed for user \"alice\"";
        let p = parse("postgresql", line);
        assert_eq!(p.username.as_deref(), Some("alice"));
        assert_eq!(p.fields.get("database").map(String::as_str), Some("app"));
        assert_eq!(p.event_outcome.as_deref(), Some("failure"));
        assert_eq!(p.mitre_technique.as_deref(), Some("T1110"));
    }

    #[test]
    fn mysql_access_denied() {
        let line = "2024-01-15T12:00:00.123456Z 12 [Note] Access denied for user 'root'@'203.0.113.5' (using password: YES)";
        let p = parse("mysql", line);
        assert_eq!(p.username.as_deref(), Some("root"));
        assert_eq!(p.event_outcome.as_deref(), Some("failure"));
    }

    #[test]
    fn docker_json_file() {
        let line = r#"{"log":"ready\n","stream":"stdout","time":"2024-01-15T12:00:00.123Z"}"#;
        let p = parse("docker", line);
        assert_eq!(p.event_category.as_deref(), Some("container"));
        assert_eq!(p.fields.get("log").map(String::as_str), Some("ready\n"));
    }

    #[test]
    fn ssh_failed_password() {
        let line = "Jun  5 12:00:00 victim sshd[4242]: Failed password for root from 203.0.113.5 port 51000 ssh2";
        let p = parse("ssh", line);
        assert_eq!(p.username.as_deref(), Some("root"));
        assert_eq!(p.src_addr.as_deref(), Some("203.0.113.5"));
        assert_eq!(p.src_port, Some(51000));
        assert_eq!(p.event_outcome.as_deref(), Some("failure"));
    }

    #[test]
    fn sudo_command() {
        let line =
            "sudo: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/cat /etc/shadow";
        let p = parse("sudo", line);
        assert_eq!(p.username.as_deref(), Some("alice"));
        assert_eq!(
            p.fields.get("command").map(String::as_str),
            Some("/bin/cat /etc/shadow")
        );
        assert_eq!(p.mitre_technique.as_deref(), Some("T1548.003"));
        assert_eq!(p.event_outcome.as_deref(), Some("success"));
    }

    #[test]
    fn auditd_syscall() {
        let line = r#"type=SYSCALL msg=audit(1700000000.123:456): arch=c000003e syscall=59 success=yes exit=0 pid=1234 uid=0 comm="bash" exe="/usr/bin/bash" key="rootcmd""#;
        let p = parse("auditd", line);
        assert_eq!(p.pid, Some(1234));
        assert_eq!(p.uid, Some(0));
        assert_eq!(
            p.fields.get("exe").map(String::as_str),
            Some("/usr/bin/bash")
        );
        assert_eq!(
            p.fields.get("audit_key").map(String::as_str),
            Some("rootcmd")
        );
        assert_eq!(p.event_outcome.as_deref(), Some("success"));
        assert!(p.timestamp.is_some());
    }

    #[test]
    fn auto_detects_json_and_audit() {
        assert_eq!(
            parse("auto", r#"{"level":"info"}"#)
                .event_category
                .as_deref(),
            Some("application")
        );
        assert_eq!(
            parse("auto", "type=SYSCALL msg=audit(1.0:1): pid=1")
                .app_name
                .as_deref(),
            Some("auditd")
        );
    }
}
