//! Parsers: turn a framed logical record into a structured [`ParsedLog`].
//!
//! Parsers never fail closed — a line that does not match the expected shape
//! falls through to `raw` so we still ship the original message. The
//! normalizer then stamps source metadata on top.

use chrono::{DateTime, Datelike, TimeZone, Timelike, Utc};
use serde_json::{Map, Value};

use crate::schema::Severity;

/// Structured result of one parser invocation.
#[derive(Debug, Clone, Default)]
pub struct ParsedLog {
    pub timestamp: Option<DateTime<Utc>>,
    pub facility: Option<String>,
    pub severity: Option<String>,
    pub host: Option<String>,
    pub proc: Option<String>,
    pub pid: Option<i32>,
    pub uid: Option<u32>,
    pub username: Option<String>,
    pub message: String,
    pub fields: Map<String, Value>,
    pub category: String,
    pub mitre_tactic: Option<String>,
    pub mitre_technique: Option<String>,
    pub severity_hint: Option<Severity>,
}

impl ParsedLog {
    fn raw(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            category: "application".into(),
            ..Default::default()
        }
    }

    fn put(&mut self, k: &str, v: impl Into<Value>) {
        self.fields.insert(k.to_string(), v.into());
    }

    fn put_u64(&mut self, k: &str, v: u64) {
        self.fields.insert(k.to_string(), Value::from(v));
    }
}

/// Dispatch by parser name. Unknown names are treated as `auto`.
pub fn parse(parser: &str, raw: &str) -> ParsedLog {
    let line = raw.trim_end();
    if line.is_empty() {
        return ParsedLog::raw(String::new());
    }
    match parser.trim().to_ascii_lowercase().as_str() {
        "raw" | "none" => ParsedLog::raw(line),
        "json" => parse_json(line),
        "syslog" => parse_syslog(line),
        "nginx_access" => parse_nginx_access(line),
        "nginx_error" => parse_nginx_error(line),
        "apache_access" => parse_nginx_access(line), // combined/clf is shared
        "apache_error" => parse_apache_error(line),
        "postgresql" | "postgres" => parse_postgresql(line),
        "mysql" | "mariadb" => parse_mysql(line),
        "docker" | "docker_json" => parse_docker(line),
        "sshd" | "ssh" => parse_sshd(line),
        "sudo" => parse_sudo(line),
        "auditd" | "audit" => parse_auditd(line),
        "kv" => parse_kv(line),
        "cef" => parse_cef(line),
        _ => parse_auto(line),
    }
}

pub fn parse_auto(line: &str) -> ParsedLog {
    let t = line.trim_start();
    if t.starts_with('{') && matches!(serde_json::from_str::<Value>(line), Ok(Value::Object(_))) {
        return parse_json(line);
    }
    if t.starts_with("CEF:") {
        return parse_cef(line);
    }
    if t.starts_with("type=") && t.contains("msg=audit(") {
        return parse_auditd(line);
    }
    if looks_like_syslog(t) {
        return parse_syslog(line);
    }
    if looks_like_combined_access(t) {
        return parse_nginx_access(line);
    }
    ParsedLog::raw(line)
}

fn looks_like_syslog(t: &str) -> bool {
    t.starts_with('<') || rfc3164_prefix(t).is_some()
}

fn looks_like_combined_access(t: &str) -> bool {
    // `1.2.3.4 - - [10/Oct/2024:13:55:36 +0000] "`
    t.contains(" - ") && t.contains(" [") && t.contains("] \"")
}

// ── JSON ────────────────────────────────────────────────────────────────────

fn parse_json(line: &str) -> ParsedLog {
    let Ok(Value::Object(map)) = serde_json::from_str::<Value>(line) else {
        return ParsedLog::raw(line);
    };
    let mut p = ParsedLog {
        category: "application".into(),
        message: first_string(&map, &["message", "msg", "log", "text", "MESSAGE"])
            .unwrap_or_else(|| line.to_string()),
        fields: map.clone(),
        ..Default::default()
    };
    p.timestamp = first_string(&map, &["timestamp", "time", "ts", "@timestamp", "@t"])
        .and_then(|s| parse_ts(&s));
    p.proc = first_string(
        &map,
        &[
            "syslog.identifier",
            "ident",
            "comm",
            "_COMM",
            "SYSLOG_IDENTIFIER",
        ],
    );
    p.host = first_string(&map, &["hostname", "host", "_HOSTNAME"]);
    p.username = first_string(&map, &["user", "username", "USER"]);
    if let Some(v) = first_i64(&map, &["pid", "_PID", "pid"]) {
        p.pid = i32::try_from(v).ok();
    }
    if let Some(v) = first_string(&map, &["stream"]) {
        p.put("stream", v);
        p.category = "container".into();
    }
    p
}

fn first_string(map: &Map<String, Value>, keys: &[&str]) -> Option<String> {
    for k in keys {
        if let Some(Value::String(s)) = map.get(*k) {
            if !s.is_empty() {
                return Some(s.clone());
            }
        }
    }
    None
}

fn first_i64(map: &Map<String, Value>, keys: &[&str]) -> Option<i64> {
    for k in keys {
        match map.get(*k) {
            Some(Value::Number(n)) => return n.as_i64(),
            Some(Value::String(s)) => return s.parse().ok(),
            _ => {}
        }
    }
    None
}

// ── syslog RFC 3164 / 5424 ─────────────────────────────────────────────────

pub fn parse_syslog(line: &str) -> ParsedLog {
    let (pri, rest) = strip_pri(line);
    let (facility, severity) = pri.map(decode_pri).unwrap_or((None, None));

    if let Some(p) = parse_rfc5424(rest, facility.clone(), severity.clone()) {
        return p;
    }
    if let Some(p) = parse_rfc3164(rest, facility.clone(), severity.clone()) {
        return p;
    }
    let mut p = ParsedLog::raw(rest);
    p.facility = facility;
    p.severity = severity;
    p.category = "syslog".into();
    p
}

fn strip_pri(line: &str) -> (Option<u8>, &str) {
    let t = line.trim_start();
    if !t.starts_with('<') {
        return (None, t);
    }
    let Some(end) = t.find('>') else {
        return (None, t);
    };
    let pri = t[1..end].parse::<u8>().ok();
    (pri, t[end + 1..].trim_start())
}

fn decode_pri(pri: u8) -> (Option<String>, Option<String>) {
    let facility = pri >> 3;
    let sev = pri & 0x07;
    (
        Some(facility_name(facility).into()),
        Some(severity_name(sev).into()),
    )
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
        16 => "local0",
        17 => "local1",
        _ => "other",
    }
}

fn severity_name(s: u8) -> &'static str {
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

fn parse_rfc5424(
    rest: &str,
    facility: Option<String>,
    severity: Option<String>,
) -> Option<ParsedLog> {
    // `<PRI>1 TIMESTAMP HOST APP PROCID MSGID SD MSG`
    let rest = rest.strip_prefix("1 ")?;
    let mut parts = rest.splitn(6, ' ');
    let ts = parts.next()?;
    let host = parts.next()?;
    let app = parts.next()?;
    let procid = parts.next()?;
    let msgid = parts.next()?;
    let remainder = parts.next().unwrap_or("");
    // structured-data is `-` or `[...]` possibly followed by msg.
    let (sd, msg) = split_sd(remainder);
    let mut p = ParsedLog {
        timestamp: parse_ts(ts),
        facility,
        severity: severity.clone(),
        host: dash_opt(host),
        proc: dash_opt(app),
        pid: dash_opt(procid).and_then(|s| s.parse().ok()),
        message: msg.trim().to_string(),
        category: "syslog".into(),
        ..Default::default()
    };
    if let Some(sd) = sd {
        p.put("structured_data", sd);
    }
    if let Some(id) = dash_opt(msgid) {
        p.put("msgid", id);
    }
    if p.message.is_empty() {
        p.message = rest.to_string();
    }
    Some(p)
}

fn split_sd(remainder: &str) -> (Option<String>, &str) {
    let r = remainder.trim_start();
    if let Some(stripped) = r.strip_prefix('-') {
        return (None, stripped.trim_start());
    }
    if !r.starts_with('[') {
        return (None, r);
    }
    // Walk until the last `] ` that closes SD.
    if let Some(pos) = r.rfind("] ") {
        return (Some(r[..=pos].to_string()), &r[pos + 2..]);
    }
    if r.ends_with(']') {
        return (Some(r.to_string()), "");
    }
    (None, r)
}

fn dash_opt(s: &str) -> Option<String> {
    if s.is_empty() || s == "-" {
        None
    } else {
        Some(s.to_string())
    }
}

fn parse_rfc3164(
    rest: &str,
    facility: Option<String>,
    severity: Option<String>,
) -> Option<ParsedLog> {
    let (ts, after) = rfc3164_prefix(rest)?;
    let (host, tag_and_msg) = after.split_once(' ')?;
    // `sshd[123]: message` or `sshd: message`
    let (tag, pid, msg) = split_tag(tag_and_msg);
    let mut p = ParsedLog {
        timestamp: Some(ts),
        facility,
        severity,
        host: dash_opt(host),
        proc: tag,
        pid,
        message: msg.trim().to_string(),
        category: "syslog".into(),
        ..Default::default()
    };
    // Layer product parsers on the inner message.
    if let Some(proc) = p.proc.clone() {
        if proc.eq_ignore_ascii_case("sshd") || proc.eq_ignore_ascii_case("ssh") {
            let inner = parse_sshd_inner(&p.message);
            overlay(&mut p, inner);
        } else if proc.eq_ignore_ascii_case("sudo") {
            let inner = parse_sudo_inner(&p.message);
            overlay(&mut p, inner);
        }
    }
    Some(p)
}

fn rfc3164_prefix(s: &str) -> Option<(DateTime<Utc>, &str)> {
    // Always 15 characters: `Oct 10 13:55:36` or `Oct  5 13:55:36`.
    let s = s.trim_start();
    if s.len() < 16 {
        return None;
    }
    let stamp = s.get(..15)?;
    if stamp.as_bytes().get(3) != Some(&b' ') {
        return None;
    }
    month_num(&stamp[..3])?;
    let ts = parse_rfc3164_ts(stamp)?;
    Some((ts, s[15..].trim_start()))
}

fn month_num(m: &str) -> Option<u32> {
    Some(match m {
        "Jan" => 1,
        "Feb" => 2,
        "Mar" => 3,
        "Apr" => 4,
        "May" => 5,
        "Jun" => 6,
        "Jul" => 7,
        "Aug" => 8,
        "Sep" => 9,
        "Oct" => 10,
        "Nov" => 11,
        "Dec" => 12,
        _ => return None,
    })
}

fn parse_rfc3164_ts(stamp: &str) -> Option<DateTime<Utc>> {
    let now = Utc::now();
    let with_year = format!("{} {stamp}", now.year());
    let parsed = DateTime::parse_from_str(&format!("{with_year} +0000"), "%Y %b %e %H:%M:%S %z")
        .or_else(|_| {
            DateTime::parse_from_str(&format!("{with_year} +0000"), "%Y %b %d %H:%M:%S %z")
        })
        .ok()?;
    let mut ts = parsed.with_timezone(&Utc);
    // Dec/Jan wrap: if the stamp is more than a day in the future, it's last year.
    if ts > now + chrono::Duration::days(1) {
        ts = Utc
            .with_ymd_and_hms(
                now.year() - 1,
                ts.month(),
                ts.day(),
                ts.hour(),
                ts.minute(),
                ts.second(),
            )
            .single()?;
    }
    Some(ts)
}

fn split_tag(s: &str) -> (Option<String>, Option<i32>, &str) {
    let s = s.trim();
    let (head, msg) = match s.split_once(": ") {
        Some(x) => x,
        None => match s.split_once(':') {
            Some(x) => x,
            None => return (None, None, s),
        },
    };
    if let Some(bracket) = head.find('[') {
        let tag = head[..bracket].to_string();
        let pid = head[bracket + 1..].trim_end_matches(']').parse().ok();
        return (Some(tag), pid, msg);
    }
    (Some(head.to_string()), None, msg)
}

fn overlay(dst: &mut ParsedLog, src: ParsedLog) {
    if src.category != "application" {
        dst.category = src.category;
    }
    if dst.username.is_none() {
        dst.username = src.username;
    }
    if dst.severity_hint.is_none() {
        dst.severity_hint = src.severity_hint;
    }
    if dst.mitre_tactic.is_none() {
        dst.mitre_tactic = src.mitre_tactic;
        dst.mitre_technique = src.mitre_technique;
    }
    for (k, v) in src.fields {
        dst.fields.entry(k).or_insert(v);
    }
}

// ── nginx / apache combined access ────────────────────────────────────────

fn parse_nginx_access(line: &str) -> ParsedLog {
    parse_combined_access(line).unwrap_or_else(|| ParsedLog::raw(line))
}

fn parse_combined_access(line: &str) -> Option<ParsedLog> {
    let (remote, rest) = split_once_space(line)?;
    let rest = rest.strip_prefix("- ")?;
    let (user, rest) = split_once_space(rest)?;
    let rest = rest.strip_prefix('[')?;
    let (time, rest) = rest.split_once("] ")?;
    let rest = rest.strip_prefix('"')?;
    let (request, rest) = rest.split_once("\" ")?;
    let mut it = rest.splitn(3, ' ');
    let status = it.next()?;
    let bytes = it.next()?;
    let tail = it.next().unwrap_or("");
    let (referer, ua, extra) = parse_two_quoted(tail);

    let mut req = request.splitn(3, ' ');
    let method = req.next().unwrap_or("");
    let uri = req.next().unwrap_or("");
    let proto = req.next().unwrap_or("");

    let status_n: u16 = status.parse().unwrap_or(0);
    let mut p = ParsedLog {
        timestamp: parse_nginx_time(time),
        username: dash_opt(user),
        message: line.to_string(),
        category: "web".into(),
        ..Default::default()
    };
    p.put("remote_addr", remote);
    p.put("method", method);
    p.put("uri", uri);
    p.put("protocol", proto);
    p.put_u64("status", u64::from(status_n));
    p.put("bytes", bytes);
    if let Some(r) = referer {
        p.put("referer", r);
    }
    if let Some(u) = ua {
        p.put("user_agent", u);
    }
    if !extra.is_empty() {
        p.put("extra", extra);
    }
    p.severity_hint = match status_n {
        500..=599 => Some(Severity::High),
        401 | 403 => Some(Severity::Medium),
        400..=499 => Some(Severity::Low),
        _ => Some(Severity::Info),
    };
    if status_n == 401 || status_n == 403 {
        p.mitre_tactic = Some("TA0006 Credential Access".into());
        p.mitre_technique = Some("T1110".into());
    }
    Some(p)
}

fn split_once_space(s: &str) -> Option<(&str, &str)> {
    s.split_once(' ')
}

fn parse_two_quoted(s: &str) -> (Option<String>, Option<String>, String) {
    let s = s.trim();
    if !s.starts_with('"') {
        return (None, None, s.to_string());
    }
    let s = &s[1..];
    let Some((a, rest)) = s.split_once('"') else {
        return (Some(s.to_string()), None, String::new());
    };
    let rest = rest.trim_start();
    if !rest.starts_with('"') {
        return (Some(a.to_string()), None, rest.to_string());
    }
    let rest = &rest[1..];
    match rest.split_once('"') {
        Some((b, extra)) => (
            Some(a.to_string()),
            Some(b.to_string()),
            extra.trim().to_string(),
        ),
        None => (Some(a.to_string()), Some(rest.to_string()), String::new()),
    }
}

fn parse_nginx_time(s: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_str(s, "%d/%b/%Y:%H:%M:%S %z")
        .ok()
        .map(|t| t.with_timezone(&Utc))
}

fn parse_nginx_error(line: &str) -> ParsedLog {
    // `2024/01/15 13:55:36 [error] 1234#0: *1 message`
    let mut p = ParsedLog::raw(line);
    p.category = "web".into();
    let mut it = line.splitn(4, ' ');
    let d = it.next().unwrap_or("");
    let t = it.next().unwrap_or("");
    let level = it.next().unwrap_or("");
    let rest = it.next().unwrap_or("");
    p.timestamp = parse_ts(&format!("{d} {t}"));
    if let Some(l) = level.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
        p.severity = Some(l.to_string());
        p.severity_hint = Some(map_word_severity(l));
    }
    if let Some((pid, msg)) = rest.split_once(": ") {
        p.pid = pid.split('#').next().and_then(|s| s.parse().ok());
        p.message = msg.to_string();
    }
    p
}

fn parse_apache_error(line: &str) -> ParsedLog {
    // `[Wed May 18 22:16:30.123456 2022] [core:error] [pid 1234] [client 1.2.3.4:1234] msg`
    let mut p = ParsedLog::raw(line);
    p.category = "web".into();
    if let Some(rest) = line.strip_prefix('[') {
        if let Some((ts, rest)) = rest.split_once("] ") {
            p.timestamp = parse_apache_error_ts(ts);
            let rest = rest.trim();
            if let Some(rest) = rest.strip_prefix('[') {
                if let Some((modlev, rest)) = rest.split_once("] ") {
                    if let Some((_, lev)) = modlev.split_once(':') {
                        p.severity = Some(lev.to_string());
                        p.severity_hint = Some(map_word_severity(lev));
                    }
                    p.message = rest.to_string();
                    if let Some(c) = extract_after(rest, "[client ") {
                        let addr = c.split(']').next().unwrap_or(c);
                        let (ip, port) = split_host_port(addr);
                        p.put("remote_addr", ip);
                        if let Some(port) = port {
                            p.put_u64("remote_port", u64::from(port));
                        }
                    }
                }
            }
        }
    }
    p
}

fn parse_apache_error_ts(s: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_str(&format!("{s} +0000"), "%a %b %d %H:%M:%S%.f %Y %z")
        .or_else(|_| DateTime::parse_from_str(&format!("{s} +0000"), "%a %b %d %H:%M:%S %Y %z"))
        .ok()
        .map(|t| t.with_timezone(&Utc))
}

fn extract_after<'a>(s: &'a str, marker: &str) -> Option<&'a str> {
    s.split(marker).nth(1)
}

fn split_host_port(s: &str) -> (String, Option<u16>) {
    if let Some((h, p)) = s.rsplit_once(':') {
        if let Ok(port) = p.parse::<u16>() {
            return (h.to_string(), Some(port));
        }
    }
    (s.to_string(), None)
}

// ── postgresql ───────────────────────────────────────────────────────────────

fn parse_postgresql(line: &str) -> ParsedLog {
    let mut p = ParsedLog {
        message: line.to_string(),
        category: "database".into(),
        ..Default::default()
    };
    // `2024-01-15 12:00:00.123 UTC [1234] user@db LOG:  message`
    if line.len() >= 23 {
        p.timestamp = parse_ts(&line[..23]);
    }
    if let Some(rest) = line.split("] ").nth(1) {
        // optional `user@db LEVEL:  msg`
        let (head, msg) = rest
            .split_once(":  ")
            .unwrap_or(rest.split_once(": ").unwrap_or(("", rest)));
        let mut bits = head.split_whitespace();
        let maybe_user = bits.next().unwrap_or("");
        let level = bits.next().unwrap_or(maybe_user);
        if maybe_user.contains('@') {
            let (u, db) = maybe_user.split_once('@').unwrap();
            p.username = Some(u.to_string());
            p.put("database", db);
            p.severity = Some(level.to_lowercase());
        } else {
            p.severity = Some(maybe_user.to_lowercase());
        }
        p.message = msg.to_string();
        if let Some(pid_s) = line.split('[').nth(1).and_then(|s| s.split(']').next()) {
            p.pid = pid_s.parse().ok();
        }
    }
    if p.severity.as_deref() == Some("fatal") || p.severity.as_deref() == Some("panic") {
        p.severity_hint = Some(Severity::High);
    }
    p
}

fn parse_mysql(line: &str) -> ParsedLog {
    let mut p = ParsedLog {
        message: line.to_string(),
        category: "database".into(),
        ..Default::default()
    };
    // `2024-01-15T12:00:00.123456Z 0 [Note] [MY-010000] [Server] msg`
    if let Some(t) = line.split_whitespace().next() {
        p.timestamp = parse_ts(t);
    }
    if let Some(rest) = line.find('[').map(|i| &line[i..]) {
        if let Some((level, rest)) = rest.split_once(']') {
            let level = level.trim_start_matches('[').to_lowercase();
            p.severity = Some(level.clone());
            p.severity_hint = Some(map_word_severity(&level));
            p.message = rest.trim().to_string();
        }
    }
    if line.to_ascii_lowercase().contains("access denied") {
        p.severity_hint = Some(Severity::Medium);
        p.mitre_tactic = Some("TA0006 Credential Access".into());
        p.mitre_technique = Some("T1110".into());
        p.category = "authentication".into();
    }
    p
}

fn parse_docker(line: &str) -> ParsedLog {
    let mut p = parse_json(line);
    p.category = "container".into();
    if let Some(Value::String(log)) = p.fields.get("log") {
        p.message = log.trim_end_matches('\n').to_string();
    }
    p
}

// ── sshd / sudo / auditd ────────────────────────────────────────────────────

fn parse_sshd(line: &str) -> ParsedLog {
    // Allow a syslog-wrapped line.
    if looks_like_syslog(line) {
        let mut p = parse_syslog(line);
        let inner = parse_sshd_inner(&p.message);
        overlay(&mut p, inner);
        return p;
    }
    parse_sshd_inner(line)
}

fn parse_sshd_inner(msg: &str) -> ParsedLog {
    let mut p = ParsedLog {
        message: msg.to_string(),
        category: "authentication".into(),
        proc: Some("sshd".into()),
        mitre_tactic: Some("TA0008 Lateral Movement".into()),
        mitre_technique: Some("T1021.004".into()),
        ..Default::default()
    };
    if let Some(ev) = parse_accepted(msg) {
        p.username = Some(ev.0);
        p.put("src_addr", ev.1.clone());
        if let Some(port) = ev.2 {
            p.put_u64("src_port", u64::from(port));
        }
        p.put("auth_method", ev.3);
        p.put("success", true);
        p.severity_hint = Some(Severity::Info);
        return p;
    }
    if let Some(ev) = parse_failed_ssh(msg) {
        p.username = Some(ev.0);
        p.put("src_addr", ev.1.clone());
        if let Some(port) = ev.2 {
            p.put_u64("src_port", u64::from(port));
        }
        if let Some(m) = ev.3 {
            p.put("auth_method", m);
        }
        p.put("success", false);
        p.severity_hint = Some(Severity::Medium);
        p.mitre_tactic = Some("TA0006 Credential Access".into());
        p.mitre_technique = Some("T1110".into());
        return p;
    }
    p
}

/// (user, addr, port, method)
fn parse_accepted(msg: &str) -> Option<(String, String, Option<u16>, String)> {
    for method in ["password", "publickey"] {
        let marker = format!("Accepted {method} for ");
        if let Some(rest) = msg.split(&marker).nth(1) {
            let parts: Vec<&str> = rest.split_whitespace().collect();
            if parts.len() >= 5 {
                return Some((
                    parts[0].to_string(),
                    parts[2].to_string(),
                    parts[4].parse().ok(),
                    method.to_string(),
                ));
            }
        }
    }
    None
}

fn parse_failed_ssh(msg: &str) -> Option<(String, String, Option<u16>, Option<String>)> {
    for method in ["password", "publickey"] {
        let marker = format!("Failed {method} for ");
        if let Some(rest) = msg.split(&marker).nth(1) {
            return parse_failed_tail(rest, Some(method));
        }
    }
    if let Some(rest) = msg.split("Invalid user ").nth(1) {
        return parse_failed_tail(rest, None);
    }
    None
}

fn parse_failed_tail(
    rest: &str,
    method: Option<&str>,
) -> Option<(String, String, Option<u16>, Option<String>)> {
    let (user_part, addr_rest) = rest.split_once(" from ")?;
    let username = user_part
        .strip_prefix("invalid user ")
        .unwrap_or(user_part)
        .trim()
        .to_string();
    if username.is_empty() {
        return None;
    }
    let parts: Vec<&str> = addr_rest.split_whitespace().collect();
    let addr = parts.first()?.to_string();
    let port = parts.get(2).and_then(|s| s.parse().ok());
    Some((username, addr, port, method.map(|m| m.to_string())))
}

fn parse_sudo(line: &str) -> ParsedLog {
    if looks_like_syslog(line) {
        let mut p = parse_syslog(line);
        let inner = parse_sudo_inner(&p.message);
        overlay(&mut p, inner);
        return p;
    }
    parse_sudo_inner(line)
}

fn parse_sudo_inner(msg: &str) -> ParsedLog {
    let mut p = ParsedLog {
        message: msg.to_string(),
        category: "authentication".into(),
        proc: Some("sudo".into()),
        mitre_tactic: Some("TA0004 Privilege Escalation".into()),
        mitre_technique: Some("T1548.003".into()),
        ..Default::default()
    };
    // `alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/bash`
    let msg = msg.trim().trim_start_matches("sudo: ").trim();
    if let Some((user, rest)) = msg.split_once(" : ") {
        p.username = Some(user.trim().to_string());
        for kv in rest.split(';') {
            if let Some((k, v)) = kv.split_once('=') {
                let k = k.trim().to_ascii_lowercase();
                let v = v.trim();
                p.put(&k, v);
                if k == "user" {
                    p.put("target_user", v);
                }
                if k == "command" {
                    p.put("command", v);
                }
            }
        }
        p.severity_hint = Some(Severity::Low);
    } else if msg.contains("authentication failure") || msg.contains("incorrect password") {
        p.severity_hint = Some(Severity::Medium);
        p.put("success", false);
    }
    p
}

fn parse_auditd(line: &str) -> ParsedLog {
    let mut p = ParsedLog {
        message: line.to_string(),
        category: "audit".into(),
        proc: Some("auditd".into()),
        ..Default::default()
    };
    let mut types = Vec::new();
    for rec in line.split('\n') {
        if let Some(t) = kv_value(rec, "type") {
            types.push(t);
        }
        merge_kv(&mut p.fields, rec);
        if let Some(id) = super::framing::audit_event_id(rec) {
            p.put("audit_id", id);
        }
        if let Some(ts) = audit_ts(rec) {
            p.timestamp = Some(ts);
        }
    }
    if !types.is_empty() {
        p.put(
            "types",
            Value::Array(types.iter().cloned().map(Value::String).collect()),
        );
    }
    if let Some(Value::String(exe)) = p.fields.get("exe") {
        p.put("image", exe.clone());
    }
    if let Some(Value::String(comm)) = p.fields.get("comm") {
        p.proc = Some(comm.trim_matches('"').to_string());
    }
    if let Some(Value::String(uid)) = p.fields.get("uid") {
        p.uid = uid.parse().ok();
    }
    if let Some(Value::String(pid)) = p.fields.get("pid") {
        p.pid = pid.parse().ok();
    }
    if let Some(Value::String(auid)) = p.fields.get("auid") {
        p.put("loginuid", auid.clone());
    }
    let joined = types.join(",");
    if joined.contains("USER_AUTH") || joined.contains("USER_LOGIN") {
        p.category = "authentication".into();
        p.mitre_tactic = Some("TA0008 Lateral Movement".into());
        p.mitre_technique = Some("T1021.004".into());
        if line.contains("res=failed") || line.contains("res=no") {
            p.severity_hint = Some(Severity::Medium);
        }
    }
    if joined.contains("AVC") || joined.contains("SELINUX") {
        p.severity_hint = Some(Severity::High);
        p.mitre_tactic = Some("TA0005 Defense Evasion".into());
    }
    if joined.contains("EXECVE") || joined.contains("SYSCALL") {
        p.mitre_tactic = Some("TA0002 Execution".into());
        p.mitre_technique = Some("T1059".into());
    }
    p
}

fn audit_ts(rec: &str) -> Option<DateTime<Utc>> {
    let id = super::framing::audit_event_id(rec)?;
    let epoch: f64 = id.split(':').next()?.parse().ok()?;
    DateTime::from_timestamp(epoch as i64, ((epoch.fract()) * 1e9) as u32)
}

fn kv_value(line: &str, key: &str) -> Option<String> {
    let pat = format!("{key}=");
    let rest = line.split(&pat).nth(1)?;
    if let Some(quoted) = rest.strip_prefix('"') {
        return quoted.split('"').next().map(|s| s.to_string());
    }
    rest.split_whitespace()
        .next()
        .map(|s| s.trim_end_matches(':').to_string())
}

fn merge_kv(into: &mut Map<String, Value>, rec: &str) {
    let mut s = rec;
    while let Some(eq) = s.find('=') {
        let key_start = s[..eq]
            .rfind(|c: char| c.is_whitespace())
            .map(|i| i + 1)
            .unwrap_or(0);
        let key = s[key_start..eq].trim();
        let rest = &s[eq + 1..];
        let (val, next) = if let Some(quoted) = rest.strip_prefix('"') {
            match quoted.find('"') {
                Some(end) => (quoted[..end].to_string(), &quoted[end + 1..]),
                None => (quoted.to_string(), ""),
            }
        } else {
            match rest.find(|c: char| c.is_whitespace()) {
                Some(end) => (rest[..end].trim_end_matches(':').to_string(), &rest[end..]),
                None => (rest.trim_end_matches(':').to_string(), ""),
            }
        };
        if !key.is_empty() && key != "msg" {
            into.entry(key.to_string()).or_insert(Value::String(val));
        }
        s = next;
        if next.is_empty() {
            break;
        }
    }
}

fn parse_kv(line: &str) -> ParsedLog {
    let mut p = ParsedLog::raw(line);
    merge_kv(&mut p.fields, line);
    p
}

fn parse_cef(line: &str) -> ParsedLog {
    let mut p = ParsedLog {
        message: line.to_string(),
        category: "syslog".into(),
        ..Default::default()
    };
    let rest = line.trim().strip_prefix("CEF:").unwrap_or(line);
    let parts: Vec<&str> = rest.splitn(8, '|').collect();
    if parts.len() >= 7 {
        p.put("cef_version", parts[0]);
        p.put("device_vendor", parts[1]);
        p.put("device_product", parts[2]);
        p.put("device_version", parts[3]);
        p.put("signature_id", parts[4]);
        p.put("name", parts[5]);
        p.put("severity", parts[6]);
        p.message = parts[5].to_string();
        if let Some(ext) = parts.get(7) {
            for token in ext.split(' ') {
                if let Some((k, v)) = token.split_once('=') {
                    p.put(k, v);
                }
            }
        }
    }
    p
}

fn map_word_severity(s: &str) -> Severity {
    match s.to_ascii_lowercase().as_str() {
        "emerg" | "emergency" | "panic" | "fatal" | "crit" | "critical" | "alert" => {
            Severity::Critical
        }
        "err" | "error" => Severity::High,
        "warning" | "warn" | "notice" => Severity::Medium,
        "debug" | "trace" => Severity::Info,
        _ => Severity::Info,
    }
}

fn parse_ts(s: &str) -> Option<DateTime<Utc>> {
    let s = s.trim();
    if let Ok(t) = DateTime::parse_from_rfc3339(s) {
        return Some(t.with_timezone(&Utc));
    }
    const FMTS: &[&str] = &[
        "%Y-%m-%d %H:%M:%S%.f %z",
        "%Y-%m-%d %H:%M:%S %z",
        "%Y-%m-%dT%H:%M:%S%.fZ",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S%.f",
        "%Y/%m-%d %H:%M:%S",
        "%Y/%m/%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S%.f",
        "%Y-%m-%d %H:%M:%S",
    ];
    for f in FMTS {
        if let Ok(t) = DateTime::parse_from_str(s, f) {
            return Some(t.with_timezone(&Utc));
        }
        if let Ok(t) = chrono::NaiveDateTime::parse_from_str(s, f) {
            return Some(t.and_utc());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn syslog_rfc3164_sshd_failed() {
        let line = "<38>Oct 10 13:55:36 victim sshd[4242]: Failed password for root from 203.0.113.5 port 51000 ssh2";
        let p = parse("syslog", line);
        assert_eq!(p.proc.as_deref(), Some("sshd"));
        assert_eq!(p.username.as_deref(), Some("root"));
        assert_eq!(p.fields["src_addr"], "203.0.113.5");
        assert_eq!(p.fields["success"], false);
        assert_eq!(p.category, "authentication");
        assert_eq!(p.facility.as_deref(), Some("auth"));
    }

    #[test]
    fn syslog_rfc5424() {
        let line = "<165>1 2024-01-15T12:00:00.000Z host app 123 ID47 - hello world";
        let p = parse("syslog", line);
        assert_eq!(p.host.as_deref(), Some("host"));
        assert_eq!(p.proc.as_deref(), Some("app"));
        assert_eq!(p.pid, Some(123));
        assert_eq!(p.message, "hello world");
    }

    #[test]
    fn nginx_combined() {
        let line = r#"203.0.113.9 - alice [10/Oct/2024:13:55:36 +0000] "GET /admin HTTP/1.1" 403 123 "http://x" "curl/8.0""#;
        let p = parse("nginx_access", line);
        assert_eq!(p.fields["method"], "GET");
        assert_eq!(p.fields["uri"], "/admin");
        assert_eq!(p.fields["status"], 403);
        assert_eq!(p.username.as_deref(), Some("alice"));
        assert_eq!(p.severity_hint, Some(Severity::Medium));
    }

    #[test]
    fn json_log() {
        let line = r#"{"message":"boom","level":"error","user":"bob","ts":"2024-01-15T12:00:00Z"}"#;
        let p = parse("json", line);
        assert_eq!(p.message, "boom");
        assert_eq!(p.username.as_deref(), Some("bob"));
        assert!(p.timestamp.is_some());
    }

    #[test]
    fn sudo_command() {
        let line = "alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/id";
        let p = parse("sudo", line);
        assert_eq!(p.username.as_deref(), Some("alice"));
        assert_eq!(p.fields["command"], "/usr/bin/id");
        assert_eq!(p.fields["target_user"], "root");
    }

    #[test]
    fn auditd_syscall_execve() {
        let rec = "type=SYSCALL msg=audit(1712345678.123:9): arch=c000003e syscall=59 success=yes pid=100 uid=0 comm=\"bash\" exe=\"/bin/bash\"\ntype=EXECVE msg=audit(1712345678.123:9): argc=2 a0=\"/bin/bash\" a1=\"-i\"";
        let p = parse("auditd", rec);
        assert_eq!(p.category, "audit");
        assert_eq!(p.pid, Some(100));
        assert_eq!(p.uid, Some(0));
        assert_eq!(p.proc.as_deref(), Some("bash"));
        assert!(p.fields.get("audit_id").is_some());
    }

    #[test]
    fn docker_json_file() {
        let line = r#"{"log":"listening on :80\n","stream":"stdout","time":"2024-01-15T12:00:00.000000000Z"}"#;
        let p = parse("docker", line);
        assert_eq!(p.message, "listening on :80");
        assert_eq!(p.category, "container");
    }

    #[test]
    fn postgres_prefix() {
        let line = "2024-01-15 12:00:00.123 UTC [4242] postgres@app LOG:  connection authorized";
        let p = parse("postgresql", line);
        assert_eq!(p.username.as_deref(), Some("postgres"));
        assert_eq!(p.fields["database"], "app");
        assert_eq!(p.pid, Some(4242));
        assert!(p.message.contains("connection authorized"));
    }

    #[test]
    fn auto_detects_json_and_syslog() {
        let j = parse("auto", r#"{"msg":"x"}"#);
        assert_eq!(p_msg_or(&j), "x");
        let s = parse("auto", "<13>Oct 10 13:55:36 host app: hello");
        assert_eq!(s.category, "syslog");
        assert_eq!(s.message, "hello");
    }

    fn p_msg_or(p: &ParsedLog) -> &str {
        p.fields
            .get("msg")
            .and_then(|v| v.as_str())
            .unwrap_or(&p.message)
    }

    #[test]
    fn mysql_access_denied_is_auth() {
        let line = "2024-01-15T12:00:00.123456Z 12 [Note] [MY-010000] Access denied for user 'root'@'1.2.3.4'";
        let p = parse("mysql", line);
        assert_eq!(p.category, "authentication");
        assert_eq!(p.severity_hint, Some(Severity::Medium));
    }
}
