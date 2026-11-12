use anyhow::Result;
use async_trait::async_trait;
use tokio::fs::File;
use tokio::io::{AsyncBufReadExt, AsyncSeekExt, BufReader};
use tokio::sync::mpsc::Sender;
use tokio::time::{interval, sleep, Duration};
use tracing::{info, warn};

use crate::collectors::Collector;
use crate::schema::{
    AgentEvent, EventAction, EventClass, EventData, Severity, UserLogonData, UserSessionData,
};

/// Candidate auth-log paths across distros: Debian/Ubuntu use `auth.log`,
/// RHEL/Fedora/SUSE use `secure`. The first readable one wins.
const AUTH_LOG_CANDIDATES: &[&str] = &["/var/log/auth.log", "/var/log/secure"];

pub struct AuthLogCollector;

impl AuthLogCollector {
    pub fn new() -> Self {
        Self
    }
}

impl Default for AuthLogCollector {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Collector for AuthLogCollector {
    fn name(&self) -> &'static str {
        "AuthLogCollector"
    }

    async fn run(
        &mut self,
        tx: Sender<AgentEvent>,
        agent_id: String,
        hostname: String,
    ) -> Result<()> {
        // Pick a source: a readable auth log first, else the systemd journal
        // (journal-only distros). If neither is available — or before the agent
        // has been granted read access (CAP_DAC_READ_SEARCH) — keep retrying
        // instead of giving up for the whole process lifetime.
        loop {
            let file = open_auth_log().await;
            let journalctl = find_journalctl();
            match select_source(file.is_some(), journalctl) {
                AuthSource::File => {
                    let (path, file) = file.expect("select_source returned File");
                    return tail_file(path, file, tx, agent_id, hostname).await;
                }
                AuthSource::Journal(bin) => {
                    return run_journal(bin, tx, agent_id, hostname).await;
                }
                AuthSource::Unavailable => {
                    warn!(
                        "AuthLogCollector: no readable auth log in {AUTH_LOG_CANDIDATES:?} and no journalctl; retrying in 30s"
                    );
                    sleep(Duration::from_secs(30)).await;
                    if tx.is_closed() {
                        return Ok(());
                    }
                }
            }
        }
    }
}

/// Where auth events come from.
#[derive(Debug, PartialEq, Eq)]
enum AuthSource {
    File,
    Journal(&'static str),
    Unavailable,
}

/// A readable auth log always wins (identical behaviour to before); the
/// journal is the fallback for hosts that only run systemd-journald.
fn select_source(file_readable: bool, journalctl: Option<&'static str>) -> AuthSource {
    match (file_readable, journalctl) {
        (true, _) => AuthSource::File,
        (false, Some(bin)) => AuthSource::Journal(bin),
        (false, None) => AuthSource::Unavailable,
    }
}

async fn tail_file(
    path: String,
    file: File,
    tx: Sender<AgentEvent>,
    agent_id: String,
    hostname: String,
) -> Result<()> {
    info!("AuthLogCollector: tailing {path}");

    let mut reader = BufReader::new(file);
    // Start at the end — ignore historical entries.
    let mut offset = reader.seek(std::io::SeekFrom::End(0)).await?;
    let mut ticker = interval(Duration::from_secs(2));
    let mut line = String::new();

    loop {
        ticker.tick().await;

        // Handle log rotation / truncation: if the file shrank, logrotate
        // rotated or truncated it — reopen the path from the start.
        if let Ok(meta) = tokio::fs::metadata(&path).await {
            if meta.len() < offset {
                if let Ok(f) = File::open(&path).await {
                    reader = BufReader::new(f);
                    offset = 0;
                }
            }
        }

        loop {
            line.clear();
            let n = reader.read_line(&mut line).await?;
            if n == 0 {
                break; // no new data yet
            }
            offset += n as u64;
            let trimmed = line.trim_end();
            if let Some(event) = parse_auth_line(trimmed, agent_id.clone(), hostname.clone()) {
                if tx.send(event).await.is_err() {
                    return Ok(()); // channel closed
                }
            }
        }
    }
}

// ── systemd-journald source ──────────────────────────────────────────────────

/// Absolute `journalctl` locations. Never resolved through `PATH`: the agent
/// runs privileged, so a `PATH` entry must not decide which binary it executes.
const JOURNALCTL_CANDIDATES: &[&str] = &["/usr/bin/journalctl", "/bin/journalctl"];

/// Syslog identifiers whose messages the file parser understands: sshd (and the
/// OpenSSH >= 9.8 `sshd-session` split), sudo/su/login, logind and the display
/// managers' PAM session lines.
const JOURNAL_IDENTIFIERS: &[&str] = &[
    "sshd",
    "sshd-session",
    "sudo",
    "su",
    "login",
    "systemd-logind",
    "gdm-password",
    "sddm-helper",
];

/// Longest journal JSON line accepted. Longer records are skipped, so a hostile
/// message cannot grow the agent's memory.
const JOURNAL_MAX_LINE: usize = 64 * 1024;
/// Restart backoff bounds for a journalctl child that exits.
const JOURNAL_BACKOFF_MIN: Duration = Duration::from_secs(1);
const JOURNAL_BACKOFF_MAX: Duration = Duration::from_secs(60);

fn find_journalctl() -> Option<&'static str> {
    JOURNALCTL_CANDIDATES
        .iter()
        .copied()
        .find(|p| std::path::Path::new(p).is_file())
}

/// Journal cursors look like `s=…;i=…;b=…;m=…;t=…;x=…`. They come from the
/// journal, but are re-validated before being handed back to a child process.
fn is_valid_cursor(c: &str) -> bool {
    !c.is_empty()
        && c.len() <= 256
        && c.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'=' | b';' | b'-' | b'_'))
}

/// Fixed argv (no shell, no user-controlled values). Without a cursor, start at
/// the tail (`-n 0`) so history is never replayed; with one, resume after it.
/// `_UID=0` restricts to records written by privileged processes, so an
/// unprivileged user cannot forge `sshd` lines via `logger -t sshd`.
fn journalctl_args(cursor: Option<&str>) -> Vec<String> {
    let mut args: Vec<String> = ["--no-pager", "--follow", "--output=json"]
        .map(String::from)
        .to_vec();
    match cursor.filter(|c| is_valid_cursor(c)) {
        Some(c) => args.push(format!("--after-cursor={c}")),
        None => args.extend(["--lines=0".to_string()]),
    }
    args.push("_UID=0".into());
    args.extend(
        JOURNAL_IDENTIFIERS
            .iter()
            .map(|id| format!("SYSLOG_IDENTIFIER={id}")),
    );
    args
}

/// One journal JSON record reduced to what the auth parser needs.
#[derive(Debug, PartialEq, Eq)]
struct JournalRecord {
    message: String,
    cursor: Option<String>,
}

/// Parse one `journalctl -o json` line. Rejects records that are not from a
/// privileged writer or an expected identifier (defence in depth: the same
/// filter is also passed to journalctl) and non-text `MESSAGE`s (journald
/// encodes binary messages as byte arrays).
fn parse_journal_record(line: &str) -> Option<JournalRecord> {
    let v: serde_json::Value = serde_json::from_str(line).ok()?;
    if v.get("_UID").and_then(|u| u.as_str()) != Some("0") {
        return None;
    }
    let ident = v.get("SYSLOG_IDENTIFIER").and_then(|i| i.as_str())?;
    if !JOURNAL_IDENTIFIERS.contains(&ident) {
        return None;
    }
    let message = v.get("MESSAGE")?.as_str()?.to_string();
    let cursor = v
        .get("__CURSOR")
        .and_then(|c| c.as_str())
        .filter(|c| is_valid_cursor(c))
        .map(String::from);
    Some(JournalRecord { message, cursor })
}

/// Result of reading one bounded line.
#[derive(Debug, PartialEq, Eq)]
enum BoundedLine {
    Line,
    /// Exceeded the cap; the remainder up to the newline was discarded.
    TooLong,
    Eof,
}

/// Read up to a newline into `buf`, holding at most `max` bytes in memory.
async fn read_bounded_line<R: AsyncBufReadExt + Unpin>(
    reader: &mut R,
    buf: &mut Vec<u8>,
    max: usize,
) -> std::io::Result<BoundedLine> {
    buf.clear();
    let mut too_long = false;
    loop {
        let chunk = reader.fill_buf().await?;
        if chunk.is_empty() {
            return Ok(if buf.is_empty() && !too_long {
                BoundedLine::Eof
            } else if too_long {
                BoundedLine::TooLong
            } else {
                BoundedLine::Line
            });
        }
        let (take, found_nl) = match chunk.iter().position(|b| *b == b'\n') {
            Some(i) => (i + 1, true),
            None => (chunk.len(), false),
        };
        if !too_long {
            if buf.len() + take > max {
                too_long = true;
                buf.clear();
            } else {
                buf.extend_from_slice(&chunk[..take]);
            }
        }
        reader.consume(take);
        if found_nl {
            return Ok(if too_long {
                BoundedLine::TooLong
            } else {
                BoundedLine::Line
            });
        }
    }
}

/// Follow the journal via a `journalctl` child, restarting with exponential
/// backoff and resuming after the last seen cursor so a restart neither replays
/// history nor (when a cursor is known) drops events.
async fn run_journal(
    journalctl: &'static str,
    tx: Sender<AgentEvent>,
    agent_id: String,
    hostname: String,
) -> Result<()> {
    info!("AuthLogCollector: no auth log file; following systemd journal via {journalctl}");
    let mut cursor: Option<String> = None;
    let mut backoff = JOURNAL_BACKOFF_MIN;
    loop {
        let started = std::time::Instant::now();
        match follow_journal_once(journalctl, &mut cursor, &tx, &agent_id, &hostname).await {
            Ok(true) => return Ok(()), // event channel closed
            Ok(false) => warn!("AuthLogCollector: journalctl exited; restarting in {backoff:?}"),
            Err(e) => warn!("AuthLogCollector: journalctl failed ({e}); restarting in {backoff:?}"),
        }
        if started.elapsed() > JOURNAL_BACKOFF_MAX {
            backoff = JOURNAL_BACKOFF_MIN; // it ran healthily for a while
        }
        sleep(backoff).await;
        backoff = (backoff * 2).min(JOURNAL_BACKOFF_MAX);
        if tx.is_closed() {
            return Ok(());
        }
    }
}

/// Run one journalctl child to completion. `Ok(true)` = the event channel is
/// closed and the collector should stop.
async fn follow_journal_once(
    journalctl: &str,
    cursor: &mut Option<String>,
    tx: &Sender<AgentEvent>,
    agent_id: &str,
    hostname: &str,
) -> Result<bool> {
    use tokio::process::Command;
    let mut child = Command::new(journalctl)
        .args(journalctl_args(cursor.as_deref()))
        .env_clear()
        .env("LC_ALL", "C")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow::anyhow!("journalctl stdout not captured"))?;
    let mut reader = BufReader::new(stdout);
    let mut buf = Vec::new();
    loop {
        match read_bounded_line(&mut reader, &mut buf, JOURNAL_MAX_LINE).await? {
            BoundedLine::Eof => {
                let _ = child.wait().await;
                return Ok(false);
            }
            BoundedLine::TooLong => {
                // The whole JSON record (message plus journal metadata) is
                // over the limit; it may have been an auth line, so the loss
                // is counted like every other drop.
                crate::telemetry::metrics::metrics()
                    .event_dropped(crate::telemetry::DropReason::EventTooLarge);
                continue;
            }
            BoundedLine::Line => {}
        }
        let Ok(text) = std::str::from_utf8(&buf) else {
            continue;
        };
        let Some(rec) = parse_journal_record(text.trim_end()) else {
            continue;
        };
        if rec.cursor.is_some() {
            *cursor = rec.cursor.clone();
        }
        if let Some(event) =
            parse_auth_line(rec.message.trim_end(), agent_id.into(), hostname.into())
        {
            if tx.send(event).await.is_err() {
                return Ok(true);
            }
        }
    }
}

/// Open the first readable auth-log candidate, returning its path and handle.
async fn open_auth_log() -> Option<(String, File)> {
    for path in AUTH_LOG_CANDIDATES {
        if let Ok(f) = File::open(path).await {
            return Some(((*path).to_string(), f));
        }
    }
    None
}

fn parse_auth_line(line: &str, agent_id: String, hostname: String) -> Option<AgentEvent> {
    if let Some(ev) = parse_accepted(line, "password") {
        return Some(AgentEvent::new(
            agent_id.clone(),
            hostname.clone(),
            EventClass::User,
            EventAction::Logon,
            Severity::Info,
            EventData::UserLogon(ev),
        ));
    }

    if let Some(ev) = parse_accepted(line, "publickey") {
        return Some(AgentEvent::new(
            agent_id.clone(),
            hostname.clone(),
            EventClass::User,
            EventAction::Logon,
            Severity::Info,
            EventData::UserLogon(ev),
        ));
    }

    if let Some(ev) = parse_failed(line) {
        return Some(AgentEvent::new(
            agent_id.clone(),
            hostname.clone(),
            EventClass::User,
            EventAction::LogonFailed,
            Severity::Medium,
            EventData::UserLogon(ev),
        ));
    }

    if let Some(ev) = parse_session(line, true) {
        return Some(AgentEvent::new(
            agent_id.clone(),
            hostname.clone(),
            EventClass::User,
            EventAction::SessionOpen,
            Severity::Info,
            EventData::UserSession(ev),
        ));
    }

    if let Some(ev) = parse_session(line, false) {
        return Some(AgentEvent::new(
            agent_id.clone(),
            hostname.clone(),
            EventClass::User,
            EventAction::SessionClose,
            Severity::Info,
            EventData::UserSession(ev),
        ));
    }

    None
}

fn parse_accepted(line: &str, method: &str) -> Option<UserLogonData> {
    let marker = format!("Accepted {method} for ");
    let pos = line.find(marker.as_str())?;
    let rest = &line[pos + marker.len()..];

    // "<user> from <ip> port <port> ssh2"
    let parts: Vec<&str> = rest.split_whitespace().collect();
    if parts.len() < 5 {
        return None;
    }
    let username = parts[0].to_string();
    // parts[1] == "from"
    let src_addr = Some(parts[2].to_string());
    // parts[3] == "port"
    let src_port = parts[4].parse::<u16>().ok();

    Some(UserLogonData {
        username,
        src_addr,
        src_port,
        auth_method: Some(method.to_string()),
        success: true,
        ..Default::default()
    })
}

/// Detect a failed SSH/PAM authentication. Brute force and credential spraying
/// rarely produce "Failed password" alone — pubkey probes and user enumeration
/// log differently — so we cover the high-signal sshd failure shapes:
///   - "Failed password for [invalid user ]<user> from <ip> [port <p>] ..."
///   - "Failed publickey for [invalid user ]<user> from <ip> [port <p>] ..."
///   - "Invalid user <user> from <ip> [port <p>]"   (logged before any password
///     prompt — covers pubkey-only / BatchMode probes that never hit a password)
fn parse_failed(line: &str) -> Option<UserLogonData> {
    for method in ["password", "publickey"] {
        let marker = format!("Failed {method} for ");
        if let Some(pos) = line.find(marker.as_str()) {
            if let Some(ev) = parse_failed_for(&line[pos + marker.len()..], Some(method)) {
                return Some(ev);
            }
        }
    }

    // "Invalid user <user> from <ip> [port <port>]" — the auth method is unknown
    // at this point (sshd rejects the user before authentication), so leave it
    // unset. This is the line an unknown-user / BatchMode probe produces.
    if let Some(pos) = line.find("Invalid user ") {
        if let Some(ev) = parse_failed_for(&line[pos + "Invalid user ".len()..], None) {
            return Some(ev);
        }
    }

    None
}

/// Parse the shared "[invalid user ]<user> from <ip> [port <port>] ..." tail of
/// an sshd auth-failure line into a (failed) `UserLogonData`.
fn parse_failed_for(rest: &str, auth_method: Option<&str>) -> Option<UserLogonData> {
    let (user_part, addr_rest) = rest.split_once(" from ")?;
    let username = user_part
        .strip_prefix("invalid user ")
        .unwrap_or(user_part)
        .trim()
        .to_string();
    if username.is_empty() {
        return None;
    }

    let addr_parts: Vec<&str> = addr_rest.split_whitespace().collect();
    let src_addr = addr_parts.first().map(|s| s.to_string());
    // "<ip> port <port>" — port may or may not be present.
    let src_port = addr_parts.get(2).and_then(|s| s.parse::<u16>().ok());

    Some(UserLogonData {
        username,
        src_addr,
        src_port,
        auth_method: auth_method.map(|m| m.to_string()),
        success: false,
        ..Default::default()
    })
}

fn parse_session(line: &str, opened: bool) -> Option<UserSessionData> {
    let marker = if opened {
        "session opened for user "
    } else {
        "session closed for user "
    };
    let pos = line.find(marker)?;
    let rest = &line[pos + marker.len()..];
    let username = rest.split_whitespace().next()?.to_string();
    Some(UserSessionData { username })
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOST: &str = "Jun  5 12:00:00 victim sshd[4242]: ";

    #[test]
    fn failed_password_known_user() {
        let l = format!("{HOST}Failed password for root from 203.0.113.5 port 51000 ssh2");
        let ev = parse_failed(&l).expect("should parse");
        assert_eq!(ev.username, "root");
        assert_eq!(ev.src_addr.as_deref(), Some("203.0.113.5"));
        assert_eq!(ev.src_port, Some(51000));
        assert_eq!(ev.auth_method.as_deref(), Some("password"));
        assert!(!ev.success);
    }

    #[test]
    fn failed_password_invalid_user_strips_prefix() {
        let l =
            format!("{HOST}Failed password for invalid user admin from 198.51.100.7 port 22 ssh2");
        let ev = parse_failed(&l).expect("should parse");
        assert_eq!(ev.username, "admin");
        assert_eq!(ev.src_addr.as_deref(), Some("198.51.100.7"));
    }

    #[test]
    fn failed_publickey_is_detected() {
        let l = format!("{HOST}Failed publickey for deploy from 203.0.113.9 port 40000 ssh2");
        let ev = parse_failed(&l).expect("should parse");
        assert_eq!(ev.username, "deploy");
        assert_eq!(ev.auth_method.as_deref(), Some("publickey"));
        assert!(!ev.success);
    }

    #[test]
    fn invalid_user_probe_is_detected() {
        // What `ssh -o BatchMode=yes baduser@host` produces (no password attempt).
        let l = format!("{HOST}Invalid user baduser from ::1 port 41954");
        let ev = parse_failed(&l).expect("should parse");
        assert_eq!(ev.username, "baduser");
        assert_eq!(ev.src_addr.as_deref(), Some("::1"));
        assert_eq!(ev.src_port, Some(41954));
        assert_eq!(ev.auth_method, None);
        assert!(!ev.success);
    }

    #[test]
    fn accepted_and_session_lines_are_not_failures() {
        let accepted = format!("{HOST}Accepted password for bob from 10.0.0.2 port 2222 ssh2");
        let session = format!("{HOST}pam_unix(sshd:session): session opened for user root(uid=0)");
        assert!(parse_failed(&accepted).is_none());
        assert!(parse_failed(&session).is_none());
    }

    #[test]
    fn parse_auth_line_maps_invalid_user_to_logon_failed() {
        let l = format!("{HOST}Invalid user oracle from 203.0.113.5 port 51000");
        let ev = parse_auth_line(&l, "agent_test".into(), "victim".into()).expect("event");
        assert!(matches!(ev.action, EventAction::LogonFailed));
        assert!(matches!(ev.class, EventClass::User));
    }

    #[test]
    fn source_selection_prefers_file_then_journal() {
        assert_eq!(
            select_source(true, Some("/usr/bin/journalctl")),
            AuthSource::File
        );
        assert_eq!(select_source(true, None), AuthSource::File);
        assert_eq!(
            select_source(false, Some("/usr/bin/journalctl")),
            AuthSource::Journal("/usr/bin/journalctl")
        );
        assert_eq!(select_source(false, None), AuthSource::Unavailable);
    }

    #[test]
    fn journal_record_message_goes_through_the_file_parser() {
        let line = r#"{"__CURSOR":"s=abc;i=1;b=2;m=3;t=4;x=5","_UID":"0","SYSLOG_IDENTIFIER":"sshd-session","MESSAGE":"Accepted publickey for alice from 203.0.113.5 port 5000 ssh2: ED25519 SHA256:x"}"#;
        let rec = parse_journal_record(line).expect("record");
        assert_eq!(rec.cursor.as_deref(), Some("s=abc;i=1;b=2;m=3;t=4;x=5"));
        let ev = parse_auth_line(&rec.message, "a".into(), "h".into()).expect("event");
        assert!(matches!(ev.action, EventAction::Logon));
        let EventData::UserLogon(d) = ev.data else {
            panic!("logon expected")
        };
        assert_eq!(d.username, "alice");
        assert_eq!(d.auth_method.as_deref(), Some("publickey"));
        assert!(d.success);

        // Identical to the file path for the same message text.
        let file_ev = parse_auth_line(&rec.message, "a".into(), "h".into()).unwrap();
        assert!(matches!(file_ev.class, EventClass::User));
    }

    #[test]
    fn journal_records_from_unprivileged_or_foreign_writers_are_rejected() {
        let forged = r#"{"_UID":"1000","SYSLOG_IDENTIFIER":"sshd","MESSAGE":"Accepted password for root from 1.2.3.4 port 1 ssh2"}"#;
        assert!(parse_journal_record(forged).is_none());
        let other = r#"{"_UID":"0","SYSLOG_IDENTIFIER":"cron","MESSAGE":"x"}"#;
        assert!(parse_journal_record(other).is_none());
        let no_uid = r#"{"SYSLOG_IDENTIFIER":"sshd","MESSAGE":"x"}"#;
        assert!(parse_journal_record(no_uid).is_none());
        // Binary messages are byte arrays, not strings.
        let binary = r#"{"_UID":"0","SYSLOG_IDENTIFIER":"sshd","MESSAGE":[65,66]}"#;
        assert!(parse_journal_record(binary).is_none());
        assert!(parse_journal_record("not json").is_none());
    }

    #[test]
    fn invalid_cursor_is_dropped_from_the_record() {
        let line =
            r#"{"__CURSOR":"s=1; rm -rf /","_UID":"0","SYSLOG_IDENTIFIER":"su","MESSAGE":"x"}"#;
        assert_eq!(parse_journal_record(line).unwrap().cursor, None);
    }

    #[test]
    fn journalctl_argv_is_fixed_and_starts_at_the_tail() {
        let a = journalctl_args(None);
        assert!(a.contains(&"--lines=0".to_string()));
        assert!(a.contains(&"--output=json".to_string()));
        assert!(a.contains(&"_UID=0".to_string()));
        assert!(a.contains(&"SYSLOG_IDENTIFIER=sshd".to_string()));
        assert!(!a.iter().any(|x| x.starts_with("--after-cursor")));
    }

    #[test]
    fn journalctl_argv_resumes_after_a_valid_cursor_only() {
        let a = journalctl_args(Some("s=abc;i=1"));
        assert!(a.contains(&"--after-cursor=s=abc;i=1".to_string()));
        assert!(!a.contains(&"--lines=0".to_string()));
        // A malformed cursor can never reach argv: fall back to the tail.
        let b = journalctl_args(Some("x --unit=evil"));
        assert!(b.contains(&"--lines=0".to_string()));
        assert!(!b.iter().any(|x| x.contains("evil")));
    }

    #[tokio::test]
    async fn bounded_reader_skips_oversized_lines_without_buffering_them() {
        let mut data = Vec::new();
        data.extend_from_slice(b"ok1\n");
        data.extend(std::iter::repeat_n(b'A', 5000));
        data.extend_from_slice(b"\nok2\n");
        let mut r = tokio::io::BufReader::with_capacity(16, &data[..]);
        let mut buf = Vec::new();
        assert_eq!(
            read_bounded_line(&mut r, &mut buf, 100).await.unwrap(),
            BoundedLine::Line
        );
        assert_eq!(buf, b"ok1\n");
        assert_eq!(
            read_bounded_line(&mut r, &mut buf, 100).await.unwrap(),
            BoundedLine::TooLong
        );
        assert!(buf.is_empty());
        assert_eq!(
            read_bounded_line(&mut r, &mut buf, 100).await.unwrap(),
            BoundedLine::Line
        );
        assert_eq!(buf, b"ok2\n");
        assert_eq!(
            read_bounded_line(&mut r, &mut buf, 100).await.unwrap(),
            BoundedLine::Eof
        );
    }
}
