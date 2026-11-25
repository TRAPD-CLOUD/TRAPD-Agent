//! Flight recorder (issue #32, point 5).
//!
//! A bounded, in-memory ring of recent pid-bearing telemetry. The engine feeds
//! every `AgentEvent` through [`FlightRecorder::record`]; when a honeytoken hit
//! is confirmed it pulls the buffered *pre-history* of the accessor and its
//! ancestry with [`FlightRecorder::history_for`] and bundles it into the
//! response — so the event ships with the story of what the session did in the
//! seconds before it touched the bait, not just the bare access.
//!
//! It also keeps a small ring of successful logins so the engine can correlate a
//! session's originating remote IP ([`FlightRecorder::correlate_remote`]).
//!
//! Everything is best-effort and lock-poison-tolerant: telemetry forensics must
//! never block or panic the response path.

use std::collections::VecDeque;
use std::sync::Mutex;

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::schema::{AgentEvent, EventAction, EventData};

/// Default capacity of the per-pid event ring.
pub const DEFAULT_CAPACITY: usize = 512;
/// Default capacity of the logon ring used for remote-IP correlation.
const LOGON_CAPACITY: usize = 64;
/// How far back a logon may be to still correlate to a session.
const LOGON_CORRELATION_WINDOW_HOURS: i64 = 24;

/// One buffered telemetry record — a compact summary, never raw file content.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FlightEvent {
    pub timestamp: DateTime<Utc>,
    pub class: String,
    pub action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<i32>,
    pub summary: String,
}

#[derive(Debug, Clone)]
struct LogonRecord {
    timestamp: DateTime<Utc>,
    username: String,
    src_addr: Option<String>,
    src_port: Option<u16>,
}

pub struct FlightRecorder {
    cap: usize,
    events: Mutex<VecDeque<FlightEvent>>,
    logons: Mutex<VecDeque<LogonRecord>>,
}

impl FlightRecorder {
    pub fn new(cap: usize) -> Self {
        Self {
            cap: cap.clamp(1, DEFAULT_CAPACITY),
            events: Mutex::new(VecDeque::new()),
            logons: Mutex::new(VecDeque::new()),
        }
    }

    /// Record one event. Pid-bearing events join the process-history ring;
    /// successful logons additionally join the correlation ring.
    pub fn record(&self, event: &AgentEvent) {
        if let EventData::UserLogon(d) = &event.data {
            if d.success
                && (d.username.len() > 256 || d.src_addr.as_ref().is_some_and(|a| a.len() > 256))
            {
                crate::telemetry::metrics::metrics().state_capacity_dropped(1);
            } else if d.success {
                if let Ok(mut logons) = self.logons.lock() {
                    push_capped(
                        &mut logons,
                        LogonRecord {
                            timestamp: event.timestamp,
                            username: d.username.clone(),
                            src_addr: d.src_addr.clone(),
                            src_port: d.src_port,
                        },
                        LOGON_CAPACITY,
                    );
                }
            }
        }

        // The start-up process baseline is lineage for the backend, not session
        // history; thousands of entries would evict the real recent events.
        if matches!(event.action, EventAction::Snapshot) {
            return;
        }
        let Some((pid, summary)) = extract(&event.data) else {
            return;
        };
        let fe = FlightEvent {
            timestamp: event.timestamp,
            class: label(&event.class),
            action: label(&event.action),
            pid: Some(pid),
            summary,
        };
        if let Ok(mut buf) = self.events.lock() {
            push_capped(&mut buf, fe, self.cap);
        }
    }

    /// Recent buffered history for any of `pids` (the accessor + its ancestry),
    /// oldest first, capped to `max` entries.
    pub fn history_for(&self, pids: &[i32], max: usize) -> Vec<FlightEvent> {
        let Ok(buf) = self.events.lock() else {
            return Vec::new();
        };
        let mut hits: Vec<FlightEvent> = buf
            .iter()
            .rev()
            .filter(|e| e.pid.is_some_and(|p| pids.contains(&p)))
            .take(max)
            .cloned()
            .collect();
        hits.reverse();
        hits
    }

    /// Best-effort remote source for a session, by matching the most recent
    /// successful logon for `login_user` within the correlation window.
    pub fn correlate_remote(&self, login_user: Option<&str>) -> Option<(String, Option<u16>)> {
        let user = login_user?;
        let cutoff = Utc::now() - Duration::hours(LOGON_CORRELATION_WINDOW_HOURS);
        let logons = self.logons.lock().ok()?;
        logons
            .iter()
            .filter(|l| l.username == user && l.timestamp >= cutoff && l.src_addr.is_some())
            .max_by_key(|l| l.timestamp)
            .and_then(|l| l.src_addr.clone().map(|addr| (addr, l.src_port)))
    }
}

fn push_capped<T>(buf: &mut VecDeque<T>, item: T, cap: usize) {
    if buf.len() >= cap {
        buf.pop_front();
        crate::telemetry::metrics::metrics().state_capacity_dropped(1);
    }
    buf.push_back(item);
}

/// Render a serde enum (e.g. `EventClass`/`EventAction`) as its wire string.
fn label<T: Serialize>(v: &T) -> String {
    match serde_json::to_value(v) {
        Ok(serde_json::Value::String(s)) => s,
        _ => "unknown".to_string(),
    }
}

const MAX_SUMMARY_BYTES: usize = 1024;

fn bounded_summary(args: std::fmt::Arguments<'_>) -> String {
    struct Bounded(String);
    impl std::fmt::Write for Bounded {
        fn write_str(&mut self, s: &str) -> std::fmt::Result {
            let remaining = MAX_SUMMARY_BYTES - self.0.len();
            if s.len() <= remaining {
                self.0.push_str(s);
                return Ok(());
            }
            let mut end = remaining;
            while !s.is_char_boundary(end) {
                end -= 1;
            }
            self.0.push_str(&s[..end]);
            Err(std::fmt::Error)
        }
    }
    let mut out = Bounded(String::new());
    if std::fmt::write(&mut out, args).is_err() {
        crate::telemetry::metrics::metrics().state_capacity_dropped(1);
    }
    out.0
}

/// Extract `(pid, summary)` from event data for the history ring. Returns `None`
/// for events with no associated pid (those are not process history).
fn extract(data: &EventData) -> Option<(i32, String)> {
    macro_rules! summary { ($($arg:tt)*) => { bounded_summary(format_args!($($arg)*)) }; }
    Some(match data {
        EventData::ProcessCreate(d) => (d.pid, summary!("exec {} ({})", d.name, d.cmdline)),
        EventData::ProcessExec(d) => (d.pid, summary!("exec {} [{}]", d.exe, d.cmdline)),
        EventData::ProcessTerminate(d) => (d.pid, summary!("exit {}", d.name)),
        EventData::FileOpen(d) => (d.pid, summary!("open {} (flags {:#x})", d.path, d.flags)),
        EventData::FileUnlink(d) => (d.pid, summary!("unlink {}", d.path)),
        EventData::FileRename(d) => (d.pid, summary!("rename {} -> {}", d.old_path, d.new_path)),
        EventData::FileChmod(d) => (d.pid, summary!("chmod {:o} {}", d.mode, d.path)),
        EventData::FileChown(d) => (
            d.pid,
            summary!("chown {}:{} {}", d.new_uid, d.new_gid, d.path),
        ),
        EventData::Mmap(d) => (d.pid, summary!("mmap {}", d.comm)),
        EventData::PrivilegeChange(d) => (
            d.pid,
            summary!("privilege_change {} -> euid {}", d.old_uid, d.new_euid),
        ),
        EventData::Setuid(d) => (d.pid, summary!("setuid {} -> {}", d.old_uid, d.new_uid)),
        EventData::MemfdCreate(d) => (d.pid, summary!("memfd_create {}", d.name)),
        EventData::NetworkSocket(d) => (d.pid, summary!("{} {}:{}", d.op, d.addr, d.port)),
        EventData::NetworkConnection(d) => (
            d.pid?,
            summary!(
                "connect {}:{} -> {}:{}",
                d.src_addr,
                d.src_port,
                d.dst_addr,
                d.dst_port
            ),
        ),
        EventData::Fork(d) => (
            d.child_pid,
            summary!("fork {} -> {}", d.parent_comm, d.child_comm),
        ),
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{
        EventAction, EventClass, ExecEventData, FileOpenData, Severity, UserLogonData,
    };

    #[test]
    fn long_multibyte_fields_are_bounded_before_storing_history() {
        let recorder = FlightRecorder::new(2);
        recorder.record(&exec_event(4, &"é".repeat(4096)));
        let history = recorder.history_for(&[4], 1);
        assert_eq!(history.len(), 1);
        assert!(history[0].summary.len() <= MAX_SUMMARY_BYTES);
    }

    fn exec_event(pid: i32, exe: &str) -> AgentEvent {
        AgentEvent::new(
            "a".into(),
            "h".into(),
            EventClass::Process,
            EventAction::Exec,
            Severity::Info,
            EventData::ProcessExec(Box::new(ExecEventData {
                pid,
                ppid: 1,
                uid: 1000,
                gid: 1000,
                username: "alice".into(),
                comm: "bash".into(),
                exe: exe.into(),
                cmdline: exe.into(),
                cwd: "/home/alice".into(),
                container_id: None,
                ld_preload: None,
                exe_sha256: None,
                loaded_libraries: Vec::new(),
                env: Default::default(),
                interpreter: None,
                container_runtime: None,
                container_image: None,
                container_image_digest: None,
                k8s: None,
                ..Default::default()
            })),
        )
    }

    fn open_event(pid: i32, path: &str) -> AgentEvent {
        AgentEvent::new(
            "a".into(),
            "h".into(),
            EventClass::Filesystem,
            EventAction::Open,
            Severity::Info,
            EventData::FileOpen(FileOpenData {
                pid,
                uid: 1000,
                gid: 1000,
                username: "alice".into(),
                comm: "cat".into(),
                path: path.into(),
                flags: 0,
                exe: None,
                process_start_time: None,
                sensitive_class: None,
                suppressed_repeats: None,
            }),
        )
    }

    #[test]
    fn history_is_filtered_by_pid_and_capped() {
        let r = FlightRecorder::new(100);
        r.record(&exec_event(50, "/bin/bash"));
        r.record(&open_event(50, "/etc/passwd"));
        r.record(&open_event(99, "/tmp/other")); // different pid
        r.record(&open_event(50, "/home/alice/.aws/credentials"));

        let hist = r.history_for(&[50], 10);
        assert_eq!(hist.len(), 3, "only pid 50's events");
        assert!(hist.iter().all(|e| e.pid == Some(50)));
        // Chronological order preserved.
        assert!(hist[0].summary.contains("exec"));
        assert!(hist.last().unwrap().summary.contains(".aws/credentials"));

        // Ancestry pids are honoured too.
        assert_eq!(r.history_for(&[50, 99], 10).len(), 4);
        // Cap keeps only the most recent.
        assert_eq!(r.history_for(&[50], 2).len(), 2);
    }

    #[test]
    fn ring_evicts_oldest_when_full() {
        let r = FlightRecorder::new(2);
        r.record(&open_event(7, "/a"));
        r.record(&open_event(7, "/b"));
        r.record(&open_event(7, "/c"));
        let hist = r.history_for(&[7], 10);
        assert_eq!(hist.len(), 2);
        assert!(hist[0].summary.contains("/b"), "oldest (/a) was evicted");
        assert!(hist[1].summary.contains("/c"));
    }

    #[test]
    fn startup_process_baseline_does_not_enter_the_history_ring() {
        let r = FlightRecorder::new(10);
        let mut ev = AgentEvent::new(
            "a".into(),
            "h".into(),
            EventClass::Process,
            EventAction::Snapshot,
            Severity::Info,
            EventData::ProcessCreate(Default::default()),
        );
        if let EventData::ProcessCreate(d) = &mut ev.data {
            d.pid = 7;
        }
        r.record(&ev);
        assert!(r.history_for(&[7], 10).is_empty());
    }

    #[test]
    fn correlates_remote_from_recent_logon() {
        let r = FlightRecorder::new(10);
        let mut logon = AgentEvent::new(
            "a".into(),
            "h".into(),
            EventClass::User,
            EventAction::Logon,
            Severity::Info,
            EventData::UserLogon(UserLogonData {
                username: "alice".into(),
                src_addr: Some("203.0.113.7".into()),
                src_port: Some(40222),
                auth_method: Some("publickey".into()),
                success: true,
                ..Default::default()
            }),
        );
        logon.timestamp = Utc::now();
        r.record(&logon);

        assert_eq!(
            r.correlate_remote(Some("alice")),
            Some(("203.0.113.7".to_string(), Some(40222)))
        );
        // Unknown / absent user does not correlate.
        assert_eq!(r.correlate_remote(Some("bob")), None);
        assert_eq!(r.correlate_remote(None), None);
    }

    #[test]
    fn failed_logons_are_not_correlated() {
        let r = FlightRecorder::new(10);
        let mut logon = AgentEvent::new(
            "a".into(),
            "h".into(),
            EventClass::User,
            EventAction::LogonFailed,
            Severity::Medium,
            EventData::UserLogon(UserLogonData {
                username: "alice".into(),
                src_addr: Some("203.0.113.9".into()),
                src_port: Some(40333),
                auth_method: Some("password".into()),
                success: false,
                ..Default::default()
            }),
        );
        logon.timestamp = Utc::now();
        r.record(&logon);
        assert_eq!(r.correlate_remote(Some("alice")), None);
    }
}
