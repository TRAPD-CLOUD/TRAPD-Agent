//! Guard pair: a second small service (`trapd-guard`, the same signed binary
//! started as `trapd-agent guard`) and the agent watch each other (phase 09,
//! layer L2).
//!
//! Why: a process that is stopped (`sc stop`, `taskkill`, `kill -9`) or merely
//! *suspended* (`NtSuspendProcess`, `kill -STOP`) leaves the host looking alive
//! while the sensor is mute. Two cooperating processes turn that into an
//! event: the survivor reports it and restarts the other. Defeating the pair
//! needs both processes stopped within the same ~10 s window, which is the bar
//! of purpose-built tooling rather than of one command.
//!
//! Design, deliberately small:
//!   * One local channel hosted by the guard: a named pipe with a SYSTEM-only
//!     DACL (Windows) or a `0600` root unix socket under `/run/trapd` (Linux).
//!     The agent pings it every [`PING_INTERVAL`]; the guard answers. Each side
//!     therefore sees the other's liveness: the guard from pings arriving, the
//!     agent from pongs arriving. Silence for [`HUNG_AFTER`] means hung.
//!   * Death is instant, not polled: a process handle wait (Windows) or a
//!     pidfd (Linux) on the peer's OS-reported pid (never a pid the peer
//!     claims).
//!   * The guard holds no backend credentials. Its findings are written as
//!     small strict records into `<state>/guard-events/`; the agent turns them
//!     into events (live, on the guard's hint in the next pong, and at start).
//!     The authenticity of a record rests on the state-directory ACL (SYSTEM
//!     only), the same barrier every other local self-protection record has;
//!     nothing from the file is copied into an event as text.
//!   * Planned stops are not tampering. The agent tells the guard what kind of
//!     stop is under way (the same validated marker the stop announcer uses);
//!     see [`classify`] and [`decide`]. The guard never trusts that for more
//!     than "do not restart": the agent reports the stop itself and the
//!     backend matches it against its own records.
//!
//! The pure parts (protocol, timing, rate limit, decisions, records) live in
//! this file and are unit-tested on every platform; the transports and the
//! service control are in the submodules.

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use trapd_schema::{AgentEvent, DetectionData, EventAction, EventClass, EventData, Severity};
use uuid::Uuid;

use super::stop_marker::{self, Reason, StopMarker};

pub mod agent_link;
#[cfg(any(windows, target_os = "linux"))]
pub mod control;
#[cfg(any(windows, target_os = "linux"))]
pub mod ipc;
#[cfg(any(windows, target_os = "linux"))]
pub mod run;
pub mod supervise;

pub const PEER_LOST_RULE_ID: &str = "selfprotect.peer_lost";
pub const PEER_BINARY_TAMPERED_RULE_ID: &str = "selfprotect.peer_binary_tampered";

/// How often the agent pings the guard.
pub const PING_INTERVAL: Duration = Duration::from_secs(2);
/// Silence after which a peer that is still running counts as hung.
pub const HUNG_AFTER: Duration = Duration::from_secs(10);
/// A peer that announced a stop and then goes quiet is shutting down, not
/// hung; it gets this long to actually die before it counts as hung.
pub const SHUTDOWN_HANG_AFTER: Duration = Duration::from_secs(60);
/// Bound for one ping/pong exchange.
pub const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(2);
/// A peer never heard from since the watcher started is given this long.
pub const STARTUP_GRACE: Duration = Duration::from_secs(30);
/// After an announced upgrade / self-update stop the peer is expected back.
pub const PLANNED_RESTART_GRACE: Duration = Duration::from_secs(120);
/// While a peer stays lost it is re-handled at most this often.
pub const RELOSS_INTERVAL: Duration = Duration::from_secs(30);
/// Restarts of one peer allowed per [`RESTART_WINDOW`].
pub const MAX_RESTARTS: usize = 3;
pub const RESTART_WINDOW: Duration = Duration::from_secs(10 * 60);

pub const PROTOCOL_VERSION: u32 = 1;
/// A frame is one JSON line; nothing legitimate comes close to this.
pub const MAX_FRAME_BYTES: usize = 4096;

/// At most this many unread guard records are kept (the guard drops the rest).
pub const MAX_SPOOL_RECORDS: usize = 32;
const MAX_RECORD_BYTES: u64 = 2048;
const SPOOL_DIR: &str = "guard-events";

// ── Peers ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Peer {
    Agent,
    Guard,
}

impl Peer {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Agent => "agent",
            Self::Guard => "guard",
        }
    }

    /// Windows service name / systemd unit stem.
    pub fn service_name(self) -> &'static str {
        match self {
            Self::Agent => "trapd-agent",
            Self::Guard => "trapd-guard",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LossReason {
    /// The process is gone (or was never seen after the startup grace).
    Died,
    /// Still running but silent for too long (suspended, deadlocked, wedged).
    Hung,
}

impl LossReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Died => "died",
            Self::Hung => "hung",
        }
    }
}

// ── Wire protocol (one JSON line per frame, request/response) ─────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NoticeKind {
    HostShutdown,
    ServiceStop,
}

/// "I am stopping" from the agent, sent before it exits. The marker is the
/// same strictly validated authorization the stop announcer consumes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StopNotice {
    pub kind: NoticeKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub marker: Option<StopMarker>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ping {
    pub v: u32,
    pub seq: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stop: Option<StopNotice>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pong {
    pub v: u32,
    pub seq: u64,
    /// The guard has records waiting for the agent to pick up.
    pub pending: bool,
    /// The guard is stopping (the agent learns it from the answer, since the
    /// guard is the server and cannot push).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stop: Option<StopNotice>,
}

/// Parse one frame. Bounded, strict (`deny_unknown_fields`, exact version).
pub fn parse_frame<T: for<'a> Deserialize<'a>>(line: &[u8]) -> Result<T> {
    if line.len() > MAX_FRAME_BYTES {
        bail!("frame too large");
    }
    serde_json::from_slice(line).context("malformed frame")
}

pub fn encode_frame<T: Serialize>(frame: &T) -> Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec(frame).context("encode frame")?;
    if bytes.len() >= MAX_FRAME_BYTES {
        bail!("frame too large");
    }
    bytes.push(b'\n');
    Ok(bytes)
}

// ── What a stop notice means ──────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopClass {
    /// The host is going down; nothing to restart, nothing to report.
    HostShutdown,
    /// A stop without a valid authorization (`sc stop`, SIGTERM, ...).
    Unauthorized,
    /// Installer / signed self-update: the peer is expected back shortly.
    Planned,
    /// Maintenance token or uninstall: the operator wants it off.
    Authorized,
}

impl StopClass {
    /// Whether a valid authorization accompanied the stop.
    pub fn authorized(self) -> bool {
        matches!(self, Self::Planned | Self::Authorized)
    }
}

/// Classify a notice at the time it arrives. An invalid or expired marker is
/// no marker (fails toward "unauthorized", as the stop announcer does).
pub fn classify(notice: &StopNotice, now_unix: i64) -> StopClass {
    match notice.kind {
        NoticeKind::HostShutdown => StopClass::HostShutdown,
        NoticeKind::ServiceStop => {
            match notice
                .marker
                .as_ref()
                .filter(|m| stop_marker::validate(m, now_unix).is_ok())
            {
                None => StopClass::Unauthorized,
                Some(m) => match m.reason {
                    Reason::Upgrade | Reason::SelfUpdate => StopClass::Planned,
                    Reason::Maintenance | Reason::Uninstall => StopClass::Authorized,
                },
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestartPolicy {
    /// Restart now (rate limited).
    Now,
    /// Never: the stop was wanted.
    Never,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Decision {
    pub report: bool,
    pub restart: RestartPolicy,
    /// The watcher itself should stop too (an authorized stop of the pair).
    pub watcher_exits: bool,
}

/// What to do about a lost peer. `class` is the peer's announced stop, if any.
/// A planned stop whose grace period ran out (see [`PeerMonitor::poll`]) is
/// handled like an unannounced loss: it did not come back.
pub fn decide(class: Option<StopClass>, grace_expired: bool) -> Decision {
    match class {
        None | Some(StopClass::Unauthorized) => Decision {
            report: true,
            restart: RestartPolicy::Now,
            watcher_exits: false,
        },
        Some(StopClass::Planned) if grace_expired => Decision {
            report: true,
            restart: RestartPolicy::Now,
            watcher_exits: false,
        },
        Some(StopClass::Planned) => Decision {
            report: false,
            restart: RestartPolicy::Never,
            watcher_exits: false,
        },
        Some(StopClass::HostShutdown) => Decision {
            report: false,
            restart: RestartPolicy::Never,
            watcher_exits: false,
        },
        Some(StopClass::Authorized) => Decision {
            report: false,
            restart: RestartPolicy::Never,
            watcher_exits: true,
        },
    }
}

// ── Liveness tracking (pure; time is passed in) ───────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Loss {
    pub reason: LossReason,
    pub class: Option<StopClass>,
    /// First handling of this episode (the one that reports).
    pub first: bool,
    /// A planned stop did not come back within [`PLANNED_RESTART_GRACE`].
    pub grace_expired: bool,
}

#[derive(Debug)]
pub struct PeerMonitor {
    born: Instant,
    last_seen: Option<Instant>,
    pid: Option<u32>,
    notice: Option<StopClass>,
    exited: bool,
    lost_since: Option<Instant>,
    last_loss: Option<Instant>,
}

impl PeerMonitor {
    pub fn new(now: Instant) -> Self {
        Self {
            born: now,
            last_seen: None,
            pid: None,
            notice: None,
            exited: false,
            lost_since: None,
            last_loss: None,
        }
    }

    pub fn pid(&self) -> Option<u32> {
        self.pid
    }

    /// An exchange with the peer succeeded. `notice` is the stop it announced,
    /// if any. A ping without a notice after one was recorded means the peer
    /// was started again: the episode is over.
    pub fn observe(&mut self, now: Instant, pid: Option<u32>, notice: Option<StopClass>) {
        let restarted = notice.is_none() && (self.notice.is_some() || self.exited);
        let new_pid = pid.is_some() && self.pid.is_some() && pid != self.pid;
        if restarted || new_pid || self.lost_since.is_some() {
            self.notice = None;
            self.exited = false;
            self.lost_since = None;
            self.last_loss = None;
        }
        if notice.is_some() {
            self.notice = notice;
        }
        self.last_seen = Some(now);
        if pid.is_some() {
            self.pid = pid;
        }
    }

    /// The OS reported the peer's process gone.
    pub fn mark_exited(&mut self) {
        self.exited = true;
    }

    fn hung_after(&self) -> Duration {
        if self.notice.is_some() {
            SHUTDOWN_HANG_AFTER
        } else {
            HUNG_AFTER
        }
    }

    /// `Some` when the peer has to be handled now. While a peer stays lost the
    /// episode is re-handled every [`RELOSS_INTERVAL`] (`first == false`), so a
    /// rate-limited restart is retried without reporting again.
    pub fn poll(&mut self, now: Instant) -> Option<Loss> {
        let reason = if self.exited {
            LossReason::Died
        } else {
            match self.last_seen {
                Some(seen) if now.duration_since(seen) > self.hung_after() => LossReason::Hung,
                None if now.duration_since(self.born) > STARTUP_GRACE => LossReason::Died,
                _ => return None,
            }
        };
        let since = *self.lost_since.get_or_insert(now);
        let first = self.last_loss.is_none();
        if !first && now.duration_since(self.last_loss?) < RELOSS_INTERVAL {
            return None;
        }
        let grace_expired = if self.notice == Some(StopClass::Planned) {
            if now.duration_since(since) < PLANNED_RESTART_GRACE {
                return None;
            }
            true
        } else {
            false
        };
        self.last_loss = Some(now);
        Some(Loss {
            reason,
            class: self.notice,
            first,
            grace_expired,
        })
    }
}

/// Sliding-window limit for restarts of one peer, so a crash loop or a hostile
/// ping-pong cannot turn the guard into a fork bomb.
#[derive(Debug)]
pub struct RestartLimiter {
    attempts: VecDeque<Instant>,
}

impl RestartLimiter {
    pub fn new() -> Self {
        Self {
            attempts: VecDeque::new(),
        }
    }

    pub fn try_acquire(&mut self, now: Instant) -> bool {
        while self
            .attempts
            .front()
            .is_some_and(|t| now.duration_since(*t) >= RESTART_WINDOW)
        {
            self.attempts.pop_front();
        }
        if self.attempts.len() >= MAX_RESTARTS {
            return false;
        }
        self.attempts.push_back(now);
        true
    }
}

impl Default for RestartLimiter {
    fn default() -> Self {
        Self::new()
    }
}

// ── Records the guard leaves for the agent ────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordKind {
    PeerLost,
    PeerBinaryTampered,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RestartOutcome {
    Started,
    /// The rate limit refused it.
    Suppressed,
    Failed,
    /// Not attempted (the binary failed its integrity check).
    Refused,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub v: u32,
    pub kind: RecordKind,
    pub event_id: Uuid,
    pub at: DateTime<Utc>,
    pub peer: Peer,
    pub reason: LossReason,
    pub announced_stop: bool,
    pub maintenance_authorized: bool,
    pub restart: RestartOutcome,
    /// A foreign process that held the hung peer under ptrace (debugger
    /// attach freezes the process and keeps its zombie from being reaped).
    /// The guard ends it so the service manager can restart the peer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tracer: Option<Tracer>,
    /// `sha256:<64 hex>`; only for `peer_binary_tampered`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_hash: Option<String>,
}

/// The process that had the peer under ptrace when the guard intervened.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tracer {
    pub pid: u32,
    /// Executable path as the kernel reports it; "unknown" if unreadable.
    pub exe: String,
}

impl Tracer {
    fn valid(&self) -> bool {
        self.pid > 1
            && !self.exe.is_empty()
            && self.exe.len() <= 4096
            && !self.exe.chars().any(char::is_control)
    }
}

/// `TracerPid:` from a `/proc/<pid>/status` text; `None` when not traced.
pub fn parse_tracer_pid(status: &str) -> Option<u32> {
    status
        .lines()
        .find_map(|l| l.strip_prefix("TracerPid:"))
        .and_then(|v| v.trim().parse::<u32>().ok())
        .filter(|p| *p > 0)
}

fn valid_hash(h: &str) -> bool {
    h.strip_prefix("sha256:")
        .is_some_and(|x| x.len() == 64 && x.bytes().all(|b| b.is_ascii_hexdigit()))
}

impl Record {
    pub fn peer_lost(peer: Peer, loss: &Loss, restart: RestartOutcome, now: DateTime<Utc>) -> Self {
        Self {
            v: 1,
            kind: RecordKind::PeerLost,
            event_id: Uuid::new_v4(),
            at: now,
            peer,
            reason: loss.reason,
            announced_stop: loss.class.is_some(),
            maintenance_authorized: loss.class.is_some_and(StopClass::authorized),
            restart,
            tracer: None,
            expected_hash: None,
            current_hash: None,
        }
    }

    /// The same record carrying the process that held the peer under ptrace.
    pub fn with_tracer(mut self, tracer: Option<Tracer>) -> Self {
        self.tracer = tracer;
        self
    }

    pub fn binary_tampered(
        peer: Peer,
        loss: &Loss,
        expected: &str,
        current: &str,
        now: DateTime<Utc>,
    ) -> Self {
        Self {
            kind: RecordKind::PeerBinaryTampered,
            restart: RestartOutcome::Refused,
            expected_hash: Some(expected.to_owned()),
            current_hash: Some(current.to_owned()),
            ..Self::peer_lost(peer, loss, RestartOutcome::Refused, now)
        }
    }

    /// Structural validation of a record read from disk.
    pub fn validate(&self) -> bool {
        self.v == 1
            && !self.event_id.is_nil()
            && match self.kind {
                RecordKind::PeerLost => {
                    self.expected_hash.is_none()
                        && self.current_hash.is_none()
                        && self.tracer.as_ref().is_none_or(Tracer::valid)
                }
                RecordKind::PeerBinaryTampered => {
                    self.expected_hash.as_deref().is_some_and(valid_hash)
                        && self.current_hash.as_deref().is_some_and(valid_hash)
                }
            }
    }
}

/// The detection event for a record. Built only from validated fields. High
/// severity is the agent's stamp; the backend decides from its own catalog.
pub fn record_event(record: &Record, agent_id: &str, hostname: &str) -> AgentEvent {
    let (rule_id, title, severity, detail) = match record.kind {
        RecordKind::PeerLost => (
            PEER_LOST_RULE_ID,
            format!("TRAPD {} was lost", record.peer.as_str()),
            if record.maintenance_authorized {
                Severity::Medium
            } else {
                Severity::High
            },
            "A TRAPD self-protection process stopped answering or ended. The surviving process \
             reports it and restarts the other one.",
        ),
        RecordKind::PeerBinaryTampered => (
            PEER_BINARY_TAMPERED_RULE_ID,
            format!(
                "TRAPD {} binary failed its integrity check",
                record.peer.as_str()
            ),
            Severity::Critical,
            "The binary on disk no longer matches its recorded digest, so the lost process was \
             not restarted from it.",
        ),
    };
    let mut evidence = serde_json::json!({
        "peer": record.peer.as_str(),
        "reason": record.reason.as_str(),
        "announced_stop": record.announced_stop,
        "maintenance_authorized": record.maintenance_authorized,
        "restart": record.restart,
    });
    if let Some(t) = &record.tracer {
        evidence["tracer_pid"] = t.pid.into();
        evidence["tracer_exe"] = t.exe.clone().into();
    }
    if record.kind == RecordKind::PeerBinaryTampered {
        evidence["expected_hash"] = record.expected_hash.clone().into();
        evidence["current_hash"] = record.current_hash.clone().into();
    }
    let finding = DetectionData {
        rule_id: rule_id.into(),
        title,
        category: "defense_evasion".into(),
        mitre_tactic: Some("TA0005 Defense Evasion".into()),
        mitre_technique: Some("T1562.001".into()),
        confidence: 90,
        subject: record.peer.service_name().into(),
        detail: detail.into(),
        evidence,
        ..Default::default()
    };
    let mut event = AgentEvent::new(
        agent_id.into(),
        hostname.into(),
        EventClass::Detection,
        EventAction::Detected,
        severity,
        EventData::Detection(Box::new(finding)),
    );
    event.timestamp = record.at;
    event.event_id = record.event_id;
    event
}

pub fn spool_dir(state_dir: &Path) -> PathBuf {
    state_dir.join(SPOOL_DIR)
}

fn record_files(dir: &Path) -> impl Iterator<Item = PathBuf> {
    std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
}

/// Number of records waiting, capped at the supported spool capacity.
pub fn pending_count(state_dir: &Path) -> usize {
    record_files(&spool_dir(state_dir))
        .take(MAX_SPOOL_RECORDS)
        .count()
}

/// Leave a record for the agent. Atomic; refused (dropped) when the spool is
/// full, which only happens if nothing has been reading it.
pub fn write_record(state_dir: &Path, record: &Record) -> Result<()> {
    let dir = spool_dir(state_dir);
    if pending_count(state_dir) >= MAX_SPOOL_RECORDS {
        crate::telemetry::metrics::metrics().state_capacity_dropped(1);
        bail!("guard record spool is full");
    }
    let name = format!("{}-{}.json", record.at.timestamp_millis(), record.event_id);
    let bytes = serde_json::to_vec(record).context("encode guard record")?;
    crate::paths::write_atomic(&dir.join(name), &bytes, 0o600).context("write guard record")
}

/// Take the records for delivery, oldest first. Unreadable, oversized or
/// invalid files are removed (not ours to keep). A record is removed by
/// [`remove_record`] only after it was handed on.
pub fn read_records(state_dir: &Path) -> Vec<(PathBuf, Record)> {
    let mut out = Vec::new();
    let mut paths: Vec<_> = record_files(&spool_dir(state_dir))
        .take(MAX_SPOOL_RECORDS)
        .collect();
    paths.sort_unstable();
    for path in paths {
        match crate::paths::bounded_regular_bytes(&path, MAX_RECORD_BYTES)
            .ok()
            .and_then(|b| serde_json::from_slice::<Record>(&b).ok())
            .filter(Record::validate)
        {
            Some(r) => out.push((path, r)),
            None => {
                if std::fs::remove_file(&path).is_ok() {
                    crate::telemetry::metrics::metrics()
                        .event_dropped(crate::telemetry::DropReason::PersistentQueueCorrupt);
                }
            }
        }
    }
    out
}

pub fn remove_record(path: &Path) {
    let _ = std::fs::remove_file(path);
}

#[cfg(test)]
mod tests;
