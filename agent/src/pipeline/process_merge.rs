//! One `process.create` per process, whichever sensors saw it.
//!
//! On Windows three independent sources can report the same process start:
//!
//! * ETW Kernel-Process (and the 3 s poller when ETW is off) — knows the exact
//!   creation FILETIME, but reads the command line only after the fact, so a
//!   short-lived LOLBin (`certutil.exe`, `mshta.exe`) arrives with
//!   `cmdline == ""` and an `io_error` marker;
//! * Security 4688 / Sysmon 1, normalised from the event log — carries the
//!   command line and account the OS recorded at creation, but no creation
//!   time, and arrives one event-log poll later.
//!
//! Forwarding both gives the backend two creates per process, and one of them
//! empty. This stage sits in front of the consumer and merges them:
//!
//! * a create that carries a command line is forwarded at once;
//! * a create without one is held for [`MERGE_GRACE`] so the audit record can
//!   complete it; after the grace it is forwarded as it is (still marked
//!   partial — the command line really could not be obtained);
//! * a second report of an already-forwarded or held process is dropped (the
//!   raw event-log record stays available as its own `Log` event).
//!
//! A `process.terminate` for a held process is queued behind it, so a consumer
//! never sees a stop before its start.
//!
//! Identity follows the process-identity rule (AGENTS.md): two reports are the
//! same process only with evidence of the same generation. Sensor reports carry
//! the creation FILETIME and must agree on it. An audit record has none, but
//! Windows writes 4688 / Sysmon 1 at process creation, so its record time must
//! lie within [`CREATION_TOLERANCE`] of the sensor's creation time, and pid,
//! parent and image must agree. Without that evidence, or when more than one
//! candidate fits, the reports stay separate events.
//!
//! Without ETW the 3 s poller is the sensor: it has the creation FILETIME and
//! image digest but misses processes shorter than its interval, while 4688
//! sees every process but has neither. Either may arrive first (the poller
//! up to 3 s after creation, the event-log poll up to 5 s). With
//! [`ProcessCreateMerger::set_audit_hold`] enabled, an audit create with no
//! sensor counterpart yet is held for [`AUDIT_GRACE`]: a sensor report that
//! arrives meanwhile becomes the event (start time, digest) and takes the
//! audit record's missing fields; otherwise the audit create goes out as it
//! is, without start time. A held audit create never suppresses a live report
//! that arrives after its release.
//!
//! The stage is pure and clock-injected so it can be tested without a runtime.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use crate::schema::{AgentEvent, EventData, ProcessCreateData};
use crate::telemetry::enrichment::EnrichmentStatus;

/// How long a create without a command line waits for the audit record. Must
/// exceed the event-log poll interval (5 s) plus read latency.
pub const MERGE_GRACE: Duration = Duration::from_secs(8);
/// How long an audit create waits for the poller to report the same process.
/// Must exceed the poll interval (3 s) plus sampling and hashing latency.
pub const AUDIT_GRACE: Duration = Duration::from_secs(5);
/// How far an audit record's time may lie from the sensor's creation time and
/// still describe the same process generation.
const CREATION_TOLERANCE_MS: i64 = 2_000;
/// How long a forwarded create still suppresses a second report of itself.
const SEEN_TTL: Duration = Duration::from_secs(60);
/// Bound on remembered forwarded creates; the oldest are forgotten first.
const SEEN_CAP: usize = 4096;
/// Bound on creates held at once. Beyond it the oldest is released early
/// rather than growing without limit under a process storm.
const HELD_CAP: usize = 1024;

struct Held {
    event: AgentEvent,
    deadline: Instant,
    /// Terminate events of this process, released right behind the create.
    trailing: Vec<AgentEvent>,
}

/// What identifies one report of a process start.
#[derive(Clone)]
struct Ident {
    pid: i32,
    ppid: i32,
    exe: String,
    /// Creation FILETIME from a sensor; `None` for an audit record.
    start: Option<u64>,
    /// Creation time in Unix ms: from `start`, or the audit record's time.
    created_ms: Option<i64>,
}

struct Seen {
    ident: Ident,
    at: Instant,
}

#[derive(Default)]
pub struct ProcessCreateMerger {
    held: Vec<Held>,
    seen: VecDeque<Seen>,
    /// Hold audit creates for the poller (no ETW process provider).
    audit_hold: bool,
}

fn create_of(event: &AgentEvent) -> Option<&ProcessCreateData> {
    match &event.data {
        EventData::ProcessCreate(d) => Some(d),
        _ => None,
    }
}

fn create_mut(event: &mut AgentEvent) -> Option<&mut ProcessCreateData> {
    match &mut event.data {
        EventData::ProcessCreate(d) => Some(d),
        _ => None,
    }
}

/// FILETIME (100 ns ticks since 1601) to Unix milliseconds.
fn filetime_ms(ticks: u64) -> Option<i64> {
    let ticks = i64::try_from(ticks).ok()?;
    ticks
        .checked_sub(116_444_736_000_000_000)
        .map(|unix| unix.div_euclid(10_000))
}

fn ident_of(event: &AgentEvent) -> Option<Ident> {
    let d = create_of(event)?;
    let created_ms = match d.process_start_time {
        Some(ft) => filetime_ms(ft),
        // The record time of 4688 / Sysmon 1 is the creation time.
        None => Some(event.timestamp.timestamp_millis()),
    };
    Some(Ident {
        pid: d.pid,
        ppid: d.ppid,
        exe: d.exe.clone(),
        start: d.process_start_time,
        created_ms,
    })
}

/// Is there evidence that two reports describe the same process generation?
/// Unknown counts as "no" (AGENTS.md, process identity).
fn same_process(a: &Ident, b: &Ident) -> bool {
    if a.pid != b.pid {
        return false;
    }
    if let (Some(x), Some(y)) = (a.start, b.start) {
        return x == y;
    }
    let close = matches!(
        (a.created_ms, b.created_ms),
        (Some(x), Some(y)) if (x - y).abs() <= CREATION_TOLERANCE_MS
    );
    if !close {
        return false;
    }
    if a.ppid != 0 && b.ppid != 0 && a.ppid != b.ppid {
        return false;
    }
    a.exe.is_empty() || b.exe.is_empty() || a.exe.eq_ignore_ascii_case(&b.exe)
}

/// Fill what `held` lacks from `extra`; never overwrite a value it has.
fn complete_from(held: &mut ProcessCreateData, extra: &ProcessCreateData) {
    if held.cmdline.is_empty() && !extra.cmdline.is_empty() {
        held.cmdline = extra.cmdline.clone();
        held.enrichment.enrichment_errors.remove("cmdline");
        match extra.enrichment.truncated_fields.get("cmdline") {
            Some(t) => {
                held.enrichment
                    .truncated_fields
                    .insert("cmdline".into(), t.clone());
            }
            None => {
                held.enrichment.truncated_fields.remove("cmdline");
            }
        }
    }
    if (held.username.is_empty() || held.username == "unknown")
        && !extra.username.is_empty()
        && extra.username != "unknown"
    {
        held.username = extra.username.clone();
        held.enrichment.enrichment_errors.remove("username");
    }
    if held.exe.is_empty() && !extra.exe.is_empty() {
        held.exe = extra.exe.clone();
        held.name = extra.name.clone();
        held.enrichment.enrichment_errors.remove("exe");
    }
    if held.parent_exe.is_none() {
        held.parent_exe = extra.parent_exe.clone();
    }
    if held.enrichment.enrichment_errors.is_empty() {
        if held.enrichment.enrichment_status != Some(EnrichmentStatus::Failed) {
            held.enrichment.enrichment_status = None;
        }
    } else if held.enrichment.enrichment_status.is_none() {
        held.enrichment.enrichment_status = Some(EnrichmentStatus::Partial);
    }
}

impl ProcessCreateMerger {
    pub fn new() -> Self {
        Self::default()
    }

    /// Hold audit creates until the poller can report the same process. Turn
    /// this on while the poller is the live process sensor.
    pub fn set_audit_hold(&mut self, on: bool) {
        self.audit_hold = on;
    }

    /// When the next held create must be released, if any.
    pub fn next_deadline(&self) -> Option<Instant> {
        self.held.iter().map(|h| h.deadline).min()
    }

    /// Run a batch through the stage; returns what may be forwarded now.
    pub fn process(&mut self, batch: Vec<AgentEvent>, now: Instant) -> Vec<AgentEvent> {
        self.forget_old(now);
        let mut out = Vec::with_capacity(batch.len());
        for event in batch {
            match &event.data {
                EventData::ProcessCreate(_) => self.on_create(event, now, &mut out),
                EventData::ProcessTerminate(t) => {
                    let pid = t.pid;
                    // A stop belongs to the newest held generation of its pid
                    // that has not stopped yet; a recycled pid's earlier
                    // generation already has its own stop queued.
                    match self.held.iter_mut().rev().find(|h| {
                        h.trailing.is_empty() && create_of(&h.event).is_some_and(|d| d.pid == pid)
                    }) {
                        Some(h) => h.trailing.push(event),
                        None => out.push(event),
                    }
                }
                _ => out.push(event),
            }
        }
        out.extend(self.flush_due(now));
        out
    }

    /// Release every held create whose grace has run out.
    pub fn flush_due(&mut self, now: Instant) -> Vec<AgentEvent> {
        let mut out = Vec::new();
        let mut i = 0;
        while i < self.held.len() {
            if self.held[i].deadline <= now {
                let held = self.held.remove(i);
                self.release(held, now, &mut out);
            } else {
                i += 1;
            }
        }
        out
    }

    /// Release everything (shutdown).
    pub fn flush_all(&mut self, now: Instant) -> Vec<AgentEvent> {
        let mut out = Vec::new();
        for held in std::mem::take(&mut self.held) {
            self.release(held, now, &mut out);
        }
        out
    }

    fn release(&mut self, held: Held, now: Instant, out: &mut Vec<AgentEvent>) {
        if let Some(ident) = ident_of(&held.event) {
            self.remember(ident, now);
        }
        out.push(held.event);
        out.extend(held.trailing);
    }

    fn remember(&mut self, ident: Ident, now: Instant) {
        if self.seen.len() >= SEEN_CAP {
            self.seen.pop_front();
        }
        self.seen.push_back(Seen { ident, at: now });
    }

    fn forget_old(&mut self, now: Instant) {
        while self
            .seen
            .front()
            .is_some_and(|s| now.duration_since(s.at) > SEEN_TTL)
        {
            self.seen.pop_front();
        }
    }

    fn on_create(&mut self, event: AgentEvent, now: Instant, out: &mut Vec<AgentEvent>) {
        let (Some(d), Some(ident)) = (create_of(&event), ident_of(&event)) else {
            out.push(event);
            return;
        };
        let precise = d.process_start_time.is_some();
        let extra = d.clone();

        // A second report of a process we hold. Merge only into the single
        // candidate with generation evidence; two fitting candidates are
        // ambiguous and the report stays its own event.
        let candidates: Vec<usize> = self
            .held
            .iter()
            .enumerate()
            .filter(|(_, h)| ident_of(&h.event).is_some_and(|held| same_process(&ident, &held)))
            .map(|(i, _)| i)
            .collect();
        if let [pos] = candidates[..] {
            let held_is_audit =
                create_of(&self.held[pos].event).is_some_and(|h| h.process_start_time.is_none());
            if precise && held_is_audit {
                // The sensor report is the better base: it alone carries the
                // creation time and image digest. The audit record only
                // fills what the sensor could not read.
                let audit = self.held.remove(pos);
                let audit_data = create_of(&audit.event).cloned().unwrap_or_default();
                let mut event = event;
                if let Some(base) = create_mut(&mut event) {
                    complete_from(base, &audit_data);
                }
                let has_cmdline = create_of(&event).is_some_and(|c| !c.cmdline.is_empty());
                let merged = Held {
                    event,
                    deadline: now + MERGE_GRACE,
                    trailing: audit.trailing,
                };
                if has_cmdline {
                    self.release(merged, now, out);
                } else {
                    self.held.push(merged);
                }
                return;
            }
            if let Some(held) = create_mut(&mut self.held[pos].event) {
                complete_from(held, &extra);
            }
            // A sensor create is released once it has a command line;
            // otherwise it keeps waiting until its own deadline (a Security
            // 4688 without command line may be followed by a Sysmon 1 that
            // has one). A held audit create waits for the poller instead.
            if !held_is_audit
                && create_of(&self.held[pos].event).is_some_and(|h| !h.cmdline.is_empty())
            {
                let held = self.held.remove(pos);
                self.release(held, now, out);
            }
            return;
        }
        if candidates.is_empty() {
            // A second report of a process already forwarded.
            // A live sensor report is never replaced by an audit record that
            // went out first: only it carries the creation time and image
            // digest. Audit records and repeated sensor reports are dropped.
            let matching = || self.seen.iter().filter(|s| same_process(&s.ident, &ident));
            // Distinct generations among the matches: sensor reports differ by
            // creation time; audit-only entries name no generation of their own.
            let generations = matching().filter(|s| s.ident.start.is_some()).count();
            let audit_only = matching().any(|s| s.ident.start.is_none());
            let duplicate = if precise {
                generations == 1
            } else {
                generations == 1 || (generations == 0 && audit_only)
            };
            if duplicate {
                return;
            }
        }

        let wait_for_cmdline = precise && extra.cmdline.is_empty();
        let wait_for_poller = !precise && self.audit_hold;
        if (wait_for_cmdline || wait_for_poller) && candidates.is_empty() {
            if self.held.len() >= HELD_CAP {
                let oldest = self.held.remove(0);
                self.release(oldest, now, out);
            }
            self.held.push(Held {
                event,
                deadline: now + if precise { MERGE_GRACE } else { AUDIT_GRACE },
                trailing: Vec::new(),
            });
            return;
        }
        self.remember(ident, now);
        out.push(event);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{EventAction, EventClass, ProcessTerminateData, Severity};
    use crate::telemetry::{Enrichment, EnrichmentError};

    const START: u64 = 133_000_000_000_000_000;

    fn wrap(data: EventData, action: EventAction) -> AgentEvent {
        AgentEvent::new(
            "a".into(),
            "h".into(),
            EventClass::Process,
            action,
            Severity::Info,
            data,
        )
    }

    /// What ETW / the poller produce.
    fn precise(pid: i32, cmdline: &str) -> AgentEvent {
        let mut notes = Enrichment::new();
        if cmdline.is_empty() {
            notes.fail("cmdline", EnrichmentError::IoError);
            notes.fail("username", EnrichmentError::IoError);
        }
        wrap(
            EventData::ProcessCreate(ProcessCreateData {
                pid,
                ppid: 10,
                name: "certutil.exe".into(),
                exe: r"C:\Windows\System32\certutil.exe".into(),
                cmdline: cmdline.into(),
                username: if cmdline.is_empty() {
                    "unknown".into()
                } else {
                    r"HOST\u".into()
                },
                process_start_time: Some(START + pid as u64),
                enrichment: notes.finish(0),
                ..Default::default()
            }),
            EventAction::Create,
        )
    }

    /// When the process of `precise(pid, …)` was created.
    fn created(pid: i32) -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::from_timestamp_millis(filetime_ms(START + pid as u64).unwrap()).unwrap()
    }

    /// What Security 4688 / Sysmon 1 normalise to, logged at creation.
    fn audit(pid: i32, cmdline: &str) -> AgentEvent {
        let mut event = audit_at(pid, cmdline);
        event.timestamp = created(pid);
        event
    }

    fn audit_at(pid: i32, cmdline: &str) -> AgentEvent {
        wrap(
            EventData::ProcessCreate(ProcessCreateData {
                pid,
                ppid: 10,
                name: "CERTUTIL.EXE".into(),
                exe: r"c:\windows\system32\CERTUTIL.EXE".into(),
                cmdline: cmdline.into(),
                username: r"DOM\alice".into(),
                ..Default::default()
            }),
            EventAction::Create,
        )
    }

    fn stop(pid: i32) -> AgentEvent {
        wrap(
            EventData::ProcessTerminate(ProcessTerminateData {
                pid,
                name: "certutil.exe".into(),
            }),
            EventAction::Terminate,
        )
    }

    fn creates(events: &[AgentEvent]) -> Vec<&ProcessCreateData> {
        events.iter().filter_map(create_of).collect()
    }

    #[test]
    fn partial_create_is_completed_by_the_audit_record() {
        let t0 = Instant::now();
        let mut m = ProcessCreateMerger::new();
        assert!(m.process(vec![precise(7, "")], t0).is_empty());
        let out = m.process(
            vec![audit(7, "certutil -urlcache -f http://x/a a")],
            t0 + Duration::from_secs(5),
        );
        let c = creates(&out);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].cmdline, "certutil -urlcache -f http://x/a a");
        assert_eq!(c[0].username, r"DOM\alice");
        assert_eq!(c[0].process_start_time, Some(START + 7));
        assert!(c[0].enrichment.enrichment_errors.is_empty());
        assert!(c[0].enrichment.enrichment_status.is_none());
        assert!(m.next_deadline().is_none());
    }

    #[test]
    fn unresolvable_command_line_yields_exactly_one_partial_event() {
        let t0 = Instant::now();
        let mut m = ProcessCreateMerger::new();
        assert!(m.process(vec![precise(7, "")], t0).is_empty());
        assert_eq!(m.next_deadline(), Some(t0 + MERGE_GRACE));
        assert!(m.flush_due(t0 + Duration::from_secs(1)).is_empty());
        let out = m.flush_due(t0 + MERGE_GRACE);
        let c = creates(&out);
        assert_eq!(c.len(), 1);
        assert!(c[0].cmdline.is_empty());
        assert!(c[0].enrichment.enrichment_errors.contains_key("cmdline"));
        assert_eq!(
            c[0].enrichment.enrichment_status,
            Some(EnrichmentStatus::Partial)
        );
        // A late audit record without a command line adds nothing.
        assert!(m
            .process(
                vec![audit(7, "")],
                t0 + MERGE_GRACE + Duration::from_secs(1)
            )
            .is_empty());
    }

    #[test]
    fn complete_create_passes_at_once_and_suppresses_the_audit_duplicate() {
        let t0 = Instant::now();
        let mut m = ProcessCreateMerger::new();
        let out = m.process(vec![precise(7, "cmd /c dir")], t0);
        assert_eq!(creates(&out).len(), 1);
        assert!(m.process(vec![audit(7, "cmd /c dir")], t0).is_empty());
    }

    #[test]
    fn identical_duplicates_from_one_sensor_collapse() {
        let t0 = Instant::now();
        let mut m = ProcessCreateMerger::new();
        let first = precise(7, "cmd /c dir");
        let dup = first.clone();
        let out = m.process(vec![first, dup], t0);
        assert_eq!(creates(&out).len(), 1);

        let mut m = ProcessCreateMerger::new();
        let first = precise(8, "");
        let dup = first.clone();
        assert!(m.process(vec![first, dup], t0).is_empty());
        assert_eq!(creates(&m.flush_all(t0)).len(), 1);
    }

    #[test]
    fn audit_without_a_sensor_counterpart_is_forwarded() {
        let t0 = Instant::now();
        let mut m = ProcessCreateMerger::new();
        let out = m.process(vec![audit(9, "x")], t0);
        assert_eq!(creates(&out).len(), 1);
    }

    #[test]
    fn different_process_is_never_merged() {
        let t0 = Instant::now();
        let mut m = ProcessCreateMerger::new();
        assert!(m.process(vec![precise(7, "")], t0).is_empty());
        // Other pid, and same pid with another parent / image.
        let out = m.process(vec![audit(8, "other")], t0);
        assert_eq!(creates(&out).len(), 1);
        let mut other_parent = audit(7, "x");
        create_mut(&mut other_parent).unwrap().ppid = 99;
        assert_eq!(creates(&m.process(vec![other_parent], t0)).len(), 1);
        let mut other_image = audit(7, "x");
        create_mut(&mut other_image).unwrap().exe = r"C:\other.exe".into();
        assert_eq!(creates(&m.process(vec![other_image], t0)).len(), 1);
        // The held one is untouched and still pending.
        assert!(m.next_deadline().is_some());
    }

    #[test]
    fn recycled_pid_with_new_start_time_is_a_new_process() {
        let t0 = Instant::now();
        let mut m = ProcessCreateMerger::new();
        let first = m.process(vec![precise(7, "a")], t0);
        assert_eq!(creates(&first).len(), 1);
        let mut again = precise(7, "b");
        create_mut(&mut again).unwrap().process_start_time = Some(START + 9_999);
        assert_eq!(creates(&m.process(vec![again], t0)).len(), 1);
    }

    #[test]
    fn terminate_never_overtakes_its_held_create() {
        let t0 = Instant::now();
        let mut m = ProcessCreateMerger::new();
        assert!(m.process(vec![precise(7, ""), stop(7)], t0).is_empty());
        let out = m.process(vec![audit(7, "certutil x")], t0 + Duration::from_secs(5));
        assert_eq!(out.len(), 2);
        assert!(matches!(out[0].data, EventData::ProcessCreate(_)));
        assert!(matches!(out[1].data, EventData::ProcessTerminate(_)));
        // Terminate of an unrelated pid is not delayed.
        let out = m.process(vec![stop(55)], t0);
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn held_creates_are_bounded() {
        let t0 = Instant::now();
        let mut m = ProcessCreateMerger::new();
        let batch: Vec<_> = (0..(HELD_CAP as i32 + 5))
            .map(|p| precise(p + 1, ""))
            .collect();
        let out = m.process(batch, t0);
        assert_eq!(creates(&out).len(), 5);
        assert_eq!(m.held.len(), HELD_CAP);
    }

    #[test]
    fn audit_record_from_another_time_is_not_merged() {
        // Same pid, parent and image, but logged 30 s after the held
        // generation was created: a recycled pid, not this process.
        let t0 = Instant::now();
        let mut m = ProcessCreateMerger::new();
        assert!(m.process(vec![precise(7, "")], t0).is_empty());
        let mut late = audit_at(7, "certutil -decode a b");
        late.timestamp = created(7) + chrono::Duration::seconds(30);
        let out = m.process(vec![late], t0);
        assert_eq!(creates(&out).len(), 1);
        let held = m.flush_all(t0);
        assert!(creates(&held)[0].cmdline.is_empty());
    }

    #[test]
    fn ambiguous_audit_record_stays_separate() {
        // Two held generations of the same pid/parent/image created within the
        // tolerance: the audit record cannot say which one it belongs to.
        let t0 = Instant::now();
        let mut m = ProcessCreateMerger::new();
        let a = precise(7, "");
        let mut b = precise(7, "");
        create_mut(&mut b).unwrap().process_start_time = Some(START + 7 + 5_000_000);
        assert!(m.process(vec![a, b], t0).is_empty());
        let out = m.process(vec![audit(7, "certutil x")], t0);
        assert_eq!(creates(&out).len(), 1);
        let held = m.flush_all(t0);
        assert_eq!(creates(&held).len(), 2);
        assert!(creates(&held).iter().all(|c| c.cmdline.is_empty()));
    }

    #[test]
    fn empty_security_record_keeps_the_create_waiting_for_sysmon() {
        let t0 = Instant::now();
        let mut m = ProcessCreateMerger::new();
        assert!(m.process(vec![precise(7, "")], t0).is_empty());
        // 4688 without command-line auditing: username only, still held.
        assert!(m.process(vec![audit(7, "")], t0).is_empty());
        assert!(m.next_deadline().is_some());
        let out = m.process(vec![audit(7, "certutil -urlcache x")], t0);
        let c = creates(&out);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].cmdline, "certutil -urlcache x");
        assert_eq!(c[0].username, r"DOM\alice");
    }

    #[test]
    fn forwarded_audit_record_does_not_hide_a_later_generation() {
        let t0 = Instant::now();
        let mut m = ProcessCreateMerger::new();
        assert_eq!(creates(&m.process(vec![audit(9, "x")], t0)).len(), 1);
        // pid 9 reused 20 s later, sensor report with its own creation time.
        let mut later = precise(9, "y");
        create_mut(&mut later).unwrap().process_start_time = Some(START + 9 + 200_000_000);
        assert_eq!(creates(&m.process(vec![later], t0)).len(), 1);
    }

    #[test]
    fn live_report_after_a_forwarded_audit_record_is_kept() {
        let t0 = Instant::now();
        let mut m = ProcessCreateMerger::new();
        assert_eq!(
            creates(&m.process(vec![audit(7, "certutil x")], t0)).len(),
            1
        );
        let out = m.process(vec![precise(7, "certutil x")], t0);
        let c = creates(&out);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].process_start_time, Some(START + 7));
        // A second audit record of the same process is still a duplicate.
        assert!(m.process(vec![audit(7, "certutil x")], t0).is_empty());
    }

    #[test]
    fn stops_follow_their_own_generation() {
        let t0 = Instant::now();
        let mut m = ProcessCreateMerger::new();
        let a = precise(7, "");
        let mut b = precise(7, "");
        create_mut(&mut b).unwrap().process_start_time = Some(START + 7 + 50_000_000);
        assert!(m.process(vec![a, stop(7), b, stop(7)], t0).is_empty());
        let out = m.flush_all(t0);
        let kinds: Vec<_> = out
            .iter()
            .map(|e| match &e.data {
                EventData::ProcessCreate(d) => {
                    format!("create {}", d.process_start_time.unwrap() - START)
                }
                EventData::ProcessTerminate(_) => "stop".to_string(),
                _ => "other".to_string(),
            })
            .collect();
        assert_eq!(kinds, ["create 7", "stop", "create 50000007", "stop"]);
    }

    #[test]
    fn unrelated_events_pass_through() {
        let t0 = Instant::now();
        let mut m = ProcessCreateMerger::new();
        let other = wrap(
            EventData::ProcessTerminate(ProcessTerminateData {
                pid: 1,
                name: "x".into(),
            }),
            EventAction::Terminate,
        );
        assert_eq!(m.process(vec![other], t0).len(), 1);
    }

    // --- No ETW: the poller and Security 4688 report the same processes. ---

    fn polling_merger() -> ProcessCreateMerger {
        let mut m = ProcessCreateMerger::new();
        m.set_audit_hold(true);
        m
    }

    /// What the poller produces: start time and digest, command line as read.
    fn polled(pid: i32, cmdline: &str) -> AgentEvent {
        let mut event = precise(pid, cmdline);
        create_mut(&mut event).unwrap().exe_sha256 = Some("ab".repeat(32));
        event
    }

    #[test]
    fn audit_first_then_poller_yields_one_event_with_everything() {
        let t0 = Instant::now();
        let mut m = polling_merger();
        assert!(m
            .process(vec![audit(7, "certutil -urlcache x")], t0)
            .is_empty());
        assert_eq!(m.next_deadline(), Some(t0 + AUDIT_GRACE));
        // The poller sees it empty-handed: 4688 completes it.
        let out = m.process(vec![polled(7, "")], t0 + Duration::from_secs(2));
        let c = creates(&out);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].process_start_time, Some(START + 7));
        assert_eq!(c[0].exe_sha256.as_deref(), Some("ab".repeat(32).as_str()));
        assert_eq!(c[0].cmdline, "certutil -urlcache x");
        assert_eq!(c[0].username, r"DOM\alice");
        assert!(c[0].enrichment.enrichment_errors.is_empty());
        assert!(m.next_deadline().is_none());
        // Nothing is left to be released later.
        assert!(m.flush_all(t0 + AUDIT_GRACE).is_empty());
    }

    #[test]
    fn audit_first_then_poller_with_command_line_keeps_the_sensor_values() {
        let t0 = Instant::now();
        let mut m = polling_merger();
        assert!(m.process(vec![audit(7, "from 4688")], t0).is_empty());
        let out = m.process(vec![polled(7, "from poller")], t0);
        let c = creates(&out);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].cmdline, "from poller");
        assert_eq!(c[0].process_start_time, Some(START + 7));
        assert!(c[0].exe_sha256.is_some());
    }

    #[test]
    fn poller_first_then_audit_yields_one_event() {
        let t0 = Instant::now();
        let mut m = polling_merger();
        let out = m.process(vec![polled(7, "certutil x")], t0);
        assert_eq!(creates(&out).len(), 1);
        assert!(m.process(vec![audit(7, "certutil x")], t0).is_empty());
        assert!(m.flush_all(t0 + AUDIT_GRACE).is_empty());
    }

    #[test]
    fn poller_without_command_line_is_completed_by_a_later_audit_record() {
        let t0 = Instant::now();
        let mut m = polling_merger();
        assert!(m.process(vec![polled(7, "")], t0).is_empty());
        let out = m.process(vec![audit(7, "certutil x")], t0 + Duration::from_secs(4));
        let c = creates(&out);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].cmdline, "certutil x");
        assert!(c[0].exe_sha256.is_some());
    }

    #[test]
    fn short_lived_process_seen_only_by_4688_is_forwarded_without_start_time() {
        let t0 = Instant::now();
        let mut m = polling_merger();
        assert!(m.process(vec![audit(7, "mshta x")], t0).is_empty());
        assert!(m
            .flush_due(t0 + AUDIT_GRACE - Duration::from_millis(1))
            .is_empty());
        let out = m.flush_due(t0 + AUDIT_GRACE);
        let c = creates(&out);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].cmdline, "mshta x");
        assert_eq!(c[0].process_start_time, None);
        assert!(c[0].exe_sha256.is_none());
    }

    #[test]
    fn poller_only_create_is_forwarded() {
        let t0 = Instant::now();
        let mut m = polling_merger();
        let out = m.process(vec![polled(7, "notepad")], t0);
        let c = creates(&out);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].process_start_time, Some(START + 7));
        assert!(m.next_deadline().is_none());
    }

    #[test]
    fn audit_creates_are_not_held_while_etw_is_the_sensor() {
        let t0 = Instant::now();
        let mut m = ProcessCreateMerger::new();
        assert_eq!(creates(&m.process(vec![audit(7, "x")], t0)).len(), 1);
    }

    #[test]
    fn recycled_pid_within_tolerance_with_another_start_time_is_not_merged() {
        let t0 = Instant::now();
        let mut m = polling_merger();
        // Generation A was seen by the poller; generation B of the same pid
        // started 1 s later (inside the tolerance) with another FILETIME.
        assert_eq!(creates(&m.process(vec![polled(7, "a")], t0)).len(), 1);
        let mut b = polled(7, "b");
        create_mut(&mut b).unwrap().process_start_time = Some(START + 7 + 10_000_000);
        let out = m.process(vec![b], t0);
        let c = creates(&out);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].cmdline, "b");
        // Held audit record fitting both generations merges with neither.
        let mut m = polling_merger();
        let mut b = polled(7, "b");
        create_mut(&mut b).unwrap().process_start_time = Some(START + 7 + 10_000_000);
        assert_eq!(creates(&m.process(vec![polled(7, "a"), b], t0)).len(), 2);
        assert!(m.process(vec![audit(7, "x")], t0).is_empty());
        let out = m.flush_all(t0);
        let c = creates(&out);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].process_start_time, None);
    }

    #[test]
    fn sysmon_record_completes_a_held_audit_record_without_releasing_it() {
        let t0 = Instant::now();
        let mut m = polling_merger();
        assert!(m.process(vec![audit(7, "")], t0).is_empty());
        assert!(m.process(vec![audit(7, "certutil x")], t0).is_empty());
        let out = m.process(vec![polled(7, "")], t0);
        let c = creates(&out);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].cmdline, "certutil x");
        assert_eq!(c[0].process_start_time, Some(START + 7));
    }

    #[test]
    fn terminate_waits_behind_a_held_audit_create() {
        let t0 = Instant::now();
        let mut m = polling_merger();
        assert!(m.process(vec![audit(7, "x"), stop(7)], t0).is_empty());
        let out = m.process(vec![polled(7, "x")], t0);
        assert_eq!(out.len(), 2);
        assert!(matches!(out[0].data, EventData::ProcessCreate(_)));
        assert!(matches!(out[1].data, EventData::ProcessTerminate(_)));
    }

    #[test]
    fn late_poller_report_after_the_grace_is_not_suppressed_by_the_audit_create() {
        let t0 = Instant::now();
        let mut m = polling_merger();
        assert!(m.process(vec![audit(7, "x")], t0).is_empty());
        assert_eq!(creates(&m.flush_due(t0 + AUDIT_GRACE)).len(), 1);
        let out = m.process(vec![polled(7, "x")], t0 + AUDIT_GRACE);
        assert_eq!(creates(&out).len(), 1);
    }
}
