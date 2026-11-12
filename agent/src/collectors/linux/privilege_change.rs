//! Privilege-escalation detection on top of the eBPF `setuid` sensor.
//!
//! The kernel hook fires on *syscall entry* with the **requested** uid, so on
//! its own it cannot tell a successful `setuid(0)` from an `EPERM`. This module
//! turns a candidate (real uid != 0, requested effective uid 0) into a
//! `process/privilege_change` event only after the result is observable in
//! `/proc/<pid>/status` (`Uid:` shows effective uid 0).
//!
//! Identity is `(pid, process_start_time)`. The start time is read before and
//! after verification and must be present and equal, otherwise the candidate is
//! unprovable (a recycled PID could otherwise be blamed) and is counted as a
//! drop instead of being emitted with a guessed identity.
//!
//! Bounds: events are deduplicated per process generation and rate limited;
//! both shed paths are counted as `rate_limit_applied`.
//!
//! Known limitation: the hook only sees the *real* uid before the call, not the
//! old effective uid. A setuid-root binary (already euid 0) calling `setuid(0)`
//! is therefore reported; `setuid_binary` lets consumers filter it.

use std::collections::HashMap;
use std::os::unix::fs::MetadataExt;
use std::time::{Duration, Instant};

use crate::schema::PrivilegeChangeData;

/// How long a process generation stays deduplicated after an emitted event.
const DEDUP_TTL: Duration = Duration::from_secs(600);
/// Hard cap on tracked generations; a full table sheds new candidates.
const MAX_TRACKED: usize = 4096;
/// Admissions allowed per rate window.
const RATE_MAX: u32 = 30;
const RATE_WINDOW: Duration = Duration::from_secs(10);

/// Verification polls: the tracepoint fires before the syscall completes.
pub const VERIFY_ATTEMPTS: u32 = 4;
pub const VERIFY_DELAY: Duration = Duration::from_millis(15);

/// Whether a raw setuid record is worth verifying: a non-root real uid asks for
/// effective uid 0. `u32::MAX` (`-1`, "leave unchanged") never equals 0.
pub fn is_candidate(old_uid: u32, requested_euid: u32) -> bool {
    old_uid != 0 && requested_euid == 0
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    Admit,
    /// Same process generation already reported or in flight.
    Duplicate,
    RateLimited,
    TableFull,
}

#[derive(Debug)]
pub struct Tracker {
    seen: HashMap<(i32, u64), Instant>,
    window_start: Option<Instant>,
    window_count: u32,
}

impl Default for Tracker {
    fn default() -> Self {
        Self::new()
    }
}

impl Tracker {
    pub fn new() -> Self {
        Self {
            seen: HashMap::new(),
            window_start: None,
            window_count: 0,
        }
    }

    /// Decide whether a candidate for this process generation may be verified.
    /// An admitted key is held (in flight) until [`Self::release`] or its TTL.
    pub fn admit(&mut self, pid: i32, start_time: u64, now: Instant) -> Admission {
        let key = (pid, start_time);
        if let Some(t) = self.seen.get(&key) {
            if now.duration_since(*t) < DEDUP_TTL {
                return Admission::Duplicate;
            }
        }
        match self.window_start {
            Some(s) if now.duration_since(s) < RATE_WINDOW => {}
            _ => {
                self.window_start = Some(now);
                self.window_count = 0;
            }
        }
        if self.window_count >= RATE_MAX {
            return Admission::RateLimited;
        }
        if self.seen.len() >= MAX_TRACKED {
            self.seen.retain(|_, t| now.duration_since(*t) < DEDUP_TTL);
            if self.seen.len() >= MAX_TRACKED && !self.seen.contains_key(&key) {
                return Admission::TableFull;
            }
        }
        self.window_count += 1;
        self.seen.insert(key, now);
        Admission::Admit
    }

    /// Forget an admitted key whose verification did not produce an event, so a
    /// later real escalation of the same generation is still reported.
    pub fn release(&mut self, pid: i32, start_time: u64) {
        self.seen.remove(&(pid, start_time));
    }
}

/// Fields of `/proc/<pid>/status` this module needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcStatus {
    pub ppid: i32,
    pub ruid: u32,
    pub euid: u32,
    pub suid: u32,
}

pub fn parse_status(text: &str) -> Option<ProcStatus> {
    let mut ppid = None;
    let mut uids = None;
    for line in text.lines() {
        if let Some(v) = line.strip_prefix("PPid:") {
            ppid = v.trim().parse::<i32>().ok();
        } else if let Some(v) = line.strip_prefix("Uid:") {
            let mut it = v.split_whitespace().map(|x| x.parse::<u32>().ok());
            uids = Some((it.next()??, it.next()??, it.next()??));
        }
    }
    let (ruid, euid, suid) = uids?;
    Some(ProcStatus {
        ppid: ppid?,
        ruid,
        euid,
        suid,
    })
}

/// Read access to a process; abstracted so verification is testable.
pub trait ProcSource {
    fn start_time(&self, pid: i32) -> Option<u64>;
    fn status(&self, pid: i32) -> Option<ProcStatus>;
    fn exe(&self, pid: i32) -> Option<String>;
    fn exe_is_setuid_root(&self, pid: i32) -> bool;
}

pub struct RealProc;

impl ProcSource for RealProc {
    fn start_time(&self, pid: i32) -> Option<u64> {
        crate::telemetry::identity::process_start_time(pid)
    }
    fn status(&self, pid: i32) -> Option<ProcStatus> {
        parse_status(&std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?)
    }
    fn exe(&self, pid: i32) -> Option<String> {
        std::fs::read_link(format!("/proc/{pid}/exe"))
            .ok()
            .map(|p| p.to_string_lossy().into_owned())
    }
    fn exe_is_setuid_root(&self, pid: i32) -> bool {
        std::fs::metadata(format!("/proc/{pid}/exe"))
            .map(|m| m.mode() & 0o4000 != 0 && m.uid() == 0)
            .unwrap_or(false)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Effective uid 0 observed on a provably unchanged process generation.
    Escalated(PrivilegeChangeData),
    /// The process is alive and not euid 0 (the syscall failed or has not
    /// completed): not an event.
    NotEscalated,
    /// Identity could not be proven (process gone, start time changed).
    Unprovable,
}

/// One verification pass. `start_before` is the start time captured at admission.
pub fn verify(
    src: &dyn ProcSource,
    pid: i32,
    start_before: u64,
    old_uid: u32,
    comm: &str,
) -> Verdict {
    let Some(status) = src.status(pid) else {
        return Verdict::Unprovable;
    };
    if status.euid != 0 {
        // Still alive with the same identity? Otherwise it is unprovable.
        return if src.start_time(pid) == Some(start_before) {
            Verdict::NotEscalated
        } else {
            Verdict::Unprovable
        };
    }
    let exe = src.exe(pid);
    let setuid_binary = src.exe_is_setuid_root(pid);
    if src.start_time(pid) != Some(start_before) {
        return Verdict::Unprovable;
    }
    Verdict::Escalated(PrivilegeChangeData {
        pid,
        process_start_time: Some(start_before),
        ppid: Some(status.ppid),
        exe,
        comm: comm.to_string(),
        old_uid,
        new_uid: status.ruid,
        new_euid: status.euid,
        new_suid: Some(status.suid),
        setuid_binary,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    struct Fake {
        start: RefCell<Vec<Option<u64>>>,
        status: Option<ProcStatus>,
    }
    impl ProcSource for Fake {
        fn start_time(&self, _: i32) -> Option<u64> {
            let mut s = self.start.borrow_mut();
            if s.len() > 1 {
                s.remove(0)
            } else {
                s[0]
            }
        }
        fn status(&self, _: i32) -> Option<ProcStatus> {
            self.status
        }
        fn exe(&self, _: i32) -> Option<String> {
            Some("/tmp/x".into())
        }
        fn exe_is_setuid_root(&self, _: i32) -> bool {
            false
        }
    }
    fn st(euid: u32) -> Option<ProcStatus> {
        Some(ProcStatus {
            ppid: 7,
            ruid: euid,
            euid,
            suid: euid,
        })
    }

    #[test]
    fn decodes_status() {
        let t = "Name:\tx\nPPid:\t42\nUid:\t1000\t0\t0\t0\nGid:\t1\t1\t1\t1\n";
        assert_eq!(
            parse_status(t),
            Some(ProcStatus {
                ppid: 42,
                ruid: 1000,
                euid: 0,
                suid: 0
            })
        );
        assert_eq!(parse_status("Name:\tx\n"), None);
        assert_eq!(parse_status("PPid:\t1\nUid:\tx\ty\tz\n"), None);
        assert_eq!(parse_status("PPid:\t1\nUid:\t1\t2\n"), None);
    }

    #[test]
    fn candidate_rules() {
        assert!(is_candidate(1000, 0));
        assert!(!is_candidate(0, 0));
        assert!(!is_candidate(1000, u32::MAX));
        assert!(!is_candidate(1000, 33));
    }

    #[test]
    fn dedups_per_generation_but_not_across_pid_reuse() {
        let mut t = Tracker::new();
        let now = Instant::now();
        assert_eq!(t.admit(10, 100, now), Admission::Admit);
        assert_eq!(t.admit(10, 100, now), Admission::Duplicate);
        assert_eq!(t.admit(10, 200, now), Admission::Admit, "new generation");
        t.release(10, 100);
        assert_eq!(t.admit(10, 100, now), Admission::Admit);
        assert_eq!(
            t.admit(10, 100, now + DEDUP_TTL + Duration::from_secs(1)),
            Admission::Admit
        );
    }

    #[test]
    fn rate_limit_sheds_and_recovers() {
        let mut t = Tracker::new();
        let now = Instant::now();
        for i in 0..RATE_MAX {
            assert_eq!(t.admit(i as i32 + 1, 1, now), Admission::Admit);
        }
        assert_eq!(t.admit(999, 1, now), Admission::RateLimited);
        assert_eq!(
            t.admit(999, 1, now + RATE_WINDOW + Duration::from_millis(1)),
            Admission::Admit
        );
    }

    #[test]
    fn table_is_bounded() {
        let mut t = Tracker::new();
        let now = Instant::now();
        for i in 0..MAX_TRACKED as i32 {
            t.seen.insert((i + 1, 1), now);
        }
        assert_eq!(
            t.admit(MAX_TRACKED as i32 + 5, 1, now),
            Admission::TableFull
        );
        // Once entries expire the table makes room again.
        assert_eq!(
            t.admit(
                MAX_TRACKED as i32 + 5,
                1,
                now + DEDUP_TTL + Duration::from_secs(1)
            ),
            Admission::Admit
        );
        assert!(t.seen.len() <= MAX_TRACKED);
    }

    #[test]
    fn verified_escalation_carries_identity() {
        let f = Fake {
            start: RefCell::new(vec![Some(55)]),
            status: st(0),
        };
        match verify(&f, 9, 55, 1000, "x") {
            Verdict::Escalated(d) => {
                assert_eq!(d.process_start_time, Some(55));
                assert_eq!((d.old_uid, d.new_euid, d.ppid), (1000, 0, Some(7)));
                assert_eq!(d.exe.as_deref(), Some("/tmp/x"));
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn failed_syscall_is_not_an_event() {
        let f = Fake {
            start: RefCell::new(vec![Some(55)]),
            status: st(1000),
        };
        assert_eq!(verify(&f, 9, 55, 1000, "x"), Verdict::NotEscalated);
    }

    #[test]
    fn exited_or_recycled_process_is_unprovable() {
        let gone = Fake {
            start: RefCell::new(vec![None]),
            status: None,
        };
        assert_eq!(verify(&gone, 9, 55, 1000, "x"), Verdict::Unprovable);
        let recycled = Fake {
            start: RefCell::new(vec![Some(99)]),
            status: st(0),
        };
        assert_eq!(verify(&recycled, 9, 55, 1000, "x"), Verdict::Unprovable);
        let no_start = Fake {
            start: RefCell::new(vec![None]),
            status: st(0),
        };
        assert_eq!(verify(&no_start, 9, 55, 1000, "x"), Verdict::Unprovable);
    }
}
