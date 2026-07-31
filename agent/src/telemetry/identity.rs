//! Event and process identity.
//!
//! Two distinct identity problems live here.
//!
//! **Event identity** — an event must be recognisable as *the same event* after
//! a retry, a queue recovery or an agent restart, so the backend can dedupe it
//! idempotently.  That is the `event_id` (assigned once, at creation, and never
//! regenerated) plus the [`EventOrigin`] provenance block: which agent, which
//! boot, and where in that boot's ordered stream the event sits.
//!
//! **Process identity** — a PID is not an identifier.  The kernel reuses PIDs,
//! so `pid=1234` observed twice can be two unrelated processes, and correlating
//! them would fabricate a process lineage that never existed.  The stable key is
//! `(boot_id, pid, start_time)`, where `start_time` is the process's start time
//! in clock ticks since boot from field 22 of `/proc/<pid>/stat` — assigned by
//! the kernel and immutable for the life of the process.  [`ProcessKey`] is that
//! triple.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};

/// Monotonically increasing per-agent-run event sequence.
static SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Next sequence number for this agent run.
///
/// Sequence numbers start at 1 and increase by exactly one per event, so a gap
/// in the numbers the backend receives is direct evidence of loss — and the
/// pair `(boot_id, sequence)` says exactly *which* events went missing.  They
/// are per-run, not per-collector, which makes them totally ordered.
pub fn next_sequence() -> u64 {
    SEQUENCE.fetch_add(1, Ordering::Relaxed) + 1
}

/// Sequence numbers issued so far this run.
pub fn issued_sequences() -> u64 {
    SEQUENCE.load(Ordering::Relaxed)
}

/// Identifier of the current *system boot*.
///
/// On Linux this is the kernel's `/proc/sys/kernel/random/boot_id`, which is
/// regenerated on every boot and shared by every process — so an agent restart
/// keeps the same `boot_id`, while a reboot changes it.  That distinction is
/// what makes `(boot_id, pid, start_time)` a sound process key: PIDs and
/// start-times are only comparable within one boot.
///
/// If the kernel file is unreadable (non-Linux, or a restricted container) a
/// random per-process UUID is used instead.  That is strictly weaker — it
/// changes on agent restart — so process keys minted before and after a restart
/// will not compare equal.  The failure mode is a lost correlation, never a
/// false one, which is the safe direction.
pub fn boot_id() -> &'static str {
    static BOOT_ID: OnceLock<String> = OnceLock::new();
    BOOT_ID.get_or_init(|| {
        #[cfg(target_os = "linux")]
        {
            if let Ok(s) = std::fs::read_to_string("/proc/sys/kernel/random/boot_id") {
                let t = s.trim();
                if !t.is_empty() {
                    return t.to_string();
                }
            }
        }
        uuid::Uuid::new_v4().to_string()
    })
}

/// Nanoseconds on a monotonic clock that no wall-clock adjustment can move.
///
/// On Linux this is `CLOCK_MONOTONIC`, the same base as the kernel's
/// `bpf_ktime_get_ns()`, so a userspace timestamp is directly comparable with
/// one taken inside an eBPF program.  Elsewhere it is nanoseconds since the
/// agent's own start.
///
/// Wall-clock timestamps alone cannot order events: NTP steps and manual clock
/// changes make `timestamp` non-monotonic and can even run it backwards.  This
/// field is what keeps ordering and latency arithmetic correct across a clock
/// jump.
pub fn monotonic_ns() -> u64 {
    #[cfg(target_os = "linux")]
    {
        let mut ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: `ts` is a valid, correctly-typed out-parameter and
        // CLOCK_MONOTONIC is always available on Linux.
        if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) } == 0 {
            return (ts.tv_sec as u64)
                .saturating_mul(1_000_000_000)
                .saturating_add(ts.tv_nsec as u64);
        }
    }
    static START: OnceLock<std::time::Instant> = OnceLock::new();
    START.get_or_init(std::time::Instant::now).elapsed().as_nanos() as u64
}

/// Provenance stamped on every event.
///
/// Carried alongside `event_id` so a receiver can reconstruct the agent's
/// ordered event stream, detect gaps, and reason about timing without trusting
/// the wall clock.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventOrigin {
    /// System boot this event belongs to; scopes `sequence` and every
    /// [`ProcessKey`].
    pub boot_id: String,
    /// Position in this run's totally-ordered event stream, starting at 1.
    pub sequence_number: u64,
    /// Monotonic clock reading at event creation, in nanoseconds.
    pub monotonic_timestamp_ns: u64,
    /// Collector that produced the event (`ebpf_exec`, `proc_poll`, …).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

impl EventOrigin {
    /// Stamp a new origin, consuming the next sequence number.
    pub fn new(source: impl Into<String>) -> Self {
        Self {
            source: Some(source.into()),
            ..Self::unsourced()
        }
    }

    /// Stamp an origin without naming a source; the collector fills it in via
    /// [`crate::schema::AgentEvent::from_source`].
    pub fn unsourced() -> Self {
        Self {
            boot_id: boot_id().to_string(),
            sequence_number: next_sequence(),
            monotonic_timestamp_ns: monotonic_ns(),
            source: None,
        }
    }
}

/// Stable identity of a running process: `(boot_id, pid, start_time)`.
///
/// `start_time` is field 22 of `/proc/<pid>/stat` — the process's start time in
/// clock ticks since boot.  Two processes in the same boot cannot share both a
/// PID and a start time, so this triple survives PID reuse where a bare PID
/// does not.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProcessKey {
    pub boot_id: String,
    pub pid: i32,
    /// `None` when the process exited before `/proc` could be read.  A key
    /// without a start time is deliberately **not** treated as equal to any
    /// other key for the same PID — see [`ProcessKey::same_process_as`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_time: Option<u64>,
}

impl ProcessKey {
    /// Resolve the key for `pid` by reading its start time from `/proc`.
    pub fn resolve(pid: i32) -> Self {
        Self {
            boot_id: boot_id().to_string(),
            pid,
            start_time: process_start_time(pid),
        }
    }

    /// Build a key from an already-known start time (no `/proc` read).
    pub fn new(pid: i32, start_time: Option<u64>) -> Self {
        Self {
            boot_id: boot_id().to_string(),
            pid,
            start_time,
        }
    }

    /// Whether both keys provably denote the same process.
    ///
    /// Requires the boot, the PID **and** the start time to match.  If either
    /// side is missing a start time the answer is `false`: an unproven match is
    /// reported as "different", because wrongly merging two processes fabricates
    /// a lineage, while wrongly splitting one only loses a correlation.
    pub fn same_process_as(&self, other: &ProcessKey) -> bool {
        self.boot_id == other.boot_id
            && self.pid == other.pid
            && match (self.start_time, other.start_time) {
                (Some(a), Some(b)) => a == b,
                _ => false,
            }
    }

    /// Whether both keys provably denote *different* processes sharing a PID —
    /// i.e. the PID was recycled between two observations.
    ///
    /// This is deliberately **not** the negation of [`Self::same_process_as`].
    /// Identity here is three-valued — same, different, or unknown — and both
    /// methods answer `false` for "unknown". Treating "unknown" as *different*
    /// would invent a terminate/create pair for every process whose start time
    /// could not be read; treating it as *same* would merge unrelated
    /// processes. Requiring proof in each direction is what keeps both errors
    /// out.
    pub fn provably_different_from(&self, other: &ProcessKey) -> bool {
        if self.boot_id != other.boot_id || self.pid != other.pid {
            return false; // Different PIDs are not a reuse question at all.
        }
        match (self.start_time, other.start_time) {
            (Some(a), Some(b)) => a != b,
            _ => false,
        }
    }
}

/// Start time of `pid` in clock ticks since boot (field 22 of `/proc/<pid>/stat`).
///
/// The `comm` field can contain spaces and parentheses, so the fields after it
/// are located by scanning to the **last** `')'` rather than splitting on
/// whitespace from the left.
pub fn process_start_time(pid: i32) -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        parse_start_time(&stat)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = pid;
        None
    }
}

/// Extract field 22 (`starttime`) from a `/proc/<pid>/stat` line.
pub fn parse_start_time(stat: &str) -> Option<u64> {
    // Fields: pid (comm) state ppid ... starttime is the 22nd overall, i.e. the
    // 20th after the closing paren of `comm`.
    let close = stat.rfind(')')?;
    let rest = stat.get(close + 1..)?;
    rest.split_whitespace().nth(19)?.parse::<u64>().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sequences_are_strictly_increasing() {
        let a = next_sequence();
        let b = next_sequence();
        let c = next_sequence();
        assert!(a < b && b < c, "sequence must be strictly increasing");
        assert_eq!(b, a + 1);
        assert_eq!(c, b + 1);
    }

    #[test]
    fn sequences_are_unique_across_threads() {
        // Gap detection depends on the counter never handing out a duplicate.
        let handles: Vec<_> = (0..8)
            .map(|_| std::thread::spawn(|| (0..500).map(|_| next_sequence()).collect::<Vec<_>>()))
            .collect();
        let mut all: Vec<u64> = handles.into_iter().flat_map(|h| h.join().unwrap()).collect();
        let total = all.len();
        all.sort_unstable();
        all.dedup();
        assert_eq!(all.len(), total, "sequence numbers must never repeat");
    }

    #[test]
    fn boot_id_is_stable_within_a_run() {
        assert_eq!(boot_id(), boot_id());
        assert!(!boot_id().is_empty());
    }

    #[test]
    fn monotonic_clock_never_goes_backwards() {
        let mut prev = monotonic_ns();
        for _ in 0..1_000 {
            let now = monotonic_ns();
            assert!(now >= prev, "monotonic clock went backwards");
            prev = now;
        }
    }

    #[test]
    fn origin_carries_boot_sequence_and_clock() {
        let o = EventOrigin::new("ebpf_exec");
        assert_eq!(o.boot_id, boot_id());
        assert!(o.sequence_number > 0);
        assert!(o.monotonic_timestamp_ns > 0);
        assert_eq!(o.source.as_deref(), Some("ebpf_exec"));
    }

    #[test]
    fn origin_round_trips_through_json() {
        let o = EventOrigin::new("proc_poll");
        let back: EventOrigin = serde_json::from_str(&serde_json::to_string(&o).unwrap()).unwrap();
        assert_eq!(o, back);
    }

    // ── /proc/<pid>/stat parsing ────────────────────────────────────────────

    /// Build a synthetic stat line whose 22nd field is `starttime`.
    fn stat_line(comm: &str, starttime: u64) -> String {
        let mut s = format!("1234 ({comm}) S 1");
        // Fields 5..=21 (17 more) before starttime at 22.
        for i in 0..17 {
            s.push_str(&format!(" {i}"));
        }
        s.push_str(&format!(" {starttime}"));
        s.push_str(" 4096 0 18446744073709551615");
        s
    }

    #[test]
    fn parses_start_time_from_a_plain_stat_line() {
        assert_eq!(parse_start_time(&stat_line("bash", 987_654)), Some(987_654));
    }

    #[test]
    fn parses_start_time_when_comm_contains_spaces_and_parens() {
        // A process can rename itself to almost anything; splitting on
        // whitespace from the left would shift every field after `comm`.
        assert_eq!(
            parse_start_time(&stat_line("evil ) proc (x", 42)),
            Some(42),
            "must scan to the LAST ')' to survive a hostile comm"
        );
    }

    #[test]
    fn malformed_stat_lines_return_none_instead_of_panicking() {
        for bad in [
            "",
            "no parens here",
            "1234 (bash) S",
            "1234 (bash)",
            ")",
            "1234 (bash) S 1 2 3 notanumber",
        ] {
            assert_eq!(parse_start_time(bad), None, "input {bad:?} must not parse");
        }
    }

    #[test]
    fn real_self_stat_parses_on_linux() {
        #[cfg(target_os = "linux")]
        {
            let pid = std::process::id() as i32;
            let start = process_start_time(pid);
            assert!(start.is_some(), "our own start time must be readable");
            assert_eq!(start, process_start_time(pid), "must be stable");
        }
    }

    // ── PID reuse ───────────────────────────────────────────────────────────

    #[test]
    fn same_pid_with_different_start_time_is_a_different_process() {
        let first = ProcessKey::new(4242, Some(100));
        let recycled = ProcessKey::new(4242, Some(900));
        assert!(
            !first.same_process_as(&recycled),
            "PID reuse must not be mistaken for process identity"
        );
        assert!(
            first.provably_different_from(&recycled),
            "and the reuse must be positively detectable"
        );
    }

    #[test]
    fn identity_is_three_valued_not_boolean() {
        // "same" and "different" both require proof; neither is the negation of
        // the other, because "unknown" must not silently become either one.
        let unknown_a = ProcessKey::new(7, None);
        let unknown_b = ProcessKey::new(7, None);
        assert!(!unknown_a.same_process_as(&unknown_b));
        assert!(!unknown_a.provably_different_from(&unknown_b));

        let known = ProcessKey::new(7, Some(1));
        assert!(!known.same_process_as(&unknown_a));
        assert!(!known.provably_different_from(&unknown_a));
    }

    #[test]
    fn different_pids_are_not_a_reuse_question() {
        let a = ProcessKey::new(1, Some(10));
        let b = ProcessKey::new(2, Some(20));
        assert!(
            !a.provably_different_from(&b),
            "reuse only applies to a shared PID"
        );
    }

    #[test]
    fn same_process_and_provably_different_are_mutually_exclusive() {
        for (sa, sb) in [
            (Some(1u64), Some(1u64)),
            (Some(1), Some(2)),
            (Some(1), None),
            (None, None),
        ] {
            let a = ProcessKey::new(5, sa);
            let b = ProcessKey::new(5, sb);
            assert!(
                !(a.same_process_as(&b) && a.provably_different_from(&b)),
                "a key pair cannot be both the same and provably different ({sa:?}, {sb:?})"
            );
        }
    }

    #[test]
    fn same_pid_and_start_time_is_the_same_process() {
        let a = ProcessKey::new(4242, Some(100));
        let b = ProcessKey::new(4242, Some(100));
        assert!(a.same_process_as(&b));
    }

    #[test]
    fn missing_start_time_never_claims_a_match() {
        let known = ProcessKey::new(7, Some(5));
        let unknown = ProcessKey::new(7, None);
        assert!(!known.same_process_as(&unknown));
        assert!(!unknown.same_process_as(&known));
        assert!(
            !unknown.same_process_as(&ProcessKey::new(7, None)),
            "two unproven keys must not be merged either"
        );
    }

    #[test]
    fn keys_from_different_boots_never_match() {
        let a = ProcessKey {
            boot_id: "boot-a".into(),
            pid: 1,
            start_time: Some(1),
        };
        let b = ProcessKey {
            boot_id: "boot-b".into(),
            pid: 1,
            start_time: Some(1),
        };
        assert!(!a.same_process_as(&b));
    }

    #[test]
    fn process_key_round_trips_through_json() {
        let k = ProcessKey::new(99, Some(12345));
        let back: ProcessKey = serde_json::from_str(&serde_json::to_string(&k).unwrap()).unwrap();
        assert_eq!(k, back);
        assert!(k.same_process_as(&back));
    }
}
