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

use std::sync::OnceLock;

use serde::{Deserialize, Serialize};

pub use trapd_schema::{EventOrigin};
pub use trapd_schema::runtime::issued_sequences;

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
    START
        .get_or_init(std::time::Instant::now)
        .elapsed()
        .as_nanos() as u64
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
    #[cfg(windows)]
    {
        use windows_sys::Win32::Foundation::{CloseHandle, FILETIME};
        use windows_sys::Win32::System::Threading::{
            GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
        };
        if pid <= 0 {
            return None;
        }
        // SAFETY: the owned process handle is closed on all paths; all FILETIME
        // out-parameters point to initialized storage. No process mutation.
        unsafe {
            let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid as u32);
            if handle.is_null() {
                return None;
            }
            let mut created = FILETIME::default();
            let mut exited = FILETIME::default();
            let mut kernel = FILETIME::default();
            let mut user = FILETIME::default();
            let ok = GetProcessTimes(handle, &mut created, &mut exited, &mut kernel, &mut user);
            CloseHandle(handle);
            (ok != 0)
                .then_some(((created.dwHighDateTime as u64) << 32) | created.dwLowDateTime as u64)
        }
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        let _ = pid;
        None
    }
}

/// A parent PID still visible at collection may have been reused after the
/// child's creation. Only bind a candidate generation demonstrably older
/// than the child; missing, zero or equal timestamps remain unknown.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn parent_generation_before_child(child: Option<u64>, parent: Option<u64>) -> Option<u64> {
    let child = child.filter(|start| *start > 0)?;
    parent.filter(|start| *start > 0 && *start < child)
}

/// Qualified account identity prevents local/domain accounts sharing a baseline.
#[cfg(windows)]
pub fn windows_process_account(pid: i32) -> Option<String> {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::Security::{GetTokenInformation, TokenUser, TOKEN_QUERY, TOKEN_USER};
    use windows_sys::Win32::System::Threading::{
        OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
    };
    if pid <= 0 {
        return None;
    }
    unsafe {
        let process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid as u32);
        if process.is_null() {
            return None;
        }
        let mut token = std::ptr::null_mut();
        let opened = OpenProcessToken(process, TOKEN_QUERY, &mut token);
        CloseHandle(process);
        if opened == 0 {
            return None;
        }
        let mut bytes = 0;
        GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut bytes);
        if bytes < std::mem::size_of::<TOKEN_USER>() as u32 || bytes > 65_536 {
            CloseHandle(token);
            return None;
        }
        let mut buffer = vec![0u64; (bytes as usize).div_ceil(8)];
        let ok = GetTokenInformation(
            token,
            TokenUser,
            buffer.as_mut_ptr().cast(),
            bytes,
            &mut bytes,
        );
        CloseHandle(token);
        if ok == 0 {
            return None;
        }
        let sid = (*(buffer.as_ptr().cast::<TOKEN_USER>())).User.Sid;
        qualified_sid_account(sid)
    }
}

#[cfg(windows)]
unsafe fn qualified_sid_account(sid: windows_sys::Win32::Security::PSID) -> Option<String> {
    use windows_sys::Win32::Security::LookupAccountSidW;
    let mut name = [0u16; 1024];
    let mut domain = [0u16; 1024];
    let mut n = name.len() as u32;
    let mut d = domain.len() as u32;
    let mut usage = 0;
    if LookupAccountSidW(
        std::ptr::null(),
        sid,
        name.as_mut_ptr(),
        &mut n,
        domain.as_mut_ptr(),
        &mut d,
        &mut usage,
    ) == 0
        || n == 0
        || d == 0
    {
        return None;
    }
    Some(format!(
        "{}\\{}",
        String::from_utf16(&domain[..d as usize]).ok()?,
        String::from_utf16(&name[..n as usize]).ok()?
    ))
}

#[cfg(windows)]
pub fn windows_sid_account(sid: &str) -> Option<String> {
    use windows_sys::Win32::Security::Authorization::ConvertStringSidToSidW;
    let wide: Vec<u16> = sid.encode_utf16().chain(Some(0)).collect();
    unsafe {
        let mut native = std::ptr::null_mut();
        if ConvertStringSidToSidW(wide.as_ptr(), &mut native) == 0 {
            return None;
        }
        let result = qualified_sid_account(native);
        windows_sys::Win32::Foundation::LocalFree(native.cast());
        result
    }
}

#[cfg(windows)]
pub fn windows_process_image(pid: i32) -> Option<String> {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION,
    };
    if pid <= 0 {
        return None;
    }
    unsafe {
        let process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid as u32);
        if process.is_null() {
            return None;
        }
        let mut image = vec![0u16; 32_768];
        let mut size = image.len() as u32;
        let ok = QueryFullProcessImageNameW(process, 0, image.as_mut_ptr(), &mut size);
        CloseHandle(process);
        (ok != 0)
            .then(|| String::from_utf16(&image[..size as usize]).ok())
            .flatten()
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
    fn parent_generation_must_predate_the_child() {
        assert_eq!(parent_generation_before_child(Some(20), Some(10)), Some(10));
        for (child, parent) in [
            (None, Some(10)),
            (Some(20), None),
            (Some(0), Some(10)),
            (Some(20), Some(0)),
            (Some(20), Some(20)),
            (Some(20), Some(21)),
        ] {
            assert_eq!(parent_generation_before_child(child, parent), None);
        }
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

#[cfg(all(test, windows))]
mod windows_account_tests {
    #[test]
    fn own_account_is_qualified_and_invalid_pid_stays_unknown() {
        let name = super::windows_process_account(std::process::id() as i32)
            .expect("own account must resolve");
        assert!(name.contains('\\'));
        assert!(super::windows_process_account(0).is_none());
        assert!(super::windows_process_account(-1).is_none());
    }
}
