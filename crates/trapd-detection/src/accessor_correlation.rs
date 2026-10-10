//! Best-effort attribution of a file access to the process that caused it.
//!
//! `ReadDirectoryChangesW` and the NTFS last-access timestamp say *that* a
//! file was touched, never *who* touched it. The process telemetry does know
//! who started which program with which arguments, and the common ways of
//! reading a file (`notepad.exe C:\…\decoy.txt`, `type`, `copy`, an editor
//! opened from a shell) put the file's path on the command line. So the file
//! collectors keep a short, bounded, in-memory window of recent
//! `process.create` events and look the touched path up in it.
//!
//! What this is not: proof. A process that opens the file without naming it
//! on its command line (a double click in Explorer starts the handler with the
//! path, but `explorer.exe` copying the file does not, a service reading it
//! from a handle inherited elsewhere never does) is not found, and an
//! unrelated process that merely mentions the same file name is matched with
//! the lower [`MatchKind::FileName`] rank. Callers must say so in the event
//! (`assessment_reasons`) instead of presenting the result as a kernel-level
//! attribution. Exact attribution needs the 4663 object-access audit path
//! (`windows_decoy`), which is used where the host has it armed.
//!
//! Privacy: command lines stay in agent memory only for [`WINDOW`], capped at
//! [`MAX_ENTRIES`] entries and [`MAX_CMDLINE`] bytes each; nothing here is
//! persisted.

// Fed by the Windows collectors; compiled and tested everywhere.
#![cfg_attr(not(windows), allow(dead_code))]

use std::collections::VecDeque;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use trapd_schema::{ProcessAncestor, ProcessCreateData, ProcessLineage, Severity};

/// How long a process start stays eligible for attribution.
pub const WINDOW: Duration = Duration::from_secs(120);
const MAX_ENTRIES: usize = 512;
const MAX_CMDLINE: usize = 1024;
const MAX_ANCESTORS: usize = 4;
/// File names shorter than this are too ambiguous to match by name alone.
const MIN_NAME_MATCH_LEN: usize = 6;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum MatchKind {
    /// Only the file name appears on the command line (relative path or a
    /// different directory spelling). Plausible, not certain.
    FileName,
    /// The full path of the file appears on the command line.
    FullPath,
}

#[derive(Debug, Clone)]
pub struct Match {
    pub lineage: ProcessLineage,
    pub kind: MatchKind,
}

impl Match {
    /// Reason text for the event, stating exactly how the process was found.
    pub fn reason(&self) -> String {
        match self.kind {
            MatchKind::FullPath => format!(
                "accessor inferred from process.create: '{}' (pid {}) has the file path on its command line; Windows change notifications carry no accessor",
                self.lineage.comm, self.lineage.pid
            ),
            MatchKind::FileName => format!(
                "accessor is a candidate only: '{}' (pid {}) names the file (without its full path) on its command line",
                self.lineage.comm, self.lineage.pid
            ),
        }
    }
}

struct Entry {
    seen: Instant,
    data: ProcessCreateData,
    /// Lower-cased, `\`-separated, quote-free command line.
    norm_cmdline: String,
}

#[derive(Default)]
pub struct RecentProcesses {
    entries: VecDeque<Entry>,
}

/// Comparison form: case-insensitive, one separator, quotes removed.
fn normalise(s: &str) -> String {
    s.chars()
        .filter(|c| *c != '"')
        .map(|c| {
            if c == '/' {
                '\\'
            } else {
                c.to_ascii_lowercase()
            }
        })
        .collect()
}

fn strip_verbatim(s: String) -> String {
    s.strip_prefix("\\\\?\\").map(str::to_string).unwrap_or(s)
}

fn file_name(norm_path: &str) -> &str {
    norm_path.rsplit('\\').next().unwrap_or(norm_path)
}

/// `needle` occurs in `haystack` delimited by start/end, whitespace, a path
/// separator or `=`/`,`/`;` on both sides (so `a.txt` does not match `data.txt`).
fn contains_token(haystack: &str, needle: &str) -> bool {
    let is_boundary = |c: char| c.is_whitespace() || matches!(c, '\\' | '=' | ',' | ';' | '\'');
    let mut from = 0;
    while let Some(i) = haystack[from..].find(needle) {
        let start = from + i;
        let end = start + needle.len();
        let before_ok = start == 0
            || haystack[..start]
                .chars()
                .next_back()
                .is_some_and(is_boundary);
        let after_ok =
            end == haystack.len() || haystack[end..].chars().next().is_some_and(is_boundary);
        if before_ok && after_ok {
            return true;
        }
        from = start + 1;
        if from >= haystack.len() {
            break;
        }
    }
    false
}

impl RecentProcesses {
    pub fn record(&mut self, p: &ProcessCreateData, now: Instant) {
        self.expire(now);
        if self.entries.len() >= MAX_ENTRIES {
            self.entries.pop_front();
        }
        let mut data = p.clone();
        if data.cmdline.len() > MAX_CMDLINE {
            let mut cut = MAX_CMDLINE;
            while !data.cmdline.is_char_boundary(cut) {
                cut -= 1;
            }
            data.cmdline.truncate(cut);
        }
        let norm_cmdline = normalise(&data.cmdline);
        self.entries.push_back(Entry {
            seen: now,
            data,
            norm_cmdline,
        });
    }

    fn expire(&mut self, now: Instant) {
        while self
            .entries
            .front()
            .is_some_and(|e| now.saturating_duration_since(e.seen) > WINDOW)
        {
            self.entries.pop_front();
        }
    }

    /// The most recent process whose command line names `path`. A full-path
    /// match always outranks a name-only match, however old (within the
    /// window).
    pub fn find(&self, path: &str, now: Instant) -> Option<Match> {
        let full = strip_verbatim(normalise(path));
        let name = file_name(&full).to_string();
        if name.is_empty() {
            return None;
        }
        let mut best: Option<(MatchKind, &Entry)> = None;
        for e in self.entries.iter().rev() {
            if now.saturating_duration_since(e.seen) > WINDOW {
                break;
            }
            // The agent itself never counts as its own accessor.
            if e.data.name.to_ascii_lowercase().starts_with("trapd")
                || e.data.pid as u32 == std::process::id()
            {
                continue;
            }
            let kind = if contains_token(&e.norm_cmdline, &full) {
                MatchKind::FullPath
            } else if name.len() >= MIN_NAME_MATCH_LEN && contains_token(&e.norm_cmdline, &name) {
                MatchKind::FileName
            } else {
                continue;
            };
            if best.is_none_or(|(k, _)| kind > k) {
                best = Some((kind, e));
            }
            if kind == MatchKind::FullPath {
                break; // newest full-path match
            }
        }
        best.map(|(kind, e)| Match {
            lineage: self.lineage_of(e),
            kind,
        })
    }

    fn lineage_of(&self, e: &Entry) -> ProcessLineage {
        let mut ancestors = Vec::new();
        let mut ppid = e.data.ppid;
        while ancestors.len() < MAX_ANCESTORS {
            // Newest entry with that pid started before this process.
            let Some(parent) = self
                .entries
                .iter()
                .rev()
                .find(|p| p.data.pid == ppid && p.seen <= e.seen)
            else {
                break;
            };
            ancestors.push(ProcessAncestor {
                pid: parent.data.pid,
                comm: parent.data.name.clone(),
                exe: Some(parent.data.exe.clone()).filter(|x| !x.is_empty()),
                cmdline: Some(parent.data.cmdline.clone()).filter(|x| !x.is_empty()),
            });
            if parent.data.ppid == ppid {
                break;
            }
            ppid = parent.data.ppid;
        }
        ProcessLineage {
            pid: e.data.pid,
            process_start_time: e.data.process_start_time,
            uid: e.data.uid,
            gid: 0,
            username: e.data.username.clone(),
            comm: e.data.name.clone(),
            exe: Some(e.data.exe.clone()).filter(|x| !x.is_empty()),
            cmdline: Some(e.data.cmdline.clone()).filter(|x| !x.is_empty()),
            ancestors,
        }
    }
}

fn global() -> &'static Mutex<RecentProcesses> {
    static G: OnceLock<Mutex<RecentProcesses>> = OnceLock::new();
    G.get_or_init(|| Mutex::new(RecentProcesses::default()))
}

/// Feed one process start (called by the process and ETW collectors).
pub fn record_process(p: &ProcessCreateData) {
    if let Ok(mut g) = global().lock() {
        g.record(p, Instant::now());
    }
}

/// Look up who most likely touched `path`.
pub fn attribute(path: &str) -> Option<Match> {
    global().lock().ok()?.find(path, Instant::now())
}

// ── Decisions built on the attribution ───────────────────────────────────────

/// How long a last-access hit waits for the process start that explains it.
/// Process telemetry lags the file access (the polling collector runs every
/// 3 s), so a hit is held back briefly rather than raised without an accessor.
pub const LAST_ACCESS_GRACE: Duration = Duration::from_secs(6);
/// After the collector starts, the agent's own start-up work (planting,
/// verifying, hashing decoys) moves access times. Last-access hits in this
/// period only count when an accessor is known.
pub const START_WARMUP: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LastAccessAction {
    /// Raise the detection now.
    Emit,
    /// An accessor may still show up in the process telemetry: look again.
    Wait,
    /// Start-up artefact without an accessor: re-baseline, raise nothing.
    Suppress,
}

/// Decide what to do with a moved last-access timestamp.
///
/// * accessor known: always emit (a process named the file);
/// * during the start-up warm-up and no accessor: suppress (restart artefact);
/// * otherwise wait up to [`LAST_ACCESS_GRACE`] for the accessor, then emit
///   the unattributed timestamp-only signal.
pub fn last_access_action(
    since_collector_start: Duration,
    accessor_known: bool,
    waited: Duration,
) -> LastAccessAction {
    if accessor_known {
        LastAccessAction::Emit
    } else if since_collector_start < START_WARMUP {
        LastAccessAction::Suppress
    } else if waited < LAST_ACCESS_GRACE {
        LastAccessAction::Wait
    } else {
        LastAccessAction::Emit
    }
}

/// Severity, confidence, MITRE tactic and technique of a Windows decoy-file
/// event. Mirrors the Linux scoring where the semantics match (content read =
/// 100, delete = 90, rename = 85).
///
/// A bare moved last-access time is weak on its own (backup and indexers move
/// it too), but a decoy that a process named on its command line is a
/// near-certain signal: nobody has a reason to open it.
pub fn fs_access_score(
    access_kind: &str,
    attribution: Option<MatchKind>,
) -> (Severity, u8, &'static str, &'static str) {
    match (access_kind, attribution) {
        ("last_access", Some(MatchKind::FullPath)) => {
            (Severity::High, 90, "TA0006 Credential Access", "T1552.001")
        }
        ("last_access", Some(MatchKind::FileName)) => {
            (Severity::High, 75, "TA0006 Credential Access", "T1552.001")
        }
        ("last_access", None) => (Severity::Low, 30, "TA0007 Discovery", "T1083"),
        ("open", _) => (
            Severity::Critical,
            100,
            "TA0006 Credential Access",
            "T1552.001",
        ),
        ("modify", _) => (Severity::Critical, 90, "TA0040 Impact", "T1565.001"),
        ("unlink", _) => (Severity::Critical, 90, "TA0040 Impact", "T1070.004"),
        ("rename", _) => (Severity::High, 85, "TA0040 Impact", "T1070.004"),
        _ => (
            Severity::Critical,
            90,
            "TA0006 Credential Access",
            "T1552.001",
        ),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn an_attributed_last_access_is_high_and_an_unattributed_one_stays_low() {
        let (sev, conf, _, _) = fs_access_score("last_access", Some(MatchKind::FullPath));
        assert_eq!((sev, conf), (Severity::High, 90));
        let (sev, conf, _, _) = fs_access_score("last_access", Some(MatchKind::FileName));
        assert_eq!((sev, conf), (Severity::High, 75));
        let (sev, conf, _, _) = fs_access_score("last_access", None);
        assert_eq!((sev, conf), (Severity::Low, 30));
        // Tamper and content-open scoring does not depend on attribution.
        assert_eq!(fs_access_score("open", None).1, 100);
        assert_eq!(fs_access_score("unlink", Some(MatchKind::FullPath)).1, 90);
        assert_eq!(fs_access_score("rename", None).0, Severity::High);
    }

    #[test]
    fn last_access_is_suppressed_at_start_up_unless_an_accessor_is_known() {
        use LastAccessAction::*;
        let early = Duration::from_secs(5);
        let late = Duration::from_secs(300);
        assert_eq!(last_access_action(early, false, Duration::ZERO), Suppress);
        assert_eq!(
            last_access_action(early, false, Duration::from_secs(60)),
            Suppress
        );
        assert_eq!(last_access_action(early, true, Duration::ZERO), Emit);
        // After warm-up an unattributed hit waits for the accessor, then fires.
        assert_eq!(last_access_action(late, false, Duration::ZERO), Wait);
        assert_eq!(last_access_action(late, false, LAST_ACCESS_GRACE), Emit);
        assert_eq!(last_access_action(late, true, Duration::ZERO), Emit);
    }

    use super::*;

    fn proc(pid: i32, ppid: i32, name: &str, cmdline: &str) -> ProcessCreateData {
        ProcessCreateData {
            pid,
            ppid,
            name: name.into(),
            exe: format!("C:\\Windows\\{name}"),
            cmdline: cmdline.into(),
            username: "CORP\\bob".into(),
            process_start_time: Some(pid as u64),
            ..Default::default()
        }
    }

    const DECOY: &str = "C:\\Users\\bob\\Documents\\bitlocker-recovery-key.txt";

    #[test]
    fn full_path_on_the_command_line_names_the_process_and_its_parent() {
        let t = Instant::now();
        let mut r = RecentProcesses::default();
        r.record(&proc(10, 1, "explorer.exe", "explorer.exe"), t);
        r.record(
            &proc(
                20,
                10,
                "Notepad.exe",
                &format!("\"C:\\Windows\\notepad.exe\" \"{}\"", DECOY.to_uppercase()),
            ),
            t + Duration::from_secs(1),
        );
        let m = r.find(DECOY, t + Duration::from_secs(3)).unwrap();
        assert_eq!(m.kind, MatchKind::FullPath);
        assert_eq!(m.lineage.comm, "Notepad.exe");
        assert_eq!(m.lineage.username, "CORP\\bob");
        assert_eq!(m.lineage.ancestors[0].comm, "explorer.exe");
        assert!(m.reason().contains("inferred"));
    }

    #[test]
    fn forward_slashes_and_verbatim_prefix_still_match() {
        let t = Instant::now();
        let mut r = RecentProcesses::default();
        r.record(
            &proc(
                20,
                1,
                "type.exe",
                "cmd /c type C:/Users/bob/Documents/bitlocker-recovery-key.txt",
            ),
            t,
        );
        let verbatim = format!("\\\\?\\{DECOY}");
        assert_eq!(r.find(&verbatim, t).unwrap().kind, MatchKind::FullPath);
    }

    #[test]
    fn a_bare_file_name_is_only_a_candidate_and_loses_to_a_full_path() {
        let t = Instant::now();
        let mut r = RecentProcesses::default();
        r.record(
            &proc(30, 1, "cmd.exe", "cmd /c type bitlocker-recovery-key.txt"),
            t,
        );
        let m = r.find(DECOY, t).unwrap();
        assert_eq!(m.kind, MatchKind::FileName);
        assert!(m.reason().contains("candidate only"));
        r.record(
            &proc(31, 1, "notepad.exe", &format!("notepad {DECOY}")),
            t - Duration::from_secs(0),
        );
        assert_eq!(r.find(DECOY, t).unwrap().lineage.pid, 31);
    }

    #[test]
    fn partial_names_and_short_names_do_not_match() {
        let t = Instant::now();
        let mut r = RecentProcesses::default();
        r.record(
            &proc(40, 1, "x.exe", "x.exe my-bitlocker-recovery-key.txt.bak"),
            t,
        );
        r.record(&proc(41, 1, "y.exe", "y.exe a.txt"), t);
        assert!(r.find(DECOY, t).is_none());
        assert!(
            r.find("C:\\Users\\bob\\a.txt", t).is_none(),
            "name too short"
        );
    }

    #[test]
    fn old_processes_expire_and_the_ring_is_bounded() {
        let t = Instant::now();
        let mut r = RecentProcesses::default();
        r.record(&proc(50, 1, "notepad.exe", &format!("notepad {DECOY}")), t);
        assert!(r.find(DECOY, t + WINDOW + Duration::from_secs(1)).is_none());
        for i in 0..(MAX_ENTRIES as i32 + 100) {
            r.record(&proc(1000 + i, 1, "a.exe", "a.exe"), t);
        }
        assert!(r.entries.len() <= MAX_ENTRIES);
    }

    #[test]
    fn the_agent_is_never_its_own_accessor() {
        let t = Instant::now();
        let mut r = RecentProcesses::default();
        r.record(
            &proc(60, 1, "trapd-agent.exe", &format!("trapd-agent {DECOY}")),
            t,
        );
        assert!(r.find(DECOY, t).is_none());
    }

    #[test]
    fn oversized_command_lines_are_truncated_on_a_char_boundary() {
        let t = Instant::now();
        let mut r = RecentProcesses::default();
        let long = format!("{}{}", "é".repeat(2000), DECOY);
        r.record(&proc(70, 1, "p.exe", &long), t);
        assert!(r.entries[0].data.cmdline.len() <= MAX_CMDLINE);
    }
}
