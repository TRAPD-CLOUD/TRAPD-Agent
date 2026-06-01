//! Forensic process snapshot (issue #32, point 5).
//!
//! When the response policy *freezes* an intruder process (SIGSTOP) instead of
//! killing it, we capture a point-in-time snapshot so an operator (or the
//! backend) can decide what to do while the process is suspended and cannot
//! react. The snapshot is intentionally lightweight — process state, exe, cwd,
//! cmdline and the open-file table — and never reads file *contents*.
//!
//! `/proc` access sits behind [`SnapshotProc`] so the assembly is unit-testable.

use serde::{Deserialize, Serialize};

/// How many open-fd links we record before truncating (bounded so a process
/// with thousands of fds cannot bloat the event).
const MAX_OPEN_FILES: usize = 64;

/// A point-in-time forensic capture of a (usually frozen) process.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct ProcessSnapshot {
    pub pid: i32,
    /// Whether the process was frozen (SIGSTOP) before the snapshot was taken.
    pub frozen: bool,
    /// Scheduler state from `/proc/<pid>/status` (`R`, `S`, `T` (stopped), …).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exe: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cmdline: Option<String>,
    /// Open file descriptors (their `readlink` targets), capped at
    /// [`MAX_OPEN_FILES`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub open_files: Vec<String>,
    /// Total open-fd count before capping, so truncation is visible.
    pub open_files_total: usize,
}

/// `/proc` reads needed to assemble a [`ProcessSnapshot`].
pub trait SnapshotProc {
    fn status(&self, pid: i32) -> Option<String>;
    fn exe(&self, pid: i32) -> Option<String>;
    fn cwd(&self, pid: i32) -> Option<String>;
    fn cmdline(&self, pid: i32) -> Option<String>;
    /// `readlink` targets of `/proc/<pid>/fd/*`.
    fn open_fds(&self, pid: i32) -> Vec<String>;
}

/// Capture a snapshot of `pid` from `p`. `frozen` records whether the caller
/// successfully suspended the process first.
pub fn capture(p: &dyn SnapshotProc, pid: i32, frozen: bool) -> ProcessSnapshot {
    let state = p.status(pid).as_deref().and_then(parse_state);
    let mut open_files = p.open_fds(pid);
    let open_files_total = open_files.len();
    open_files.truncate(MAX_OPEN_FILES);

    ProcessSnapshot {
        pid,
        frozen,
        state,
        exe: p.exe(pid).filter(|s| !s.is_empty()),
        cwd: p.cwd(pid).filter(|s| !s.is_empty()),
        cmdline: p.cmdline(pid).filter(|s| !s.is_empty()),
        open_files,
        open_files_total,
    }
}

/// Extract the `State:` line value from `/proc/<pid>/status`, e.g. `S (sleeping)`.
pub fn parse_state(status: &str) -> Option<String> {
    status
        .lines()
        .find_map(|l| l.strip_prefix("State:"))
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FakeProc {
        fds: Vec<String>,
    }
    impl SnapshotProc for FakeProc {
        fn status(&self, _: i32) -> Option<String> {
            Some("Name:\tcat\nState:\tT (stopped)\nPid:\t100\n".into())
        }
        fn exe(&self, _: i32) -> Option<String> { Some("/bin/cat".into()) }
        fn cwd(&self, _: i32) -> Option<String> { Some("/home/alice".into()) }
        fn cmdline(&self, _: i32) -> Option<String> { Some("cat /home/alice/.aws/credentials".into()) }
        fn open_fds(&self, _: i32) -> Vec<String> { self.fds.clone() }
    }

    #[test]
    fn parses_state_line() {
        assert_eq!(parse_state("State:\tT (stopped)\n").as_deref(), Some("T (stopped)"));
        assert_eq!(parse_state("No state here"), None);
    }

    #[test]
    fn captures_and_marks_frozen() {
        let p = FakeProc { fds: vec!["/dev/pts/3".into(), "/home/alice/.aws/credentials".into()] };
        let snap = capture(&p, 100, true);
        assert!(snap.frozen);
        assert_eq!(snap.state.as_deref(), Some("T (stopped)"));
        assert_eq!(snap.exe.as_deref(), Some("/bin/cat"));
        assert_eq!(snap.open_files.len(), 2);
        assert_eq!(snap.open_files_total, 2);
    }

    #[test]
    fn open_files_are_capped() {
        let fds: Vec<String> = (0..200).map(|i| format!("/tmp/f{i}")).collect();
        let snap = capture(&FakeProc { fds }, 7, false);
        assert_eq!(snap.open_files.len(), MAX_OPEN_FILES);
        assert_eq!(snap.open_files_total, 200, "total reflects pre-cap count");
        assert!(!snap.frozen);
    }
}
