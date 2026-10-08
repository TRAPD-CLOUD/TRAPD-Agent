//! Response forensics (issue #32, point 5) — the context the agent gathers so a
//! confirmed honeytoken hit ships as a full picture, not a bare access:
//!
//!   * [`session`] — who/where: login session, TTY, container/namespace/cgroup,
//!     captured from `/proc` at detection time;
//!   * [`snapshot`] — a point-in-time capture of a (usually frozen) process, for
//!     the "freeze, snapshot, then decide" response;
//!   * [`recorder`] — a bounded flight recorder of recent pid-bearing telemetry,
//!     pulled into the response as the session's pre-history.
//!
//! Production `/proc` readers live here; the assembly logic is unit-tested in
//! each submodule against fakes.

// The session-capture half is consumed by the Linux honeytoken detector only;
// off-Linux it compiles (pure /proc string reads) but has no caller yet.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

pub mod recorder;
pub mod session;
pub mod snapshot;

pub use recorder::FlightRecorder;
pub use snapshot::ProcessSnapshot;

use crate::schema::SessionContext as SchemaSessionContext;

/// Capture the [`SchemaSessionContext`] for `pid` from the live host: `/proc`
/// on Linux, the process token and terminal-services session on Windows.
pub fn capture_session(pid: i32) -> SchemaSessionContext {
    #[allow(unused_mut)]
    let mut context = session::capture(&RealProc, pid);
    #[cfg(windows)]
    {
        // Windows has no audit `loginuid`: the owning account (qualified with its
        // domain) and the logon *session* identify who and where instead.
        context.login_user = crate::telemetry::identity::windows_process_account(pid);
        context.audit_session_id = win::session_id(pid);
    }
    context
}

/// Like [`capture_session`] but `None` when nothing could be resolved (e.g. the
/// process already exited), so a detection event never carries an empty `{}`.
pub fn capture_session_opt(pid: i32) -> Option<SchemaSessionContext> {
    let s = capture_session(pid);
    if session_is_empty(&s) {
        None
    } else {
        Some(s)
    }
}

fn session_is_empty(s: &SchemaSessionContext) -> bool {
    s.loginuid.is_none()
        && s.login_user.is_none()
        && s.audit_session_id.is_none()
        && s.tty.is_none()
        && s.cwd.is_none()
        && s.cgroup.is_none()
        && s.container_id.is_none()
        && s.namespaces.is_empty()
        && s.remote_addr.is_none()
}

/// Capture a [`ProcessSnapshot`] of `pid` from the live `/proc`. `frozen` records
/// whether the caller suspended the process first.
pub fn capture_snapshot(pid: i32, frozen: bool) -> ProcessSnapshot {
    snapshot::capture(&RealProc, pid, frozen)
}

/// Reads the live `/proc` and `/etc/passwd`. Implements both reader traits.
pub struct RealProc;

#[cfg(not(windows))]
impl session::ProcReader for RealProc {
    fn loginuid(&self, pid: i32) -> Option<String> {
        std::fs::read_to_string(format!("/proc/{pid}/loginuid")).ok()
    }
    fn sessionid(&self, pid: i32) -> Option<String> {
        std::fs::read_to_string(format!("/proc/{pid}/sessionid")).ok()
    }
    fn stat(&self, pid: i32) -> Option<String> {
        std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()
    }
    fn cgroup(&self, pid: i32) -> Option<String> {
        std::fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()
    }
    fn cwd(&self, pid: i32) -> Option<String> {
        std::fs::read_link(format!("/proc/{pid}/cwd"))
            .ok()
            .map(|p| p.to_string_lossy().into_owned())
    }
    fn ns_link(&self, pid: i32, ns: &str) -> Option<String> {
        std::fs::read_link(format!("/proc/{pid}/ns/{ns}"))
            .ok()
            .map(|p| p.to_string_lossy().into_owned())
    }
    fn username_for_uid(&self, uid: u32) -> Option<String> {
        username_for_uid(uid)
    }
}

#[cfg(not(windows))]
impl snapshot::SnapshotProc for RealProc {
    fn status(&self, pid: i32) -> Option<String> {
        std::fs::read_to_string(format!("/proc/{pid}/status")).ok()
    }
    fn exe(&self, pid: i32) -> Option<String> {
        std::fs::read_link(format!("/proc/{pid}/exe"))
            .ok()
            .map(|p| p.to_string_lossy().into_owned())
    }
    fn cwd(&self, pid: i32) -> Option<String> {
        std::fs::read_link(format!("/proc/{pid}/cwd"))
            .ok()
            .map(|p| p.to_string_lossy().into_owned())
    }
    fn cmdline(&self, pid: i32) -> Option<String> {
        let raw = std::fs::read(format!("/proc/{pid}/cmdline")).ok()?;
        let s: String = raw
            .split(|&b| b == 0)
            .filter(|p| !p.is_empty())
            .map(|p| String::from_utf8_lossy(p))
            .collect::<Vec<_>>()
            .join(" ");
        (!s.is_empty()).then_some(s)
    }
    fn open_fds(&self, pid: i32) -> Vec<String> {
        let mut out = Vec::new();
        if let Ok(entries) = std::fs::read_dir(format!("/proc/{pid}/fd")) {
            for e in entries.flatten() {
                if let Ok(target) = std::fs::read_link(e.path()) {
                    out.push(target.to_string_lossy().into_owned());
                }
            }
        }
        out
    }
}

/// Resolve a username from `/etc/passwd` (shared by the readers).
#[cfg(not(windows))]
fn username_for_uid(uid: u32) -> Option<String> {
    std::fs::read_to_string("/etc/passwd")
        .ok()?
        .lines()
        .find_map(|line| {
            let mut f = line.splitn(7, ':');
            let name = f.next()?;
            let _ = f.next();
            let u = f.next()?.parse::<u32>().ok()?;
            (u == uid).then(|| name.to_string())
        })
}

/// Windows readers. There is no `/proc`: process facts come from the process
/// table (`sysinfo`), the logon session from `ProcessIdToSessionId`. Open
/// handles are deliberately not enumerated — that needs the undocumented
/// `NtQuerySystemInformation(SystemExtendedHandleInformation)` and a privileged
/// handle duplication per object, which a freeze-time snapshot should not do.
#[cfg(windows)]
mod win {
    use sysinfo::{Pid, ProcessRefreshKind, System, UpdateKind};

    use super::{session, snapshot, RealProc};

    /// Terminal-services session id of `pid` (`0` is the services session).
    pub(super) fn session_id(pid: i32) -> Option<u32> {
        use windows_sys::Win32::System::RemoteDesktop::ProcessIdToSessionId;
        let mut id = 0u32;
        // SAFETY: valid out-pointer.
        (pid > 0 && unsafe { ProcessIdToSessionId(pid as u32, &mut id) } != 0).then_some(id)
    }

    fn with_process<T>(pid: i32, f: impl FnOnce(&sysinfo::Process) -> Option<T>) -> Option<T> {
        if pid <= 0 {
            return None;
        }
        let mut sys = System::new();
        let kind = ProcessRefreshKind::new()
            .with_exe(UpdateKind::Always)
            .with_cwd(UpdateKind::Always)
            .with_cmd(UpdateKind::Always);
        let pid = Pid::from_u32(pid as u32);
        sys.refresh_process_specifics(pid, kind);
        sys.process(pid).and_then(f)
    }

    impl session::ProcReader for RealProc {
        fn loginuid(&self, _: i32) -> Option<String> {
            None
        }
        fn sessionid(&self, _: i32) -> Option<String> {
            None
        }
        fn stat(&self, _: i32) -> Option<String> {
            None
        }
        fn cgroup(&self, _: i32) -> Option<String> {
            None
        }
        fn cwd(&self, pid: i32) -> Option<String> {
            with_process(pid, |p| p.cwd().map(|c| c.to_string_lossy().into_owned()))
        }
        fn ns_link(&self, _: i32, _: &str) -> Option<String> {
            None
        }
        fn username_for_uid(&self, _: u32) -> Option<String> {
            None
        }
    }

    impl snapshot::SnapshotProc for RealProc {
        fn status(&self, _: i32) -> Option<String> {
            // The caller records `frozen`; Windows has no `/proc/<pid>/status`.
            None
        }
        fn exe(&self, pid: i32) -> Option<String> {
            with_process(pid, |p| p.exe().map(|e| e.to_string_lossy().into_owned()))
        }
        fn cwd(&self, pid: i32) -> Option<String> {
            with_process(pid, |p| p.cwd().map(|c| c.to_string_lossy().into_owned()))
        }
        fn cmdline(&self, pid: i32) -> Option<String> {
            with_process(pid, |p| {
                let joined = p.cmd().join(" ");
                (!joined.is_empty()).then_some(joined)
            })
        }
        fn open_fds(&self, _: i32) -> Vec<String> {
            Vec::new()
        }
    }
}
