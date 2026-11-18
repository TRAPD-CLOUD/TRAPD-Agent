//! Service control for the guard pair: is the peer installed, which process is
//! it, start it again (killing it first if it is hung), and wait for its
//! process to end. Blocking APIs; callers use `spawn_blocking`.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;

use super::{Peer, Tracer};

/// Poll interval of the exit watch; bounds how long a cancelled watch lingers.
const WATCH_SLICE: Duration = Duration::from_millis(250);

/// Wait for the process `pid` to end. Returns `true` if it ended, `false` if
/// `cancel` was set first. Runs on the blocking pool.
///
/// Dropping this future (task aborted, runtime shutting down) cancels the
/// blocking wait as well. Without that, the blocking thread kept polling a
/// live peer forever and the runtime's shutdown, which joins the blocking
/// pool, never finished: an agent whose `main` returned stayed a half-dead
/// process, and the guard then killed it as hung.
pub async fn wait_exit(pid: u32, cancel: Arc<AtomicBool>) -> bool {
    struct CancelOnDrop(Arc<AtomicBool>);
    impl Drop for CancelOnDrop {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Relaxed);
        }
    }
    let _on_drop = CancelOnDrop(Arc::clone(&cancel));
    tokio::task::spawn_blocking(move || wait_exit_blocking(pid, &cancel))
        .await
        .unwrap_or(false)
}

fn never_signal_self_or_init(pid: u32) -> bool {
    pid > 1 && pid != std::process::id()
}

/// A peer process as it was when the authenticated channel first showed it: the pid and the
/// start (creation) time that makes the pid stable. Signalling a bare pid is unsafe after the peer
/// had time to exit, because the pid can be reused by an unrelated process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcessIdentity {
    pub pid: u32,
    /// `None` when the start time could not be read: the process is then never signalled.
    pub start: Option<u64>,
}

impl ProcessIdentity {
    /// Identity of `pid` right now; call it when the pid is first observed.
    pub fn observe(pid: u32) -> Self {
        Self {
            pid,
            start: crate::telemetry::identity::process_start_time(pid as i32),
        }
    }
}

/// Kill a hung peer, bound to the observed process generation (pidfd / process handle opened before
/// the start time is compared), so a pid reused during the settle delay is never hit.
fn kill_hung_peer(id: ProcessIdentity) {
    if !never_signal_self_or_init(id.pid) {
        return;
    }
    let Some(start) = id.start else {
        tracing::warn!(
            pid = id.pid,
            "the hung peer's start time is unknown; not signalling a bare pid"
        );
        return;
    };
    if let Err(e) = crate::prevention::process::kill_observed(id.pid as i32, Some(start)) {
        // Typically "gone already" or "pid belongs to a different process": exactly the cases in
        // which nothing must be signalled.
        tracing::debug!(pid = id.pid, error = %e, "hung peer not killed");
    }
}

#[cfg(target_os = "linux")]
mod imp {
    use super::*;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::path::Path;
    use std::process::Command;

    pub fn installed(peer: Peer) -> bool {
        [
            "/usr/lib/systemd/system",
            "/lib/systemd/system",
            "/etc/systemd/system",
        ]
        .iter()
        .any(|d| {
            Path::new(d)
                .join(format!("{}.service", peer.service_name()))
                .exists()
        })
    }

    /// systemd's main pid of the peer's unit, if it is running.
    pub fn service_pid(_peer: Peer) -> Option<u32> {
        // Linux authenticates the channel by `SO_PEERCRED` (root); a per-ping
        // `systemctl show` would cost more than it adds.
        None
    }

    pub fn wait_exit_blocking(pid: u32, cancel: &AtomicBool) -> bool {
        // pidfd: the kernel signals readability when the process is gone, with
        // no pid-reuse race. Fall back to polling /proc on kernels without it.
        // SAFETY: plain syscall; the returned fd (if any) is owned below.
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0) };
        if fd >= 0 {
            // SAFETY: `fd` is a fresh descriptor we own.
            let owned = unsafe { OwnedFd::from_raw_fd(fd as i32) };
            loop {
                if cancel.load(Ordering::Relaxed) {
                    return false;
                }
                let mut p = libc::pollfd {
                    fd: owned.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                };
                // SAFETY: one valid pollfd.
                let n = unsafe { libc::poll(&mut p, 1, WATCH_SLICE.as_millis() as i32) };
                if n > 0 {
                    return true;
                }
            }
        }
        let proc_dir = format!("/proc/{pid}");
        loop {
            if cancel.load(Ordering::Relaxed) {
                return false;
            }
            if !Path::new(&proc_dir).exists() {
                return true;
            }
            std::thread::sleep(WATCH_SLICE);
        }
    }

    /// Start the peer's unit. A hung peer (`kill_pid`) is killed first: SIGKILL
    /// works on a stopped process, a stop request would stay pending forever.
    /// `start`, never `restart`: the agent unit is `PartOf` the other way round
    /// and a restart of one would take the restarter down with it.
    pub fn restart(peer: Peer, kill: Option<ProcessIdentity>) -> Result<Option<Tracer>> {
        let mut held_by = None;
        if let Some(id) = kill.filter(|id| never_signal_self_or_init(id.pid)) {
            // A debugger attach freezes the peer; after SIGKILL its zombie
            // cannot be reaped while the tracer holds it, so systemd keeps the
            // unit "active" and `start` does nothing. End the tracer too: no
            // legitimate tool debugs the sensor outside a maintenance window
            // (authorized stops never reach this path).
            //
            // The tracer is read only while the pid still is the observed peer generation, and
            // killed through its own start time, so a reused pid is never mistaken for either.
            let pid = id.pid;
            let still_the_peer = id.start.is_some()
                && crate::telemetry::identity::process_start_time(pid as i32) == id.start;
            let tracer = still_the_peer
                .then(|| std::fs::read_to_string(format!("/proc/{pid}/status")).ok())
                .flatten()
                .and_then(|s| super::super::parse_tracer_pid(&s))
                .filter(|t| never_signal_self_or_init(*t) && *t != pid);
            let tracer_start =
                tracer.and_then(|t| crate::telemetry::identity::process_start_time(t as i32));
            kill_hung_peer(id);
            if let (Some(t), Some(start)) = (tracer, tracer_start) {
                // The guard has no CAP_SYS_PTRACE, so the exe link of another
                // process may be unreadable; `comm` needs no privilege.
                let exe = std::fs::read_link(format!("/proc/{t}/exe"))
                    .map(|p| p.to_string_lossy().into_owned())
                    .or_else(|_| {
                        std::fs::read_to_string(format!("/proc/{t}/comm"))
                            .map(|c| format!("comm:{}", c.trim()))
                    })
                    .unwrap_or_else(|_| "unknown".into());
                if crate::prevention::process::kill_observed(t as i32, Some(start)).is_ok() {
                    held_by = Some(Tracer { pid: t, exe });
                }
            }
        }
        let status = Command::new("systemctl")
            .args([
                "start",
                "--no-block",
                &format!("{}.service", peer.service_name()),
            ])
            .status()?;
        anyhow::ensure!(status.success(), "systemctl start failed ({status})");
        Ok(held_by)
    }
}

#[cfg(windows)]
mod imp {
    use super::*;
    use windows_service::service::{ServiceAccess, ServiceState};
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
    use windows_sys::Win32::Foundation::{CloseHandle, WAIT_OBJECT_0};
    use windows_sys::Win32::System::Threading::{OpenProcess, WaitForSingleObject};

    const SYNCHRONIZE: u32 = 0x0010_0000;

    fn open(peer: Peer, access: ServiceAccess) -> Result<windows_service::service::Service> {
        let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
        Ok(manager.open_service(peer.service_name(), access)?)
    }

    pub fn installed(peer: Peer) -> bool {
        open(peer, ServiceAccess::QUERY_STATUS).is_ok()
    }

    /// The pid the SCM reports for the peer's service: the OS-side answer to
    /// "is this pipe client really that service".
    pub fn service_pid(peer: Peer) -> Option<u32> {
        open(peer, ServiceAccess::QUERY_STATUS)
            .ok()?
            .query_status()
            .ok()?
            .process_id
    }

    pub fn wait_exit_blocking(pid: u32, cancel: &AtomicBool) -> bool {
        // SAFETY: handle closed on every path.
        let handle = unsafe { OpenProcess(SYNCHRONIZE, 0, pid) };
        if handle.is_null() {
            // Gone already (or not ours to open): treat as ended so the caller
            // re-checks through the normal ping path.
            return true;
        }
        let ended = loop {
            if cancel.load(Ordering::Relaxed) {
                break false;
            }
            // SAFETY: valid handle.
            if unsafe { WaitForSingleObject(handle, WATCH_SLICE.as_millis() as u32) }
                == WAIT_OBJECT_0
            {
                break true;
            }
        };
        // SAFETY: handle opened above.
        unsafe { CloseHandle(handle) };
        ended
    }

    pub fn restart(peer: Peer, kill: Option<ProcessIdentity>) -> Result<Option<Tracer>> {
        // Windows: TerminateProcess ends a debugged process regardless of the
        // debugger, so there is no holder to report.
        if let Some(id) = kill {
            kill_hung_peer(id);
        }
        let service = open(peer, ServiceAccess::START | ServiceAccess::QUERY_STATUS)?;
        // A just-terminated service needs a moment to report Stopped.
        for _ in 0..20 {
            match service.query_status()?.current_state {
                ServiceState::Stopped => {
                    service.start::<&std::ffi::OsStr>(&[])?;
                    return Ok(None);
                }
                ServiceState::Running | ServiceState::StartPending => return Ok(None),
                _ => std::thread::sleep(Duration::from_millis(250)),
            }
        }
        anyhow::bail!("{} did not reach the stopped state", peer.service_name())
    }
}

use imp::wait_exit_blocking;
pub use imp::{installed, restart, service_pid};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn never_signals_itself_or_init() {
        assert!(!never_signal_self_or_init(0));
        assert!(!never_signal_self_or_init(1));
        assert!(!never_signal_self_or_init(std::process::id()));
        assert!(never_signal_self_or_init(std::process::id() + 1));
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn wait_exit_returns_when_the_process_ends_and_stops_when_cancelled() {
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let pid = child.id();
        // Cancelled while it still runs.
        let cancel = Arc::new(AtomicBool::new(false));
        let waiter = tokio::spawn(wait_exit(pid, Arc::clone(&cancel)));
        tokio::time::sleep(Duration::from_millis(300)).await;
        cancel.store(true, Ordering::Relaxed);
        assert!(!waiter.await.unwrap());
        // Ends while watched (reaped by wait() so the pid disappears).
        let cancel = Arc::new(AtomicBool::new(false));
        let waiter = tokio::spawn(wait_exit(pid, Arc::clone(&cancel)));
        tokio::time::sleep(Duration::from_millis(300)).await;
        child.kill().unwrap();
        let _ = child.wait();
        let ended = tokio::time::timeout(Duration::from_secs(5), waiter)
            .await
            .unwrap()
            .unwrap();
        assert!(ended);
    }

    /// Field regression: a runtime dropped while a watch on a live peer runs
    /// (the agent's `main` returned) must shut down promptly instead of
    /// joining a blocking thread that polls forever.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_runtime_with_a_running_watch_still_shuts_down() {
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let pid = child.id();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(1)
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async {
                tokio::spawn(wait_exit(pid, Arc::new(AtomicBool::new(false))));
                tokio::time::sleep(Duration::from_millis(300)).await;
            });
            drop(rt); // joins the blocking pool
            let _ = tx.send(());
        });
        let finished = rx.recv_timeout(Duration::from_secs(5)).is_ok();
        child.kill().unwrap();
        let _ = child.wait();
        assert!(finished, "runtime shutdown hung on the exit watch");
    }
}

#[cfg(all(test, target_os = "linux"))]
mod kill_tests {
    use super::*;

    #[test]
    fn a_hung_peer_is_killed_only_as_the_generation_that_was_observed() {
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let id = ProcessIdentity::observe(child.id());
        let start = id.start.expect("start time of a live child");

        // A pid that now belongs to a different process generation must not be signalled.
        kill_hung_peer(ProcessIdentity {
            pid: child.id(),
            start: Some(start + 1),
        });
        // Nor one whose start time was never known.
        kill_hung_peer(ProcessIdentity {
            pid: child.id(),
            start: None,
        });
        assert!(child.try_wait().unwrap().is_none(), "signalled a stranger");

        kill_hung_peer(id);
        assert!(
            !child.wait().unwrap().success(),
            "the observed process is killed"
        );
    }

    #[test]
    fn never_signals_self_or_init() {
        assert!(!never_signal_self_or_init(0));
        assert!(!never_signal_self_or_init(1));
        assert!(!never_signal_self_or_init(std::process::id()));
    }
}
