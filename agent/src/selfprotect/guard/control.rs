//! Service control for the guard pair: is the peer installed, which process is
//! it, start it again (killing it first if it is hung), and wait for its
//! process to end. Blocking APIs; callers use `spawn_blocking`.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;

use super::Peer;

/// Poll interval of the exit watch; bounds how long a cancelled watch lingers.
const WATCH_SLICE: Duration = Duration::from_millis(250);

/// Wait for the process `pid` to end. Returns `true` if it ended, `false` if
/// `cancel` was set first. Runs on the blocking pool.
pub async fn wait_exit(pid: u32, cancel: Arc<AtomicBool>) -> bool {
    tokio::task::spawn_blocking(move || wait_exit_blocking(pid, &cancel))
        .await
        .unwrap_or(false)
}

fn never_signal_self_or_init(pid: u32) -> bool {
    pid > 1 && pid != std::process::id()
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
    pub fn restart(peer: Peer, kill_pid: Option<u32>) -> Result<()> {
        if let Some(pid) = kill_pid.filter(|p| never_signal_self_or_init(*p)) {
            let _ = nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(pid as i32),
                nix::sys::signal::Signal::SIGKILL,
            );
        }
        let status = Command::new("systemctl")
            .args([
                "start",
                "--no-block",
                &format!("{}.service", peer.service_name()),
            ])
            .status()?;
        anyhow::ensure!(status.success(), "systemctl start failed ({status})");
        Ok(())
    }
}

#[cfg(windows)]
mod imp {
    use super::*;
    use windows_service::service::{ServiceAccess, ServiceState};
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
    use windows_sys::Win32::Foundation::{CloseHandle, WAIT_OBJECT_0};
    use windows_sys::Win32::System::Threading::{
        OpenProcess, TerminateProcess, WaitForSingleObject, PROCESS_TERMINATE,
    };

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

    pub fn restart(peer: Peer, kill_pid: Option<u32>) -> Result<()> {
        if let Some(pid) = kill_pid.filter(|p| never_signal_self_or_init(*p)) {
            // SAFETY: handle closed below. Both services run as SYSTEM, which
            // the peer's process DACL grants full access.
            unsafe {
                let handle = OpenProcess(PROCESS_TERMINATE, 0, pid);
                if !handle.is_null() {
                    TerminateProcess(handle, 1);
                    CloseHandle(handle);
                }
            }
        }
        let service = open(peer, ServiceAccess::START | ServiceAccess::QUERY_STATUS)?;
        // A just-terminated service needs a moment to report Stopped.
        for _ in 0..20 {
            match service.query_status()?.current_state {
                ServiceState::Stopped => {
                    service.start::<&std::ffi::OsStr>(&[])?;
                    return Ok(());
                }
                ServiceState::Running | ServiceState::StartPending => return Ok(()),
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
}
