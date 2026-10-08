//! Windows apply platform: Service Control Manager restart and helper launch.
//!
//! The update flow is the Linux one (`apply_staged`): the service only *stages*
//! a verified update; a separate helper process re-verifies it, swaps the
//! binary, restarts the service and rolls back if the new version does not
//! report healthy. Windows differences, all handled here:
//!
//!   * There is no systemd path unit, so the service launches the helper itself
//!     right after staging ([`spawn_apply_helper`]).
//!   * The helper must outlive the service it restarts and must not be the file
//!     being replaced, so it runs from a **copy** of the current executable in
//!     the staging directory.
//!   * The install path comes from the SCM (the authoritative registration), not
//!     from the helper's own location or an argument a compromised agent could
//!     choose.
//!   * A running image can be renamed but not deleted, so the service is stopped
//!     before a rollback puts the previous binary back.

use std::os::windows::process::CommandExt;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use windows_service::service::{ServiceAccess, ServiceState};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

use super::apply::Platform;

const SERVICE_NAME: &str = "trapd-agent";
const STOP_TIMEOUT: Duration = Duration::from_secs(60);
/// `ERROR_SERVICE_ALREADY_RUNNING`.
const ERROR_SERVICE_ALREADY_RUNNING: i32 = 1056;
/// `CREATE_NO_WINDOW | DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP`.
const HELPER_CREATION_FLAGS: u32 = 0x0800_0000 | 0x0000_0008 | 0x0000_0200;

/// Extract the executable from a service `BinaryPathName`, which may be quoted
/// and may carry arguments: `"C:\Program Files\X\a.exe" -flag`.
pub fn parse_service_binary_path(raw: &str) -> PathBuf {
    let raw = raw.trim();
    if let Some(rest) = raw.strip_prefix('"') {
        return PathBuf::from(rest.split('"').next().unwrap_or(rest));
    }
    // Unquoted: the executable ends at the first `.exe` (case-insensitive).
    let lower = raw.to_ascii_lowercase();
    match lower.find(".exe") {
        Some(i) => PathBuf::from(&raw[..i + 4]),
        None => PathBuf::from(raw),
    }
}

/// The service executable as registered with the SCM.
pub fn installed_binary_path() -> Result<PathBuf> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .context("update: connect to the service manager")?;
    let service = manager
        .open_service(SERVICE_NAME, ServiceAccess::QUERY_CONFIG)
        .context("update: open the agent service")?;
    let config = service
        .query_config()
        .context("update: query service config")?;
    Ok(parse_service_binary_path(
        &config.executable_path.to_string_lossy(),
    ))
}

pub struct ScmPlatform;

impl ScmPlatform {
    fn open(access: ServiceAccess) -> Result<windows_service::service::Service> {
        let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
            .context("update: connect to the service manager")?;
        manager
            .open_service(SERVICE_NAME, access)
            .context("update: open the agent service")
    }

    fn stop_and_wait(service: &windows_service::service::Service) -> Result<()> {
        if service.query_status()?.current_state != ServiceState::Stopped {
            // Stopping an already-stopping service reports an error; the wait
            // below is what decides success.
            let _ = service.stop();
            let deadline = Instant::now() + STOP_TIMEOUT;
            while service.query_status()?.current_state != ServiceState::Stopped {
                if Instant::now() >= deadline {
                    bail!("update: the agent service did not stop within {STOP_TIMEOUT:?}");
                }
                std::thread::sleep(Duration::from_millis(250));
            }
        }
        Ok(())
    }
}

impl Platform for ScmPlatform {
    fn stop_service(&self) -> Result<()> {
        let service = Self::open(ServiceAccess::STOP | ServiceAccess::QUERY_STATUS)?;
        Self::stop_and_wait(&service)
    }

    fn restart_service(&self) -> Result<()> {
        let service =
            Self::open(ServiceAccess::STOP | ServiceAccess::START | ServiceAccess::QUERY_STATUS)?;
        Self::stop_and_wait(&service)?;
        match service.start::<&std::ffi::OsStr>(&[]) {
            Ok(()) => Ok(()),
            Err(windows_service::Error::Winapi(e))
                if e.raw_os_error() == Some(ERROR_SERVICE_ALREADY_RUNNING) =>
            {
                Ok(())
            }
            Err(e) => Err(e).context("update: start the agent service"),
        }
    }
}

/// Launch the apply helper from a copy of the running executable, detached from
/// the service so that stopping the service for the swap does not take the
/// helper down with it.
pub fn spawn_apply_helper(staging_dir: &std::path::Path) -> Result<()> {
    let helper = staging_dir.join("apply-helper.exe");
    if staging_dir.join("recovery.json").exists() {
        // Reuse the known-good helper, rather than copying the failed release
        // currently running in the service over our automatic recovery path.
        if !helper.is_file() {
            let previous = super::apply::prev_path(&installed_binary_path()?);
            std::fs::copy(previous, &helper)
                .context("update: recover helper from previous binary")?;
        }
    } else {
        let current = std::env::current_exe().context("update: locate the running binary")?;
        let _ = std::fs::remove_file(&helper);
        std::fs::copy(&current, &helper).context("update: copy the apply helper")?;
    }
    std::process::Command::new(&helper)
        .arg("--apply-update")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .creation_flags(HELPER_CREATION_FLAGS)
        .spawn()
        .context("update: launch the apply helper")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binary_path_handles_quotes_arguments_and_spaces() {
        let want = PathBuf::from("C:\\Program Files\\TRAPD Agent\\trapd-agent.exe");
        assert_eq!(
            parse_service_binary_path("\"C:\\Program Files\\TRAPD Agent\\trapd-agent.exe\" --x"),
            want
        );
        assert_eq!(
            parse_service_binary_path("C:\\Program Files\\TRAPD Agent\\trapd-agent.exe /arg"),
            want
        );
        assert_eq!(
            parse_service_binary_path("  C:\\Program Files\\TRAPD Agent\\TRAPD-AGENT.EXE "),
            PathBuf::from("C:\\Program Files\\TRAPD Agent\\TRAPD-AGENT.EXE")
        );
    }
}
