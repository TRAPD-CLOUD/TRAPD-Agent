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
use std::path::{Path, PathBuf};
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
///
/// An unquoted value ends at the first `.exe` that is a whole token (followed
/// by whitespace or the end), so a directory such as `C:\my.exe.d\` or
/// `C:\tools.executables\` is not cut short. Unquoted paths containing spaces
/// are inherently ambiguous (the CWE-428 shape); the MSI and the CLI install
/// path register quoted values, and [`installed_binary_path`] additionally
/// requires the result to be absolute.
pub fn parse_service_binary_path(raw: &str) -> PathBuf {
    let raw = raw.trim();
    if let Some(rest) = raw.strip_prefix('"') {
        return PathBuf::from(rest.split('"').next().unwrap_or(rest));
    }
    let lower = raw.to_ascii_lowercase(); // ASCII-only: byte offsets are preserved
    let mut from = 0;
    while let Some(i) = lower[from..].find(".exe") {
        let end = from + i + 4;
        if end == raw.len() || raw[end..].starts_with(char::is_whitespace) {
            return PathBuf::from(&raw[..end]);
        }
        from = end;
    }
    PathBuf::from(raw)
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
    let path = parse_service_binary_path(&config.executable_path.to_string_lossy());
    // A relative registration would resolve against the caller's working
    // directory; never accept it as an install target.
    if !path.is_absolute() {
        bail!(
            "update: service binary path {} is not absolute",
            path.display()
        );
    }
    Ok(path)
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

/// Refuse to stage into, copy to, or launch from a directory that anything but
/// `SYSTEM` and `Administrators` can write. The directory normally inherits the
/// private state-directory DACL; this checks the effective result (and the
/// owner, which keeps implicit WRITE_DAC) instead of assuming it.
pub fn verify_private_staging(dir: &Path) -> Result<()> {
    let sddl = crate::winacl::get_file_security(dir)
        .with_context(|| format!("update: read ACL of {}", dir.display()))?;
    if !super::apply::sddl_is_system_admin_only(&sddl) {
        bail!(
            "update: staging directory {} is not private to SYSTEM/Administrators ({sddl}); \
             refusing to run the apply helper from it",
            dir.display()
        );
    }
    Ok(())
}

/// `FILE_SHARE_READ` only: while the handle is open nobody can open the file
/// for writing or delete/rename it.
const SHARE_READ_ONLY: u32 = 0x0000_0001;

/// Open `path` so it cannot be modified or replaced for as long as the handle lives.
fn open_write_locked(path: &Path) -> Result<std::fs::File> {
    use std::os::windows::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .read(true)
        .share_mode(SHARE_READ_ONLY)
        .open(path)
        .with_context(|| format!("update: open {} write-locked", path.display()))
}

fn sha256_of(file: &mut std::fs::File) -> Result<String> {
    use std::io::{Seek, SeekFrom};
    file.seek(SeekFrom::Start(0))?;
    crate::telemetry::image_hash::stream_sha256(&*file, u64::MAX - 1)
        .context("update: hash apply helper")?
        .context("update: apply helper exceeds hash limit")
}

/// Launch the apply helper from a copy of the running executable, detached from
/// the service so that stopping the service for the swap does not take the
/// helper down with it.
///
/// Before launching: the staging directory must be private
/// ([`verify_private_staging`]); the copy is opened with write sharing denied,
/// hashed and compared with its source, and that handle stays open across the
/// spawn so the verified bytes are the ones executed (no check/use window).
pub fn spawn_apply_helper(staging_dir: &Path) -> Result<()> {
    verify_private_staging(staging_dir)?;
    let helper = staging_dir.join("apply-helper.exe");
    let expected = if staging_dir.join("recovery.json").exists() {
        // Reuse the known-good helper, rather than copying the failed release
        // currently running in the service over our automatic recovery path.
        if !helper.is_file() {
            let previous = super::apply::prev_path(&installed_binary_path()?);
            std::fs::copy(&previous, &helper)
                .context("update: recover helper from previous binary")?;
            Some(previous)
        } else {
            None // no independent reference for an existing helper
        }
    } else {
        let current = std::env::current_exe().context("update: locate the running binary")?;
        let _ = std::fs::remove_file(&helper);
        std::fs::copy(&current, &helper).context("update: copy the apply helper")?;
        Some(current)
    };
    // Lock first, verify second: after this point the content cannot change.
    let mut locked = open_write_locked(&helper)?;
    if let Some(source) = expected {
        let mut source_file = std::fs::File::open(&source)
            .with_context(|| format!("update: open {}", source.display()))?;
        if sha256_of(&mut locked)? != sha256_of(&mut source_file)? {
            drop(locked);
            let _ = std::fs::remove_file(&helper);
            bail!("update: apply helper copy does not match its source; not launching it");
        }
    }
    let spawned = std::process::Command::new(&helper)
        .arg("--apply-update")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .creation_flags(HELPER_CREATION_FLAGS)
        .spawn()
        .context("update: launch the apply helper");
    drop(locked);
    spawned.map(|_| ())
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

    #[test]
    fn binary_path_edge_cases() {
        // `.exe` inside a directory name is not the end of the executable.
        assert_eq!(
            parse_service_binary_path("C:\\my.exe.d\\a.exe -x"),
            PathBuf::from("C:\\my.exe.d\\a.exe")
        );
        assert_eq!(
            parse_service_binary_path("C:\\tools.executables\\a.exe"),
            PathBuf::from("C:\\tools.executables\\a.exe")
        );
        // Unterminated quote: everything after it is the path.
        assert_eq!(
            parse_service_binary_path("\"C:\\Program Files\\a.exe"),
            PathBuf::from("C:\\Program Files\\a.exe")
        );
        // No `.exe` at all (e.g. a bare name) is returned unchanged.
        assert_eq!(
            parse_service_binary_path("svchost"),
            PathBuf::from("svchost")
        );
        assert_eq!(parse_service_binary_path(""), PathBuf::from(""));
    }
}
