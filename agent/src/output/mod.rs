use std::env;
use std::path::PathBuf;

use anyhow::Result;
use tokio::fs;
#[cfg(not(target_os = "linux"))]
use tokio::fs::OpenOptions;
use tokio::io::AsyncWriteExt;
use tracing::info;

use crate::schema::AgentEvent;

pub mod siem;

const MAX_FILE_BYTES: u64 = 100 * 1024 * 1024; // 100 MB
const MAX_ROTATED_FILES: u32 = 3;

/// Absolute path to the NDJSON event log, resolved via [`crate::paths`] so it
/// honours `TRAPD_LOG_DIR` (default `/var/log/trapd/events.ndjson`).
#[cfg(not(target_os = "linux"))]
fn log_file() -> PathBuf {
    crate::paths::log_dir().join("events.ndjson")
}

#[derive(Debug, Clone)]
pub enum OutputMode {
    Stdout,
    File,
}

impl OutputMode {
    pub fn from_env() -> Self {
        match env::var("TRAPD_OUTPUT").as_deref() {
            Ok("file") => OutputMode::File,
            _ => OutputMode::Stdout,
        }
    }
}

fn serialize_event(event: &AgentEvent) -> Result<String> {
    let legacy = serde_json::to_value(event)?;
    Ok(serde_json::to_string(&trapd_schema::ocsf::to_ocsf(
        &legacy,
    )?)?)
}

pub async fn write_event(event: &AgentEvent, mode: &OutputMode) -> Result<()> {
    let line = serialize_event(event)?;
    match mode {
        OutputMode::Stdout => {
            let mut out = tokio::io::stdout();
            out.write_all(line.as_bytes()).await?;
            out.write_all(b"\n").await?;
            out.flush().await?;
        }
        OutputMode::File => {
            #[cfg(target_os = "linux")]
            {
                use std::os::fd::AsRawFd;
                let directory = secure_log_dir(crate::paths::log_dir())?;
                // Hold the directory descriptor for the whole operation: even
                // replacement of the configured path cannot redirect rotation.
                for i in 0..=MAX_ROTATED_FILES {
                    let name = if i == 0 {
                        "events.ndjson".into()
                    } else {
                        format!("events.ndjson.{i}")
                    };
                    match open_secure_log(&directory, &name, false) {
                        Ok(_) => {}
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                        Err(e) => return Err(e.into()),
                    }
                }
                let log_file = PathBuf::from(format!(
                    "/proc/self/fd/{}/events.ndjson",
                    directory.as_raw_fd()
                ));
                rotate_if_needed(&log_file).await?;
                let mut file =
                    tokio::fs::File::from_std(secure_log_file(&directory, "events.ndjson")?);
                file.write_all(line.as_bytes()).await?;
                file.write_all(b"\n").await?;
            }
            #[cfg(not(target_os = "linux"))]
            {
                let log_file = log_file();
                ensure_log_dir().await?;
                rotate_if_needed(&log_file).await?;
                let mut file = OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&log_file)
                    .await?;
                file.write_all(line.as_bytes()).await?;
                file.write_all(b"\n").await?;
            }
        }
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
async fn ensure_log_dir() -> Result<()> {
    fs::create_dir_all(crate::paths::log_dir()).await?;
    Ok(())
}

async fn rotate_if_needed(log_file: &std::path::Path) -> Result<()> {
    match fs::metadata(log_file).await {
        Ok(meta) if meta.len() >= MAX_FILE_BYTES => rotate_log(log_file).await,
        _ => Ok(()),
    }
}

/// Shift rotated files: .3 deleted, .2→.3, .1→.2, current→.1
async fn rotate_log(log_file: &std::path::Path) -> Result<()> {
    let base = log_file.display().to_string();
    for i in (1..=MAX_ROTATED_FILES).rev() {
        let src = format!("{base}.{i}");
        if fs::try_exists(&src).await.unwrap_or(false) {
            if i == MAX_ROTATED_FILES {
                fs::remove_file(&src).await?;
            } else {
                let dst = format!("{base}.{}", i + 1);
                fs::rename(&src, &dst).await?;
            }
        }
    }
    if fs::try_exists(log_file).await.unwrap_or(false) {
        fs::rename(log_file, format!("{base}.1")).await?;
        info!("Log rotated: {base} → {base}.1");
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn secure_log_dir(path: &std::path::Path) -> Result<std::fs::File> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    std::fs::create_dir_all(path)?;
    let directory = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(path)?;
    if directory.metadata()?.uid() != unsafe { libc::geteuid() } {
        anyhow::bail!("log directory is not owned by the agent user");
    }
    directory.set_permissions(std::fs::Permissions::from_mode(0o700))?;
    Ok(directory)
}

#[cfg(target_os = "linux")]
fn secure_log_file(directory: &std::fs::File, name: &str) -> Result<std::fs::File> {
    Ok(open_secure_log(directory, name, true)?)
}

#[cfg(target_os = "linux")]
fn open_secure_log(
    directory: &std::fs::File,
    name: &str,
    create: bool,
) -> std::io::Result<std::fs::File> {
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let name = std::ffi::CString::new(name)?;
    let flags = libc::O_WRONLY
        | libc::O_APPEND
        | libc::O_NOFOLLOW
        | libc::O_CLOEXEC
        | libc::O_NONBLOCK
        | if create { libc::O_CREAT } else { 0 };
    // openat pins the parent; O_NOFOLLOW rejects the final symlink. Nonblock
    // ensures a malicious FIFO is rejected by fstat without hanging first.
    let fd = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), flags, 0o600) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let file = unsafe { std::fs::File::from_raw_fd(fd) };
    let meta = file.metadata()?;
    if !meta.is_file() || meta.uid() != unsafe { libc::geteuid() } || meta.nlink() != 1 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "log must be a regular, single-link file owned by the agent user",
        ));
    }
    file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    Ok(file)
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};
    fn scratch() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("trapd-log-security-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&dir).unwrap();
        dir
    }
    #[test]
    fn logs_restrict_existing_files_and_directory() {
        let dir = scratch();
        let path = dir.join("events.ndjson");
        std::fs::write(&path, b"old\n").unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let directory = secure_log_dir(&dir).unwrap();
        let file = secure_log_file(&directory, "events.ndjson").unwrap();
        assert_eq!(file.metadata().unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(
            directory.metadata().unwrap().permissions().mode() & 0o777,
            0o700
        );
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn log_symlinks_do_not_modify_targets() {
        let dir = scratch();
        let target = dir.join("private");
        std::fs::write(&target, b"untouched").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o644)).unwrap();
        symlink(&target, dir.join("events.ndjson")).unwrap();
        let directory = secure_log_dir(&dir).unwrap();
        assert!(secure_log_file(&directory, "events.ndjson").is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"untouched");
        assert_eq!(
            std::fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o644
        );
        let alias = dir.with_extension("alias");
        symlink(&dir, &alias).unwrap();
        assert!(secure_log_dir(&alias).is_err());
        std::fs::remove_file(alias).unwrap();
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn hardlinked_logs_do_not_change_target_permissions() {
        let dir = scratch();
        let target = dir.join("private");
        std::fs::write(&target, b"untouched").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o644)).unwrap();
        std::fs::hard_link(&target, dir.join("events.ndjson")).unwrap();
        let directory = secure_log_dir(&dir).unwrap();
        assert!(secure_log_file(&directory, "events.ndjson").is_err());
        assert_eq!(
            std::fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o644
        );
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[tokio::test]
    async fn rotation_keeps_logs_private_and_new_log_private() {
        use std::os::fd::AsRawFd;
        let dir = scratch();
        let directory = secure_log_dir(&dir).unwrap();
        secure_log_file(&directory, "events.ndjson").unwrap();
        let anchored = PathBuf::from(format!(
            "/proc/self/fd/{}/events.ndjson",
            directory.as_raw_fd()
        ));
        rotate_log(&anchored).await.unwrap();
        assert_eq!(
            std::fs::metadata(dir.join("events.ndjson.1"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            secure_log_file(&directory, "events.ndjson")
                .unwrap()
                .metadata()
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        std::fs::remove_dir_all(dir).unwrap();
    }
}

#[cfg(test)]
mod ocsf_tests {
    use super::*;
    #[test]
    fn local_output_is_ocsf_and_replays_losslessly() {
        let event = AgentEvent::new(
            "agent".into(),
            "host".into(),
            crate::schema::EventClass::Process,
            crate::schema::EventAction::Create,
            crate::schema::Severity::Info,
            crate::schema::EventData::ProcessCreate(crate::schema::ProcessCreateData {
                pid: 42,
                ..Default::default()
            }),
        );
        let wire: serde_json::Value =
            serde_json::from_str(&serialize_event(&event).unwrap()).unwrap();
        assert_eq!(wire["class_uid"], 1007);
        assert_eq!(
            trapd_schema::ocsf::from_ocsf(&wire).unwrap(),
            serde_json::to_value(&event).unwrap()
        );
    }
}
