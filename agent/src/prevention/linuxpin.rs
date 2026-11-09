//! Directory-anchored file moves for Linux.
//!
//! A path checked against the protected list can be redirected before it is
//! used if an attacker can swap a parent directory. These helpers hold the
//! verified directory open and act relative to it, so a later swap has no effect.

use std::ffi::{CString, OsStr};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use anyhow::{bail, Context, Result};

fn c_bytes(value: &OsStr) -> Result<CString> {
    CString::new(value.as_bytes()).context("path contains a NUL byte")
}

/// Open a canonical directory and confirm the handle really is that directory.
fn open_directory(path: &Path) -> Result<OwnedFd> {
    let c_path = c_bytes(path.as_os_str())?;
    // SAFETY: NUL-terminated path; the returned descriptor is owned below.
    let raw = unsafe {
        libc::open(
            c_path.as_ptr(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if raw < 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("open directory {}", path.display()));
    }
    // SAFETY: successful open returned a descriptor nothing else owns.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    let actual = std::fs::read_link(format!("/proc/self/fd/{raw}")).context("resolve directory")?;
    if actual != path {
        bail!("directory {} was redirected", path.display());
    }
    Ok(fd)
}

fn split(path: &Path) -> Result<(&Path, CString)> {
    let parent = path.parent().context("path has no parent directory")?;
    let name = path.file_name().context("path has no file name")?;
    Ok((parent, c_bytes(name)?))
}

/// A regular file held open through its verified parent directory.
pub struct PinnedFile {
    directory: OwnedFd,
    name: CString,
    pub file: File,
}

impl PinnedFile {
    pub fn pin(path: &Path) -> Result<Self> {
        let (parent, name) = split(path)?;
        let directory = open_directory(parent)?;
        // SAFETY: valid directory descriptor and NUL-terminated name.
        let raw = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        if raw < 0 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("open {}", path.display()));
        }
        // SAFETY: successful openat returned a descriptor nothing else owns.
        let file = unsafe { File::from_raw_fd(raw) };
        if !file.metadata().context("stat target")?.is_file() {
            bail!("not a regular file: {}", path.display());
        }
        Ok(Self {
            directory,
            name,
            file,
        })
    }

    pub fn move_to(&self, destination: &Path) -> Result<()> {
        let c_destination = c_bytes(destination.as_os_str())?;
        // SAFETY: valid directory descriptor and NUL-terminated names.
        let renamed = unsafe {
            libc::renameat(
                self.directory.as_raw_fd(),
                self.name.as_ptr(),
                libc::AT_FDCWD,
                c_destination.as_ptr(),
            )
        };
        if renamed == 0 {
            return Ok(());
        }
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EXDEV) {
            return Err(error).context("move into quarantine");
        }
        self.copy_then_unlink(destination)
    }

    fn copy_then_unlink(&self, destination: &Path) -> Result<()> {
        let mut source = &self.file;
        source.seek(SeekFrom::Start(0)).context("rewind target")?;
        let mut target = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(destination)
            .context("create quarantine copy")?;
        std::io::copy(&mut source, &mut target).context("copy into quarantine")?;
        target.sync_all().context("sync quarantine copy")?;
        // SAFETY: valid directory descriptor and NUL-terminated name.
        if unsafe { libc::unlinkat(self.directory.as_raw_fd(), self.name.as_ptr(), 0) } != 0 {
            return Err(std::io::Error::last_os_error()).context("remove original");
        }
        Ok(())
    }
}

/// Move `source` to `target` without ever replacing an existing file. The
/// target's directory must be canonical; a redirected directory is refused.
pub fn place_new(source: &Path, target: &Path) -> Result<()> {
    let (parent, name) = split(target)?;
    let directory = open_directory(parent)?;
    let c_source = c_bytes(source.as_os_str())?;
    // SAFETY: valid directory descriptor and NUL-terminated names.
    let moved = unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            c_source.as_ptr(),
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if moved == 0 {
        return Ok(());
    }
    let error = std::io::Error::last_os_error();
    if !matches!(
        error.raw_os_error(),
        Some(libc::EXDEV | libc::EINVAL | libc::ENOSYS)
    ) {
        return Err(error).with_context(|| format!("restore to {}", target.display()));
    }
    copy_new(source, &directory, &name)
}

fn copy_new(source: &Path, directory: &OwnedFd, name: &CString) -> Result<()> {
    let mut input = File::open(source).context("open quarantined file")?;
    // SAFETY: valid directory descriptor and NUL-terminated name.
    let raw = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600 as libc::c_uint,
        )
    };
    if raw < 0 {
        return Err(std::io::Error::last_os_error()).context("create restore target");
    }
    // SAFETY: successful openat returned a descriptor nothing else owns.
    let mut output = unsafe { File::from_raw_fd(raw) };
    let mut buffer = [0u8; 65_536];
    loop {
        let count = input.read(&mut buffer).context("read quarantined file")?;
        if count == 0 {
            break;
        }
        output
            .write_all(&buffer[..count])
            .context("write restore target")?;
    }
    output.sync_all().context("sync restore target")?;
    std::fs::remove_file(source).context("remove quarantined copy")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use std::path::PathBuf;

    fn dir() -> PathBuf {
        let path = std::env::temp_dir().join(format!("trapd-pin-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&path).unwrap();
        std::fs::canonicalize(path).unwrap()
    }

    #[test]
    fn a_leaf_symlink_is_refused() {
        let d = dir();
        symlink("/etc/passwd", d.join("link")).unwrap();
        assert!(PinnedFile::pin(&d.join("link")).is_err());
    }

    #[test]
    fn a_symlinked_parent_is_refused() {
        let d = dir();
        std::fs::create_dir(d.join("real")).unwrap();
        std::fs::write(d.join("real/f"), b"x").unwrap();
        symlink(d.join("real"), d.join("alias")).unwrap();
        assert!(PinnedFile::pin(&d.join("alias/f")).is_err());
    }

    #[test]
    fn a_directory_is_refused() {
        let d = dir();
        std::fs::create_dir(d.join("sub")).unwrap();
        assert!(PinnedFile::pin(&d.join("sub")).is_err());
    }

    #[test]
    fn a_pinned_file_moves_even_after_its_parent_is_swapped() {
        let d = dir();
        std::fs::create_dir(d.join("a")).unwrap();
        std::fs::write(d.join("a/f"), b"payload").unwrap();
        let pinned = PinnedFile::pin(&d.join("a/f")).unwrap();
        std::fs::rename(d.join("a"), d.join("moved")).unwrap();
        std::fs::create_dir(d.join("a")).unwrap();
        std::fs::write(d.join("a/f"), b"decoy").unwrap();
        pinned.move_to(&d.join("vault")).unwrap();
        assert_eq!(std::fs::read(d.join("vault")).unwrap(), b"payload");
        assert_eq!(std::fs::read(d.join("a/f")).unwrap(), b"decoy");
        assert!(!d.join("moved/f").exists());
    }

    #[test]
    fn the_cross_device_path_copies_and_removes_the_original() {
        let d = dir();
        std::fs::write(d.join("f"), b"payload").unwrap();
        let pinned = PinnedFile::pin(&d.join("f")).unwrap();
        pinned.copy_then_unlink(&d.join("vault")).unwrap();
        assert_eq!(std::fs::read(d.join("vault")).unwrap(), b"payload");
        assert!(!d.join("f").exists());
    }

    #[test]
    fn place_new_never_replaces_a_file() {
        let d = dir();
        std::fs::write(d.join("s"), b"new").unwrap();
        std::fs::write(d.join("t"), b"keep").unwrap();
        assert!(place_new(&d.join("s"), &d.join("t")).is_err());
        assert_eq!(std::fs::read(d.join("t")).unwrap(), b"keep");
        assert!(d.join("s").exists());
    }

    #[test]
    fn the_copy_fallback_never_replaces_a_file_either() {
        let d = dir();
        std::fs::write(d.join("s"), b"new").unwrap();
        std::fs::write(d.join("t"), b"keep").unwrap();
        let directory = open_directory(&d).unwrap();
        let name = CString::new("t").unwrap();
        assert!(copy_new(&d.join("s"), &directory, &name).is_err());
        assert_eq!(std::fs::read(d.join("t")).unwrap(), b"keep");
    }

    #[test]
    fn place_new_refuses_a_redirected_directory() {
        let d = dir();
        std::fs::create_dir(d.join("real")).unwrap();
        symlink(d.join("real"), d.join("alias")).unwrap();
        std::fs::write(d.join("s"), b"new").unwrap();
        assert!(place_new(&d.join("s"), &d.join("alias/t")).is_err());
        assert!(!d.join("real/t").exists());
    }
}
