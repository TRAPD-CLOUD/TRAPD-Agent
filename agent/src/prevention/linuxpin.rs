//! Linux response file transactions. All untrusted names are resolved without
//! symlinks, then accessed relative to retained directory descriptors. Originals
//! are held in private staging until the index commits; no chmod touches them.
use super::quarantine::{QuarantineIndex, QuarantineRecord};
use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use std::{
    ffi::{CStr, CString},
    fs::{self, File, Metadata},
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{ffi::OsStrExt, fs::MetadataExt},
    },
    path::{Component, Path, PathBuf},
    sync::Mutex,
};
use uuid::Uuid;

static TRANSACTION: Mutex<()> = Mutex::new(());
const MAX_BYTES: u64 = 1 << 30;

fn cvt(value: i32) -> std::io::Result<i32> {
    if value < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(value)
    }
}
fn open_at(dir: &File, name: &CStr, flags: i32, mode: u32) -> Result<File> {
    let fd = cvt(unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            mode,
        )
    })?;
    Ok(unsafe { File::from_raw_fd(fd) })
}
fn parent(path: &Path, create: bool) -> Result<(File, CString)> {
    if !path.is_absolute() || path.components().any(|c| matches!(c, Component::ParentDir)) {
        bail!("response path must be absolute without parent traversal");
    }
    let name = CString::new(path.file_name().context("path has no filename")?.as_bytes())?;
    let fd = cvt(unsafe {
        libc::open(
            c"/".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    })?;
    let mut dir = unsafe { File::from_raw_fd(fd) };
    for component in path.parent().context("path has no parent")?.components() {
        if let Component::Normal(part) = component {
            let part = CString::new(part.as_bytes())?;
            if create {
                let result = unsafe { libc::mkdirat(dir.as_raw_fd(), part.as_ptr(), 0o700) };
                if result < 0
                    && std::io::Error::last_os_error().kind() != std::io::ErrorKind::AlreadyExists
                {
                    return Err(std::io::Error::last_os_error().into());
                }
            }
            dir = open_at(&dir, &part, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
        }
    }
    Ok((dir, name))
}
fn rename(from: &File, name: &CStr, to: &File, target: &CStr) -> Result<()> {
    cvt(unsafe {
        libc::renameat2(
            from.as_raw_fd(),
            name.as_ptr(),
            to.as_raw_fd(),
            target.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    })?;
    Ok(())
}
fn unlink(dir: &File, name: &CStr) -> Result<()> {
    cvt(unsafe { libc::unlinkat(dir.as_raw_fd(), name.as_ptr(), 0) })?;
    Ok(())
}
fn regular(file: &File) -> Result<Metadata> {
    let meta = file.metadata()?;
    if !meta.is_file() || meta.nlink() != 1 || meta.len() > MAX_BYTES {
        bail!("quarantine requires a singly-linked regular file of at most 1 GiB");
    }
    Ok(meta)
}
// O_PATH pins even a mode-000 vault object. Reopening its proc descriptor is
// deliberate: it names the retained inode, never the original pathname.
fn open_stored(dir: &File, name: &CStr) -> Result<File> {
    use std::os::unix::fs::PermissionsExt;
    let pinned = open_at(dir, name, libc::O_PATH, 0)?;
    let meta = regular(&pinned)?;
    let path = PathBuf::from(format!("/proc/self/fd/{}", pinned.as_raw_fd()));
    match File::open(&path) {
        Ok(file) => Ok(file),
        Err(error)
            if error.kind() == std::io::ErrorKind::PermissionDenied
                && meta.uid() == unsafe { libc::geteuid() } =>
        {
            // Non-root development agents own their vault but cannot read 000.
            // Restore permissions even if reopening fails. The containing vault
            // remains private throughout, and only the pinned inode is touched.
            fs::set_permissions(&path, fs::Permissions::from_mode(meta.mode() | 0o400))?;
            let opened = File::open(&path);
            fs::set_permissions(&path, fs::Permissions::from_mode(meta.mode()))?;
            Ok(opened?)
        }
        Err(error) => Err(error.into()),
    }
}
// Linux's on-disk POSIX ACL xattr is retained verbatim; no pathname lookup.
fn access_acl(file: &File) -> Result<Option<Vec<u8>>> {
    let mut bytes = vec![0u8; 65536];
    let len = unsafe {
        libc::fgetxattr(
            file.as_raw_fd(),
            c"system.posix_acl_access".as_ptr(),
            bytes.as_mut_ptr().cast(),
            bytes.len(),
        )
    };
    if len < 0 {
        let error = std::io::Error::last_os_error();
        if matches!(error.raw_os_error(), Some(libc::ENODATA | libc::EOPNOTSUPP)) {
            return Ok(None);
        }
        return Err(error).context("read original access ACL");
    }
    bytes.truncate(len as usize);
    Ok(Some(bytes))
}
fn apply_acl(file: &File, acl: Option<&[u8]>) -> Result<()> {
    let result = match acl {
        Some(bytes) => unsafe {
            libc::fsetxattr(
                file.as_raw_fd(),
                c"system.posix_acl_access".as_ptr(),
                bytes.as_ptr().cast(),
                bytes.len(),
                0,
            )
        },
        None => unsafe {
            libc::fremovexattr(file.as_raw_fd(), c"system.posix_acl_access".as_ptr())
        },
    };
    if result < 0 {
        let error = std::io::Error::last_os_error();
        if acl.is_none() && matches!(error.raw_os_error(), Some(libc::ENODATA | libc::EOPNOTSUPP)) {
            return Ok(());
        }
        return Err(error).context("restore access ACL");
    }
    Ok(())
}

fn same(a: &Metadata, b: &Metadata) -> bool {
    a.dev() == b.dev() && a.ino() == b.ino()
}

struct Stage {
    parent: File,
    dir: File,
    name: CString,
}
impl Stage {
    fn new(parent: File) -> Result<Self> {
        let name = CString::new(format!(".trapd-quarantine-{}", Uuid::new_v4()))?;
        cvt(unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) })?;
        let dir = open_at(&parent, &name, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
        let meta = dir.metadata()?;
        if meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o077 != 0 {
            bail!("private quarantine staging directory was replaced");
        }
        Ok(Self { parent, dir, name })
    }
}
impl Drop for Stage {
    fn drop(&mut self) {
        // Never remove contents: a failed rollback keeps its recovery object.
        unsafe {
            libc::unlinkat(
                self.parent.as_raw_fd(),
                self.name.as_ptr(),
                libc::AT_REMOVEDIR,
            );
        }
    }
}
struct Captured {
    stage: Stage,
    name: CString,
    file: File,
    meta: Metadata,
    retained: bool,
    original: PathBuf,
}
impl Captured {
    fn new(path: &Path) -> Result<Self> {
        let (dir, name) = parent(path, false)?;
        let file = open_at(&dir, &name, libc::O_RDONLY, 0)?;
        let meta = regular(&file)?;
        let stage = Stage::new(dir)?;
        rename(&stage.parent, &name, &stage.dir, c"payload")?;
        let captured = Self {
            stage,
            name,
            file,
            meta,
            retained: true,
            original: path.into(),
        };
        // Reopen the moved entry: a replacement between open and rename must
        // be restored unchanged, never hashed, chmodded or deleted.
        let moved = open_at(&captured.stage.dir, c"payload", libc::O_RDONLY, 0)?;
        if !same(&captured.meta, &regular(&moved)?) {
            bail!("quarantine source changed during capture");
        }
        Ok(captured)
    }
    fn discard(&mut self) -> Result<()> {
        unlink(&self.stage.dir, c"payload")?;
        self.retained = false;
        self.stage.parent.sync_all()?;
        Ok(())
    }
}
impl Drop for Captured {
    fn drop(&mut self) {
        if self.retained {
            if let Err(error) = rename(&self.stage.dir, c"payload", &self.stage.parent, &self.name)
            {
                let recovery = self
                    .original
                    .parent()
                    .unwrap_or(Path::new("/"))
                    .join(self.stage.name.to_string_lossy().as_ref())
                    .join("payload");
                tracing::error!(%error, recovery = %recovery.display(), "quarantine rollback blocked; original preserved in private staging");
            }
        }
    }
}
struct Prepared {
    stage: Stage,
    name: CString,
    file: File,
    sha: String,
    published: bool,
}
impl Prepared {
    fn new(
        source: &mut File,
        meta: &Metadata,
        destination: &Path,
        mode: u32,
        owner: Option<(u32, u32)>,
    ) -> Result<Self> {
        let (dir, name) = parent(destination, true)?;
        let stage = Stage::new(dir)?;
        let file = open_at(
            &stage.dir,
            c"payload",
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
            0o600,
        )?;
        let mut prepared = Self {
            stage,
            name,
            file,
            sha: String::new(),
            published: false,
        };
        let mut digest = Sha256::new();
        let mut count = 0u64;
        let mut buf = [0u8; 65536];
        loop {
            let n = source.read(&mut buf)?;
            if n == 0 {
                break;
            }
            count += n as u64;
            if count > MAX_BYTES {
                bail!("quarantine source exceeds copy budget");
            }
            digest.update(&buf[..n]);
            prepared.file.write_all(&buf[..n])?;
        }
        let after = regular(source)?;
        if count != meta.len()
            || after.len() != meta.len()
            || after.mtime() != meta.mtime()
            || after.mtime_nsec() != meta.mtime_nsec()
            || after.ctime() != meta.ctime()
            || after.ctime_nsec() != meta.ctime_nsec()
        {
            bail!("quarantine source changed while copying");
        }
        prepared.sha = hex::encode(digest.finalize());
        if let Some((uid, gid)) = owner {
            cvt(unsafe { libc::fchown(prepared.file.as_raw_fd(), uid, gid) })?;
        }
        // Attributes are applied before publication, through the owned handle.
        cvt(unsafe { libc::fchmod(prepared.file.as_raw_fd(), mode & 0o7777) })?;
        prepared.file.sync_all()?;
        Ok(prepared)
    }
    fn publish(&mut self) -> Result<()> {
        rename(&self.stage.dir, c"payload", &self.stage.parent, &self.name)?;
        self.published = true;
        self.stage.parent.sync_all()?;
        Ok(())
    }
}
impl Drop for Prepared {
    fn drop(&mut self) {
        if !self.published {
            let _ = unlink(&self.stage.dir, c"payload");
        }
    }
}
fn load_index(path: &Path) -> Result<QuarantineIndex> {
    match fs::read(path) {
        Ok(bytes) => Ok(serde_json::from_slice(&bytes).context("invalid quarantine index")?),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(QuarantineIndex::default()),
        Err(e) => Err(e.into()),
    }
}
fn save_index(path: &Path, index: &QuarantineIndex) -> Result<()> {
    crate::paths::write_atomic(path, &serde_json::to_vec_pretty(index)?, 0o600)?;
    Ok(())
}
pub(super) fn quarantine(path: &Path) -> Result<QuarantineRecord> {
    quarantine_at(path, &super::quarantine_dir(), &super::quarantine_index())
}
fn quarantine_at(path: &Path, vault: &Path, index: &Path) -> Result<QuarantineRecord> {
    quarantine_with_commit(path, vault, index, save_index)
}

fn quarantine_with_commit(
    path: &Path,
    vault: &Path,
    index: &Path,
    commit: impl FnOnce(&Path, &QuarantineIndex) -> Result<()>,
) -> Result<QuarantineRecord> {
    let _guard = TRANSACTION.lock().unwrap_or_else(|p| p.into_inner());
    let mut idx = load_index(index)?;
    let mut source = Captured::new(path)?;
    // Rename updates ctime; capture the metadata of the held object now.
    let meta = regular(&source.file)?;
    let acl = access_acl(&source.file)?;
    let id = Uuid::new_v4();
    let stored = vault.join(format!("{id}.bin"));
    let mut prepared = Prepared::new(&mut source.file, &meta, &stored, 0, None)?;
    let record = QuarantineRecord {
        id,
        original_path: path.to_string_lossy().into_owned(),
        stored_path: stored.to_string_lossy().into_owned(),
        sha256: prepared.sha.clone(),
        size_bytes: meta.len(),
        mode: meta.mode(),
        uid: meta.uid(),
        gid: meta.gid(),
        security_descriptor: None,
        access_acl: acl,
        quarantined_at: chrono::Utc::now(),
    };
    prepared.publish()?;
    idx.records.push(record.clone());
    if let Err(error) = commit(index, &idx) {
        // Atomic rename can succeed before directory fsync reports failure.
        // Remove the copy only when the readable index proves it is unreferenced.
        // On an uncertain commit retain both copies rather than strand a record.
        match load_index(index) {
            Ok(persisted) if !persisted.records.iter().any(|r| r.id == id) => {
                unlink(&prepared.stage.parent, &prepared.name)
                    .context("remove unindexed quarantine copy")?;
            }
            _ => {
                tracing::error!(stored = %stored.display(), "quarantine index commit uncertain; retaining vault copy")
            }
        }
        return Err(error);
    }
    // If removing the original fails, the indexed copy remains recoverable and
    // Drop attempts a no-clobber rollback of the original.
    source.discard()?;
    Ok(record)
}
pub(super) fn restore(id: &Uuid) -> Result<QuarantineRecord> {
    restore_at(id, &super::quarantine_index())
}
fn restore_at(id: &Uuid, index: &Path) -> Result<QuarantineRecord> {
    let _guard = TRANSACTION.lock().unwrap_or_else(|p| p.into_inner());
    let mut idx = load_index(index)?;
    let pos = idx
        .records
        .iter()
        .position(|r| &r.id == id)
        .context("unknown quarantine id")?;
    let record = idx.records[pos].clone();
    restore_record(&record, || {
        idx.records.remove(pos);
        save_index(index, &idx)
    })?;
    Ok(record)
}

pub(super) fn restore_record(
    record: &QuarantineRecord,
    commit: impl FnOnce() -> Result<()>,
) -> Result<()> {
    let (dir, name) = parent(Path::new(&record.stored_path), false)?;
    let mut source = open_stored(&dir, &name)?;
    let meta = regular(&source)?;
    let mut prepared = Prepared::new(
        &mut source,
        &meta,
        Path::new(&record.original_path),
        record.mode,
        Some((record.uid, record.gid)),
    )?;
    if prepared.sha != record.sha256 {
        bail!("quarantine content no longer matches its record");
    }
    // Override any inherited default ACL before making the file reachable.
    apply_acl(&prepared.file, record.access_acl.as_deref())?;
    prepared.file.sync_all()?;
    prepared.publish()?;
    // Preserve both the stored object and its index on failure. The caller can
    // resolve the occupied restore destination and retry without losing bytes.
    commit()?;
    // Restoration and index commit succeeded. Cleanup is best-effort: an old
    // immutable vault copy or a failed unlink must not turn a completed restore
    // into a reported failure with its record already removed.
    let cleanup = (|| -> Result<()> {
        let mut flags: libc::c_long = 0;
        if unsafe { libc::ioctl(source.as_raw_fd(), libc::FS_IOC_GETFLAGS, &mut flags) } == 0
            && flags & 0x10 != 0
        {
            flags &= !0x10;
            cvt(unsafe { libc::ioctl(source.as_raw_fd(), libc::FS_IOC_SETFLAGS, &flags) })?;
        }
        unlink(&dir, &name)?;
        dir.sync_all()?;
        Ok(())
    })();
    if let Err(error) = cleanup {
        tracing::warn!(%error, stored = %record.stored_path, "restored file; obsolete vault copy could not be removed");
    }
    Ok(())
}

#[cfg(test)]
pub(super) fn test_move(src: &Path, dst: &Path, quarantine: bool) -> Result<()> {
    let mut source = Captured::new(src)?;
    let meta = regular(&source.file)?;
    let mut prepared = Prepared::new(
        &mut source.file,
        &meta,
        dst,
        if quarantine { 0 } else { meta.mode() },
        None,
    )?;
    prepared.publish()?;
    source.discard()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    struct Sandbox(PathBuf);
    impl Sandbox {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("trapd-q-transaction-{}", Uuid::new_v4()));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
        fn path(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
        fn quarantine(&self) -> QuarantineRecord {
            fs::write(self.path("payload"), b"sample").unwrap();
            quarantine_at(
                &self.path("payload"),
                &self.path("vault"),
                &self.path("index.json"),
            )
            .unwrap()
        }
        fn readable(record: &QuarantineRecord) {
            // Production runs as root. Let the unprivileged test process read
            // its own mode-000 vault object without altering the contents.
            fs::set_permissions(&record.stored_path, fs::Permissions::from_mode(0o600)).unwrap();
        }
    }
    impl Drop for Sandbox {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn sample_acl() -> Vec<u8> {
        let mut acl = 2u32.to_le_bytes().to_vec();
        // owner rw-, named user r--, owning group ---, mask r--, others ---.
        for (tag, perm, id) in [
            (1u16, 6u16, u32::MAX),
            (2, 4, 12345),
            (4, 0, u32::MAX),
            (16, 4, u32::MAX),
            (32, 0, u32::MAX),
        ] {
            acl.extend(tag.to_le_bytes());
            acl.extend(perm.to_le_bytes());
            acl.extend(id.to_le_bytes());
        }
        acl
    }

    #[test]
    fn access_acl_survives_quarantine_without_exposing_the_vault() {
        let dir = Sandbox::new();
        fs::write(dir.path("payload"), b"sample").unwrap();
        let acl = sample_acl();
        apply_acl(&File::open(dir.path("payload")).unwrap(), Some(&acl)).unwrap();
        let record = quarantine_at(
            &dir.path("payload"),
            &dir.path("vault"),
            &dir.path("index.json"),
        )
        .unwrap();
        assert_eq!(record.access_acl.as_deref(), Some(acl.as_slice()));
        assert_eq!(fs::metadata(&record.stored_path).unwrap().mode() & 0o777, 0);
        restore_at(&record.id, &dir.path("index.json")).unwrap();
        assert_eq!(
            access_acl(&File::open(dir.path("payload")).unwrap()).unwrap(),
            Some(acl)
        );
        assert_eq!(
            fs::metadata(dir.path("payload")).unwrap().mode() & 0o777,
            0o640
        );
    }

    #[test]
    fn restore_removes_inherited_acl_when_original_had_none() {
        let dir = Sandbox::new();
        let record = dir.quarantine();
        let mut acl = sample_acl();
        acl[6] = 7; // Directory owner needs search permission in inherited staging directories.
        let parent = File::open(&dir.0).unwrap();
        cvt(unsafe {
            libc::fsetxattr(
                parent.as_raw_fd(),
                c"system.posix_acl_default".as_ptr(),
                acl.as_ptr().cast(),
                acl.len(),
                0,
            )
        })
        .unwrap();
        restore_at(&record.id, &dir.path("index.json")).unwrap();
        assert!(access_acl(&File::open(dir.path("payload")).unwrap())
            .unwrap()
            .is_none());
    }

    #[test]
    #[ignore = "runs as root with only CHOWN and FOWNER in native service-capability acceptance"]
    fn ownership_roundtrip_under_service_capabilities() {
        assert_eq!(unsafe { libc::geteuid() }, 0);
        let dir = Sandbox::new();
        fs::write(dir.path("payload"), b"sample").unwrap();
        let file = File::open(dir.path("payload")).unwrap();
        cvt(unsafe { libc::fchmod(file.as_raw_fd(), 0o644) }).unwrap();
        cvt(unsafe { libc::fchown(file.as_raw_fd(), 12345, 12346) }).unwrap();
        let record = quarantine_at(
            &dir.path("payload"),
            &dir.path("vault"),
            &dir.path("index.json"),
        )
        .unwrap();
        restore_at(&record.id, &dir.path("index.json")).unwrap();
        let meta = fs::metadata(dir.path("payload")).unwrap();
        assert_eq!(
            (meta.uid(), meta.gid(), meta.mode() & 0o777),
            (12345, 12346, 0o644)
        );
    }

    #[test]
    fn transaction_roundtrip_uses_a_fresh_inode_and_clears_index() {
        let dir = Sandbox::new();
        fs::write(dir.path("payload"), b"sample").unwrap();
        let before = fs::metadata(dir.path("payload")).unwrap().ino();
        let record = quarantine_at(
            &dir.path("payload"),
            &dir.path("vault"),
            &dir.path("index.json"),
        )
        .unwrap();
        assert!(!dir.path("payload").exists());
        let stored = fs::metadata(&record.stored_path).unwrap();
        assert_ne!(before, stored.ino());
        assert_eq!(stored.mode() & 0o777, 0);
        restore_at(&record.id, &dir.path("index.json")).unwrap();
        assert_eq!(fs::read(dir.path("payload")).unwrap(), b"sample");
        assert!(load_index(&dir.path("index.json"))
            .unwrap()
            .records
            .is_empty());
        assert!(!Path::new(&record.stored_path).exists());
    }

    #[test]
    fn failed_quarantine_index_commit_restores_original() {
        let dir = Sandbox::new();
        fs::write(dir.path("payload"), b"sample").unwrap();
        let unavailable = PathBuf::from(format!("/proc/trapd-index-{}", Uuid::new_v4()));
        assert!(quarantine_at(&dir.path("payload"), &dir.path("vault"), &unavailable).is_err());
        assert_eq!(fs::read(dir.path("payload")).unwrap(), b"sample");
        assert_eq!(fs::read_dir(dir.path("vault")).unwrap().count(), 0);
    }

    #[test]
    fn uncertain_index_commit_keeps_the_referenced_payload() {
        let dir = Sandbox::new();
        fs::write(dir.path("payload"), b"sample").unwrap();
        let result = quarantine_with_commit(
            &dir.path("payload"),
            &dir.path("vault"),
            &dir.path("index.json"),
            |path, index| {
                save_index(path, index)?;
                // A directory-sync error can be reported after atomic rename.
                bail!("injected post-rename durability failure")
            },
        );
        assert!(result.is_err());
        let index = load_index(&dir.path("index.json")).unwrap();
        assert_eq!(index.records.len(), 1);
        assert!(Path::new(&index.records[0].stored_path).exists());
        assert_eq!(fs::read(dir.path("payload")).unwrap(), b"sample");
    }

    #[test]
    fn occupied_restore_keeps_vault_and_index() {
        let dir = Sandbox::new();
        let record = dir.quarantine();
        fs::write(dir.path("payload"), b"replacement").unwrap();
        assert!(restore_at(&record.id, &dir.path("index.json")).is_err());
        assert_eq!(fs::read(dir.path("payload")).unwrap(), b"replacement");
        assert!(Path::new(&record.stored_path).exists());
        assert_eq!(
            load_index(&dir.path("index.json")).unwrap().records.len(),
            1
        );
    }

    #[test]
    fn failed_restore_index_commit_keeps_vault_and_record() {
        let dir = Sandbox::new();
        let record = dir.quarantine();
        let index = File::open(dir.path("index.json")).unwrap();
        // Read succeeds through this descriptor; creating an atomic-write
        // temporary file in procfs fails for root and unprivileged users alike.
        let unavailable = PathBuf::from(format!("/proc/self/fd/{}", index.as_raw_fd()));
        assert!(restore_at(&record.id, &unavailable).is_err());
        assert!(Path::new(&record.stored_path).exists());
        assert_eq!(
            load_index(&dir.path("index.json")).unwrap().records.len(),
            1
        );
    }

    #[test]
    fn parent_replacement_after_prepare_cannot_redirect_publication() {
        let dir = Sandbox::new();
        fs::write(dir.path("source"), b"sample").unwrap();
        fs::create_dir(dir.path("destination")).unwrap();
        fs::create_dir(dir.path("unrelated")).unwrap();
        let mut source = File::open(dir.path("source")).unwrap();
        let meta = source.metadata().unwrap();
        let mut prepared = Prepared::new(
            &mut source,
            &meta,
            &dir.path("destination/payload"),
            0o600,
            None,
        )
        .unwrap();
        fs::rename(dir.path("destination"), dir.path("moved")).unwrap();
        symlink(dir.path("unrelated"), dir.path("destination")).unwrap();
        prepared.publish().unwrap();
        assert_eq!(fs::read(dir.path("moved/payload")).unwrap(), b"sample");
        assert!(!dir.path("unrelated/payload").exists());
    }

    #[test]
    fn replacement_after_capture_is_never_deleted() {
        let dir = Sandbox::new();
        fs::write(dir.path("source"), b"sample").unwrap();
        let mut captured = Captured::new(&dir.path("source")).unwrap();
        fs::write(dir.path("source"), b"replacement").unwrap();
        captured.discard().unwrap();
        assert_eq!(fs::read(dir.path("source")).unwrap(), b"replacement");
    }

    #[test]
    fn restore_rejects_tampered_vault_contents_and_preserves_record() {
        let dir = Sandbox::new();
        let record = dir.quarantine();
        Sandbox::readable(&record);
        fs::write(&record.stored_path, b"changed").unwrap();
        assert!(restore_at(&record.id, &dir.path("index.json")).is_err());
        assert!(!dir.path("payload").exists());
        assert_eq!(
            load_index(&dir.path("index.json")).unwrap().records.len(),
            1
        );
    }
}
