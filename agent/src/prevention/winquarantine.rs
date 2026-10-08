//! Retained Windows handles for quarantine of file paths.
//! Pin every ancestor against replacement/reparse changes and the source against
//! writes/deletion, then copy into a new protected object. Previously granted
//! source ACL handles cannot control the quarantined copy.
//! Copying includes every $DATA stream. A shared 1 GiB size budget is checked
//! before hashing to bound disk amplification from large/sparse inputs.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek};
use std::os::windows::ffi::OsStringExt;
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use windows_sys::Win32::Foundation::{
    GetLastError, SetLastError, ERROR_HANDLE_EOF, ERROR_INSUFFICIENT_BUFFER, ERROR_MORE_DATA,
};
use windows_sys::Win32::Storage::FileSystem::{
    FileDispositionInfo, FileStreamInfo, GetFileInformationByHandle, GetFileInformationByHandleEx,
    SetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION, DELETE, FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_DISPOSITION_INFO, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_READ_ATTRIBUTES, FILE_READ_DATA, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_STREAM_INFO,
    READ_CONTROL,
};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Stream {
    /// Validated native suffix, including the $DATA type, without normalization.
    name: Vec<u16>,
    size: u64,
}

fn stream_path(path: &Path, name: &[u16]) -> PathBuf {
    let mut path = path.as_os_str().to_os_string();
    path.push(std::ffi::OsString::from_wide(name));
    path.into()
}

fn file_information(file: &File) -> Result<BY_HANDLE_FILE_INFORMATION> {
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: retained valid file handle and initialized, correctly sized buffer.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle() as _, &mut info) } == 0 {
        return Err(std::io::Error::last_os_error()).context("identify quarantine stream");
    }
    Ok(info)
}

pub(super) fn file_identity(file: &File) -> Result<(u32, u32, u32)> {
    let info = file_information(file)?;
    Ok((
        info.dwVolumeSerialNumber,
        info.nFileIndexHigh,
        info.nFileIndexLow,
    ))
}

fn require_link_count(file: &File, expected: u32) -> Result<()> {
    let links = file_information(file)?.nNumberOfLinks;
    if links != expected {
        bail!("quarantine source has {links} hard links; expected {expected}");
    }
    Ok(())
}

fn parse_streams(bytes: &[u8]) -> Result<Vec<Stream>> {
    let mut streams = Vec::new();
    let mut offset = 0usize;
    loop {
        let header = bytes
            .get(offset..offset + std::mem::size_of::<FILE_STREAM_INFO>())
            .context("truncated quarantine stream metadata")?;
        // SAFETY: enough readable bytes for the header; Windows uses 8-byte
        // alignment but read_unaligned also supports pure byte-buffer tests.
        let info = unsafe { std::ptr::read_unaligned(header.as_ptr().cast::<FILE_STREAM_INFO>()) };
        let name_start = offset + std::mem::offset_of!(FILE_STREAM_INFO, StreamName);
        let name_end = name_start
            .checked_add(info.StreamNameLength as usize)
            .context("quarantine stream name length overflow")?;
        if info.StreamNameLength % 2 != 0 || info.StreamSize < 0 {
            bail!("invalid quarantine stream metadata");
        }
        let name: Vec<u16> = bytes
            .get(name_start..name_end)
            .context("truncated quarantine stream name")?
            .as_chunks::<2>()
            .0
            .iter()
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
            .collect();
        let unnamed: Vec<u16> = "::$DATA".encode_utf16().collect();
        if name != unnamed {
            let suffix: Vec<u16> = ":$DATA".encode_utf16().collect();
            if name.first() != Some(&(b':' as u16))
                || !name.ends_with(&suffix)
                || name.len() <= 1 + suffix.len()
            {
                bail!("unsupported quarantine stream type");
            }
            // Only native $DATA names are appended. Reject path syntax so this
            // cannot turn into another base file, device or security stream.
            let inner = &name[1..name.len() - suffix.len()];
            if inner.iter().any(|c| matches!(*c, 0 | 47 | 58 | 92)) {
                bail!("invalid quarantine data stream name");
            }
            streams.push(Stream {
                name,
                size: info.StreamSize as u64,
            });
        }
        if info.NextEntryOffset == 0 {
            break;
        }
        let next = offset
            .checked_add(info.NextEntryOffset as usize)
            .context("quarantine stream offset overflow")?;
        if info.NextEntryOffset % 8 != 0 || next < name_end || next <= offset || next >= bytes.len()
        {
            bail!("invalid quarantine stream chain");
        }
        offset = next;
    }
    streams.sort();
    if streams.windows(2).any(|pair| pair[0].name == pair[1].name) {
        bail!("duplicate quarantine data stream");
    }
    Ok(streams)
}

fn stream_snapshot(file: &File) -> Result<Vec<Stream>> {
    // Metadata is untrusted; bound both allocation and each native chain entry.
    const MAX_METADATA_BYTES: usize = 1 << 20;
    let mut buffer = vec![0u64; 512];
    loop {
        // SAFETY: buffer is 8-byte aligned, writable and sized to the API length.
        let (ok, error) = unsafe {
            SetLastError(0);
            let ok = GetFileInformationByHandleEx(
                file.as_raw_handle() as _,
                FileStreamInfo,
                buffer.as_mut_ptr().cast(),
                (buffer.len() * 8) as u32,
            );
            (ok, GetLastError())
        };
        if ok != 0 {
            if error == ERROR_HANDLE_EOF {
                return Ok(Vec::new());
            }
            // SAFETY: buffer allocation covers all of these bytes for its lifetime.
            let bytes =
                unsafe { std::slice::from_raw_parts(buffer.as_ptr().cast(), buffer.len() * 8) };
            return parse_streams(bytes);
        }
        if matches!(error, ERROR_MORE_DATA | ERROR_INSUFFICIENT_BUFFER)
            && buffer.len() * 8 < MAX_METADATA_BYTES
        {
            buffer.resize(buffer.len() * 2, 0);
            continue;
        }
        return Err(std::io::Error::from_raw_os_error(error as i32))
            .context("enumerate quarantine data streams");
    }
}

struct Parents {
    _handles: Vec<File>,
}

impl Parents {
    fn pin(path: &Path) -> Result<Self> {
        let mut handles = Vec::new();
        let ancestors: Vec<_> = path
            .parent()
            .context("quarantine source has no parent")?
            .ancestors()
            .collect();
        // Root first: each next lookup takes place under an already pinned
        // directory. No WRITE/DELETE sharing permits reparse-point replacement.
        for parent in ancestors.into_iter().rev() {
            let file = OpenOptions::new()
                .access_mode(FILE_READ_ATTRIBUTES)
                .share_mode(FILE_SHARE_READ)
                .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
                .open(parent)
                .with_context(|| format!("pin quarantine parent {}", parent.display()))?;
            let metadata = file.metadata()?;
            if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
            {
                bail!(
                    "quarantine parent is not a plain directory: {}",
                    parent.display()
                );
            }
            handles.push(file);
        }
        Ok(Self { _handles: handles })
    }
}

pub(super) struct Source {
    file: File,
    size: u64,
    streams: Vec<(Stream, File)>,
    _parents: Parents,
}

impl Source {
    pub(super) fn pin(path: &Path) -> Result<Self> {
        let parents = Parents::pin(path)?;
        let file = OpenOptions::new()
            .access_mode(FILE_READ_DATA | FILE_READ_ATTRIBUTES | READ_CONTROL | DELETE)
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
            .context("pin quarantine source")?;
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            bail!("quarantine source is not a plain file");
        }
        // Deleting one name cannot contain a file reachable by another link.
        // Query the retained handle, never a separately resolved pathname.
        require_link_count(&file, 1)?;
        let snapshot = stream_snapshot(&file)?;
        super::quarantine::checked_windows_copy_size(
            std::iter::once(metadata.len()).chain(snapshot.iter().map(|stream| stream.size)),
        )?;
        let identity = file_identity(&file)?;
        let mut streams = Vec::with_capacity(snapshot.len());
        for stream in &snapshot {
            // Sharing is per stream. Every ADS reader must share DELETE to
            // allow the retained base handle to set the whole file pending.
            let input = OpenOptions::new()
                .access_mode(FILE_READ_DATA | FILE_READ_ATTRIBUTES)
                .share_mode(FILE_SHARE_READ | FILE_SHARE_DELETE)
                .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
                .open(stream_path(path, &stream.name))
                .context("pin quarantine data stream")?;
            if file_identity(&input)? != identity || input.metadata()?.len() != stream.size {
                bail!("quarantine data stream changed while pinning");
            }
            streams.push((stream.clone(), input));
        }
        if stream_snapshot(&file)? != snapshot {
            bail!("quarantine data streams changed while pinning");
        }
        Ok(Self {
            file,
            size: metadata.len(),
            streams,
            _parents: parents,
        })
    }

    fn mark_deleted(&self, deleted: bool) -> Result<()> {
        let info = FILE_DISPOSITION_INFO {
            DeleteFile: deleted,
        };
        // SAFETY: valid retained handle with DELETE access, correctly sized
        // file-information buffer. This always addresses the opened generation.
        if unsafe {
            SetFileInformationByHandle(
                self.file.as_raw_handle() as _,
                FileDispositionInfo,
                (&info as *const FILE_DISPOSITION_INFO).cast(),
                std::mem::size_of_val(&info) as u32,
            )
        } == 0
        {
            return Err(std::io::Error::last_os_error())
                .context("set quarantine source deletion state");
        }
        Ok(())
    }

    pub(super) fn copy_to(&self, destination: &Path) -> Result<()> {
        require_link_count(&self.file, 1)?;
        let parents = Parents::pin(destination)?;
        let output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .share_mode(FILE_SHARE_READ)
            .open(destination)
            .context("create fresh quarantine object")?;
        let mut deletion_pending = false;
        let result = (|| -> Result<()> {
            crate::winacl::set_file_security(destination, crate::winacl::QUARANTINE_FILE_SDDL)?;
            copy_stream(&self.file, &output, self.size)?;
            for (stream, input) in &self.streams {
                let output = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .share_mode(FILE_SHARE_READ)
                    .open(stream_path(destination, &stream.name))
                    .context("create protected quarantine data stream")?;
                copy_stream(input, &output, stream.size)?;
            }
            self.verify_source(1)?;
            self.mark_deleted(true)?;
            deletion_pending = true;
            // New ADS can be created independently of the main stream sharing
            // mode. Delete-pending closes that opening window; check the final
            // complete list and require no surviving hard links before success.
            // Windows excludes the pending-deletion name from nNumberOfLinks.
            // Share modes alone must not stand in for a hardlink-count check.
            if let Err(error) = self.verify_source(0) {
                self.mark_deleted(false)
                    .context("undo quarantine deletion after source change")?;
                deletion_pending = false;
                return Err(error);
            }
            Ok(())
        })();
        drop(output);
        if result.is_err() && !deletion_pending {
            std::fs::remove_file(destination).context("clean failed quarantine copy")?;
        }
        // Retain parents until all path-based destination operations finish.
        drop(parents);
        if result.is_err() && deletion_pending {
            return result.with_context(|| {
                format!(
                    "source deletion could not be undone; protected copy retained at {}",
                    destination.display()
                )
            });
        }
        result
    }

    fn verify_source(&self, expected_links: u32) -> Result<()> {
        require_link_count(&self.file, expected_links)?;
        let expected: Vec<_> = self
            .streams
            .iter()
            .map(|(stream, _)| stream.clone())
            .collect();
        if stream_snapshot(&self.file)? != expected {
            bail!("quarantine data streams changed during copying");
        }
        Ok(())
    }

    /// Undo the pending source deletion when persistence of the record fails.
    pub(super) fn cancel(&self, destination: &Path) -> Result<()> {
        self.mark_deleted(false)?;
        std::fs::remove_file(destination).context("remove unindexed quarantine copy")
    }
}

fn copy_stream(input: &File, output: &File, expected: u64) -> Result<()> {
    let mut input = input.try_clone()?;
    input.rewind()?;
    let mut output = output.try_clone()?;
    let copied = std::io::copy(&mut input.take(expected + 1), &mut output)
        .context("copy pinned quarantine stream")?;
    if copied != expected {
        bail!("quarantine data stream size changed during copying");
    }
    output.sync_all().context("flush quarantined data stream")
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestDirectory(PathBuf);
    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn native_quarantine_rejects_hardlinks_without_mutating_either_name() {
        let root = TestDirectory(
            std::env::temp_dir().join(format!("trapd-hardlink-{}", uuid::Uuid::new_v4())),
        );
        std::fs::create_dir_all(&root.0).unwrap();
        let original = root.0.join("payload.exe");
        let alias = root.0.join("alias.exe");
        let destination = root.0.join("stored.bin");
        std::fs::write(&original, b"must remain unchanged on refusal").unwrap();
        std::fs::hard_link(&original, &alias).unwrap();
        let identity = file_identity(&File::open(&original).unwrap()).unwrap();
        let security = crate::winacl::get_file_security(&original).unwrap();
        for path in [&original, &alias] {
            let result = Source::pin(path);
            let error = match result {
                Ok(source) => {
                    drop(source);
                    panic!("a multiply linked source must be refused before quarantine mutation")
                }
                Err(error) => error,
            };
            assert!(
                error.to_string().contains("hard link"),
                "unexpected refusal: {error:#}"
            );
        }
        assert!(!destination.exists());
        for path in [&original, &alias] {
            assert_eq!(
                std::fs::read(path).unwrap(),
                b"must remain unchanged on refusal"
            );
            assert_eq!(file_identity(&File::open(path).unwrap()).unwrap(), identity);
            assert_eq!(crate::winacl::get_file_security(path).unwrap(), security);
        }
    }

    #[test]
    #[ignore = "assigns SYSTEM ownership when linking is blocked; requires elevated Windows token"]
    fn native_quarantine_rechecks_late_links_or_proves_sharing_blocks_them() {
        use windows_sys::Win32::Foundation::ERROR_SHARING_VIOLATION;
        let root = TestDirectory(
            std::env::temp_dir().join(format!("trapd-late-link-{}", uuid::Uuid::new_v4())),
        );
        std::fs::create_dir_all(&root.0).unwrap();
        let original = root.0.join("payload.exe");
        let alias = root.0.join("alias.exe");
        let destination = root.0.join("stored.bin");
        std::fs::write(&original, b"payload").unwrap();
        let source = Source::pin(&original).unwrap();
        let linked = match std::fs::hard_link(&original, &alias) {
            Ok(()) => {
                let error = source
                    .copy_to(&destination)
                    .expect_err("late hardlink must prevent quarantine success");
                assert!(
                    error.to_string().contains("hard link"),
                    "unexpected refusal: {error:#}"
                );
                true
            }
            Err(error) => {
                assert_eq!(error.raw_os_error(), Some(ERROR_SHARING_VIOLATION as i32));
                source
                    .copy_to(&destination)
                    .expect("a protected single-link source must remain quarantinable");
                assert_eq!(std::fs::read(&destination).unwrap(), b"payload");
                source.cancel(&destination).unwrap();
                false
            }
        };
        drop(source);
        assert!(!destination.exists());
        assert_eq!(std::fs::read(&original).unwrap(), b"payload");
        if linked {
            assert_eq!(std::fs::read(&alias).unwrap(), b"payload");
        } else {
            assert!(!alias.exists());
        }
    }

    fn stream_metadata(name: &str, size: i64) -> Vec<u8> {
        let name: Vec<_> = name.encode_utf16().collect();
        let mut bytes = vec![0u8; 24 + name.len() * 2];
        bytes[4..8].copy_from_slice(&((name.len() * 2) as u32).to_le_bytes());
        bytes[8..16].copy_from_slice(&size.to_le_bytes());
        for (chunk, character) in bytes[24..].as_chunks_mut::<2>().0.iter_mut().zip(name) {
            chunk.copy_from_slice(&character.to_le_bytes());
        }
        bytes
    }

    #[test]
    fn native_quarantine_stream_metadata_accepts_data_and_rejects_path_syntax() {
        let valid = parse_streams(&stream_metadata(":Zone.Identifier:$DATA", 3)).unwrap();
        assert_eq!(valid[0].size, 3);
        assert!(parse_streams(&stream_metadata("::$DATA", 7))
            .unwrap()
            .is_empty());
        for name in [
            ":../x:$DATA",
            ":x\\y:$DATA",
            ":x:y:$DATA",
            ":x:$INDEX_ALLOCATION",
            ":\0:$DATA",
        ] {
            assert!(parse_streams(&stream_metadata(name, 0)).is_err(), "{name}");
        }
        assert!(parse_streams(&stream_metadata(":x:$DATA", -1)).is_err());
        let mut malformed = stream_metadata(":x:$DATA", 0);
        malformed[..4].copy_from_slice(&8u32.to_le_bytes());
        assert!(parse_streams(&malformed).is_err());
        malformed[..4].copy_from_slice(&0u32.to_le_bytes());
        malformed[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(parse_streams(&malformed).is_err());
    }

    #[test]
    fn native_quarantine_pin_rejects_oversized_primary_before_copying() {
        let root = std::env::temp_dir().join(format!("trapd-size-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("payload");
        File::create(&path).unwrap().set_len((1 << 30) + 1).unwrap();
        assert!(Source::pin(&path).is_err());
        assert!(path.exists());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    #[ignore = "assigns SYSTEM ownership; requires elevated Windows token"]
    fn native_quarantine_late_ads_aborts_without_deleting_source() {
        let root = std::env::temp_dir().join(format!("trapd-late-ads-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("payload");
        let destination = root.join("stored.bin");
        std::fs::write(&path, b"payload").unwrap();
        let source = Source::pin(&path).unwrap();
        std::fs::write(stream_path(&path, "late"), b"must not disappear").unwrap();
        assert!(source.copy_to(&destination).is_err());
        assert!(!destination.exists());
        assert_eq!(
            std::fs::read(stream_path(&path, "late")).unwrap(),
            b"must not disappear"
        );
        drop(source);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn native_quarantine_pins_parent_and_source_against_replacement() {
        let root = std::env::temp_dir().join(format!("trapd-pinned-{}", uuid::Uuid::new_v4()));
        let parent = root.join("parent");
        std::fs::create_dir_all(&parent).unwrap();
        let path = parent.join("payload");
        std::fs::write(&path, b"payload").unwrap();
        let source = Source::pin(&path).unwrap();
        assert!(std::fs::rename(&parent, root.join("old-parent")).is_err());
        assert!(std::fs::rename(&path, parent.join("old-payload")).is_err());
        assert!(std::fs::write(&path, b"replacement").is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"payload");
        drop(source);
        std::fs::rename(&parent, root.join("old-parent")).unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }

    fn stream_path(path: &Path, name: &str) -> std::path::PathBuf {
        let mut path = path.as_os_str().to_os_string();
        path.push(format!(":{name}"));
        path.into()
    }

    #[test]
    #[ignore = "assigns SYSTEM ownership; requires elevated Windows token"]
    fn native_quarantine_copy_preserves_all_ads_and_cancel_keeps_original_streams() {
        let root = std::env::temp_dir().join(format!("trapd-ads-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("payload");
        let destination = root.join("stored.bin");
        std::fs::write(&path, b"payload").unwrap();
        let streams = [
            ("Zone.Identifier", &b"[ZoneTransfer]\r\nZoneId=3\r\n"[..]),
            ("forensic.data", &b"extra forensic bytes"[..]),
            ("empty", &b""[..]),
        ];
        for (name, bytes) in streams {
            std::fs::write(stream_path(&path, name), bytes).unwrap();
        }
        let source = Source::pin(&path).unwrap();
        source.copy_to(&destination).unwrap();
        for (name, bytes) in streams {
            assert_eq!(
                std::fs::read(stream_path(&destination, name)).unwrap(),
                bytes
            );
        }
        source.cancel(&destination).unwrap();
        assert!(!destination.exists());
        for (name, bytes) in streams {
            assert_eq!(std::fs::read(stream_path(&path, name)).unwrap(), bytes);
        }
        source.copy_to(&destination).unwrap();
        drop(source);
        assert!(!path.exists());
        for (name, bytes) in streams {
            assert_eq!(
                std::fs::read(stream_path(&destination, name)).unwrap(),
                bytes
            );
        }
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    #[ignore = "assigns SYSTEM ownership; requires elevated Windows token"]
    fn native_quarantine_old_write_dac_handle_cannot_control_fresh_stored_object() {
        use windows_sys::Win32::Security::Authorization::{SetSecurityInfo, SE_FILE_OBJECT};
        use windows_sys::Win32::Security::{ACL, DACL_SECURITY_INFORMATION};
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_SHARE_DELETE, FILE_SHARE_WRITE, WRITE_DAC,
        };
        let root = std::env::temp_dir().join(format!("trapd-old-acl-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("payload");
        let destination = root.join("stored.bin");
        std::fs::write(&path, b"payload").unwrap();
        let retained = OpenOptions::new()
            .access_mode(READ_CONTROL | WRITE_DAC)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .open(&path)
            .unwrap();
        let source = Source::pin(&path).unwrap();
        source.copy_to(&destination).unwrap();
        let before = crate::winacl::get_file_security(&destination).unwrap();
        // Windows may reject descriptor operations on DELETE_PENDING files.
        // Clear that state for this test while retaining both source and copy,
        // so success must come from the original granted ACL handle itself.
        source.mark_deleted(false).unwrap();
        let original_before = crate::winacl::get_file_security(&path).unwrap();
        // Grant everyone access through the previously granted source handle.
        // This must still affect only the old source object, not its fresh copy.
        let status = unsafe {
            SetSecurityInfo(
                retained.as_raw_handle() as _,
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null::<ACL>(),
                std::ptr::null(),
            )
        };
        assert_eq!(status, 0, "old granted WRITE_DAC handle remains usable");
        assert_ne!(
            crate::winacl::get_file_security(&path).unwrap(),
            original_before,
            "the retained handle must positively change the original DACL"
        );
        assert_eq!(
            crate::winacl::get_file_security(&destination).unwrap(),
            before
        );
        source.mark_deleted(true).unwrap();
        drop(source);
        drop(retained);
        assert_eq!(std::fs::read(&destination).unwrap(), b"payload");
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    #[ignore = "assigns SYSTEM ownership; requires elevated Windows token"]
    fn native_quarantine_private_copy_preserves_cancel_and_source_identity() {
        let root = std::env::temp_dir().join(format!("trapd-copy-{}", uuid::Uuid::new_v4()));
        let stored = root.join("stored");
        std::fs::create_dir_all(&stored).unwrap();
        crate::winacl::set_file_security(&stored, "O:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
            .unwrap();
        let path = root.join("payload");
        let destination = stored.join("payload.bin");
        std::fs::write(&path, b"payload").unwrap();
        let original_security = crate::winacl::get_file_security(&path).unwrap();
        let source = Source::pin(&path).unwrap();
        source.copy_to(&destination).unwrap();
        let security = crate::winacl::get_file_security(&destination).unwrap();
        assert!(
            security.starts_with("O:SY"),
            "private copy must be owned by SYSTEM: {security}"
        );
        assert!(crate::winacl::sddl_is_protected(&security));
        source.cancel(&destination).unwrap();
        assert!(!destination.exists());
        assert_eq!(
            crate::winacl::get_file_security(&path).unwrap(),
            original_security
        );
        source.copy_to(&destination).unwrap();
        drop(source);
        assert!(!path.exists(), "only the retained source is deleted");
        assert_eq!(std::fs::read(&destination).unwrap(), b"payload");
        std::fs::remove_dir_all(root).unwrap();
    }
}
