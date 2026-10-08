//! File reader: glob expansion, inode tracking, rotation, truncation.
//!
//! The state machine is synchronous (`std::fs`) so rotation cases can be
//! unit-tested without a runtime. The collector loop polls it on a timer
//! (250 ms). inotify is not used: NFS, overlayfs and many containers do
//! not deliver it, and a missed event would stall the tail. Polling plus
//! inode identity is the reliable path.
//!
//! Resume rules, in order:
//!
//! 1. Same `(dev, inode)`, `size >= offset` → append, continue from offset.
//! 2. Same `(dev, inode)`, `size < offset` → copytruncate; restart at 0.
//! 3. Same inode, fingerprint of the first 256 bytes changed → rewritten
//!    in place; restart at 0.
//! 4. Path exists with a **new** inode → logrotate rename+create. Drain the
//!    still-open previous handle to EOF (or hunt the rotated file by inode
//!    after a restart), then open the new path from 0.
//! 5. Path never seen → honour `read_from` (`end` by default).

use std::fs::{File, Metadata, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use chrono::Utc;
use tracing::{debug, info};

use crate::config::LogSourceConfig;

use super::checkpoint::{fingerprint, FileCheckpoint, FINGERPRINT_BYTES};
use super::framing::{frame_bytes, RawLine};

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

/// One framed physical line plus the byte offset *after* it was consumed.
#[derive(Debug, Clone)]
pub struct TailedLine {
    pub line: RawLine,
    pub inode: u64,
    pub start_offset: u64,
    pub checkpoint: FileCheckpoint,
    /// Fields resolved from the same open file generation. An empty list
    /// deliberately clears any previous generation's W3C header.
    pub w3c_fields: Option<Arc<Vec<String>>>,
}

/// Open file + cursor for a single path.
pub struct FileTail {
    pub path: PathBuf,
    source: String,
    file: Option<File>,
    /// Inode of the currently open handle (the one we read from, which may
    /// already have been renamed away from `path`).
    open_inode: Option<(u64, u64)>,
    offset: u64,
    fingerprint: String,
    rest: Vec<u8>,
    max_line: usize,
    starts_at_end: bool,
    known: bool,
    /// Path now points at a different inode; switch once the current handle
    /// returns EOF so unread bytes on the rotated file are not dropped.
    pending_switch: Option<((u64, u64), String)>,
    reached_eof: bool,
    w3c_fields: Option<Arc<Vec<String>>>,
}

impl FileTail {
    pub fn new(
        source: &LogSourceConfig,
        path: PathBuf,
        checkpoint: Option<&FileCheckpoint>,
    ) -> Self {
        let mut tail = Self {
            path,
            source: source.name.clone(),
            file: None,
            open_inode: None,
            offset: 0,
            fingerprint: String::new(),
            rest: Vec::new(),
            max_line: source.max_line_bytes.max(256),
            starts_at_end: source.starts_at_end(),
            known: checkpoint.is_some(),
            pending_switch: None,
            reached_eof: false,
            w3c_fields: matches!(
                source.parser.to_ascii_lowercase().as_str(),
                "iis" | "iis_w3c" | "w3c"
            )
            .then(|| Arc::new(Vec::new())),
        };
        if let Some(cp) = checkpoint {
            tail.offset = cp.offset;
            tail.fingerprint = cp.fingerprint.clone();
            tail.open_inode = Some((cp.dev, cp.inode));
        }
        tail
    }

    /// Read newly available physical lines. Handles rotation/truncation.
    pub fn poll(&mut self) -> std::io::Result<Vec<TailedLine>> {
        self.reconcile()?;
        let mut out = self.read_available()?;
        if self.reached_eof && self.pending_switch.is_some() {
            // EOF on the rotated handle: emit a trailing line that never
            // saw a newline, then switch. Dropping `rest` here is how
            // readers silently lose the last record of a rotated file.
            if let Some(rest) = self.take_incomplete() {
                out.push(rest);
            }
            if let Some((ident, fp)) = self.pending_switch.take() {
                self.reopen_at(0, ident, fp)?;
                out.extend(self.read_available()?);
            }
        }
        Ok(out)
    }

    fn take_incomplete(&mut self) -> Option<TailedLine> {
        if self.rest.is_empty() {
            return None;
        }
        let bytes = std::mem::take(&mut self.rest);
        let inode = self.open_inode.map(|(_, i)| i).unwrap_or(0);
        let start_offset = self.offset.saturating_sub(bytes.len() as u64);
        Some(TailedLine {
            line: RawLine {
                original_len: bytes.len(),
                consumed_len: bytes.len(),
                truncated: false,
                bytes,
            },
            inode,
            start_offset,
            checkpoint: self.checkpoint_at(self.offset)?,
            w3c_fields: self.w3c_fields.clone(),
        })
    }

    fn read_available(&mut self) -> std::io::Result<Vec<TailedLine>> {
        self.reached_eof = false;
        let start = self.offset.saturating_sub(self.rest.len() as u64);
        let Some(file) = self.file.as_mut() else {
            return Ok(Vec::new());
        };
        let mut buf = vec![0u8; 64 * 1024];
        let n = match file.read(&mut buf) {
            Ok(0) => {
                self.reached_eof = true;
                return Ok(Vec::new());
            }
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => return Ok(Vec::new()),
            Err(e) => return Err(e),
        };
        let framed = frame_bytes(&buf[..n], self.max_line, &mut self.rest);
        let pos = file.stream_position().unwrap_or(self.offset + n as u64);
        self.offset = pos;
        let inode = self.open_inode.map(|(_, i)| i).unwrap_or(0);
        let template = self
            .checkpoint_at(pos)
            .ok_or_else(|| std::io::Error::other("open log file has no identity"))?;
        let mut cursor = start;
        let mut out = Vec::with_capacity(framed.len());
        for line in framed {
            if let Some(fields) = &mut self.w3c_fields {
                if let Some(header) = line.as_str().strip_prefix("#Fields:") {
                    *fields = Arc::new(header.split_whitespace().map(str::to_string).collect());
                }
            }
            let start_offset = cursor;
            cursor += line.consumed_len as u64;
            let mut checkpoint = template.clone();
            checkpoint.offset = cursor;
            out.push(TailedLine {
                line,
                inode,
                start_offset,
                checkpoint,
                w3c_fields: self.w3c_fields.clone(),
            });
        }
        Ok(out)
    }

    pub fn checkpoint(&self) -> Option<FileCheckpoint> {
        // The physical suffix lives only in memory and must be replayed after
        // a restart. Logical framing may rewind this cursor further.
        self.checkpoint_at(self.offset.saturating_sub(self.rest.len() as u64))
    }

    fn checkpoint_at(&self, offset: u64) -> Option<FileCheckpoint> {
        let (dev, inode) = self.open_inode?;
        Some(FileCheckpoint {
            path: self.path.to_string_lossy().into_owned(),
            dev,
            inode,
            offset,
            size: self
                .file
                .as_ref()
                .and_then(|f| f.metadata().ok().map(|m| m.len()))
                .unwrap_or(self.offset),
            fingerprint: self.fingerprint.clone(),
            updated_at: Utc::now(),
        })
    }

    fn reconcile(&mut self) -> std::io::Result<()> {
        let meta = match std::fs::metadata(&self.path) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // Path gone (rotation in progress). Keep draining the open
                // handle if we have one; otherwise wait for the path to
                // reappear.
                return Ok(());
            }
            Err(e) => return Err(e),
        };
        if !meta.is_file() {
            return Ok(());
        }
        let ident = file_ident(&self.path, &meta);
        let fp = read_fingerprint(&self.path);

        if self.file.is_none() {
            return self.open_fresh(&meta, ident, fp);
        }

        // Handle still open.
        let open_id = self.open_inode;
        if open_id == Some(ident) {
            // Same inode. Detect copytruncate / in-place rewrite.
            if meta.len() < self.offset {
                info!(
                    source = %self.source,
                    path = %self.path.display(),
                    old_offset = self.offset,
                    new_size = meta.len(),
                    "log truncated — restarting at 0"
                );
                return self.reopen_at(0, ident, fp);
            }
            // Fingerprint of the first 256 bytes is only stable once we
            // have consumed past that prefix. On a file still shorter than
            // 256 bytes every append changes the hash of "the first N bytes"
            // because N is the whole file.
            if self.offset >= FINGERPRINT_BYTES as u64
                && !self.fingerprint.is_empty()
                && !fp.is_empty()
                && fp != self.fingerprint
            {
                info!(
                    source = %self.source,
                    path = %self.path.display(),
                    "log fingerprint changed on same inode — restarting at 0"
                );
                return self.reopen_at(0, ident, fp);
            }
            return Ok(());
        }

        // Inode at the path changed: keep draining the open (renamed) handle
        // until EOF, then switch. Unread bytes on the rotated file must not
        // be dropped — that is the whole point of holding the inode.
        if self.pending_switch.is_none() {
            debug!(
                source = %self.source,
                path = %self.path.display(),
                old = ?open_id,
                new = ?ident,
                "log rotated — will switch after draining previous inode"
            );
            self.pending_switch = Some((ident, fp));
        }
        Ok(())
    }

    fn open_fresh(
        &mut self,
        meta: &Metadata,
        ident: (u64, u64),
        fp: String,
    ) -> std::io::Result<()> {
        let mut start = 0u64;
        if let Some(prev) = self.open_inode {
            if prev == ident && self.offset <= meta.len() {
                start = self.offset;
            } else if prev == ident && meta.len() < self.offset {
                start = 0;
            } else if prev != ident {
                // After a restart the path has a new inode. Hunt the old
                // one so we don't lose the tail of the rotated file.
                if let Some(rotated) = hunt_inode(self.path.parent(), prev) {
                    info!(
                        source = %self.source,
                        path = %rotated.display(),
                        "resuming rotated log by inode"
                    );
                    self.open_path(&rotated, self.offset, prev, self.fingerprint.clone())?;
                    // Next poll will drain it; subsequent reconcile opens the
                    // new path once this handle hits EOF. For simplicity we
                    // finish the rotated file here on the next polls via the
                    // still-open handle; the path identity is updated when
                    // we switch. Fall through to also remember the new ident
                    // after the rotated file is exhausted — handled by
                    // reconcile seeing inode mismatch.
                    return Ok(());
                }
                start = 0;
            }
        } else if self.starts_at_end && !self.known {
            start = meta.len();
        }
        self.reopen_at(start, ident, fp)
    }

    fn reopen_at(&mut self, offset: u64, ident: (u64, u64), fp: String) -> std::io::Result<()> {
        let path = self.path.clone();
        self.open_path(&path, offset, ident, fp)
    }

    fn open_path(
        &mut self,
        path: &Path,
        offset: u64,
        ident: (u64, u64),
        fp: String,
    ) -> std::io::Result<()> {
        let mut f = OpenOptions::new().read(true).open(path)?;
        let len = f.metadata()?.len();
        let pos = offset.min(len);
        if self.w3c_fields.is_some() {
            self.w3c_fields = Some(Arc::new(w3c_fields_before(&mut f, pos, self.max_line)?));
        }
        f.seek(SeekFrom::Start(pos))?;
        self.file = Some(f);
        self.open_inode = Some(ident);
        self.offset = pos;
        self.fingerprint = fp;
        self.rest.clear();
        self.known = true;
        Ok(())
    }
}

/// Search backwards for the latest complete directive before the resume
/// cursor. Reading from this handle also works for renamed/rotated logs and
/// prevents borrowing a header from the replacement path. Memory stays bounded
/// even when an untrusted log contains an arbitrarily long physical line.
fn w3c_fields_before(
    file: &mut File,
    mut cursor: u64,
    max_line: usize,
) -> std::io::Result<Vec<String>> {
    let mut carry = Vec::new();
    let mut discard_suffix = false;
    while cursor > 0 {
        let count = cursor.min(64 * 1024) as usize;
        cursor -= count as u64;
        file.seek(SeekFrom::Start(cursor))?;
        let mut bytes = vec![0; count];
        file.read_exact(&mut bytes)?;
        bytes.extend_from_slice(&carry);
        let has_newline = bytes.contains(&b'\n');
        let mut lines = bytes.rsplit(|b| *b == b'\n').peekable();
        let mut first = true;
        let mut prefix = &[][..];
        while let Some(line) = lines.next() {
            if lines.peek().is_none() && cursor > 0 {
                prefix = line;
                break;
            }
            if !(first && discard_suffix) && line.len() <= max_line {
                if let Some(header) = line.strip_prefix(b"#Fields:") {
                    return Ok(String::from_utf8_lossy(header)
                        .split_whitespace()
                        .map(str::to_string)
                        .collect());
                }
            }
            first = false;
        }
        if prefix.len() > max_line || (discard_suffix && !has_newline) {
            carry.clear();
            discard_suffix = true;
        } else {
            carry = prefix.to_vec();
            discard_suffix = false;
        }
    }
    Ok(Vec::new())
}

/// Stable identity of the file at `path`: `(device, inode)` on Unix, `(volume
/// serial, file index)` on Windows. Rotation is detected by this changing while
/// the path stays the same, so it must not depend on anything a growing log
/// changes (size, mtime).
#[cfg(unix)]
fn file_ident(_path: &Path, meta: &Metadata) -> (u64, u64) {
    (meta.dev(), meta.ino())
}

#[cfg(windows)]
fn file_ident(path: &Path, _meta: &Metadata) -> (u64, u64) {
    // `File::open` shares read/write/delete, so asking for the identity never
    // blocks the writer from rotating the file.
    windows_file_id(path).unwrap_or((0, 0))
}

#[cfg(windows)]
fn windows_file_id(path: &Path) -> Option<(u64, u64)> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
    };
    let file = File::open(path).ok()?;
    // SAFETY: a valid handle owned by `file` for the duration of the call, and
    // a zeroed out-parameter of the documented size.
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    let ok = unsafe { GetFileInformationByHandle(file.as_raw_handle() as _, &mut info) };
    (ok != 0).then(|| {
        (
            u64::from(info.dwVolumeSerialNumber),
            (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
        )
    })
}

#[cfg(not(any(unix, windows)))]
fn file_ident(_path: &Path, meta: &Metadata) -> (u64, u64) {
    (0, meta.len())
}

fn read_fingerprint(path: &Path) -> String {
    let mut buf = vec![0u8; FINGERPRINT_BYTES];
    let Ok(mut f) = File::open(path) else {
        return String::new();
    };
    let n = f.read(&mut buf).unwrap_or(0);
    if n == 0 {
        return String::new();
    }
    fingerprint(&buf[..n])
}

/// Look for a file in `dir` whose `(dev, inode)` matches `ident`.
fn hunt_inode(dir: Option<&Path>, ident: (u64, u64)) -> Option<PathBuf> {
    let dir = dir?;
    let rd = std::fs::read_dir(dir).ok()?;
    for ent in rd.flatten() {
        let path = ent.path();
        if !path.is_file() {
            continue;
        }
        let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
        if name.ends_with(".gz")
            || name.ends_with(".xz")
            || name.ends_with(".bz2")
            || name.ends_with(".zip")
            || name.ends_with(".zst")
        {
            continue;
        }
        let Ok(meta) = ent.metadata() else { continue };
        if file_ident(&path, &meta) == ident {
            return Some(path);
        }
    }
    None
}

/// Expand a path that may contain glob characters. Non-glob paths are
/// returned as-is (even if they do not exist yet — the tailer waits).
pub fn expand_paths(pattern: &str, exclude: &[String]) -> Vec<PathBuf> {
    if !is_glob(pattern) {
        return vec![PathBuf::from(pattern)];
    }
    let Ok(glob) = globset::Glob::new(pattern) else {
        return vec![PathBuf::from(pattern)];
    };
    let matcher = glob.compile_matcher();
    let mut excl = globset::GlobSetBuilder::new();
    for e in exclude {
        if let Ok(g) = globset::Glob::new(e) {
            excl.add(g);
        }
    }
    let excl = excl.build().ok();
    let (root, depth) = walk_root(pattern);
    let mut out = Vec::new();
    let walker = walkdir::WalkDir::new(&root)
        .max_depth(depth)
        .follow_links(true);
    for ent in walker.into_iter().filter_map(|e| e.ok()) {
        if !ent.file_type().is_file() {
            continue;
        }
        let path = ent.path();
        if !matcher.is_match(path) {
            continue;
        }
        if let Some(set) = &excl {
            if let Some(name) = path.file_name() {
                if set.is_match(name) {
                    continue;
                }
            }
        }
        out.push(path.to_path_buf());
    }
    out.sort();
    out
}

fn is_glob(p: &str) -> bool {
    p.contains('*') || p.contains('?') || p.contains('[')
}

fn walk_root(pattern: &str) -> (PathBuf, usize) {
    let path = Path::new(pattern);
    let mut root = PathBuf::new();
    let mut depth = 1usize;
    let mut globbed = false;
    for c in path.components() {
        let s = c.as_os_str().to_string_lossy();
        if globbed {
            depth += 1;
            continue;
        }
        if s.contains('*') || s.contains('?') || s.contains('[') {
            globbed = true;
            depth = 1;
            continue;
        }
        root.push(c);
    }
    if root.as_os_str().is_empty() {
        root = PathBuf::from(".");
    }
    (root, depth.max(1))
}

/// Per-source token bucket. `rate == 0` means unlimited.
pub struct RateLimiter {
    rate: f64,
    burst: f64,
    tokens: f64,
    last: std::time::Instant,
}

impl RateLimiter {
    pub fn new(max_eps: u32) -> Self {
        let rate = f64::from(max_eps);
        Self {
            rate,
            burst: (rate * 2.0).max(1.0),
            tokens: (rate * 2.0).max(1.0),
            last: std::time::Instant::now(),
        }
    }

    pub fn allow(&mut self) -> bool {
        if self.rate <= 0.0 {
            return true;
        }
        let now = std::time::Instant::now();
        let dt = now.duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + dt * self.rate).min(self.burst);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::LogSourceConfig;
    use std::io::Write;

    fn tmpdir() -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let d = std::env::temp_dir().join(format!("trapd_logtail_{nanos}"));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn write(path: &Path, s: &str) {
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .unwrap();
        f.write_all(s.as_bytes()).unwrap();
        f.flush().unwrap();
    }

    #[test]
    fn restart_retains_an_incomplete_line() {
        let dir = tmpdir();
        let path = dir.join("app.log");
        write(&path, "complete\nprefix");
        let src =
            LogSourceConfig::file("app", &path.to_string_lossy(), "raw").read_from_beginning();
        let mut tail = FileTail::new(&src, path.clone(), None);
        assert_eq!(tail.poll().unwrap().len(), 1);
        let cp = tail.checkpoint().unwrap();
        assert_eq!(
            cp.offset, 9,
            "un-emitted prefix must remain before the checkpoint"
        );
        drop(tail);
        write(&path, " suffix\n");
        let mut resumed = FileTail::new(&src, path, Some(&cp));
        assert_eq!(resumed.poll().unwrap()[0].line.as_str(), "prefix suffix");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn resumed_w3c_header_search_crosses_chunks_and_skips_oversized_lines() {
        let dir = tmpdir();
        let path = dir.join("iis.log");
        let old = "#Fields: s-ip c-ip\n";
        let current = "#Fields: c-ip s-ip\n";
        // Place a directive across the 64 KiB backwards-reader boundary and
        // a hostile long line before the cursor. Neither changes its meaning.
        let text = format!(
            "{old}{}{current}{}\n",
            "x\n".repeat(32_763),
            "x".repeat(130_000)
        );
        std::fs::write(&path, &text).unwrap();
        let mut file = File::open(&path).unwrap();
        assert_eq!(
            w3c_fields_before(&mut file, text.len() as u64, 256).unwrap(),
            vec!["c-ip", "s-ip"]
        );
        assert_eq!(
            w3c_fields_before(&mut file, old.len() as u64, 256).unwrap(),
            vec!["s-ip", "c-ip"]
        );
        assert!(w3c_fields_before(&mut file, 0, 256).unwrap().is_empty());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn w3c_rotation_uses_each_generation_header_and_clears_missing_headers() {
        let dir = tmpdir();
        let path = dir.join("iis.log");
        std::fs::write(&path, "#Fields: c-ip s-ip\n203.0.113.1 10.0.0.1\n").unwrap();
        let src =
            LogSourceConfig::file("iis", &path.to_string_lossy(), "iis").read_from_beginning();
        let mut tail = FileTail::new(&src, path.clone(), None);
        tail.poll().unwrap();
        let cp = tail.checkpoint().unwrap();
        drop(tail);
        std::fs::rename(&path, dir.join("iis.log.1")).unwrap();
        write(&dir.join("iis.log.1"), "203.0.113.2 10.0.0.2\n");
        write(&path, "10.0.0.3 203.0.113.3\n");
        let mut resumed = FileTail::new(&src, path, Some(&cp));
        let mut lines = Vec::new();
        for _ in 0..4 {
            lines.extend(resumed.poll().unwrap());
        }
        assert_eq!(lines.len(), 2);
        assert_eq!(
            lines[0].w3c_fields.as_ref().unwrap().as_slice(),
            &["c-ip", "s-ip"]
        );
        assert!(
            lines[1].w3c_fields.as_ref().unwrap().is_empty(),
            "replacement log must not inherit the rotated header"
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn physical_lines_have_distinct_end_offsets() {
        let dir = tmpdir();
        let path = dir.join("app.log");
        write(&path, "one\ntwo\r\nprefix");
        let src =
            LogSourceConfig::file("app", &path.to_string_lossy(), "raw").read_from_beginning();
        let mut tail = FileTail::new(&src, path, None);
        let got = tail.poll().unwrap();
        assert_eq!(
            got.iter().map(|r| r.checkpoint.offset).collect::<Vec<_>>(),
            vec![4, 9]
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn rotation_drains_reads_without_complete_lines() {
        let dir = tmpdir();
        let path = dir.join("app.log");
        write(&path, "old\n");
        let mut src =
            LogSourceConfig::file("app", &path.to_string_lossy(), "raw").read_from_beginning();
        src.max_line_bytes = 256 * 1024;
        let mut tail = FileTail::new(&src, path.clone(), None);
        tail.poll().unwrap();
        let long = "x".repeat(100_000);
        write(&path, &format!("{long}\nlast old\n"));
        std::fs::rename(&path, dir.join("app.log.1")).unwrap();
        write(&path, "new\n");
        let mut got = Vec::new();
        for _ in 0..6 {
            got.extend(tail.poll().unwrap().into_iter().map(|r| r.line.as_str()));
        }
        assert_eq!(got, vec![long, "last old".into(), "new".into()]);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn tails_appended_lines_from_beginning() {
        let dir = tmpdir();
        let path = dir.join("app.log");
        write(&path, "one\n");
        let src =
            LogSourceConfig::file("app", &path.to_string_lossy(), "raw").read_from_beginning();
        let mut tail = FileTail::new(&src, path.clone(), None);
        let lines = tail.poll().unwrap();
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].line.as_str(), "one");
        write(&path, "two\n");
        let lines = tail.poll().unwrap();
        assert_eq!(
            lines.iter().map(|l| l.line.as_str()).collect::<Vec<_>>(),
            vec!["two"]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn detects_truncation_and_rereads() {
        let dir = tmpdir();
        let path = dir.join("app.log");
        write(&path, "aaaaaaaa\n");
        let src =
            LogSourceConfig::file("app", &path.to_string_lossy(), "raw").read_from_beginning();
        let mut tail = FileTail::new(&src, path.clone(), None);
        let _ = tail.poll().unwrap();
        std::fs::write(&path, "b\n").unwrap();
        let lines = tail.poll().unwrap();
        assert_eq!(
            lines.iter().map(|l| l.line.as_str()).collect::<Vec<_>>(),
            vec!["b"]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn follows_rename_rotation() {
        let dir = tmpdir();
        let path = dir.join("app.log");
        write(&path, "old\n");
        let src =
            LogSourceConfig::file("app", &path.to_string_lossy(), "raw").read_from_beginning();
        let mut tail = FileTail::new(&src, path.clone(), None);
        let _ = tail.poll().unwrap();
        let rotated = dir.join("app.log.1");
        std::fs::rename(&path, &rotated).unwrap();
        write(&path, "new\n");
        let lines = tail.poll().unwrap();
        assert!(
            lines.iter().any(|l| l.line.as_str() == "new"),
            "expected the new file's line, got {:?}",
            lines.iter().map(|l| l.line.as_str()).collect::<Vec<_>>()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rename_rotation_does_not_drop_unread_bytes() {
        let dir = tmpdir();
        let path = dir.join("app.log");
        write(&path, "old\n");
        let src =
            LogSourceConfig::file("app", &path.to_string_lossy(), "raw").read_from_beginning();
        let mut tail = FileTail::new(&src, path.clone(), None);
        let _ = tail.poll().unwrap();
        // Append while we are not polling, then rotate — the still-open
        // handle must drain these bytes before switching to the new inode.
        write(&path, "tail\n");
        let rotated = dir.join("app.log.1");
        std::fs::rename(&path, &rotated).unwrap();
        write(&path, "new\n");
        let mut got = Vec::new();
        for _ in 0..6 {
            got.extend(
                tail.poll()
                    .unwrap()
                    .into_iter()
                    .map(|l| l.line.as_str().to_string()),
            );
        }
        assert!(
            got.iter().any(|l| l == "tail"),
            "unread bytes on the rotated inode must not be dropped, got {got:?}"
        );
        assert!(
            got.iter().any(|l| l == "new"),
            "must follow the new inode, got {got:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rotation_emits_incomplete_trailing_line() {
        let dir = tmpdir();
        let path = dir.join("app.log");
        write(&path, "old\npartial");
        let src =
            LogSourceConfig::file("app", &path.to_string_lossy(), "raw").read_from_beginning();
        let mut tail = FileTail::new(&src, path.clone(), None);
        let first = tail.poll().unwrap();
        assert_eq!(
            first.iter().map(|l| l.line.as_str()).collect::<Vec<_>>(),
            vec!["old"]
        );
        let rotated = dir.join("app.log.1");
        std::fs::rename(&path, &rotated).unwrap();
        write(&path, "new\n");
        let mut got = Vec::new();
        for _ in 0..6 {
            got.extend(
                tail.poll()
                    .unwrap()
                    .into_iter()
                    .map(|l| l.line.as_str().to_string()),
            );
        }
        assert!(
            got.iter().any(|l| l == "partial"),
            "incomplete last line of a rotated file must be emitted, got {got:?}"
        );
        assert!(got.iter().any(|l| l == "new"), "got {got:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn new_file_starts_at_end_by_default() {
        let dir = tmpdir();
        let path = dir.join("app.log");
        write(&path, "history\n");
        let src = LogSourceConfig::file("app", &path.to_string_lossy(), "raw");
        let mut tail = FileTail::new(&src, path.clone(), None);
        let lines = tail.poll().unwrap();
        assert!(lines.is_empty(), "must not ingest historical lines");
        write(&path, "fresh\n");
        let lines = tail.poll().unwrap();
        assert_eq!(
            lines.iter().map(|l| l.line.as_str()).collect::<Vec<_>>(),
            vec!["fresh"]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn glob_expansion_skips_compressed() {
        let dir = tmpdir();
        write(&dir.join("a.log"), "x\n");
        write(&dir.join("a.log.gz"), "y\n");
        let pat = dir.join("*.log").to_string_lossy().into_owned();
        // `*.log` does not match `a.log.gz`; exclude is belt-and-suspenders.
        let got = expand_paths(&pat, &["*.gz".into()]);
        assert_eq!(got.len(), 1);
        assert!(got[0].ends_with("a.log"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rate_limiter_sheds_after_burst() {
        let mut r = RateLimiter::new(1);
        assert!(r.allow());
        // Burst is 2× rate, so a second immediate allow still passes, a
        // third must fail until tokens refill.
        let _ = r.allow();
        assert!(!r.allow());
    }

    #[test]
    fn resume_from_checkpoint_does_not_replay() {
        let dir = tmpdir();
        let path = dir.join("app.log");
        write(&path, "one\n");
        let src =
            LogSourceConfig::file("app", &path.to_string_lossy(), "raw").read_from_beginning();
        let mut tail = FileTail::new(&src, path.clone(), None);
        let _ = tail.poll().unwrap();
        let cp = tail.checkpoint().unwrap();
        drop(tail);
        write(&path, "two\n");
        let mut tail = FileTail::new(&src, path.clone(), Some(&cp));
        let lines = tail.poll().unwrap();
        assert_eq!(
            lines.iter().map(|l| l.line.as_str()).collect::<Vec<_>>(),
            vec!["two"]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(all(test, windows))]
mod windows_native_tests {
    use super::*;
    use std::io::Write;

    fn ident(path: &Path) -> (u64, u64) {
        file_ident(path, &std::fs::metadata(path).unwrap())
    }

    #[test]
    fn file_identity_survives_growth_but_not_rotation() {
        let dir = std::env::temp_dir().join(format!("trapd-ident-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let log = dir.join("a.log");
        std::fs::write(&log, b"one\n").unwrap();
        let first = ident(&log);
        assert_ne!(first, (0, 0), "a real identity must be available");

        // Appending changes size and mtime, never the identity.
        std::fs::OpenOptions::new()
            .append(true)
            .open(&log)
            .unwrap()
            .write_all(b"two\n")
            .unwrap();
        assert_eq!(ident(&log), first);

        // Rotation: the old file keeps its identity under the new name, and the
        // path now answers with a different one.
        let rotated = dir.join("a.log.1");
        std::fs::rename(&log, &rotated).unwrap();
        std::fs::write(&log, b"fresh\n").unwrap();
        assert_ne!(ident(&log), first, "new file at the same path");
        assert_eq!(ident(&rotated), first, "rotated file keeps its identity");
        assert_eq!(hunt_inode(Some(&dir), first), Some(rotated));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
