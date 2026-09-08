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
    pub offset: u64,
    pub inode: u64,
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
        if out.is_empty() && self.pending_switch.is_some() {
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
        Some(TailedLine {
            line: RawLine {
                original_len: bytes.len(),
                truncated: false,
                bytes,
            },
            offset: self.offset,
            inode,
        })
    }

    fn read_available(&mut self) -> std::io::Result<Vec<TailedLine>> {
        let Some(file) = self.file.as_mut() else {
            return Ok(Vec::new());
        };
        let mut buf = vec![0u8; 64 * 1024];
        let n = match file.read(&mut buf) {
            Ok(0) => return Ok(Vec::new()),
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => return Ok(Vec::new()),
            Err(e) => return Err(e),
        };
        let framed = frame_bytes(&buf[..n], self.max_line, &mut self.rest);
        let pos = file.stream_position().unwrap_or(self.offset + n as u64);
        self.offset = pos;
        let inode = self.open_inode.map(|(_, i)| i).unwrap_or(0);
        Ok(framed
            .into_iter()
            .map(|line| TailedLine {
                line,
                offset: pos,
                inode,
            })
            .collect())
    }

    pub fn checkpoint(&self) -> Option<FileCheckpoint> {
        let (dev, inode) = self.open_inode?;
        Some(FileCheckpoint {
            path: self.path.to_string_lossy().into_owned(),
            dev,
            inode,
            offset: self.offset,
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
        let ident = file_ident(&meta);
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

#[cfg(unix)]
fn file_ident(meta: &Metadata) -> (u64, u64) {
    (meta.dev(), meta.ino())
}

#[cfg(not(unix))]
fn file_ident(meta: &Metadata) -> (u64, u64) {
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
        if file_ident(&meta) == ident {
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
