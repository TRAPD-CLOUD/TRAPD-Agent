//! File tailer: inode tracking, rotation, truncation, fingerprints, globs.
//!
//! Design goals (where Falcon-class collectors typically stop at inode+offset):
//!
//! 1. **Hold the fd.** After `logrotate` renames `access.log` → `access.log.1`
//!    the open descriptor still points at the old inode; we drain it to EOF
//!    before switching to the new path. Copytruncate is the other case: same
//!    inode, size < offset → seek 0.
//! 2. **Fingerprints.** Head-of-file + bytes-before-cursor hashes detect inode
//!    reuse and a rewrite that happens to land on the same (dev,ino,offset).
//! 3. **New files from byte 0.** A file that appears after the collector
//!    starts is harvested from the beginning so a newly-created log is not
//!    skipped; files present at start honour `start_at` unless a checkpoint
//!    says otherwise.
//! 4. **Never block the pipeline on a parse.** The caller decides backpressure.

use std::collections::{HashMap, HashSet};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::Instant;

use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tracing::{debug, info, warn};

use crate::config::LogSourceConfig;

use super::checkpoint::{
    head_fingerprint, read_head, read_tail_at, sha256_hex, CheckpointStore, FileCheckpoint,
    TAIL_BYTES,
};
use super::discover::{expand_glob, is_glob};
use super::framing::{Frame, LineAssembler, MultilineFramer};

pub struct FileEngine {
    /// source name → config
    sources: Vec<LogSourceConfig>,
    open: HashMap<String, OpenFile>,
    /// Paths already seen at startup (so later-created files start at 0).
    known_at_boot: HashSet<PathBuf>,
    /// First reconcile uses `start_at`; later-discovered files always start at 0.
    first_pass: bool,
    max_line: usize,
    max_open: usize,
    start_at_beginning: bool,
    max_ml_lines: usize,
    max_ml_bytes: usize,
    exclude: globset::GlobSet,
}

struct OpenFile {
    source_name: String,
    path: PathBuf,
    file: File,
    assembler: LineAssembler,
    multiline: Option<MultilineFramer>,
    parser: String,
    dev: u64,
    ino: u64,
    offset: u64,
    head_fp: String,
    last_read: Instant,
    /// Bytes of the last TAIL_BYTES window, for fingerprint updates.
    tail_window: Vec<u8>,
}

#[derive(Debug)]
pub struct Harvested {
    pub source_name: String,
    pub parser: String,
    pub path: PathBuf,
    pub frame: Frame,
}

impl FileEngine {
    pub fn new(
        sources: Vec<LogSourceConfig>,
        max_line: usize,
        max_open: usize,
        start_at_beginning: bool,
        max_ml_lines: usize,
        max_ml_bytes: usize,
    ) -> Self {
        let mut builder = globset::GlobSetBuilder::new();
        for s in &sources {
            for ex in &s.exclude {
                if let Ok(g) = globset::Glob::new(ex) {
                    builder.add(g);
                }
            }
        }
        let exclude = builder
            .build()
            .unwrap_or_else(|_| globset::GlobSet::empty());
        Self {
            sources,
            open: HashMap::new(),
            known_at_boot: HashSet::new(),
            first_pass: true,
            max_line,
            max_open,
            start_at_beginning,
            max_ml_lines: max_ml_lines.max(2),
            max_ml_bytes: max_ml_bytes.max(1024),
            exclude,
        }
    }

    /// Snapshot currently-open cursors into the checkpoint store.
    pub fn write_checkpoints(&self, store: &mut CheckpointStore) {
        for (key, f) in &self.open {
            store.files.insert(
                key.clone(),
                FileCheckpoint {
                    path: f.path.to_string_lossy().into_owned(),
                    dev: f.dev,
                    ino: f.ino,
                    offset: f.offset,
                    head_fp: f.head_fp.clone(),
                    tail_fp: sha256_hex(&f.tail_window),
                },
            );
        }
    }

    pub async fn reconcile(&mut self, store: &CheckpointStore) {
        let mut desired: HashSet<String> = HashSet::new();
        let file_sources: Vec<LogSourceConfig> = self
            .sources
            .iter()
            .filter(|s| s.kind() == crate::config::logs::SourceKind::File)
            .cloned()
            .collect();

        let first = self.first_pass;
        self.first_pass = false;

        for src in &file_sources {
            let mut paths = expand_glob(&src.path);
            if paths.is_empty() && !is_glob(&src.path) {
                // Path does not exist yet — retry next reconcile.
                continue;
            }
            paths.retain(|p| !self.exclude.is_match(p));
            for path in paths {
                let key = CheckpointStore::file_key(&src.name, &path.to_string_lossy());
                desired.insert(key.clone());
                if self.open.contains_key(&key) {
                    continue;
                }
                if self.open.len() >= self.max_open {
                    self.evict_oldest();
                    if self.open.len() >= self.max_open {
                        warn!(
                            source = %src.name,
                            "log collector: max_open_files reached, deferring {}",
                            path.display()
                        );
                        continue;
                    }
                }
                let seen = self.known_at_boot.contains(&path);
                if !seen {
                    self.known_at_boot.insert(path.clone());
                }
                // Honour `start_at` for files present on the first pass.
                // Anything discovered later is harvested from byte 0 so a
                // newly created log is not skipped.
                let from_start =
                    src.start_at_beginning(self.start_at_beginning) || (!seen && !first);
                match open_one(
                    src,
                    &path,
                    &key,
                    store,
                    from_start,
                    self.max_line,
                    self.max_ml_lines,
                    self.max_ml_bytes,
                )
                .await
                {
                    Ok(opened) => {
                        info!(
                            source = %src.name,
                            path = %path.display(),
                            inode = opened.ino,
                            offset = opened.offset,
                            "log collector: tailing"
                        );
                        self.open.insert(key, opened);
                    }
                    Err(e) => {
                        debug!(
                            source = %src.name,
                            path = %path.display(),
                            error = %e,
                            "log collector: could not open"
                        );
                    }
                }
            }
        }

        self.open.retain(|k, _| desired.contains(k));
    }

    fn evict_oldest(&mut self) {
        if let Some(key) = self
            .open
            .iter()
            .min_by_key(|(_, f)| f.last_read)
            .map(|(k, _)| k.clone())
        {
            self.open.remove(&key);
        }
    }

    /// Read newly available bytes from every open file. Rotation / truncation
    /// is handled per file before the read.
    pub async fn poll(&mut self) -> Vec<Harvested> {
        let keys: Vec<String> = self.open.keys().cloned().collect();
        let mut out = Vec::new();
        for key in keys {
            if let Some(harvested) = self.poll_one(&key).await {
                out.extend(harvested);
            }
        }
        out
    }

    pub fn flush_timeouts(&mut self) -> Vec<Harvested> {
        let mut out = Vec::new();
        for f in self.open.values_mut() {
            if let Some(ml) = f.multiline.as_mut() {
                if let Some(frame) = ml.poll_timeout() {
                    out.push(Harvested {
                        source_name: f.source_name.clone(),
                        parser: f.parser.clone(),
                        path: f.path.clone(),
                        frame,
                    });
                }
            }
        }
        out
    }

    async fn poll_one(&mut self, key: &str) -> Option<Vec<Harvested>> {
        let file = self.open.get_mut(key)?;
        if let Err(e) = handle_rotation_or_truncation(file).await {
            debug!(path = %file.path.display(), error = %e, "log rotation check failed");
        }
        match read_available(file).await {
            Ok(frames) => {
                file.last_read = Instant::now();
                let harvested = frames
                    .into_iter()
                    .map(|frame| Harvested {
                        source_name: file.source_name.clone(),
                        parser: file.parser.clone(),
                        path: file.path.clone(),
                        frame,
                    })
                    .collect();
                Some(harvested)
            }
            Err(e) => {
                warn!(path = %file.path.display(), error = %e, "log read failed — will reopen");
                self.open.remove(key);
                None
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn open_one(
    src: &LogSourceConfig,
    path: &Path,
    key: &str,
    store: &CheckpointStore,
    from_start: bool,
    max_line: usize,
    max_ml_lines: usize,
    max_ml_bytes: usize,
) -> std::io::Result<OpenFile> {
    let meta = tokio::fs::metadata(path).await?;
    let dev = meta.dev();
    let ino = meta.ino();
    let size = meta.len();
    let mut file = File::open(path).await?;
    let head = read_head(path).unwrap_or_default();
    let head_fp = head_fingerprint(&head);

    let mut offset = 0u64;
    if let Some(ckpt) = store.files.get(key) {
        offset = resume_offset(ckpt, dev, ino, size, &head_fp, path);
    } else if !from_start {
        offset = size;
    }

    if offset > size {
        offset = 0;
    }
    file.seek(std::io::SeekFrom::Start(offset)).await?;

    let tail_window = if offset == 0 {
        Vec::new()
    } else {
        read_tail_at(path, offset).unwrap_or_default()
    };

    let multiline = src.multiline.as_ref().and_then(|cfg| {
        MultilineFramer::new(cfg, max_ml_lines, max_ml_bytes)
            .map_err(|e| {
                warn!(source = %src.name, error = %e, "invalid multiline regex — disabled");
                e
            })
            .ok()
    });

    Ok(OpenFile {
        source_name: src.name.clone(),
        path: path.to_path_buf(),
        file,
        assembler: LineAssembler::new(max_line),
        multiline,
        parser: src.parser_name().to_string(),
        dev,
        ino,
        offset,
        head_fp,
        last_read: Instant::now(),
        tail_window,
    })
}

/// Decide where to resume given a checkpoint and the file currently at `path`.
fn resume_offset(
    ckpt: &FileCheckpoint,
    dev: u64,
    ino: u64,
    size: u64,
    head_fp: &str,
    path: &Path,
) -> u64 {
    // Same inode.
    if ckpt.dev == dev && ckpt.ino == ino {
        if size < ckpt.offset {
            info!(path = %path.display(), "log truncated — harvesting from start");
            return 0;
        }
        if !ckpt.tail_fp.is_empty() {
            if let Some(tail) = read_tail_at(path, ckpt.offset) {
                if sha256_hex(&tail) != ckpt.tail_fp {
                    info!(
                        path = %path.display(),
                        "log cursor fingerprint mismatch — harvesting from start"
                    );
                    return 0;
                }
            }
        }
        return ckpt.offset;
    }
    // Inode changed. If the *content* head still matches we likely hit
    // copytruncate that also replaced the inode (rare) or a tool that
    // rewrote in place via rename. Prefer the checkpoint offset only when
    // the new file is at least as long and the head fingerprint matches.
    if !ckpt.head_fp.is_empty() && ckpt.head_fp == head_fp && size >= ckpt.offset {
        debug!(path = %path.display(), "log inode changed but head matches — keeping offset");
        return ckpt.offset;
    }
    info!(
        path = %path.display(),
        old_ino = ckpt.ino,
        new_ino = ino,
        "log rotated — harvesting new inode from start"
    );
    0
}

async fn handle_rotation_or_truncation(file: &mut OpenFile) -> std::io::Result<()> {
    // Truncation / copytruncate on the open fd: fstat size < offset.
    let meta = file.file.metadata().await?;
    if meta.len() < file.offset {
        info!(path = %file.path.display(), "open fd truncated — seeking to 0");
        if let Some(partial) = file.assembler.flush() {
            let _ = partial; // dropped: a cut-off line at truncation is not a record
        }
        file.file.seek(std::io::SeekFrom::Start(0)).await?;
        file.offset = 0;
        file.tail_window.clear();
        file.head_fp = read_head(&file.path)
            .map(|h| head_fingerprint(&h))
            .unwrap_or_default();
        return Ok(());
    }

    // Path now points at a different inode (rename rotation). Drain the old
    // fd first (next read_available will hit EOF); switch once the old file
    // has nothing left. We detect the switch here when the path's inode
    // differs AND the open fd is at EOF (size == offset).
    if let Ok(path_meta) = tokio::fs::metadata(&file.path).await {
        if (path_meta.dev() != file.dev || path_meta.ino() != file.ino) && meta.len() <= file.offset
        {
            info!(
                path = %file.path.display(),
                old_ino = file.ino,
                new_ino = path_meta.ino(),
                "log rotated — switching to new inode"
            );
            if let Some(frame) = file.assembler.flush() {
                let _ = frame;
            }
            if let Some(ml) = file.multiline.as_mut() {
                let _ = ml.flush();
            }
            let mut neu = File::open(&file.path).await?;
            neu.seek(std::io::SeekFrom::Start(0)).await?;
            file.file = neu;
            file.dev = path_meta.dev();
            file.ino = path_meta.ino();
            file.offset = 0;
            file.tail_window.clear();
            file.head_fp = read_head(&file.path)
                .map(|h| head_fingerprint(&h))
                .unwrap_or_default();
        }
    }
    Ok(())
}

async fn read_available(file: &mut OpenFile) -> std::io::Result<Vec<Frame>> {
    let mut buf = vec![0u8; 64 * 1024];
    let mut frames = Vec::new();
    loop {
        match file.file.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => {
                file.offset += n as u64;
                update_tail_window(&mut file.tail_window, &buf[..n]);
                let physical = file.assembler.push(&buf[..n]);
                for line in physical {
                    if let Some(ml) = file.multiline.as_mut() {
                        if let Some(frame) = ml.push(line) {
                            frames.push(frame);
                        }
                    } else {
                        frames.push(line);
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
        // Yield after one 64KiB chunk so a huge catch-up cannot starve
        // other sources in the same tick.
        if frames.len() > 512 {
            break;
        }
    }
    Ok(frames)
}

fn update_tail_window(window: &mut Vec<u8>, chunk: &[u8]) {
    window.extend_from_slice(chunk);
    if window.len() > TAIL_BYTES {
        let drop = window.len() - TAIL_BYTES;
        window.drain(..drop);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::LogSourceConfig;
    use std::fs;
    use std::io::Write as _;
    use std::os::unix::fs::MetadataExt;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "trapd_log_rd_{}_{}_{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            tag
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn src(name: &str, path: &Path) -> LogSourceConfig {
        LogSourceConfig {
            name: name.into(),
            source_type: "file".into(),
            path: path.to_string_lossy().into_owned(),
            parser: "plain".into(),
            unit: String::new(),
            identifier: String::new(),
            multiline: None,
            start_at: "beginning".into(),
            exclude: vec![],
            rate_limit: None,
        }
    }

    #[tokio::test]
    async fn tails_new_lines_and_persists_offset() {
        let dir = scratch("tail");
        let path = dir.join("app.log");
        fs::write(&path, b"one\ntwo\n").unwrap();

        let store = CheckpointStore::default();
        let mut engine = FileEngine::new(vec![src("app", &path)], 1024, 16, true, 100, 65536);
        engine.reconcile(&store).await;
        let got = engine.poll().await;
        let texts: Vec<_> = got.iter().map(|h| h.frame.text.as_str()).collect();
        assert_eq!(texts, ["one", "two"]);

        let mut store = CheckpointStore::default();

        engine.write_checkpoints(&mut store);
        let ckpt = store.files.values().next().unwrap();
        assert_eq!(ckpt.offset, 8);

        fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"three\n")
            .ok();
        // reopen via the still-open fd
        let got = engine.poll().await;
        assert_eq!(
            got.iter()
                .map(|h| h.frame.text.as_str())
                .collect::<Vec<_>>(),
            ["three"]
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn truncation_rereads_from_start() {
        let dir = scratch("trunc");
        let path = dir.join("app.log");
        fs::write(&path, b"aaaa\nbbbb\n").unwrap();
        let store = CheckpointStore::default();
        let mut engine = FileEngine::new(vec![src("app", &path)], 1024, 16, true, 100, 65536);
        engine.reconcile(&store).await;
        let _ = engine.poll().await;

        fs::write(&path, b"cccc\n").unwrap();
        let got = engine.poll().await;
        assert_eq!(
            got.iter()
                .map(|h| h.frame.text.as_str())
                .collect::<Vec<_>>(),
            ["cccc"]
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn rename_rotation_drains_old_then_reads_new() {
        let dir = scratch("rot");
        let path = dir.join("app.log");
        fs::write(&path, b"old1\n").unwrap();
        let store = CheckpointStore::default();
        let mut engine = FileEngine::new(vec![src("app", &path)], 1024, 16, true, 100, 65536);
        engine.reconcile(&store).await;
        let _ = engine.poll().await;

        // Append a line, then rotate before the next poll so the old fd still
        // has unread data.
        fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"old2\n")
            .ok();
        fs::rename(&path, dir.join("app.log.1")).unwrap();
        fs::write(&path, b"new1\n").unwrap();

        let got = engine.poll().await;
        let texts: Vec<_> = got.iter().map(|h| h.frame.text.clone()).collect();
        assert!(
            texts.contains(&"old2".to_string()),
            "must drain renamed inode, got {texts:?}"
        );

        // Next poll (or same poll after EOF) switches to the new inode.
        let got = engine.poll().await;
        let texts: Vec<_> = got.iter().map(|h| h.frame.text.clone()).collect();
        assert!(
            texts.contains(&"new1".to_string()),
            "must pick up the new file, got {texts:?}"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn fingerprint_mismatch_resets_offset() {
        let dir = scratch("fp");
        let path = dir.join("app.log");
        fs::write(&path, b"hello world\n").unwrap();
        let meta = fs::metadata(&path).unwrap();
        let mut store = CheckpointStore::default();
        store.files.insert(
            CheckpointStore::file_key("app", &path.to_string_lossy()),
            FileCheckpoint {
                path: path.to_string_lossy().into_owned(),
                dev: meta.dev(),
                ino: meta.ino(),
                offset: 6, // mid-line, with a tail fingerprint of "hello "
                head_fp: head_fingerprint(b"hello world\n"),
                tail_fp: sha256_hex(b"XXXXXX"), // deliberate mismatch
            },
        );
        let off = resume_offset(
            store.files.values().next().unwrap(),
            meta.dev(),
            meta.ino(),
            meta.len(),
            &head_fingerprint(b"hello world\n"),
            &path,
        );
        assert_eq!(off, 0, "bad tail fingerprint must not resume mid-file");
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn start_at_end_skips_existing_history() {
        let dir = scratch("end");
        let path = dir.join("app.log");
        fs::write(&path, b"history\n").unwrap();
        let mut s = src("app", &path);
        s.start_at = "end".into();
        let store = CheckpointStore::default();
        let mut engine = FileEngine::new(vec![s], 1024, 16, false, 100, 65536);
        engine.reconcile(&store).await;
        let got = engine.poll().await;
        assert!(
            got.is_empty(),
            "start_at=end must skip existing bytes, got {got:?}"
        );
        let _ = fs::remove_dir_all(&dir);
    }
}
