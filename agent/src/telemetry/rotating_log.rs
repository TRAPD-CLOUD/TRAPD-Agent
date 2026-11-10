//! Size-based rotating log file for the Windows service (`agent.log`).
//!
//! A service has no console, so `agent.log` is the only diagnostic channel and
//! would otherwise grow without bound. Files rotate as
//! `agent.log -> agent.log.1 -> ... -> agent.log.<keep>`; the oldest is
//! dropped. The writer is deliberately dependency-free: the policy is a few
//! lines and the agent already avoids pulling a logging framework for it.
//!
//! Failure policy: logging must never take the service down. If a rotation
//! step fails (for example an AV scanner holds `agent.log.1`), the writer keeps
//! appending to the current file and retries after [`RETRY_AFTER_BYTES`] more
//! bytes instead of dropping log lines.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

/// Default rotation threshold.
pub const DEFAULT_MAX_BYTES: u64 = 10 * 1024 * 1024;
/// Default number of rotated generations kept besides the live file.
pub const DEFAULT_KEEP: usize = 3;
/// After a failed rotation, how much more may be written before retrying.
const RETRY_AFTER_BYTES: u64 = 1024 * 1024;

pub struct RotatingFile {
    path: PathBuf,
    file: File,
    size: u64,
    max_bytes: u64,
    keep: usize,
    /// Do not attempt rotation before `size` reaches this (backoff after failure).
    next_rotation_at: u64,
}

fn open_append(path: &Path) -> std::io::Result<File> {
    OpenOptions::new().create(true).append(true).open(path)
}

fn generation(path: &Path, n: usize) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(format!(".{n}"));
    PathBuf::from(s)
}

impl RotatingFile {
    /// Open (creating if needed) `path`; the current size counts towards the
    /// threshold so a restart loop cannot defeat rotation.
    pub fn open(path: &Path, max_bytes: u64, keep: usize) -> std::io::Result<Self> {
        let file = open_append(path)?;
        let size = file.metadata().map(|m| m.len()).unwrap_or(0);
        Ok(Self {
            path: path.to_path_buf(),
            file,
            size,
            max_bytes: max_bytes.max(1),
            keep: keep.max(1),
            next_rotation_at: 0,
        })
    }

    fn rotate(&mut self) -> std::io::Result<()> {
        self.file.flush()?;
        // Shift oldest-first; a missing generation is not an error.
        let _ = std::fs::remove_file(generation(&self.path, self.keep));
        for n in (1..self.keep).rev() {
            let from = generation(&self.path, n);
            if from.exists() {
                std::fs::rename(&from, generation(&self.path, n + 1))?;
            }
        }
        std::fs::rename(&self.path, generation(&self.path, 1))?;
        self.file = open_append(&self.path)?;
        self.size = 0;
        self.next_rotation_at = 0;
        Ok(())
    }
}

impl Write for RotatingFile {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.size.saturating_add(buf.len() as u64) > self.max_bytes
            && self.size >= self.next_rotation_at
            && self.rotate().is_err()
        {
            // Keep logging into the current file; try again later.
            self.next_rotation_at = self.size.saturating_add(RETRY_AFTER_BYTES);
            // A half-finished rotation may have renamed the live file away
            // while the open handle still points at it: that is fine, the
            // handle keeps working and the next success re-creates the path.
        }
        let n = self.file.write(buf)?;
        self.size = self.size.saturating_add(n as u64);
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("trapd-rotlog-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn rotates_at_threshold_and_keeps_bounded_generations() {
        let d = dir("rot");
        let p = d.join("agent.log");
        let mut w = RotatingFile::open(&p, 100, 2).unwrap();
        for i in 0..10 {
            w.write_all(format!("{i}{}\n", "x".repeat(59)).as_bytes())
                .unwrap();
        }
        assert!(p.exists());
        assert!(generation(&p, 1).exists());
        assert!(generation(&p, 2).exists());
        assert!(!generation(&p, 3).exists(), "oldest generation is dropped");
        for f in [&p, &generation(&p, 1), &generation(&p, 2)] {
            assert!(std::fs::metadata(f).unwrap().len() <= 100);
        }
        // Newest line is in the live file.
        assert!(std::fs::read_to_string(&p).unwrap().contains("9xxx"));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn existing_size_counts_towards_threshold() {
        let d = dir("existing");
        let p = d.join("agent.log");
        std::fs::write(&p, vec![b'a'; 90]).unwrap();
        let mut w = RotatingFile::open(&p, 100, 1).unwrap();
        w.write_all(&[b'b'; 20]).unwrap();
        assert_eq!(std::fs::metadata(&p).unwrap().len(), 20);
        assert_eq!(std::fs::metadata(generation(&p, 1)).unwrap().len(), 90);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn failed_rotation_keeps_logging() {
        let d = dir("fail");
        let p = d.join("agent.log");
        let mut w = RotatingFile::open(&p, 10, 1).unwrap();
        // A directory in the way makes the rename of generation 1 fail.
        std::fs::create_dir(generation(&p, 1)).unwrap();
        std::fs::create_dir(generation(&p, 1).join("blocker")).unwrap();
        w.write_all(&[b'a'; 8]).unwrap();
        w.write_all(&[b'b'; 8]).unwrap();
        w.write_all(&[b'c'; 8]).unwrap();
        assert_eq!(std::fs::metadata(&p).unwrap().len(), 24);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn open_failure_is_reported() {
        let d = dir("nofile");
        assert!(RotatingFile::open(&d.join("missing").join("agent.log"), 10, 1).is_err());
        let _ = std::fs::remove_dir_all(&d);
    }
}
