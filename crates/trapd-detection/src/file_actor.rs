//! Kernel-evidenced "who wrote this file" cache (Windows ETW Kernel-File).
//!
//! `ReadDirectoryChangesW` reports that a path changed, never who changed it.
//! A dedicated ETW session on Microsoft-Windows-Kernel-File does carry the
//! process that issued the create/write. The ETW side feeds this cache with
//! `(path, process)` stamps; the filesystem collector looks the changed path
//! up here before falling back to the command-line inference in
//! [`crate::accessor_correlation`].
//!
//! Bounds: at most [`MAX_PATHS`] paths, each stamp valid for [`WINDOW`]; the
//! oldest stamp is evicted first. Only path, pid and process identity are
//! kept, never file content. Nothing is persisted.

// Fed only by the Windows ETW sensor; compiled and tested everywhere.
#![cfg_attr(not(windows), allow(dead_code))]

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use trapd_schema::ProcessLineage;

/// How long a write stamp stays eligible: the directory notification arrives
/// within milliseconds, the slack covers a busy collector.
pub const WINDOW: Duration = Duration::from_secs(30);
pub const MAX_PATHS: usize = 4096;
/// Longest path kept as a key; longer ones are not stamped (counted).
const MAX_PATH_BYTES: usize = 1024;

struct Stamp {
    seen: Instant,
    actor: Arc<ProcessLineage>,
}

#[derive(Default)]
pub struct FileActors {
    by_path: HashMap<String, Stamp>,
    order: VecDeque<String>,
    /// Stamps refused because the path exceeded [`MAX_PATH_BYTES`].
    pub rejected_long: u64,
    /// Stamps evicted to stay within [`MAX_PATHS`].
    pub evicted: u64,
}

/// Case-insensitive, single-separator, verbatim-prefix-free comparison key.
pub fn path_key(path: &str) -> String {
    let p = path.strip_prefix("\\\\?\\").unwrap_or(path);
    p.chars()
        .map(|c| {
            if c == '/' {
                '\\'
            } else {
                c.to_ascii_lowercase()
            }
        })
        .collect()
}

impl FileActors {
    pub fn record(&mut self, path: &str, actor: Arc<ProcessLineage>, now: Instant) {
        if path.len() > MAX_PATH_BYTES {
            self.rejected_long += 1;
            return;
        }
        self.expire(now);
        let key = path_key(path);
        if self
            .by_path
            .insert(key.clone(), Stamp { seen: now, actor })
            .is_none()
        {
            self.order.push_back(key);
        }
        while self.by_path.len() > MAX_PATHS {
            if let Some(old) = self.order.pop_front() {
                if self.by_path.remove(&old).is_some() {
                    self.evicted += 1;
                }
            } else {
                break;
            }
        }
    }

    fn expire(&mut self, now: Instant) {
        while let Some(front) = self.order.front() {
            match self.by_path.get(front) {
                None => {
                    self.order.pop_front();
                }
                Some(s) if now.saturating_duration_since(s.seen) > WINDOW => {
                    let key = self.order.pop_front().unwrap_or_default();
                    self.by_path.remove(&key);
                }
                Some(_) => break,
            }
        }
    }

    pub fn find(&self, path: &str, now: Instant) -> Option<ProcessLineage> {
        let s = self.by_path.get(&path_key(path))?;
        (now.saturating_duration_since(s.seen) <= WINDOW).then(|| (*s.actor).clone())
    }

    pub fn len(&self) -> usize {
        self.by_path.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_path.is_empty()
    }
}

fn global() -> &'static Mutex<FileActors> {
    static G: OnceLock<Mutex<FileActors>> = OnceLock::new();
    G.get_or_init(|| Mutex::new(FileActors::default()))
}

/// Feed one kernel-observed write/create of `path` by `actor`.
pub fn record(path: &str, actor: Arc<ProcessLineage>) {
    if let Ok(mut g) = global().lock() {
        g.record(path, actor, Instant::now());
    }
}

/// The process the kernel saw write `path` within [`WINDOW`], if any.
pub fn lookup(path: &str) -> Option<ProcessLineage> {
    global().lock().ok()?.find(path, Instant::now())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn actor(pid: i32) -> Arc<ProcessLineage> {
        Arc::new(ProcessLineage {
            pid,
            process_start_time: Some(133_000_000_000_000_000 + pid as u64),
            uid: 0,
            gid: 0,
            username: String::new(),
            comm: "evil.exe".into(),
            exe: Some("C:\\Users\\a\\evil.exe".into()),
            cmdline: None,
            ancestors: vec![],
        })
    }

    #[test]
    fn lookup_is_case_and_separator_insensitive_and_keeps_identity() {
        let mut c = FileActors::default();
        let t0 = Instant::now();
        c.record("C:\\Users\\A\\Doc.txt", actor(42), t0);
        let hit = c.find("\\\\?\\c:/users/a/doc.TXT", t0).unwrap();
        assert_eq!(hit.pid, 42);
        assert_eq!(hit.process_start_time, Some(133_000_000_000_000_042));
        assert!(c.find("C:\\Users\\A\\other.txt", t0).is_none());
    }

    #[test]
    fn stamps_expire_and_the_newest_writer_wins() {
        let mut c = FileActors::default();
        let t0 = Instant::now();
        c.record("C:\\a.txt", actor(1), t0);
        c.record("C:\\a.txt", actor(2), t0 + Duration::from_secs(1));
        assert_eq!(
            c.find("C:\\a.txt", t0 + Duration::from_secs(2))
                .unwrap()
                .pid,
            2
        );
        assert!(c
            .find("C:\\a.txt", t0 + WINDOW + Duration::from_secs(5))
            .is_none());
        // Expiry also reclaims memory.
        c.record("C:\\b.txt", actor(3), t0 + WINDOW + Duration::from_secs(60));
        assert_eq!(c.len(), 1);
    }

    #[test]
    fn state_is_bounded_and_evictions_are_counted() {
        let mut c = FileActors::default();
        let t0 = Instant::now();
        for i in 0..(MAX_PATHS + 10) {
            c.record(&format!("C:\\f\\{i}.txt"), actor(1), t0);
        }
        assert_eq!(c.len(), MAX_PATHS);
        assert_eq!(c.evicted, 10);
        assert!(c.find("C:\\f\\0.txt", t0).is_none());
        assert!(c
            .find(&format!("C:\\f\\{}.txt", MAX_PATHS + 9), t0)
            .is_some());
        c.record(&"x".repeat(MAX_PATH_BYTES + 1), actor(1), t0);
        assert_eq!(c.rejected_long, 1);
        assert_eq!(c.len(), MAX_PATHS);
    }
}
