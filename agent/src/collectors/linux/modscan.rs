//! User-space shared-object load stream (Linux `module_load`, B10).
//!
//! There is no eBPF hook for `dlopen`: a uprobe on it is per-libc fragile, and
//! the loader maps libraries with plain `mmap(PROT_EXEC)`. Rather than add a
//! kernel program, this collector does a bounded periodic diff of
//! `/proc/<pid>/maps`: every executable, file-backed mapping that appeared in a
//! process since the last sweep is a load. Trade-off: a library mapped and
//! unmapped between two sweeps is missed (the memory scanner and eBPF `mmap`
//! stream cover transient injection); in exchange there is no kernel code, no
//! per-libc dependency and a hard CPU bound.
//!
//! Volume is controlled the way the Windows DLL stream does it: only loads
//! from outside the system library roots are shipped (a volume filter, not a
//! verdict; the backend judges them). Everything else is still recorded so it
//! is not re-examined.
//!
//! Bounds (each overflow is counted, never silent):
//!   * per-sweep wall-clock budget; the pid cursor rotates so a slow sweep
//!     cannot starve the tail of the process table;
//!   * `/proc/<pid>/maps` is read at most [`MAX_MAPS_BYTES`];
//!   * at most [`MAX_EVENTS_PER_SWEEP`] events per sweep, the rest counted as
//!     `rate_limit_applied`;
//!   * an (exe, library) pair is shipped once per [`DEDUP_TTL`];
//!   * tracked-state size is capped.
//!
//! `process_start_time` is carried so a load stays attributable to one process
//! generation even after PID reuse.

use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::time::{Duration, Instant};

use anyhow::Result;
use async_trait::async_trait;
use tokio::sync::mpsc::Sender;
use tracing::debug;

use crate::schema::{AgentEvent, EventAction, EventClass, EventData, ModuleLoadData, Severity};
use crate::telemetry::drops::DropReason;
use crate::telemetry::metrics::metrics;

use super::super::Collector;

const SWEEP_INTERVAL: Duration = Duration::from_secs(15);
const SWEEP_BUDGET: Duration = Duration::from_millis(300);
const MAX_MAPS_BYTES: u64 = 2 * 1024 * 1024;
const MAX_EVENTS_PER_SWEEP: usize = 100;
const MAX_TRACKED_PROCS: usize = 16_384;
const MAX_PATHS_PER_PROC: usize = 512;
const MAX_DEDUP: usize = 8_192;
const DEDUP_TTL: Duration = Duration::from_secs(3600);

/// Roots a distribution installs libraries to. A mapping from here is routine.
const SYSTEM_ROOTS: &[&str] = &[
    "/lib/",
    "/lib32/",
    "/lib64/",
    "/usr/lib/",
    "/usr/lib32/",
    "/usr/lib64/",
    "/usr/libexec/",
    "/usr/local/lib/",
    "/usr/bin/",
    "/usr/sbin/",
    "/bin/",
    "/sbin/",
];

/// One load observed in a process generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Load {
    pub pid: i32,
    pub start_time: u64,
    pub uid: u32,
    pub exe: String,
    pub path: String,
}

/// What the sweep needs to know about one process. Abstracted so the diff
/// logic is tested without `/proc`.
#[derive(Debug, Clone)]
pub struct Snapshot {
    pub start_time: u64,
    pub uid: u32,
    pub exe: String,
    pub maps: String,
}

/// Unique executable file-backed mapping paths. Deleted images and memfds are
/// the memory scanner's findings, not loads.
pub fn exec_file_mappings(maps: &str) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for r in super::memscan::parse_maps(maps) {
        if !r.perms.contains('x') || !r.path.starts_with('/') || r.path.ends_with(" (deleted)") {
            continue;
        }
        if seen.insert(r.path.clone()) {
            out.push(r.path);
        }
    }
    out
}

/// Whether a library path is worth shipping (outside the system roots).
pub fn is_notable(path: &str) -> bool {
    !SYSTEM_ROOTS.iter().any(|r| path.starts_with(r))
}

#[derive(Default)]
pub struct Tracker {
    procs: HashMap<(i32, u64), HashSet<String>>,
    dedup: HashMap<(String, String), Instant>,
    cursor: usize,
}

impl Tracker {
    /// Diff one process. First sight records everything and reports the notable
    /// mappings; later sights report only mappings not seen before.
    fn observe(&mut self, pid: i32, snap: &Snapshot, now: Instant, out: &mut Vec<Load>) {
        if self.procs.len() >= MAX_TRACKED_PROCS
            && !self.procs.contains_key(&(pid, snap.start_time))
        {
            metrics().event_dropped(DropReason::RateLimitApplied);
            return;
        }
        let known = self.procs.entry((pid, snap.start_time)).or_default();
        for path in exec_file_mappings(&snap.maps) {
            if path == snap.exe || known.contains(&path) {
                continue;
            }
            if known.len() >= MAX_PATHS_PER_PROC {
                break;
            }
            known.insert(path.clone());
            if !is_notable(&path) {
                continue;
            }
            let key = (snap.exe.clone(), path.clone());
            if self
                .dedup
                .get(&key)
                .is_some_and(|t| now.duration_since(*t) < DEDUP_TTL)
            {
                continue;
            }
            if self.dedup.len() >= MAX_DEDUP {
                self.dedup.retain(|_, t| now.duration_since(*t) < DEDUP_TTL);
            }
            if self.dedup.len() < MAX_DEDUP {
                self.dedup.insert(key, now);
            }
            out.push(Load {
                pid,
                start_time: snap.start_time,
                uid: snap.uid,
                exe: snap.exe.clone(),
                path,
            });
        }
    }

    /// One bounded sweep over `pids`, reading through `read`. Returns the loads
    /// to ship (already capped) and counts everything it sheds.
    pub fn sweep(
        &mut self,
        pids: &[i32],
        budget: Duration,
        now: Instant,
        read: &mut dyn FnMut(i32) -> Option<Snapshot>,
    ) -> Vec<Load> {
        let began = Instant::now();
        let mut out = Vec::new();
        let mut live = HashSet::new();
        let n = pids.len();
        let mut visited = 0;
        if n > 0 {
            self.cursor %= n;
        }
        for i in 0..n {
            if began.elapsed() >= budget {
                debug!(
                    visited,
                    total = n,
                    "modscan: budget exhausted, resuming next sweep"
                );
                break;
            }
            let pid = pids[(self.cursor + i) % n];
            visited += 1;
            if let Some(snap) = read(pid) {
                live.insert((pid, snap.start_time));
                self.observe(pid, &snap, now, &mut out);
            }
        }
        // Only forget processes when the whole table was seen, otherwise a
        // partial sweep would re-report everything it did not reach.
        if visited == n {
            self.procs.retain(|k, _| live.contains(k));
        }
        self.cursor = if n > 0 {
            (self.cursor + visited) % n
        } else {
            0
        };
        if out.len() > MAX_EVENTS_PER_SWEEP {
            for _ in MAX_EVENTS_PER_SWEEP..out.len() {
                metrics().event_dropped(DropReason::RateLimitApplied);
            }
            out.truncate(MAX_EVENTS_PER_SWEEP);
        }
        out
    }
}

/// Map a load to the wire event (`kernel` / `module_load`, same pair the
/// Windows DLL stream uses).
pub fn to_event(agent_id: &str, hostname: &str, l: &Load) -> AgentEvent {
    AgentEvent::new(
        agent_id.to_string(),
        hostname.to_string(),
        EventClass::Kernel,
        EventAction::ModuleLoad,
        Severity::Info,
        EventData::ModuleLoad(ModuleLoadData {
            pid: l.pid,
            uid: l.uid,
            gid: 0,
            username: String::new(),
            name: l.path.rsplit('/').next().unwrap_or(&l.path).to_string(),
            taints: 0,
            path: Some(l.path.clone()),
            process_exe: Some(l.exe.clone()),
            process_start_time: Some(l.start_time),
        }),
    )
}

fn read_snapshot(pid: i32) -> Option<Snapshot> {
    let start_time = crate::telemetry::identity::process_start_time(pid)?;
    let exe = std::fs::read_link(format!("/proc/{pid}/exe"))
        .ok()?
        .to_string_lossy()
        .into_owned();
    let uid = std::fs::metadata(format!("/proc/{pid}")).ok()?.uid();
    let mut maps = String::new();
    std::fs::File::open(format!("/proc/{pid}/maps"))
        .ok()?
        .take(MAX_MAPS_BYTES)
        .read_to_string(&mut maps)
        .ok()?;
    // Re-check the generation: if the pid was reused mid-read the maps belong
    // to a different process.
    if crate::telemetry::identity::process_start_time(pid)? != start_time {
        return None;
    }
    Some(Snapshot {
        start_time,
        uid,
        exe,
        maps,
    })
}

fn list_pids(own: i32) -> Vec<i32> {
    std::fs::read_dir("/proc")
        .map(|rd| {
            rd.flatten()
                .filter_map(|e| e.file_name().to_str().and_then(|s| s.parse::<i32>().ok()))
                .filter(|p| *p != own)
                .collect()
        })
        .unwrap_or_default()
}

#[derive(Default)]
pub struct ModScanCollector;

impl ModScanCollector {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Collector for ModScanCollector {
    fn name(&self) -> &'static str {
        "ModScanCollector"
    }

    async fn run(
        &mut self,
        tx: Sender<AgentEvent>,
        agent_id: String,
        hostname: String,
    ) -> Result<()> {
        let own = std::process::id() as i32;
        let mut tracker = Tracker::default();
        let mut ticker = tokio::time::interval(SWEEP_INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            // Blocking /proc reads stay off the async workers.
            let swept = tokio::task::spawn_blocking(move || {
                let pids = list_pids(own);
                let loads = tracker.sweep(&pids, SWEEP_BUDGET, Instant::now(), &mut read_snapshot);
                (tracker, loads)
            })
            .await;
            let Ok((t, loads)) = swept else {
                metrics().event_dropped(DropReason::InternalError);
                tracker = Tracker::default();
                continue;
            };
            tracker = t;
            for l in loads {
                if tx.send(to_event(&agent_id, &hostname, &l)).await.is_err() {
                    return Ok(());
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAPS: &str = "\
55d0-55d1 r-xp 00000000 08:01 1 /usr/bin/app
7f00-7f10 r-xp 00000000 08:01 2 /usr/lib/x86_64-linux-gnu/libc.so.6
7f20-7f30 r-xp 00000000 08:01 3 /tmp/evil.so
7f20-7f30 r--p 00000000 08:01 3 /tmp/evil.so
7f40-7f50 r-xp 00000000 08:01 4 /opt/vendor/lib/plug.so
7f60-7f70 r-xp 00000000 08:01 5 /dev/shm/gone.so (deleted)
7f80-7f90 r-xp 00000000 00:01 6 /memfd:x (deleted)
7fa0-7fb0 rw-p 00000000 00:00 0
7fc0-7fd0 rw-p 00000000 08:01 7 /var/data.so
";

    fn snap(maps: &str, start: u64) -> Snapshot {
        Snapshot {
            start_time: start,
            uid: 1000,
            exe: "/usr/bin/app".into(),
            maps: maps.into(),
        }
    }

    #[test]
    fn only_exec_file_backed_non_deleted_mappings() {
        let m = exec_file_mappings(MAPS);
        assert_eq!(
            m,
            vec![
                "/usr/bin/app",
                "/usr/lib/x86_64-linux-gnu/libc.so.6",
                "/tmp/evil.so",
                "/opt/vendor/lib/plug.so"
            ]
        );
    }

    #[test]
    fn notable_excludes_system_roots() {
        assert!(!is_notable("/usr/lib/x86_64-linux-gnu/libc.so.6"));
        assert!(!is_notable("/lib64/ld-linux-x86-64.so.2"));
        assert!(is_notable("/tmp/evil.so"));
        assert!(is_notable("/opt/vendor/lib/plug.so"));
        assert!(is_notable("/home/u/.local/lib/x.so"));
        // A look-alike prefix is not a system root.
        assert!(is_notable("/usr/libx/evil.so"));
    }

    fn run(t: &mut Tracker, s: Snapshot, now: Instant) -> Vec<Load> {
        let mut read = |_p: i32| Some(s.clone());
        t.sweep(&[10], Duration::from_secs(1), now, &mut read)
    }

    #[test]
    fn first_sight_reports_notable_then_only_new() {
        let mut t = Tracker::default();
        let now = Instant::now();
        let first = run(&mut t, snap(MAPS, 100), now);
        let paths: Vec<_> = first.iter().map(|l| l.path.as_str()).collect();
        assert_eq!(paths, ["/tmp/evil.so", "/opt/vendor/lib/plug.so"]);
        assert_eq!(first[0].start_time, 100);
        assert_eq!(first[0].exe, "/usr/bin/app");
        assert!(run(&mut t, snap(MAPS, 100), now).is_empty());

        let more = format!("{MAPS}7ff0-8000 r-xp 00000000 08:01 9 /tmp/injected.so\n");
        let next = run(&mut t, snap(&more, 100), now);
        assert_eq!(next.len(), 1);
        assert_eq!(next[0].path, "/tmp/injected.so");
    }

    #[test]
    fn pid_reuse_is_a_new_generation() {
        let mut t = Tracker::default();
        let now = Instant::now();
        assert_eq!(run(&mut t, snap(MAPS, 100), now).len(), 2);
        // Same pid, new start time: seen again, but the (exe, path) dedup keeps
        // the stream quiet within the TTL ...
        assert!(run(&mut t, snap(MAPS, 200), now).is_empty());
        // ... and reports again once it expires.
        let later = now + DEDUP_TTL + Duration::from_secs(1);
        assert_eq!(run(&mut t, snap(MAPS, 300), later).len(), 2);
    }

    #[test]
    fn dead_processes_are_forgotten() {
        let mut t = Tracker::default();
        let now = Instant::now();
        run(&mut t, snap(MAPS, 100), now);
        assert_eq!(t.procs.len(), 1);
        let mut gone = |_p: i32| None;
        t.sweep(&[10], Duration::from_secs(1), now, &mut gone);
        assert!(t.procs.is_empty());
    }

    #[test]
    fn per_sweep_cap_counts_drops() {
        let mut maps = String::new();
        for i in 0..(MAX_EVENTS_PER_SWEEP + 5) {
            maps.push_str(&format!("{i:x}0-{i:x}f r-xp 0 08:01 {i} /tmp/l{i}.so\n"));
        }
        let before = metrics().drops_for(DropReason::RateLimitApplied);
        let mut t = Tracker::default();
        let out = run(&mut t, snap(&maps, 1), Instant::now());
        assert_eq!(out.len(), MAX_EVENTS_PER_SWEEP);
        assert!(metrics().drops_for(DropReason::RateLimitApplied) >= before + 5);
    }

    #[test]
    fn budget_rotates_cursor_and_keeps_state_on_partial_sweep() {
        let mut t = Tracker::default();
        let now = Instant::now();
        let mut read = |_p: i32| Some(snap(MAPS, 100));
        // Zero budget: nothing visited, nothing forgotten, no panic.
        let out = t.sweep(&[1, 2, 3], Duration::ZERO, now, &mut read);
        assert!(out.is_empty());
        let out = t.sweep(&[1, 2, 3], Duration::from_secs(1), now, &mut read);
        assert!(!out.is_empty());
    }

    #[test]
    fn event_is_kernel_module_load_with_identity() {
        let ev = to_event(
            "a",
            "h",
            &Load {
                pid: 7,
                start_time: 42,
                uid: 0,
                exe: "/usr/bin/app".into(),
                path: "/tmp/evil.so".into(),
            },
        );
        let v = serde_json::to_value(&ev).unwrap();
        assert_eq!(v["class"], "kernel");
        assert_eq!(v["action"], "module_load");
        assert_eq!(v["data"]["path"], "/tmp/evil.so");
        assert_eq!(v["data"]["name"], "evil.so");
        assert_eq!(v["data"]["process_start_time"], 42);
    }
}
