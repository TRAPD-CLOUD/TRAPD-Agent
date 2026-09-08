//! What the kernel told us directly, kept so it can be compared with what
//! userspace interfaces claim.
//!
//! The eBPF collectors see execs, forks, binds and module loads at the syscall
//! and tracepoint layer, below anything a userland rootkit can hook and below
//! the `/proc` and `/sys` text interfaces a kernel rootkit typically filters.
//! Those sightings are recorded here as they stream past, and the rootkit
//! sweeps read them back as an independent view.
//!
//! Everything is held for a bounded time and in a bounded amount of memory: the
//! value of a sighting decays quickly (a process seen an hour ago has almost
//! certainly exited), and a registry that can grow without limit on a busy host
//! is a liability in a process that must not be the reason a box falls over.

use std::collections::HashMap;
use std::hash::Hash;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

/// How long an observed process stays in the view. Long enough to survive a
/// couple of sweep intervals, short enough that exited processes age out
/// instead of accumulating into false "hidden process" reports.
const PROCESS_TTL: Duration = Duration::from_secs(600);
const PROCESS_CAP: usize = 8_192;

/// Binds are rarer and longer-lived than processes, so they are held longer.
const BIND_TTL: Duration = Duration::from_secs(1_800);
const BIND_CAP: usize = 1_024;

/// Module load sightings are held long enough to outlive several sweeps but not
/// indefinitely: a module that loaded and was legitimately removed before any
/// sweep could list it is indistinguishable from one that hid itself, and a
/// long TTL would keep that ambiguity alive for a day.
const MODULE_TTL: Duration = Duration::from_secs(3_600);
const MODULE_CAP: usize = 512;

/// A bounded, expiring set of sightings.
#[derive(Debug)]
struct Recent<K: Eq + Hash + Clone, V> {
    ttl: Duration,
    cap: usize,
    entries: HashMap<K, (Instant, V)>,
}

impl<K: Eq + Hash + Clone, V: Clone> Recent<K, V> {
    fn new(ttl: Duration, cap: usize) -> Self {
        Self {
            ttl,
            cap,
            entries: HashMap::new(),
        }
    }

    fn insert(&mut self, key: K, value: V, now: Instant) {
        self.prune(now);
        if self.entries.len() >= self.cap && !self.entries.contains_key(&key) {
            // Full: the oldest sighting is the least useful one to keep.
            if let Some(oldest) = self
                .entries
                .iter()
                .min_by_key(|(_, (seen, _))| *seen)
                .map(|(k, _)| k.clone())
            {
                self.entries.remove(&oldest);
            }
        }
        self.entries.insert(key, (now, value));
    }

    fn prune(&mut self, now: Instant) {
        let ttl = self.ttl;
        self.entries
            .retain(|_, (seen, _)| now.duration_since(*seen) <= ttl);
    }

    fn snapshot(&self, now: Instant) -> Vec<(K, V)> {
        self.entries
            .iter()
            .filter(|(_, (seen, _))| now.duration_since(*seen) <= self.ttl)
            .map(|(k, (_, v))| (k.clone(), v.clone()))
            .collect()
    }
}

/// A process the kernel told us about.
#[derive(Debug, Clone)]
pub struct ProcessSighting {
    pub comm: String,
}

/// A bind the kernel told us about. The eBPF bind tracepoint carries no
/// protocol, so a port is considered visible if *either* the TCP or the UDP
/// view accounts for it.
#[derive(Debug, Clone)]
pub struct BindSighting {
    pub pid: i32,
    pub comm: String,
}

#[derive(Debug)]
pub struct KernelView {
    processes: Mutex<Recent<i32, ProcessSighting>>,
    binds: Mutex<Recent<u16, BindSighting>>,
    modules: Mutex<Recent<String, ()>>,
}

impl KernelView {
    fn new() -> Self {
        Self {
            processes: Mutex::new(Recent::new(PROCESS_TTL, PROCESS_CAP)),
            binds: Mutex::new(Recent::new(BIND_TTL, BIND_CAP)),
            modules: Mutex::new(Recent::new(MODULE_TTL, MODULE_CAP)),
        }
    }

    pub fn record_process(&self, pid: i32, comm: &str) {
        if pid <= 0 {
            return;
        }
        if let Ok(mut g) = self.processes.lock() {
            g.insert(
                pid,
                ProcessSighting {
                    comm: comm.to_string(),
                },
                Instant::now(),
            );
        }
    }

    pub fn record_bind(&self, pid: i32, port: u16, comm: &str) {
        if port == 0 {
            return;
        }
        if let Ok(mut g) = self.binds.lock() {
            g.insert(
                port,
                BindSighting {
                    pid,
                    comm: comm.to_string(),
                },
                Instant::now(),
            );
        }
    }

    pub fn record_module_load(&self, name: &str) {
        if name.is_empty() {
            return;
        }
        if let Ok(mut g) = self.modules.lock() {
            g.insert(normalize_module_name(name), (), Instant::now());
        }
    }

    pub fn processes(&self) -> Vec<(i32, ProcessSighting)> {
        let now = Instant::now();
        self.processes
            .lock()
            .map(|g| g.snapshot(now))
            .unwrap_or_default()
    }

    pub fn binds(&self) -> Vec<(u16, BindSighting)> {
        let now = Instant::now();
        self.binds
            .lock()
            .map(|g| g.snapshot(now))
            .unwrap_or_default()
    }

    pub fn modules(&self) -> Vec<String> {
        let now = Instant::now();
        self.modules
            .lock()
            .map(|g| g.snapshot(now).into_iter().map(|(k, _)| k).collect())
            .unwrap_or_default()
    }
}

/// The kernel writes module names with underscores where the file on disk may
/// use hyphens; comparing either form directly produces phantom mismatches.
pub fn normalize_module_name(name: &str) -> String {
    name.trim().replace('-', "_")
}

/// Process-wide kernel view, written by the eBPF collectors and read by the
/// rootkit sweeps.
pub fn kernel_view() -> &'static KernelView {
    static VIEW: OnceLock<KernelView> = OnceLock::new();
    VIEW.get_or_init(KernelView::new)
}

/// True when this process shares PID 1's PID namespace.
///
/// eBPF reports host PIDs. If the agent runs in its own PID namespace those
/// numbers do not exist in the `/proc` it can see, and every eBPF-observed
/// process would look hidden. The cross-view comparison against the kernel view
/// is therefore only sound in the initial namespace, and is dropped elsewhere
/// rather than producing findings that are guaranteed to be wrong.
pub fn in_initial_pid_namespace() -> bool {
    match (
        std::fs::read_link("/proc/self/ns/pid"),
        std::fs::read_link("/proc/1/ns/pid"),
    ) {
        (Ok(own), Ok(init)) => own == init,
        // Unreadable (hidepid, restricted container): assume not comparable.
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sightings_expire_once_past_their_ttl() {
        let mut r: Recent<i32, ()> = Recent::new(Duration::from_secs(10), 16);
        let t0 = Instant::now();
        r.insert(1, (), t0);
        assert_eq!(r.snapshot(t0 + Duration::from_secs(9)).len(), 1);
        assert!(
            r.snapshot(t0 + Duration::from_secs(11)).is_empty(),
            "an exited process must age out rather than look hidden forever"
        );
    }

    #[test]
    fn the_registry_stays_bounded_under_churn() {
        let mut r: Recent<i32, ()> = Recent::new(Duration::from_secs(600), 4);
        let t0 = Instant::now();
        for pid in 0..100 {
            r.insert(pid, (), t0 + Duration::from_millis(pid as u64));
        }
        assert!(r.entries.len() <= 4);
    }

    #[test]
    fn eviction_keeps_the_newest_sightings() {
        let mut r: Recent<i32, ()> = Recent::new(Duration::from_secs(600), 2);
        let t0 = Instant::now();
        r.insert(1, (), t0);
        r.insert(2, (), t0 + Duration::from_secs(1));
        r.insert(3, (), t0 + Duration::from_secs(2));
        let keys: Vec<i32> = r
            .snapshot(t0 + Duration::from_secs(2))
            .into_iter()
            .map(|(k, _)| k)
            .collect();
        assert!(!keys.contains(&1));
        assert!(keys.contains(&3));
    }

    #[test]
    fn re_sighting_refreshes_rather_than_duplicates() {
        let mut r: Recent<i32, ()> = Recent::new(Duration::from_secs(10), 4);
        let t0 = Instant::now();
        r.insert(1, (), t0);
        r.insert(1, (), t0 + Duration::from_secs(8));
        assert_eq!(r.snapshot(t0 + Duration::from_secs(12)).len(), 1);
    }

    #[test]
    fn module_names_compare_across_the_hyphen_underscore_split() {
        assert_eq!(normalize_module_name("snd-hda-intel"), "snd_hda_intel");
        assert_eq!(normalize_module_name(" nf_tables "), "nf_tables");
    }

    #[test]
    fn invalid_sightings_are_ignored() {
        let view = KernelView::new();
        view.record_process(0, "x");
        view.record_bind(1, 0, "x");
        view.record_module_load("");
        assert!(view.processes().is_empty());
        assert!(view.binds().is_empty());
        assert!(view.modules().is_empty());
    }
}
