//! Container lifecycle stream (B10): start and stop of docker / containerd /
//! CRI-O / podman containers.
//!
//! No runtime socket is touched. Every OCI runtime on a cgroup-v2 host creates
//! one cgroup directory per container (`docker-<id>.scope`, `libpod-<id>.scope`,
//! `cri-containerd-<id>.scope`, `crio-<id>.scope`, or a bare `<id>` with the
//! cgroupfs driver) and removes it when the container is gone. The directory is
//! created with `mkdir(2)`, which cgroupfs reports through inotify, so a watch on
//! the (bounded-depth) cgroup tree sees both. The image and labels come from
//! the runtime's own on-disk state via [`super::container::resolve`], read-only
//! and best-effort. The init pid is the first entry of the cgroup's
//! `cgroup.procs` once the runtime has moved it in (it is empty for a few
//! milliseconds after `mkdir`, so a start is held back until the pid shows up or
//! [`PID_WAIT`] passes).
//!
//! Wire shape: `log` / `log` with `category = "container"` and the lifecycle
//! facts in `fields` (`event`, `container_id`, `runtime`, `image`, `init_pid`,
//! `init_start_time`, `cgroup_path`). Containers that already ran when the agent
//! started are recorded silently (their processes already carry the container
//! id); only transitions seen while running are events.
//!
//! Bounds: watch count, tree depth, tracked containers and events per minute
//! are capped; sheds are counted (`rate_limit_applied`), kernel inotify
//! overflow as `kernel_ringbuffer_full`. A 30 s reconcile re-walks the tree to
//! pick up directories the watch missed and to close containers whose deletion
//! event was lost.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::Result;
use async_trait::async_trait;
use inotify::{EventMask, Inotify, WatchDescriptor, WatchMask};
use tokio::sync::mpsc::Sender;
use tracing::{info, warn};

use crate::schema::{AgentEvent, EventAction, EventClass, EventData, LogEventData, Severity};
use crate::telemetry::drops::DropReason;
use crate::telemetry::metrics::metrics;

use super::super::Collector;

const CGROUP_ROOT: &str = "/sys/fs/cgroup";
const MAX_DEPTH: usize = 6;
const MAX_WATCHES: usize = 2048;
const MAX_ACTIVE: usize = 4096;
const MAX_PENDING: usize = 512;
const PID_WAIT: Duration = Duration::from_secs(5);
const POLL_MS: i32 = 250;
const RECONCILE: Duration = Duration::from_secs(30);
const MAX_EVENTS_PER_MINUTE: usize = 120;

/// A container identified from one cgroup directory name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerRef {
    pub runtime: &'static str,
    pub id: String,
}

fn is_full_id(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Identify a container from a cgroup directory `name` under `parent_rel` (the
/// path of its parent relative to the cgroup root). Only the leaf counts:
/// `docker-<id>.scope/init.scope` or `libpod-conmon-<id>.scope` are not
/// containers.
pub fn container_from_dir(parent_rel: &str, name: &str) -> Option<ContainerRef> {
    if name.contains("conmon") {
        return None;
    }
    let stem = name.strip_suffix(".scope").unwrap_or(name);
    let id = stem.rsplit('-').next().unwrap_or(stem);
    if !is_full_id(id) {
        return None;
    }
    let full = format!("{parent_rel}/{name}");
    let runtime = if name.contains("docker") || parent_rel.split('/').any(|s| s == "docker") {
        "docker"
    } else if name.contains("libpod") || full.contains("libpod") {
        "podman"
    } else if name.contains("crio") || full.contains("crio") {
        "cri-o"
    } else if full.contains("kubepods") {
        "kubepods"
    } else {
        "containerd"
    };
    Some(ContainerRef {
        runtime,
        id: id.to_ascii_lowercase(),
    })
}

/// First pid of a `cgroup.procs` listing.
pub fn first_pid(procs: &str) -> Option<i32> {
    procs
        .lines()
        .next()
        .and_then(|l| l.trim().parse().ok())
        .filter(|p| *p > 0)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Start,
    Stop,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lifecycle {
    pub kind: Kind,
    pub container: ContainerRef,
    pub cgroup_path: String,
    pub init_pid: Option<i32>,
    pub init_start_time: Option<u64>,
    pub image: Option<String>,
    pub image_digest: Option<String>,
}

#[derive(Clone)]
struct Active {
    cref: ContainerRef,
    rel: String,
    init_pid: Option<i32>,
    init_start_time: Option<u64>,
    image: Option<String>,
    image_digest: Option<String>,
}

struct Pending {
    cref: ContainerRef,
    rel: String,
    since: Instant,
}

/// Map a lifecycle to the wire event.
pub fn to_event(agent_id: &str, hostname: &str, root: &Path, l: &Lifecycle) -> AgentEvent {
    let (name, verb) = match l.kind {
        Kind::Start => ("container_start", "started"),
        Kind::Stop => ("container_stop", "stopped"),
    };
    let short: String = l.container.id.chars().take(12).collect();
    let mut fields = serde_json::Map::new();
    fields.insert("event".into(), name.into());
    fields.insert("container_id".into(), l.container.id.clone().into());
    fields.insert("runtime".into(), l.container.runtime.into());
    fields.insert("cgroup_path".into(), l.cgroup_path.clone().into());
    if let Some(v) = &l.image {
        fields.insert("image".into(), v.clone().into());
    }
    if let Some(v) = &l.image_digest {
        fields.insert("image_digest".into(), v.clone().into());
    }
    if let Some(v) = l.init_pid {
        fields.insert("init_pid".into(), v.into());
    }
    if let Some(v) = l.init_start_time {
        fields.insert("init_start_time".into(), v.into());
    }
    AgentEvent::new(
        agent_id.to_string(),
        hostname.to_string(),
        EventClass::Log,
        EventAction::Log,
        Severity::Info,
        EventData::Log(Box::new(LogEventData {
            source: "container_runtime".into(),
            source_type: "cgroup".into(),
            source_path: root.to_string_lossy().into_owned(),
            parser: "cgroup_inotify".into(),
            message: format!("{} container {short} {verb}", l.container.runtime),
            category: "container".into(),
            log_timestamp: None,
            facility: None,
            log_severity: None,
            proc: None,
            pid: l.init_pid,
            uid: None,
            username: None,
            log_host: None,
            fields,
            mitre_tactic: None,
            mitre_technique: None,
            offset: None,
            inode: None,
            truncated_fields: None,
        })),
    )
    .with_source("container:cgroup")
}

/// The cgroup watcher. `root` is injectable so tests use a temp directory.
pub struct Watcher {
    root: PathBuf,
    inotify: Inotify,
    wds: HashMap<WatchDescriptor, PathBuf>,
    active: BTreeMap<String, Active>,
    pending: BTreeMap<String, Pending>,
    out: VecDeque<Lifecycle>,
    last_reconcile: Instant,
    budget: VecDeque<Instant>,
}

impl Watcher {
    pub fn new(root: PathBuf) -> std::io::Result<Self> {
        let mut w = Self {
            root,
            inotify: Inotify::init()?,
            wds: HashMap::new(),
            active: BTreeMap::new(),
            pending: BTreeMap::new(),
            out: VecDeque::new(),
            last_reconcile: Instant::now(),
            budget: VecDeque::new(),
        };
        let root = w.root.clone();
        w.walk(&root, 0, true);
        Ok(w)
    }

    fn rel(&self, p: &Path) -> String {
        format!(
            "/{}",
            p.strip_prefix(&self.root)
                .unwrap_or(p)
                .to_string_lossy()
                .trim_start_matches('/')
        )
        .trim_end_matches('/')
        .to_string()
    }

    /// Watch `dir` and walk below it. `baseline`: containers found are recorded
    /// silently (running before the agent); otherwise they are starts.
    fn walk(&mut self, dir: &Path, depth: usize, baseline: bool) {
        if !self.wds.values().any(|d| d == dir) {
            if self.wds.len() >= MAX_WATCHES {
                warn!("containerwatch: watch limit reached at {}", dir.display());
                return;
            }
            let mask = WatchMask::CREATE
                .union(WatchMask::DELETE)
                .union(WatchMask::ONLYDIR);
            match self.inotify.watches().add(dir, mask) {
                Ok(wd) => {
                    self.wds.insert(wd, dir.to_path_buf());
                }
                Err(e) => {
                    warn!("containerwatch: cannot watch {}: {e}", dir.display());
                    return;
                }
            }
        }
        let rel_parent = self.rel(dir);
        let Ok(rd) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in rd.flatten() {
            if !entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                continue;
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            if let Some(c) = container_from_dir(&rel_parent, &name) {
                self.found(c, entry.path(), baseline);
            } else if depth < MAX_DEPTH {
                self.walk(&entry.path(), depth + 1, baseline);
            }
        }
    }

    fn found(&mut self, c: ContainerRef, path: PathBuf, baseline: bool) {
        if self.active.contains_key(&c.id) || self.pending.contains_key(&c.id) {
            return;
        }
        let rel = self.rel(&path);
        if baseline {
            if self.active.len() < MAX_ACTIVE {
                let (pid, start) = read_init(&path);
                self.active.insert(
                    c.id.clone(),
                    Active {
                        cref: c,
                        rel,
                        init_pid: pid,
                        init_start_time: start,
                        image: None,
                        image_digest: None,
                    },
                );
            }
            return;
        }
        if self.pending.len() >= MAX_PENDING || self.active.len() >= MAX_ACTIVE {
            metrics().event_dropped(DropReason::RateLimitApplied);
            return;
        }
        self.pending.insert(
            c.id.clone(),
            Pending {
                cref: c,
                rel,
                since: Instant::now(),
            },
        );
    }

    fn stopped(&mut self, id: &str) {
        self.pending.remove(id);
        if let Some(a) = self.active.remove(id) {
            self.out.push_back(Lifecycle {
                kind: Kind::Stop,
                container: a.cref,
                cgroup_path: a.rel,
                init_pid: a.init_pid,
                init_start_time: a.init_start_time,
                image: a.image,
                image_digest: a.image_digest,
            });
        }
    }

    /// Resolve pending starts whose init pid arrived or whose wait ran out.
    fn settle_pending(&mut self, now: Instant) {
        let ids: Vec<String> = self.pending.keys().cloned().collect();
        for id in ids {
            let Some(p) = self.pending.get(&id) else {
                continue;
            };
            let dir = self.root.join(p.rel.trim_start_matches('/'));
            let (pid, start) = read_init(&dir);
            if pid.is_none() && now.duration_since(p.since) < PID_WAIT {
                continue;
            }
            let Some(p) = self.pending.remove(&id) else {
                continue;
            };
            let img = super::container::resolve(&p.cref.id);
            let a = Active {
                cref: p.cref.clone(),
                rel: p.rel.clone(),
                init_pid: pid,
                init_start_time: start,
                image: img.image.clone(),
                image_digest: img.image_digest.clone(),
            };
            self.out.push_back(Lifecycle {
                kind: Kind::Start,
                container: p.cref,
                cgroup_path: p.rel,
                init_pid: pid,
                init_start_time: start,
                image: img.image,
                image_digest: img.image_digest,
            });
            self.active.insert(id, a);
        }
    }

    /// Process whatever inotify has queued, settle pending starts, reconcile on
    /// schedule, and return the lifecycles to ship.
    pub fn step(&mut self, now: Instant) -> Vec<Lifecycle> {
        let mut buf = [0u8; 8192];
        loop {
            let events: Vec<_> = match self.inotify.read_events(&mut buf) {
                Ok(e) => e
                    .map(|e| {
                        (
                            e.wd.clone(),
                            e.mask,
                            e.name.map(|n| n.to_string_lossy().into_owned()),
                        )
                    })
                    .collect(),
                Err(_) => break,
            };
            if events.is_empty() {
                break;
            }
            for (wd, mask, name) in events {
                if mask.contains(EventMask::Q_OVERFLOW) {
                    metrics().event_dropped(DropReason::KernelRingbufferFull);
                    // Re-walk: the lost events may have been containers.
                    self.last_reconcile = now - RECONCILE;
                    continue;
                }
                if mask.contains(EventMask::IGNORED) {
                    self.wds.remove(&wd);
                    continue;
                }
                let (Some(dir), Some(name)) = (self.wds.get(&wd).cloned(), name) else {
                    continue;
                };
                if !mask.contains(EventMask::ISDIR) {
                    continue;
                }
                let rel_parent = self.rel(&dir);
                let container = container_from_dir(&rel_parent, &name);
                if mask.contains(EventMask::CREATE) {
                    let path = dir.join(&name);
                    match container {
                        Some(c) => self.found(c, path, false),
                        None => {
                            let depth = rel_parent.matches('/').count();
                            if depth <= MAX_DEPTH {
                                self.walk(&path, depth, false);
                            }
                        }
                    }
                } else if mask.contains(EventMask::DELETE) {
                    if let Some(c) = container {
                        self.stopped(&c.id);
                    }
                }
            }
        }
        self.settle_pending(now);
        if now.duration_since(self.last_reconcile) >= RECONCILE {
            self.last_reconcile = now;
            self.reconcile();
        }
        let mut shipped = Vec::new();
        while let Some(l) = self.out.pop_front() {
            while self
                .budget
                .front()
                .is_some_and(|t| now.duration_since(*t) >= Duration::from_secs(60))
            {
                self.budget.pop_front();
            }
            if self.budget.len() >= MAX_EVENTS_PER_MINUTE {
                metrics().event_dropped(DropReason::RateLimitApplied);
                continue;
            }
            self.budget.push_back(now);
            shipped.push(l);
        }
        shipped
    }

    /// Close containers whose directory vanished without a delete event and
    /// pick up ones created before their parent was watched.
    fn reconcile(&mut self) {
        let gone: Vec<String> = self
            .active
            .iter()
            .filter(|(_, a)| !self.root.join(a.rel.trim_start_matches('/')).is_dir())
            .map(|(id, _)| id.clone())
            .collect();
        for id in gone {
            self.stopped(&id);
        }
        let root = self.root.clone();
        self.walk(&root, 0, false);
    }

    pub fn as_raw_fd(&self) -> i32 {
        self.inotify.as_raw_fd()
    }
    pub fn watch_count(&self) -> usize {
        self.wds.len()
    }
}

fn read_init(dir: &Path) -> (Option<i32>, Option<u64>) {
    let pid = std::fs::read_to_string(dir.join("cgroup.procs"))
        .ok()
        .and_then(|s| first_pid(&s));
    let start = pid.and_then(crate::telemetry::identity::process_start_time);
    (pid, start)
}

#[derive(Default)]
pub struct ContainerWatchCollector;

impl ContainerWatchCollector {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Collector for ContainerWatchCollector {
    fn name(&self) -> &'static str {
        "ContainerWatchCollector"
    }

    async fn run(
        &mut self,
        tx: Sender<AgentEvent>,
        agent_id: String,
        hostname: String,
    ) -> Result<()> {
        let root = PathBuf::from(CGROUP_ROOT);
        // cgroup v1 has no single tree to watch; the process-level container
        // id enrichment still works there.
        if !root.join("cgroup.controllers").exists() {
            info!("containerwatch: cgroup v2 not mounted, container lifecycle unavailable");
            return Ok(());
        }
        let (ctx, mut crx) = tokio::sync::mpsc::channel::<AgentEvent>(64);
        let root2 = root.clone();
        std::thread::spawn(move || {
            let mut w = match Watcher::new(root2.clone()) {
                Ok(w) => w,
                Err(e) => {
                    warn!("containerwatch: inotify init failed: {e}");
                    return;
                }
            };
            info!(
                watches = w.watch_count(),
                "containerwatch: watching cgroup tree"
            );
            loop {
                let mut fd = libc::pollfd {
                    fd: w.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                };
                // SAFETY: `fd` is a valid pollfd for the duration of the call.
                unsafe { libc::poll(&mut fd, 1, POLL_MS) };
                for l in w.step(Instant::now()) {
                    if ctx
                        .blocking_send(to_event(&agent_id, &hostname, &root2, &l))
                        .is_err()
                    {
                        return;
                    }
                }
            }
        });
        while let Some(ev) = crx.recv().await {
            if tx.send(ev).await.is_err() {
                break;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn leaf_names_per_runtime() {
        let d = container_from_dir("/system.slice", &format!("docker-{ID}.scope")).unwrap();
        assert_eq!((d.runtime, d.id.as_str()), ("docker", ID));
        assert_eq!(
            container_from_dir("/machine.slice", &format!("libpod-{ID}.scope"))
                .unwrap()
                .runtime,
            "podman"
        );
        assert_eq!(
            container_from_dir(
                "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod1.slice",
                &format!("cri-containerd-{ID}.scope")
            )
            .unwrap()
            .runtime,
            "kubepods"
        );
        assert_eq!(
            container_from_dir("/system.slice", &format!("crio-{ID}.scope"))
                .unwrap()
                .runtime,
            "cri-o"
        );
        // cgroupfs driver: bare id under /docker.
        assert_eq!(container_from_dir("/docker", ID).unwrap().runtime, "docker");
    }

    #[test]
    fn non_containers_are_rejected() {
        assert!(container_from_dir("/system.slice", "sshd.service").is_none());
        assert!(container_from_dir("/x", &format!("libpod-conmon-{ID}.scope")).is_none());
        assert!(container_from_dir("/x", "init.scope").is_none());
        // Short ids and non-hex are not accepted for a lifecycle stream.
        assert!(container_from_dir("/x", "docker-abcdef123456.scope").is_none());
        assert!(container_from_dir("/x", &"z".repeat(64)).is_none());
    }

    #[test]
    fn first_pid_parses() {
        assert_eq!(first_pid("123\n456\n"), Some(123));
        assert_eq!(first_pid(""), None);
        assert_eq!(first_pid("0\n"), None);
    }

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("trapd-cw-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn start_and_stop_through_a_watched_tree() {
        let root = tmp("life");
        std::fs::create_dir_all(root.join("system.slice")).unwrap();
        // Running before the agent: baseline, silent.
        let old = "f".repeat(64);
        std::fs::create_dir_all(root.join(format!("system.slice/docker-{old}.scope"))).unwrap();
        let mut w = Watcher::new(root.clone()).unwrap();
        assert!(w.step(Instant::now()).is_empty());

        // A new slice appears, then a container inside it.
        let slice = root.join("machine.slice");
        std::fs::create_dir_all(&slice).unwrap();
        let scope = slice.join(format!("libpod-{ID}.scope"));
        let _ = w.step(Instant::now());
        std::fs::create_dir_all(&scope).unwrap();
        // Runtime moves the init pid in shortly after mkdir.
        let me = std::process::id();
        std::fs::write(scope.join("cgroup.procs"), format!("{me}\n")).unwrap();
        // inotify delivery is asynchronous.
        let mut shipped = Vec::new();
        for _ in 0..50 {
            shipped = w.step(Instant::now());
            if !shipped.is_empty() {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(shipped.len(), 1, "{shipped:?}");
        let s = &shipped[0];
        assert_eq!(s.kind, Kind::Start);
        assert_eq!(s.container.runtime, "podman");
        assert_eq!(s.container.id, ID);
        assert_eq!(s.init_pid, Some(me as i32));
        assert!(s.init_start_time.is_some());
        assert_eq!(s.cgroup_path, format!("/machine.slice/libpod-{ID}.scope"));

        std::fs::remove_file(scope.join("cgroup.procs")).unwrap();
        std::fs::remove_dir(&scope).unwrap();
        let mut stop = Vec::new();
        for _ in 0..50 {
            stop = w.step(Instant::now());
            if !stop.is_empty() {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(stop.len(), 1);
        assert_eq!(stop[0].kind, Kind::Stop);
        assert_eq!(stop[0].init_pid, Some(me as i32));

        // The baseline container stops too (its id was tracked silently).
        std::fs::remove_dir(root.join(format!("system.slice/docker-{old}.scope"))).unwrap();
        let mut stop = Vec::new();
        for _ in 0..50 {
            stop = w.step(Instant::now());
            if !stop.is_empty() {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(stop[0].container.runtime, "docker");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn start_without_pid_is_emitted_after_the_wait() {
        let root = tmp("nopid");
        let mut w = Watcher::new(root.clone()).unwrap();
        std::fs::create_dir_all(root.join(format!("docker-{ID}.scope"))).unwrap();
        let t0 = Instant::now();
        std::thread::sleep(Duration::from_millis(50));
        assert!(w.step(t0).is_empty(), "held back while waiting for a pid");
        let out = w.step(t0 + PID_WAIT + Duration::from_secs(1));
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].init_pid, None);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn reconcile_closes_containers_whose_delete_was_lost() {
        let root = tmp("recon");
        let dir = root.join(format!("docker-{ID}.scope"));
        std::fs::create_dir_all(&dir).unwrap();
        let mut w = Watcher::new(root.clone()).unwrap();
        std::fs::remove_dir(&dir).unwrap();
        // Drain the real event, then force a reconcile with the entry still
        // active by re-inserting it.
        let _ = w.step(Instant::now());
        w.active.insert(
            ID.into(),
            Active {
                cref: ContainerRef {
                    runtime: "docker",
                    id: ID.into(),
                },
                rel: format!("/docker-{ID}.scope"),
                init_pid: None,
                init_start_time: None,
                image: None,
                image_digest: None,
            },
        );
        let out = w.step(Instant::now() + RECONCILE + Duration::from_secs(1));
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].kind, Kind::Stop);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn event_shape() {
        let ev = to_event(
            "a",
            "h",
            Path::new(CGROUP_ROOT),
            &Lifecycle {
                kind: Kind::Start,
                container: ContainerRef {
                    runtime: "docker",
                    id: ID.into(),
                },
                cgroup_path: "/x".into(),
                init_pid: Some(9),
                init_start_time: Some(5),
                image: Some("nginx:1".into()),
                image_digest: None,
            },
        );
        let v = serde_json::to_value(&ev).unwrap();
        assert_eq!(v["class"], "log");
        assert_eq!(v["data"]["category"], "container");
        assert_eq!(v["data"]["fields"]["event"], "container_start");
        assert_eq!(v["data"]["fields"]["init_pid"], 9);
        assert_eq!(v["data"]["fields"]["image"], "nginx:1");
        assert_eq!(v["data"]["pid"], 9);
    }
}
