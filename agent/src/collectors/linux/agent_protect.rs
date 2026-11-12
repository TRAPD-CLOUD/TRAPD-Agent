use std::collections::{BTreeMap, HashMap, VecDeque};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::Result;
use async_trait::async_trait;
use inotify::{EventMask, Inotify, WatchMask};
use tokio::sync::mpsc::Sender;
use tracing::{info, warn};

use crate::collectors::Collector;
use crate::schema::{AgentEvent, AgentTamperData, EventAction, EventClass, EventData, Severity};

/// Directories whose contents are made immutable with `chattr +i` at startup.
const IMMUTABLE_FILES: &[&str] = &[
    "/etc/trapd/agent.conf",
    "/etc/trapd/credentials",
    "/etc/trapd/enrollment.json",
];

const WATCH_MASK: WatchMask = WatchMask::CREATE
    .union(WatchMask::DELETE)
    .union(WatchMask::MODIFY)
    .union(WatchMask::MOVED_FROM)
    .union(WatchMask::MOVED_TO)
    .union(WatchMask::ATTRIB)
    .union(WatchMask::DELETE_SELF)
    .union(WatchMask::MOVE_SELF);

/// systemd unit directories a unit file for the agent may live in:
/// `install.sh` writes `/etc/systemd/system`, the `.deb` ships `/usr/lib` (and
/// `/lib` is the same directory on merged-usr systems). Deployment facts, not
/// agent configuration, so they are not part of the `paths` module.
const UNIT_DIRS: &[&str] = &[
    "/etc/systemd/system",
    "/usr/lib/systemd/system",
    "/lib/systemd/system",
];
const UNIT_FILES: &[&str] = &[
    "trapd-agent.service",
    "trapd-agent-update.service",
    "trapd-agent-update.path",
];
/// Drop-ins (`trapd-agent.service.d/*.conf`) can override `ExecStart=`.
const UNIT_DROPIN_DIRS: &[&str] = &["trapd-agent.service.d", "trapd-agent-update.service.d"];

/// Seconds after the last in-process atomic write during which a rewrite of the
/// same path is treated as the agent's own.
const RESCAN_INTERVAL_MS: i32 = 5_000;
/// Tamper events per minute before further ones are shed (and counted).
const MAX_EVENTS_PER_MINUTE: usize = 60;
/// Identical (path, action) pairs closer together than this are one fact.
const COALESCE: Duration = Duration::from_secs(1);

/// What is expected of one protected name, i.e. which changes are tamper.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Scope {
    /// Every change is tamper (keys, certs, unit files, identity).
    Always,
    /// Like `Always`, but the signed updater legitimately replaces it; events
    /// are suppressed while its recovery journal exists.
    UpdateManaged,
    /// The agent appends to / compacts it constantly: only removal, move-away
    /// and attribute changes count (the spool journal).
    Journal,
    /// Rotated by the agent and logrotate (rename + recreate): only removal and
    /// attribute changes count (`events.ndjson`).
    RotatedLog,
}

/// The rule for one watched directory.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct DirRule {
    /// Every entry is protected with `Scope::Always` (drop-in and key dirs).
    pub all: Option<Scope>,
    pub names: BTreeMap<String, Scope>,
}

impl DirRule {
    fn scope_of(&self, name: &str) -> Option<Scope> {
        self.names.get(name).copied().or(self.all)
    }
}

/// Where the agent lives on this host. Built from the `paths` module and the
/// updater's own location helpers so the watcher can never drift from them.
#[derive(Debug, Clone)]
pub(crate) struct Layout {
    pub state_dir: PathBuf,
    pub config_dir: PathBuf,
    pub release_key_dir: PathBuf,
    pub log_dir: PathBuf,
    pub binary: Option<PathBuf>,
    pub ebpf_object: PathBuf,
    pub legacy_home_trapd: Option<PathBuf>,
}

impl Layout {
    fn discover() -> Self {
        Self {
            state_dir: crate::paths::state_dir().to_path_buf(),
            config_dir: crate::paths::config_dir().to_path_buf(),
            release_key_dir: crate::update::release_key_dir(),
            log_dir: crate::paths::log_dir().to_path_buf(),
            binary: std::env::current_exe().ok().map(strip_deleted_suffix),
            ebpf_object: std::env::var_os("TRAPD_EBPF_INSTALL_PATH")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("/usr/lib/trapd-agent/trapd-agent-exec")),
            legacy_home_trapd: std::env::var_os("HOME")
                .filter(|h| !h.is_empty())
                .map(|h| PathBuf::from(h).join(".trapd")),
        }
    }
}

/// `/proc/self/exe` reads `<path> (deleted)` once the binary was replaced; the
/// install path is what must stay watched.
fn strip_deleted_suffix(p: PathBuf) -> PathBuf {
    match p.to_str().and_then(|s| s.strip_suffix(" (deleted)")) {
        Some(clean) => PathBuf::from(clean),
        None => p,
    }
}

fn add_name(plan: &mut BTreeMap<PathBuf, DirRule>, file: &Path, scope: Scope) {
    if let (Some(dir), Some(name)) = (file.parent(), file.file_name().and_then(|n| n.to_str())) {
        plan.entry(dir.to_path_buf())
            .or_default()
            .names
            .insert(name.to_string(), scope);
    }
}

fn add_all(plan: &mut BTreeMap<PathBuf, DirRule>, dir: &Path, scope: Scope) {
    plan.entry(dir.to_path_buf()).or_default().all = Some(scope);
}

/// The full set of protected locations. Pure: no filesystem access, so the set
/// is testable and identical to what the watcher arms.
pub(crate) fn watch_plan(l: &Layout) -> BTreeMap<PathBuf, DirRule> {
    let mut plan = BTreeMap::new();

    // Trust and identity material. Only the files an attacker gains from
    // changing: the agent's own churn (telemetry.json, baselines, nonces, ...)
    // is deliberately not listed or every write would be a critical alert.
    for f in [
        "agent.env",
        "ca.crt",
        "agent.crt",
        "agent.key",
        "command_signing.pub",
    ] {
        add_name(&mut plan, &l.config_dir.join(f), Scope::Always);
    }
    for f in ["binary.sha256", "binary.sig"] {
        add_name(&mut plan, &l.config_dir.join(f), Scope::UpdateManaged);
    }
    add_all(&mut plan, &l.config_dir.join("rules"), Scope::Always);
    add_all(&mut plan, &l.release_key_dir, Scope::Always);
    for f in ["device_id", "credentials.json"] {
        add_name(&mut plan, &l.state_dir.join(f), Scope::Always);
    }
    add_name(
        &mut plan,
        &l.state_dir.join("spool").join("queue.journal"),
        Scope::Journal,
    );
    add_name(
        &mut plan,
        &l.log_dir.join("events.ndjson"),
        Scope::RotatedLog,
    );

    // Executables: the running binary, its updater and the eBPF object.
    if let Some(bin) = &l.binary {
        add_name(&mut plan, bin, Scope::UpdateManaged);
        if let Some(dir) = bin.parent() {
            add_name(&mut plan, &dir.join("trapd-update"), Scope::UpdateManaged);
        }
    }
    add_name(&mut plan, &l.ebpf_object, Scope::UpdateManaged);

    // systemd: unit files, drop-ins and the enable symlink.
    for dir in UNIT_DIRS {
        let dir = Path::new(dir);
        for f in UNIT_FILES {
            add_name(&mut plan, &dir.join(f), Scope::Always);
        }
        for d in UNIT_DROPIN_DIRS {
            add_all(&mut plan, &dir.join(d), Scope::Always);
        }
    }
    add_name(
        &mut plan,
        &Path::new(UNIT_DIRS[0])
            .join("multi-user.target.wants")
            .join(UNIT_FILES[0]),
        Scope::Always,
    );

    if let Some(home) = &l.legacy_home_trapd {
        add_all(&mut plan, home, Scope::Always);
    }
    plan
}

/// Map an inotify mask to the tamper vocabulary the backend already receives
/// (`create`/`delete`/`modify`), plus `chmod` for attribute changes. `None`
/// when `scope` says the change is expected.
pub(crate) fn map_change(mask: EventMask, scope: Scope) -> Option<&'static str> {
    let removed = mask.intersects(
        EventMask::DELETE
            .union(EventMask::MOVED_FROM)
            .union(EventMask::DELETE_SELF)
            .union(EventMask::MOVE_SELF),
    );
    let created = mask.intersects(EventMask::CREATE.union(EventMask::MOVED_TO));
    let attrib = mask.contains(EventMask::ATTRIB);
    let modified = mask.contains(EventMask::MODIFY);
    match scope {
        Scope::Always | Scope::UpdateManaged => {
            if removed {
                Some("delete")
            } else if created {
                Some("create")
            } else if attrib {
                Some("chmod")
            } else if modified {
                Some("modify")
            } else {
                None
            }
        }
        Scope::Journal => {
            if removed {
                Some("delete")
            } else if attrib {
                Some("chmod")
            } else {
                None
            }
        }
        Scope::RotatedLog => {
            if mask.intersects(EventMask::DELETE.union(EventMask::DELETE_SELF)) {
                Some("delete")
            } else if attrib {
                Some("chmod")
            } else {
                None
            }
        }
    }
}

/// True while the signed updater is mid-flight, i.e. replacing the binary,
/// eBPF object and baseline is expected.
fn update_in_progress(state_dir: &Path) -> bool {
    crate::update::apply::StagingPaths::new(state_dir)
        .recovery()
        .exists()
}

/// Sliding one-minute budget so a loop rewriting a watched file cannot turn the
/// watcher into an event flood.
struct Budget {
    stamps: VecDeque<Instant>,
}

impl Budget {
    fn new() -> Self {
        Self {
            stamps: VecDeque::new(),
        }
    }
    fn allow(&mut self, now: Instant) -> bool {
        while self
            .stamps
            .front()
            .is_some_and(|t| now.duration_since(*t) >= Duration::from_secs(60))
        {
            self.stamps.pop_front();
        }
        if self.stamps.len() >= MAX_EVENTS_PER_MINUTE {
            return false;
        }
        self.stamps.push_back(now);
        true
    }
}

pub struct AgentProtectCollector {
    layout: Layout,
}

impl AgentProtectCollector {
    pub fn new() -> Self {
        Self {
            layout: Layout::discover(),
        }
    }
}

impl Default for AgentProtectCollector {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Collector for AgentProtectCollector {
    fn name(&self) -> &'static str {
        "AgentProtectCollector"
    }

    async fn run(
        &mut self,
        tx: Sender<AgentEvent>,
        agent_id: String,
        hostname: String,
    ) -> Result<()> {
        let layout = self.layout.clone();
        let (ap_tx, mut ap_rx) = tokio::sync::mpsc::channel::<AgentEvent>(64);

        std::thread::spawn(move || {
            run_protect_sync(ap_tx, agent_id, hostname, layout);
        });

        while let Some(event) = ap_rx.recv().await {
            if tx.send(event).await.is_err() {
                return Ok(());
            }
        }
        Ok(())
    }
}

/// Arm every planned directory that exists and is not yet watched.
fn arm(
    inotify: &Inotify,
    plan: &BTreeMap<PathBuf, DirRule>,
    wd_map: &mut HashMap<inotify::WatchDescriptor, PathBuf>,
) {
    for dir in plan.keys() {
        if wd_map.values().any(|d| d == dir) || !dir.is_dir() {
            continue;
        }
        match inotify.watches().add(dir, WATCH_MASK) {
            Ok(wd) => {
                info!(
                    "AgentProtectCollector: watching {} for tampering",
                    dir.display()
                );
                wd_map.insert(wd, dir.clone());
            }
            Err(e) => warn!("AgentProtectCollector: cannot watch {}: {e}", dir.display()),
        }
    }
}

fn wait_readable(inotify: &Inotify) -> bool {
    let mut fd = libc::pollfd {
        fd: inotify.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: `fd` is a valid pollfd for the duration of the call.
    unsafe { libc::poll(&mut fd, 1, RESCAN_INTERVAL_MS) > 0 }
}

fn run_protect_sync(
    tx: tokio::sync::mpsc::Sender<AgentEvent>,
    agent_id: String,
    hostname: String,
    layout: Layout,
) {
    // Apply chattr +i to critical agent files.
    apply_immutable_flags();

    let mut inotify = match Inotify::init() {
        Ok(i) => i,
        Err(e) => {
            warn!("AgentProtectCollector: inotify init failed: {e}");
            return;
        }
    };
    let plan = watch_plan(&layout);
    let mut wd_map: HashMap<inotify::WatchDescriptor, PathBuf> = HashMap::new();
    arm(&inotify, &plan, &mut wd_map);

    let mut budget = Budget::new();
    let mut last_emit: HashMap<(String, &'static str), Instant> = HashMap::new();
    let mut buf = [0u8; 4096];
    loop {
        // Re-arm on a timer: a directory that did not exist at start (spool,
        // /etc/trapd/rules) or was replaced must not stay unwatched forever.
        if !wait_readable(&inotify) {
            arm(&inotify, &plan, &mut wd_map);
            continue;
        }
        let events = match inotify.read_events(&mut buf) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(e) => {
                warn!("AgentProtectCollector: inotify read error: {e}");
                break;
            }
        };

        for event in events {
            let mask = event.mask;
            if mask.contains(EventMask::Q_OVERFLOW) {
                // The kernel dropped inotify events: loss we can name.
                crate::telemetry::metrics::metrics()
                    .event_dropped(crate::telemetry::drops::DropReason::KernelRingbufferFull);
                continue;
            }
            let Some(dir) = wd_map.get(&event.wd).cloned() else {
                continue;
            };
            if mask.contains(EventMask::IGNORED) {
                // Directory gone; `arm` re-adds it when it reappears.
                wd_map.remove(&event.wd);
                continue;
            }
            let Some(rule) = plan.get(&dir) else {
                continue;
            };
            let (path, scope) = match &event.name {
                Some(name) => {
                    let name = name.to_string_lossy();
                    match rule.scope_of(&name) {
                        Some(scope) => (dir.join(name.as_ref()), scope),
                        None => continue,
                    }
                }
                // The watched directory itself was removed or moved.
                None => match rule.all {
                    Some(scope) => (dir.clone(), scope),
                    None => continue,
                },
            };
            let Some(action) = map_change(mask, scope) else {
                continue;
            };
            if scope == Scope::UpdateManaged && update_in_progress(&layout.state_dir) {
                continue;
            }
            if crate::paths::was_self_written(&path, crate::paths::SELF_WRITE_WINDOW) {
                continue;
            }
            let now = Instant::now();
            let path_str = path.to_string_lossy().into_owned();
            if last_emit
                .get(&(path_str.clone(), action))
                .is_some_and(|t| now.duration_since(*t) < COALESCE)
            {
                continue;
            }
            last_emit.retain(|_, t| now.duration_since(*t) < Duration::from_secs(60));
            last_emit.insert((path_str.clone(), action), now);
            if !budget.allow(now) {
                crate::telemetry::metrics::metrics()
                    .event_dropped(crate::telemetry::drops::DropReason::RateLimitApplied);
                continue;
            }

            let ev = AgentEvent::new(
                agent_id.clone(),
                hostname.clone(),
                EventClass::Filesystem,
                EventAction::AgentTamper,
                Severity::Critical,
                EventData::AgentTamper(AgentTamperData {
                    path: path_str.clone(),
                    action: action.to_string(),
                }),
            );
            if tx.blocking_send(ev).is_err() {
                return;
            }

            // Re-apply immutable flag if an immutable file was tampered with.
            if (mask.contains(EventMask::ATTRIB) || mask.contains(EventMask::MODIFY))
                && IMMUTABLE_FILES.contains(&path_str.as_str())
            {
                apply_chattr_immutable(&path_str);
            }
        }
    }
}

/// Attempt to make critical agent config files immutable via `chattr +i`.
/// Requires CAP_LINUX_IMMUTABLE (root). Failures are logged as warnings.
fn apply_immutable_flags() {
    for &file in IMMUTABLE_FILES {
        if std::path::Path::new(file).exists() {
            apply_chattr_immutable(file);
        }
    }
}

fn apply_chattr_immutable(path: &str) {
    match std::process::Command::new("chattr")
        .args(["+i", path])
        .output()
    {
        Ok(out) if out.status.success() => {
            info!("AgentProtectCollector: chattr +i applied to {path}")
        }
        Ok(out) => warn!(
            "AgentProtectCollector: chattr +i failed for {path}: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ),
        Err(e) => warn!("AgentProtectCollector: cannot run chattr: {e}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn layout() -> Layout {
        Layout {
            state_dir: "/s".into(),
            config_dir: "/c".into(),
            release_key_dir: "/r".into(),
            log_dir: "/l".into(),
            binary: Some("/opt/x/trapd-agent".into()),
            ebpf_object: "/e/obj".into(),
            legacy_home_trapd: Some("/home/u/.trapd".into()),
        }
    }

    fn scope(plan: &BTreeMap<PathBuf, DirRule>, dir: &str, name: &str) -> Option<Scope> {
        plan.get(Path::new(dir)).and_then(|r| r.scope_of(name))
    }

    #[test]
    fn plan_is_derived_from_layout() {
        let p = watch_plan(&layout());
        assert_eq!(scope(&p, "/c", "agent.key"), Some(Scope::Always));
        assert_eq!(scope(&p, "/c", "binary.sha256"), Some(Scope::UpdateManaged));
        assert_eq!(scope(&p, "/c/rules", "any.yar"), Some(Scope::Always));
        assert_eq!(scope(&p, "/r", "release_signing.pub"), Some(Scope::Always));
        assert_eq!(scope(&p, "/s", "credentials.json"), Some(Scope::Always));
        assert_eq!(scope(&p, "/s/spool", "queue.journal"), Some(Scope::Journal));
        assert_eq!(scope(&p, "/l", "events.ndjson"), Some(Scope::RotatedLog));
        assert_eq!(
            scope(&p, "/opt/x", "trapd-agent"),
            Some(Scope::UpdateManaged)
        );
        assert_eq!(scope(&p, "/e", "obj"), Some(Scope::UpdateManaged));
        assert_eq!(scope(&p, "/home/u/.trapd", "x"), Some(Scope::Always));
        assert_eq!(
            scope(&p, "/etc/systemd/system", "trapd-agent.service"),
            Some(Scope::Always)
        );
        assert_eq!(
            scope(&p, "/etc/systemd/system/trapd-agent.service.d", "o.conf"),
            Some(Scope::Always)
        );
        assert_eq!(
            scope(
                &p,
                "/etc/systemd/system/multi-user.target.wants",
                "trapd-agent.service"
            ),
            Some(Scope::Always)
        );
    }

    #[test]
    fn agent_churn_is_not_watched() {
        let p = watch_plan(&layout());
        for n in ["telemetry.json", "command_nonces.json", "agent_config.json"] {
            assert_eq!(scope(&p, "/s", n), None, "{n}");
        }
        assert_eq!(scope(&p, "/etc/systemd/system", "sshd.service"), None);
    }

    #[test]
    fn deleted_binary_suffix_is_stripped() {
        assert_eq!(
            strip_deleted_suffix("/usr/bin/trapd-agent (deleted)".into()),
            PathBuf::from("/usr/bin/trapd-agent")
        );
    }

    #[test]
    fn event_mapping() {
        use EventMask as M;
        assert_eq!(map_change(M::DELETE, Scope::Always), Some("delete"));
        assert_eq!(map_change(M::MOVED_FROM, Scope::Always), Some("delete"));
        assert_eq!(map_change(M::MOVED_TO, Scope::Always), Some("create"));
        assert_eq!(map_change(M::ATTRIB, Scope::Always), Some("chmod"));
        assert_eq!(map_change(M::MODIFY, Scope::Always), Some("modify"));
        assert_eq!(map_change(M::OPEN, Scope::Always), None);
        // Journal: appends and compaction are expected, removal is not.
        assert_eq!(map_change(M::MODIFY, Scope::Journal), None);
        assert_eq!(map_change(M::MOVED_TO, Scope::Journal), None);
        assert_eq!(map_change(M::DELETE, Scope::Journal), Some("delete"));
        assert_eq!(map_change(M::MOVED_FROM, Scope::Journal), Some("delete"));
        // Rotated log: rename-away is rotation, unlink is not.
        assert_eq!(map_change(M::MOVED_FROM, Scope::RotatedLog), None);
        assert_eq!(map_change(M::DELETE, Scope::RotatedLog), Some("delete"));
    }

    #[test]
    fn budget_sheds_after_limit() {
        let mut b = Budget::new();
        let now = Instant::now();
        for _ in 0..MAX_EVENTS_PER_MINUTE {
            assert!(b.allow(now));
        }
        assert!(!b.allow(now));
        assert!(b.allow(now + Duration::from_secs(61)));
    }

    #[test]
    fn self_write_is_recorded_in_process() {
        let d = std::env::temp_dir().join(format!("trapd-sw-{}", std::process::id()));
        let f = d.join("x");
        assert!(!crate::paths::was_self_written(&f, Duration::from_secs(3)));
        crate::paths::write_atomic(&f, b"a", 0o600).unwrap();
        assert!(crate::paths::was_self_written(&f, Duration::from_secs(3)));
        let _ = std::fs::remove_dir_all(d);
    }
}
