//! Sensitive credential-file read sensor (GAP-MATRIX T9).
//!
//! Read-only access to real credential stores (`/etc/shadow`, SSH host keys,
//! `/etc/sudoers*`, root's SSH private keys, ...) leaves no trace in the
//! path-based open telemetry: `FILE_OPEN_EVENTS` is write-biased and the only
//! read path used to be the honeytoken inode gate. This module extends that
//! same mechanism:
//!
//! * a **fixed, built-in** list of paths is resolved to `(dev, ino)` and armed in
//!   the `SENSITIVE_INODES` BPF map;
//! * the existing `vfs_open` kprobe checks the opened inode against the map in
//!   kernel space, so an ordinary open costs one extra hash lookup and never
//!   reaches userspace;
//! * a hit is emitted on a dedicated ring buffer and becomes a
//!   `filesystem`/`open` [`FileOpenData`] (the backend maps this to DCS
//!   File/Read) with pid, process start time, exe, uid, path and flags.
//!
//! Package tools replace these files (`passwd`, `useradd`, `ssh-keygen` write a
//! temp file and `rename(2)` it over the target), which gives the path a new
//! inode. The armed set is therefore re-resolved on every change of the watched
//! directories (inotify) and on a periodic safety tick.
//!
//! Legitimate readers (sshd, login, sudo, unix_chkpwd, ...) are **not**
//! filtered here: the detection layer decides. Volume is bounded instead by a
//! per-`(exe, path)` rate limit and a global budget; every suppressed event is
//! counted as [`DropReason::RateLimitApplied`] and summarised in the log, and the
//! next emitted event for the same key carries `suppressed_repeats`.

use std::collections::{BTreeMap, HashMap};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use aya::maps::{HashMap as BpfHashMap, MapData, RingBuf};
use aya::Ebpf;
use inotify::{Inotify, WatchMask};
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc::Sender;
use tracing::{info, warn};

use crate::config::AgentConfig;
use crate::schema::{AgentEvent, EventAction, EventClass, EventData, FileOpenData, Severity};
use crate::telemetry::metrics::metrics;
use crate::telemetry::DropReason;

/// Safety-net re-resolution interval; inotify is the fast path.
const REFRESH_INTERVAL: Duration = Duration::from_secs(30);
/// Delay between a directory change and the re-resolution, so a rename burst
/// (`passwd` touches several files) is handled once.
const DEBOUNCE: Duration = Duration::from_millis(200);
/// Per-directory cap on enumerated entries (bounds map use and stat cost).
const MAX_DIR_ENTRIES: usize = 64;
/// Upper bound on armed inodes; the BPF map holds 256.
const MAX_ARMED: usize = 200;

/// Events allowed per `(exe, path)` per window.
const KEY_BURST: u32 = 3;
const LIMIT_WINDOW: Duration = Duration::from_secs(60);
/// Events allowed across all keys per window.
const GLOBAL_BURST: u32 = 120;
/// Tracked `(exe, path)` keys; beyond this only the global budget applies.
const MAX_KEYS: usize = 512;
const SUMMARY_INTERVAL: Duration = Duration::from_secs(300);

// ── Path list ────────────────────────────────────────────────────────────────

/// Credential class of an armed file. The numeric id is the BPF map value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SensitiveClass {
    Shadow = 1,
    Gshadow = 2,
    Opasswd = 3,
    Sudoers = 4,
    SshHostKey = 5,
    SshPrivateKey = 6,
    Keytab = 7,
}

impl SensitiveClass {
    pub fn name(self) -> &'static str {
        match self {
            Self::Shadow => "shadow",
            Self::Gshadow => "gshadow",
            Self::Opasswd => "opasswd",
            Self::Sudoers => "sudoers",
            Self::SshHostKey => "ssh_host_key",
            Self::SshPrivateKey => "ssh_private_key",
            Self::Keytab => "keytab",
        }
    }

    fn from_id(id: u32) -> Option<Self> {
        [
            Self::Shadow,
            Self::Gshadow,
            Self::Opasswd,
            Self::Sudoers,
            Self::SshHostKey,
            Self::SshPrivateKey,
            Self::Keytab,
        ]
        .into_iter()
        .find(|c| *c as u32 == id)
    }
}

/// Directories whose entries change the armed set. The bool says whether every
/// entry of the directory is relevant (`sudoers.d`) or only well-known names.
const WATCHED_DIRS: [(&str, bool); 4] = [
    ("/etc", false),
    ("/etc/sudoers.d", true),
    ("/etc/ssh", false),
    ("/root/.ssh", false),
];

/// One resolvable candidate: the absolute path reported in events and the
/// filesystem path actually stat'ed (differs only under a test root).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    pub display: String,
    pub fs_path: PathBuf,
    pub class: SensitiveClass,
}

fn is_ssh_host_key(name: &str) -> bool {
    name.starts_with("ssh_host_") && name.ends_with("_key")
}

fn is_ssh_private_key(name: &str) -> bool {
    name.starts_with("id_") && !name.ends_with(".pub")
}

/// Whether a directory-entry name can change the armed set.
pub fn is_relevant_name(name: &str, all_entries: bool) -> bool {
    all_entries
        || matches!(
            name,
            "shadow" | "gshadow" | "sudoers" | "krb5.keytab" | "opasswd"
        )
        || is_ssh_host_key(name)
        || is_ssh_private_key(name)
}

fn push_dir(
    root: &Path,
    dir: &str,
    class: SensitiveClass,
    accept: impl Fn(&str) -> bool,
    out: &mut Vec<Candidate>,
) {
    let rel = dir.trim_start_matches('/');
    let Ok(read) = std::fs::read_dir(root.join(rel)) else {
        return;
    };
    let mut names: Vec<String> = read
        .flatten()
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| accept(n))
        .collect();
    names.sort();
    names.truncate(MAX_DIR_ENTRIES);
    for name in names {
        out.push(Candidate {
            display: format!("{dir}/{name}"),
            fs_path: root.join(rel).join(&name),
            class,
        });
    }
}

/// The built-in path list, expanded against `root` (`/` in production).
/// Deliberately fixed: no operator-supplied paths, so the map content cannot be
/// steered by a config change. `/etc/passwd` is world-readable and far too
/// noisy; user-level keys are out of scope (see AGENTS.md).
pub fn candidates(root: &Path) -> Vec<Candidate> {
    let mut out = Vec::new();
    for (path, class) in [
        ("/etc/shadow", SensitiveClass::Shadow),
        ("/etc/gshadow", SensitiveClass::Gshadow),
        ("/etc/security/opasswd", SensitiveClass::Opasswd),
        ("/etc/sudoers", SensitiveClass::Sudoers),
        ("/etc/krb5.keytab", SensitiveClass::Keytab),
    ] {
        out.push(Candidate {
            display: path.to_string(),
            fs_path: root.join(path.trim_start_matches('/')),
            class,
        });
    }
    push_dir(
        root,
        "/etc/sudoers.d",
        SensitiveClass::Sudoers,
        |_| true,
        &mut out,
    );
    push_dir(
        root,
        "/etc/ssh",
        SensitiveClass::SshHostKey,
        is_ssh_host_key,
        &mut out,
    );
    push_dir(
        root,
        "/root/.ssh",
        SensitiveClass::SshPrivateKey,
        is_ssh_private_key,
        &mut out,
    );
    out
}

/// What an armed inode stands for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Armed {
    pub path: String,
    pub class: SensitiveClass,
}

/// Resolve candidates to `(dev, ino)` keys. Only regular files are armed (a
/// symlink is followed so the *target* inode, which is what `vfs_open` sees, is
/// armed); missing or unreadable candidates are skipped. Deterministic: when two
/// candidates share an inode (hard link) the first in list order wins.
pub fn resolve(cands: &[Candidate]) -> BTreeMap<[u64; 2], Armed> {
    let mut out = BTreeMap::new();
    for c in cands {
        if out.len() >= MAX_ARMED {
            break;
        }
        let Ok(meta) = std::fs::metadata(&c.fs_path) else {
            continue;
        };
        if !meta.is_file() {
            continue;
        }
        out.entry(super::honeytoken_layout::inode_key(meta.dev(), meta.ino()))
            .or_insert_with(|| Armed {
                path: c.display.clone(),
                class: c.class,
            });
    }
    out
}

/// Difference between the armed and the desired inode sets.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Plan {
    pub add: Vec<([u64; 2], u32)>,
    pub remove: Vec<[u64; 2]>,
}

/// Compute the map updates. A class change on a stable inode is remove + add.
pub fn plan(
    current: &BTreeMap<[u64; 2], SensitiveClass>,
    desired: &BTreeMap<[u64; 2], Armed>,
) -> Plan {
    let mut p = Plan::default();
    for (key, armed) in desired {
        if current.get(key) != Some(&armed.class) {
            p.add.push((*key, armed.class as u32));
        }
    }
    for (key, class) in current {
        if desired.get(key).map(|a| a.class) != Some(*class) {
            // A class change is re-added above; removal is only for the stale
            // key itself and must not undo that insert.
            if !desired.contains_key(key) {
                p.remove.push(*key);
            }
        }
    }
    p
}

// ── Rate limit ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Emit; `suppressed_before` events of this key were dropped since the last
    /// emitted one.
    Emit {
        suppressed_before: u64,
    },
    Suppress,
}

struct KeyState {
    window_start: Instant,
    emitted: u32,
    suppressed: u64,
}

/// Rate limiter for identical `(exe, path)` events plus a global budget. Pure
/// (time is injected) so it is unit-testable.
pub struct ReadLimiter {
    keys: HashMap<(String, String), KeyState>,
    global_start: Instant,
    global_emitted: u32,
    global_suppressed: u64,
}

/// One idle key whose suppressed count was never carried by a later event.
#[derive(Debug, PartialEq, Eq)]
pub struct Summary {
    pub exe: String,
    pub path: String,
    pub suppressed: u64,
}

impl ReadLimiter {
    pub fn new(now: Instant) -> Self {
        Self {
            keys: HashMap::new(),
            global_start: now,
            global_emitted: 0,
            global_suppressed: 0,
        }
    }

    pub fn check(&mut self, exe: &str, path: &str, now: Instant) -> Verdict {
        if now.duration_since(self.global_start) >= LIMIT_WINDOW {
            self.global_start = now;
            self.global_emitted = 0;
        }
        let global_ok = self.global_emitted < GLOBAL_BURST;

        if self.keys.len() >= MAX_KEYS
            && !self.keys.contains_key(&(exe.to_string(), path.to_string()))
        {
            self.keys.retain(|_, s| {
                now.duration_since(s.window_start) < LIMIT_WINDOW || s.suppressed > 0
            });
        }
        let tracked = self.keys.len() < MAX_KEYS
            || self.keys.contains_key(&(exe.to_string(), path.to_string()));

        if !tracked {
            // Key table saturated with live keys: only the global budget applies.
            return if global_ok {
                self.global_emitted += 1;
                Verdict::Emit {
                    suppressed_before: 0,
                }
            } else {
                self.global_suppressed += 1;
                Verdict::Suppress
            };
        }

        let st = self
            .keys
            .entry((exe.to_string(), path.to_string()))
            .or_insert(KeyState {
                window_start: now,
                emitted: 0,
                suppressed: 0,
            });
        if now.duration_since(st.window_start) >= LIMIT_WINDOW {
            st.window_start = now;
            st.emitted = 0;
        }
        if st.emitted >= KEY_BURST || !global_ok {
            st.suppressed += 1;
            if !global_ok {
                self.global_suppressed += 1;
            }
            return Verdict::Suppress;
        }
        st.emitted += 1;
        self.global_emitted += 1;
        Verdict::Emit {
            suppressed_before: std::mem::take(&mut st.suppressed),
        }
    }

    /// Remove keys idle for a full window and report the ones that still hold
    /// an unreported suppressed count, plus the global-budget suppressions.
    pub fn drain_idle(&mut self, now: Instant) -> (Vec<Summary>, u64) {
        let mut out = Vec::new();
        self.keys.retain(|(exe, path), s| {
            if now.duration_since(s.window_start) < LIMIT_WINDOW {
                return true;
            }
            if s.suppressed > 0 {
                out.push(Summary {
                    exe: exe.clone(),
                    path: path.clone(),
                    suppressed: s.suppressed,
                });
            }
            false
        });
        out.sort_by_key(|a| std::cmp::Reverse(a.suppressed));
        (out, std::mem::take(&mut self.global_suppressed))
    }
}

// ── Kernel event ─────────────────────────────────────────────────────────────

const COMM_LEN: usize = 16;
const PID_MAX: u32 = 4_194_304;

/// Matches `SensitiveReadEvent` in trapd-agent-ebpf/src/file_open.rs exactly.
#[repr(C)]
#[derive(Clone, Copy)]
struct RawSensitiveReadEvent {
    pid: u32,
    uid: u32,
    gid: u32,
    class_id: u32,
    flags: u64,
    dev: u64,
    ino: u64,
    observed_monotonic_ns: u64,
    comm: [u8; COMM_LEN],
}

fn decode(bytes: &[u8]) -> Option<RawSensitiveReadEvent> {
    if bytes.len() < std::mem::size_of::<RawSensitiveReadEvent>() {
        return None;
    }
    // SAFETY: length checked above; repr(C) of plain integers, read unaligned.
    let ev: RawSensitiveReadEvent =
        unsafe { std::ptr::read_unaligned(bytes.as_ptr().cast::<RawSensitiveReadEvent>()) };
    // A layout drift between kernel and userspace shows up as an implausible
    // pid or class; drop rather than ship garbage (same canary as `read_raw`).
    ((1..=PID_MAX).contains(&ev.pid) && SensitiveClass::from_id(ev.class_id).is_some())
        .then_some(ev)
}

fn cstr(buf: &[u8]) -> String {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end]).into_owned()
}

/// Process facts that can be established after the fact.
pub struct Opener {
    pub exe: Option<String>,
    pub start_time: Option<u64>,
}

/// Look the opener up in `/proc`. `process_start_time` is only reported when its
/// creation tick provably ended before the kernel timestamp of the open and is
/// unchanged after the `exe` read (PID-reuse guard, AGENTS.md process identity).
fn lookup_opener(pid: u32, observed_ns: u64) -> Opener {
    let exe = std::fs::read_link(format!("/proc/{pid}/exe"))
        .ok()
        .map(|p| p.to_string_lossy().into_owned());
    let start = crate::telemetry::identity::process_start_time(pid as i32);
    // SAFETY: sysconf takes no pointers and queries a constant property.
    let ticks = u64::try_from(unsafe { libc::sysconf(libc::_SC_CLK_TCK) }).unwrap_or(0);
    let start_time = start.filter(|s| {
        trapd_detection::honeytoken::generation_before_access(*s, observed_ns, ticks)
            && crate::telemetry::identity::process_start_time(pid as i32) == Some(*s)
    });
    Opener { exe, start_time }
}

/// Build the event. Pure apart from the supplied `Opener`.
#[allow(clippy::too_many_arguments)]
fn build_event(
    agent_id: &str,
    hostname: &str,
    ev: &RawSensitiveReadEvent,
    armed: &Armed,
    opener: Opener,
    username: String,
    suppressed_before: u64,
) -> AgentEvent {
    AgentEvent::new(
        agent_id.to_string(),
        hostname.to_string(),
        EventClass::Filesystem,
        EventAction::Open,
        Severity::Info,
        EventData::FileOpen(FileOpenData {
            pid: ev.pid as i32,
            uid: ev.uid,
            gid: ev.gid,
            username,
            comm: cstr(&ev.comm),
            path: armed.path.clone(),
            flags: ev.flags,
            exe: opener.exe,
            process_start_time: opener.start_time,
            sensitive_class: Some(armed.class.name().to_string()),
            suppressed_repeats: (suppressed_before > 0).then_some(suppressed_before),
        }),
    )
}

// ── Wiring ───────────────────────────────────────────────────────────────────

type InodeMap = BpfHashMap<MapData, [u64; 2], u32>;
type Index = Arc<RwLock<BTreeMap<[u64; 2], Armed>>>;

fn enabled(cfg: &Option<Arc<RwLock<AgentConfig>>>) -> bool {
    // No live config (minimal/test wiring) keeps the compiled-in default.
    cfg.as_ref()
        .and_then(|c| c.read().ok().map(|c| c.sensitive_file_read_enabled))
        .unwrap_or(true)
}

fn apply(map: &mut InodeMap, armed: &mut BTreeMap<[u64; 2], SensitiveClass>, p: Plan) {
    for (key, class) in p.add {
        // Insert before remove-on-failure bookkeeping: only record what the
        // kernel accepted so a failed insert is retried on the next refresh.
        match map.insert(key, class, 0) {
            Ok(()) => {
                if let Some(c) = SensitiveClass::from_id(class) {
                    armed.insert(key, c);
                }
            }
            Err(e) => warn!(error = %e, "sensitive-file inode arm failed"),
        }
    }
    for key in p.remove {
        if map.remove(&key).is_ok() || !armed.contains_key(&key) {
            armed.remove(&key);
        }
    }
}

/// Take the sensitive-file maps from `bpf` and spawn the reconciler and the
/// consumer. Returns the task handles for the caller to abort on teardown.
/// Missing maps (older eBPF object) or an inactive `vfs_open` kprobe disable the
/// feature without touching the other sensors.
pub fn spawn(
    bpf: &mut Ebpf,
    kprobe_active: bool,
    cfg: Option<Arc<RwLock<AgentConfig>>>,
    tx: Sender<AgentEvent>,
    agent_id: String,
    hostname: String,
) -> Vec<tokio::task::AbortHandle> {
    let mut handles = Vec::new();
    crate::telemetry::coverage::update(|c| c.ebpf_sensitive_file_read = Some(false));
    if !kprobe_active {
        info!("sensitive-file read sensor inactive: vfs_open inode probe is not attached");
        return handles;
    }
    let (Some(inodes_raw), Some(ring_raw)) = (
        bpf.take_map("SENSITIVE_INODES"),
        bpf.take_map("SENSITIVE_READ_EVENTS"),
    ) else {
        info!("eBPF binary has no sensitive-file maps — sensitive-file read sensor unavailable");
        return handles;
    };
    let (Ok(mut inodes), Ok(ring)) = (InodeMap::try_from(inodes_raw), RingBuf::try_from(ring_raw))
    else {
        warn!("sensitive-file maps not usable — sensor disabled");
        return handles;
    };
    let Ok(mut ring) = AsyncFd::new(ring) else {
        warn!("sensitive-file ring buffer not pollable — sensor disabled");
        return handles;
    };
    crate::telemetry::coverage::update(|c| c.ebpf_sensitive_file_read = Some(true));
    info!("sensitive-file read sensor active");

    let index: Index = Arc::new(RwLock::new(BTreeMap::new()));

    // Reconciler.
    {
        let index = Arc::clone(&index);
        let cfg = cfg.clone();
        handles.push(
            tokio::spawn(async move {
                let mut armed: BTreeMap<[u64; 2], SensitiveClass> = BTreeMap::new();
                let mut watcher = DirWatcher::new();
                let mut ticker = tokio::time::interval(REFRESH_INTERVAL);
                loop {
                    let on = enabled(&cfg);
                    let desired = if on {
                        resolve(&candidates(Path::new("/")))
                    } else {
                        BTreeMap::new()
                    };
                    let p = plan(&armed, &desired);
                    apply(&mut inodes, &mut armed, p);
                    // Index only what the kernel actually holds, so an event is
                    // never attributed to a path that was not armed.
                    if let Ok(mut idx) = index.write() {
                        *idx = desired
                            .into_iter()
                            .filter(|(k, _)| armed.contains_key(k))
                            .collect();
                    }
                    tokio::select! {
                        _ = ticker.tick() => {}
                        _ = watcher.changed() => {
                            tokio::time::sleep(DEBOUNCE).await;
                            watcher.drain();
                        }
                    }
                }
            })
            .abort_handle(),
        );
    }

    // Consumer.
    handles.push(
        tokio::spawn(async move {
            let agent_pid = std::process::id();
            let mut limiter = ReadLimiter::new(Instant::now());
            let mut summary = tokio::time::interval(SUMMARY_INTERVAL);
            summary.tick().await;
            loop {
                tokio::select! {
                    _ = summary.tick() => {
                        let (idle, global) = limiter.drain_idle(Instant::now());
                        if !idle.is_empty() || global > 0 {
                            let top: Vec<String> = idle
                                .iter()
                                .take(10)
                                .map(|s| format!("{} {} x{}", s.exe, s.path, s.suppressed))
                                .collect();
                            info!(
                                idle_keys = idle.len(),
                                global_budget_suppressed = global,
                                top = ?top,
                                "sensitive-file reads suppressed by rate limit (counted as rate_limit_applied)"
                            );
                        }
                    }
                    guard = ring.readable_mut() => {
                        let Ok(mut guard) = guard else {
                            warn!("sensitive-file ring buffer closed — sensor stopped");
                            crate::telemetry::coverage::update(|c| c.ebpf_sensitive_file_read = Some(false));
                            return;
                        };
                        let rb = guard.get_inner_mut();
                        while let Some(item) = rb.next() {
                            let Some(ev) = decode(&item) else { continue };
                            if !enabled(&cfg) || ev.pid == agent_pid {
                                // Disabled by config, or the agent's own read:
                                // intentional exclusion, not a loss.
                                continue;
                            }
                            let key = [ev.dev, ev.ino];
                            let armed = index.read().ok().and_then(|i| i.get(&key).cloned());
                            let Some(armed) = armed else {
                                // Inode rotated out between the kernel match and
                                // this lookup: the event cannot be attributed to
                                // a path. Counted, never silent.
                                metrics().event_dropped(DropReason::InternalError);
                                continue;
                            };
                            let exe_hint = std::fs::read_link(format!("/proc/{}/exe", ev.pid))
                                .ok()
                                .map(|p| p.to_string_lossy().into_owned())
                                .unwrap_or_else(|| format!("comm:{}", cstr(&ev.comm)));
                            let suppressed_before = match limiter.check(&exe_hint, &armed.path, Instant::now()) {
                                Verdict::Emit { suppressed_before } => suppressed_before,
                                Verdict::Suppress => {
                                    metrics().event_dropped(DropReason::RateLimitApplied);
                                    continue;
                                }
                            };
                            let opener = lookup_opener(ev.pid, ev.observed_monotonic_ns);
                            let username = super::ebpf_syscalls::proc_username(ev.uid);
                            let event = build_event(&agent_id, &hostname, &ev, &armed, opener, username, suppressed_before);
                            if tx.is_closed() {
                                return;
                            }
                            crate::pipeline::try_emit(&tx, event, "sensitive_file_read");
                        }
                        guard.clear_ready();
                    }
                }
            }
        })
        .abort_handle(),
    );
    handles
}

/// inotify watch on the directories that hold armed files. Directories missing
/// at start are covered by the periodic refresh.
struct DirWatcher {
    fd: Option<AsyncFd<Inotify>>,
    /// Descriptors of directories where every entry is relevant.
    all_entries: Vec<inotify::WatchDescriptor>,
}

impl DirWatcher {
    fn new() -> Self {
        let fd = Inotify::init().ok().and_then(|i| {
            let mask = WatchMask::CREATE
                | WatchMask::MOVED_TO
                | WatchMask::MOVED_FROM
                | WatchMask::DELETE
                | WatchMask::CLOSE_WRITE;
            let mut all = Vec::new();
            let mut any = false;
            for (dir, every) in WATCHED_DIRS {
                if let Ok(wd) = i.watches().add(dir, mask) {
                    any = true;
                    if every {
                        all.push(wd);
                    }
                }
            }
            any.then_some((i, all))
        });
        let (fd, all_entries) = match fd {
            Some((i, all)) => (AsyncFd::new(i).ok(), all),
            None => (None, Vec::new()),
        };
        if fd.is_none() {
            warn!(
                "sensitive-file watcher unavailable — relying on the {REFRESH_INTERVAL:?} refresh"
            );
        }
        Self { fd, all_entries }
    }

    /// Resolve when a relevant entry changed; pends forever without a watcher.
    async fn changed(&mut self) {
        let all_entries = self.all_entries.clone();
        let Some(fd) = self.fd.as_mut() else {
            return std::future::pending().await;
        };
        loop {
            let Ok(mut guard) = fd.readable_mut().await else {
                return std::future::pending().await;
            };
            let mut buf = [0u8; 4096];
            let mut relevant = false;
            while let Ok(events) = guard.get_inner_mut().read_events(&mut buf) {
                let mut seen = false;
                for e in events {
                    seen = true;
                    if let Some(name) = e.name.and_then(|n| n.to_str()) {
                        relevant |= is_relevant_name(name, all_entries.contains(&e.wd));
                    }
                }
                if !seen {
                    break;
                }
            }
            guard.clear_ready();
            if relevant {
                return;
            }
        }
    }

    /// Discard events queued during the debounce delay.
    fn drain(&mut self) {
        if let Some(fd) = self.fd.as_mut() {
            let mut buf = [0u8; 4096];
            while let Ok(events) = fd.get_mut().read_events(&mut buf) {
                if events.count() == 0 {
                    break;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("trapd-sens-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn touch(root: &Path, rel: &str) {
        let p = root.join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, b"x").unwrap();
    }

    #[test]
    fn candidates_expand_fixed_list() {
        let r = tmp("cand");
        for f in [
            "etc/shadow",
            "etc/sudoers.d/90-admin",
            "etc/ssh/ssh_host_ed25519_key",
            "etc/ssh/ssh_host_ed25519_key.pub",
            "etc/ssh/sshd_config",
            "root/.ssh/id_rsa",
            "root/.ssh/id_rsa.pub",
            "root/.ssh/known_hosts",
        ] {
            touch(&r, f);
        }
        let c = candidates(&r);
        let shown: Vec<&str> = c.iter().map(|c| c.display.as_str()).collect();
        assert!(shown.contains(&"/etc/shadow"));
        assert!(shown.contains(&"/etc/sudoers.d/90-admin"));
        assert!(shown.contains(&"/etc/ssh/ssh_host_ed25519_key"));
        assert!(shown.contains(&"/root/.ssh/id_rsa"));
        assert!(!shown.iter().any(|p| p.ends_with(".pub")));
        assert!(!shown.contains(&"/etc/ssh/sshd_config"));
        assert!(!shown.contains(&"/root/.ssh/known_hosts"));
        assert!(!shown.contains(&"/etc/passwd"));
        let _ = fs::remove_dir_all(r);
    }

    #[test]
    fn resolve_skips_missing_and_non_regular_and_follows_replacement() {
        let r = tmp("res");
        touch(&r, "etc/shadow");
        fs::create_dir_all(r.join("etc/gshadow")).unwrap(); // directory: not armed
        let first = resolve(&candidates(&r));
        assert_eq!(first.len(), 1);
        let (k1, a1) = first.iter().next().unwrap();
        assert_eq!(a1.path, "/etc/shadow");
        assert_eq!(a1.class, SensitiveClass::Shadow);

        // passwd-style replacement: new file renamed over the old one.
        fs::write(r.join("etc/nshadow"), b"y").unwrap();
        fs::rename(r.join("etc/nshadow"), r.join("etc/shadow")).unwrap();
        let second = resolve(&candidates(&r));
        let k2 = second.keys().next().unwrap();
        assert_ne!(k1, k2, "replacement must yield a new inode key");

        let cur: BTreeMap<_, _> = first.iter().map(|(k, a)| (*k, a.class)).collect();
        let p = plan(&cur, &second);
        assert_eq!(p.add, vec![(*k2, SensitiveClass::Shadow as u32)]);
        assert_eq!(p.remove, vec![*k1]);
        let _ = fs::remove_dir_all(r);
    }

    #[test]
    fn plan_is_noop_when_unchanged_and_clears_when_disabled() {
        let key = [1, 2];
        let armed = Armed {
            path: "/etc/shadow".into(),
            class: SensitiveClass::Shadow,
        };
        let desired = BTreeMap::from([(key, armed)]);
        let cur = BTreeMap::from([(key, SensitiveClass::Shadow)]);
        assert_eq!(plan(&cur, &desired), Plan::default());
        let p = plan(&cur, &BTreeMap::new());
        assert_eq!(p.remove, vec![key]);
        assert!(p.add.is_empty());
        // class change on same inode: re-added, not removed
        let cur2 = BTreeMap::from([(key, SensitiveClass::Gshadow)]);
        let p = plan(&cur2, &desired);
        assert_eq!(p.add.len(), 1);
        assert!(p.remove.is_empty());
    }

    #[test]
    fn relevant_names() {
        assert!(is_relevant_name("shadow", false));
        assert!(is_relevant_name("ssh_host_rsa_key", false));
        assert!(is_relevant_name("id_ed25519", false));
        assert!(!is_relevant_name("id_ed25519.pub", false));
        assert!(!is_relevant_name("hosts", false));
        assert!(is_relevant_name("anything", true));
    }

    #[test]
    fn limiter_bursts_then_suppresses_and_reports_count() {
        let t0 = Instant::now();
        let mut l = ReadLimiter::new(t0);
        for _ in 0..KEY_BURST {
            assert_eq!(
                l.check("/usr/sbin/sshd", "/etc/shadow", t0),
                Verdict::Emit {
                    suppressed_before: 0
                }
            );
        }
        assert_eq!(
            l.check("/usr/sbin/sshd", "/etc/shadow", t0),
            Verdict::Suppress
        );
        assert_eq!(
            l.check("/usr/sbin/sshd", "/etc/shadow", t0),
            Verdict::Suppress
        );
        // a different exe is not affected
        assert_eq!(
            l.check("/usr/bin/cat", "/etc/shadow", t0),
            Verdict::Emit {
                suppressed_before: 0
            }
        );
        // next window: count is carried by the next emitted event
        let t1 = t0 + LIMIT_WINDOW + Duration::from_secs(1);
        assert_eq!(
            l.check("/usr/sbin/sshd", "/etc/shadow", t1),
            Verdict::Emit {
                suppressed_before: 2
            }
        );
    }

    #[test]
    fn limiter_global_budget_and_idle_summary() {
        let t0 = Instant::now();
        let mut l = ReadLimiter::new(t0);
        let mut emitted = 0;
        for i in 0..(GLOBAL_BURST + 10) {
            if matches!(
                l.check(&format!("/bin/p{i}"), "/etc/shadow", t0),
                Verdict::Emit { .. }
            ) {
                emitted += 1;
            }
        }
        assert_eq!(emitted, GLOBAL_BURST);
        // idle key with unreported suppressions is summarised, then forgotten
        for _ in 0..(KEY_BURST + 2) {
            l.check("/bin/loop", "/etc/gshadow", t0 + LIMIT_WINDOW);
        }
        let (idle, global) = l.drain_idle(t0 + LIMIT_WINDOW * 3);
        assert_eq!(global, 10);
        assert!(idle
            .iter()
            .any(|s| s.exe == "/bin/loop" && s.suppressed == 2));
        let (idle, global) = l.drain_idle(t0 + LIMIT_WINDOW * 4);
        assert!(idle.is_empty());
        assert_eq!(global, 0);
    }

    #[test]
    fn decode_rejects_short_and_implausible() {
        assert!(decode(&[0u8; 8]).is_none());
        assert!(decode(&[0u8; std::mem::size_of::<RawSensitiveReadEvent>()]).is_none());
        assert_eq!(std::mem::size_of::<RawSensitiveReadEvent>(), 64);
    }

    #[test]
    fn event_shape() {
        let mut comm = [0u8; COMM_LEN];
        comm[..3].copy_from_slice(b"cat");
        let ev = RawSensitiveReadEvent {
            pid: 42,
            uid: 1000,
            gid: 1000,
            class_id: 1,
            flags: 0,
            dev: 1,
            ino: 2,
            observed_monotonic_ns: 5,
            comm,
        };
        let armed = Armed {
            path: "/etc/shadow".into(),
            class: SensitiveClass::Shadow,
        };
        let e = build_event(
            "a",
            "h",
            &ev,
            &armed,
            Opener {
                exe: Some("/usr/bin/cat".into()),
                start_time: Some(77),
            },
            "alice".into(),
            4,
        );
        assert!(matches!(e.class, EventClass::Filesystem));
        assert!(matches!(e.action, EventAction::Open));
        let v = serde_json::to_value(&e).unwrap();
        let d = &v["data"];
        assert_eq!(d["path"], "/etc/shadow");
        assert_eq!(d["pid"], 42);
        assert_eq!(d["process_start_time"], 77);
        assert_eq!(d["exe"], "/usr/bin/cat");
        assert_eq!(d["comm"], "cat");
        assert_eq!(d["sensitive_class"], "shadow");
        assert_eq!(d["suppressed_repeats"], 4);
        assert_eq!(d["flags"], 0);
    }
}
