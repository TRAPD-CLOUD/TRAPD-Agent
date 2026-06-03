//! eBPF-backed syscall tracer for Linux (kernel ≥ 5.8).
//!
//! Loads the same `trapd-agent-exec` eBPF binary as [`EbpfExecCollector`] and
//! attaches the following programs:
//!
//! | Program               | Tracepoint / kprobe                   | Event type   |
//! |-----------------------|---------------------------------------|--------------|
//! | sys_enter_openat      | syscalls/sys_enter_openat             | FileOpen     |
//! | sys_enter_open*       | syscalls/sys_enter_open               | Honeytoken   |
//! | sys_enter_openat2*    | syscalls/sys_enter_openat2            | Honeytoken   |
//! | sys_enter_newfstatat* | syscalls/sys_enter_newfstatat         | Honeytoken   |
//! | sys_enter_statx*      | syscalls/sys_enter_statx              | Honeytoken   |
//! | sys_enter_readlinkat* | syscalls/sys_enter_readlinkat         | Honeytoken   |
//! | sys_enter_linkat*     | syscalls/sys_enter_linkat             | Honeytoken   |
//! | sys_exit_open{,at,at2}*| syscalls/sys_exit_open*              | (fd binding) |
//! | sys_enter_getdents64* | syscalls/sys_enter_getdents64         | Honeytoken   |
//! | sys_enter_close*      | syscalls/sys_enter_close              | (fd pruning) |
//! | sys_enter_connect     | syscalls/sys_enter_connect            | NetworkSocket|
//! | sys_enter_bind        | syscalls/sys_enter_bind               | NetworkSocket|
//! | sys_enter_accept4     | syscalls/sys_enter_accept4            | NetworkSocket|
//! | sched_process_fork    | sched/sched_process_fork              | Fork         |
//! | sys_enter_unlinkat    | syscalls/sys_enter_unlinkat           | FileUnlink   |
//! | sys_enter_renameat2   | syscalls/sys_enter_renameat2          | FileRename   |
//! | sys_enter_fchmodat    | syscalls/sys_enter_fchmodat           | FileChmod    |
//! | sys_enter_fchownat    | syscalls/sys_enter_fchownat           | FileChown    |
//! | sys_enter_mmap        | syscalls/sys_enter_mmap               | Mmap         |
//! | sys_enter_ptrace      | syscalls/sys_enter_ptrace             | Ptrace       |
//! | module_load           | module/module_load                    | ModuleLoad   |
//! | sys_enter_shmget      | syscalls/sys_enter_shmget             | Shm          |
//! | sys_enter_shmat       | syscalls/sys_enter_shmat              | Shm          |
//! | sys_enter_unshare     | syscalls/sys_enter_unshare            | NsChange     |
//! | sys_enter_setns       | syscalls/sys_enter_setns              | NsChange     |
//! | kprobe__udp_sendmsg   | kprobe:udp_sendmsg                    | Dns          |
//! | vfs_open*             | kprobe:vfs_open                       | Honeytoken   |
//!
//! Honeytoken detection spans several programs, all feeding
//! `HoneytokenAccessEvent` tagged with an `access_kind`:
//!
//!   * **content read** — the `vfs_open` kprobe (issue #32, point 2a) resolves
//!     the opened *inode* and matches `HONEYTOKEN_INODES`, firing regardless of
//!     open flags and robust against symlinks, relative paths, `..` and
//!     hardlinks. This is the canonical open detector; the `sys_enter_open*`
//!     tracepoints no longer emit for opens, they only stash the returned fd.
//!   * **metadata recon / tamper / hardlink** — the `sys_enter_{newfstatat,
//!     statx,readlinkat,linkat,unlinkat,renameat2}` tracepoints match by path
//!     via `HONEYTOKEN_PATHS`; token exec is gated in `sched_process_exec`.
//!   * **mmap (content read) / getdents64 (directory recon)** — correlated by
//!     binding the fd a token `open` returns (`sys_exit_open*`) and releasing it
//!     on `close`.
//!
//! Programs marked `*` are attached best-effort: they are arch/kernel-specific
//! (e.g. `open` is absent on arm64, `openat2` needs ≥ 5.6, `statx` needs ≥ 4.11),
//! so a failed attach is logged and tolerated rather than aborting the collector.

use std::collections::{HashMap as StdHashMap, HashSet};
use std::os::unix::fs::MetadataExt;
use std::sync::{Arc, RwLock};
use std::{fs, net::Ipv4Addr};

use anyhow::{Context, Result};
use async_trait::async_trait;
use aya::{
    maps::RingBuf,
    programs::{KProbe, TracePoint},
    Ebpf,
};
// MapData is the owned map type returned by Ebpf::take_map; importing it here
// ensures the TryFrom<Map> → RingBuf<MapData> conversion is unambiguous.
use aya::maps::HashMap as BpfHashMap;
use aya::maps::{MapData, PerCpuArray};
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc::Sender;
use tokio::time::{interval, Duration, MissedTickBehavior};
use tracing::{info, warn};

use crate::collectors::linux::ebpf_drops::DropMonitor;
use crate::collectors::Collector;
use crate::config::AgentConfig;
use crate::detection::honeytoken::{self, AccessHit, AccessKind, Allowlist, RealProc};
use crate::schema::{
    AgentEvent, DnsData, EventAction, EventClass, EventData, FileChmodData, FileChownData,
    FileOpenData, FileRenameData, FileUnlinkData, ForkData, KillAttemptData, MemfdCreateData,
    MmapData, ModuleLoadData, NetworkSocketData, NsChangeData, PtraceData, SetuidData, Severity,
    ShmData, WriteRateAnomalyData,
};

/// How often the eBPF ring-buffer drop counters are polled and exported (#52).
const DROP_POLL_INTERVAL: Duration = Duration::from_secs(30);

// ── Kernel ↔ Userspace struct layouts ────────────────────────────────────────
// Every struct here must be repr(C) and match its counterpart in
// trapd-agent-ebpf/src/*.rs exactly (field order, padding, sizes).

const COMM_LEN: usize = 16;
const PATH_LEN: usize = 256;

/// Shared `token_id → (uuid, path, kind)` lookup, written by the honeytoken
/// reconciler and read by the access consumer.
type TokenIndex = Arc<RwLock<StdHashMap<u64, (String, String, String)>>>;

#[repr(C)]
struct RawFileOpenEvent {
    pid: u32,
    uid: u32,
    gid: u32,
    flags: u64,
    comm: [u8; COMM_LEN],
    filename: [u8; PATH_LEN],
    filename_len: u32,
}

#[repr(C)]
struct RawNetEvent {
    pid: u32,
    uid: u32,
    gid: u32,
    op: u8,
    _pad0: [u8; 1],
    family: u16,
    port: u16,
    _pad1: [u8; 6],
    comm: [u8; COMM_LEN],
    addr: [u8; 16],
}

#[repr(C)]
struct RawForkEvent {
    parent_pid: u32,
    child_pid: u32,
    parent_comm: [u8; COMM_LEN],
    child_comm: [u8; COMM_LEN],
}

#[repr(C)]
struct RawFileUnlinkEvent {
    pid: u32,
    uid: u32,
    gid: u32,
    _pad: u32,
    comm: [u8; COMM_LEN],
    path: [u8; PATH_LEN],
    path_len: u32,
}

#[repr(C)]
struct RawFileRenameEvent {
    pid: u32,
    uid: u32,
    gid: u32,
    _pad: u32,
    comm: [u8; COMM_LEN],
    old_path: [u8; PATH_LEN],
    old_path_len: u32,
    new_path: [u8; PATH_LEN],
    new_path_len: u32,
}

#[repr(C)]
struct RawFileChmodEvent {
    pid: u32,
    uid: u32,
    gid: u32,
    mode: u32,
    comm: [u8; COMM_LEN],
    path: [u8; PATH_LEN],
    path_len: u32,
}

#[repr(C)]
struct RawFileChownEvent {
    pid: u32,
    uid: u32,
    gid: u32,
    new_uid: u32,
    new_gid: u32,
    _pad: u32,
    comm: [u8; COMM_LEN],
    path: [u8; PATH_LEN],
    path_len: u32,
}

#[repr(C)]
struct RawMmapEvent {
    pid: u32,
    uid: u32,
    gid: u32,
    prot: u32,
    flags: u32,
    _pad: u32,
    addr: u64,
    len: u64,
    comm: [u8; COMM_LEN],
}

#[repr(C)]
struct RawPtraceEvent {
    pid: u32,
    uid: u32,
    gid: u32,
    request: u32,
    target_pid: u32,
    _pad: u32,
    comm: [u8; COMM_LEN],
}

#[repr(C)]
struct RawModuleLoadEvent {
    pid: u32,
    uid: u32,
    gid: u32,
    taints: u32,
    name: [u8; 64],
    name_len: u32,
}

#[repr(C)]
struct RawShmEvent {
    pid: u32,
    uid: u32,
    gid: u32,
    op: u8,
    _pad: [u8; 3],
    comm: [u8; COMM_LEN],
    key: i32,
    _pad2: u32,
    size: u64,
    flags: i32,
    _pad3: u32,
}

#[repr(C)]
struct RawNsChangeEvent {
    pid: u32,
    uid: u32,
    gid: u32,
    op: u8,
    _pad: [u8; 3],
    comm: [u8; COMM_LEN],
    flags: u64,
    nstype: u32,
    _pad2: u32,
}

#[repr(C)]
struct RawDnsEvent {
    pid: u32,
    uid: u32,
    gid: u32,
    family: u16,
    dst_port: u16,
    comm: [u8; COMM_LEN],
    dst_addr: [u8; 16],
}

/// Matches `WriteRateEvent` in trapd-agent-ebpf/src/write.rs exactly.
#[repr(C)]
struct RawWriteRateEvent {
    pid: u32,
    uid: u32,
    gid: u32,
    _pad: u32,
    comm: [u8; COMM_LEN],
    write_count: u64,
    burst_threshold: u64,
}

/// Matches `KillSignalEvent` in trapd-agent-ebpf/src/kill.rs exactly.
#[repr(C)]
struct RawKillSignalEvent {
    sender_pid: u32,
    sender_uid: u32,
    sender_gid: u32,
    target_pid: i32,
    signal: i32,
    comm: [u8; COMM_LEN],
}

/// Matches `SetuidEvent` in trapd-agent-ebpf/src/setuid.rs exactly.
#[repr(C)]
struct RawSetuidEvent {
    pid: u32,
    old_uid: u32,
    new_uid: u32,
    _pad: u32,
    comm: [u8; COMM_LEN],
}

const MEMFD_NAME_LEN: usize = 64;

/// Matches `MemfdEvent` in trapd-agent-ebpf/src/memfd.rs exactly.
#[repr(C)]
struct RawMemfdEvent {
    pid: u32,
    flags: u32,
    comm: [u8; COMM_LEN],
    name: [u8; MEMFD_NAME_LEN],
    name_len: u32,
    _pad: u32,
}

/// Matches `HoneytokenAccessEvent` in trapd-agent-ebpf/src/file_open.rs exactly.
#[repr(C)]
struct RawHoneytokenAccessEvent {
    pid: u32,
    uid: u32,
    gid: u32,
    _pad: u32,
    token_id: u64,
    ino: u64,
    flags: u64,
    comm: [u8; COMM_LEN],
    filename: [u8; PATH_LEN],
    filename_len: u32,
    access_kind: u32,
}

// ── Event validation ──────────────────────────────────────────────────────────
// Each event exposes its primary PID field so `read_raw` can reject records
// whose decoded layout is implausible (see `RawEbpfEvent`).

macro_rules! impl_raw_event_pid {
    ($($ty:ty => $field:ident),+ $(,)?) => {
        $(impl RawEbpfEvent for $ty {
            #[inline]
            fn primary_pid(&self) -> u32 { self.$field }
        })+
    };
}

impl_raw_event_pid! {
    RawFileOpenEvent    => pid,
    RawNetEvent         => pid,
    RawFileUnlinkEvent  => pid,
    RawFileRenameEvent  => pid,
    RawFileChmodEvent   => pid,
    RawFileChownEvent   => pid,
    RawMmapEvent        => pid,
    RawPtraceEvent      => pid,
    RawModuleLoadEvent  => pid,
    RawShmEvent         => pid,
    RawNsChangeEvent    => pid,
    RawDnsEvent         => pid,
    RawWriteRateEvent   => pid,
    RawForkEvent        => parent_pid,
    RawKillSignalEvent  => sender_pid,
    RawSetuidEvent      => pid,
    RawMemfdEvent       => pid,
    RawHoneytokenAccessEvent => pid,
}

// ── Collector ─────────────────────────────────────────────────────────────────

pub struct EbpfSyscallCollector {
    ebpf_path: Option<String>,
    /// Live agent config — drives honeytoken-detection enable + accessor
    /// allowlist. `None` disables honeytoken arming (e.g. in minimal tests).
    cfg: Option<Arc<RwLock<AgentConfig>>>,
}

impl EbpfSyscallCollector {
    pub fn new() -> Self {
        Self {
            ebpf_path: Self::locate_binary(),
            cfg: None,
        }
    }

    /// Attach the live config so honeytoken detection can be enabled and its
    /// accessor allowlist read at runtime.
    pub fn with_config(mut self, cfg: Arc<RwLock<AgentConfig>>) -> Self {
        self.cfg = Some(cfg);
        self
    }

    pub fn is_available(&self) -> bool {
        self.ebpf_path.is_some()
    }

    /// Wire up honeytoken detection on top of an already-loaded eBPF object.
    ///
    /// Two detached tasks: a reconciler that arms `HONEYTOKEN_PATHS` from the
    /// on-disk register every 15s, and a consumer that enriches each access hit
    /// into a `HoneytokenAccess` detection. No-ops if the binary lacks the maps.
    fn spawn_honeytoken_tasks(
        &self,
        bpf: &mut Ebpf,
        tx: Sender<AgentEvent>,
        agent_id: String,
        hostname: String,
    ) {
        let Some(paths_raw) = bpf.take_map("HONEYTOKEN_PATHS") else {
            info!(
                "eBPF honeytoken detection unavailable (older eBPF binary) — continuing without it"
            );
            return;
        };
        let paths_map: BpfHashMap<MapData, [u8; PATH_LEN], u64> = match BpfHashMap::try_from(
            paths_raw,
        ) {
            Ok(m) => m,
            Err(e) => {
                warn!(error = %e, "HONEYTOKEN_PATHS not usable — honeytoken detection disabled");
                return;
            }
        };
        // Parent-directory match table for getdents recon. Optional: an older
        // eBPF binary without it simply means no directory-recon coverage.
        let dirs_map: Option<BpfHashMap<MapData, [u8; PATH_LEN], u64>> = bpf
            .take_map("HONEYTOKEN_DIRS")
            .and_then(|raw| match BpfHashMap::try_from(raw) {
                Ok(m) => Some(m),
                Err(e) => {
                    warn!(error = %e, "HONEYTOKEN_DIRS not usable — directory-recon coverage disabled");
                    None
                }
            });
        // Inode match table for the vfs_open content-read detector. Optional: an
        // older eBPF binary without it falls back to path-only coverage.
        let inodes_map: Option<BpfHashMap<MapData, u64, u64>> = bpf
            .take_map("HONEYTOKEN_INODES")
            .and_then(|raw| match BpfHashMap::try_from(raw) {
                Ok(m) => Some(m),
                Err(e) => {
                    warn!(error = %e, "HONEYTOKEN_INODES not usable — inode content-read detection disabled");
                    None
                }
            });
        let access_afd = match bpf.take_map("HONEYTOKEN_ACCESS_EVENTS") {
            Some(map) => match RingBuf::try_from(map)
                .map_err(anyhow::Error::from)
                .and_then(|rb| Ok(AsyncFd::new(rb)?))
            {
                Ok(afd) => afd,
                Err(e) => {
                    warn!(error = %e, "HONEYTOKEN_ACCESS_EVENTS not usable — honeytoken detection disabled");
                    return;
                }
            },
            None => {
                warn!("HONEYTOKEN_ACCESS_EVENTS missing — honeytoken detection disabled");
                return;
            }
        };

        let cfg = self.cfg.clone();
        let agent_pid = std::process::id();
        // token_id(u64) → (uuid string, path, kind), written by the reconciler,
        // read by the access consumer.
        let token_index: TokenIndex = Arc::new(RwLock::new(StdHashMap::new()));

        // Reconciler.
        {
            let token_index = Arc::clone(&token_index);
            let cfg = cfg.clone();
            let mut paths_map = paths_map;
            let mut dirs_map = dirs_map;
            let mut inodes_map = inodes_map;
            tokio::spawn(async move {
                let mut armed: HashSet<[u8; PATH_LEN]> = HashSet::new();
                let mut armed_dirs: HashSet<[u8; PATH_LEN]> = HashSet::new();
                let mut armed_inodes: HashSet<u64> = HashSet::new();
                let mut ticker = tokio::time::interval(std::time::Duration::from_secs(15));
                loop {
                    ticker.tick().await;
                    let enabled = cfg
                        .as_ref()
                        .map(|c| {
                            c.read()
                                .map(|c| c.honeytoken_detection_enabled)
                                .unwrap_or(true)
                        })
                        .unwrap_or(false);
                    reconcile_honeytokens(
                        &mut paths_map,
                        dirs_map.as_mut(),
                        inodes_map.as_mut(),
                        &token_index,
                        &mut armed,
                        &mut armed_dirs,
                        &mut armed_inodes,
                        enabled,
                    );
                }
            });
        }

        // Access consumer.
        {
            let mut access_afd = access_afd;
            tokio::spawn(async move {
                info!("eBPF honeytoken detection active");
                loop {
                    let mut guard = match access_afd.readable_mut().await {
                        Ok(g) => g,
                        Err(_) => return,
                    };
                    let rb = guard.get_inner_mut();
                    while let Some(item) = rb.next() {
                        let Some(ev) = (unsafe { read_raw::<RawHoneytokenAccessEvent>(&item) })
                        else {
                            continue;
                        };
                        // Resolve the token from the index. Fall back to the
                        // kernel-reported path (path-based gates) or the matched
                        // inode (the vfs_open detector sends no path) if the index
                        // has not caught up to a very fresh deploy.
                        let (tid, path, kind) = token_index
                            .read()
                            .ok()
                            .and_then(|idx| idx.get(&ev.token_id).cloned())
                            .unwrap_or_else(|| {
                                let fname = cstr(&ev.filename);
                                let subject = if fname.is_empty() {
                                    format!("inode:{}", ev.ino)
                                } else {
                                    fname.to_string()
                                };
                                (
                                    format!("0x{:x}", ev.token_id),
                                    subject,
                                    "unknown".to_string(),
                                )
                            });
                        let comm = cstr(&ev.comm).to_string();
                        let extra: Vec<String> = cfg
                            .as_ref()
                            .and_then(|c| {
                                c.read()
                                    .ok()
                                    .map(|c| c.honeytoken_accessor_allowlist.clone())
                            })
                            .unwrap_or_default();
                        let allowlist = Allowlist::new(agent_pid, &extra);
                        let hit = AccessHit {
                            pid: ev.pid as i32,
                            uid: ev.uid,
                            gid: ev.gid,
                            comm: &comm,
                            open_flags: ev.flags,
                            token_id: &tid,
                            path: &path,
                            kind: &kind,
                            access_kind: AccessKind::from_u32(ev.access_kind),
                        };
                        if let Some(event) = honeytoken::build_access_event(
                            &agent_id, &hostname, &hit, &allowlist, &RealProc,
                        ) {
                            if tx.send(event).await.is_err() {
                                return;
                            }
                        }
                    }
                    guard.clear_ready();
                }
            });
        }
    }

    fn locate_binary() -> Option<String> {
        let sibling = std::env::current_exe().ok().and_then(|p| {
            p.parent()
                .map(|d| d.join("trapd-agent-exec").to_string_lossy().into_owned())
        });
        let candidates: &[Option<String>] = &[
            std::env::var("TRAPD_EBPF_PATH").ok(),
            Some("/usr/lib/trapd-agent/trapd-agent-exec".into()),
            Some("/usr/local/lib/trapd-agent/trapd-agent-exec".into()),
            sibling,
            Some("../../target/bpfel-unknown-none/release/trapd-agent-exec".into()),
        ];
        candidates
            .iter()
            .flatten()
            .find(|p| std::path::Path::new(p).exists())
            .cloned()
    }
}

impl Default for EbpfSyscallCollector {
    fn default() -> Self {
        Self::new()
    }
}

// ── /proc helpers (shared helpers, duplicated for independence) ───────────────

fn cstr(buf: &[u8]) -> &str {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    std::str::from_utf8(&buf[..end]).unwrap_or("")
}

fn proc_username(uid: u32) -> String {
    fs::read_to_string("/etc/passwd")
        .unwrap_or_default()
        .lines()
        .find_map(|line| {
            let mut fields = line.splitn(7, ':');
            let name = fields.next()?;
            let _ = fields.next();
            let u = fields.next()?.parse::<u32>().ok()?;
            (u == uid).then(|| name.to_string())
        })
        .unwrap_or_else(|| format!("uid:{uid}"))
}

/// Build the fixed-size, NUL-padded `HONEYTOKEN_PATHS` key for an absolute
/// path. Must mirror how the kernel reads the path into a zeroed buffer.
fn path_key(path: &str) -> [u8; PATH_LEN] {
    let mut key = [0u8; PATH_LEN];
    let b = path.as_bytes();
    // Leave at least one trailing NUL, matching the kernel's str read.
    let n = b.len().min(PATH_LEN - 1);
    key[..n].copy_from_slice(&b[..n]);
    key
}

/// Bring the in-kernel honeytoken tables in line with the on-disk register:
/// arm newly-deployed tokens (by path, by parent directory, and by inode), drop
/// revoked ones, and rebuild the `token_id → (uuid, path, kind)` index used to
/// enrich access events. When detection is disabled every table is cleared so
/// nothing is armed.
///
/// Three kernel tables, each gating a different mechanism:
///   * `HONEYTOKEN_PATHS` (by path) — recon/tamper/linkat gates + open-time fd
///     stash for mmap/getdents;
///   * `HONEYTOKEN_DIRS` (by parent dir) — getdents directory recon;
///   * `HONEYTOKEN_INODES` (by inode) — the `vfs_open` content-read detector,
///     robust against symlinks/relative/hardlinks.
#[allow(clippy::too_many_arguments)]
fn reconcile_honeytokens(
    map: &mut BpfHashMap<MapData, [u8; PATH_LEN], u64>,
    mut dirs_map: Option<&mut BpfHashMap<MapData, [u8; PATH_LEN], u64>>,
    mut inodes_map: Option<&mut BpfHashMap<MapData, u64, u64>>,
    token_index: &TokenIndex,
    armed: &mut HashSet<[u8; PATH_LEN]>,
    armed_dirs: &mut HashSet<[u8; PATH_LEN]>,
    armed_inodes: &mut HashSet<u64>,
    enabled: bool,
) {
    let mut desired: StdHashMap<[u8; PATH_LEN], u64> = StdHashMap::new();
    let mut desired_dirs: StdHashMap<[u8; PATH_LEN], u64> = StdHashMap::new();
    let mut desired_inodes: StdHashMap<u64, u64> = StdHashMap::new();
    let mut index: StdHashMap<u64, (String, String, String)> = StdHashMap::new();

    if enabled {
        for rec in crate::deception::HoneytokenStore::load().list() {
            let key = path_key(&rec.path);
            let tid = honeytoken::token_id_u64(&rec.id);
            desired.insert(key, tid);
            index.insert(
                tid,
                (rec.id.to_string(), rec.path.clone(), rec.kind.clone()),
            );
            // Arm the token's parent directory for getdents (directory) recon.
            if let Some(parent) = std::path::Path::new(&rec.path)
                .parent()
                .and_then(|p| p.to_str())
            {
                desired_dirs.entry(path_key(parent)).or_insert(tid);
            }
            // Arm the token's inode for the vfs_open content-read detector. The
            // token must exist on disk to learn its inode; a vanished token is
            // simply not armed here (and surfaces as a tamper signal elsewhere).
            if let Ok(meta) = fs::metadata(&rec.path) {
                desired_inodes.insert(meta.ino(), tid);
            }
        }
    }

    // Arm newly-desired paths.
    for (key, tid) in &desired {
        if !armed.contains(key) && map.insert(key, tid, 0).is_ok() {
            armed.insert(*key);
        }
    }
    // Disarm paths no longer desired (revoked, or detection turned off).
    let stale: Vec<[u8; PATH_LEN]> = armed
        .iter()
        .filter(|k| !desired.contains_key(*k))
        .copied()
        .collect();
    for key in stale {
        let _ = map.remove(&key);
        armed.remove(&key);
    }

    // Same arm/disarm dance for the parent-directory table, when present.
    if let Some(dirs) = dirs_map.as_mut() {
        for (key, tid) in &desired_dirs {
            if !armed_dirs.contains(key) && dirs.insert(key, tid, 0).is_ok() {
                armed_dirs.insert(*key);
            }
        }
        let stale_dirs: Vec<[u8; PATH_LEN]> = armed_dirs
            .iter()
            .filter(|k| !desired_dirs.contains_key(*k))
            .copied()
            .collect();
        for key in stale_dirs {
            let _ = dirs.remove(&key);
            armed_dirs.remove(&key);
        }
    }

    // Same arm/disarm dance for the inode table, when present.
    if let Some(inodes) = inodes_map.as_mut() {
        for (ino, tid) in &desired_inodes {
            if !armed_inodes.contains(ino) && inodes.insert(ino, tid, 0).is_ok() {
                armed_inodes.insert(*ino);
            }
        }
        let stale_inodes: Vec<u64> = armed_inodes
            .iter()
            .filter(|k| !desired_inodes.contains_key(*k))
            .copied()
            .collect();
        for ino in stale_inodes {
            let _ = inodes.remove(&ino);
            armed_inodes.remove(&ino);
        }
    }

    if let Ok(mut guard) = token_index.write() {
        *guard = index;
    }
}

fn format_ipv4(addr: &[u8; 16]) -> String {
    Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]).to_string()
}

fn format_ipv6(addr: &[u8; 16]) -> String {
    use std::net::Ipv6Addr;
    let a = u16::from_be_bytes([addr[0], addr[1]]);
    let b = u16::from_be_bytes([addr[2], addr[3]]);
    let c = u16::from_be_bytes([addr[4], addr[5]]);
    let d = u16::from_be_bytes([addr[6], addr[7]]);
    let e = u16::from_be_bytes([addr[8], addr[9]]);
    let f = u16::from_be_bytes([addr[10], addr[11]]);
    let g = u16::from_be_bytes([addr[12], addr[13]]);
    let h = u16::from_be_bytes([addr[14], addr[15]]);
    Ipv6Addr::new(a, b, c, d, e, f, g, h).to_string()
}

fn format_addr(family: u16, addr: &[u8; 16]) -> String {
    match family {
        2 => format_ipv4(addr),
        10 => format_ipv6(addr),
        _ => format!("unknown-family-{family}"),
    }
}

fn family_str(family: u16) -> &'static str {
    match family {
        2 => "ipv4",
        10 => "ipv6",
        _ => "unknown",
    }
}

fn net_op_str(op: u8) -> &'static str {
    match op {
        0 => "connect",
        1 => "bind",
        2 => "accept",
        _ => "unknown",
    }
}

fn ns_flags_to_string(flags: u64) -> String {
    const CLONE_NEWNS: u64 = 0x0002_0000;
    const CLONE_NEWPID: u64 = 0x2000_0000;
    const CLONE_NEWNET: u64 = 0x4000_0000;
    const CLONE_NEWUTS: u64 = 0x0400_0000;
    const CLONE_NEWUSER: u64 = 0x1000_0000;
    const CLONE_NEWIPC: u64 = 0x0800_0000;

    let mut parts: Vec<&str> = Vec::new();
    if flags & CLONE_NEWPID != 0 {
        parts.push("pid");
    }
    if flags & CLONE_NEWNET != 0 {
        parts.push("net");
    }
    if flags & CLONE_NEWNS != 0 {
        parts.push("mnt");
    }
    if flags & CLONE_NEWUTS != 0 {
        parts.push("uts");
    }
    if flags & CLONE_NEWUSER != 0 {
        parts.push("user");
    }
    if flags & CLONE_NEWIPC != 0 {
        parts.push("ipc");
    }
    if parts.is_empty() {
        format!("0x{flags:x}")
    } else {
        parts.join(",")
    }
}

fn mmap_description(prot: u32, flags: u32) -> String {
    const PROT_WRITE: u32 = 0x2;
    const PROT_EXEC: u32 = 0x4;
    const MAP_ANONYMOUS: u32 = 0x20;

    let anon = flags & MAP_ANONYMOUS != 0;
    let exec = prot & PROT_EXEC != 0;
    let write = prot & PROT_WRITE != 0;

    match (anon && exec, write && exec) {
        (true, true) => "anon|rwx".to_string(),
        (true, false) => "anon|exec".to_string(),
        (false, true) => "rwx".to_string(),
        _ => format!("prot=0x{prot:x}|flags=0x{flags:x}"),
    }
}

// ── safe read helper ──────────────────────────────────────────────────────────

/// Upper bound for a plausible PID. The kernel caps PIDs at
/// `/proc/sys/kernel/pid_max`, which itself cannot exceed 2^22 (4194304) on
/// 64-bit Linux. A value of 0 or above this bound after casting a ring-buffer
/// record indicates the kernel/userspace struct layouts have drifted (an ABI
/// change, a padding difference, or a partial-update deployment), so the bytes
/// are semantically garbage and the event must be dropped rather than shipped.
const PID_MAX: u32 = 4_194_304;

/// Implemented by every `Raw*Event` so [`read_raw`] can sanity-check a defining
/// field after the unaligned cast. We validate the primary PID field because it
/// is present in every event and its plausible range is tightly bounded, making
/// it a reliable canary for struct-layout mismatch.
trait RawEbpfEvent {
    fn primary_pid(&self) -> u32;
}

#[inline]
fn plausible_pid(pid: u32) -> bool {
    (1..=PID_MAX).contains(&pid)
}

/// Cast `bytes` into a `repr(C)` `Raw*Event`, then validate it. Returns `None`
/// when the buffer is too short *or* the decoded event fails its sanity check,
/// so a layout mismatch surfaces as a dropped event instead of garbage —
/// including potentially uninitialised kernel bytes — reaching the backend.
unsafe fn read_raw<T: RawEbpfEvent>(bytes: &[u8]) -> Option<T> {
    if bytes.len() < std::mem::size_of::<T>() {
        return None;
    }
    let ev: T = std::ptr::read_unaligned(bytes.as_ptr() as *const T);
    if !plausible_pid(ev.primary_pid()) {
        return None;
    }
    Some(ev)
}

// ── Collector impl ────────────────────────────────────────────────────────────

#[async_trait]
impl Collector for EbpfSyscallCollector {
    fn name(&self) -> &'static str {
        "EbpfSyscallCollector"
    }

    async fn run(
        &mut self,
        tx: Sender<AgentEvent>,
        agent_id: String,
        hostname: String,
    ) -> Result<()> {
        let path = self
            .ebpf_path
            .as_deref()
            .context("eBPF binary not found — run `cargo xtask build-ebpf --release`")?;

        let bytes = fs::read(path).with_context(|| format!("cannot read eBPF binary: {path}"))?;

        let mut bpf = Ebpf::load(&bytes)
            .context("failed to load eBPF program (requires Linux ≥ 5.8 and CAP_BPF)")?;

        // ── Attach tracepoints ────────────────────────────────────────────────
        macro_rules! attach_tp {
            ($cat:expr, $name:expr) => {{
                let prog: &mut TracePoint = bpf
                    .program_mut($name)
                    .with_context(|| format!("program '{}' not found in eBPF binary", $name))?
                    .try_into()
                    .with_context(|| format!("'{}' is not a TracePoint", $name))?;
                prog.load()
                    .with_context(|| format!("BPF verifier rejected '{}'", $name))?;
                prog.attach($cat, $name)
                    .with_context(|| format!("failed to attach {}/{}", $cat, $name))?;
            }};
        }

        // Best-effort attach: the program is loaded and attached, but a failure
        // (e.g. the tracepoint does not exist on this arch/kernel, or the eBPF
        // binary predates the program) is logged and tolerated instead of
        // aborting the whole collector. Used for the honeytoken-coverage
        // tracepoints, several of which are arch- or version-specific:
        // `open` is absent on arm64, `openat2` needs ≥ 5.6, `statx` needs ≥ 4.11.
        macro_rules! attach_tp_optional {
            ($cat:expr, $name:expr) => {{
                match bpf
                    .program_mut($name)
                    .and_then(|p| TryInto::<&mut TracePoint>::try_into(p).ok())
                {
                    Some(prog) => match prog.load().and_then(|_| prog.attach($cat, $name)) {
                        Ok(_) => {}
                        Err(e) => warn!(
                            tracepoint = format!("{}/{}", $cat, $name),
                            error = %e,
                            "optional honeytoken tracepoint not attached — coverage reduced"
                        ),
                    },
                    None => info!(
                        tracepoint = format!("{}/{}", $cat, $name),
                        "optional honeytoken tracepoint absent in eBPF binary — skipping"
                    ),
                }
            }};
        }

        attach_tp!("syscalls", "sys_enter_openat");
        // ── Honeytoken coverage: additional access paths (issue #32, point 1) ──
        // open/openat2 round out file-open coverage; the stat/statx/readlink
        // tracepoints catch metadata recon; linkat catches hardlink evasion.
        attach_tp_optional!("syscalls", "sys_enter_open");
        attach_tp_optional!("syscalls", "sys_enter_openat2");
        attach_tp_optional!("syscalls", "sys_enter_newfstatat");
        attach_tp_optional!("syscalls", "sys_enter_statx");
        attach_tp_optional!("syscalls", "sys_enter_readlinkat");
        attach_tp_optional!("syscalls", "sys_enter_linkat");
        // fd correlation for mmap (content read) + getdents64 (directory recon):
        // the exit hooks bind a token open's returned fd, close prunes it.
        attach_tp_optional!("syscalls", "sys_exit_openat");
        attach_tp_optional!("syscalls", "sys_exit_open");
        attach_tp_optional!("syscalls", "sys_exit_openat2");
        attach_tp_optional!("syscalls", "sys_enter_getdents64");
        attach_tp_optional!("syscalls", "sys_enter_close");
        attach_tp!("syscalls", "sys_enter_connect");
        attach_tp!("syscalls", "sys_enter_bind");
        attach_tp!("syscalls", "sys_enter_accept4");
        attach_tp!("sched", "sched_process_fork");
        attach_tp!("syscalls", "sys_enter_unlinkat");
        attach_tp!("syscalls", "sys_enter_renameat2");
        attach_tp!("syscalls", "sys_enter_fchmodat");
        attach_tp!("syscalls", "sys_enter_fchownat");
        attach_tp!("syscalls", "sys_enter_mmap");
        attach_tp!("syscalls", "sys_enter_ptrace");
        attach_tp!("module", "module_load");
        attach_tp!("syscalls", "sys_enter_shmget");
        attach_tp!("syscalls", "sys_enter_shmat");
        attach_tp!("syscalls", "sys_enter_unshare");
        attach_tp!("syscalls", "sys_enter_setns");
        attach_tp!("syscalls", "sys_enter_write");
        attach_tp!("syscalls", "sys_enter_kill");
        attach_tp!("syscalls", "sys_enter_tkill");
        attach_tp!("syscalls", "sys_enter_tgkill");
        attach_tp!("syscalls", "sys_enter_setuid");
        attach_tp!("syscalls", "sys_enter_setreuid");
        attach_tp!("syscalls", "sys_enter_setresuid");
        attach_tp!("syscalls", "sys_enter_memfd_create");

        // ── Attach kprobe ─────────────────────────────────────────────────────
        {
            let prog: &mut KProbe = bpf
                .program_mut("kprobe__udp_sendmsg")
                .context("kprobe__udp_sendmsg not found in eBPF binary")?
                .try_into()
                .context("kprobe__udp_sendmsg is not a KProbe")?;
            prog.load()
                .context("BPF verifier rejected kprobe__udp_sendmsg")?;
            prog.attach("udp_sendmsg", 0)
                .context("failed to attach kprobe on udp_sendmsg")?;
        }

        // ── Attach honeytoken inode kprobe (best-effort) ──────────────────────
        // The vfs_open kprobe is the canonical content-read detector (matches by
        // inode, robust against symlinks/relative/hardlinks). It is present only
        // in newer eBPF binaries and its failure must never take down the rest of
        // the telemetry, so we log and continue rather than bail.
        match bpf.program_mut("vfs_open") {
            Some(prog) => {
                let attached = (|| -> Result<()> {
                    let prog: &mut KProbe = prog.try_into().context("vfs_open is not a KProbe")?;
                    prog.load().context("BPF verifier rejected vfs_open")?;
                    prog.attach("vfs_open", 0)
                        .context("failed to attach kprobe on vfs_open")?;
                    Ok(())
                })();
                match attached {
                    Ok(()) => info!("eBPF honeytoken inode kprobe attached on vfs_open"),
                    Err(e) => {
                        warn!(error = %e, "honeytoken vfs_open kprobe unavailable — inode content-read detection disabled")
                    }
                }
            }
            None => info!(
                "eBPF binary has no vfs_open program — honeytoken inode detection unavailable"
            ),
        }

        // ── Open ring buffer maps ─────────────────────────────────────────────
        // Use take_map (aya 0.13+) to get *owned* MapData rather than &mut MapData.
        // Owned ring buffers do not borrow from `bpf`, so we can hold all of them
        // simultaneously without running into the multiple-mutable-borrow limit.
        macro_rules! open_rb {
            ($name:expr) => {{
                let map = bpf
                    .take_map($name)
                    .with_context(|| format!("map '{}' not found in eBPF binary", $name))?;
                let rb: RingBuf<MapData> = RingBuf::try_from(map)
                    .with_context(|| format!("failed to open ring buffer '{}'", $name))?;
                AsyncFd::new(rb)
                    .with_context(|| format!("failed to create AsyncFd for '{}'", $name))?
            }};
        }

        let mut afd_file_open = open_rb!("FILE_OPEN_EVENTS");
        let mut afd_net = open_rb!("NET_EVENTS");
        let mut afd_fork = open_rb!("FORK_EVENTS");
        let mut afd_unlink = open_rb!("UNLINK_EVENTS");
        let mut afd_rename = open_rb!("RENAME_EVENTS");
        let mut afd_chmod = open_rb!("CHMOD_EVENTS");
        let mut afd_chown = open_rb!("CHOWN_EVENTS");
        let mut afd_mmap = open_rb!("MMAP_EVENTS");
        let mut afd_ptrace = open_rb!("PTRACE_EVENTS");
        let mut afd_module = open_rb!("MODULE_LOAD_EVENTS");
        let mut afd_shm = open_rb!("SHM_EVENTS");
        let mut afd_ns = open_rb!("NS_CHANGE_EVENTS");
        let mut afd_dns = open_rb!("DNS_EVENTS");
        let mut afd_write_rate = open_rb!("WRITE_RATE_EVENTS");
        let mut afd_kill = open_rb!("KILL_SIGNAL_EVENTS");
        let mut afd_setuid = open_rb!("SETUID_EVENTS");
        let mut afd_memfd = open_rb!("MEMFD_EVENTS");

        // ── Write protected PID into the PROTECTED_PID eBPF array map ────────
        // The kill-detection tracepoints use this to filter events to only those
        // targeting the agent itself.
        {
            use aya::maps::Array;
            let map = bpf
                .map_mut("PROTECTED_PID")
                .context("PROTECTED_PID map not found in eBPF binary")?;
            let mut pid_map: Array<_, u32> = map
                .try_into()
                .context("PROTECTED_PID is not an Array map")?;
            pid_map
                .set(0, std::process::id(), 0)
                .context("Failed to write agent PID into PROTECTED_PID eBPF map")?;
            info!(
                agent_pid = std::process::id(),
                "eBPF kill-shield: agent PID registered in PROTECTED_PID map"
            );
        }

        // ── Honeytoken detection (step 2; optional) ─────────────────────────
        // Arms the HONEYTOKEN_PATHS match table from the on-disk register and
        // consumes HONEYTOKEN_ACCESS_EVENTS. Runs in its own tasks so the main
        // ring-buffer loop below is untouched; gracefully no-ops on an older
        // eBPF binary that lacks these maps.
        self.spawn_honeytoken_tasks(&mut bpf, tx.clone(), agent_id.clone(), hostname.clone());

        info!(
            "eBPF syscall tracer attached: 24 core tracepoints + 1 kprobe + \
             up to 6 best-effort honeytoken-coverage tracepoints"
        );

        // Our own PID, used to drop the agent's self-generated file opens (see
        // the FILE_OPEN_EVENTS arm below) and break the events.ndjson loop.
        let agent_pid = std::process::id();

        // ── eBPF ring-buffer drop counters (issue #52) ──────────────────────
        // The kernel side bumps a per-program counter in the shared `DROPPED`
        // per-CPU map whenever a ring buffer is full and an event is dropped.
        // Poll it on an interval, log sustained drops and export them as an
        // event. Gracefully no-ops on an older eBPF binary that lacks the map.
        let mut drop_monitor = match bpf.take_map("DROPPED") {
            Some(map) => match PerCpuArray::<_, u64>::try_from(map) {
                Ok(arr) => Some(DropMonitor::new(arr)),
                Err(e) => {
                    warn!(error = %e, "DROPPED map not usable — eBPF drop metrics disabled");
                    None
                }
            },
            None => {
                info!("eBPF binary has no DROPPED map — ring-buffer drop metrics unavailable");
                None
            }
        };
        let mut drop_ticker = interval(DROP_POLL_INTERVAL);
        // Don't burst-catch-up missed ticks (e.g. after the loop was busy); a
        // single delayed poll is enough since the counters are cumulative.
        drop_ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                _ = tx.closed() => {
                    return Ok(());
                }

                // Periodic eBPF ring-buffer drop report (issue #52). Emits an
                // event only when new drops occurred since the last poll.
                _ = drop_ticker.tick() => {
                    if let Some(data) = drop_monitor.as_mut().and_then(DropMonitor::poll) {
                        let event = AgentEvent::new(
                            agent_id.clone(), hostname.clone(),
                            EventClass::System, EventAction::EbpfDrops,
                            Severity::Medium,
                            EventData::EbpfDrops(data),
                        );
                        if tx.send(event).await.is_err() { return Ok(()); }
                    }
                }

                Ok(mut guard) = afd_file_open.readable_mut() => {
                    let rb = guard.get_inner_mut();
                    while let Some(item) = rb.next() {
                        if let Some(ev) = unsafe { read_raw::<RawFileOpenEvent>(&item) } {
                            // Self-exclusion: the agent's own file opens are pure
                            // monitor noise and, for its telemetry sink
                            // (`/var/log/trapd/events.ndjson`), a runaway feedback
                            // loop — every append opens the file, which emits an
                            // open event, which is appended to the file, which
                            // opens it again. Drop opens by our own process; this
                            // mirrors the honeytoken `Allowlist` self-exclusion.
                            if ev.pid == agent_pid {
                                continue;
                            }
                            let username = proc_username(ev.uid);
                            let event = AgentEvent::new(
                                agent_id.clone(), hostname.clone(),
                                EventClass::Filesystem, EventAction::Open,
                                Severity::Info,
                                EventData::FileOpen(FileOpenData {
                                    pid: ev.pid as i32,
                                    uid: ev.uid,
                                    gid: ev.gid,
                                    username,
                                    comm: cstr(&ev.comm).to_string(),
                                    path: cstr(&ev.filename).to_string(),
                                    flags: ev.flags,
                                }),
                            );
                            if tx.send(event).await.is_err() { return Ok(()); }
                        }
                    }
                    guard.clear_ready();
                }

                Ok(mut guard) = afd_net.readable_mut() => {
                    let rb = guard.get_inner_mut();
                    while let Some(item) = rb.next() {
                        if let Some(ev) = unsafe { read_raw::<RawNetEvent>(&item) } {
                            if ev.pid == agent_pid { continue; } // self-exclusion (own uploads to backend)
                            let username = proc_username(ev.uid);
                            let (action, severity) = match ev.op {
                                0 => (EventAction::Connection, Severity::Info),
                                1 => (EventAction::Bind,       Severity::Info),
                                _ => (EventAction::Accept,     Severity::Info),
                            };
                            let event = AgentEvent::new(
                                agent_id.clone(), hostname.clone(),
                                EventClass::Network, action,
                                severity,
                                EventData::NetworkSocket(NetworkSocketData {
                                    pid:    ev.pid as i32,
                                    uid:    ev.uid,
                                    gid:    ev.gid,
                                    username,
                                    comm:   cstr(&ev.comm).to_string(),
                                    op:     net_op_str(ev.op).to_string(),
                                    family: family_str(ev.family).to_string(),
                                    addr:   format_addr(ev.family, &ev.addr),
                                    port:   ev.port,
                                }),
                            );
                            if tx.send(event).await.is_err() { return Ok(()); }
                        }
                    }
                    guard.clear_ready();
                }

                Ok(mut guard) = afd_fork.readable_mut() => {
                    let rb = guard.get_inner_mut();
                    while let Some(item) = rb.next() {
                        if let Some(ev) = unsafe { read_raw::<RawForkEvent>(&item) } {
                            if ev.parent_pid == agent_pid || ev.child_pid == agent_pid { continue; } // self-exclusion
                            let event = AgentEvent::new(
                                agent_id.clone(), hostname.clone(),
                                EventClass::Process, EventAction::Fork,
                                Severity::Info,
                                EventData::Fork(ForkData {
                                    parent_pid:  ev.parent_pid as i32,
                                    child_pid:   ev.child_pid  as i32,
                                    parent_comm: cstr(&ev.parent_comm).to_string(),
                                    child_comm:  cstr(&ev.child_comm).to_string(),
                                }),
                            );
                            if tx.send(event).await.is_err() { return Ok(()); }
                        }
                    }
                    guard.clear_ready();
                }

                Ok(mut guard) = afd_unlink.readable_mut() => {
                    let rb = guard.get_inner_mut();
                    while let Some(item) = rb.next() {
                        if let Some(ev) = unsafe { read_raw::<RawFileUnlinkEvent>(&item) } {
                            if ev.pid == agent_pid { continue; } // self-exclusion
                            let username = proc_username(ev.uid);
                            let event = AgentEvent::new(
                                agent_id.clone(), hostname.clone(),
                                EventClass::Filesystem, EventAction::Unlink,
                                Severity::Low,
                                EventData::FileUnlink(FileUnlinkData {
                                    pid: ev.pid as i32,
                                    uid: ev.uid,
                                    gid: ev.gid,
                                    username,
                                    comm: cstr(&ev.comm).to_string(),
                                    path: cstr(&ev.path).to_string(),
                                }),
                            );
                            if tx.send(event).await.is_err() { return Ok(()); }
                        }
                    }
                    guard.clear_ready();
                }

                Ok(mut guard) = afd_rename.readable_mut() => {
                    let rb = guard.get_inner_mut();
                    while let Some(item) = rb.next() {
                        if let Some(ev) = unsafe { read_raw::<RawFileRenameEvent>(&item) } {
                            if ev.pid == agent_pid { continue; } // self-exclusion
                            let username = proc_username(ev.uid);
                            let event = AgentEvent::new(
                                agent_id.clone(), hostname.clone(),
                                EventClass::Filesystem, EventAction::Rename,
                                Severity::Info,
                                EventData::FileRename(FileRenameData {
                                    pid:      ev.pid as i32,
                                    uid:      ev.uid,
                                    gid:      ev.gid,
                                    username,
                                    comm:     cstr(&ev.comm).to_string(),
                                    old_path: cstr(&ev.old_path).to_string(),
                                    new_path: cstr(&ev.new_path).to_string(),
                                }),
                            );
                            if tx.send(event).await.is_err() { return Ok(()); }
                        }
                    }
                    guard.clear_ready();
                }

                Ok(mut guard) = afd_chmod.readable_mut() => {
                    let rb = guard.get_inner_mut();
                    while let Some(item) = rb.next() {
                        if let Some(ev) = unsafe { read_raw::<RawFileChmodEvent>(&item) } {
                            if ev.pid == agent_pid { continue; } // self-exclusion
                            let username = proc_username(ev.uid);
                            let event = AgentEvent::new(
                                agent_id.clone(), hostname.clone(),
                                EventClass::Filesystem, EventAction::Chmod,
                                Severity::Info,
                                EventData::FileChmod(FileChmodData {
                                    pid:  ev.pid as i32,
                                    uid:  ev.uid,
                                    gid:  ev.gid,
                                    username,
                                    comm: cstr(&ev.comm).to_string(),
                                    path: cstr(&ev.path).to_string(),
                                    mode: ev.mode,
                                }),
                            );
                            if tx.send(event).await.is_err() { return Ok(()); }
                        }
                    }
                    guard.clear_ready();
                }

                Ok(mut guard) = afd_chown.readable_mut() => {
                    let rb = guard.get_inner_mut();
                    while let Some(item) = rb.next() {
                        if let Some(ev) = unsafe { read_raw::<RawFileChownEvent>(&item) } {
                            if ev.pid == agent_pid { continue; } // self-exclusion
                            let username = proc_username(ev.uid);
                            let event = AgentEvent::new(
                                agent_id.clone(), hostname.clone(),
                                EventClass::Filesystem, EventAction::Chown,
                                Severity::Info,
                                EventData::FileChown(FileChownData {
                                    pid:     ev.pid as i32,
                                    uid:     ev.uid,
                                    gid:     ev.gid,
                                    username,
                                    comm:    cstr(&ev.comm).to_string(),
                                    path:    cstr(&ev.path).to_string(),
                                    new_uid: ev.new_uid,
                                    new_gid: ev.new_gid,
                                }),
                            );
                            if tx.send(event).await.is_err() { return Ok(()); }
                        }
                    }
                    guard.clear_ready();
                }

                Ok(mut guard) = afd_mmap.readable_mut() => {
                    let rb = guard.get_inner_mut();
                    while let Some(item) = rb.next() {
                        if let Some(ev) = unsafe { read_raw::<RawMmapEvent>(&item) } {
                            if ev.pid == agent_pid { continue; } // self-exclusion
                            let username = proc_username(ev.uid);
                            let desc = mmap_description(ev.prot, ev.flags);
                            let event = AgentEvent::new(
                                agent_id.clone(), hostname.clone(),
                                EventClass::Memory, EventAction::Mmap,
                                Severity::Medium,
                                EventData::Mmap(MmapData {
                                    pid:         ev.pid as i32,
                                    uid:         ev.uid,
                                    gid:         ev.gid,
                                    username,
                                    comm:        cstr(&ev.comm).to_string(),
                                    addr:        ev.addr,
                                    len:         ev.len,
                                    prot:        ev.prot,
                                    flags:       ev.flags,
                                    description: desc,
                                }),
                            );
                            if tx.send(event).await.is_err() { return Ok(()); }
                        }
                    }
                    guard.clear_ready();
                }

                Ok(mut guard) = afd_ptrace.readable_mut() => {
                    let rb = guard.get_inner_mut();
                    while let Some(item) = rb.next() {
                        if let Some(ev) = unsafe { read_raw::<RawPtraceEvent>(&item) } {
                            // self-exclusion for the agent AS tracer; an attacker
                            // ptracing the agent (target_pid == us) still reports.
                            if ev.pid == agent_pid { continue; }
                            let username = proc_username(ev.uid);
                            let event = AgentEvent::new(
                                agent_id.clone(), hostname.clone(),
                                EventClass::Process, EventAction::Ptrace,
                                Severity::High,
                                EventData::Ptrace(PtraceData {
                                    pid:        ev.pid as i32,
                                    uid:        ev.uid,
                                    gid:        ev.gid,
                                    username,
                                    comm:       cstr(&ev.comm).to_string(),
                                    request:    ev.request,
                                    target_pid: ev.target_pid as i32,
                                }),
                            );
                            if tx.send(event).await.is_err() { return Ok(()); }
                        }
                    }
                    guard.clear_ready();
                }

                Ok(mut guard) = afd_module.readable_mut() => {
                    let rb = guard.get_inner_mut();
                    while let Some(item) = rb.next() {
                        if let Some(ev) = unsafe { read_raw::<RawModuleLoadEvent>(&item) } {
                            if ev.pid == agent_pid { continue; } // self-exclusion
                            let username = proc_username(ev.uid);
                            let event = AgentEvent::new(
                                agent_id.clone(), hostname.clone(),
                                EventClass::Kernel, EventAction::ModuleLoad,
                                Severity::High,
                                EventData::ModuleLoad(ModuleLoadData {
                                    pid:      ev.pid as i32,
                                    uid:      ev.uid,
                                    gid:      ev.gid,
                                    username,
                                    name:     cstr(&ev.name).to_string(),
                                    taints:   ev.taints,
                                }),
                            );
                            if tx.send(event).await.is_err() { return Ok(()); }
                        }
                    }
                    guard.clear_ready();
                }

                Ok(mut guard) = afd_shm.readable_mut() => {
                    let rb = guard.get_inner_mut();
                    while let Some(item) = rb.next() {
                        if let Some(ev) = unsafe { read_raw::<RawShmEvent>(&item) } {
                            if ev.pid == agent_pid { continue; } // self-exclusion
                            let username = proc_username(ev.uid);
                            let (action, op_str) = if ev.op == 0 {
                                (EventAction::Shmget, "shmget")
                            } else {
                                (EventAction::Shmat, "shmat")
                            };
                            let event = AgentEvent::new(
                                agent_id.clone(), hostname.clone(),
                                EventClass::Ipc, action,
                                Severity::Low,
                                EventData::Shm(ShmData {
                                    pid:      ev.pid as i32,
                                    uid:      ev.uid,
                                    gid:      ev.gid,
                                    username,
                                    comm:     cstr(&ev.comm).to_string(),
                                    op:       op_str.to_string(),
                                    key:      ev.key,
                                    size:     ev.size,
                                    flags:    ev.flags,
                                }),
                            );
                            if tx.send(event).await.is_err() { return Ok(()); }
                        }
                    }
                    guard.clear_ready();
                }

                Ok(mut guard) = afd_ns.readable_mut() => {
                    let rb = guard.get_inner_mut();
                    while let Some(item) = rb.next() {
                        if let Some(ev) = unsafe { read_raw::<RawNsChangeEvent>(&item) } {
                            if ev.pid == agent_pid { continue; } // self-exclusion
                            let username = proc_username(ev.uid);
                            let op_str = if ev.op == 0 { "unshare" } else { "setns" };
                            let namespaces = ns_flags_to_string(ev.flags);
                            let event = AgentEvent::new(
                                agent_id.clone(), hostname.clone(),
                                EventClass::Process, EventAction::NsChange,
                                Severity::Medium,
                                EventData::NsChange(NsChangeData {
                                    pid:        ev.pid as i32,
                                    uid:        ev.uid,
                                    gid:        ev.gid,
                                    username,
                                    comm:       cstr(&ev.comm).to_string(),
                                    op:         op_str.to_string(),
                                    namespaces,
                                    flags:      ev.flags,
                                }),
                            );
                            if tx.send(event).await.is_err() { return Ok(()); }
                        }
                    }
                    guard.clear_ready();
                }

                Ok(mut guard) = afd_dns.readable_mut() => {
                    let rb = guard.get_inner_mut();
                    while let Some(item) = rb.next() {
                        if let Some(ev) = unsafe { read_raw::<RawDnsEvent>(&item) } {
                            if ev.pid == agent_pid { continue; } // self-exclusion (own backend lookups)
                            let username = proc_username(ev.uid);
                            let event = AgentEvent::new(
                                agent_id.clone(), hostname.clone(),
                                EventClass::Network, EventAction::DnsQuery,
                                Severity::Info,
                                EventData::Dns(DnsData {
                                    pid:      ev.pid as i32,
                                    uid:      ev.uid,
                                    gid:      ev.gid,
                                    username,
                                    comm:     cstr(&ev.comm).to_string(),
                                    dst_addr: format_addr(ev.family, &ev.dst_addr),
                                    dst_port: ev.dst_port,
                                }),
                            );
                            if tx.send(event).await.is_err() { return Ok(()); }
                        }
                    }
                    guard.clear_ready();
                }

                Ok(mut guard) = afd_write_rate.readable_mut() => {
                    let rb = guard.get_inner_mut();
                    while let Some(item) = rb.next() {
                        if let Some(ev) = unsafe { read_raw::<RawWriteRateEvent>(&item) } {
                            if ev.pid == agent_pid { continue; } // self-exclusion (own NDJSON log writes)
                            let username = proc_username(ev.uid);
                            let event = AgentEvent::new(
                                agent_id.clone(), hostname.clone(),
                                EventClass::Filesystem, EventAction::WriteRateAnomaly,
                                Severity::High,
                                EventData::WriteRateAnomaly(WriteRateAnomalyData {
                                    pid:             ev.pid as i32,
                                    uid:             ev.uid,
                                    gid:             ev.gid,
                                    username,
                                    comm:            cstr(&ev.comm).to_string(),
                                    write_count:     ev.write_count,
                                    burst_threshold: ev.burst_threshold,
                                }),
                            );
                            if tx.send(event).await.is_err() { return Ok(()); }
                        }
                    }
                    guard.clear_ready();
                }

                Ok(mut guard) = afd_kill.readable_mut() => {
                    let rb = guard.get_inner_mut();
                    while let Some(item) = rb.next() {
                        if let Some(ev) = unsafe { read_raw::<RawKillSignalEvent>(&item) } {
                            let sender_comm = cstr(&ev.comm).to_string();
                            let signal_name = match ev.signal {
                                9  => "SIGKILL",
                                15 => "SIGTERM",
                                _  => "SIG?",
                            };
                            tracing::warn!(
                                sender_pid  = ev.sender_pid,
                                sender_uid  = ev.sender_uid,
                                sender_comm = %sender_comm,
                                target_pid  = ev.target_pid,
                                signal      = ev.signal,
                                signal_name = signal_name,
                                "KILL-SHIELD: kill signal detected targeting the agent"
                            );
                            let event = AgentEvent::new(
                                agent_id.clone(), hostname.clone(),
                                EventClass::Process, EventAction::KillAttempt,
                                Severity::Critical,
                                EventData::KillAttempt(KillAttemptData {
                                    sender_pid:  ev.sender_pid,
                                    sender_uid:  ev.sender_uid,
                                    sender_gid:  ev.sender_gid,
                                    sender_comm,
                                    target_pid:  ev.target_pid,
                                    signal:      ev.signal,
                                    signal_name: signal_name.to_string(),
                                }),
                            );
                            if tx.send(event).await.is_err() { return Ok(()); }
                        }
                    }
                    guard.clear_ready();
                }

                Ok(mut guard) = afd_setuid.readable_mut() => {
                    let rb = guard.get_inner_mut();
                    while let Some(item) = rb.next() {
                        if let Some(ev) = unsafe { read_raw::<RawSetuidEvent>(&item) } {
                            if ev.pid == agent_pid { continue; } // self-exclusion
                            let event = AgentEvent::new(
                                agent_id.clone(), hostname.clone(),
                                EventClass::Process, EventAction::Setuid,
                                Severity::Info,
                                EventData::Setuid(SetuidData {
                                    pid:     ev.pid as i32,
                                    old_uid: ev.old_uid,
                                    new_uid: ev.new_uid,
                                    comm:    cstr(&ev.comm).to_string(),
                                }),
                            );
                            if tx.send(event).await.is_err() { return Ok(()); }
                        }
                    }
                    guard.clear_ready();
                }

                Ok(mut guard) = afd_memfd.readable_mut() => {
                    let rb = guard.get_inner_mut();
                    while let Some(item) = rb.next() {
                        if let Some(ev) = unsafe { read_raw::<RawMemfdEvent>(&item) } {
                            if ev.pid == agent_pid { continue; } // self-exclusion
                            let event = AgentEvent::new(
                                agent_id.clone(), hostname.clone(),
                                EventClass::Memory, EventAction::MemfdCreate,
                                Severity::High,
                                EventData::MemfdCreate(MemfdCreateData {
                                    pid:   ev.pid as i32,
                                    comm:  cstr(&ev.comm).to_string(),
                                    name:  cstr(&ev.name).to_string(),
                                    flags: ev.flags,
                                }),
                            );
                            if tx.send(event).await.is_err() { return Ok(()); }
                        }
                    }
                    guard.clear_ready();
                }
            }
        }
    }
}
