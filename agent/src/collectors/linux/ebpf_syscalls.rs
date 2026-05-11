//! eBPF-backed syscall tracer for Linux (kernel ≥ 5.8).
//!
//! Loads the same `trapd-agent-exec` eBPF binary as [`EbpfExecCollector`] and
//! attaches the following programs:
//!
//! | Program               | Tracepoint / kprobe                   | Event type   |
//! |-----------------------|---------------------------------------|--------------|
//! | sys_enter_openat      | syscalls/sys_enter_openat             | FileOpen     |
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
use aya::maps::MapData;
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc::Sender;
use tracing::info;

use crate::collectors::Collector;
use crate::schema::{
    AgentEvent, DnsData, EventAction, EventClass, EventData, FileChmodData, FileChownData,
    FileOpenData, FileRenameData, FileUnlinkData, ForkData, KillAttemptData, MmapData,
    ModuleLoadData, NetworkSocketData, NsChangeData, PtraceData, Severity, ShmData,
    WriteRateAnomalyData,
};

// ── Kernel ↔ Userspace struct layouts ────────────────────────────────────────
// Every struct here must be repr(C) and match its counterpart in
// trapd-agent-ebpf/src/*.rs exactly (field order, padding, sizes).

const COMM_LEN: usize = 16;
const PATH_LEN: usize = 256;

#[repr(C)]
struct RawFileOpenEvent {
    pid:          u32,
    uid:          u32,
    gid:          u32,
    flags:        u64,
    comm:         [u8; COMM_LEN],
    filename:     [u8; PATH_LEN],
    filename_len: u32,
}

#[repr(C)]
struct RawNetEvent {
    pid:   u32,
    uid:   u32,
    gid:   u32,
    op:    u8,
    _pad0: [u8; 1],
    family: u16,
    port:  u16,
    _pad1: [u8; 6],
    comm:  [u8; COMM_LEN],
    addr:  [u8; 16],
}

#[repr(C)]
struct RawForkEvent {
    parent_pid:  u32,
    child_pid:   u32,
    parent_comm: [u8; COMM_LEN],
    child_comm:  [u8; COMM_LEN],
}

#[repr(C)]
struct RawFileUnlinkEvent {
    pid:      u32,
    uid:      u32,
    gid:      u32,
    _pad:     u32,
    comm:     [u8; COMM_LEN],
    path:     [u8; PATH_LEN],
    path_len: u32,
}

#[repr(C)]
struct RawFileRenameEvent {
    pid:          u32,
    uid:          u32,
    gid:          u32,
    _pad:         u32,
    comm:         [u8; COMM_LEN],
    old_path:     [u8; PATH_LEN],
    old_path_len: u32,
    new_path:     [u8; PATH_LEN],
    new_path_len: u32,
}

#[repr(C)]
struct RawFileChmodEvent {
    pid:      u32,
    uid:      u32,
    gid:      u32,
    mode:     u32,
    comm:     [u8; COMM_LEN],
    path:     [u8; PATH_LEN],
    path_len: u32,
}

#[repr(C)]
struct RawFileChownEvent {
    pid:      u32,
    uid:      u32,
    gid:      u32,
    new_uid:  u32,
    new_gid:  u32,
    _pad:     u32,
    comm:     [u8; COMM_LEN],
    path:     [u8; PATH_LEN],
    path_len: u32,
}

#[repr(C)]
struct RawMmapEvent {
    pid:   u32,
    uid:   u32,
    gid:   u32,
    prot:  u32,
    flags: u32,
    _pad:  u32,
    addr:  u64,
    len:   u64,
    comm:  [u8; COMM_LEN],
}

#[repr(C)]
struct RawPtraceEvent {
    pid:        u32,
    uid:        u32,
    gid:        u32,
    request:    u32,
    target_pid: u32,
    _pad:       u32,
    comm:       [u8; COMM_LEN],
}

#[repr(C)]
struct RawModuleLoadEvent {
    pid:      u32,
    uid:      u32,
    gid:      u32,
    taints:   u32,
    name:     [u8; 64],
    name_len: u32,
}

#[repr(C)]
struct RawShmEvent {
    pid:   u32,
    uid:   u32,
    gid:   u32,
    op:    u8,
    _pad:  [u8; 3],
    comm:  [u8; COMM_LEN],
    key:   i32,
    _pad2: u32,
    size:  u64,
    flags: i32,
    _pad3: u32,
}

#[repr(C)]
struct RawNsChangeEvent {
    pid:    u32,
    uid:    u32,
    gid:    u32,
    op:     u8,
    _pad:   [u8; 3],
    comm:   [u8; COMM_LEN],
    flags:  u64,
    nstype: u32,
    _pad2:  u32,
}

#[repr(C)]
struct RawDnsEvent {
    pid:      u32,
    uid:      u32,
    gid:      u32,
    family:   u16,
    dst_port: u16,
    comm:     [u8; COMM_LEN],
    dst_addr: [u8; 16],
}

/// Matches `WriteRateEvent` in trapd-agent-ebpf/src/write.rs exactly.
#[repr(C)]
struct RawWriteRateEvent {
    pid:             u32,
    uid:             u32,
    gid:             u32,
    _pad:            u32,
    comm:            [u8; COMM_LEN],
    write_count:     u64,
    burst_threshold: u64,
}

/// Matches `KillSignalEvent` in trapd-agent-ebpf/src/kill.rs exactly.
#[repr(C)]
struct RawKillSignalEvent {
    sender_pid: u32,
    sender_uid: u32,
    sender_gid: u32,
    target_pid: i32,
    signal:     i32,
    comm:       [u8; COMM_LEN],
}

// ── Collector ─────────────────────────────────────────────────────────────────

pub struct EbpfSyscallCollector {
    ebpf_path: Option<String>,
}

impl EbpfSyscallCollector {
    pub fn new() -> Self {
        Self { ebpf_path: Self::locate_binary() }
    }

    pub fn is_available(&self) -> bool {
        self.ebpf_path.is_some()
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

fn format_ipv4(addr: &[u8; 16]) -> String {
    Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]).to_string()
}

fn format_ipv6(addr: &[u8; 16]) -> String {
    use std::net::Ipv6Addr;
    let a = u16::from_be_bytes([addr[0],  addr[1]]);
    let b = u16::from_be_bytes([addr[2],  addr[3]]);
    let c = u16::from_be_bytes([addr[4],  addr[5]]);
    let d = u16::from_be_bytes([addr[6],  addr[7]]);
    let e = u16::from_be_bytes([addr[8],  addr[9]]);
    let f = u16::from_be_bytes([addr[10], addr[11]]);
    let g = u16::from_be_bytes([addr[12], addr[13]]);
    let h = u16::from_be_bytes([addr[14], addr[15]]);
    Ipv6Addr::new(a, b, c, d, e, f, g, h).to_string()
}

fn format_addr(family: u16, addr: &[u8; 16]) -> String {
    match family {
        2  => format_ipv4(addr),
        10 => format_ipv6(addr),
        _  => format!("unknown-family-{family}"),
    }
}

fn family_str(family: u16) -> &'static str {
    match family {
        2  => "ipv4",
        10 => "ipv6",
        _  => "unknown",
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
    const CLONE_NEWNS:   u64 = 0x0002_0000;
    const CLONE_NEWPID:  u64 = 0x2000_0000;
    const CLONE_NEWNET:  u64 = 0x4000_0000;
    const CLONE_NEWUTS:  u64 = 0x0400_0000;
    const CLONE_NEWUSER: u64 = 0x1000_0000;
    const CLONE_NEWIPC:  u64 = 0x0800_0000;

    let mut parts: Vec<&str> = Vec::new();
    if flags & CLONE_NEWPID  != 0 { parts.push("pid"); }
    if flags & CLONE_NEWNET  != 0 { parts.push("net"); }
    if flags & CLONE_NEWNS   != 0 { parts.push("mnt"); }
    if flags & CLONE_NEWUTS  != 0 { parts.push("uts"); }
    if flags & CLONE_NEWUSER != 0 { parts.push("user"); }
    if flags & CLONE_NEWIPC  != 0 { parts.push("ipc"); }
    if parts.is_empty() {
        format!("0x{flags:x}")
    } else {
        parts.join(",")
    }
}

fn mmap_description(prot: u32, flags: u32) -> String {
    const PROT_WRITE:    u32 = 0x2;
    const PROT_EXEC:     u32 = 0x4;
    const MAP_ANONYMOUS: u32 = 0x20;

    let anon = flags & MAP_ANONYMOUS != 0;
    let exec = prot  & PROT_EXEC     != 0;
    let write = prot & PROT_WRITE    != 0;

    match (anon && exec, write && exec) {
        (true, true)  => "anon|rwx".to_string(),
        (true, false) => "anon|exec".to_string(),
        (false, true) => "rwx".to_string(),
        _             => format!("prot=0x{prot:x}|flags=0x{flags:x}"),
    }
}

// ── safe read helper ──────────────────────────────────────────────────────────

unsafe fn read_raw<T>(bytes: &[u8]) -> Option<T> {
    if bytes.len() < std::mem::size_of::<T>() {
        return None;
    }
    Some(std::ptr::read_unaligned(bytes.as_ptr() as *const T))
}

// ── Collector impl ────────────────────────────────────────────────────────────

#[async_trait]
impl Collector for EbpfSyscallCollector {
    fn name(&self) -> &'static str {
        "EbpfSyscallCollector"
    }

    async fn run(
        &mut self,
        tx:       Sender<AgentEvent>,
        agent_id: String,
        hostname: String,
    ) -> Result<()> {
        let path = self
            .ebpf_path
            .as_deref()
            .context("eBPF binary not found — run `cargo xtask build-ebpf --release`")?;

        let bytes = fs::read(path)
            .with_context(|| format!("cannot read eBPF binary: {path}"))?;

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

        attach_tp!("syscalls", "sys_enter_openat");
        attach_tp!("syscalls", "sys_enter_connect");
        attach_tp!("syscalls", "sys_enter_bind");
        attach_tp!("syscalls", "sys_enter_accept4");
        attach_tp!("sched",    "sched_process_fork");
        attach_tp!("syscalls", "sys_enter_unlinkat");
        attach_tp!("syscalls", "sys_enter_renameat2");
        attach_tp!("syscalls", "sys_enter_fchmodat");
        attach_tp!("syscalls", "sys_enter_fchownat");
        attach_tp!("syscalls", "sys_enter_mmap");
        attach_tp!("syscalls", "sys_enter_ptrace");
        attach_tp!("module",   "module_load");
        attach_tp!("syscalls", "sys_enter_shmget");
        attach_tp!("syscalls", "sys_enter_shmat");
        attach_tp!("syscalls", "sys_enter_unshare");
        attach_tp!("syscalls", "sys_enter_setns");
        attach_tp!("syscalls", "sys_enter_write");
        attach_tp!("syscalls", "sys_enter_kill");
        attach_tp!("syscalls", "sys_enter_tkill");
        attach_tp!("syscalls", "sys_enter_tgkill");

        // ── Attach kprobe ─────────────────────────────────────────────────────
        {
            let prog: &mut KProbe = bpf
                .program_mut("kprobe__udp_sendmsg")
                .context("kprobe__udp_sendmsg not found in eBPF binary")?
                .try_into()
                .context("kprobe__udp_sendmsg is not a KProbe")?;
            prog.load().context("BPF verifier rejected kprobe__udp_sendmsg")?;
            prog.attach("udp_sendmsg", 0)
                .context("failed to attach kprobe on udp_sendmsg")?;
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
        let mut afd_net       = open_rb!("NET_EVENTS");
        let mut afd_fork      = open_rb!("FORK_EVENTS");
        let mut afd_unlink    = open_rb!("UNLINK_EVENTS");
        let mut afd_rename    = open_rb!("RENAME_EVENTS");
        let mut afd_chmod     = open_rb!("CHMOD_EVENTS");
        let mut afd_chown     = open_rb!("CHOWN_EVENTS");
        let mut afd_mmap      = open_rb!("MMAP_EVENTS");
        let mut afd_ptrace    = open_rb!("PTRACE_EVENTS");
        let mut afd_module    = open_rb!("MODULE_LOAD_EVENTS");
        let mut afd_shm       = open_rb!("SHM_EVENTS");
        let mut afd_ns        = open_rb!("NS_CHANGE_EVENTS");
        let mut afd_dns        = open_rb!("DNS_EVENTS");
        let mut afd_write_rate = open_rb!("WRITE_RATE_EVENTS");
        let mut afd_kill       = open_rb!("KILL_SIGNAL_EVENTS");

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

        info!("eBPF syscall tracer attached: 21 programs (20 tracepoints + 1 kprobe)");

        loop {
            tokio::select! {
                _ = tx.closed() => {
                    return Ok(());
                }

                Ok(mut guard) = afd_file_open.readable_mut() => {
                    let rb = guard.get_inner_mut();
                    while let Some(item) = rb.next() {
                        if let Some(ev) = unsafe { read_raw::<RawFileOpenEvent>(&item) } {
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
            }
        }
    }
}
