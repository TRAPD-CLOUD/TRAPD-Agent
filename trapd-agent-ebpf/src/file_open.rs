use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
        bpf_probe_read_kernel, bpf_probe_read_user_str_bytes,
    },
    macros::{kprobe, map, tracepoint},
    maps::{HashMap, RingBuf},
    programs::{ProbeContext, TracePointContext},
};

use crate::{COMM_LEN, PATH_LEN};

/// File open event emitted for every openat(2) call.
#[repr(C)]
pub struct FileOpenEvent {
    pub pid:          u32,
    pub uid:          u32,
    pub gid:          u32,
    /// O_RDONLY=0, O_WRONLY=1, O_RDWR=2, O_CREAT=0x40, O_TRUNC=0x200, …
    pub flags:        u64,
    pub comm:         [u8; COMM_LEN],
    pub filename:     [u8; PATH_LEN],
    pub filename_len: u32,
}

/// Honeytoken-access event — emitted from the `vfs_open` kprobe whenever the
/// opened inode is in [`HONEYTOKEN_INODES`], **regardless of open flags** (the
/// read-only detection fix: a `cat ~/.aws/credentials` is the whole point and
/// must fire). Carries the matched inode so userspace can re-verify identity.
#[repr(C)]
pub struct HoneytokenAccessEvent {
    pub pid:      u32,
    pub uid:      u32,
    pub gid:      u32,
    pub _pad:     u32,
    /// Token id the userspace side associated with this inode.
    pub token_id: u64,
    /// The matched inode number (for userspace re-verification).
    pub ino:      u64,
    /// open(2) flags, when known (the vfs_open path reports 0 — informational).
    pub flags:    u64,
    pub comm:     [u8; COMM_LEN],
}

/// 512 KiB – openat is frequent; ring buffer drops gracefully under load.
#[map]
static FILE_OPEN_EVENTS: RingBuf = RingBuf::with_byte_size(512 * 1024, 0);

/// Honeytoken match table: **inode number → token id**.
///
/// Userspace owns this map and reconciles it from the on-disk register by
/// `stat()`ing each deployed token. Matching on the resolved inode (rather than
/// the open path) is robust against symlinks, relative paths and `..`, and is a
/// single cheap hash lookup — path parsing in BPF would be fragile. Userspace
/// additionally re-verifies the hit against the token's recorded device+inode.
#[map]
static HONEYTOKEN_INODES: HashMap<u64, u64> = HashMap::<u64, u64>::with_max_entries(256, 0);

/// Dedicated low-volume channel for honeytoken accesses, separate from
/// `FILE_OPEN_EVENTS` so a hit is never lost in openat traffic and the
/// read-only suppression on the main channel can stay exactly as it is.
#[map]
static HONEYTOKEN_ACCESS_EVENTS: RingBuf = RingBuf::with_byte_size(64 * 1024, 0);

// ── struct field offsets for the inode walk (x86_64) ──────────────────────────
// The codebase reads kernel structs only by stable, documented offsets (see
// dns.rs reading struct sock). `struct path` is two pointers, so `dentry` at +8
// is rock-solid; `d_inode` / `i_ino` are the conventional x86_64 layout for
// 4.x–6.x defconfig kernels. Every read is fail-safe: a wrong offset or bad
// pointer yields a miss (no event), never a false positive. A BTF/CO-RE-driven
// resolution is the portability hardening tracked for later.
const PATH_DENTRY_OFFSET:   usize = 8;  // struct path { struct vfsmount *mnt; struct dentry *dentry; }
const DENTRY_DINODE_OFFSET: usize = 48; // struct dentry.d_inode
const INODE_IINO_OFFSET:    usize = 64; // struct inode.i_ino

/// Tracepoint: syscalls/sys_enter_openat
///
/// Record layout (sys_enter_openat, x86_64):
///   offset  8 │ i32  __syscall_nr  (4 bytes + 4 pad)
///   offset 16 │ u64  arg0  dfd
///   offset 24 │ u64  arg1  filename  ← user pointer to path string
///   offset 32 │ u64  arg2  flags
///   offset 40 │ u64  arg3  mode
#[tracepoint]
pub fn sys_enter_openat(ctx: TracePointContext) -> u32 {
    match try_file_open(&ctx) {
        Ok(_) => 0,
        Err(_) => 0,
    }
}

#[inline(always)]
fn try_file_open(ctx: &TracePointContext) -> Result<(), i64> {
    let filename_uptr: u64 = unsafe { ctx.read_at(24).map_err(|_| -1i64)? };
    if filename_uptr == 0 {
        return Ok(());
    }
    let flags: u64 = unsafe { ctx.read_at(32).map_err(|_| -1i64)? };

    // O_WRONLY=1, O_RDWR=2, O_CREAT=0x40, O_TRUNC=0x200 – skip pure read-only opens to
    // reduce volume; honeytoken read-only access is caught by the vfs_open kprobe
    // below, which matches by inode regardless of flags.
    const O_WRONLY: u64 = 1;
    const O_RDWR: u64 = 2;
    const O_CREAT: u64 = 0x40;
    const O_TRUNC: u64 = 0x200;
    if (flags & (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC)) == 0 {
        return Ok(());
    }

    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let uid_gid = bpf_get_current_uid_gid();
    let uid = (uid_gid & 0xFFFF_FFFF) as u32;
    let gid = (uid_gid >> 32) as u32;

    let comm = [0u8; COMM_LEN];
    let comm = bpf_get_current_comm().unwrap_or(comm);

    let mut entry = FILE_OPEN_EVENTS.reserve::<FileOpenEvent>(0).ok_or(-1i64)?;
    let ev = unsafe { entry.assume_init_mut() };
    ev.pid = pid;
    ev.uid = uid;
    ev.gid = gid;
    ev.flags = flags;
    ev.comm = comm;

    let written = unsafe {
        bpf_probe_read_user_str_bytes(filename_uptr as *const u8, &mut ev.filename)
            .map(|s| s.len())
            .unwrap_or(0)
    };
    ev.filename_len = written as u32;

    entry.submit(0);
    Ok(())
}

/// kprobe: vfs_open(const struct path *path, struct file *file)
///
/// Runs after path resolution, so the dentry/inode is known. We resolve the
/// opened inode and, if it is a deployed honeytoken, emit an access event
/// **regardless of open flags** — this is the read-only detection. All struct
/// reads are fail-safe (a miss on error), so this never produces a false
/// positive even on a kernel whose layout differs from the assumed offsets.
#[kprobe]
pub fn vfs_open(ctx: ProbeContext) -> u32 {
    match try_vfs_open(&ctx) {
        Ok(_) => 0,
        Err(_) => 0,
    }
}

#[inline(always)]
fn try_vfs_open(ctx: &ProbeContext) -> Result<(), i64> {
    // arg0 = const struct path *path (kernel pointer)
    let path: *const u8 = ctx.arg(0).ok_or(-1i64)?;
    if path.is_null() {
        return Ok(());
    }
    // path->dentry
    let dentry: *const u8 = unsafe {
        bpf_probe_read_kernel((path as usize + PATH_DENTRY_OFFSET) as *const *const u8)
            .unwrap_or(core::ptr::null())
    };
    if dentry.is_null() {
        return Ok(());
    }
    // dentry->d_inode
    let inode: *const u8 = unsafe {
        bpf_probe_read_kernel((dentry as usize + DENTRY_DINODE_OFFSET) as *const *const u8)
            .unwrap_or(core::ptr::null())
    };
    if inode.is_null() {
        return Ok(());
    }
    // inode->i_ino
    let ino: u64 = unsafe {
        bpf_probe_read_kernel((inode as usize + INODE_IINO_OFFSET) as *const u64).unwrap_or(0)
    };
    if ino == 0 {
        return Ok(());
    }

    let token_id = match unsafe { HONEYTOKEN_INODES.get(&ino) } {
        Some(&t) => t,
        None => return Ok(()),
    };

    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let uid_gid = bpf_get_current_uid_gid();
    let uid = (uid_gid & 0xFFFF_FFFF) as u32;
    let gid = (uid_gid >> 32) as u32;
    let comm = bpf_get_current_comm().unwrap_or([0u8; COMM_LEN]);

    let mut entry = HONEYTOKEN_ACCESS_EVENTS.reserve::<HoneytokenAccessEvent>(0).ok_or(-1i64)?;
    let ev = unsafe { entry.assume_init_mut() };
    ev.pid = pid;
    ev.uid = uid;
    ev.gid = gid;
    ev._pad = 0;
    ev.token_id = token_id;
    ev.ino = ino;
    ev.flags = 0; // vfs_open does not carry the syscall flags cheaply
    ev.comm = comm;
    entry.submit(0);
    Ok(())
}
