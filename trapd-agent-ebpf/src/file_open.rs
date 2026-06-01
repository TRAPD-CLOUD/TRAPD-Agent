use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
        bpf_probe_read_user_str_bytes,
    },
    macros::{map, tracepoint},
    maps::{HashMap, RingBuf},
    programs::TracePointContext,
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

/// Honeytoken-access event — emitted whenever an open targets a path present in
/// [`HONEYTOKEN_PATHS`], **regardless of open flags** (this is the read-only
/// detection fix: a `cat ~/.aws/credentials` is the whole point and must fire).
#[repr(C)]
pub struct HoneytokenAccessEvent {
    pub pid:          u32,
    pub uid:          u32,
    pub gid:          u32,
    pub _pad:         u32,
    /// Token id the userspace side associated with this path.
    pub token_id:     u64,
    /// open(2) flags the accessor used.
    pub flags:        u64,
    pub comm:         [u8; COMM_LEN],
    pub filename:     [u8; PATH_LEN],
    pub filename_len: u32,
    pub _pad2:        u32,
}

/// 512 KiB – openat is frequent; ring buffer drops gracefully under load.
#[map]
static FILE_OPEN_EVENTS: RingBuf = RingBuf::with_byte_size(512 * 1024, 0);

/// Honeytoken match table: absolute path (NUL-padded to `PATH_LEN`) → token id.
///
/// Userspace owns this map and reconciles it from the on-disk honeytoken
/// register. We match by the exact path string here rather than by inode: the
/// codebase deliberately avoids dereferencing kernel structs in BPF (CO-RE is
/// fragile across kernels — see `process_block.rs`), and `sys_enter_openat`
/// exposes only the user path pointer, not a resolved inode. The userspace
/// consumer re-verifies the hit against the token's recorded device+inode, so
/// the authoritative identity check is inode-based even though the cheap
/// in-kernel gate is path-based.
#[map]
static HONEYTOKEN_PATHS: HashMap<[u8; PATH_LEN], u64> =
    HashMap::<[u8; PATH_LEN], u64>::with_max_entries(256, 0);

/// Dedicated low-volume channel for honeytoken accesses. Separate from
/// `FILE_OPEN_EVENTS` so a hit is never lost in openat traffic and so the
/// read-only suppression on the main channel can stay exactly as it is.
#[map]
static HONEYTOKEN_ACCESS_EVENTS: RingBuf = RingBuf::with_byte_size(64 * 1024, 0);

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

    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let uid_gid = bpf_get_current_uid_gid();
    let uid = (uid_gid & 0xFFFF_FFFF) as u32;
    let gid = (uid_gid >> 32) as u32;

    let comm = [0u8; COMM_LEN];
    let comm = bpf_get_current_comm().unwrap_or(comm);

    // Read the path once, into a zero-initialised buffer, so the trailing bytes
    // are deterministic and the HONEYTOKEN_PATHS key matches the NUL-padded key
    // userspace inserts. We do this for *every* open (including read-only) — the
    // cost is one bounded string copy plus a hash lookup; an event is only ever
    // emitted on a (rare) honeytoken hit, so volume does not increase.
    let mut path = [0u8; PATH_LEN];
    let written = unsafe {
        bpf_probe_read_user_str_bytes(filename_uptr as *const u8, &mut path)
            .map(|s| s.len())
            .unwrap_or(0)
    };

    // ── Honeytoken gate (fires regardless of flags) ──────────────────────────
    if let Some(&token_id) = unsafe { HONEYTOKEN_PATHS.get(&path) } {
        if let Some(mut entry) = HONEYTOKEN_ACCESS_EVENTS.reserve::<HoneytokenAccessEvent>(0) {
            let ev = unsafe { entry.assume_init_mut() };
            ev.pid = pid;
            ev.uid = uid;
            ev.gid = gid;
            ev._pad = 0;
            ev.token_id = token_id;
            ev.flags = flags;
            ev.comm = comm;
            ev.filename = path;
            ev.filename_len = written as u32;
            ev._pad2 = 0;
            entry.submit(0);
        }
    }

    // ── Normal file-open telemetry (unchanged read-only suppression) ─────────
    // O_WRONLY=1, O_RDWR=2, O_CREAT=0x40, O_TRUNC=0x200 – skip pure read-only opens to
    // reduce volume; read-only tracking can be re-enabled via a BPF config map later.
    const O_WRONLY: u64 = 1;
    const O_RDWR: u64 = 2;
    const O_CREAT: u64 = 0x40;
    const O_TRUNC: u64 = 0x200;
    if (flags & (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC)) == 0 {
        return Ok(());
    }

    let mut entry = FILE_OPEN_EVENTS.reserve::<FileOpenEvent>(0).ok_or(-1i64)?;
    let ev = unsafe { entry.assume_init_mut() };
    ev.pid = pid;
    ev.uid = uid;
    ev.gid = gid;
    ev.flags = flags;
    ev.comm = comm;
    ev.filename = path;
    ev.filename_len = written as u32;

    entry.submit(0);
    Ok(())
}
