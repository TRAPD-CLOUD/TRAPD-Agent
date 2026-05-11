use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
        bpf_probe_read_user_str_bytes,
    },
    macros::{map, tracepoint},
    maps::RingBuf,
    programs::TracePointContext,
};

use crate::{COMM_LEN, PATH_LEN};

// ── Event structs ─────────────────────────────────────────────────────────────

#[repr(C)]
pub struct FileUnlinkEvent {
    pub pid:      u32,
    pub uid:      u32,
    pub gid:      u32,
    pub _pad:     u32,
    pub comm:     [u8; COMM_LEN],
    pub path:     [u8; PATH_LEN],
    pub path_len: u32,
}

#[repr(C)]
pub struct FileRenameEvent {
    pub pid:          u32,
    pub uid:          u32,
    pub gid:          u32,
    pub _pad:         u32,
    pub comm:         [u8; COMM_LEN],
    pub old_path:     [u8; PATH_LEN],
    pub old_path_len: u32,
    pub new_path:     [u8; PATH_LEN],
    pub new_path_len: u32,
}

#[repr(C)]
pub struct FileChmodEvent {
    pub pid:      u32,
    pub uid:      u32,
    pub gid:      u32,
    pub mode:     u32,
    pub comm:     [u8; COMM_LEN],
    pub path:     [u8; PATH_LEN],
    pub path_len: u32,
}

#[repr(C)]
pub struct FileChownEvent {
    pub pid:      u32,
    pub uid:      u32,
    pub gid:      u32,
    pub new_uid:  u32,
    pub new_gid:  u32,
    pub _pad:     u32,
    pub comm:     [u8; COMM_LEN],
    pub path:     [u8; PATH_LEN],
    pub path_len: u32,
}

// ── Maps ─────────────────────────────────────────────────────────────────────

#[map]
static UNLINK_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[map]
static RENAME_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[map]
static CHMOD_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[map]
static CHOWN_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

// ── Tracepoints ───────────────────────────────────────────────────────────────

/// Tracepoint: syscalls/sys_enter_unlinkat
///
///   offset 16 │ u64  arg0  dfd
///   offset 24 │ u64  arg1  pathname  ← user ptr
///   offset 32 │ u64  arg2  flag
#[tracepoint]
pub fn sys_enter_unlinkat(ctx: TracePointContext) -> u32 {
    match try_unlink(&ctx) {
        Ok(_) => 0,
        Err(_) => 0,
    }
}

/// Tracepoint: syscalls/sys_enter_renameat2
///
///   offset 16 │ u64  arg0  olddfd
///   offset 24 │ u64  arg1  oldname  ← user ptr
///   offset 32 │ u64  arg2  newdfd
///   offset 40 │ u64  arg3  newname  ← user ptr
///   offset 48 │ u64  arg4  flags
#[tracepoint]
pub fn sys_enter_renameat2(ctx: TracePointContext) -> u32 {
    match try_rename(&ctx) {
        Ok(_) => 0,
        Err(_) => 0,
    }
}

/// Tracepoint: syscalls/sys_enter_fchmodat
///
///   offset 16 │ u64  arg0  dfd
///   offset 24 │ u64  arg1  filename  ← user ptr
///   offset 32 │ u64  arg2  mode
#[tracepoint]
pub fn sys_enter_fchmodat(ctx: TracePointContext) -> u32 {
    match try_chmod(&ctx) {
        Ok(_) => 0,
        Err(_) => 0,
    }
}

/// Tracepoint: syscalls/sys_enter_fchownat
///
///   offset 16 │ u64  arg0  dfd
///   offset 24 │ u64  arg1  filename  ← user ptr
///   offset 32 │ u64  arg2  user (new uid)
///   offset 40 │ u64  arg3  group (new gid)
///   offset 48 │ u64  arg4  flag
#[tracepoint]
pub fn sys_enter_fchownat(ctx: TracePointContext) -> u32 {
    match try_chown(&ctx) {
        Ok(_) => 0,
        Err(_) => 0,
    }
}

// ── Implementations ───────────────────────────────────────────────────────────

#[inline(always)]
fn try_unlink(ctx: &TracePointContext) -> Result<(), i64> {
    let path_uptr: u64 = unsafe { ctx.read_at(24).map_err(|_| -1i64)? };
    if path_uptr == 0 {
        return Ok(());
    }

    let (pid, uid, gid, comm) = current_task_info();

    let mut entry = UNLINK_EVENTS.reserve::<FileUnlinkEvent>(0).ok_or(-1i64)?;
    let ev = unsafe { entry.assume_init_mut() };
    ev.pid  = pid;
    ev.uid  = uid;
    ev.gid  = gid;
    ev._pad = 0;
    ev.comm = comm;

    let written = unsafe {
        bpf_probe_read_user_str_bytes(path_uptr as *const u8, &mut ev.path)
            .map(|s| s.len())
            .unwrap_or(0)
    };
    ev.path_len = written as u32;

    entry.submit(0);
    Ok(())
}

#[inline(always)]
fn try_rename(ctx: &TracePointContext) -> Result<(), i64> {
    let old_uptr: u64 = unsafe { ctx.read_at(24).map_err(|_| -1i64)? };
    let new_uptr: u64 = unsafe { ctx.read_at(40).map_err(|_| -1i64)? };
    if old_uptr == 0 || new_uptr == 0 {
        return Ok(());
    }

    let (pid, uid, gid, comm) = current_task_info();

    let mut entry = RENAME_EVENTS.reserve::<FileRenameEvent>(0).ok_or(-1i64)?;
    let ev = unsafe { entry.assume_init_mut() };
    ev.pid  = pid;
    ev.uid  = uid;
    ev.gid  = gid;
    ev._pad = 0;
    ev.comm = comm;

    let old_written = unsafe {
        bpf_probe_read_user_str_bytes(old_uptr as *const u8, &mut ev.old_path)
            .map(|s| s.len())
            .unwrap_or(0)
    };
    ev.old_path_len = old_written as u32;

    let new_written = unsafe {
        bpf_probe_read_user_str_bytes(new_uptr as *const u8, &mut ev.new_path)
            .map(|s| s.len())
            .unwrap_or(0)
    };
    ev.new_path_len = new_written as u32;

    entry.submit(0);
    Ok(())
}

#[inline(always)]
fn try_chmod(ctx: &TracePointContext) -> Result<(), i64> {
    let path_uptr: u64 = unsafe { ctx.read_at(24).map_err(|_| -1i64)? };
    if path_uptr == 0 {
        return Ok(());
    }
    let mode: u64 = unsafe { ctx.read_at(32).map_err(|_| -1i64)? };

    let (pid, uid, gid, comm) = current_task_info();

    let mut entry = CHMOD_EVENTS.reserve::<FileChmodEvent>(0).ok_or(-1i64)?;
    let ev = unsafe { entry.assume_init_mut() };
    ev.pid  = pid;
    ev.uid  = uid;
    ev.gid  = gid;
    ev.mode = mode as u32;
    ev.comm = comm;

    let written = unsafe {
        bpf_probe_read_user_str_bytes(path_uptr as *const u8, &mut ev.path)
            .map(|s| s.len())
            .unwrap_or(0)
    };
    ev.path_len = written as u32;

    entry.submit(0);
    Ok(())
}

#[inline(always)]
fn try_chown(ctx: &TracePointContext) -> Result<(), i64> {
    let path_uptr: u64 = unsafe { ctx.read_at(24).map_err(|_| -1i64)? };
    if path_uptr == 0 {
        return Ok(());
    }
    let new_uid: u64 = unsafe { ctx.read_at(32).map_err(|_| -1i64)? };
    let new_gid: u64 = unsafe { ctx.read_at(40).map_err(|_| -1i64)? };

    let (pid, uid, gid, comm) = current_task_info();

    let mut entry = CHOWN_EVENTS.reserve::<FileChownEvent>(0).ok_or(-1i64)?;
    let ev = unsafe { entry.assume_init_mut() };
    ev.pid     = pid;
    ev.uid     = uid;
    ev.gid     = gid;
    ev.new_uid = new_uid as u32;
    ev.new_gid = new_gid as u32;
    ev._pad    = 0;
    ev.comm    = comm;

    let written = unsafe {
        bpf_probe_read_user_str_bytes(path_uptr as *const u8, &mut ev.path)
            .map(|s| s.len())
            .unwrap_or(0)
    };
    ev.path_len = written as u32;

    entry.submit(0);
    Ok(())
}

#[inline(always)]
fn current_task_info() -> (u32, u32, u32, [u8; COMM_LEN]) {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let uid_gid = bpf_get_current_uid_gid();
    let uid = (uid_gid & 0xFFFF_FFFF) as u32;
    let gid = (uid_gid >> 32) as u32;
    let mut comm = [0u8; COMM_LEN];
    unsafe { bpf_get_current_comm(&mut comm); }
    (pid, uid, gid, comm)
}
