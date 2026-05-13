use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid},
    macros::{map, tracepoint},
    maps::RingBuf,
    programs::TracePointContext,
};

use crate::COMM_LEN;

/// Shared memory event: shmget(2) or shmat(2).
///
/// `op`: 0 = shmget, 1 = shmat.
#[repr(C)]
pub struct ShmEvent {
    pub pid:   u32,
    pub uid:   u32,
    pub gid:   u32,
    pub op:    u8,
    pub _pad:  [u8; 3],
    pub comm:  [u8; COMM_LEN],
    /// shmget: IPC key  │  shmat: shmid
    pub key:   i32,
    pub _pad2: u32,
    /// shmget: requested size  │  shmat: requested shm address (hint)
    pub size:  u64,
    pub flags: i32,
    pub _pad3: u32,
}

/// 256 KiB.
#[map]
static SHM_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Tracepoint: syscalls/sys_enter_shmget
///
///   offset 16 │ u64  arg0  key    (key_t)
///   offset 24 │ u64  arg1  size   (size_t)
///   offset 32 │ u64  arg2  shmflg
#[tracepoint]
pub fn sys_enter_shmget(ctx: TracePointContext) -> u32 {
    match try_shmget(&ctx) {
        Ok(_) => 0,
        Err(_) => 0,
    }
}

/// Tracepoint: syscalls/sys_enter_shmat
///
///   offset 16 │ u64  arg0  shmid
///   offset 24 │ u64  arg1  shmaddr  (attach hint)
///   offset 32 │ u64  arg2  shmflg
#[tracepoint]
pub fn sys_enter_shmat(ctx: TracePointContext) -> u32 {
    match try_shmat(&ctx) {
        Ok(_) => 0,
        Err(_) => 0,
    }
}

#[inline(always)]
fn try_shmget(ctx: &TracePointContext) -> Result<(), i64> {
    let key:   u64 = unsafe { ctx.read_at(16).map_err(|_| -1i64)? };
    let size:  u64 = unsafe { ctx.read_at(24).map_err(|_| -1i64)? };
    let flags: u64 = unsafe { ctx.read_at(32).map_err(|_| -1i64)? };

    emit_shm(0u8, key as i32, size, flags as i32)
}

#[inline(always)]
fn try_shmat(ctx: &TracePointContext) -> Result<(), i64> {
    let shmid:   u64 = unsafe { ctx.read_at(16).map_err(|_| -1i64)? };
    let shmaddr: u64 = unsafe { ctx.read_at(24).map_err(|_| -1i64)? };
    let flags:   u64 = unsafe { ctx.read_at(32).map_err(|_| -1i64)? };

    emit_shm(1u8, shmid as i32, shmaddr, flags as i32)
}

#[inline(always)]
fn emit_shm(op: u8, key: i32, size: u64, flags: i32) -> Result<(), i64> {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let uid_gid = bpf_get_current_uid_gid();
    let uid = (uid_gid & 0xFFFF_FFFF) as u32;
    let gid = (uid_gid >> 32) as u32;

    let comm = [0u8; COMM_LEN];
    let comm = bpf_get_current_comm().unwrap_or(comm);

    let mut entry = SHM_EVENTS.reserve::<ShmEvent>(0).ok_or(-1i64)?;
    let ev = unsafe { entry.assume_init_mut() };
    ev.pid   = pid;
    ev.uid   = uid;
    ev.gid   = gid;
    ev.op    = op;
    ev._pad  = [0u8; 3];
    ev.comm  = comm;
    ev.key   = key;
    ev._pad2 = 0;
    ev.size  = size;
    ev.flags = flags;
    ev._pad3 = 0;

    entry.submit(0);
    Ok(())
}
