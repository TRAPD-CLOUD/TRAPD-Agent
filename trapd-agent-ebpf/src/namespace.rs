use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid},
    macros::{map, tracepoint},
    maps::RingBuf,
    programs::TracePointContext,
};

use crate::COMM_LEN;

// Relevant unshare/setns flags (CLONE_NEW*)
pub const CLONE_NEWNS:  u64 = 0x0002_0000; // mount namespace
pub const CLONE_NEWPID: u64 = 0x2000_0000; // PID namespace
pub const CLONE_NEWNET: u64 = 0x4000_0000; // network namespace
pub const CLONE_NEWUTS: u64 = 0x0400_0000; // UTS namespace
pub const CLONE_NEWUSER: u64 = 0x1000_0000; // user namespace
pub const CLONE_NEWIPC: u64 = 0x0800_0000; // IPC namespace

const NS_INTERESTING: u64 =
    CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWNET | CLONE_NEWUTS | CLONE_NEWUSER | CLONE_NEWIPC;

/// Namespace change event: unshare(2) or setns(2).
///
/// `op`: 0 = unshare, 1 = setns.
/// `flags` holds the CLONE_NEW* bitmask.
#[repr(C)]
pub struct NsChangeEvent {
    pub pid:    u32,
    pub uid:    u32,
    pub gid:    u32,
    pub op:     u8,
    pub _pad:   [u8; 3],
    pub comm:   [u8; COMM_LEN],
    pub flags:  u64,
    pub nstype: u32,
    pub _pad2:  u32,
}

/// 256 KiB – namespace changes are rare; all are tracked.
#[map]
static NS_CHANGE_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Tracepoint: syscalls/sys_enter_unshare
///
///   offset 16 │ u64  arg0  unshare_flags  (CLONE_NEW* bitmask)
#[tracepoint]
pub fn sys_enter_unshare(ctx: TracePointContext) -> u32 {
    match try_unshare(&ctx) {
        Ok(_) => 0,
        Err(_) => 0,
    }
}

/// Tracepoint: syscalls/sys_enter_setns
///
///   offset 16 │ u64  arg0  fd
///   offset 24 │ u64  arg1  nstype  (CLONE_NEW* constant, 0 = detect automatically)
#[tracepoint]
pub fn sys_enter_setns(ctx: TracePointContext) -> u32 {
    match try_setns(&ctx) {
        Ok(_) => 0,
        Err(_) => 0,
    }
}

#[inline(always)]
fn try_unshare(ctx: &TracePointContext) -> Result<(), i64> {
    let flags: u64 = unsafe { ctx.read_at(16).map_err(|_| -1i64)? };
    // Only emit for namespace-related flags
    if (flags & NS_INTERESTING) == 0 {
        return Ok(());
    }
    emit_ns(0u8, flags, 0u32)
}

#[inline(always)]
fn try_setns(ctx: &TracePointContext) -> Result<(), i64> {
    let nstype: u64 = unsafe { ctx.read_at(24).map_err(|_| -1i64)? };
    // nstype=0 means "any" → always interesting; otherwise check for NS flags
    emit_ns(1u8, nstype, nstype as u32)
}

#[inline(always)]
fn emit_ns(op: u8, flags: u64, nstype: u32) -> Result<(), i64> {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let uid_gid = bpf_get_current_uid_gid();
    let uid = (uid_gid & 0xFFFF_FFFF) as u32;
    let gid = (uid_gid >> 32) as u32;

    let comm = [0u8; COMM_LEN];
    let comm = bpf_get_current_comm().unwrap_or(comm);

    let mut entry = NS_CHANGE_EVENTS.reserve::<NsChangeEvent>(0).ok_or(-1i64)?;
    let ev = unsafe { entry.assume_init_mut() };
    ev.pid    = pid;
    ev.uid    = uid;
    ev.gid    = gid;
    ev.op     = op;
    ev._pad   = [0u8; 3];
    ev.comm   = comm;
    ev.flags  = flags;
    ev.nstype = nstype;
    ev._pad2  = 0;

    entry.submit(0);
    Ok(())
}
