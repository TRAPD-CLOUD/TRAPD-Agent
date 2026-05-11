use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid},
    macros::{map, tracepoint},
    maps::RingBuf,
    programs::TracePointContext,
};

use crate::COMM_LEN;

/// ptrace event — every ptrace(2) call is security-relevant.
#[repr(C)]
pub struct PtraceEvent {
    pub pid:        u32,
    pub uid:        u32,
    pub gid:        u32,
    /// PTRACE_ATTACH=16, PTRACE_PEEKDATA=2, PTRACE_POKEDATA=5, etc.
    pub request:    u32,
    /// Target process PID (arg1 of ptrace(2))
    pub target_pid: u32,
    pub _pad:       u32,
    pub comm:       [u8; COMM_LEN],
}

/// 256 KiB – ptrace is uncommon; all calls are tracked.
#[map]
static PTRACE_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Tracepoint: syscalls/sys_enter_ptrace
///
///   offset 16 │ u64  arg0  request  (PTRACE_* constant)
///   offset 24 │ u64  arg1  pid      (target PID)
///   offset 32 │ u64  arg2  addr
///   offset 40 │ u64  arg3  data
#[tracepoint]
pub fn sys_enter_ptrace(ctx: TracePointContext) -> u32 {
    match try_ptrace(&ctx) {
        Ok(_) => 0,
        Err(_) => 0,
    }
}

#[inline(always)]
fn try_ptrace(ctx: &TracePointContext) -> Result<(), i64> {
    let request:    u64 = unsafe { ctx.read_at(16).map_err(|_| -1i64)? };
    let target_pid: u64 = unsafe { ctx.read_at(24).map_err(|_| -1i64)? };

    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let uid_gid = bpf_get_current_uid_gid();
    let uid = (uid_gid & 0xFFFF_FFFF) as u32;
    let gid = (uid_gid >> 32) as u32;

    let mut comm = [0u8; COMM_LEN];
    unsafe { bpf_get_current_comm(&mut comm); }

    let mut entry = PTRACE_EVENTS.reserve::<PtraceEvent>(0).ok_or(-1i64)?;
    let ev = unsafe { entry.assume_init_mut() };
    ev.pid        = pid;
    ev.uid        = uid;
    ev.gid        = gid;
    ev.request    = request as u32;
    ev.target_pid = target_pid as u32;
    ev._pad       = 0;
    ev.comm       = comm;

    entry.submit(0);
    Ok(())
}
