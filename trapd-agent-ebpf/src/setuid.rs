use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid},
    macros::{map, tracepoint},
    maps::RingBuf,
    programs::TracePointContext,
};

use crate::COMM_LEN;

/// setuid event — emitted for setuid/setreuid/setresuid syscalls.
#[repr(C)]
pub struct SetuidEvent {
    pub pid:     u32,
    pub old_uid: u32,
    pub new_uid: u32,
    pub _pad:    u32,
    pub comm:    [u8; COMM_LEN],
}

/// 256 KiB – setuid calls are uncommon; all are tracked.
#[map]
static SETUID_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Tracepoint: syscalls/sys_enter_setuid
///
///   offset 16 │ u64  arg0  uid  (new uid to set)
#[tracepoint]
pub fn sys_enter_setuid(ctx: TracePointContext) -> u32 {
    let uid: u64 = match unsafe { ctx.read_at(16) } {
        Ok(v) => v,
        Err(_) => return 0,
    };
    emit_setuid_event(&ctx, uid as u32);
    0
}

/// Tracepoint: syscalls/sys_enter_setreuid
///
///   offset 16 │ u64  arg0  ruid
///   offset 24 │ u64  arg1  euid  ← effective uid — security-relevant
#[tracepoint]
pub fn sys_enter_setreuid(ctx: TracePointContext) -> u32 {
    let euid: u64 = match unsafe { ctx.read_at(24) } {
        Ok(v) => v,
        Err(_) => return 0,
    };
    emit_setuid_event(&ctx, euid as u32);
    0
}

/// Tracepoint: syscalls/sys_enter_setresuid
///
///   offset 16 │ u64  arg0  ruid
///   offset 24 │ u64  arg1  euid  ← effective uid — security-relevant
///   offset 32 │ u64  arg2  suid
#[tracepoint]
pub fn sys_enter_setresuid(ctx: TracePointContext) -> u32 {
    let euid: u64 = match unsafe { ctx.read_at(24) } {
        Ok(v) => v,
        Err(_) => return 0,
    };
    emit_setuid_event(&ctx, euid as u32);
    0
}

#[inline(always)]
fn emit_setuid_event(ctx: &TracePointContext, new_uid: u32) {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let uid_gid = bpf_get_current_uid_gid();
    let old_uid = (uid_gid & 0xFFFF_FFFF) as u32;

    let comm = [0u8; COMM_LEN];
    let comm = bpf_get_current_comm().unwrap_or(comm);

    let mut entry = match SETUID_EVENTS.reserve::<SetuidEvent>(0) {
        Some(e) => e,
        None => return,
    };
    let ev = unsafe { entry.assume_init_mut() };
    ev.pid     = pid;
    ev.old_uid = old_uid;
    ev.new_uid = new_uid;
    ev._pad    = 0;
    ev.comm    = comm;

    entry.submit(0);
}
