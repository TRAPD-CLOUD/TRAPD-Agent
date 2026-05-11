use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid},
    macros::{map, tracepoint},
    maps::{Array, RingBuf},
    programs::TracePointContext,
};

use crate::COMM_LEN;

/// Kill signal event — emitted when a process sends SIGKILL/SIGTERM to our
/// protected agent PID.  Layout must match `RawKillSignalEvent` in
/// agent/src/collectors/linux/ebpf_syscalls.rs exactly.
#[repr(C)]
pub struct KillSignalEvent {
    pub sender_pid: u32,
    pub sender_uid: u32,
    pub sender_gid: u32,
    pub target_pid: i32,
    pub signal:     i32,
    pub comm:       [u8; COMM_LEN],
}

/// Single-slot array: index 0 holds the PID we are protecting.
/// Userspace writes the agent's own PID here after eBPF load.
/// Value 0 = "not configured yet" — all kill events are ignored.
#[map]
static PROTECTED_PID: Array<u32> = Array::with_max_entries(1, 0);

/// 256 KiB ring buffer; kill(2) towards a specific PID is extremely rare.
#[map]
static KILL_SIGNAL_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Tracepoint: syscalls/sys_enter_kill
///
/// Raw tracepoint record layout (x86-64):
///   offset  8 │ u64  __syscall_nr
///   offset 16 │ i64  pid    (target PID; −1 = broadcast to all)
///   offset 24 │ i64  sig    (signal number)
#[tracepoint]
pub fn sys_enter_kill(ctx: TracePointContext) -> u32 {
    match try_kill_event(&ctx) {
        Ok(_)  => 0,
        Err(_) => 0,
    }
}

/// Tracepoint: syscalls/sys_enter_tkill
///
/// Raw tracepoint record layout (x86-64):
///   offset 16 │ i64  tid    (target thread ID)
///   offset 24 │ i64  sig
#[tracepoint]
pub fn sys_enter_tkill(ctx: TracePointContext) -> u32 {
    match try_kill_event(&ctx) {
        Ok(_)  => 0,
        Err(_) => 0,
    }
}

/// Tracepoint: syscalls/sys_enter_tgkill
///
/// Raw tracepoint record layout (x86-64):
///   offset 16 │ i64  tgid   (thread-group ID = process PID)
///   offset 24 │ i64  pid    (thread ID within the group)
///   offset 32 │ i64  sig
///
/// We use tgid (offset 16) as the target because that is the process-level PID.
#[tracepoint]
pub fn sys_enter_tgkill(ctx: TracePointContext) -> u32 {
    match try_tgkill_event(&ctx) {
        Ok(_)  => 0,
        Err(_) => 0,
    }
}

#[inline(always)]
fn try_kill_event(ctx: &TracePointContext) -> Result<(), i64> {
    let target_pid: i32 = unsafe { ctx.read_at(16).map_err(|_| -1i64)? };
    let signal:     i32 = unsafe { ctx.read_at(24).map_err(|_| -1i64)? };
    emit_if_protected(ctx, target_pid, signal)
}

#[inline(always)]
fn try_tgkill_event(ctx: &TracePointContext) -> Result<(), i64> {
    let target_pid: i32 = unsafe { ctx.read_at(16).map_err(|_| -1i64)? };
    let signal:     i32 = unsafe { ctx.read_at(32).map_err(|_| -1i64)? };
    emit_if_protected(ctx, target_pid, signal)
}

#[inline(always)]
fn emit_if_protected(
    ctx:        &TracePointContext,
    target_pid: i32,
    signal:     i32,
) -> Result<(), i64> {
    // Only track SIGKILL (9) and SIGTERM (15) — the signals used to silence an EDR.
    if signal != 9 && signal != 15 {
        return Ok(());
    }

    // Skip if the protected PID has not been set by userspace yet.
    let protected = unsafe { PROTECTED_PID.get(0).copied().unwrap_or(0) };
    if protected == 0 {
        return Ok(());
    }

    // Only emit when target == our protected agent PID.
    if target_pid as u32 != protected {
        return Ok(());
    }

    let pid_tgid  = bpf_get_current_pid_tgid();
    let sender_pid = (pid_tgid >> 32) as u32;

    // The agent itself sends SIGTERM to itself on clean shutdown — ignore.
    if sender_pid == protected {
        return Ok(());
    }

    let uid_gid = bpf_get_current_uid_gid();
    let uid = (uid_gid & 0xFFFF_FFFF) as u32;
    let gid = (uid_gid >> 32) as u32;

    let mut comm = [0u8; COMM_LEN];
    unsafe { bpf_get_current_comm(&mut comm); }

    let mut entry = KILL_SIGNAL_EVENTS
        .reserve::<KillSignalEvent>(0)
        .ok_or(-1i64)?;
    let ev = unsafe { entry.assume_init_mut() };
    ev.sender_pid = sender_pid;
    ev.sender_uid = uid;
    ev.sender_gid = gid;
    ev.target_pid = target_pid;
    ev.signal     = signal;
    ev.comm       = comm;

    entry.submit(0);
    Ok(())
}
