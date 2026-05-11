use aya_ebpf::{
    macros::{map, tracepoint},
    maps::RingBuf,
    programs::TracePointContext,
};

use crate::COMM_LEN;

/// Fork/clone event emitted on every successful process creation.
#[repr(C)]
pub struct ForkEvent {
    pub parent_pid:  u32,
    pub child_pid:   u32,
    pub parent_comm: [u8; COMM_LEN],
    pub child_comm:  [u8; COMM_LEN],
}

/// 256 KiB – fork events are moderately frequent.
#[map]
static FORK_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Tracepoint: sched/sched_process_fork
///
/// Record layout:
///   offset  8 │ char[16]  parent_comm
///   offset 24 │ i32       parent_pid
///   offset 28 │ char[16]  child_comm
///   offset 44 │ i32       child_pid
#[tracepoint]
pub fn sched_process_fork(ctx: TracePointContext) -> u32 {
    match try_fork(&ctx) {
        Ok(_) => 0,
        Err(_) => 0,
    }
}

#[inline(always)]
fn try_fork(ctx: &TracePointContext) -> Result<(), i64> {
    let parent_pid: i32 = unsafe { ctx.read_at(24).map_err(|_| -1i64)? };
    let child_pid:  i32 = unsafe { ctx.read_at(44).map_err(|_| -1i64)? };

    let mut parent_comm = [0u8; COMM_LEN];
    let mut child_comm  = [0u8; COMM_LEN];

    // comm arrays are directly embedded in the TP record (kernel memory)
    let parent_comm_raw: [u8; COMM_LEN] = unsafe { ctx.read_at(8).map_err(|_| -1i64)? };
    let child_comm_raw:  [u8; COMM_LEN] = unsafe { ctx.read_at(28).map_err(|_| -1i64)? };
    parent_comm.copy_from_slice(&parent_comm_raw);
    child_comm.copy_from_slice(&child_comm_raw);

    let mut entry = FORK_EVENTS.reserve::<ForkEvent>(0).ok_or(-1i64)?;
    let ev = unsafe { entry.assume_init_mut() };
    ev.parent_pid  = parent_pid as u32;
    ev.child_pid   = child_pid  as u32;
    ev.parent_comm = parent_comm;
    ev.child_comm  = child_comm;

    entry.submit(0);
    Ok(())
}
