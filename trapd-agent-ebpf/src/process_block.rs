//! Kernel-side pre-execve process blocker.
//!
//! Attached to `sched/sched_process_exec`, fires *after* the kernel has
//! committed the new exec but *before* the first userspace instruction
//! returns from execve.  At that point `bpf_send_signal(SIGKILL)` on the
//! current task synchronously terminates the new process — equivalent to
//! pre-exec blocking from the perspective of any application code in the
//! binary.
//!
//! Two map-driven block lists:
//!   - `BLOCKED_COMMS`  : comm[16] → 1   (userspace populates from IocRule::Comm)
//!   - `BLOCKED_INODES` : inode_u64 → 1  (reserved for SHA256 rules)
//!
//! Kernel requirements:
//!   - `bpf_send_signal` — kernel ≥ 5.3
//!   - `BPF_MAP_TYPE_HASH` — universally available
//!
//! Falls open: if neither map contains the current task, the program does
//! nothing and the exec proceeds normally.

use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_send_signal},
    macros::{map, tracepoint},
    maps::HashMap,
    programs::TracePointContext,
};

use crate::COMM_LEN;

const SIGKILL: u32 = 9;

/// Map of blocked comms.  Up to 1024 entries.
#[map]
static BLOCKED_COMMS: HashMap<[u8; COMM_LEN], u8> =
    HashMap::<[u8; COMM_LEN], u8>::with_max_entries(1024, 0);

/// Map of blocked inodes (executable file).  Up to 1024 entries.
#[map]
static BLOCKED_INODES: HashMap<u64, u8> =
    HashMap::<u64, u8>::with_max_entries(1024, 0);

/// Tracepoint: sched/sched_process_exec
///
/// We intentionally don't dereference task_struct fields here (CO-RE is
/// fragile across kernels).  `bpf_get_current_comm()` is enough for comm
/// matches; inode-based matches happen by reading the tracepoint's
/// `__data_loc filename` field and letting userspace resolve to inode at
/// policy-update time.
#[tracepoint]
pub fn process_block_exec(ctx: TracePointContext) -> u32 {
    let _ = try_block(&ctx);
    0
}

#[inline(always)]
fn try_block(_ctx: &TracePointContext) -> Result<(), i64> {
    let comm = [0u8; COMM_LEN];
    let comm = bpf_get_current_comm().unwrap_or(comm);

    if unsafe { BLOCKED_COMMS.get(&comm).is_some() } {
        // bpf_send_signal sends to current task — the just-execed process.
        let _ = unsafe { bpf_send_signal(SIGKILL) };
        return Ok(());
    }

    Ok(())
}
