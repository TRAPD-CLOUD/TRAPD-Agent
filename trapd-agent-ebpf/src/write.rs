use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
    },
    macros::{map, tracepoint},
    maps::{HashMap, RingBuf},
    programs::TracePointContext,
};

use crate::{COMM_LEN, PATH_LEN};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Emit a WriteRateEvent when a process accumulates this many write(2) calls.
/// Chosen high enough to ignore normal I/O, low enough to catch ransomware bursts.
const WRITE_BURST_THRESHOLD: u64 = 200;

// ── Event struct ──────────────────────────────────────────────────────────────

/// Emitted to userspace when a process exceeds WRITE_BURST_THRESHOLD write(2) calls.
#[repr(C)]
pub struct WriteRateEvent {
    pub pid:             u32,
    pub uid:             u32,
    pub gid:             u32,
    pub _pad:            u32,
    pub comm:            [u8; COMM_LEN],
    /// Accumulated write call count at time of emission.
    pub write_count:     u64,
    /// Threshold that triggered this emission (always WRITE_BURST_THRESHOLD).
    pub burst_threshold: u64,
}

// ── Maps ──────────────────────────────────────────────────────────────────────

/// Per-PID write call accumulator. Resets after each emission.
#[map]
static WRITE_COUNTS: HashMap<u32, u64> = HashMap::with_max_entries(16_384, 0);

/// Ring buffer to userspace: one entry per burst threshold crossing.
#[map]
static WRITE_RATE_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

// ── Tracepoint ────────────────────────────────────────────────────────────────

/// Tracepoint: syscalls/sys_enter_write
///
///   offset  8 │ u64  syscall_nr
///   offset 16 │ u64  arg0  fd
///   offset 24 │ u64  arg1  buf (user ptr)
///   offset 32 │ u64  arg2  count (bytes requested)
#[tracepoint]
pub fn sys_enter_write(ctx: TracePointContext) -> u32 {
    match try_write(&ctx) {
        Ok(_)  => 0,
        Err(_) => 0,
    }
}

#[inline(always)]
fn try_write(ctx: &TracePointContext) -> Result<(), i64> {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;

    // Read and increment the per-PID counter.
    let prev: u64 = unsafe {
        WRITE_COUNTS.get(&pid).copied().unwrap_or(0)
    };
    let next = prev + 1;
    unsafe { WRITE_COUNTS.insert(&pid, &next, 0).map_err(|_| -1i64)?; }

    // Emit once per threshold crossing, then reset the counter.
    if next % WRITE_BURST_THRESHOLD != 0 {
        return Ok(());
    }

    let uid_gid = bpf_get_current_uid_gid();
    let uid = (uid_gid & 0xFFFF_FFFF) as u32;
    let gid = (uid_gid >> 32) as u32;
    let comm = [0u8; COMM_LEN];
    let comm = bpf_get_current_comm().unwrap_or(comm);

    let mut entry = WRITE_RATE_EVENTS.reserve::<WriteRateEvent>(0).ok_or(-1i64)?;
    let ev = unsafe { entry.assume_init_mut() };
    ev.pid             = pid;
    ev.uid             = uid;
    ev.gid             = gid;
    ev._pad            = 0;
    ev.comm            = comm;
    ev.write_count     = next;
    ev.burst_threshold = WRITE_BURST_THRESHOLD;

    entry.submit(0);
    Ok(())
}
