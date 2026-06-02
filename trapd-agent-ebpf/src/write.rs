use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
        bpf_ktime_get_ns,
    },
    macros::{map, tracepoint},
    maps::{HashMap, RingBuf},
    programs::TracePointContext,
};

use crate::{COMM_LEN, PATH_LEN};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Rolling window for the write-rate (ransomware) detector. Writes are counted
/// per-PID within this window; the window resets once it elapses, so this is a
/// true *rate* — not a lifetime total.
const WRITE_WINDOW_NS: u64 = 1_000_000_000; // 1 second

/// Emit a WriteRateEvent when a process exceeds this many write(2) calls *within
/// one WRITE_WINDOW_NS window*. High enough that normal desktop/daemon I/O (which
/// is mostly to sockets/pipes and rarely sustains four-digit syscall rates per
/// second) does not trip it; low enough to catch a mass-encryption burst.
///
/// NOTE: this counts all write(2) fds (files, sockets, pipes). Filtering to
/// regular files would need fd→inode resolution in-kernel; the window + this
/// threshold already eliminate the steady-state false positives.
const WRITE_RATE_THRESHOLD: u64 = 1_000;

// ── Event struct ──────────────────────────────────────────────────────────────

/// Emitted to userspace when a process exceeds WRITE_BURST_THRESHOLD write(2) calls.
#[repr(C)]
pub struct WriteRateEvent {
    pub pid:             u32,
    pub uid:             u32,
    pub gid:             u32,
    pub _pad:            u32,
    pub comm:            [u8; COMM_LEN],
    /// Write-call count within the current window at time of emission.
    pub write_count:     u64,
    /// Threshold that triggered this emission (always WRITE_RATE_THRESHOLD).
    pub burst_threshold: u64,
}

/// Per-PID rolling-window write accounting.
#[repr(C)]
#[derive(Clone, Copy)]
struct WriteWindow {
    /// Monotonic ns at which the current window began.
    start_ns: u64,
    /// write(2) calls observed since `start_ns`.
    count:    u64,
}

// ── Maps ──────────────────────────────────────────────────────────────────────

/// Per-PID rolling-window write accounting (start timestamp + count).
#[map]
static WRITE_WINDOWS: HashMap<u32, WriteWindow> = HashMap::with_max_entries(16_384, 0);

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
    let now = unsafe { bpf_ktime_get_ns() };

    // Load the current window; start a fresh one if there is none or it elapsed.
    let (start_ns, prev_count) = match unsafe { WRITE_WINDOWS.get(&pid) } {
        Some(w) if now.saturating_sub(w.start_ns) <= WRITE_WINDOW_NS => (w.start_ns, w.count),
        _ => (now, 0),
    };
    let count = prev_count + 1;
    let win = WriteWindow { start_ns, count };
    unsafe { WRITE_WINDOWS.insert(&pid, &win, 0).map_err(|_| -1i64)?; }

    // Emit exactly once per window, at the moment the rate threshold is crossed.
    if count != WRITE_RATE_THRESHOLD {
        return Ok(());
    }

    let uid_gid = bpf_get_current_uid_gid();
    let uid = (uid_gid & 0xFFFF_FFFF) as u32;
    let gid = (uid_gid >> 32) as u32;
    let comm = [0u8; COMM_LEN];
    let comm = bpf_get_current_comm().unwrap_or(comm);

    let mut entry = match WRITE_RATE_EVENTS.reserve::<WriteRateEvent>(0) {
        Some(e) => e,
        None => {
            crate::dropcount::record_drop(crate::dropcount::SLOT_WRITE_RATE);
            return Err(-1i64);
        }
    };
    let ev = unsafe { entry.assume_init_mut() };
    ev.pid             = pid;
    ev.uid             = uid;
    ev.gid             = gid;
    ev._pad            = 0;
    ev.comm            = comm;
    ev.write_count     = count;
    ev.burst_threshold = WRITE_RATE_THRESHOLD;

    entry.submit(0);
    Ok(())
}
