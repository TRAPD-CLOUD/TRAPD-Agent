#![no_std]
#![no_main]
#![allow(nonstandard_style, dead_code)]

use aya_ebpf::{
    helpers::{
        bpf_get_current_comm,
        bpf_get_current_pid_tgid,
        bpf_get_current_uid_gid,
        bpf_probe_read_kernel_str_bytes,
    },
    macros::{map, tracepoint},
    maps::RingBuf,
    programs::TracePointContext,
};

// ── Sizes — must match `RawExecEvent` in agent/src/collectors/linux/ebpf_exec.rs
const COMM_LEN: usize = 16;
const FILENAME_LEN: usize = 256;

/// Raw event emitted from kernel to userspace on every successful execve(2).
///
/// repr(C) guarantees stable field layout across the ring-buffer boundary.
/// All byte arrays are NUL-terminated; `filename_len` is the number of
/// non-NUL bytes written to `filename`.
#[repr(C)]
pub struct ExecEvent {
    /// User-space visible PID (kernel tgid)
    pub pid: u32,
    /// Parent PID — always 0 here; enriched in userspace via /proc
    pub ppid: u32,
    /// Real UID of the calling process
    pub uid: u32,
    /// Real GID of the calling process
    pub gid: u32,
    /// Task comm name (≤ 15 chars + NUL)
    pub comm: [u8; COMM_LEN],
    /// Absolute path of the exec'd binary (NUL-terminated)
    pub filename: [u8; FILENAME_LEN],
    /// Byte length of filename content (excluding NUL)
    pub filename_len: u32,
}

/// 1 MiB ring buffer — handles ≈ 4 000 events/s at ≈ 256 B/event.
///
/// Ring buffers (kernel ≥ 5.8) are preferred over perf-event arrays:
/// no per-CPU overhead, no lost-events counter per-CPU, lower latency.
#[map]
static EXEC_EVENTS: RingBuf = RingBuf::with_byte_size(1024 * 1024, 0);

/// Tracepoint: sched/sched_process_exec
///
/// Fires after every successful execve(2)/execveat(2). The process image
/// has already been replaced at this point — pid/uid/comm reflect the new
/// process, not the caller.
///
/// Tracepoint record layout
/// (see /sys/kernel/tracing/events/sched/sched_process_exec/format):
///
///   offset  0 │ u16  common_type
///   offset  2 │ u8   common_flags
///   offset  3 │ u8   common_preempt_count
///   offset  4 │ i32  common_pid
///   offset  8 │ u32  __data_loc filename   ← bits[15:0]=offset, bits[31:16]=len
///   offset 12 │ i32  pid
///   offset 16 │ i32  old_pid
#[tracepoint]
pub fn sched_process_exec(ctx: TracePointContext) -> u32 {
    match try_exec(&ctx) {
        Ok(_) => 0,
        Err(_) => 1,
    }
}

#[inline(always)]
fn try_exec(ctx: &TracePointContext) -> Result<(), i64> {
    // ── Identity ─────────────────────────────────────────────────────────────
    // bpf_get_current_pid_tgid → upper 32 bits = tgid (user-space PID)
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;

    // bpf_get_current_uid_gid → lower 32 bits = uid, upper 32 bits = gid
    let uid_gid = bpf_get_current_uid_gid();
    let uid = (uid_gid & 0xFFFF_FFFF) as u32;
    let gid = (uid_gid >> 32) as u32;

    // ── Task name (comm) ──────────────────────────────────────────────────────
    let mut comm = [0u8; COMM_LEN];
    unsafe {
        bpf_get_current_comm(&mut comm);
    }

    // ── Filename via __data_loc ───────────────────────────────────────────────
    // Read the 4-byte __data_loc descriptor at context offset 8.
    // bits[15:0] = byte offset from the start of the tp record to the string.
    // bits[31:16] = length (we don't use this; bpf_probe_read_kernel_str handles it).
    let data_loc: u32 = unsafe { ctx.read_at(8).map_err(|_| -1i64)? };
    let fn_offset = (data_loc & 0xFFFF) as usize;

    // Pointer to the NUL-terminated filename inside the tracepoint record.
    let filename_ptr = (ctx.as_ptr() as usize)
        .checked_add(fn_offset)
        .ok_or(-1i64)? as *const u8;

    // ── Reserve ring buffer slot and fill it ──────────────────────────────────
    let mut entry = EXEC_EVENTS.reserve::<ExecEvent>(0).ok_or(-1i64)?;

    // SAFETY: the kernel zeroes ring-buffer memory before making it available.
    let ev = unsafe { entry.assume_init_mut() };
    ev.pid = pid;
    ev.ppid = 0; // enriched from /proc/<pid>/status in userspace
    ev.uid = uid;
    ev.gid = gid;
    ev.comm = comm;

    // Read the filename string from kernel memory into our ring buffer slot.
    let written = unsafe {
        bpf_probe_read_kernel_str_bytes(filename_ptr, &mut ev.filename)
            .map(|s| s.len())
            .unwrap_or(0)
    };
    ev.filename_len = written as u32;

    entry.submit(0);
    Ok(())
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
