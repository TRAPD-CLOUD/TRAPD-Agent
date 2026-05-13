use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
        bpf_probe_read_kernel_str_bytes,
    },
    macros::{map, tracepoint},
    maps::RingBuf,
    programs::TracePointContext,
    EbpfContext,
};

use crate::{COMM_LEN, PATH_LEN};

/// Raw exec event — layout must match `RawExecEvent` in agent/src/collectors/linux/ebpf_exec.rs.
#[repr(C)]
pub struct ExecEvent {
    pub pid:          u32,
    pub ppid:         u32,
    pub uid:          u32,
    pub gid:          u32,
    pub comm:         [u8; COMM_LEN],
    pub filename:     [u8; PATH_LEN],
    pub filename_len: u32,
}

/// 1 MiB ring buffer – handles ≈ 4 000 exec events/s at ≈ 256 B/event.
#[map]
static EXEC_EVENTS: RingBuf = RingBuf::with_byte_size(1024 * 1024, 0);

/// Tracepoint: sched/sched_process_exec
///
/// Fires after every successful execve(2)/execveat(2).
///
/// Record layout (sched_process_exec):
///   offset  8 │ u32  __data_loc filename  (bits[15:0]=offset, bits[31:16]=len)
///   offset 12 │ i32  pid
///   offset 16 │ i32  old_pid
#[tracepoint]
pub fn sched_process_exec(ctx: TracePointContext) -> u32 {
    match try_exec(&ctx) {
        Ok(_) => 0,
        Err(_) => 0,
    }
}

#[inline(always)]
fn try_exec(ctx: &TracePointContext) -> Result<(), i64> {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let uid_gid = bpf_get_current_uid_gid();
    let uid = (uid_gid & 0xFFFF_FFFF) as u32;
    let gid = (uid_gid >> 32) as u32;

    let comm = [0u8; COMM_LEN];
    let comm = bpf_get_current_comm().unwrap_or(comm);

    // __data_loc: bits[15:0] = byte offset from TP record start to the string
    let data_loc: u32 = unsafe { ctx.read_at(8).map_err(|_| -1i64)? };
    let fn_offset = (data_loc & 0xFFFF) as usize;
    let filename_ptr = (ctx.as_ptr() as usize).checked_add(fn_offset).ok_or(-1i64)? as *const u8;

    let mut entry = EXEC_EVENTS.reserve::<ExecEvent>(0).ok_or(-1i64)?;
    let ev = unsafe { entry.assume_init_mut() };
    ev.pid = pid;
    ev.ppid = 0;
    ev.uid = uid;
    ev.gid = gid;
    ev.comm = comm;

    let written = unsafe {
        bpf_probe_read_kernel_str_bytes(filename_ptr, &mut ev.filename)
            .map(|s| s.len())
            .unwrap_or(0)
    };
    ev.filename_len = written as u32;

    entry.submit(0);
    Ok(())
}
