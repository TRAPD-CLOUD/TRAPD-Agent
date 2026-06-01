use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
        bpf_probe_read_kernel_str_bytes, bpf_probe_read_user, bpf_probe_read_user_str_bytes,
    },
    macros::{map, tracepoint},
    maps::RingBuf,
    programs::TracePointContext,
    EbpfContext,
};

use crate::{COMM_LEN, PATH_LEN};

const PRELOAD_LEN: usize = 256;

/// Raw exec event — layout must match `RawExecEvent` in agent/src/collectors/linux/ebpf_exec.rs.
#[repr(C)]
pub struct ExecEvent {
    pub pid:            u32,
    pub ppid:           u32,
    pub uid:            u32,
    pub gid:            u32,
    pub comm:           [u8; COMM_LEN],
    pub filename:       [u8; PATH_LEN],
    pub filename_len:   u32,
    /// Non-zero when an LD_PRELOAD value was detected in the process environment.
    pub ld_preload_len: u32,
    pub ld_preload:     [u8; PRELOAD_LEN],
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
    ev.pid            = pid;
    ev.ppid           = 0;
    ev.uid            = uid;
    ev.gid            = gid;
    ev.comm           = comm;
    ev.ld_preload_len = 0;

    let written = unsafe {
        bpf_probe_read_kernel_str_bytes(filename_ptr, &mut ev.filename)
            .map(|s| s.len())
            .unwrap_or(0)
    };
    ev.filename_len = written as u32;

    entry.submit(0);
    Ok(())
}

/// Tracepoint: syscalls/sys_enter_execve
///
/// Fires at the entry of execve(2). Scans the envp array for LD_PRELOAD and
/// emits an ExecEvent with ld_preload set only when found.
///
/// Record layout (sys_enter_execve, x86_64):
///   offset 16 │ u64  arg0  filename  (user pointer)
///   offset 24 │ u64  arg1  argv      (user pointer to char** array)
///   offset 32 │ u64  arg2  envp      (user pointer to char** array)
#[tracepoint]
pub fn sys_enter_execve(ctx: TracePointContext) -> u32 {
    match try_execve_ld_preload(&ctx) {
        Ok(_) => 0,
        Err(_) => 0,
    }
}

#[inline(always)]
fn try_execve_ld_preload(ctx: &TracePointContext) -> Result<(), i64> {
    let filename_uptr: u64 = unsafe { ctx.read_at(16).map_err(|_| -1i64)? };
    let envp_uptr:     u64 = unsafe { ctx.read_at(32).map_err(|_| -1i64)? };

    if envp_uptr == 0 {
        return Ok(());
    }

    // Scan up to 32 env vars for LD_PRELOAD=. The loop is bounded for the
    // BPF verifier. Using `continue` rather than `break` keeps the loop
    // structure simple and verifier-friendly.
    const MAX_ENV: usize = 32;
    const PREFIX_LEN: usize = 11; // len("LD_PRELOAD=")

    let mut found_str_ptr: u64 = 0;

    for i in 0..MAX_ENV {
        if found_str_ptr != 0 {
            continue;
        }

        let ptr_addr = (envp_uptr as usize).wrapping_add(i.wrapping_mul(8)) as *const u64;
        let str_ptr: u64 = unsafe { bpf_probe_read_user(ptr_addr).unwrap_or(0) };
        if str_ptr == 0 {
            continue;
        }

        // Read just enough bytes to check the "LD_PRELOAD=" prefix.
        let mut peek = [0u8; PREFIX_LEN + 1];
        let n = unsafe {
            bpf_probe_read_user_str_bytes(str_ptr as *const u8, &mut peek)
                .map(|s| s.len())
                .unwrap_or(0)
        };
        if n >= PREFIX_LEN && &peek[..PREFIX_LEN] == b"LD_PRELOAD=" {
            found_str_ptr = str_ptr;
        }
    }

    if found_str_ptr == 0 {
        return Ok(());
    }

    // LD_PRELOAD found — emit an exec event with the preload value.
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let uid_gid = bpf_get_current_uid_gid();
    let uid = (uid_gid & 0xFFFF_FFFF) as u32;
    let gid = (uid_gid >> 32) as u32;

    let comm = [0u8; COMM_LEN];
    let comm = bpf_get_current_comm().unwrap_or(comm);

    let mut entry = EXEC_EVENTS.reserve::<ExecEvent>(0).ok_or(-1i64)?;
    let ev = unsafe { entry.assume_init_mut() };
    ev.pid  = pid;
    ev.ppid = 0;
    ev.uid  = uid;
    ev.gid  = gid;
    ev.comm = comm;

    let fn_written = if filename_uptr != 0 {
        unsafe {
            bpf_probe_read_user_str_bytes(filename_uptr as *const u8, &mut ev.filename)
                .map(|s| s.len())
                .unwrap_or(0)
        }
    } else {
        0
    };
    ev.filename_len = fn_written as u32;

    let ld_written = unsafe {
        bpf_probe_read_user_str_bytes(found_str_ptr as *const u8, &mut ev.ld_preload)
            .map(|s| s.len())
            .unwrap_or(0)
    };
    ev.ld_preload_len = ld_written as u32;

    entry.submit(0);
    Ok(())
}
