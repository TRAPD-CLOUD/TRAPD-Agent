use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
        bpf_probe_read_kernel_buf, bpf_probe_read_kernel_str_bytes, bpf_probe_read_user,
        bpf_probe_read_user_str_bytes,
    },
    macros::{map, tracepoint},
    maps::{LruHashMap, PerCpuArray, RingBuf},
    programs::TracePointContext,
    EbpfContext,
};

use crate::{COMM_LEN, PATH_LEN};

const PRELOAD_LEN: usize = 256;

/// argv capture budget. A power of two so the write offset can be masked into
/// range for the verifier; the buffer carries one extra argument's worth of
/// slack so a masked offset plus `ARG_MAX` never leaves it.
const ARGS_LEN: usize = 1024;
const ARG_MAX: usize = 256;
const ARGS_BUF: usize = ARGS_LEN + ARG_MAX;
const MAX_ARGS: usize = 32;

/// `args_flags` bits.
const ARGS_PRESENT: u32 = 1;
const ARGS_TRUNCATED: u32 = 2;

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
    /// argv as read at execve entry: NUL-terminated strings back to back,
    /// like `/proc/<pid>/cmdline`. Only `args_len` bytes are meaningful.
    pub args_len:       u32,
    pub args_flags:     u32,
    pub args:           [u8; ARGS_BUF],
}

/// argv captured at execve entry, waiting for `sched_process_exec`.
#[repr(C)]
pub struct PendingArgv {
    pub len:   u32,
    pub flags: u32,
    pub buf:   [u8; ARGS_BUF],
}

/// 2 MiB ring buffer – an exec event is ≈ 1.9 KiB with argv, so this keeps
/// about 1 000 events of headroom for exec bursts. Every collector that loads
/// this object gets its own instance, so keep it modest.
#[map]
static EXEC_EVENTS: RingBuf = RingBuf::with_byte_size(2 * 1024 * 1024, 0);

/// Scratch space for building a `PendingArgv` (too large for the BPF stack).
#[map]
static ARGV_SCRATCH: PerCpuArray<PendingArgv> = PerCpuArray::with_max_entries(1, 0);

/// argv keyed by the exec'ing thread id. `/proc/<pid>/cmdline` is empty or
/// gone once a short-lived process has exited, so the command line is taken
/// from the syscall arguments instead (issue #218). LRU so failed execs that
/// never reach `sched_process_exec` age out.
#[map]
static ARGV_PENDING: LruHashMap<u32, PendingArgv> = LruHashMap::with_max_entries(1024, 0);

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

    // Read the executed binary's path into a local, zero-padded buffer first so
    // we can (a) run it through the honeytoken gate and (b) copy it into the
    // exec event. Doing the honeytoken check here — *before* reserving the exec
    // event — keeps the two ring-buffer reservations from overlapping.
    let mut filename = [0u8; PATH_LEN];
    let written = unsafe {
        bpf_probe_read_kernel_str_bytes(filename_ptr, &mut filename)
            .map(|s| s.len())
            .unwrap_or(0)
    };

    // ── Honeytoken gate: someone executed a bait file ────────────────────────
    crate::file_open::emit_honeytoken_buf(
        &filename,
        written as u32,
        0,
        crate::file_open::ACCESS_EXEC,
    );

    let mut entry = match EXEC_EVENTS.reserve::<ExecEvent>(0) {
        Some(e) => e,
        None => {
            crate::dropcount::record_drop(crate::dropcount::SLOT_EXEC);
            return Err(-1i64);
        }
    };
    let ev = unsafe { entry.assume_init_mut() };
    ev.pid            = pid;
    ev.ppid           = 0;
    ev.uid            = uid;
    ev.gid            = gid;
    ev.comm           = comm;
    ev.ld_preload_len = 0;
    ev.filename       = filename;
    ev.filename_len   = written as u32;
    ev.args_len       = 0;
    ev.args_flags     = 0;

    // old_pid is the id of the thread that called execve (a non-leader thread
    // takes over the leader's pid during exec), which is the pending key.
    let old_tid: i32 = unsafe { ctx.read_at(16).unwrap_or(-1) };
    if old_tid > 0 {
        let key = old_tid as u32;
        if let Some(p) = ARGV_PENDING.get_ptr_mut(&key) {
            let p = p as *const PendingArgv;
            // Copy map memory to ring memory with a helper: a struct copy of
            // this size would go through the 512-byte BPF stack.
            let ok = unsafe {
                bpf_probe_read_kernel_buf((*p).buf.as_ptr(), &mut ev.args).is_ok()
            };
            if ok {
                let len = unsafe { (*p).len };
                ev.args_len   = if (len as usize) < ARGS_BUF { len } else { ARGS_BUF as u32 };
                ev.args_flags = unsafe { (*p).flags };
            }
        }
        let _ = ARGV_PENDING.remove(&key);
    }

    entry.submit(0);
    Ok(())
}

/// Read up to [`MAX_ARGS`] argv strings from user memory into the pending map
/// for the current thread. Always clears an older entry first, so a failed
/// capture can never leave a previous exec's argv to be attached.
#[inline(always)]
fn capture_argv(argv_uptr: u64) {
    let tid = bpf_get_current_pid_tgid() as u32;
    let _ = ARGV_PENDING.remove(&tid);
    if argv_uptr == 0 {
        return;
    }
    let scratch = match ARGV_SCRATCH.get_ptr_mut(0) {
        Some(p) => p,
        None => return,
    };
    let a = unsafe { &mut *scratch };
    let mut off: usize = 0;
    let mut flags = ARGS_PRESENT;
    let mut ended = false;
    for i in 0..MAX_ARGS {
        let slot = (argv_uptr as usize).wrapping_add(i.wrapping_mul(8)) as *const u64;
        let ptr: u64 = unsafe { bpf_probe_read_user(slot).unwrap_or(0) };
        if ptr == 0 {
            ended = true;
            break;
        }
        if off >= ARGS_LEN {
            flags |= ARGS_TRUNCATED;
            ended = true;
            break;
        }
        let at = off & (ARGS_LEN - 1);
        let n = unsafe {
            aya_ebpf::helpers::gen::bpf_probe_read_user_str(
                a.buf.as_mut_ptr().add(at) as *mut core::ffi::c_void,
                ARG_MAX as u32,
                ptr as *const core::ffi::c_void,
            )
        };
        if n <= 0 {
            ended = true;
            break;
        }
        // A full read may have cut the argument short.
        if n as usize >= ARG_MAX {
            flags |= ARGS_TRUNCATED;
        }
        off = at + n as usize;
    }
    if !ended {
        // MAX_ARGS strings read; anything after them is lost.
        let slot = (argv_uptr as usize).wrapping_add(MAX_ARGS * 8) as *const u64;
        if unsafe { bpf_probe_read_user(slot).unwrap_or(0) } != 0 {
            flags |= ARGS_TRUNCATED;
        }
    }
    a.len = if off < ARGS_BUF { off as u32 } else { ARGS_BUF as u32 };
    a.flags = flags;
    if ARGV_PENDING.insert(&tid, a, 0).is_err() {
        crate::dropcount::record_drop(crate::dropcount::SLOT_EXEC);
    }
}

/// Tracepoint: syscalls/sys_enter_execveat — argv capture only.
///
///   offset 32 │ u64  arg2  argv  (user pointer to char** array)
#[tracepoint]
pub fn sys_enter_execveat(ctx: TracePointContext) -> u32 {
    let argv: u64 = unsafe { ctx.read_at(32).unwrap_or(0) };
    capture_argv(argv);
    0
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
    let argv_uptr:     u64 = unsafe { ctx.read_at(24).unwrap_or(0) };
    let envp_uptr:     u64 = unsafe { ctx.read_at(32).map_err(|_| -1i64)? };

    capture_argv(argv_uptr);

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

    let mut entry = match EXEC_EVENTS.reserve::<ExecEvent>(0) {
        Some(e) => e,
        None => {
            crate::dropcount::record_drop(crate::dropcount::SLOT_EXEC);
            return Err(-1i64);
        }
    };
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
    ev.args_len       = 0;
    ev.args_flags     = 0;

    entry.submit(0);
    Ok(())
}
