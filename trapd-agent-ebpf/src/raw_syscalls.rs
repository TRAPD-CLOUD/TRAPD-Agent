//! Path-argument syscalls on `raw_syscalls:sys_enter`.
//!
//! The per-syscall tracepoints (`syscalls/sys_enter_*`) run BPF from
//! `perf_syscall_enter()`. On kernels that copy user-space string arguments
//! into syscall trace events, that function first faults those strings into a
//! per-CPU buffer and returns *before* calling BPF when that copy or the perf
//! buffer allocation fails. On the ubuntu-26.04 CI kernel `sys_enter_linkat`
//! and `sys_enter_renameat2` never ran while `ln`/`mv` executed, and write
//! opens of the same processes produced no file telemetry. The raw tracepoint
//! does not go through that function.
//!
//! When userspace attaches [`raw_sys_enter`] it does not attach the per-syscall
//! programs it replaces (open/openat/openat2, the stat/readlink/link path
//! gates, unlinkat, renameat2, fchmodat, fchownat), so nothing is reported
//! twice. The handlers are the same functions those programs call.
//!
//! x86_64 only: the syscall numbers and `struct pt_regs` offsets below are that
//! ABI's, and userspace attaches this program only on x86_64.

use aya_ebpf::{
    helpers::{bpf_probe_read_kernel, bpf_probe_read_user},
    macros::raw_tracepoint,
    programs::RawTracePointContext,
    EbpfContext,
};

use crate::file_manip::{chmod_enter, chown_enter, rename_enter, unlink_enter};
use crate::file_open::{
    check_honeytoken_user, open_enter, ACCESS_LINK, ACCESS_READLINK, ACCESS_STAT, ACCESS_STATX,
};

// `struct pt_regs` offsets of the syscall arguments (di, si, dx, r10).
const ARG0: usize = 112;
const ARG1: usize = 104;
const ARG2: usize = 96;
const ARG3: usize = 56;
const PT_REGS_CS: usize = 136;
/// `__USER_CS`: a 64-bit syscall. ia32 compat syscalls (`__USER32_CS`) number
/// differently (4 is `write` there, not `stat`) and are not decoded; the
/// per-syscall tracepoints do not report compat syscalls either. Only the low
/// 16 bits are the selector: with FRED the same slot carries further state.
const USER_CS_64: u64 = 0x33;

/// `creat(path, mode)` is `open(path, O_CREAT | O_WRONLY | O_TRUNC, mode)`.
const CREAT_FLAGS: u64 = 0x40 | 0x1 | 0x200;

/// Raw tracepoint: raw_syscalls/sys_enter (`args[0]` = user `pt_regs *`,
/// `args[1]` = syscall number). Runs for every syscall; anything not handled
/// returns after the number comparison.
#[raw_tracepoint(tracepoint = "sys_enter")]
pub fn raw_sys_enter(ctx: RawTracePointContext) -> i32 {
    let args = ctx.as_ptr() as *const u64;
    let nr = unsafe { *args.add(1) };
    if !handled(nr) {
        return 0;
    }
    let regs = unsafe { *args } as *const u8;
    let arg = |offset: usize| -> u64 {
        unsafe { bpf_probe_read_kernel(regs.add(offset) as *const u64) }.unwrap_or(0)
    };
    if arg(PT_REGS_CS) & 0xffff != USER_CS_64 {
        return 0;
    }
    let _ = match nr {
        2 => open_enter(arg(ARG0), arg(ARG1)),     // open
        257 => open_enter(arg(ARG1), arg(ARG2)),   // openat
        85 => open_enter(arg(ARG0), CREAT_FLAGS),  // creat
        437 => {
            // openat2: flags are the first field of the user `struct open_how`.
            match unsafe { bpf_probe_read_user(arg(ARG2) as *const u64) } {
                Ok(flags) => open_enter(arg(ARG1), flags),
                Err(_) => Ok(()),
            }
        }
        4 | 6 => gate(arg(ARG0), ACCESS_STAT),    // stat, lstat
        262 => gate(arg(ARG1), ACCESS_STAT),      // newfstatat
        332 => gate(arg(ARG1), ACCESS_STATX),     // statx
        89 => gate(arg(ARG0), ACCESS_READLINK),   // readlink
        267 => gate(arg(ARG1), ACCESS_READLINK),  // readlinkat
        86 => gate(arg(ARG0), ACCESS_LINK),       // link (oldpath)
        265 => gate(arg(ARG1), ACCESS_LINK),      // linkat (oldpath)
        87 => unlink_enter(arg(ARG0)),            // unlink
        263 => unlink_enter(arg(ARG1)),           // unlinkat
        82 => rename_enter(arg(ARG0), arg(ARG1)), // rename
        264 | 316 => rename_enter(arg(ARG1), arg(ARG3)), // renameat, renameat2
        90 => chmod_enter(arg(ARG0), arg(ARG1)),  // chmod
        268 | 452 => chmod_enter(arg(ARG1), arg(ARG2)), // fchmodat, fchmodat2
        92 | 94 => chown_enter(arg(ARG0), arg(ARG1), arg(ARG2)), // chown, lchown
        260 => chown_enter(arg(ARG1), arg(ARG2), arg(ARG3)),    // fchownat
        _ => Ok(()),
    };
    0
}

#[inline(always)]
fn handled(nr: u64) -> bool {
    matches!(
        nr,
        2 | 4 | 6 | 82 | 85 | 86 | 87 | 89 | 90 | 92 | 94 | 257 | 260 | 262 | 263 | 264 | 265
            | 267 | 268 | 316 | 332 | 437 | 452
    )
}

#[inline(always)]
fn gate(path_uptr: u64, access_kind: u32) -> Result<(), i64> {
    check_honeytoken_user(path_uptr, 0, access_kind);
    Ok(())
}
