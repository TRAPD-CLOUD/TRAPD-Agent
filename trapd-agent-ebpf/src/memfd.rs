use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_probe_read_user_str_bytes},
    macros::{map, tracepoint},
    maps::RingBuf,
    programs::TracePointContext,
};

use crate::COMM_LEN;

const MEMFD_NAME_LEN: usize = 64;

/// memfd_create event — fileless malware indicator (MITRE T1620).
#[repr(C)]
pub struct MemfdEvent {
    pub pid:      u32,
    pub flags:    u32,
    pub comm:     [u8; COMM_LEN],
    pub name:     [u8; MEMFD_NAME_LEN],
    pub name_len: u32,
    pub _pad:     u32,
}

/// 256 KiB – memfd_create is uncommon; all calls are tracked.
#[map]
static MEMFD_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Tracepoint: syscalls/sys_enter_memfd_create
///
///   offset 16 │ u64  arg0  uname_ptr  (user pointer to name string)
///   offset 24 │ u64  arg1  flags
#[tracepoint]
pub fn sys_enter_memfd_create(ctx: TracePointContext) -> u32 {
    match try_memfd(&ctx) {
        Ok(_) => 0,
        Err(_) => 0,
    }
}

#[inline(always)]
fn try_memfd(ctx: &TracePointContext) -> Result<(), i64> {
    let uname_ptr: u64 = unsafe { ctx.read_at(16).map_err(|_| -1i64)? };
    let flags:     u64 = unsafe { ctx.read_at(24).map_err(|_| -1i64)? };

    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;

    let comm = [0u8; COMM_LEN];
    let comm = bpf_get_current_comm().unwrap_or(comm);

    let mut entry = match MEMFD_EVENTS.reserve::<MemfdEvent>(0) {
        Some(e) => e,
        None => {
            crate::dropcount::record_drop(crate::dropcount::SLOT_MEMFD);
            return Err(-1i64);
        }
    };
    let ev = unsafe { entry.assume_init_mut() };
    ev.pid   = pid;
    ev.flags = flags as u32;
    ev.comm  = comm;
    ev._pad  = 0;

    let written = if uname_ptr != 0 {
        unsafe {
            bpf_probe_read_user_str_bytes(uname_ptr as *const u8, &mut ev.name)
                .map(|s| s.len())
                .unwrap_or(0)
        }
    } else {
        0
    };
    ev.name_len = written as u32;

    entry.submit(0);
    Ok(())
}
