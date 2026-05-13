use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid},
    macros::{map, tracepoint},
    maps::RingBuf,
    programs::TracePointContext,
};

use crate::COMM_LEN;

// mmap protection flags
const PROT_WRITE: u64 = 0x2;
const PROT_EXEC:  u64 = 0x4;
// mmap flags
const MAP_ANONYMOUS: u64 = 0x20;

/// mmap event — only emitted for security-relevant mappings (anon+exec or rwx).
#[repr(C)]
pub struct MmapEvent {
    pub pid:   u32,
    pub uid:   u32,
    pub gid:   u32,
    pub prot:  u32,
    pub flags: u32,
    pub _pad:  u32,
    pub addr:  u64,
    pub len:   u64,
    pub comm:  [u8; COMM_LEN],
}

/// 256 KiB – filtered to suspicious mappings only.
#[map]
static MMAP_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Tracepoint: syscalls/sys_enter_mmap
///
///   offset 16 │ u64  arg0  addr
///   offset 24 │ u64  arg1  len
///   offset 32 │ u64  arg2  prot
///   offset 40 │ u64  arg3  flags
///   offset 48 │ u64  arg4  fd
///   offset 56 │ u64  arg5  off
#[tracepoint]
pub fn sys_enter_mmap(ctx: TracePointContext) -> u32 {
    match try_mmap(&ctx) {
        Ok(_) => 0,
        Err(_) => 0,
    }
}

#[inline(always)]
fn try_mmap(ctx: &TracePointContext) -> Result<(), i64> {
    let prot:  u64 = unsafe { ctx.read_at(32).map_err(|_| -1i64)? };
    let flags: u64 = unsafe { ctx.read_at(40).map_err(|_| -1i64)? };

    // Only track:
    //  • Anonymous executable mappings (fileless malware pattern)
    //  • Writable+executable mappings (shellcode injection pattern)
    let is_anon_exec = (flags & MAP_ANONYMOUS != 0) && (prot & PROT_EXEC != 0);
    let is_rwx = (prot & (PROT_WRITE | PROT_EXEC)) == (PROT_WRITE | PROT_EXEC);
    if !is_anon_exec && !is_rwx {
        return Ok(());
    }

    let addr: u64 = unsafe { ctx.read_at(16).map_err(|_| -1i64)? };
    let len:  u64 = unsafe { ctx.read_at(24).map_err(|_| -1i64)? };

    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let uid_gid = bpf_get_current_uid_gid();
    let uid = (uid_gid & 0xFFFF_FFFF) as u32;
    let gid = (uid_gid >> 32) as u32;

    let comm = [0u8; COMM_LEN];
    let comm = bpf_get_current_comm().unwrap_or(comm);

    let mut entry = MMAP_EVENTS.reserve::<MmapEvent>(0).ok_or(-1i64)?;
    let ev = unsafe { entry.assume_init_mut() };
    ev.pid   = pid;
    ev.uid   = uid;
    ev.gid   = gid;
    ev.prot  = prot as u32;
    ev.flags = flags as u32;
    ev._pad  = 0;
    ev.addr  = addr;
    ev.len   = len;
    ev.comm  = comm;

    entry.submit(0);
    Ok(())
}
