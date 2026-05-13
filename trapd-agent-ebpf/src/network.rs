use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
        bpf_probe_read_user,
    },
    macros::{map, tracepoint},
    maps::RingBuf,
    programs::TracePointContext,
};

use crate::COMM_LEN;

pub const AF_INET: u16 = 2;
pub const AF_INET6: u16 = 10;

/// Network socket event: connect(2), bind(2), accept4(2).
///
/// `op`: 0 = connect, 1 = bind, 2 = accept.
/// `addr` holds the IPv4 address in bytes [0..4] (zero-padded) or the full
/// 16-byte IPv6 address. `port` is in host byte order. Both are zero for
/// accept events (remote addr not yet known at sys_enter).
#[repr(C)]
pub struct NetEvent {
    pub pid:    u32,
    pub uid:    u32,
    pub gid:    u32,
    pub op:     u8,
    pub _pad0:  [u8; 1],
    pub family: u16,
    pub port:   u16,
    pub _pad1:  [u8; 6],
    pub comm:   [u8; COMM_LEN],
    pub addr:   [u8; 16],
}

/// 512 KiB – shared by connect/bind/accept.
#[map]
static NET_EVENTS: RingBuf = RingBuf::with_byte_size(512 * 1024, 0);

// ── connect(2) ────────────────────────────────────────────────────────────────

/// Tracepoint: syscalls/sys_enter_connect
///
///   offset 16 │ u64  arg0  fd
///   offset 24 │ u64  arg1  uservaddr  ← user ptr to sockaddr
///   offset 32 │ u64  arg2  addrlen
#[tracepoint]
pub fn sys_enter_connect(ctx: TracePointContext) -> u32 {
    match try_net(&ctx, 0u8) {
        Ok(_) => 0,
        Err(_) => 0,
    }
}

// ── bind(2) ───────────────────────────────────────────────────────────────────

/// Tracepoint: syscalls/sys_enter_bind
///
///   offset 16 │ u64  arg0  fd
///   offset 24 │ u64  arg1  umyaddr  ← user ptr to sockaddr
///   offset 32 │ u64  arg2  addrlen
#[tracepoint]
pub fn sys_enter_bind(ctx: TracePointContext) -> u32 {
    match try_net(&ctx, 1u8) {
        Ok(_) => 0,
        Err(_) => 0,
    }
}

// ── accept4(2) ────────────────────────────────────────────────────────────────

/// Tracepoint: syscalls/sys_enter_accept4
///
///   offset 16 │ u64  arg0  fd  ← the listening socket
#[tracepoint]
pub fn sys_enter_accept4(ctx: TracePointContext) -> u32 {
    match try_accept(&ctx) {
        Ok(_) => 0,
        Err(_) => 0,
    }
}

// ── Shared helpers ────────────────────────────────────────────────────────────

#[inline(always)]
fn try_net(ctx: &TracePointContext, op: u8) -> Result<(), i64> {
    let sockaddr_uptr: u64 = unsafe { ctx.read_at(24).map_err(|_| -1i64)? };
    if sockaddr_uptr == 0 {
        return Ok(());
    }

    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let uid_gid = bpf_get_current_uid_gid();
    let uid = (uid_gid & 0xFFFF_FFFF) as u32;
    let gid = (uid_gid >> 32) as u32;

    let comm = [0u8; COMM_LEN];
    let comm = bpf_get_current_comm().unwrap_or(comm);

    // Read raw sockaddr bytes:
    //   sockaddr_in:  family(2) + port(2) + sin_addr(4)       = 8 bytes in addr_raw
    //   sockaddr_in6: family(2) + port(2) + flowinfo(4) + sin6_addr(16) = 20 bytes in addr_raw
    #[repr(C)]
    #[derive(Copy, Clone)]
    struct RawSockaddr {
        family:   u16,
        port_be:  u16,
        addr_raw: [u8; 20],
    }
    let raw: RawSockaddr = unsafe {
        bpf_probe_read_user(sockaddr_uptr as *const RawSockaddr).unwrap_or(RawSockaddr {
            family:   0,
            port_be:  0,
            addr_raw: [0u8; 20],
        })
    };

    let family = raw.family;
    // Only track IPv4 and IPv6
    if family != AF_INET && family != AF_INET6 {
        return Ok(());
    }

    let port = u16::from_be(raw.port_be);

    let mut addr = [0u8; 16];
    match family {
        AF_INET => {
            // addr_raw[0..4] = sin_addr.s_addr (IPv4 address)
            addr[..4].copy_from_slice(&raw.addr_raw[..4]);
        }
        AF_INET6 => {
            // addr_raw[0..4] = sin6_flowinfo (skipped)
            // addr_raw[4..20] = sin6_addr (IPv6 address, 16 bytes)
            addr.copy_from_slice(&raw.addr_raw[4..20]);
        }
        _ => {}
    }

    let mut entry = NET_EVENTS.reserve::<NetEvent>(0).ok_or(-1i64)?;
    let ev = unsafe { entry.assume_init_mut() };
    ev.pid = pid;
    ev.uid = uid;
    ev.gid = gid;
    ev.op = op;
    ev._pad0 = [0u8; 1];
    ev.family = family;
    ev.port = port;
    ev._pad1 = [0u8; 6];
    ev.comm = comm;
    ev.addr = addr;

    entry.submit(0);
    Ok(())
}

#[inline(always)]
fn try_accept(ctx: &TracePointContext) -> Result<(), i64> {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let uid_gid = bpf_get_current_uid_gid();
    let uid = (uid_gid & 0xFFFF_FFFF) as u32;
    let gid = (uid_gid >> 32) as u32;

    let comm = [0u8; COMM_LEN];
    let comm = bpf_get_current_comm().unwrap_or(comm);

    let mut entry = NET_EVENTS.reserve::<NetEvent>(0).ok_or(-1i64)?;
    let ev = unsafe { entry.assume_init_mut() };
    ev.pid = pid;
    ev.uid = uid;
    ev.gid = gid;
    ev.op = 2;
    ev._pad0 = [0u8; 1];
    ev.family = 0;
    ev.port = 0;
    ev._pad1 = [0u8; 6];
    ev.comm = comm;
    ev.addr = [0u8; 16];

    entry.submit(0);
    Ok(())
}
