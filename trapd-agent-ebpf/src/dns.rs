use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
        bpf_probe_read_kernel,
    },
    macros::{kprobe, map},
    maps::RingBuf,
    programs::ProbeContext,
};

use crate::COMM_LEN;

// struct sock_common offsets (stable across kernel 5.2+)
const SOCK_DADDR_OFFSET:  usize = 0;   // __be32 skc_daddr  (IPv4 dst addr)
const SOCK_DPORT_OFFSET:  usize = 12;  // __be16 skc_dport  (network byte order)
const SOCK_FAMILY_OFFSET: usize = 16;  // u16    skc_family

// DNS port 53 in network byte order (big-endian stored as little-endian u16 on x86_64)
// 53 = 0x0035  →  big-endian bytes [0x00, 0x35]  →  read as u16 LE = 0x3500
const DNS_PORT_BE: u16 = 53u16.swap_bytes();

pub const AF_INET: u16 = 2;

/// DNS query event captured via kprobe on udp_sendmsg.
#[repr(C)]
pub struct DnsEvent {
    pub pid:      u32,
    pub uid:      u32,
    pub gid:      u32,
    pub family:   u16,
    pub dst_port: u16,
    pub comm:     [u8; COMM_LEN],
    pub dst_addr: [u8; 16],
}

/// 256 KiB – DNS queries are frequent but the filter keeps volume low.
#[map]
static DNS_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// kprobe: udp_sendmsg(struct sock *sk, struct msghdr *msg, size_t len)
///
/// Reads the destination port from the socket's skc_dport field.
/// For connected UDP sockets (the common DNS resolver pattern) this is set
/// after connect(); for one-shot sendto() sockets skc_dport may be 0 and
/// we fall back to reading msg->msg_name.
#[kprobe]
pub fn kprobe__udp_sendmsg(ctx: ProbeContext) -> u32 {
    match try_dns(&ctx) {
        Ok(_) => 0,
        Err(_) => 0,
    }
}

#[inline(always)]
fn try_dns(ctx: &ProbeContext) -> Result<(), i64> {
    // arg0 = struct sock *sk  (kernel pointer)
    let sk: *const u8 = ctx.arg(0).ok_or(-1i64)?;
    if sk.is_null() {
        return Ok(());
    }

    // Read destination port from struct sock_common
    let dport_be: u16 = unsafe {
        bpf_probe_read_kernel((sk as usize + SOCK_DPORT_OFFSET) as *const u16)
            .unwrap_or(0)
    };

    let family: u16 = unsafe {
        bpf_probe_read_kernel((sk as usize + SOCK_FAMILY_OFFSET) as *const u16)
            .unwrap_or(0)
    };

    // Try msg->msg_name fallback for unconnected sendto() when sk_dport == 0
    let (effective_port_be, effective_family) = if dport_be == 0 {
        // arg1 = struct msghdr *msg  (kernel pointer)
        let msg: *const u8 = ctx.arg(1).ok_or(-1i64)?;
        if msg.is_null() {
            return Ok(());
        }
        // msg->msg_name is at offset 0 (kernel-space pointer to sockaddr)
        let msg_name: *const u8 = unsafe {
            bpf_probe_read_kernel(msg as *const *const u8).unwrap_or(core::ptr::null())
        };
        if msg_name.is_null() {
            return Ok(());
        }
        let f: u16 = unsafe {
            bpf_probe_read_kernel(msg_name as *const u16).unwrap_or(0)
        };
        let p: u16 = unsafe {
            bpf_probe_read_kernel((msg_name as usize + 2) as *const u16).unwrap_or(0)
        };
        (p, f)
    } else {
        (dport_be, family)
    };

    if effective_port_be != DNS_PORT_BE {
        return Ok(());
    }

    // Read destination IPv4 address
    let daddr: u32 = unsafe {
        bpf_probe_read_kernel((sk as usize + SOCK_DADDR_OFFSET) as *const u32)
            .unwrap_or(0)
    };
    let mut dst_addr = [0u8; 16];
    dst_addr[..4].copy_from_slice(&daddr.to_ne_bytes());

    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let uid_gid = bpf_get_current_uid_gid();
    let uid = (uid_gid & 0xFFFF_FFFF) as u32;
    let gid = (uid_gid >> 32) as u32;

    let mut comm = [0u8; COMM_LEN];
    unsafe { bpf_get_current_comm(&mut comm); }

    let mut entry = DNS_EVENTS.reserve::<DnsEvent>(0).ok_or(-1i64)?;
    let ev = unsafe { entry.assume_init_mut() };
    ev.pid      = pid;
    ev.uid      = uid;
    ev.gid      = gid;
    ev.family   = effective_family;
    ev.dst_port = 53;
    ev.comm     = comm;
    ev.dst_addr = dst_addr;

    entry.submit(0);
    Ok(())
}
