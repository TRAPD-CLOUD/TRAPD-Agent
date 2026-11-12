//! USB / removable-disk attach and detach from kernel uevents.
//!
//! Reads the kernel uevent multicast group (`NETLINK_KOBJECT_UEVENT`, group 1)
//! with a plain `libc` socket, no udev dependency. Only datagrams whose sender
//! is the kernel (`nl_pid == 0`) are parsed: a local process can otherwise
//! forge uevents on that socket family. Parsing and filtering live in
//! [`crate::collectors::device`].
//!
//! Loss transparency: a kernel receive-buffer overflow (`ENOBUFS`) is counted
//! as `kernel_ringbuffer_full`, a full pipeline channel as
//! `userspace_channel_full`, a burst beyond the rate budget as
//! `rate_limit_applied`, and a datagram that is not a valid uevent as
//! `internal_error`.

use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::{Arc, RwLock};
use std::time::Instant;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use tokio::sync::mpsc::Sender;
use tracing::{info, warn};

use crate::collectors::device::{
    clean_text, event_from_uevent, parse_uevent, Action, Parsed, RateBudget, SysfsInfo, Uevent,
    MAX_UEVENT_BYTES,
};
use crate::collectors::Collector;
use crate::config::AgentConfig;
use crate::schema::{AgentEvent, EventAction, EventClass, EventData, Severity};
use crate::telemetry::{metrics::metrics, DropReason};

const NETLINK_KOBJECT_UEVENT: libc::c_int = 15;
const KERNEL_GROUP: u32 = 1;
const EVENTS_PER_SECOND: u32 = 50;
const SYSFS_READ_MAX: u64 = 256;

pub struct DeviceCollector {
    config: Arc<RwLock<AgentConfig>>,
}

impl DeviceCollector {
    pub fn new(config: Arc<RwLock<AgentConfig>>) -> Self {
        Self { config }
    }
}

fn open_socket() -> std::io::Result<OwnedFd> {
    // SAFETY: plain syscalls; the fd is wrapped immediately and closed on drop.
    unsafe {
        let fd = libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            NETLINK_KOBJECT_UEVENT,
        );
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let owned = OwnedFd::from_raw_fd(fd);
        let mut addr: libc::sockaddr_nl = std::mem::zeroed();
        addr.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        addr.nl_groups = KERNEL_GROUP;
        if libc::bind(
            owned.as_raw_fd(),
            &addr as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        ) < 0
        {
            return Err(std::io::Error::last_os_error());
        }
        let tv = libc::timeval {
            tv_sec: 1,
            tv_usec: 0,
        };
        libc::setsockopt(
            owned.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &tv as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        );
        Ok(owned)
    }
}

enum Recv {
    Datagram(usize, u32),
    Timeout,
    Overflow,
    Failed(std::io::Error),
}

fn receive(fd: &OwnedFd, buf: &mut [u8]) -> Recv {
    // SAFETY: `buf` and `addr` outlive the call and the lengths are exact.
    unsafe {
        let mut addr: libc::sockaddr_nl = std::mem::zeroed();
        let mut len = std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t;
        let n = libc::recvfrom(
            fd.as_raw_fd(),
            buf.as_mut_ptr() as *mut libc::c_void,
            buf.len(),
            0,
            &mut addr as *mut _ as *mut libc::sockaddr,
            &mut len,
        );
        if n >= 0 {
            return Recv::Datagram(n as usize, addr.nl_pid);
        }
        let err = std::io::Error::last_os_error();
        match err.raw_os_error() {
            Some(libc::EAGAIN) | Some(libc::EINTR) => Recv::Timeout,
            Some(libc::ENOBUFS) => Recv::Overflow,
            _ => Recv::Failed(err),
        }
    }
}

/// One small sysfs attribute, bounded; `None` when the device is already gone.
fn read_attr(devpath: &str, name: &str) -> Option<String> {
    let mut text = String::new();
    std::fs::File::open(format!("/sys{devpath}/{name}"))
        .ok()?
        .take(SYSFS_READ_MAX)
        .read_to_string(&mut text)
        .ok()?;
    clean_text(&text)
}

fn sysfs_info(u: &Uevent, capture_serial: bool) -> SysfsInfo {
    if u.action != Action::Add || u.devtype != "usb_device" {
        return SysfsInfo::default();
    }
    SysfsInfo {
        // Never read the serial unless the operator opted in.
        serial: capture_serial
            .then(|| read_attr(&u.devpath, "serial"))
            .flatten(),
        manufacturer: read_attr(&u.devpath, "manufacturer"),
        product: read_attr(&u.devpath, "product"),
    }
}

#[async_trait]
impl Collector for DeviceCollector {
    fn name(&self) -> &'static str {
        "DeviceCollector"
    }

    async fn run(
        &mut self,
        tx: Sender<AgentEvent>,
        agent_id: String,
        hostname: String,
    ) -> Result<()> {
        let fd = open_socket().map_err(|e| anyhow!("uevent socket unavailable: {e}"))?;
        info!("DeviceCollector: listening for kernel uevents (usb, block)");
        let config = Arc::clone(&self.config);
        tokio::task::spawn_blocking(move || {
            let mut buf = vec![0u8; MAX_UEVENT_BYTES + 1];
            let mut budget = RateBudget::new(EVENTS_PER_SECOND, Instant::now());
            loop {
                if tx.is_closed() {
                    return Ok(());
                }
                match receive(&fd, &mut buf) {
                    Recv::Timeout => {}
                    Recv::Overflow => {
                        warn!("uevent receive buffer overflowed; device events were lost");
                        metrics().event_dropped(DropReason::KernelRingbufferFull);
                    }
                    Recv::Failed(e) => return Err(anyhow!("uevent receive failed: {e}")),
                    Recv::Datagram(_, pid) if pid != 0 => {
                        // Not the kernel: a local process injecting uevents.
                        metrics().event_dropped(DropReason::InternalError);
                    }
                    Recv::Datagram(n, _) => match parse_uevent(&buf[..n]) {
                        Parsed::Ignored => {}
                        Parsed::Malformed => metrics().event_dropped(DropReason::InternalError),
                        Parsed::Event(u) => {
                            if !budget.allow(Instant::now()) {
                                metrics().event_dropped(DropReason::RateLimitApplied);
                                continue;
                            }
                            let action = match u.action {
                                Action::Add => EventAction::Create,
                                Action::Remove => EventAction::Delete,
                            };
                            let capture_serial = config
                                .read()
                                .map(|c| c.device_serial_capture_enabled)
                                .unwrap_or(false);
                            let data = event_from_uevent(
                                &u,
                                sysfs_info(&u, capture_serial),
                                capture_serial,
                            );
                            let ev = AgentEvent::new(
                                agent_id.clone(),
                                hostname.clone(),
                                EventClass::Device,
                                action,
                                Severity::Info,
                                EventData::Device(data),
                            );
                            if tx.try_send(ev).is_err() {
                                metrics().event_dropped(DropReason::UserspaceChannelFull);
                            }
                        }
                    },
                }
            }
        })
        .await?
    }
}
