//! Optional syslog listener (`type: syslog`).
//!
//! Binds UDP or a Unix datagram socket and feeds each datagram through the
//! same syslog parser the file path uses. Does **not** bind `:514` or
//! `/dev/log` by default — stealing the system logger would be a
//! self-inflicted outage.

use tokio::net::UdpSocket;
use tracing::{info, warn};

use crate::config::LogSourceConfig;

pub enum SyslogListen {
    Udp(UdpSocket),
    #[cfg(unix)]
    Unix(tokio::net::UnixDatagram),
}

impl SyslogListen {
    pub async fn bind(source: &LogSourceConfig) -> Option<Self> {
        let addr = source.path.trim();
        if let Some(hp) = addr.strip_prefix("udp://") {
            match UdpSocket::bind(hp).await {
                Ok(sock) => {
                    info!(source = %source.name, addr = hp, "syslog UDP listener bound");
                    return Some(Self::Udp(sock));
                }
                Err(e) => {
                    warn!(source = %source.name, addr = hp, error = %e, "syslog UDP bind failed");
                    return None;
                }
            }
        }
        #[cfg(unix)]
        {
            let path = addr.strip_prefix("unix://").unwrap_or(addr);
            if path.starts_with('/') {
                let _ = std::fs::remove_file(path);
                match tokio::net::UnixDatagram::bind(path) {
                    Ok(sock) => {
                        info!(source = %source.name, path, "syslog unix listener bound");
                        return Some(Self::Unix(sock));
                    }
                    Err(e) => {
                        warn!(source = %source.name, path, error = %e, "syslog unix bind failed");
                        return None;
                    }
                }
            }
        }
        warn!(source = %source.name, addr = addr, "syslog listen address not recognised (use udp://host:port or unix:///path)");
        None
    }

    pub async fn recv_record(
        &self,
        buf: &mut [u8],
        counters: &crate::telemetry::metrics::Metrics,
    ) -> std::io::Result<Option<usize>> {
        let result = match self {
            Self::Udp(s) => s.recv(buf).await,
            #[cfg(unix)]
            Self::Unix(s) => s.recv(buf).await,
        };
        #[cfg(windows)]
        if matches!(&result, Err(error) if error.raw_os_error() == Some(windows_sys::Win32::Networking::WinSock::WSAEMSGSIZE))
        {
            counters.event_dropped(crate::telemetry::DropReason::EventTooLarge);
            return Ok(None);
        }
        let n = result?;
        if n == buf.len() {
            counters.event_dropped(crate::telemetry::DropReason::EventTooLarge);
            return Ok(None);
        }
        Ok(Some(n))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::telemetry::{metrics::Metrics, DropReason};

    #[tokio::test]
    async fn receive_distinguishes_exact_limit_from_oversize() {
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = receiver.local_addr().unwrap();
        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let listener = SyslogListen::Udp(receiver);
        let mut buf = [0; 5];
        let counters = Metrics::new();
        for (message, expected) in [
            (&b"1234"[..], Some(4)),
            (b"12345", None),
            (b"123456", None),
            (b"ok", Some(2)),
        ] {
            sender.send_to(message, address).await.unwrap();
            assert_eq!(
                listener.recv_record(&mut buf, &counters).await.unwrap(),
                expected
            );
        }
        assert_eq!(counters.drops_for(DropReason::EventTooLarge), 2);
    }
}
