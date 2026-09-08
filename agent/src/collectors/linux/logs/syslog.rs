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

    pub async fn recv(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Udp(s) => s.recv(buf).await,
            #[cfg(unix)]
            Self::Unix(s) => s.recv(buf).await,
        }
    }
}
