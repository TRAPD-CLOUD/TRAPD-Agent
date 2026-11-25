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
                if let Err(e) = remove_stale_socket(std::path::Path::new(path)) {
                    warn!(source = %source.name, error = %e, "syslog path already occupied");
                    return None;
                }
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

#[cfg(unix)]
fn remove_stale_socket(path: &std::path::Path) -> std::io::Result<()> {
    use std::io::{Error, ErrorKind};
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let meta = match std::fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    let occupied = || {
        Error::new(
            ErrorKind::AddrInUse,
            "existing syslog path is not a stale agent-owned socket",
        )
    };
    #[cfg(target_os = "linux")]
    let uid = unsafe { libc::geteuid() };
    #[cfg(not(target_os = "linux"))]
    let uid = 0;
    if !meta.file_type().is_socket() || meta.uid() != uid {
        return Err(occupied());
    }
    // A writable or symlinked ancestor allows replacement between probe and unlink.
    for dir in path.ancestors().skip(1) {
        let m = std::fs::symlink_metadata(dir)?;
        if !m.is_dir() || (m.uid() != uid && m.uid() != 0) || m.mode() & 0o022 != 0 {
            return Err(occupied());
        }
    }
    let probe = std::os::unix::net::UnixDatagram::unbound()?;
    match probe.connect(path) {
        Err(e) if e.kind() == ErrorKind::ConnectionRefused => {
            let now = std::fs::symlink_metadata(path)?;
            if (now.dev(), now.ino()) != (meta.dev(), meta.ino()) {
                return Err(occupied());
            }
            std::fs::remove_file(path)
        }
        _ => Err(occupied()),
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    #[test]
    fn existing_regular_file_is_preserved() {
        let path = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
        std::fs::write(&path, b"preserve").unwrap();
        assert!(remove_stale_socket(&path).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"preserve");
        std::fs::remove_file(path).unwrap();
    }
}
