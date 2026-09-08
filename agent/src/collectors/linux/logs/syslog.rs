//! Syslog listener (RFC 3164 / RFC 5424) over a Unix datagram socket or UDP.
//!
//! This is the *intake* side — applications and rsyslog can forward to the
//! agent. Default is off; bind addresses come from `type: syslog` sources.
//! Datagrams are capped at `max_line_bytes` and parsed by the syslog parser
//! (or whatever `parser` the source selected). UDP cannot block, so a full
//! pipeline uses `try_emit` rather than awaiting.

use std::path::Path;

use tokio::net::{UdpSocket, UnixDatagram};
use tokio::sync::mpsc::Sender;
use tracing::{info, warn};

use crate::config::LogSourceConfig;
use crate::pipeline;
use crate::schema::AgentEvent;
use crate::telemetry::{metrics::metrics, DropReason};

use super::framing::Frame;
use super::normalize;
use super::parser;
use super::rate::TokenBucket;

pub async fn run(
    source: LogSourceConfig,
    tx: Sender<AgentEvent>,
    agent_id: String,
    hostname: String,
    max_line: usize,
    mut limiter: TokenBucket,
) {
    let bind = source.path.trim();
    if bind.is_empty() {
        warn!(source = %source.name, "syslog source has empty path — skipped");
        return;
    }
    if let Some(path) = unix_path(bind) {
        listen_unix(
            &source,
            &tx,
            &agent_id,
            &hostname,
            path,
            max_line,
            &mut limiter,
        )
        .await;
    } else if let Some(addr) = udp_addr(bind) {
        listen_udp(
            &source,
            &tx,
            &agent_id,
            &hostname,
            &addr,
            max_line,
            &mut limiter,
        )
        .await;
    } else {
        warn!(source = %source.name, bind, "syslog source: unrecognised listen address");
    }
}

fn unix_path(bind: &str) -> Option<&str> {
    bind.strip_prefix("unix://")
        .or_else(|| bind.starts_with('/').then_some(bind))
}

fn udp_addr(bind: &str) -> Option<String> {
    bind.strip_prefix("udp://")
        .or_else(|| bind.strip_prefix("syslog://"))
        .map(str::to_string)
        .or_else(|| {
            if bind.contains(':') && !bind.starts_with('/') {
                Some(bind.to_string())
            } else {
                None
            }
        })
}

async fn listen_unix(
    source: &LogSourceConfig,
    tx: &Sender<AgentEvent>,
    agent_id: &str,
    hostname: &str,
    path: &str,
    max_line: usize,
    limiter: &mut TokenBucket,
) {
    let p = Path::new(path);
    if let Some(parent) = p.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::remove_file(p);
    let sock = match UnixDatagram::bind(p) {
        Ok(s) => s,
        Err(e) => {
            warn!(source = %source.name, path, error = %e, "syslog unix bind failed");
            return;
        }
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o660));
    }
    info!(source = %source.name, path, "log collector: syslog unix socket");
    let mut buf = vec![0u8; max_line.clamp(2048, 64 * 1024)];
    loop {
        if tx.is_closed() {
            let _ = std::fs::remove_file(p);
            return;
        }
        match sock.recv(&mut buf).await {
            Ok(n) => dispatch(source, tx, agent_id, hostname, &buf[..n], limiter, path),
            Err(e) => {
                warn!(source = %source.name, error = %e, "syslog unix recv failed");
                return;
            }
        }
    }
}

async fn listen_udp(
    source: &LogSourceConfig,
    tx: &Sender<AgentEvent>,
    agent_id: &str,
    hostname: &str,
    addr: &str,
    max_line: usize,
    limiter: &mut TokenBucket,
) {
    let sock = match UdpSocket::bind(addr).await {
        Ok(s) => s,
        Err(e) => {
            warn!(source = %source.name, addr, error = %e, "syslog udp bind failed");
            return;
        }
    };
    info!(source = %source.name, addr, "log collector: syslog UDP");
    let mut buf = vec![0u8; max_line.clamp(2048, 64 * 1024)];
    loop {
        if tx.is_closed() {
            return;
        }
        match sock.recv_from(&mut buf).await {
            Ok((n, _)) => dispatch(source, tx, agent_id, hostname, &buf[..n], limiter, addr),
            Err(e) => {
                warn!(source = %source.name, error = %e, "syslog udp recv failed");
                return;
            }
        }
    }
}

fn dispatch(
    source: &LogSourceConfig,
    tx: &Sender<AgentEvent>,
    agent_id: &str,
    hostname: &str,
    bytes: &[u8],
    limiter: &mut TokenBucket,
    origin: &str,
) {
    if !limiter.allow() {
        metrics().event_dropped(DropReason::RateLimitApplied);
        return;
    }
    let text = String::from_utf8_lossy(bytes)
        .trim_end_matches(['\0', '\n', '\r'])
        .to_string();
    if text.is_empty() {
        return;
    }
    let parser_name = if source.parser_name() == "auto" {
        "syslog"
    } else {
        source.parser_name()
    };
    let frame = Frame {
        truncated: false,
        bytes: bytes.len() as u64,
        multiline: false,
        text,
    };
    let parsed = parser::parse(parser_name, &frame.text);
    let event = normalize::normalize(agent_id, hostname, source, Some(origin), &frame, parsed);
    let _ = pipeline::try_emit(tx, event, "log");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_unix_and_udp_bind_specs() {
        assert_eq!(
            unix_path("unix:///run/trapd/syslog.sock"),
            Some("/run/trapd/syslog.sock")
        );
        assert_eq!(
            unix_path("/run/trapd/syslog.sock"),
            Some("/run/trapd/syslog.sock")
        );
        assert_eq!(
            udp_addr("udp://127.0.0.1:1514").as_deref(),
            Some("127.0.0.1:1514")
        );
        assert_eq!(udp_addr("0.0.0.0:1514").as_deref(), Some("0.0.0.0:1514"));
        assert!(unix_path("udp://127.0.0.1:1514").is_none());
    }
}
