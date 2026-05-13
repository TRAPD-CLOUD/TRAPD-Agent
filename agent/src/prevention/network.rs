//! Network containment via `nft` (preferred) or `iptables` (fallback).
//!
//! The agent owns a dedicated table/chain so its rules can be inspected,
//! audited and torn down without touching operator-managed policy:
//!
//!   - nftables: table `inet trapd`, chain `block` (priority -200, prerouting
//!     equivalents added under `output` chain).
//!   - iptables: chain `TRAPD_BLOCK` jumped from `OUTPUT`.
//!
//! Two distinct response actions live here:
//!
//!   * `block_ip` / `unblock_ip` — surgically deny a single IP or CIDR.
//!   * `isolate` / `deisolate`   — full host isolation: only the management
//!     channel + an explicit allow-list are reachable.
//!
//! All shell-outs are quoted via `std::process::Command::arg()` to avoid
//! injection: input is parsed by `ipnet::IpNet` / `IpAddr` first.

use std::net::IpAddr;
use std::process::Command;

use anyhow::{anyhow, bail, Context, Result};
use ipnet::IpNet;
use tracing::{debug, info, warn};

const NFT_TABLE:    &str = "trapd";
const NFT_FAMILY:   &str = "inet";
const NFT_BLOCK:    &str = "block";
const NFT_ISOLATE:  &str = "isolate_allow";
const IPT_CHAIN:    &str = "TRAPD_BLOCK";

#[derive(Debug, Clone, Copy)]
pub enum Backend { Nft, Iptables, None }

pub fn detect_backend() -> Backend {
    if Command::new("nft").arg("--version").output().is_ok() {
        Backend::Nft
    } else if Command::new("iptables").arg("--version").output().is_ok() {
        Backend::Iptables
    } else {
        Backend::None
    }
}

/// Initialise the agent's own table/chain.  Idempotent.
pub fn ensure_chains(backend: Backend) -> Result<()> {
    match backend {
        Backend::Nft => {
            nft(&["add", "table", NFT_FAMILY, NFT_TABLE])?;
            nft(&[
                "add", "chain", NFT_FAMILY, NFT_TABLE, NFT_BLOCK,
                "{", "type", "filter", "hook", "output", "priority", "-200", ";", "}",
            ])?;
            nft(&[
                "add", "chain", NFT_FAMILY, NFT_TABLE, NFT_ISOLATE,
                "{", "type", "filter", "hook", "output", "priority", "-150", ";", "policy", "accept", ";", "}",
            ])?;
            Ok(())
        }
        Backend::Iptables => {
            let _ = run("iptables", &["-N", IPT_CHAIN]);
            let listed = run_output("iptables", &["-C", "OUTPUT", "-j", IPT_CHAIN]);
            if !listed.ok() {
                run("iptables", &["-I", "OUTPUT", "1", "-j", IPT_CHAIN])
                    .context("cannot insert TRAPD_BLOCK jump into OUTPUT")?;
            }
            Ok(())
        }
        Backend::None => bail!("no firewall backend available (need nft or iptables)"),
    }
}

/// Add a deny rule for `target`.
pub fn block_ip(backend: Backend, target: &str) -> Result<String> {
    let parsed = parse_ip_or_cidr(target)?;
    match backend {
        Backend::Nft => {
            let (family, addr) = match parsed {
                NetTarget::Ip(IpAddr::V4(a))     => ("ip",  a.to_string()),
                NetTarget::Ip(IpAddr::V6(a))     => ("ip6", a.to_string()),
                NetTarget::Cidr(IpNet::V4(n))    => ("ip",  n.to_string()),
                NetTarget::Cidr(IpNet::V6(n))    => ("ip6", n.to_string()),
            };
            nft(&[
                "add", "rule", NFT_FAMILY, NFT_TABLE, NFT_BLOCK,
                family, "daddr", &addr, "counter", "drop",
            ])?;
            info!(target, "nft drop rule added");
            Ok(format!("nft:{family}:{addr}"))
        }
        Backend::Iptables => {
            let opt = match parsed {
                NetTarget::Ip(IpAddr::V4(_)) | NetTarget::Cidr(IpNet::V4(_)) => "iptables",
                NetTarget::Ip(IpAddr::V6(_)) | NetTarget::Cidr(IpNet::V6(_)) => "ip6tables",
            };
            run(opt, &["-A", IPT_CHAIN, "-d", target, "-j", "DROP"])?;
            info!(target, tool=opt, "iptables drop rule added");
            Ok(format!("{opt}:{target}"))
        }
        Backend::None => bail!("no firewall backend"),
    }
}

pub fn unblock_ip(backend: Backend, target: &str) -> Result<()> {
    let parsed = parse_ip_or_cidr(target)?;
    match backend {
        Backend::Nft => {
            let (family, addr) = match parsed {
                NetTarget::Ip(IpAddr::V4(a))     => ("ip",  a.to_string()),
                NetTarget::Ip(IpAddr::V6(a))     => ("ip6", a.to_string()),
                NetTarget::Cidr(IpNet::V4(n))    => ("ip",  n.to_string()),
                NetTarget::Cidr(IpNet::V6(n))    => ("ip6", n.to_string()),
            };
            // nft doesn't support delete-by-criteria; we look up handles.
            let listing = run_output("nft", &["-a", "list", "chain", NFT_FAMILY, NFT_TABLE, NFT_BLOCK]);
            if !listing.ok() {
                bail!("cannot list nft chain {NFT_BLOCK}");
            }
            let text = String::from_utf8_lossy(&listing.stdout);
            let needle = format!("{family} daddr {addr} ");
            let mut removed = 0;
            for line in text.lines() {
                if line.contains(&needle) {
                    if let Some(idx) = line.find("# handle ") {
                        let handle = line[idx + "# handle ".len()..].trim();
                        if !handle.is_empty() {
                            let _ = run("nft", &[
                                "delete", "rule", NFT_FAMILY, NFT_TABLE, NFT_BLOCK,
                                "handle", handle,
                            ]);
                            removed += 1;
                        }
                    }
                }
            }
            if removed == 0 { warn!(target, "no matching nft rule to unblock"); }
            else            { info!(target, removed, "nft rules removed"); }
            Ok(())
        }
        Backend::Iptables => {
            let opt = match parsed {
                NetTarget::Ip(IpAddr::V4(_)) | NetTarget::Cidr(IpNet::V4(_)) => "iptables",
                NetTarget::Ip(IpAddr::V6(_)) | NetTarget::Cidr(IpNet::V6(_)) => "ip6tables",
            };
            run(opt, &["-D", IPT_CHAIN, "-d", target, "-j", "DROP"])?;
            info!(target, tool=opt, "iptables drop rule removed");
            Ok(())
        }
        Backend::None => bail!("no firewall backend"),
    }
}

/// Apply full host isolation: deny everything except the management
/// channel and an explicit allow-list (loopback is always included).
pub fn isolate(backend: Backend, allowlist_ips: &[IpAddr]) -> Result<()> {
    match backend {
        Backend::Nft => {
            nft(&["flush", "chain", NFT_FAMILY, NFT_TABLE, NFT_ISOLATE])?;
            nft(&["add", "rule", NFT_FAMILY, NFT_TABLE, NFT_ISOLATE,
                  "meta", "oif", "lo", "accept"])?;
            for ip in allowlist_ips {
                let (family, addr) = match ip {
                    IpAddr::V4(a) => ("ip",  a.to_string()),
                    IpAddr::V6(a) => ("ip6", a.to_string()),
                };
                nft(&["add", "rule", NFT_FAMILY, NFT_TABLE, NFT_ISOLATE,
                      family, "daddr", &addr, "accept"])?;
            }
            nft(&["add", "rule", NFT_FAMILY, NFT_TABLE, NFT_ISOLATE,
                  "counter", "drop"])?;
            info!(allow = allowlist_ips.len(), "host isolated (nft)");
            Ok(())
        }
        Backend::Iptables => {
            const ISOLATE_CHAIN: &str = "TRAPD_ISOLATE";
            let _ = run("iptables", &["-N", ISOLATE_CHAIN]);
            run("iptables", &["-F", ISOLATE_CHAIN])?;
            run("iptables", &["-A", ISOLATE_CHAIN, "-o", "lo", "-j", "ACCEPT"])?;
            for ip in allowlist_ips {
                if let IpAddr::V4(a) = ip {
                    run("iptables", &["-A", ISOLATE_CHAIN, "-d", &a.to_string(), "-j", "ACCEPT"])?;
                }
            }
            run("iptables", &["-A", ISOLATE_CHAIN, "-j", "DROP"])?;
            if !run_output("iptables", &["-C", "OUTPUT", "-j", ISOLATE_CHAIN]).ok() {
                run("iptables", &["-I", "OUTPUT", "1", "-j", ISOLATE_CHAIN])?;
            }
            info!(allow = allowlist_ips.len(), "host isolated (iptables)");
            Ok(())
        }
        Backend::None => bail!("no firewall backend"),
    }
}

pub fn deisolate(backend: Backend) -> Result<()> {
    match backend {
        Backend::Nft => {
            nft(&["flush", "chain", NFT_FAMILY, NFT_TABLE, NFT_ISOLATE])?;
            info!("host isolation lifted (nft)");
            Ok(())
        }
        Backend::Iptables => {
            const ISOLATE_CHAIN: &str = "TRAPD_ISOLATE";
            let _ = run("iptables", &["-D", "OUTPUT", "-j", ISOLATE_CHAIN]);
            let _ = run("iptables", &["-F", ISOLATE_CHAIN]);
            info!("host isolation lifted (iptables)");
            Ok(())
        }
        Backend::None => bail!("no firewall backend"),
    }
}

enum NetTarget {
    Ip(IpAddr),
    Cidr(IpNet),
}

fn parse_ip_or_cidr(s: &str) -> Result<NetTarget> {
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Ok(NetTarget::Ip(ip));
    }
    if let Ok(net) = s.parse::<IpNet>() {
        return Ok(NetTarget::Cidr(net));
    }
    Err(anyhow!("not a valid IP address or CIDR: {s}"))
}

fn nft(args: &[&str]) -> Result<()> {
    run("nft", args)
}

fn run(bin: &str, args: &[&str]) -> Result<()> {
    debug!(?bin, ?args, "exec");
    let out = Command::new(bin)
        .args(args)
        .output()
        .with_context(|| format!("failed to spawn {bin}"))?;
    if !out.status.success() {
        bail!(
            "{bin} {} exited {}: {}",
            args.join(" "),
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

struct CapturedOutput {
    status: bool,
    stdout: Vec<u8>,
}

impl CapturedOutput {
    fn ok(&self) -> bool { self.status }
}

fn run_output(bin: &str, args: &[&str]) -> CapturedOutput {
    match Command::new(bin).args(args).output() {
        Ok(o)  => CapturedOutput { status: o.status.success(), stdout: o.stdout },
        Err(_) => CapturedOutput { status: false, stdout: Vec::new() },
    }
}
