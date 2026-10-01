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

const NFT_TABLE: &str = "trapd";
const NFT_FAMILY: &str = "inet";
const NFT_BLOCK: &str = "block";
const NFT_ISOLATE: &str = "isolate_allow";
const IPT_CHAIN: &str = "TRAPD_BLOCK";

#[derive(Debug, Clone, Copy)]
pub enum Backend {
    Nft,
    Iptables,
    None,
}

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
                "add", "chain", NFT_FAMILY, NFT_TABLE, NFT_BLOCK, "{", "type", "filter", "hook",
                "output", "priority", "-200", ";", "}",
            ])?;
            nft(&[
                "add",
                "chain",
                NFT_FAMILY,
                NFT_TABLE,
                NFT_ISOLATE,
                "{",
                "type",
                "filter",
                "hook",
                "output",
                "priority",
                "-150",
                ";",
                "policy",
                "accept",
                ";",
                "}",
            ])?;
            Ok(())
        }
        Backend::Iptables => {
            for tool in ["iptables", "ip6tables"] {
                ensure_iptables_chain(tool, IPT_CHAIN)?;
                if !run_output(tool, &["-C", "OUTPUT", "-j", IPT_CHAIN]).ok() {
                    run(tool, &["-I", "OUTPUT", "1", "-j", IPT_CHAIN])
                        .context("cannot insert TRAPD_BLOCK jump into OUTPUT")?;
                }
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
                NetTarget::Ip(IpAddr::V4(a)) => ("ip", a.to_string()),
                NetTarget::Ip(IpAddr::V6(a)) => ("ip6", a.to_string()),
                NetTarget::Cidr(IpNet::V4(n)) => ("ip", n.to_string()),
                NetTarget::Cidr(IpNet::V6(n)) => ("ip6", n.to_string()),
            };
            nft(&[
                "add", "rule", NFT_FAMILY, NFT_TABLE, NFT_BLOCK, family, "daddr", &addr, "counter",
                "drop",
            ])?;
            info!(target, "nft drop rule added");
            Ok(format!("nft:{family}:{addr}"))
        }
        Backend::Iptables => {
            let opt = match parsed {
                NetTarget::Ip(IpAddr::V4(_)) | NetTarget::Cidr(IpNet::V4(_)) => "iptables",
                NetTarget::Ip(IpAddr::V6(_)) | NetTarget::Cidr(IpNet::V6(_)) => "ip6tables",
            };
            ensure_iptables_chain(opt, IPT_CHAIN)?;
            if !run_output(opt, &["-C", "OUTPUT", "-j", IPT_CHAIN]).ok() {
                run(opt, &["-I", "OUTPUT", "1", "-j", IPT_CHAIN])?;
            }
            run(opt, &["-A", IPT_CHAIN, "-d", target, "-j", "DROP"])?;
            info!(target, tool = opt, "iptables drop rule added");
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
                NetTarget::Ip(IpAddr::V4(a)) => ("ip", a.to_string()),
                NetTarget::Ip(IpAddr::V6(a)) => ("ip6", a.to_string()),
                NetTarget::Cidr(IpNet::V4(n)) => ("ip", n.to_string()),
                NetTarget::Cidr(IpNet::V6(n)) => ("ip6", n.to_string()),
            };
            // nft doesn't support delete-by-criteria; we look up handles.
            let listing = run_output(
                "nft",
                &["-a", "list", "chain", NFT_FAMILY, NFT_TABLE, NFT_BLOCK],
            );
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
                            run(
                                "nft",
                                &[
                                    "delete", "rule", NFT_FAMILY, NFT_TABLE, NFT_BLOCK, "handle",
                                    handle,
                                ],
                            )?;
                            removed += 1;
                        }
                    }
                }
            }
            if removed == 0 {
                warn!(target, "no matching nft rule to unblock");
            } else {
                info!(target, removed, "nft rules removed");
            }
            Ok(())
        }
        Backend::Iptables => {
            let opt = match parsed {
                NetTarget::Ip(IpAddr::V4(_)) | NetTarget::Cidr(IpNet::V4(_)) => "iptables",
                NetTarget::Ip(IpAddr::V6(_)) | NetTarget::Cidr(IpNet::V6(_)) => "ip6tables",
            };
            run(opt, &["-D", IPT_CHAIN, "-d", target, "-j", "DROP"])?;
            info!(target, tool = opt, "iptables drop rule removed");
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
            nft(&[
                "add",
                "rule",
                NFT_FAMILY,
                NFT_TABLE,
                NFT_ISOLATE,
                "meta",
                "oif",
                "lo",
                "accept",
            ])?;
            for ip in allowlist_ips {
                let (family, addr) = match ip {
                    IpAddr::V4(a) => ("ip", a.to_string()),
                    IpAddr::V6(a) => ("ip6", a.to_string()),
                };
                nft(&[
                    "add",
                    "rule",
                    NFT_FAMILY,
                    NFT_TABLE,
                    NFT_ISOLATE,
                    family,
                    "daddr",
                    &addr,
                    "accept",
                ])?;
            }
            nft(&[
                "add",
                "rule",
                NFT_FAMILY,
                NFT_TABLE,
                NFT_ISOLATE,
                "counter",
                "drop",
            ])?;
            info!(allow = allowlist_ips.len(), "host isolated (nft)");
            Ok(())
        }
        Backend::Iptables => {
            const ISOLATE_CHAIN: &str = "TRAPD_ISOLATE";
            for tool in ["iptables", "ip6tables"] {
                ensure_iptables_chain(tool, ISOLATE_CHAIN)?;
                run(tool, &["-F", ISOLATE_CHAIN])?;
                run(tool, &["-A", ISOLATE_CHAIN, "-o", "lo", "-j", "ACCEPT"])?;
                for ip in allowlist_ips {
                    if matches!(
                        (tool, ip),
                        ("iptables", IpAddr::V4(_)) | ("ip6tables", IpAddr::V6(_))
                    ) {
                        run(
                            tool,
                            &["-A", ISOLATE_CHAIN, "-d", &ip.to_string(), "-j", "ACCEPT"],
                        )?;
                    }
                }
                run(tool, &["-A", ISOLATE_CHAIN, "-j", "DROP"])?;
                if !run_output(tool, &["-C", "OUTPUT", "-j", ISOLATE_CHAIN]).ok() {
                    run(tool, &["-I", "OUTPUT", "1", "-j", ISOLATE_CHAIN])?;
                }
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
            let mut failures = Vec::new();
            for tool in ["iptables", "ip6tables"] {
                if let Err(e) = (|| -> Result<()> {
                    // Create an absent chain so repeated deisolation is safe;
                    // a missing executable/permission failure still fails closed.
                    ensure_iptables_chain(tool, ISOLATE_CHAIN)?;
                    while run_output(tool, &["-C", "OUTPUT", "-j", ISOLATE_CHAIN]).ok() {
                        run(tool, &["-D", "OUTPUT", "-j", ISOLATE_CHAIN])?;
                    }
                    run(tool, &["-F", ISOLATE_CHAIN])
                })() {
                    failures.push(format!("{tool}: {e:#}"));
                }
            }
            if !failures.is_empty() {
                bail!("deisolation failed: {}", failures.join("; "));
            }
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

fn ensure_iptables_chain(tool: &str, chain: &str) -> Result<()> {
    if run(tool, &["-N", chain]).is_err() {
        run(tool, &["-S", chain]).context("cannot create or inspect firewall chain")?;
    }
    Ok(())
}

fn run(bin: &str, args: &[&str]) -> Result<()> {
    #[cfg(test)]
    if let Some(ok) = tests::capture(bin, args) {
        return if ok {
            Ok(())
        } else {
            Err(anyhow!("mock firewall failure"))
        };
    }
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
    fn ok(&self) -> bool {
        self.status
    }
}

fn run_output(bin: &str, args: &[&str]) -> CapturedOutput {
    #[cfg(test)]
    if let Some(status) = tests::capture(bin, args) {
        return CapturedOutput {
            status,
            stdout: Vec::new(),
        };
    }
    match Command::new(bin).args(args).output() {
        Ok(o) => CapturedOutput {
            status: o.status.success(),
            stdout: o.stdout,
        },
        Err(_) => CapturedOutput {
            status: false,
            stdout: Vec::new(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    #[derive(Default)]
    struct Firewall {
        calls: Vec<(String, Vec<String>)>,
        fail_v6: bool,
        jumps: std::collections::HashSet<(String, String)>,
    }
    thread_local! { static FIREWALL: RefCell<Option<Firewall>> = const { RefCell::new(None) }; }
    pub(super) fn capture(bin: &str, args: &[&str]) -> Option<bool> {
        FIREWALL.with(|state| {
            state.borrow_mut().as_mut().map(|f| {
                f.calls
                    .push((bin.into(), args.iter().map(|s| s.to_string()).collect()));
                if f.fail_v6 && bin == "ip6tables" {
                    return false;
                }
                if args.get(1) == Some(&"OUTPUT") {
                    let key = (bin.to_string(), args.last().unwrap().to_string());
                    match args.first().copied() {
                        Some("-C") => return f.jumps.contains(&key),
                        Some("-I") => {
                            f.jumps.insert(key);
                        }
                        Some("-D") => {
                            f.jumps.remove(&key);
                        }
                        _ => {}
                    }
                }
                true
            })
        })
    }
    fn setup(fail_v6: bool) {
        FIREWALL.with(|f| {
            *f.borrow_mut() = Some(Firewall {
                fail_v6,
                ..Default::default()
            })
        });
    }
    fn called(bin: &str, args: &[&str]) -> bool {
        FIREWALL.with(|f| {
            f.borrow()
                .as_ref()
                .unwrap()
                .calls
                .iter()
                .any(|(b, a)| b == bin && a == args)
        })
    }
    #[test]
    fn iptables_isolates_both_families_and_preserves_allowlists() {
        setup(false);
        isolate(
            Backend::Iptables,
            &["192.0.2.1".parse().unwrap(), "2001:db8::1".parse().unwrap()],
        )
        .unwrap();
        assert!(called("ip6tables", &["-A", "TRAPD_ISOLATE", "-j", "DROP"]));
        assert!(called(
            "ip6tables",
            &["-A", "TRAPD_ISOLATE", "-d", "2001:db8::1", "-j", "ACCEPT"]
        ));
        assert!(called(
            "iptables",
            &["-A", "TRAPD_ISOLATE", "-d", "192.0.2.1", "-j", "ACCEPT"]
        ));
    }
    #[test]
    fn iptables_chain_setup_and_deisolation_cover_ipv6() {
        setup(false);
        ensure_chains(Backend::Iptables).unwrap();
        assert!(called("ip6tables", &["-N", "TRAPD_BLOCK"]));
        isolate(Backend::Iptables, &[]).unwrap();
        deisolate(Backend::Iptables).unwrap();
        assert!(called(
            "ip6tables",
            &["-D", "OUTPUT", "-j", "TRAPD_ISOLATE"]
        ));
        assert!(called("iptables", &["-D", "OUTPUT", "-j", "TRAPD_ISOLATE"]));
        assert!(called("ip6tables", &["-F", "TRAPD_ISOLATE"]));
    }
    #[test]
    fn ipv6_failure_is_not_successful_isolation_or_deisolation() {
        setup(true);
        assert!(isolate(Backend::Iptables, &[]).is_err());
        assert!(deisolate(Backend::Iptables).is_err());
    }
    #[test]
    fn ipv6_block_and_unblock_use_attached_ipv6_chain() {
        setup(false);
        block_ip(Backend::Iptables, "2001:db8::2").unwrap();
        assert!(called(
            "ip6tables",
            &["-I", "OUTPUT", "1", "-j", "TRAPD_BLOCK"]
        ));
        unblock_ip(Backend::Iptables, "2001:db8::2").unwrap();
        assert!(called(
            "ip6tables",
            &["-D", "TRAPD_BLOCK", "-d", "2001:db8::2", "-j", "DROP"]
        ));
    }
}
