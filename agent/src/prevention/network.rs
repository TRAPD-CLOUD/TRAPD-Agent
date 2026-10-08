//! Network containment via `nft` (preferred) or `iptables` (fallback) on Linux
//! and Windows Defender Firewall (`netsh advfirewall`) on Windows.
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
//!
//! The Windows backend builds explicit block rules only (see [`super::netsh`]):
//! it never rewrites the firewall profile defaults, so a GPO-managed policy is
//! neither overridden nor left in a half-restored state if the agent dies.

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
    #[cfg(windows)]
    WindowsFirewall,
    None,
}

#[cfg(windows)]
pub fn detect_backend() -> Backend {
    if win::netsh_path().is_file() {
        Backend::WindowsFirewall
    } else {
        Backend::None
    }
}

#[cfg(not(windows))]
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
        #[cfg(windows)]
        Backend::WindowsFirewall => win::ensure_enforcing(),
        Backend::None => bail!("no firewall backend available (need nft, iptables or netsh)"),
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
        #[cfg(windows)]
        Backend::WindowsFirewall => win::block(&parsed, target),
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
        #[cfg(windows)]
        Backend::WindowsFirewall => win::unblock(target),
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
        #[cfg(windows)]
        Backend::WindowsFirewall => win::isolate(allowlist_ips),
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
        #[cfg(windows)]
        Backend::WindowsFirewall => win::deisolate(),
        Backend::None => bail!("no firewall backend"),
    }
}

#[cfg(windows)]
mod win {
    //! `netsh advfirewall` execution. The rule construction is in
    //! [`super::super::netsh`]; this module only runs it and reads the
    //! language-independent firewall state from the registry.

    use std::path::PathBuf;

    use anyhow::{anyhow, bail, Context, Result};
    use windows_sys::Win32::System::Registry::RRF_SUBKEY_WOW6464KEY;

    use super::super::netsh::{self, Direction};
    use super::{info, warn, IpAddr, NetTarget};
    use crate::collectors::windows::registry;

    use super::super::netsh::{
        FIREWALL_LOCAL_PROFILES, FIREWALL_POLICY_PROFILES, FIREWALL_PROFILES,
    };

    /// Absolute path, so a poisoned `PATH` can never substitute the binary the
    /// SYSTEM service executes.
    pub(super) fn netsh_path() -> PathBuf {
        let root = std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into());
        PathBuf::from(root).join("System32").join("netsh.exe")
    }

    fn run_netsh(args: &[String]) -> Result<()> {
        let out = std::process::Command::new(netsh_path())
            .args(args)
            .output()
            .context("failed to spawn netsh")?;
        if !out.status.success() {
            // netsh reports errors on stdout, localised; keep it for the audit
            // trail but never parse it.
            bail!(
                "netsh {} exited {}: {}",
                args.get(2).map(String::as_str).unwrap_or(""),
                out.status,
                String::from_utf8_lossy(&out.stdout).trim()
            );
        }
        Ok(())
    }

    fn rule_exists(name: &str) -> bool {
        std::process::Command::new(netsh_path())
            .args(netsh::show_rule_args(name))
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    /// Delete `name` if present. Absence is success (idempotent); a failed
    /// delete of an existing rule is an error, so a rule is never left behind
    /// while reporting success.
    fn delete_if_present(name: &str) -> Result<bool> {
        if !rule_exists(name) {
            return Ok(false);
        }
        run_netsh(&netsh::delete_rule_args(name))?;
        Ok(true)
    }

    /// Fail unless at least one firewall profile is actually enforcing: block
    /// rules on a disabled firewall would be reported as success while
    /// containing nothing.
    pub(super) fn ensure_enforcing() -> Result<()> {
        let enforcing = FIREWALL_PROFILES.iter().any(|profile| {
            let policy = registry::dword(
                &format!("{FIREWALL_POLICY_PROFILES}\\{profile}"),
                "EnableFirewall",
                RRF_SUBKEY_WOW6464KEY,
            );
            let local = registry::dword(
                &format!("{FIREWALL_LOCAL_PROFILES}\\{profile}"),
                "EnableFirewall",
                RRF_SUBKEY_WOW6464KEY,
            );
            netsh::profile_enforcing(policy, local)
        });
        if !enforcing {
            bail!("Windows Defender Firewall is disabled on every profile; block rules would not be enforced");
        }
        Ok(())
    }

    pub(super) fn block(parsed: &NetTarget, target: &str) -> Result<String> {
        ensure_enforcing()?;
        let net = match parsed {
            NetTarget::Ip(ip) => ipnet::IpNet::from(*ip),
            NetTarget::Cidr(n) => *n,
        };
        let remote = netsh::remote_for(&net);
        for dir in [Direction::Out, Direction::In] {
            let name = netsh::block_rule_name(target, dir);
            // Re-adding an existing block must not stack duplicates.
            delete_if_present(&name)?;
            run_netsh(&netsh::add_block_args(
                &name,
                dir,
                &remote,
                "TRAPD containment: blocked indicator",
            ))
            .inspect_err(|_| {
                // Never leave a half-installed pair behind.
                let _ = delete_if_present(&netsh::block_rule_name(target, Direction::Out));
            })?;
        }
        info!(target, "windows firewall block rules added");
        Ok(format!("netsh:{target}"))
    }

    pub(super) fn unblock(target: &str) -> Result<()> {
        let mut removed = 0;
        let mut failures = Vec::new();
        for dir in [Direction::Out, Direction::In] {
            match delete_if_present(&netsh::block_rule_name(target, dir)) {
                Ok(true) => removed += 1,
                Ok(false) => {}
                Err(e) => failures.push(format!("{e:#}")),
            }
        }
        if !failures.is_empty() {
            bail!("unblock failed: {}", failures.join("; "));
        }
        if removed == 0 {
            warn!(target, "no matching windows firewall rule to unblock");
        } else {
            info!(target, removed, "windows firewall rules removed");
        }
        Ok(())
    }

    pub(super) fn isolate(allow: &[IpAddr]) -> Result<()> {
        ensure_enforcing()?;
        let ranges = netsh::complement_ranges(allow).join(",");
        // Replace, never stack: re-isolating with a new allow-list swaps the set.
        for (name, dir) in [
            (netsh::ISOLATE_OUT, Direction::Out),
            (netsh::ISOLATE_IN, Direction::In),
        ] {
            delete_if_present(name)?;
            if let Err(e) = run_netsh(&netsh::add_block_args(
                name,
                dir,
                &ranges,
                "TRAPD containment: host isolated",
            )) {
                // Fail closed on the *rules*, open on connectivity: a partial
                // isolation is reported as failure and rolled back so the
                // operator is never told a half-contained host is contained.
                let _ = deisolate();
                return Err(anyhow!("isolation rule {name} failed: {e:#}"));
            }
        }
        info!(allow = allow.len(), "host isolated (windows firewall)");
        Ok(())
    }

    pub(super) fn deisolate() -> Result<()> {
        let mut failures = Vec::new();
        for name in [netsh::ISOLATE_OUT, netsh::ISOLATE_IN] {
            if let Err(e) = delete_if_present(name) {
                failures.push(format!("{name}: {e:#}"));
            }
        }
        if !failures.is_empty() {
            bail!("deisolation failed: {}", failures.join("; "));
        }
        info!("host isolation lifted (windows firewall)");
        Ok(())
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

/// Native Windows Firewall acceptance. Ignored by default: it changes the host's
/// firewall rule set (briefly) and needs an elevated token, so CI runs it as an
/// explicit step. It never enables a rule that could cut the runner's own
/// connectivity: rules are created disabled.
#[cfg(all(test, windows))]
mod windows_native {
    use super::super::netsh;
    use std::process::Command;

    fn exists(name: &str) -> bool {
        Command::new(super::win::netsh_path())
            .args(netsh::show_rule_args(name))
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    #[test]
    #[ignore = "modifies Windows Firewall rules; run explicitly on an elevated CI host"]
    fn native_netsh_accepts_the_generated_rule_syntax_and_deletes_it_again() {
        let allow: Vec<std::net::IpAddr> = vec![
            "192.0.2.10".parse().unwrap(),
            "2001:db8::1".parse().unwrap(),
        ];
        let ranges = netsh::complement_ranges(&allow).join(",");
        let name = "TRAPD-NATIVE-TEST-ISOLATE";
        let _ = Command::new(super::win::netsh_path())
            .args(netsh::delete_rule_args(name))
            .output();

        let mut args = netsh::add_block_args(
            name,
            netsh::Direction::Out,
            &ranges,
            "TRAPD native test - disabled",
        );
        // Never enforce: this only proves the syntax (a long mixed v4/v6 range
        // list) is accepted by the real netsh.
        for a in &mut args {
            if a == "enable=yes" {
                *a = "enable=no".into();
            }
        }
        let out = Command::new(super::win::netsh_path())
            .args(&args)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "netsh rejected the rule: {}",
            String::from_utf8_lossy(&out.stdout)
        );
        assert!(exists(name), "rule must exist after add");

        let out = Command::new(super::win::netsh_path())
            .args(netsh::delete_rule_args(name))
            .output()
            .unwrap();
        assert!(out.status.success());
        assert!(!exists(name), "rule must be gone after delete");
    }

    #[test]
    #[ignore = "modifies Windows Firewall rules; run explicitly on an elevated CI host"]
    fn native_block_and_unblock_an_unroutable_test_address() {
        use super::{block_ip, detect_backend, unblock_ip, Backend};
        let backend = detect_backend();
        assert!(matches!(backend, Backend::WindowsFirewall));
        // 203.0.113.0/24 is TEST-NET-3 (RFC 5737): never routed, safe to block.
        let target = "203.0.113.77";
        block_ip(backend, target).expect("block");
        assert!(exists(&netsh::block_rule_name(
            target,
            netsh::Direction::Out
        )));
        assert!(exists(&netsh::block_rule_name(
            target,
            netsh::Direction::In
        )));
        // Adding the same block again must replace, not stack, the rule.
        block_ip(backend, target).expect("re-block");
        unblock_ip(backend, target).expect("unblock");
        assert!(!exists(&netsh::block_rule_name(
            target,
            netsh::Direction::Out
        )));
        assert!(!exists(&netsh::block_rule_name(
            target,
            netsh::Direction::In
        )));
        // Unblocking something that is not blocked is a no-op, not an error.
        unblock_ip(backend, target).expect("idempotent unblock");
    }
}
