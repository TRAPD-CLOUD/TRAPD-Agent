//! Network containment via `nft` (preferred) or `iptables` (fallback) on Linux
//! and Windows Defender Firewall (native COM API) on Windows.
//!
//! The agent owns a dedicated table/chain so its rules can be inspected,
//! audited and torn down without touching operator-managed policy:
//!
//!   - nftables: table `inet trapd`, outbound IP block chain plus atomic
//!     input/output/forward isolation chains.
//!   - iptables: outbound IP blocking only. Full isolation requires nftables
//!     because separate IPv4/IPv6 commits cannot preserve the policy atomically.
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
//! The Windows backend builds explicit block rules only (see [`super::firewall`]):
//! it never rewrites the firewall profile defaults, so a GPO-managed policy is
//! neither overridden nor left in a half-restored state if the agent dies.

use std::net::IpAddr;
#[cfg(target_os = "linux")]
use std::process::Command;
use std::sync::Mutex;

use anyhow::{anyhow, bail, Context, Result};
use ipnet::IpNet;
use tracing::{debug, warn};

const NFT_TABLE: &str = "trapd";
const NFT_FAMILY: &str = "inet";
const NFT_BLOCK: &str = "block";
const NFT_ISOLATE: &str = "isolate_allow";
const IPT_CHAIN: &str = "TRAPD_BLOCK";
const MAX_ISOLATION_PEERS: usize = 256;
const MAX_FIREWALL_SCRIPT: usize = 128 * 1024;
const NFT_ISOLATION: [(&str, &str); 3] = [
    ("input", "isolate_input"),
    ("output", NFT_ISOLATE),
    ("forward", "isolate_forward"),
];
// Serialize every mutation, including handle lookup/deletion and TTL changes
// made by the engine. External firewall managers still own their rules.
static NETWORK_MUTATION: Mutex<()> = Mutex::new(());

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
    if super::winfirewall::Firewall::open().is_ok() {
        Backend::WindowsFirewall
    } else {
        Backend::None
    }
}

#[cfg(not(windows))]
pub fn detect_backend() -> Backend {
    if run_output("nft", &["--version"]).ok() {
        Backend::Nft
    } else if run_output("iptables", &["--version"]).ok() {
        Backend::Iptables
    } else {
        Backend::None
    }
}

/// Initialise the agent's own table/chain.  Idempotent.
pub fn ensure_chains(backend: Backend) -> Result<()> {
    let _guard = NETWORK_MUTATION
        .lock()
        .map_err(|_| anyhow!("network mutation lock poisoned"))?;
    match backend {
        Backend::Nft => run_stdin("nft", &["-f", "-"], &nft_chains()),
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
        Backend::WindowsFirewall => super::winfirewall::ensure_enforcing(),
        Backend::None => {
            bail!("no firewall backend available (need nft, iptables or Windows Firewall)")
        }
    }
}

/// Add a deny rule for `target`.
pub fn block_ip(backend: Backend, target: &str) -> Result<String> {
    let _guard = NETWORK_MUTATION
        .lock()
        .map_err(|_| anyhow!("network mutation lock poisoned"))?;
    let target = canonical_target(target)?;
    #[cfg(windows)]
    let parsed = parse_ip_or_cidr(&target)?;
    match backend {
        Backend::Nft => {
            let family = if target.contains(':') { "ip6" } else { "ip" };
            let listing = run_output(
                "nft",
                &["-a", "list", "chain", NFT_FAMILY, NFT_TABLE, NFT_BLOCK],
            );
            if !listing.ok() {
                bail!("cannot inspect nft block chain");
            }
            if nft_block_handles(&listing.stdout, &target)?.is_empty() {
                nft(&[
                    "add", "rule", NFT_FAMILY, NFT_TABLE, NFT_BLOCK, family, "daddr", &target,
                    "counter", "drop",
                ])?;
            }
            Ok(format!("nft:{family}:{target}"))
        }
        Backend::Iptables => {
            let tool = if target.contains(':') {
                "ip6tables"
            } else {
                "iptables"
            };
            ensure_iptables_chain(tool, IPT_CHAIN)?;
            if !run_output(tool, &["-C", "OUTPUT", "-j", IPT_CHAIN]).ok() {
                run(tool, &["-I", "OUTPUT", "1", "-j", IPT_CHAIN])?;
            }
            if iptables_block_count(tool, &target)? == 0 {
                run(tool, &["-A", IPT_CHAIN, "-d", &target, "-j", "DROP"])?;
            }
            Ok(format!("{tool}:{target}"))
        }
        #[cfg(windows)]
        Backend::WindowsFirewall => super::winfirewall::block(&parsed.as_net()),
        Backend::None => bail!("no firewall backend"),
    }
}

/// One stable target for registry keys, firewall rules and host/CIDR aliases.
pub(super) fn canonical_target(target: &str) -> Result<String> {
    let net = match parse_ip_or_cidr(target)? {
        NetTarget::Ip(ip) => IpNet::from(ip),
        NetTarget::Cidr(net) => net.trunc(),
    };
    Ok(
        if net.prefix_len() == if net.addr().is_ipv4() { 32 } else { 128 } {
            net.addr().to_string()
        } else {
            net.to_string()
        },
    )
}

fn nft_block_handles(listing: &[u8], target: &str) -> Result<Vec<String>> {
    let text = std::str::from_utf8(listing).context("invalid nft block listing")?;
    let mut handles = Vec::new();
    for line in text.lines() {
        let words: Vec<_> = line.split_whitespace().collect();
        let Some(index) = words.iter().position(|word| *word == "daddr") else {
            continue;
        };
        if !words.contains(&"drop")
            || words
                .get(index + 1)
                .and_then(|s| canonical_target(s).ok())
                .as_deref()
                != Some(target)
        {
            continue;
        }
        let index = words
            .iter()
            .position(|word| *word == "handle")
            .context("nft block has no handle")?;
        let handle = words
            .get(index + 1)
            .context("nft block has no handle value")?;
        handle.parse::<u64>().context("invalid nft block handle")?;
        handles.push(handle.to_string());
        if handles.len() > 4096 {
            bail!("too many duplicate nft block rules");
        }
    }
    Ok(handles)
}

fn iptables_block_count(tool: &str, target: &str) -> Result<usize> {
    let listing = run_output(tool, &["-S", IPT_CHAIN]);
    if !listing.ok() {
        bail!("cannot inspect {tool} block chain");
    }
    let text = std::str::from_utf8(&listing.stdout).context("invalid iptables block listing")?;
    let count = text
        .lines()
        .filter(|line| {
            let words: Vec<_> = line.split_whitespace().collect();
            words.len() == 6
                && words[0] == "-A"
                && words[1] == IPT_CHAIN
                && words[2] == "-d"
                && words[4] == "-j"
                && words[5] == "DROP"
                && canonical_target(words[3]).ok().as_deref() == Some(target)
        })
        .count();
    if count > 4096 {
        bail!("too many duplicate iptables block rules");
    }
    Ok(count)
}

/// Windows rules carry their deadline durably; other backends retain the
/// existing engine timer behavior.
pub fn block_ip_with_ttl(
    backend: Backend,
    target: &str,
    ttl: Option<u64>,
    command_id: &str,
) -> Result<String> {
    #[cfg(windows)]
    if matches!(backend, Backend::WindowsFirewall) {
        return super::winfirewall::block_with_ttl(
            &parse_ip_or_cidr(target)?.as_net(),
            ttl,
            command_id,
        );
    }
    #[cfg(not(windows))]
    let _ = (ttl, command_id);
    block_ip(backend, target)
}

#[cfg(windows)]
pub(super) fn canonical_windows_target(target: &str) -> Result<String> {
    Ok(super::firewall::remote_for(
        &parse_ip_or_cidr(target)?.as_net().trunc(),
    ))
}

pub fn unblock_ip(backend: Backend, target: &str) -> Result<()> {
    let _guard = NETWORK_MUTATION
        .lock()
        .map_err(|_| anyhow!("network mutation lock poisoned"))?;
    let target = canonical_target(target)?;
    match backend {
        Backend::Nft => {
            let listing = run_output(
                "nft",
                &["-a", "list", "chain", NFT_FAMILY, NFT_TABLE, NFT_BLOCK],
            );
            if !listing.ok() {
                bail!("cannot inspect nft block chain");
            }
            let handles = nft_block_handles(&listing.stdout, &target)?;
            // One nft transaction removes every historical duplicate without
            // partially deleting a block if an intermediate deletion fails.
            if !handles.is_empty() {
                let script = handles
                    .into_iter()
                    .map(|handle| {
                        format!(
                            "delete rule {NFT_FAMILY} {NFT_TABLE} {NFT_BLOCK} handle {handle}\n"
                        )
                    })
                    .collect::<String>();
                run_stdin("nft", &["-f", "-"], &script)?;
            }
            Ok(())
        }
        Backend::Iptables => {
            let tool = if target.contains(':') {
                "ip6tables"
            } else {
                "iptables"
            };
            for _ in 0..iptables_block_count(tool, &target)? {
                run(tool, &["-D", IPT_CHAIN, "-d", &target, "-j", "DROP"])?;
            }
            Ok(())
        }
        #[cfg(windows)]
        Backend::WindowsFirewall => {
            super::winfirewall::unblock(&parse_ip_or_cidr(&target)?.as_net())
        }
        Backend::None => bail!("no firewall backend"),
    }
}

/// Apply full host isolation: deny everything except the management
/// channel and an explicit allow-list (loopback is always included).
pub fn isolate(backend: Backend, allowlist_ips: &[IpAddr]) -> Result<()> {
    if matches!(backend, Backend::Nft) && allowlist_ips.len() > MAX_ISOLATION_PEERS {
        bail!("isolation allowlist exceeds {MAX_ISOLATION_PEERS} addresses");
    }
    let _guard = NETWORK_MUTATION
        .lock()
        .map_err(|_| anyhow!("network mutation lock poisoned"))?;
    match backend {
        Backend::Nft => run_stdin("nft", &["-f", "-"], &nft_isolation(Some(allowlist_ips))),
        Backend::Iptables => bail!("full host isolation requires nftables: install nft and restart the agent; legacy iptables supports IP blocking only"),
        #[cfg(windows)]
        Backend::WindowsFirewall => super::winfirewall::isolate(allowlist_ips),
        Backend::None => bail!("no firewall backend"),
    }
}

pub fn deisolate(backend: Backend) -> Result<()> {
    let _guard = NETWORK_MUTATION
        .lock()
        .map_err(|_| anyhow!("network mutation lock poisoned"))?;
    match backend {
        Backend::Nft => run_stdin("nft", &["-f", "-"], &nft_isolation(None)),
        Backend::Iptables => bail!("full host isolation release requires nftables: install nft and restart the agent; existing legacy isolation must be removed using the documented local migration procedure"),
        #[cfg(windows)]
        Backend::WindowsFirewall => super::winfirewall::deisolate(),
        Backend::None => bail!("no firewall backend"),
    }
}

fn nft_chains() -> String {
    // 'add' is idempotent (unlike 'create') and does not flush existing rules.
    let mut rules = format!("add table {NFT_FAMILY} {NFT_TABLE}\nadd chain {NFT_FAMILY} {NFT_TABLE} {NFT_BLOCK} {{ type filter hook output priority -200; }}\n");
    for (hook, chain) in NFT_ISOLATION {
        rules.push_str(&format!("add chain {NFT_FAMILY} {NFT_TABLE} {chain} {{ type filter hook {hook} priority -150; policy accept; }}\n"));
    }
    rules
}

fn nft_isolation(allow: Option<&[IpAddr]>) -> String {
    let mut rules = nft_chains();
    for (hook, chain) in NFT_ISOLATION {
        let prefix = format!("add rule {NFT_FAMILY} {NFT_TABLE} {chain}");
        rules.push_str(&format!("flush chain {NFT_FAMILY} {NFT_TABLE} {chain}\n"));
        if let Some(ips) = allow {
            if hook != "forward" {
                let interface = if hook == "input" {
                    "iifname"
                } else {
                    "oifname"
                };
                rules.push_str(&format!("{prefix} {interface} \"lo\" accept\n"));
                // Neighbor discovery is link-local control traffic required to
                // reach IPv6 management peers. No other ICMP or general
                // established-connection exception survives isolation.
                let types = if hook == "input" {
                    "134, 135, 136"
                } else {
                    "133, 135, 136"
                };
                rules.push_str(&format!(
                    "{prefix} ip6 hoplimit 255 icmpv6 type {{ {types} }} accept\n"
                ));
                for ip in ips {
                    let family = if ip.is_ipv4() { "ip" } else { "ip6" };
                    let match_peer = if hook == "input" {
                        format!("saddr {ip} ct state established,related")
                    } else {
                        format!("daddr {ip}")
                    };
                    rules.push_str(&format!("{prefix} {family} {match_peer} accept\n"));
                }
            }
            rules.push_str(&format!("{prefix} counter drop\n"));
        }
    }
    rules
}

fn run_stdin(bin: &str, args: &[&str], input: &str) -> Result<()> {
    if input.len() > MAX_FIREWALL_SCRIPT {
        bail!("firewall transaction exceeds {MAX_FIREWALL_SCRIPT} bytes");
    }
    #[cfg(test)]
    if let Some(ok) = tests::capture_batch(bin, args, input) {
        return if ok {
            Ok(())
        } else {
            bail!("mock firewall transaction failure")
        };
    }
    #[cfg(target_os = "linux")]
    return run_firewall_process(bin, args, input, std::time::Duration::from_secs(10));
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (bin, args);
        bail!("nftables containment requires Linux");
    }
}

#[cfg(target_os = "linux")]
fn run_firewall_process(
    bin: &str,
    args: &[&str],
    input: &str,
    timeout: std::time::Duration,
) -> Result<()> {
    let (output, diagnostic) = capture_firewall_process(bin, args, input, timeout)?;
    if !output.ok() {
        bail!("{bin} transaction failed: {diagnostic}");
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn capture_firewall_process(
    bin: &str,
    args: &[&str],
    input: &str,
    timeout: std::time::Duration,
) -> Result<(CapturedOutput, String)> {
    use std::io::{ErrorKind, Read, Write};
    use std::os::fd::AsRawFd;
    use std::os::unix::process::CommandExt;
    use std::process::Stdio;
    use std::time::{Duration, Instant};

    fn read_available(pipe: &mut impl Read, data: &mut Vec<u8>, limit: usize) -> Result<bool> {
        // Bound work per loop so a noisy child cannot starve the deadline.
        for _ in 0..3 {
            let mut buffer = [0_u8; 4096];
            match pipe.read(&mut buffer) {
                Ok(0) => return Ok(true),
                Ok(count) => {
                    if data.len() + count > limit {
                        bail!(
                            "firewall output exceeded {limit} bytes; outcome requires inspection"
                        );
                    }
                    data.extend_from_slice(&buffer[..count]);
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => return Ok(false),
                Err(error) if error.kind() == ErrorKind::Interrupted => continue,
                Err(error) => return Err(error).context("firewall output read failed"),
            }
        }
        Ok(false)
    }

    if input.len() > MAX_FIREWALL_SCRIPT {
        bail!("firewall input exceeds limit");
    }
    let mut child = Command::new(bin)
        .args(args)
        .process_group(0)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("failed to spawn {bin}"))?;
    // Do not reap the leader before both pipes close: its PID reserves the
    // process-group ID while descendants may hold the inherited pipes open.
    let group = child.id() as libc::pid_t;
    let mut reaped = false;
    let result = (|| -> Result<(CapturedOutput, String)> {
        let mut stdin = Some(child.stdin.take().context("firewall stdin unavailable")?);
        let mut stdout = child.stdout.take().context("firewall stdout unavailable")?;
        let mut stderr = child.stderr.take().context("firewall stderr unavailable")?;
        for fd in [
            stdin.as_ref().unwrap().as_raw_fd(),
            stdout.as_raw_fd(),
            stderr.as_raw_fd(),
        ] {
            // SAFETY: these are live owned pipe descriptors. fcntl changes only
            // status flags and does not transfer ownership.
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
            if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
            {
                return Err(std::io::Error::last_os_error())
                    .context("cannot configure firewall pipes");
            }
        }
        let deadline = Instant::now() + timeout;
        let mut written = 0;
        let mut output = Vec::new();
        let mut diagnostic = Vec::new();
        loop {
            if let Some(pipe) = stdin.as_mut() {
                match pipe.write(&input.as_bytes()[written..]) {
                    Ok(count) => written += count,
                    Err(error)
                        if matches!(
                            error.kind(),
                            ErrorKind::WouldBlock | ErrorKind::Interrupted
                        ) => {}
                    Err(error) => return Err(error).context("firewall transaction input failed"),
                }
                if written == input.len() {
                    stdin.take();
                }
            }
            let output_closed = read_available(&mut stdout, &mut output, 1024 * 1024)?;
            let diagnostic_closed = read_available(&mut stderr, &mut diagnostic, 8192)?;
            if output_closed && diagnostic_closed {
                if let Some(status) = child
                    .try_wait()
                    .context("firewall transaction wait failed")?
                {
                    reaped = true;
                    if status.success() && written != input.len() {
                        bail!("{bin} exited before reading the complete transaction");
                    }
                    return Ok((
                        CapturedOutput {
                            status: status.success(),
                            stdout: output,
                        },
                        String::from_utf8_lossy(&diagnostic).trim().into(),
                    ));
                }
            }
            if Instant::now() >= deadline {
                bail!("{bin} transaction timed out; firewall outcome requires inspection before retry");
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    })();
    if !reaped {
        // SAFETY: a positive, unreaped child PID is the dedicated group ID set
        // by process_group(0). Kill descendants before reaping the leader.
        unsafe {
            libc::kill(-group, libc::SIGKILL);
        }
        let _ = child.kill();
        let _ = child.wait();
    }
    result
}

enum NetTarget {
    Ip(IpAddr),
    Cidr(IpNet),
}

#[cfg(windows)]
impl NetTarget {
    fn as_net(&self) -> IpNet {
        match self {
            Self::Ip(ip) => IpNet::from(*ip),
            Self::Cidr(net) => *net,
        }
    }
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
    #[cfg(target_os = "linux")]
    return run_firewall_process(bin, args, "", std::time::Duration::from_secs(10));
    #[cfg(not(target_os = "linux"))]
    bail!("Linux firewall backend is unavailable on this operating system");
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
    #[cfg(not(target_os = "linux"))]
    let _ = (bin, args);
    #[cfg(test)]
    if let Some(output) = tests::capture_output(bin, args) {
        return output;
    }
    #[cfg(target_os = "linux")]
    match capture_firewall_process(bin, args, "", std::time::Duration::from_secs(10)) {
        Ok((output, _)) => return output,
        Err(error) => warn!(bin, error = %error, "firewall inspection failed"),
    }
    CapturedOutput {
        status: false,
        stdout: Vec::new(),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::cell::RefCell;

    #[derive(Default)]
    struct Firewall {
        calls: Vec<(String, Vec<String>)>,
        batches: Vec<(String, String)>,
        fail_v6: bool,
        fail_nft: bool,
        nft_policy: String,
        jumps: std::collections::HashSet<(String, String)>,
        blocks: Vec<(String, String)>,
        nft_blocks: std::collections::BTreeMap<u64, String>,
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
                if args.get(1) == Some(&IPT_CHAIN) && args.last() == Some(&"DROP") {
                    let target = args.get(3).unwrap().to_string();
                    let key = (bin.to_string(), target);
                    match args.first().copied() {
                        Some("-C") => return f.blocks.contains(&key),
                        Some("-A") => f.blocks.push(key),
                        Some("-D") => {
                            let Some(index) = f.blocks.iter().position(|rule| rule == &key) else {
                                return false;
                            };
                            f.blocks.remove(index);
                        }
                        _ => {}
                    }
                }
                if bin == "nft" && args.first() == Some(&"add") && args.get(4) == Some(&NFT_BLOCK) {
                    let index = args.iter().position(|a| *a == "daddr").unwrap();
                    let handle = f.nft_blocks.keys().next_back().copied().unwrap_or(0) + 1;
                    f.nft_blocks.insert(
                        handle,
                        format!(
                            "{} daddr {} counter drop # handle {handle}",
                            args[index - 1],
                            args[index + 1]
                        ),
                    );
                }
                if bin == "nft"
                    && args.first() == Some(&"delete")
                    && args.get(4) == Some(&NFT_BLOCK)
                {
                    let handle: u64 = args.last().unwrap().parse().unwrap();
                    f.nft_blocks.remove(&handle);
                }
                true
            })
        })
    }
    pub(super) fn capture_output(bin: &str, args: &[&str]) -> Option<CapturedOutput> {
        capture(bin, args).map(|status| CapturedOutput {
            status,
            stdout: FIREWALL.with(|f| {
                let f = f.borrow();
                let f = f.as_ref().unwrap();
                if bin == "nft" {
                    f.nft_blocks
                        .values()
                        .cloned()
                        .collect::<Vec<_>>()
                        .join("\n")
                        .into_bytes()
                } else if args == ["-S", IPT_CHAIN] {
                    f.blocks
                        .iter()
                        .filter(|(tool, _)| tool == bin)
                        .map(|(_, target)| format!("-A {IPT_CHAIN} -d {target} -j DROP"))
                        .collect::<Vec<_>>()
                        .join("\n")
                        .into_bytes()
                } else {
                    Vec::new()
                }
            }),
        })
    }
    pub(super) fn capture_batch(bin: &str, args: &[&str], input: &str) -> Option<bool> {
        FIREWALL.with(|state| {
            state.borrow_mut().as_mut().map(|f| {
                f.calls
                    .push((bin.into(), args.iter().map(|s| s.to_string()).collect()));
                f.batches.push((bin.into(), input.into()));
                if f.fail_nft {
                    return false;
                }
                for line in input
                    .lines()
                    .filter(|line| line.starts_with("delete rule inet trapd block handle "))
                {
                    let handle: u64 = line.split_whitespace().last().unwrap().parse().unwrap();
                    f.nft_blocks.remove(&handle);
                }
                if input.contains("flush chain") {
                    f.nft_policy = input.into();
                }
                true
            })
        })
    }
    pub(crate) fn setup(fail_v6: bool) {
        FIREWALL.with(|f| {
            *f.borrow_mut() = Some(Firewall {
                fail_v6,
                ..Default::default()
            })
        });
    }
    pub(crate) fn called(bin: &str, args: &[&str]) -> bool {
        FIREWALL.with(|f| {
            let f = f.borrow();
            let f = f.as_ref().unwrap();
            f.calls.iter().any(|(b, a)| b == bin && a == args)
                || f.batches.iter().any(|(b, input)| {
                    b == bin
                        && input
                            .lines()
                            .any(|line| line.split_whitespace().eq(args.iter().copied()))
                })
        })
    }
    pub(crate) fn no_calls() -> bool {
        FIREWALL.with(|f| f.borrow().as_ref().unwrap().calls.is_empty())
    }

    #[test]
    fn excessive_isolation_allowlist_is_rejected_before_process_spawn() {
        setup(false);
        let peers = vec!["192.0.2.1".parse().unwrap(); 257];
        assert!(isolate(Backend::Nft, &peers).is_err());
        assert!(no_calls());
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn firewall_process_diagnostics_are_bounded() {
        FIREWALL.with(|f| *f.borrow_mut() = None);
        let error =
            run_stdin("sh", &["-c", "head -c 32768 /dev/zero >&2; exit 1"], "").unwrap_err();
        assert!(
            error.to_string().len() < 9000,
            "diagnostics must be bounded"
        );
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn firewall_process_timeout_terminates_group_without_worker_threads() {
        let pid_path = std::env::temp_dir().join(format!(
            "trapd-firewall-child-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _pid_file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&pid_path)
            .unwrap();
        let start = std::time::Instant::now();
        let error = run_firewall_process(
            "sh",
            &[
                "-c",
                "sleep 30 & printf '%s' \"$!\" > \"$1\"; wait",
                "sh",
                pid_path.to_str().unwrap(),
            ],
            "",
            std::time::Duration::from_millis(250),
        )
        .unwrap_err();
        assert!(error.to_string().contains("timed out"));
        assert!(start.elapsed() < std::time::Duration::from_secs(2));
        let pid: i32 = std::fs::read_to_string(&pid_path).unwrap().parse().unwrap();
        let _ = std::fs::remove_file(pid_path);
        // Signal delivery to a descendant is asynchronous after the direct
        // child is reaped. Poll its observable process state briefly.
        let stopped_by = std::time::Instant::now() + std::time::Duration::from_millis(500);
        let running = loop {
            let running = std::fs::read_to_string(format!("/proc/{pid}/stat"))
                .map(|stat| !stat.rsplit_once(") ").unwrap().1.starts_with('Z'))
                .unwrap_or(false);
            if !running || std::time::Instant::now() >= stopped_by {
                break running;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        };
        // Clean up even if a future regression stops killing descendants.
        if running {
            unsafe {
                libc::kill(pid, libc::SIGKILL);
            }
        }
        assert!(
            !running,
            "timed-out firewall descendants must not keep running"
        );
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn firewall_process_transmits_full_script_and_reports_normal_exit() {
        run_firewall_process(
            "sh",
            &["-c", "test \"$(cat)\" = \"complete script\""],
            "complete script",
            std::time::Duration::from_secs(2),
        )
        .unwrap();
        assert!(run_firewall_process(
            "sh",
            &["-c", "cat >/dev/null; echo invalid >&2; exit 1"],
            "input",
            std::time::Duration::from_secs(2)
        )
        .is_err());
    }
    #[test]
    fn excessive_script_is_rejected_before_process_spawn() {
        setup(false);
        assert!(run_stdin("nft", &["-f", "-"], &"a".repeat(128 * 1024 + 1)).is_err());
        assert!(no_calls());
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn firewall_listing_rejects_excessive_stdout() {
        FIREWALL.with(|f| *f.borrow_mut() = None);
        assert!(!run_output("sh", &["-c", "head -c 1048577 /dev/zero"]).ok());
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn firewall_listing_reads_all_stdout_before_reporting_success() {
        FIREWALL.with(|f| *f.borrow_mut() = None);
        let output = run_output("sh", &["-c", "head -c 100000 /dev/zero"]);
        assert!(output.ok());
        assert_eq!(output.stdout.len(), 100000);
    }
    #[test]
    fn nft_isolation_is_one_dual_stack_transaction_for_all_directions() {
        setup(false);
        isolate(
            Backend::Nft,
            &["192.0.2.1".parse().unwrap(), "2001:db8::1".parse().unwrap()],
        )
        .unwrap();
        FIREWALL.with(|f| {
            let f = f.borrow();
            let f = f.as_ref().unwrap();
            assert_eq!(
                f.batches.len(),
                1,
                "isolation must use one atomic stdin batch"
            );
            assert_eq!(
                f.calls,
                [("nft".to_string(), vec!["-f".to_string(), "-".to_string()])]
            );
            let rules = &f.batches[0].1;
            for (hook, chain) in [
                ("input", "isolate_input"),
                ("output", "isolate_allow"),
                ("forward", "isolate_forward"),
            ] {
                assert!(rules.contains(&format!("hook {hook} ")), "missing {hook}");
                assert!(rules.contains(&format!("flush chain inet trapd {chain}\n")));
                assert!(rules.contains(&format!("add rule inet trapd {chain} counter drop\n")));
            }
            assert!(rules.contains("isolate_allow ip daddr 192.0.2.1 accept\n"));
            assert!(rules.contains("isolate_allow ip6 daddr 2001:db8::1 accept\n"));
            assert!(rules.contains(
                "isolate_input ip saddr 192.0.2.1 ct state established,related accept\n"
            ));
            assert!(rules.contains(
                "isolate_input ip6 saddr 2001:db8::1 ct state established,related accept\n"
            ));
            assert!(
                !rules.contains("isolate_forward ip"),
                "management must not authorize transit"
            );
            assert!(
                !rules.contains("flush table"),
                "IP blocks must survive isolation replacement"
            );
        });
    }
    #[test]
    fn nft_allows_loopback_and_link_local_neighbor_discovery_but_no_established_bypass() {
        setup(false);
        isolate(Backend::Nft, &[]).unwrap();
        FIREWALL.with(|f| {
            let f = f.borrow();
            let rules = &f.as_ref().unwrap().batches[0].1;
            assert!(rules.contains("isolate_input iifname \"lo\" accept\n"));
            assert!(rules.contains("isolate_allow oifname \"lo\" accept\n"));
            assert!(rules
                .contains("isolate_input ip6 hoplimit 255 icmpv6 type { 134, 135, 136 } accept\n"));
            assert!(rules
                .contains("isolate_allow ip6 hoplimit 255 icmpv6 type { 133, 135, 136 } accept\n"));
            assert!(!rules.contains("ct state"));
            assert!(!rules.contains("isolate_forward iifname"));
        });
    }
    #[test]
    fn nft_failure_and_reinitialization_never_clear_committed_policy() {
        setup(false);
        isolate(Backend::Nft, &["192.0.2.1".parse().unwrap()]).unwrap();
        let before = FIREWALL.with(|f| f.borrow().as_ref().unwrap().nft_policy.clone());
        ensure_chains(Backend::Nft).unwrap();
        ensure_chains(Backend::Nft).unwrap();
        FIREWALL.with(|f| {
            let mut f = f.borrow_mut();
            let f = f.as_mut().unwrap();
            assert!(f.batches[1..]
                .iter()
                .all(|(_, rules)| !rules.contains("flush")));
            f.fail_nft = true;
        });
        assert!(isolate(Backend::Nft, &[]).is_err());
        assert!(deisolate(Backend::Nft).is_err());
        FIREWALL.with(|f| assert_eq!(f.borrow().as_ref().unwrap().nft_policy, before));
    }
    #[test]
    fn nft_deisolation_clears_all_isolation_directions_in_one_transaction_only() {
        setup(false);
        deisolate(Backend::Nft).unwrap();
        FIREWALL.with(|f| {
            let f = f.borrow();
            let f = f.as_ref().unwrap();
            assert_eq!(f.batches.len(), 1);
            let rules = &f.batches[0].1;
            assert_eq!(
                rules
                    .lines()
                    .filter(|line| line.starts_with("flush chain"))
                    .count(),
                3
            );
            assert!(!rules.contains("add rule"));
            assert!(!rules.contains("flush chain inet trapd block"));
            assert!(!rules.contains("flush table"));
        });
    }
    #[test]
    fn legacy_full_isolation_and_release_reject_before_any_firewall_mutation() {
        setup(false);
        for result in [
            isolate(Backend::Iptables, &[]),
            deisolate(Backend::Iptables),
        ] {
            assert!(result
                .unwrap_err()
                .to_string()
                .contains("requires nftables"));
        }
        assert!(
            no_calls(),
            "unsupported operations must not leave partial policy"
        );
    }
    #[test]
    fn invalid_ip_never_reaches_firewall_tools() {
        setup(false);
        for input in [
            "192.0.2.1; drop",
            "--help",
            "192.0.2.1\nCOMMIT",
            "example.org",
        ] {
            assert!(block_ip(Backend::Iptables, input).is_err());
            assert!(unblock_ip(Backend::Nft, input).is_err());
        }
        assert!(no_calls());
    }
    #[test]
    fn iptables_block_setup_still_covers_ipv6_and_reports_failures() {
        setup(false);
        ensure_chains(Backend::Iptables).unwrap();
        assert!(called("ip6tables", &["-N", "TRAPD_BLOCK"]));
        setup(true);
        assert!(ensure_chains(Backend::Iptables).is_err());
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
    #[test]
    fn linux_ip_block_repeats_do_not_accumulate_duplicate_rules() {
        for backend in [Backend::Nft, Backend::Iptables] {
            setup(false);
            block_ip(backend, "192.0.2.123").unwrap();
            block_ip(backend, "192.0.2.123/32").unwrap();
            FIREWALL.with(|f| {
                let f = f.borrow();
                let f = f.as_ref().unwrap();
                assert_eq!(
                    f.blocks.len() + f.nft_blocks.len(),
                    1,
                    "repeated blocks must be idempotent across aliases"
                );
            });
        }
    }
    #[test]
    fn linux_unblock_removes_all_preexisting_duplicate_rules() {
        setup(false);
        FIREWALL.with(|f| {
            f.borrow_mut().as_mut().unwrap().blocks = vec![
                ("iptables".into(), "192.0.2.123".into()),
                ("iptables".into(), "192.0.2.123".into()),
                ("iptables".into(), "192.0.2.123".into()),
            ]
        });
        unblock_ip(Backend::Iptables, "192.0.2.123").unwrap();
        FIREWALL.with(|f| assert!(f.borrow().as_ref().unwrap().blocks.is_empty()));
    }
}
