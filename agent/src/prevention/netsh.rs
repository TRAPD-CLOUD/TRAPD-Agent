//! Windows Firewall containment: pure rule construction.
//!
//! Everything here is platform-neutral (no process spawning, no registry) so the
//! address arithmetic and the `netsh` argument vectors are unit-tested on every
//! CI platform; only `network.rs` executes them, and only on Windows.
//!
//! Design notes:
//!
//!   * Containment uses **explicit block rules only**. Windows Firewall lets a
//!     block rule override any allow rule, so "isolate" cannot be built as
//!     "allow list + default deny" without rewriting the profile defaults,
//!     which are GPO-managed on domain hosts and would be silently reverted.
//!     Instead isolation blocks the *complement* of the allow-list (see
//!     [`complement_ranges`]) — the same observable behaviour as the Linux
//!     nftables chain, with nothing of the operator's policy touched.
//!   * Every rule carries the [`GROUP`] so an operator can audit or remove the
//!     agent's rules in one step, and a fixed, space-free name so deletion never
//!     depends on `netsh` quoting.
//!   * Inputs are typed (`IpAddr` / `IpNet`) before they reach an argument, so no
//!     operator- or backend-supplied string is ever interpolated into a rule.

// Pure logic compiled everywhere so it is tested on every CI platform; only the
// Windows build calls it.
#![cfg_attr(not(windows), allow(dead_code))]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ipnet::IpNet;

/// Rule group shown in `wf.msc`; every rule the agent creates belongs to it.
pub const GROUP: &str = "TRAPD-Containment";
/// Fixed names of the two isolation rules (one per direction).
pub const ISOLATE_OUT: &str = "TRAPD-ISOLATE-OUT";
pub const ISOLATE_IN: &str = "TRAPD-ISOLATE-IN";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    In,
    Out,
}

impl Direction {
    fn as_str(self) -> &'static str {
        match self {
            Direction::In => "in",
            Direction::Out => "out",
        }
    }
}

/// Rule name for a surgical block of `target` in `dir`.
///
/// `target` must already be a validated IP or CIDR; the only characters that
/// can occur are hex digits, `.`, `:` and `/`, and the last is replaced so the
/// name is a single token on every `netsh` version.
pub fn block_rule_name(target: &str, dir: Direction) -> String {
    format!(
        "TRAPD-BLOCK-{}-{}",
        dir.as_str().to_ascii_uppercase(),
        target.replace('/', "_")
    )
}

/// `netsh` arguments creating one block rule.
pub fn add_block_args(name: &str, dir: Direction, remote: &str, description: &str) -> Vec<String> {
    vec![
        "advfirewall".into(),
        "firewall".into(),
        "add".into(),
        "rule".into(),
        format!("name={name}"),
        format!("dir={}", dir.as_str()),
        "action=block".into(),
        format!("remoteip={remote}"),
        "protocol=any".into(),
        "profile=any".into(),
        "enable=yes".into(),
        format!("group={GROUP}"),
        format!("description={description}"),
    ]
}

/// `netsh` arguments that exit 0 only if a rule with `name` exists.
pub fn show_rule_args(name: &str) -> Vec<String> {
    vec![
        "advfirewall".into(),
        "firewall".into(),
        "show".into(),
        "rule".into(),
        format!("name={name}"),
    ]
}

/// `netsh` arguments deleting every rule called `name`.
pub fn delete_rule_args(name: &str) -> Vec<String> {
    vec![
        "advfirewall".into(),
        "firewall".into(),
        "delete".into(),
        "rule".into(),
        format!("name={name}"),
    ]
}

/// Registry locations of the per-profile firewall switch: the local setting and
/// the group-policy override. Shared by containment (is the firewall actually
/// enforcing?) and the hardening inventory.
pub const FIREWALL_LOCAL_PROFILES: &str =
    "SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy";
pub const FIREWALL_POLICY_PROFILES: &str = "SOFTWARE\\Policies\\Microsoft\\WindowsFirewall";
pub const FIREWALL_PROFILES: [&str; 3] = ["DomainProfile", "StandardProfile", "PublicProfile"];

/// Whether one firewall profile enforces rules. Group policy wins over the
/// local setting; a profile with neither value set is on (the Windows default).
pub fn profile_enforcing(policy: Option<u32>, local: Option<u32>) -> bool {
    policy.or(local).map(|v| v != 0).unwrap_or(true)
}

/// Format a remote address for `remoteip=`: single host, CIDR, or `a-b` range.
pub fn remote_for(target: &IpNet) -> String {
    if target.prefix_len() == target.max_prefix_len() {
        target.addr().to_string()
    } else {
        target.to_string()
    }
}

/// Inclusive address ranges covering every address that is **not** in `keep`
/// and not loopback, as `netsh` `remoteip` tokens (`a-b`), IPv4 and IPv6.
///
/// Loopback stays reachable on purpose (local IPC, the agent's own loopback
/// services), matching the Linux `oif lo accept` rule.
pub fn complement_ranges(keep: &[IpAddr]) -> Vec<String> {
    let mut v4: Vec<(u32, u32)> = vec![(
        u32::from(Ipv4Addr::new(127, 0, 0, 0)),
        u32::from(Ipv4Addr::new(127, 255, 255, 255)),
    )];
    let mut v6: Vec<(u128, u128)> = vec![(1, 1)]; // ::1
    for ip in keep {
        match ip {
            IpAddr::V4(a) => v4.push((u32::from(*a), u32::from(*a))),
            IpAddr::V6(a) => v6.push((u128::from(*a), u128::from(*a))),
        }
    }
    let mut out = Vec::new();
    for (lo, hi) in gaps(v4, u32::MAX) {
        out.push(format!("{}-{}", Ipv4Addr::from(lo), Ipv4Addr::from(hi)));
    }
    for (lo, hi) in gaps(v6, u128::MAX) {
        out.push(format!("{}-{}", Ipv6Addr::from(lo), Ipv6Addr::from(hi)));
    }
    out
}

/// Gaps between the (sorted, merged) `used` inclusive intervals within
/// `0..=max`.
fn gaps<T>(mut used: Vec<(T, T)>, max: T) -> Vec<(T, T)>
where
    T: Copy + Ord + Bounded,
{
    used.sort();
    let mut merged: Vec<(T, T)> = Vec::new();
    for (lo, hi) in used {
        match merged.last_mut() {
            // Overlapping or directly adjacent: extend.
            Some(last) if lo <= last.1 || last.1.succ() == Some(lo) => {
                if hi > last.1 {
                    last.1 = hi;
                }
            }
            _ => merged.push((lo, hi)),
        }
    }
    let mut out = Vec::new();
    let mut next = Some(T::MIN);
    for (lo, hi) in merged {
        if let Some(n) = next {
            if n < lo {
                out.push((n, lo.pred().unwrap_or(n)));
            }
        }
        next = hi.succ();
    }
    if let Some(n) = next {
        if n <= max {
            out.push((n, max));
        }
    }
    out
}

/// Minimal integer abstraction so [`gaps`] serves both address families.
pub trait Bounded: Sized {
    const MIN: Self;
    fn succ(self) -> Option<Self>;
    fn pred(self) -> Option<Self>;
}

impl Bounded for u32 {
    const MIN: u32 = 0;
    fn succ(self) -> Option<u32> {
        self.checked_add(1)
    }
    fn pred(self) -> Option<u32> {
        self.checked_sub(1)
    }
}

impl Bounded for u128 {
    const MIN: u128 = 0;
    fn succ(self) -> Option<u128> {
        self.checked_add(1)
    }
    fn pred(self) -> Option<u128> {
        self.checked_sub(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn covers(ranges: &[String], ip: &str) -> bool {
        let ip: IpAddr = ip.parse().unwrap();
        ranges.iter().any(|r| {
            let (lo, hi) = r.split_once('-').unwrap();
            match ip {
                IpAddr::V4(a) => match (lo.parse::<Ipv4Addr>(), hi.parse::<Ipv4Addr>()) {
                    (Ok(lo), Ok(hi)) => lo <= a && a <= hi,
                    _ => false,
                },
                IpAddr::V6(a) => match (lo.parse::<Ipv6Addr>(), hi.parse::<Ipv6Addr>()) {
                    (Ok(lo), Ok(hi)) => lo <= a && a <= hi,
                    _ => false,
                },
            }
        })
    }

    #[test]
    fn isolation_blocks_the_world_but_not_the_allowlist_or_loopback() {
        let r = complement_ranges(&[
            "192.0.2.10".parse().unwrap(),
            "2001:db8::1".parse().unwrap(),
        ]);
        assert!(!covers(&r, "192.0.2.10"), "allow-listed v4 must stay open");
        assert!(!covers(&r, "2001:db8::1"), "allow-listed v6 must stay open");
        assert!(!covers(&r, "127.0.0.1") && !covers(&r, "127.255.255.255"));
        assert!(!covers(&r, "::1"));
        for blocked in [
            "0.0.0.0",
            "1.1.1.1",
            "192.0.2.9",
            "192.0.2.11",
            "10.0.0.5",
            "255.255.255.255",
            "126.255.255.255",
            "128.0.0.0",
            "::",
            "2001:db8::2",
            "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
        ] {
            assert!(covers(&r, blocked), "{blocked} must be blocked");
        }
    }

    #[test]
    fn adjacent_and_duplicate_allow_entries_merge_without_gaps() {
        let r = complement_ranges(&[
            "10.0.0.5".parse().unwrap(),
            "10.0.0.6".parse().unwrap(),
            "10.0.0.5".parse().unwrap(),
        ]);
        assert!(!covers(&r, "10.0.0.5") && !covers(&r, "10.0.0.6"));
        assert!(covers(&r, "10.0.0.4") && covers(&r, "10.0.0.7"));
    }

    #[test]
    fn allowlisting_the_address_space_edges_does_not_overflow() {
        let r = complement_ranges(&[
            "0.0.0.0".parse().unwrap(),
            "255.255.255.255".parse().unwrap(),
        ]);
        assert!(!covers(&r, "0.0.0.0") && !covers(&r, "255.255.255.255"));
        assert!(covers(&r, "0.0.0.1") && covers(&r, "255.255.255.254"));
        let r = complement_ranges(&["::".parse().unwrap()]);
        assert!(!covers(&r, "::") && covers(&r, "::2"));
    }

    #[test]
    fn empty_allowlist_still_spares_only_loopback() {
        let r = complement_ranges(&[]);
        assert!(!covers(&r, "127.0.0.1") && !covers(&r, "::1"));
        assert!(covers(&r, "8.8.8.8") && covers(&r, "fe80::1"));
    }

    #[test]
    fn block_rule_arguments_are_typed_tokens_without_shell_metacharacters() {
        let net: IpNet = "203.0.113.0/24".parse().unwrap();
        let name = block_rule_name("203.0.113.0/24", Direction::Out);
        assert_eq!(name, "TRAPD-BLOCK-OUT-203.0.113.0_24");
        let args = add_block_args(
            &name,
            Direction::Out,
            &remote_for(&net),
            "TRAPD containment",
        );
        assert!(args.contains(&"action=block".to_string()));
        assert!(args.contains(&"remoteip=203.0.113.0/24".to_string()));
        assert!(args.contains(&"dir=out".to_string()));
        assert!(args.contains(&format!("group={GROUP}")));
        assert!(args.iter().all(|a| !a.contains(['&', '|', ';', '\n', '"'])));
    }

    #[test]
    fn group_policy_overrides_the_local_firewall_switch() {
        assert!(profile_enforcing(None, None), "unset means on");
        assert!(!profile_enforcing(None, Some(0)));
        assert!(
            profile_enforcing(Some(1), Some(0)),
            "GPO on beats local off"
        );
        assert!(
            !profile_enforcing(Some(0), Some(1)),
            "GPO off beats local on"
        );
    }

    #[test]
    fn single_host_networks_are_emitted_without_a_prefix() {
        assert_eq!(
            remote_for(&"198.51.100.7/32".parse().unwrap()),
            "198.51.100.7"
        );
        assert_eq!(
            remote_for(&"2001:db8::7/128".parse().unwrap()),
            "2001:db8::7"
        );
    }
}
