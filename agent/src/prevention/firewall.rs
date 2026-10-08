//! Windows Firewall containment: pure address and profile logic.
//!
//! Platform-neutral policy arithmetic, exercised on both Linux and Windows.
//! Native COM rule management lives in `winfirewall.rs`. Isolation blocks the
//! complement of the allowlist without rewriting operator or GPO defaults.

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
/// name stays stable across API and diagnostic views.
pub fn block_rule_name(target: &str, dir: Direction) -> String {
    format!(
        "TRAPD-BLOCK-{}-{}",
        dir.as_str().to_ascii_uppercase(),
        target.replace('/', "_")
    )
}

/// Recover the canonical target we encoded in a block rule's stable name.
/// Windows may reformat RemoteAddresses as a subnet mask or address range;
/// rule names preserve our original validated IP/CIDR representation.
pub fn parse_block_rule_name(name: &str) -> Option<(IpNet, Direction)> {
    let (target, direction) = if let Some(target) = name.strip_prefix("TRAPD-BLOCK-OUT-") {
        (target, Direction::Out)
    } else {
        (name.strip_prefix("TRAPD-BLOCK-IN-")?, Direction::In)
    };
    let target = target.replace('_', "/");
    let net = target
        .parse::<IpNet>()
        .or_else(|_| target.parse::<IpAddr>().map(IpNet::from))
        .ok()?
        .trunc();
    (block_rule_name(&remote_for(&net), direction) == name).then_some((net, direction))
}

const BLOCK_DESCRIPTION: &str = "TRAPD containment: blocked indicator";
const EXPIRY_PREFIX: &str = "TRAPD containment: blocked indicator; expiry-v1:";

/// Stored in the native rule itself, so a crash cannot lose a separate timer
/// or leave the rule and its expiry journal out of sync.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlockExpiry {
    pub deadline: u64,
    pub command_id: String,
}

impl BlockExpiry {
    pub fn expired(&self, now: u64) -> bool {
        now >= self.deadline
    }
}

pub fn block_description(ttl: Option<u64>, command_id: &str, now: u64) -> anyhow::Result<String> {
    let Some(ttl) = ttl else {
        return Ok(BLOCK_DESCRIPTION.to_string());
    };
    let deadline = now
        .checked_add(ttl)
        .ok_or_else(|| anyhow::anyhow!("block TTL exceeds timestamp range"))?;
    let description = format!(
        "{EXPIRY_PREFIX}{}",
        serde_json::to_string(&BlockExpiry {
            deadline,
            command_id: command_id.into(),
        })?
    );
    // INetFwRule descriptions forbid '|'. Bound metadata before publishing.
    if description.len() > 512 || description.contains('|') {
        anyhow::bail!("invalid firewall expiry metadata");
    }
    Ok(description)
}

pub fn block_expiry(description: &str) -> anyhow::Result<Option<BlockExpiry>> {
    let Some(metadata) = description.strip_prefix(EXPIRY_PREFIX) else {
        return Ok(None);
    };
    if description.len() > 512 {
        anyhow::bail!("firewall expiry metadata exceeds limit");
    }
    Ok(Some(serde_json::from_str(metadata)?))
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

/// Require enforcing firewall state for every active network profile.
/// The caller obtains the active mask from INetFwPolicy2, and combines local
/// native state with group policy before constructing `profiles`.
pub fn active_profiles_enforcing(active: u32, profiles: &[(u32, bool)]) -> bool {
    active != 0
        && active & !7 == 0
        && [1, 2, 4].into_iter().all(|profile| {
            active & profile == 0
                || profiles
                    .iter()
                    .any(|(p, enabled)| *p == profile && *enabled)
        })
}

/// Format a remote address for the native RemoteAddresses property: single host, CIDR, or `a-b` range.
pub fn remote_for(target: &IpNet) -> String {
    if target.prefix_len() == target.max_prefix_len() {
        target.addr().to_string()
    } else {
        target.to_string()
    }
}

/// Inclusive address ranges covering every address that is **not** in `keep`
/// and not loopback, as Firewall API address tokens (`a-b`), IPv4 and IPv6.
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

    #[test]
    fn block_expiry_survives_serialization_and_expires_at_deadline() {
        let description = block_description(Some(60), "command-1", 1_000).unwrap();
        let restored = block_expiry(&description).unwrap().unwrap();
        assert_eq!(restored.deadline, 1_060);
        assert_eq!(restored.command_id, "command-1");
        assert!(!restored.expired(1_059));
        assert!(restored.expired(1_060));
        assert!(restored.expired(1_100));
    }

    #[test]
    fn permanent_blocks_have_no_expiry_and_zero_ttl_is_immediate() {
        assert!(block_expiry(&block_description(None, "", 1_000).unwrap())
            .unwrap()
            .is_none());
        assert!(block_expiry("TRAPD containment: host isolated")
            .unwrap()
            .is_none());
        assert!(
            block_expiry(&block_description(Some(0), "cmd", 1_000).unwrap())
                .unwrap()
                .unwrap()
                .expired(1_000)
        );
    }

    #[test]
    fn block_expiry_rejects_overflow_and_corrupt_metadata() {
        assert!(block_description(Some(u64::MAX), "cmd", 1).is_err());
        for description in [
            "TRAPD containment: blocked indicator; expiry-v1:broken",
            "TRAPD containment: blocked indicator; expiry-v1:{\"deadline\":-1,\"command_id\":\"cmd\"}",
            "TRAPD containment: blocked indicator; expiry-v1:{\"deadline\":1}",
        ] {
            assert!(block_expiry(description).is_err(), "{description}");
        }
    }

    #[test]
    fn expiry_recovers_targets_from_owned_rule_names() {
        for (name, target, direction) in [
            (
                "TRAPD-BLOCK-OUT-203.0.113.77",
                "203.0.113.77/32",
                Direction::Out,
            ),
            (
                "TRAPD-BLOCK-IN-203.0.113.0_24",
                "203.0.113.0/24",
                Direction::In,
            ),
            (
                "TRAPD-BLOCK-IN-2001:db8::1",
                "2001:db8::1/128",
                Direction::In,
            ),
            (
                "TRAPD-BLOCK-OUT-2001:db8::_64",
                "2001:db8::/64",
                Direction::Out,
            ),
        ] {
            assert_eq!(
                parse_block_rule_name(name),
                Some((target.parse::<IpNet>().unwrap(), direction))
            );
        }
        for name in [
            "TRAPD-ISOLATE-OUT",
            "Other-Application",
            "TRAPD-BLOCK-OUT-DNS",
            "TRAPD-BLOCK-OUT-203.0.113.77_24",
        ] {
            assert!(parse_block_rule_name(name).is_none(), "{name}");
        }
    }

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
    fn block_rule_names_and_addresses_are_stable() {
        let net: IpNet = "203.0.113.0/24".parse().unwrap();
        assert_eq!(
            block_rule_name("203.0.113.0/24", Direction::Out),
            "TRAPD-BLOCK-OUT-203.0.113.0_24"
        );
        assert_eq!(remote_for(&net), "203.0.113.0/24");
    }

    #[test]
    fn inactive_enabled_profile_cannot_hide_disabled_active_profile() {
        assert!(!active_profiles_enforcing(
            4,
            &[(1, true), (2, true), (4, false)]
        ));
    }

    #[test]
    fn every_active_profile_must_enforce() {
        let profiles = [(1, true), (2, false), (4, true)];
        assert!(active_profiles_enforcing(5, &profiles));
        assert!(!active_profiles_enforcing(3, &profiles));
        assert!(!active_profiles_enforcing(0, &profiles));
        assert!(!active_profiles_enforcing(8, &profiles));
        assert!(!active_profiles_enforcing(4, &[(1, true)]));
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
