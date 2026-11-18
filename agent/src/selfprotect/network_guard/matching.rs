//! Pure matching of firewall filters / rules against what the agent must keep
//! reachable: its own executable, its UID and the backend addresses.
//!
//! Everything here is platform independent so the decision logic is unit
//! tested on Linux for the Windows (WFP) and Linux (nftables/iptables) readers.

use std::net::IpAddr;

/// One remote-address condition of a filter or rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddrMatch {
    Addr(IpAddr),
    /// Inclusive range (both ends of the same family).
    Range(IpAddr, IpAddr),
    /// Network prefix.
    Net(IpAddr, u8),
}

impl AddrMatch {
    pub fn contains(&self, ip: IpAddr) -> bool {
        match self {
            AddrMatch::Addr(a) => *a == ip,
            AddrMatch::Range(lo, hi) => match (lo, hi, ip) {
                (IpAddr::V4(l), IpAddr::V4(h), IpAddr::V4(i)) => {
                    u32::from(*l) <= u32::from(i) && u32::from(i) <= u32::from(*h)
                }
                (IpAddr::V6(l), IpAddr::V6(h), IpAddr::V6(i)) => {
                    u128::from(*l) <= u128::from(i) && u128::from(i) <= u128::from(*h)
                }
                _ => false,
            },
            AddrMatch::Net(net, len) => prefix_contains(*net, *len, ip),
        }
    }
}

fn prefix_contains(net: IpAddr, len: u8, ip: IpAddr) -> bool {
    match (net, ip) {
        (IpAddr::V4(n), IpAddr::V4(i)) => {
            let len = u32::from(len.min(32));
            let mask = if len == 0 { 0 } else { u32::MAX << (32 - len) };
            u32::from(n) & mask == u32::from(i) & mask
        }
        (IpAddr::V6(n), IpAddr::V6(i)) => {
            let len = u32::from(len.min(128));
            let mask = if len == 0 {
                0
            } else {
                u128::MAX << (128 - len)
            };
            u128::from(n) & mask == u128::from(i) & mask
        }
        _ => false,
    }
}

/// What we need to stay reachable.
#[derive(Debug, Clone, Default)]
pub struct Targets {
    /// Normalised application ids (see [`normalize_app_id`]) of our binaries.
    pub app_ids: Vec<String>,
    pub backend_ips: Vec<IpAddr>,
    /// Effective UID of the agent process (Linux).
    pub uid: Option<u32>,
    /// cgroup v2 path of the agent (no leading slash) and its inode id, which
    /// is what nftables compares (Linux).
    pub cgroup_path: Option<String>,
    pub cgroup_id: Option<u64>,
}

/// Lowercase, strip trailing NULs, unify separators. WFP app ids are the NT
/// device path (`\device\harddiskvolume3\...`), stored lowercase.
pub fn normalize_app_id(raw: &str) -> String {
    raw.trim_end_matches('\0')
        .trim()
        .replace('/', "\\")
        .to_lowercase()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Block,
    Permit,
    Other,
}

/// A firewall rule or WFP filter reduced to the parts that matter here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilterInfo {
    /// `wfp`, `nftables`, `iptables`.
    pub source: &'static str,
    pub name: String,
    pub provider: String,
    /// WFP layer name, or `<family> <table>/<chain>` for Linux rules.
    pub layer: String,
    pub verdict: Verdict,
    pub disabled: bool,
    pub app_ids: Vec<String>,
    pub remote: Vec<AddrMatch>,
    /// Inclusive UID ranges the rule selects on.
    pub uid_ranges: Vec<(u32, u32)>,
    /// cgroup v2 paths / inode ids the rule selects on.
    pub cgroup_paths: Vec<String>,
    pub cgroup_ids: Vec<u64>,
}

/// Why a filter was flagged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    AppId,
    BackendAddress,
    Uid,
    Cgroup,
}

impl Reason {
    pub fn as_str(self) -> &'static str {
        match self {
            Reason::AppId => "app_id",
            Reason::BackendAddress => "backend_address",
            Reason::Uid => "uid",
            Reason::Cgroup => "cgroup",
        }
    }
}

/// `Some(reason)` when `f` blocks traffic of ours. A filter that has no
/// condition naming us or the backend (a plain "block all" default policy) is
/// not flagged: it is a platform posture, not targeted silencing.
///
/// The condition families (application, remote address, UID, cgroup) are a conjunction, as in the
/// firewalls themselves: a rule that blocks the backend address only for another user or another
/// executable cannot block us. Every populated family must match; the reported reason is the most
/// specific one.
pub fn blocks_us(f: &FilterInfo, t: &Targets) -> Option<Reason> {
    if f.verdict != Verdict::Block || f.disabled {
        return None;
    }
    let app = (!f.app_ids.is_empty()).then(|| f.app_ids.iter().any(|a| t.app_ids.contains(a)));
    let uid = (!f.uid_ranges.is_empty()).then(|| {
        t.uid.is_some_and(|uid| {
            f.uid_ranges
                .iter()
                .any(|(lo, hi)| (*lo..=*hi).contains(&uid))
        })
    });
    let remote = (!f.remote.is_empty()).then(|| {
        f.remote
            .iter()
            .any(|m| t.backend_ips.iter().any(|ip| m.contains(*ip)))
    });
    let cgroup = (!f.cgroup_paths.is_empty() || !f.cgroup_ids.is_empty()).then(|| {
        let path_hit = t
            .cgroup_path
            .as_ref()
            .is_some_and(|p| f.cgroup_paths.iter().any(|c| c == p));
        let id_hit = t.cgroup_id.is_some_and(|id| f.cgroup_ids.contains(&id));
        path_hit || id_hit
    });
    let populated = [
        (app, Reason::AppId),
        (uid, Reason::Uid),
        (remote, Reason::BackendAddress),
        (cgroup, Reason::Cgroup),
    ];
    let mut reason = None;
    for (matched, why) in populated {
        match matched {
            Some(false) => return None,
            Some(true) => reason = reason.or(Some(why)),
            None => {}
        }
    }
    reason
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn filter(verdict: Verdict) -> FilterInfo {
        FilterInfo {
            source: "wfp",
            name: "rule".into(),
            provider: "p".into(),
            layer: "FWPM_LAYER_ALE_AUTH_CONNECT_V4".into(),
            verdict,
            disabled: false,
            app_ids: vec![],
            remote: vec![],
            uid_ranges: vec![],
            cgroup_paths: vec![],
            cgroup_ids: vec![],
        }
    }

    fn targets() -> Targets {
        Targets {
            app_ids: vec![normalize_app_id(
                "\\DEVICE\\HarddiskVolume3\\Program Files\\TRAPD Agent\\trapd-agent.exe\0",
            )],
            backend_ips: vec![ip("203.0.113.10"), ip("2001:db8::10")],
            uid: Some(0),
            cgroup_path: Some("system.slice/trapd-agent.service".into()),
            cgroup_id: Some(4242),
        }
    }

    #[test]
    fn edrsilencer_style_app_block_is_flagged() {
        let mut f = filter(Verdict::Block);
        f.app_ids = vec![normalize_app_id(
            "\\device\\harddiskvolume3\\program files\\trapd agent\\TRAPD-AGENT.EXE",
        )];
        assert_eq!(blocks_us(&f, &targets()), Some(Reason::AppId));
    }

    #[test]
    fn permit_and_disabled_filters_are_ignored() {
        let mut f = filter(Verdict::Permit);
        f.app_ids = targets().app_ids;
        assert_eq!(blocks_us(&f, &targets()), None);
        let mut f = filter(Verdict::Block);
        f.app_ids = targets().app_ids;
        f.disabled = true;
        assert_eq!(blocks_us(&f, &targets()), None);
    }

    #[test]
    fn other_applications_are_not_flagged() {
        let mut f = filter(Verdict::Block);
        f.app_ids = vec![normalize_app_id(
            "\\device\\harddiskvolume3\\tools\\other.exe",
        )];
        assert_eq!(blocks_us(&f, &targets()), None);
    }

    #[test]
    fn default_block_without_conditions_is_not_targeted() {
        assert_eq!(blocks_us(&filter(Verdict::Block), &targets()), None);
    }

    #[test]
    fn backend_address_block_via_addr_net_and_range() {
        let t = targets();
        for m in [
            AddrMatch::Addr(ip("203.0.113.10")),
            AddrMatch::Net(ip("203.0.113.0"), 24),
            AddrMatch::Range(ip("203.0.113.1"), ip("203.0.113.200")),
            AddrMatch::Net(ip("2001:db8::"), 32),
            AddrMatch::Net(ip("0.0.0.0"), 0),
        ] {
            let mut f = filter(Verdict::Block);
            f.remote = vec![m.clone()];
            assert_eq!(blocks_us(&f, &t), Some(Reason::BackendAddress), "{m:?}");
        }
    }

    #[test]
    fn unrelated_address_is_not_flagged() {
        let mut f = filter(Verdict::Block);
        f.remote = vec![
            AddrMatch::Addr(ip("198.51.100.1")),
            AddrMatch::Net(ip("10.0.0.0"), 8),
            AddrMatch::Range(ip("203.0.113.11"), ip("203.0.113.20")),
        ];
        assert_eq!(blocks_us(&f, &targets()), None);
    }

    #[test]
    fn address_families_do_not_cross_match() {
        assert!(!AddrMatch::Net(ip("::"), 0).contains(ip("203.0.113.10")));
        assert!(!AddrMatch::Addr(ip("::ffff:203.0.113.10")).contains(ip("203.0.113.10")));
    }

    #[test]
    fn linux_uid_and_cgroup_rules() {
        let mut f = filter(Verdict::Block);
        f.source = "iptables";
        f.uid_ranges = vec![(0, 0)];
        assert_eq!(blocks_us(&f, &targets()), Some(Reason::Uid));
        f.uid_ranges = vec![(1000, 1000)];
        assert_eq!(blocks_us(&f, &targets()), None);
        // The families are a conjunction: a uid that is not ours rules the rule out even when a
        // cgroup condition matches, so the cgroup cases below stand on their own.
        f.cgroup_ids = vec![4242];
        assert_eq!(blocks_us(&f, &targets()), None);
        f.cgroup_ids = vec![];
        f.uid_ranges = vec![];
        f.cgroup_paths = vec!["system.slice/other.service".into()];
        f.cgroup_ids = vec![7];
        assert_eq!(blocks_us(&f, &targets()), None);
        f.cgroup_ids = vec![4242];
        assert_eq!(blocks_us(&f, &targets()), Some(Reason::Cgroup));
        f.cgroup_ids = vec![];
        f.cgroup_paths = vec!["system.slice/trapd-agent.service".into()];
        assert_eq!(blocks_us(&f, &targets()), Some(Reason::Cgroup));
    }

    #[test]
    fn conditions_are_a_conjunction_not_alternatives() {
        // Backend address blocked, but only for another uid or another executable: not us.
        let mut f = filter(Verdict::Block);
        f.remote = vec![AddrMatch::Addr(ip("203.0.113.10"))];
        f.uid_ranges = vec![(1000, 1000)];
        assert_eq!(
            blocks_us(&f, &targets()),
            None,
            "uid 0 is outside 1000-1000"
        );

        let mut f = filter(Verdict::Block);
        f.remote = vec![AddrMatch::Addr(ip("203.0.113.10"))];
        f.app_ids = vec![normalize_app_id(
            "\\device\\harddiskvolume3\\tools\\other.exe",
        )];
        assert_eq!(blocks_us(&f, &targets()), None, "another executable");

        let mut f = filter(Verdict::Block);
        f.remote = vec![AddrMatch::Addr(ip("198.51.100.1"))];
        f.uid_ranges = vec![(0, 0)];
        assert_eq!(
            blocks_us(&f, &targets()),
            None,
            "uid matches, address does not"
        );

        // Every populated family matches: flagged, with the most specific reason.
        let mut f = filter(Verdict::Block);
        f.remote = vec![AddrMatch::Addr(ip("203.0.113.10"))];
        f.uid_ranges = vec![(0, 0)];
        assert_eq!(blocks_us(&f, &targets()), Some(Reason::Uid));
        let mut f = filter(Verdict::Block);
        f.remote = vec![AddrMatch::Net(ip("203.0.113.0"), 24)];
        f.cgroup_ids = vec![4242];
        assert_eq!(blocks_us(&f, &targets()), Some(Reason::BackendAddress));
    }
}
