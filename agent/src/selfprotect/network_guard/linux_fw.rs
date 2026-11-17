//! Parsers for Linux packet-filter rule dumps (`nft -j list ruleset`,
//! `iptables-save`). Pure: the runner that executes the tools lives in
//! `mod.rs`-level glue so these are testable without root or the tools.

use std::net::IpAddr;

use serde_json::Value;

use super::matching::{AddrMatch, FilterInfo, Verdict};

const MAX_RULES: usize = 20_000;

fn blank(source: &'static str, layer: String) -> FilterInfo {
    FilterInfo {
        source,
        name: String::new(),
        provider: source.to_string(),
        layer,
        verdict: Verdict::Other,
        disabled: false,
        app_ids: vec![],
        remote: vec![],
        uid_ranges: vec![],
        cgroup_paths: vec![],
        cgroup_ids: vec![],
    }
}

// --- nftables JSON --------------------------------------------------------

/// Rules of `nft -j list ruleset` output. Unparseable input yields no rules.
pub fn parse_nft_json(raw: &str) -> Vec<FilterInfo> {
    let Ok(root) = serde_json::from_str::<Value>(raw) else {
        return Vec::new();
    };
    let Some(items) = root.get("nftables").and_then(Value::as_array) else {
        return Vec::new();
    };
    items
        .iter()
        .filter_map(|i| i.get("rule"))
        .take(MAX_RULES)
        .map(nft_rule)
        .collect()
}

fn nft_rule(rule: &Value) -> FilterInfo {
    let s = |k: &str| rule.get(k).and_then(Value::as_str).unwrap_or("?");
    let mut f = blank(
        "nftables",
        format!("{} {}/{}", s("family"), s("table"), s("chain")),
    );
    f.name = match rule.get("comment").and_then(Value::as_str) {
        Some(c) => c.to_string(),
        None => format!(
            "handle {}",
            rule.get("handle").and_then(Value::as_u64).unwrap_or(0)
        ),
    };
    for expr in rule
        .get("expr")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        if expr.get("drop").is_some() || expr.get("reject").is_some() {
            f.verdict = Verdict::Block;
        } else if expr.get("accept").is_some() && f.verdict == Verdict::Other {
            f.verdict = Verdict::Permit;
        }
        if let Some(m) = expr.get("match") {
            // Negated comparisons select everything *but* the value.
            if m.get("op").and_then(Value::as_str).unwrap_or("==") != "==" {
                continue;
            }
            nft_match(&mut f, m.get("left"), m.get("right"));
        }
    }
    f
}

fn nft_values(right: &Value) -> Vec<&Value> {
    match right {
        Value::Object(o) if o.contains_key("set") => o["set"]
            .as_array()
            .map(|a| a.iter().collect())
            .unwrap_or_default(),
        v => vec![v],
    }
}

fn nft_match(f: &mut FilterInfo, left: Option<&Value>, right: Option<&Value>) {
    let (Some(left), Some(right)) = (left, right) else {
        return;
    };
    if let Some(meta) = left.get("meta") {
        let key = meta.get("key").and_then(Value::as_str);
        if key == Some("skuid") {
            for v in nft_values(right) {
                if let Some(range) = nft_uid(v) {
                    f.uid_ranges.push(range);
                }
            }
        }
    } else if let Some(p) = left.get("payload") {
        if p.get("field").and_then(Value::as_str) == Some("daddr") {
            for v in nft_values(right) {
                if let Some(m) = nft_addr(v) {
                    f.remote.push(m);
                }
            }
        }
    } else if let Some(sock) = left.get("socket") {
        if sock.get("key").and_then(Value::as_str) == Some("cgroupv2") {
            for v in nft_values(right) {
                if let Some(id) = v.as_u64() {
                    f.cgroup_ids.push(id);
                } else if let Some(p) = v.as_str() {
                    f.cgroup_paths.push(p.trim_matches('/').to_string());
                }
            }
        }
    }
}

fn nft_uid(v: &Value) -> Option<(u32, u32)> {
    match v {
        Value::Number(n) => {
            let u = u32::try_from(n.as_u64()?).ok()?;
            Some((u, u))
        }
        Value::String(s) if s == "root" => Some((0, 0)),
        Value::String(s) => s.parse::<u32>().ok().map(|u| (u, u)),
        Value::Object(o) => {
            let r = o.get("range")?.as_array()?;
            Some((
                u32::try_from(r.first()?.as_u64()?).ok()?,
                u32::try_from(r.get(1)?.as_u64()?).ok()?,
            ))
        }
        _ => None,
    }
}

fn nft_addr(v: &Value) -> Option<AddrMatch> {
    match v {
        Value::String(s) => s.parse::<IpAddr>().ok().map(AddrMatch::Addr),
        Value::Object(o) => {
            if let Some(p) = o.get("prefix") {
                let addr = p.get("addr")?.as_str()?.parse().ok()?;
                let len = u8::try_from(p.get("len")?.as_u64()?).ok()?;
                Some(AddrMatch::Net(addr, len))
            } else if let Some(r) = o.get("range") {
                let r = r.as_array()?;
                Some(AddrMatch::Range(
                    r.first()?.as_str()?.parse().ok()?,
                    r.get(1)?.as_str()?.parse().ok()?,
                ))
            } else {
                None
            }
        }
        _ => None,
    }
}

// --- iptables-save --------------------------------------------------------

/// Split on whitespace honouring double quotes (for `--comment "a b"`).
fn tokenize(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    for c in line.chars() {
        match c {
            '"' => quoted = !quoted,
            c if c.is_whitespace() && !quoted => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            c => cur.push(c),
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

fn ipt_addr(s: &str) -> Option<AddrMatch> {
    match s.split_once('/') {
        Some((a, len)) => {
            let addr: IpAddr = a.parse().ok()?;
            // iptables-save prints CIDR; a dotted mask is converted.
            let len = match len.parse::<u8>() {
                Ok(l) => l,
                Err(_) => {
                    let m: std::net::Ipv4Addr = len.parse().ok()?;
                    u32::from(m).count_ones() as u8
                }
            };
            Some(AddrMatch::Net(addr, len))
        }
        None => s.parse().ok().map(AddrMatch::Addr),
    }
}

fn ipt_uid(s: &str) -> Option<(u32, u32)> {
    if s == "root" {
        return Some((0, 0));
    }
    match s.split_once('-') {
        Some((a, b)) => Some((a.parse().ok()?, b.parse().ok()?)),
        None => s.parse().ok().map(|u| (u, u)),
    }
}

/// Rules of `iptables-save` / `ip6tables-save` output (all tables).
pub fn parse_iptables_save(raw: &str) -> Vec<FilterInfo> {
    let mut table = String::from("?");
    let mut out = Vec::new();
    for line in raw.lines() {
        if let Some(t) = line.strip_prefix('*') {
            table = t.trim().to_string();
            continue;
        }
        if !line.starts_with("-A ") || out.len() >= MAX_RULES {
            continue;
        }
        let toks = tokenize(line);
        let chain = toks.get(1).cloned().unwrap_or_default();
        let mut f = blank("iptables", format!("{table}/{chain}"));
        let mut negate = false;
        let mut i = 2;
        while i < toks.len() {
            let t = toks[i].as_str();
            let val = toks.get(i + 1).map(String::as_str);
            match (t, val) {
                ("!", _) => {
                    negate = true;
                    i += 1;
                    continue;
                }
                ("-d" | "--destination", Some(v)) if !negate => {
                    f.remote.extend(v.split(',').filter_map(ipt_addr));
                }
                ("--uid-owner", Some(v)) if !negate => {
                    if let Some(r) = ipt_uid(v) {
                        f.uid_ranges.push(r);
                    }
                }
                ("--path", Some(v)) if !negate => {
                    f.cgroup_paths.push(v.trim_matches('/').to_string());
                }
                ("--comment", Some(v)) => f.name = v.to_string(),
                ("-j" | "-g", Some(v)) => {
                    f.verdict = match v {
                        "DROP" | "REJECT" => Verdict::Block,
                        "ACCEPT" => Verdict::Permit,
                        _ => Verdict::Other,
                    };
                }
                _ => {}
            }
            negate = false;
            i += 1;
        }
        if f.name.is_empty() {
            f.name = format!("{chain} rule {}", out.len() + 1);
        }
        out.push(f);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::selfprotect::network_guard::matching::{blocks_us, Reason, Targets};

    fn t() -> Targets {
        Targets {
            app_ids: vec![],
            backend_ips: vec!["203.0.113.10".parse().unwrap()],
            uid: Some(0),
            cgroup_path: Some("system.slice/trapd-agent.service".into()),
            cgroup_id: Some(4242),
        }
    }

    #[test]
    fn iptables_uid_owner_drop_is_the_adversarial_row() {
        // iptables -A OUTPUT -m owner --uid-owner 0 -j DROP
        let rules = parse_iptables_save(
            "*filter\n:OUTPUT ACCEPT [0:0]\n-A OUTPUT -m owner --uid-owner 0 -j DROP\nCOMMIT\n",
        );
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].verdict, Verdict::Block);
        assert_eq!(blocks_us(&rules[0], &t()), Some(Reason::Uid));
    }

    #[test]
    fn iptables_backend_drop_comment_and_negation() {
        let rules = parse_iptables_save(
            "*filter\n\
             -A OUTPUT -d 203.0.113.0/24 -m comment --comment \"cleanup job\" -j REJECT --reject-with icmp-port-unreachable\n\
             -A OUTPUT ! -d 203.0.113.10/32 -j DROP\n\
             -A OUTPUT -d 203.0.113.10/32 -j ACCEPT\n\
             -A OUTPUT -m owner ! --uid-owner 0 -j DROP\n\
             -A OUTPUT -m cgroup --path system.slice/trapd-agent.service -j DROP\n\
             COMMIT\n",
        );
        assert_eq!(rules.len(), 5);
        assert_eq!(rules[0].name, "cleanup job");
        assert_eq!(blocks_us(&rules[0], &t()), Some(Reason::BackendAddress));
        assert_eq!(blocks_us(&rules[1], &t()), None, "negated match");
        assert_eq!(blocks_us(&rules[2], &t()), None, "accept");
        assert_eq!(blocks_us(&rules[3], &t()), None, "negated uid");
        assert_eq!(blocks_us(&rules[4], &t()), Some(Reason::Cgroup));
    }

    #[test]
    fn trapd_isolation_chain_is_not_flagged() {
        // The agent's own isolation: DROP without conditions, ACCEPT for the
        // allowlisted backend. Neither is targeted silencing.
        let rules = parse_iptables_save(
            "*filter\n-N TRAPD_ISOLATE\n-A TRAPD_ISOLATE -d 203.0.113.10/32 -j ACCEPT\n-A TRAPD_ISOLATE -j DROP\nCOMMIT\n",
        );
        assert!(rules.iter().all(|r| blocks_us(r, &t()).is_none()));
    }

    #[test]
    fn uid_range_and_dotted_mask() {
        let rules = parse_iptables_save(
            "*filter\n-A OUTPUT -d 203.0.113.0/255.255.255.0 -j DROP\n-A OUTPUT -m owner --uid-owner 0-999 -j DROP\n",
        );
        assert_eq!(blocks_us(&rules[0], &t()), Some(Reason::BackendAddress));
        assert_eq!(blocks_us(&rules[1], &t()), Some(Reason::Uid));
    }

    const NFT: &str = r#"{"nftables":[
      {"metainfo":{"version":"1.0.9"}},
      {"table":{"family":"inet","name":"filter","handle":1}},
      {"rule":{"family":"inet","table":"filter","chain":"output","handle":4,
        "expr":[{"match":{"op":"==","left":{"meta":{"key":"skuid"}},"right":0}},{"counter":{"packets":0,"bytes":0}},{"drop":null}]}},
      {"rule":{"family":"ip","table":"filter","chain":"output","handle":5,"comment":"x",
        "expr":[{"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"daddr"}},"right":{"prefix":{"addr":"203.0.113.0","len":24}}}},{"reject":{"type":"icmp"}}]}},
      {"rule":{"family":"ip","table":"filter","chain":"output","handle":6,
        "expr":[{"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"daddr"}},"right":{"set":["198.51.100.1","203.0.113.10"]}}},{"drop":null}]}},
      {"rule":{"family":"inet","table":"filter","chain":"output","handle":7,
        "expr":[{"match":{"op":"!=","left":{"meta":{"key":"skuid"}},"right":0}},{"drop":null}]}},
      {"rule":{"family":"inet","table":"filter","chain":"output","handle":8,
        "expr":[{"match":{"op":"==","left":{"socket":{"key":"cgroupv2","level":2}},"right":4242}},{"drop":null}]}},
      {"rule":{"family":"inet","table":"filter","chain":"output","handle":9,
        "expr":[{"match":{"op":"==","left":{"meta":{"key":"skuid"}},"right":0}},{"accept":null}]}}
    ]}"#;

    #[test]
    fn nft_rules() {
        let rules = parse_nft_json(NFT);
        assert_eq!(rules.len(), 6);
        assert_eq!(blocks_us(&rules[0], &t()), Some(Reason::Uid));
        assert_eq!(rules[1].name, "x");
        assert_eq!(blocks_us(&rules[1], &t()), Some(Reason::BackendAddress));
        assert_eq!(blocks_us(&rules[2], &t()), Some(Reason::BackendAddress));
        assert_eq!(blocks_us(&rules[3], &t()), None);
        assert_eq!(blocks_us(&rules[4], &t()), Some(Reason::Cgroup));
        assert_eq!(blocks_us(&rules[5], &t()), None);
        assert_eq!(rules[0].layer, "inet filter/output");
    }

    #[test]
    fn garbage_yields_no_rules() {
        assert!(parse_nft_json("not json").is_empty());
        assert!(parse_nft_json("{}").is_empty());
        assert!(parse_iptables_save("garbage\n-A\n").len() <= 1);
    }
}
