//! Pure detection of backend redirection: hosts-file entries, proxy settings
//! and NRPT (DNS policy) rules that apply to the backend host.

/// One name of a hosts-file line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostsEntry {
    pub ip: String,
    pub host: String,
}

/// Parse hosts-file text: `ip name [alias...] [# comment]`. Malformed lines are
/// skipped. Bounded so a hostile multi-megabyte file cannot stall a scan.
pub fn parse_hosts(text: &str) -> Vec<HostsEntry> {
    let mut out = Vec::new();
    for line in text.lines().take(50_000) {
        let line = line.split('#').next().unwrap_or("").trim();
        let mut parts = line.split_whitespace();
        let Some(ip) = parts.next() else { continue };
        if ip.parse::<std::net::IpAddr>().is_err() {
            continue;
        }
        for name in parts {
            out.push(HostsEntry {
                ip: ip.to_string(),
                host: normalize_host(name),
            });
        }
    }
    out
}

pub fn normalize_host(h: &str) -> String {
    h.trim().trim_end_matches('.').to_lowercase()
}

/// Entries that name `backend_host` (case-insensitive, trailing dot ignored).
pub fn hosts_for<'a>(entries: &'a [HostsEntry], backend_host: &str) -> Vec<&'a HostsEntry> {
    let want = normalize_host(backend_host);
    entries.iter().filter(|e| e.host == want).collect()
}

/// A proxy setting seen on the host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyConfig {
    /// `env`, `winhttp`, `wininet`.
    pub source: &'static str,
    /// Proxy server for HTTPS, or the PAC / auto-config marker.
    pub server: String,
    pub bypass: Vec<String>,
}

/// WinINET/WinHTTP syntax: `host:port` or `http=h:p;https=h2:p;ftp=...`.
/// Returns the server that carries HTTPS traffic.
pub fn https_proxy_server(raw: &str) -> Option<String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    if !raw.contains('=') {
        return Some(raw.to_string());
    }
    let mut http = None;
    for part in raw.split(';') {
        let (scheme, server) = part.split_once('=')?;
        match scheme.trim().to_ascii_lowercase().as_str() {
            "https" => return Some(server.trim().to_string()),
            "http" => http = Some(server.trim().to_string()),
            _ => {}
        }
    }
    http
}

/// Whether the bypass list exempts `host` from the proxy.
pub fn bypassed(host: &str, bypass: &[String]) -> bool {
    let host = normalize_host(host);
    bypass.iter().any(|raw| {
        let e = raw.trim().to_lowercase();
        if e.is_empty() {
            return false;
        }
        if e == "<local>" {
            return !host.contains('.');
        }
        if e == "*" {
            return true;
        }
        if let Some(suffix) = e.strip_prefix("*.") {
            return host.ends_with(&format!(".{suffix}"));
        }
        if let Some(suffix) = e.strip_prefix('.') {
            return host == suffix || host.ends_with(&format!(".{suffix}"));
        }
        // Optional `:port` is ignored: the decision is per host.
        e.split(':').next() == Some(host.as_str())
    })
}

/// Whether `cfg` routes traffic for `backend_host` through the proxy.
pub fn proxy_applies(cfg: &ProxyConfig, backend_host: &str) -> bool {
    !cfg.server.is_empty() && !bypassed(backend_host, &cfg.bypass)
}

/// Split a bypass / `NO_PROXY` list on `;` and `,`.
pub fn split_bypass(raw: &str) -> Vec<String> {
    raw.split([';', ','])
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// Proxy configuration from process environment values.
pub fn env_proxy(get: impl Fn(&str) -> Option<String>) -> Option<ProxyConfig> {
    let server = ["HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"]
        .iter()
        .find_map(|k| get(k).filter(|v| !v.trim().is_empty()))?;
    let bypass = ["NO_PROXY", "no_proxy"]
        .iter()
        .find_map(|k| get(k))
        .map(|v| split_bypass(&v))
        .unwrap_or_default();
    Some(ProxyConfig {
        source: "env",
        server: server.trim().to_string(),
        bypass,
    })
}

/// Decode a `WinHttpSettings` registry blob (machine-wide WinHTTP proxy).
/// Layout: version u32, counter u32, flags u32, proxy len u32 + bytes, bypass
/// len u32 + bytes. Flag `0x02` = named proxy, `0x04` = PAC, `0x08` = autodetect.
pub fn parse_winhttp_settings(blob: &[u8]) -> Option<ProxyConfig> {
    let u32_at = |off: usize| -> Option<usize> {
        let b = blob.get(off..off.checked_add(4)?)?;
        Some(u32::from_le_bytes(b.try_into().ok()?) as usize)
    };
    let flags = u32_at(8)?;
    if flags & 0x02 == 0 {
        return None;
    }
    let plen = u32_at(12)?;
    if plen > 4096 {
        return None;
    }
    let proxy = blob.get(16..16usize.checked_add(plen)?)?;
    let boff = 16 + plen;
    let blen = u32_at(boff)?;
    if blen > 8192 {
        return None;
    }
    let bypass = blob.get(boff + 4..(boff + 4).checked_add(blen)?)?;
    let server = https_proxy_server(&String::from_utf8_lossy(proxy))?;
    Some(ProxyConfig {
        source: "winhttp",
        server,
        bypass: split_bypass(&String::from_utf8_lossy(bypass)),
    })
}

/// Whether an NRPT rule namespace applies to `backend_host`. `.` (catch-all) is
/// deliberately not matched: VPN and DirectAccess clients use it legitimately.
pub fn nrpt_applies(namespace: &str, backend_host: &str) -> bool {
    let ns = normalize_host(namespace);
    let host = normalize_host(backend_host);
    if ns.is_empty() {
        return false;
    }
    if let Some(suffix) = ns.strip_prefix('.') {
        return !suffix.is_empty() && (host == suffix || host.ends_with(&format!(".{suffix}")));
    }
    host == ns
}

/// Decode a `REG_MULTI_SZ` / `REG_SZ` byte buffer (UTF-16LE) into its strings.
pub fn utf16_multi_sz(bytes: &[u8]) -> Vec<String> {
    let units: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        .collect();
    units
        .split(|u| *u == 0)
        .filter(|s| !s.is_empty())
        .map(String::from_utf16_lossy)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multi_sz_is_split_on_nul() {
        let mut b = Vec::new();
        for s in ["a.example", "b.example"] {
            b.extend(s.encode_utf16().flat_map(u16::to_le_bytes));
            b.extend([0, 0]);
        }
        b.extend([0, 0]);
        assert_eq!(utf16_multi_sz(&b), ["a.example", "b.example"]);
    }

    const HOSTS: &str = "# comment\n127.0.0.1 localhost\n\
        0.0.0.0\tAPI.TRAPD.EU. alias.example # blocked\n\
        ::1 localhost6\nnot-an-ip foo.bar\n   \n198.51.100.7 other.example\n";

    #[test]
    fn parses_hosts_with_aliases_comments_and_garbage() {
        let e = parse_hosts(HOSTS);
        assert!(e.contains(&HostsEntry {
            ip: "0.0.0.0".into(),
            host: "api.trapd.eu".into()
        }));
        assert!(e.iter().any(|x| x.host == "alias.example"));
        assert!(!e.iter().any(|x| x.host == "foo.bar"));
        assert_eq!(e.len(), 5);
    }

    #[test]
    fn hosts_redirect_of_backend_is_found_case_insensitively() {
        let e = parse_hosts(HOSTS);
        let hit = hosts_for(&e, "Api.Trapd.eu");
        assert_eq!(hit.len(), 1);
        assert_eq!(hit[0].ip, "0.0.0.0");
        assert!(hosts_for(&e, "trapd.eu").is_empty());
    }

    #[test]
    fn commented_out_entry_is_ignored() {
        assert!(parse_hosts("# 6.6.6.6 api.trapd.eu\n").is_empty());
    }

    #[test]
    fn https_server_selection() {
        assert_eq!(https_proxy_server("p:8080").as_deref(), Some("p:8080"));
        assert_eq!(
            https_proxy_server("http=a:1;https=b:2;ftp=c:3").as_deref(),
            Some("b:2")
        );
        assert_eq!(
            https_proxy_server("http=a:1;ftp=c:3").as_deref(),
            Some("a:1")
        );
        assert_eq!(https_proxy_server("  "), None);
    }

    #[test]
    fn bypass_rules() {
        let b = split_bypass("*.corp.example;<local>; .trapd.eu ,10.0.0.1");
        assert!(bypassed("x.corp.example", &b));
        assert!(bypassed("intranet", &b));
        assert!(bypassed("api.trapd.eu", &b));
        assert!(bypassed("10.0.0.1", &b));
        assert!(!bypassed("api.other.eu", &b));
        assert!(!bypassed("corp.example", &split_bypass("*.corp.example")));
    }

    #[test]
    fn proxy_applies_unless_bypassed() {
        let mut cfg = ProxyConfig {
            source: "env",
            server: "http://evil:3128".into(),
            bypass: vec![],
        };
        assert!(proxy_applies(&cfg, "api.trapd.eu"));
        cfg.bypass = vec!["api.trapd.eu".into()];
        assert!(!proxy_applies(&cfg, "api.trapd.eu"));
    }

    #[test]
    fn env_proxy_reads_https_then_all_and_ignores_empty() {
        let env = |k: &str| match k {
            "https_proxy" => Some("http://p:1".to_string()),
            "NO_PROXY" => Some("a.example,b.example".to_string()),
            _ => None,
        };
        let c = env_proxy(env).unwrap();
        assert_eq!(c.server, "http://p:1");
        assert_eq!(c.bypass.len(), 2);
        assert!(env_proxy(|_| Some("  ".into())).is_none());
        assert!(env_proxy(|_| None).is_none());
    }

    fn winhttp_blob(flags: u32, proxy: &str, bypass: &str) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&0x46u32.to_le_bytes());
        b.extend_from_slice(&1u32.to_le_bytes());
        b.extend_from_slice(&flags.to_le_bytes());
        b.extend_from_slice(&(proxy.len() as u32).to_le_bytes());
        b.extend_from_slice(proxy.as_bytes());
        b.extend_from_slice(&(bypass.len() as u32).to_le_bytes());
        b.extend_from_slice(bypass.as_bytes());
        b
    }

    #[test]
    fn winhttp_blob_with_named_proxy() {
        let c =
            parse_winhttp_settings(&winhttp_blob(0x03, "proxy:8080", "<local>;*.corp")).unwrap();
        assert_eq!(c.server, "proxy:8080");
        assert_eq!(c.bypass, ["<local>", "*.corp"]);
        assert_eq!(c.source, "winhttp");
    }

    #[test]
    fn winhttp_blob_direct_or_truncated_is_none() {
        assert!(parse_winhttp_settings(&winhttp_blob(0x01, "", "")).is_none());
        let mut b = winhttp_blob(0x03, "proxy:8080", "x");
        b.truncate(20);
        assert!(parse_winhttp_settings(&b).is_none());
        assert!(parse_winhttp_settings(&[0u8; 3]).is_none());
        // Hostile length field must not overflow or allocate.
        let mut b = winhttp_blob(0x03, "p", "");
        b[12..16].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(parse_winhttp_settings(&b).is_none());
    }

    #[test]
    fn nrpt_namespace_matching() {
        assert!(nrpt_applies(".trapd.eu", "api.trapd.eu"));
        assert!(nrpt_applies("api.trapd.eu", "API.trapd.eu."));
        assert!(!nrpt_applies("trapd.eu", "api.trapd.eu"));
        assert!(!nrpt_applies(".", "api.trapd.eu"));
        assert!(!nrpt_applies(".other.eu", "api.trapd.eu"));
        assert!(!nrpt_applies("", "api.trapd.eu"));
    }
}
