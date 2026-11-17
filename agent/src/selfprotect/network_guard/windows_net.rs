//! Windows readers for backend-redirection settings: WinHTTP / WinINET proxy
//! and NRPT (DNS policy) rules. Parsing and matching are in `redirect.rs`.

use windows_sys::Win32::System::Registry::{
    RegGetValueW, HKEY, HKEY_LOCAL_MACHINE, RRF_RT_REG_BINARY, RRF_RT_REG_MULTI_SZ, RRF_RT_REG_SZ,
};

use super::redirect::{
    https_proxy_server, parse_winhttp_settings, split_bypass, utf16_multi_sz, ProxyConfig,
};
use crate::collectors::windows::registry::{self, Hive};

const INTERNET_SETTINGS: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings";
const NRPT_KEYS: [&str; 2] = [
    r"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig",
    r"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig",
];

fn reg_raw(root: HKEY, path: &str, name: &str, flags: u32) -> Option<Vec<u8>> {
    let path: Vec<u16> = path.encode_utf16().chain(Some(0)).collect();
    let name: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
    let mut size = 0u32;
    // SAFETY: terminated strings; a null data pointer queries the size.
    let rc = unsafe {
        RegGetValueW(
            root,
            path.as_ptr(),
            name.as_ptr(),
            flags,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut size,
        )
    };
    if rc != 0 || size == 0 || size > 65_536 {
        return None;
    }
    let mut buf = vec![0u8; size as usize];
    // SAFETY: buffer capacity is the size the first call reported.
    let rc = unsafe {
        RegGetValueW(
            root,
            path.as_ptr(),
            name.as_ptr(),
            flags,
            std::ptr::null_mut(),
            buf.as_mut_ptr().cast(),
            &mut size,
        )
    };
    if rc != 0 {
        return None;
    }
    buf.truncate(size as usize);
    Some(buf)
}

/// Machine-wide WinHTTP proxy plus WinINET proxies of every loaded profile
/// (including SYSTEM, whose settings the service's own HTTP stack reads).
pub fn proxies() -> Vec<ProxyConfig> {
    let mut out = Vec::new();
    if let Some(blob) = reg_raw(
        HKEY_LOCAL_MACHINE,
        &format!(r"{INTERNET_SETTINGS}\Connections"),
        "WinHttpSettings",
        RRF_RT_REG_BINARY,
    ) {
        out.extend(parse_winhttp_settings(&blob));
    }
    let mut sids = vec![".DEFAULT".to_string()];
    sids.extend(
        registry::subkeys_in(Hive::Users, "", 0)
            .into_iter()
            .filter(|s| s.starts_with("S-1-5-") && !s.ends_with("_Classes")),
    );
    for sid in sids {
        let path = format!(r"{sid}\{INTERNET_SETTINGS}");
        if registry::dword_in(Hive::Users, &path, "ProxyEnable", 0) == Some(1) {
            if let Some(server) = registry::string_in(Hive::Users, &path, "ProxyServer", 0)
                .and_then(|s| https_proxy_server(&s))
            {
                out.push(ProxyConfig {
                    source: "wininet",
                    server,
                    bypass: registry::string_in(Hive::Users, &path, "ProxyOverride", 0)
                        .map(|b| split_bypass(&b))
                        .unwrap_or_default(),
                });
            }
        }
        if let Some(pac) = registry::string_in(Hive::Users, &path, "AutoConfigURL", 0)
            .filter(|s| !s.trim().is_empty())
        {
            out.push(ProxyConfig {
                source: "wininet",
                server: format!("pac:{pac}"),
                bypass: vec![],
            });
        }
    }
    out
}

/// One NRPT rule: its namespaces and the DNS servers it forces.
pub struct NrptRule {
    pub namespaces: Vec<String>,
    pub servers: String,
}

pub fn nrpt_rules() -> Vec<NrptRule> {
    let mut out = Vec::new();
    for base in NRPT_KEYS {
        for sub in registry::subkeys(base, 0) {
            let path = format!(r"{base}\{sub}");
            let namespaces = reg_raw(
                HKEY_LOCAL_MACHINE,
                &path,
                "Name",
                RRF_RT_REG_MULTI_SZ | RRF_RT_REG_SZ,
            )
            .map(|b| utf16_multi_sz(&b))
            .unwrap_or_default();
            if namespaces.is_empty() {
                continue;
            }
            out.push(NrptRule {
                namespaces,
                servers: registry::string(&path, "GenericDNSServers", 0).unwrap_or_default(),
            });
        }
    }
    out
}
