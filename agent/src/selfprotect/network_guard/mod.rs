//! Network guard (phase 09, layer L4): detects attempts to silence or redirect
//! the agent's channel to the backend.
//!
//! | Finding (rule id)                          | Source |
//! |--------------------------------------------|--------|
//! | `selfprotect.network_silenced`             | WFP block filters (Windows; covers Windows Firewall rules, which are WFP filters), nftables / iptables rules (Linux) matching our app id / UID / cgroup / backend address |
//! | `selfprotect.backend_redirected`           | hosts-file entry, proxy (env, WinHTTP, WinINET), NRPT rule for the backend host |
//! | `selfprotect.tls_pin_mismatch`             | [`tls_pin`] verifier refused the chain |
//! | `selfprotect.backend_unreachable_selective`| backend down while an operator-configured neutral probe is up |
//!
//! Events travel through the normal pipeline into the persistent spool, so
//! findings raised while the backend cannot be reached are delivered as soon
//! as it can.
//!
//! False positives: every finding that can be legitimate (admin firewall
//! rules, corporate proxy, on-prem hosts entry) can be listed in the `allow`
//! setting ([`settings`]); the whole guard can be switched off.
//!
//! Selective-unreachability probe privacy: the probe is a request from every
//! host to a URL the tenant chooses and reveals the host's public IP to that
//! server. TRAPD is EU-first and does not phone third parties by default, so
//! the probe is off unless `probe_url` is set; point it at an endpoint the
//! tenant or an EU provider operates. The request carries no identifiers: a
//! bare `HEAD` with the generic agent User-Agent, over HTTPS only.

// Compiled everywhere so the pure logic is unit-tested on Linux; some readers
// exist for one OS only.
#![cfg_attr(not(any(windows, target_os = "linux")), allow(dead_code))]
#![allow(dead_code)]

pub mod findings;
pub mod linux_fw;
pub mod matching;
pub mod redirect;
pub mod settings;
pub mod signed_pins;
pub mod tls_pin;
#[cfg(windows)]
mod windows_net;
#[cfg(windows)]
mod windows_wfp;

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use tokio::sync::mpsc::Sender;
use tokio::sync::Notify;
#[cfg(target_os = "linux")]
use tracing::debug;
use tracing::{info, warn};
use trapd_schema::{AgentEvent, Severity};

use crate::collectors::Collector;
use findings::{Finding, Reported, SelectiveTracker};
use matching::Targets;
use settings::Settings;

const FIRST_SCAN_DELAY: Duration = Duration::from_secs(20);
const SCAN_INTERVAL: Duration = Duration::from_secs(60);
/// Filter-change notifications closer together than this share one scan.
const MIN_SCAN_GAP: Duration = Duration::from_secs(5);
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);
const TOOL_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_TOOL_OUTPUT: usize = 8 * 1024 * 1024;
const MAX_HOSTS_BYTES: u64 = 1024 * 1024;

/// Host and port of the backend the agent talks to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendTarget {
    pub host: String,
    pub port: u16,
    pub url: String,
}

pub fn parse_backend(url: &str) -> Option<BackendTarget> {
    let u = reqwest::Url::parse(url.trim()).ok()?;
    Some(BackendTarget {
        host: u.host_str()?.to_string(),
        port: u.port_or_known_default()?,
        url: crate::http::normalize_base_url(url),
    })
}

/// A probe URL must be HTTPS without credentials; anything else is ignored.
pub fn valid_probe_url(raw: &str) -> Option<reqwest::Url> {
    let u = reqwest::Url::parse(raw.trim()).ok()?;
    (u.scheme() == "https"
        && u.username().is_empty()
        && u.password().is_none()
        && u.host().is_some())
    .then_some(u)
}

pub struct NetworkGuard {
    backend_url: String,
}

impl NetworkGuard {
    pub fn new(backend_url: &str) -> Self {
        Self {
            backend_url: backend_url.to_string(),
        }
    }
}

#[async_trait]
impl Collector for NetworkGuard {
    fn name(&self) -> &'static str {
        "NetworkGuard"
    }

    async fn run(
        &mut self,
        tx: Sender<AgentEvent>,
        agent_id: String,
        hostname: String,
    ) -> Result<()> {
        let settings = match Settings::load() {
            Ok(s) => s,
            Err(e) => {
                warn!(error = %e, "network guard settings unreadable; using defaults");
                Settings::default()
            }
        };
        if !settings.enabled {
            info!("network guard disabled by configuration");
            return Ok(());
        }
        let Some(backend) = parse_backend(&self.backend_url) else {
            warn!("network guard: backend URL has no host; guard not started");
            return Ok(());
        };
        let probe = settings.probe_url.as_deref().and_then(|raw| {
            let u = valid_probe_url(raw);
            if u.is_none() {
                warn!("network guard: probe_url must be an https URL without credentials; probe disabled");
            }
            u
        });

        let wake = Arc::new(Notify::new());
        #[cfg(windows)]
        let _subscription = windows_wfp::subscribe(Arc::clone(&wake));
        #[cfg(windows)]
        if _subscription.is_none() {
            warn!("network guard: WFP change subscription unavailable; relying on periodic scans");
        }

        let mut reported = Reported::default();
        let mut selective = SelectiveTracker::default();
        let mut selective_reported = false;
        let mut observed_written = Vec::<String>::new();
        let mut wait = FIRST_SCAN_DELAY;
        loop {
            tokio::select! {
                _ = tokio::time::sleep(wait) => {}
                _ = wake.notified() => {
                    // Let a burst of filter changes settle.
                    tokio::time::sleep(MIN_SCAN_GAP).await;
                }
                _ = tx.closed() => return Ok(()),
            }
            wait = SCAN_INTERVAL;

            let targets = collect_targets(&backend).await;
            let mut found = scan(&settings, &backend, &targets).await;
            for m in tls_pin::global().take_mismatches() {
                found.push(Finding::PinMismatch(m));
            }
            if let Some(n) = tls_pin::global().take_pins_removed(&signed_pins::high_water_path()) {
                found.push(Finding::PinsRemoved {
                    enforced_pins: n.enforced_pins,
                });
            }
            if let Some(probe) = &probe {
                let backend_ok = backend_reachable(&backend).await;
                let probe_ok = probe_reachable(probe).await;
                if selective.observe(backend_ok, probe_ok) && !selective_reported {
                    selective_reported = true;
                    found.push(Finding::UnreachableSelective {
                        backend: backend.host.clone(),
                        probe: probe.host_str().unwrap_or("").to_string(),
                    });
                } else if backend_ok {
                    selective_reported = false;
                }
            }
            let fresh = reported.fresh(found);
            for f in fresh {
                warn!(rule = %f.detection().rule_id, subject = %f.detection().subject, "network guard finding");
                if tx.send(f.to_event(&agent_id, &hostname)).await.is_err() {
                    return Ok(());
                }
            }
            persist_observed_pins(&mut observed_written);
        }
    }
}

/// Run one scan and drop what the operator allowlisted.
async fn scan(settings: &Settings, backend: &BackendTarget, targets: &Targets) -> Vec<Finding> {
    let mut found = firewall_findings(targets).await;
    found.extend(redirect_findings(backend).await);
    found.retain(|f| !f.allow_keys().iter().any(|k| settings.allows(k)));
    found
}

async fn collect_targets(backend: &BackendTarget) -> Targets {
    let mut t = Targets::default();
    #[cfg(windows)]
    if let Ok(exe) = std::env::current_exe() {
        t.app_ids.extend(windows_wfp::app_id_for_path(&exe));
    }
    #[cfg(target_os = "linux")]
    {
        // SAFETY: geteuid has no preconditions.
        t.uid = Some(unsafe { libc::geteuid() });
        if let Some(path) = std::fs::read_to_string("/proc/self/cgroup")
            .ok()
            .as_deref()
            .and_then(own_cgroup_path)
        {
            use std::os::unix::fs::MetadataExt;
            t.cgroup_id = std::fs::metadata(format!("/sys/fs/cgroup/{path}"))
                .ok()
                .map(|m| m.ino());
            t.cgroup_path = Some(path);
        }
    }
    t.backend_ips = resolve_backend_ips(backend).await;
    t
}

/// cgroup v2 path (no leading slash) from `/proc/self/cgroup` content.
pub fn own_cgroup_path(proc_cgroup: &str) -> Option<String> {
    let line = proc_cgroup.lines().find(|l| l.starts_with("0::"))?;
    let p = line.strip_prefix("0::")?.trim().trim_matches('/');
    (!p.is_empty()).then(|| p.to_string())
}

async fn resolve_backend_ips(backend: &BackendTarget) -> Vec<std::net::IpAddr> {
    match tokio::time::timeout(
        PROBE_TIMEOUT,
        tokio::net::lookup_host((backend.host.as_str(), backend.port)),
    )
    .await
    {
        Ok(Ok(addrs)) => addrs.map(|a| a.ip()).collect(),
        _ => vec![],
    }
}

// --- firewall readers -----------------------------------------------------

#[cfg(windows)]
async fn firewall_findings(targets: &Targets) -> Vec<Finding> {
    let t = targets.clone();
    match tokio::task::spawn_blocking(move || windows_wfp::blocking_filters(&t)).await {
        Ok(Ok(hits)) => hits
            .into_iter()
            .map(|(filter, reason)| Finding::Silenced { filter, reason })
            .collect(),
        Ok(Err(rc)) => {
            warn!(status = rc, "network guard: WFP enumeration failed");
            vec![]
        }
        Err(e) => {
            warn!(error = %e, "network guard: WFP scan task failed");
            vec![]
        }
    }
}

#[cfg(target_os = "linux")]
async fn firewall_findings(targets: &Targets) -> Vec<Finding> {
    let mut rules = Vec::new();
    if let Some(out) = run_tool("nft", &["-j", "list", "ruleset"]).await {
        rules.extend(linux_fw::parse_nft_json(&out));
    }
    for tool in ["iptables-save", "ip6tables-save"] {
        if let Some(out) = run_tool(tool, &[]).await {
            rules.extend(linux_fw::parse_iptables_save(&out));
        }
    }
    rules
        .into_iter()
        .filter_map(|filter| {
            matching::blocks_us(&filter, targets).map(|reason| Finding::Silenced { filter, reason })
        })
        .collect()
}

/// Run a firewall tool from a fixed set of system directories (not `PATH`).
/// A missing tool, a permission error or a timeout is simply "no data".
#[cfg(target_os = "linux")]
async fn run_tool(name: &str, args: &[&str]) -> Option<String> {
    let bin = ["/usr/sbin", "/sbin", "/usr/bin", "/bin"]
        .iter()
        .map(|d| std::path::Path::new(d).join(name))
        .find(|p| p.is_file())?;
    let out = tokio::time::timeout(
        TOOL_TIMEOUT,
        tokio::process::Command::new(bin)
            .args(args)
            .kill_on_drop(true)
            .output(),
    )
    .await
    .ok()?
    .ok()?;
    if !out.status.success() || out.stdout.len() > MAX_TOOL_OUTPUT {
        debug!(
            tool = name,
            "network guard: firewall tool gave no usable output"
        );
        return None;
    }
    String::from_utf8(out.stdout).ok()
}

// --- redirect readers -----------------------------------------------------

fn hosts_path() -> std::path::PathBuf {
    #[cfg(windows)]
    {
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
        std::path::PathBuf::from(root).join(r"System32\drivers\etc\hosts")
    }
    #[cfg(not(windows))]
    {
        std::path::PathBuf::from("/etc/hosts")
    }
}

async fn redirect_findings(backend: &BackendTarget) -> Vec<Finding> {
    let host = backend.host.clone();
    tokio::task::spawn_blocking(move || redirect_findings_blocking(&host))
        .await
        .unwrap_or_default()
}

fn redirect_findings_blocking(host: &str) -> Vec<Finding> {
    let mut out = Vec::new();

    let path = hosts_path();
    if std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0) <= MAX_HOSTS_BYTES {
        if let Ok(text) = std::fs::read_to_string(&path) {
            let entries = redirect::parse_hosts(&text);
            for e in redirect::hosts_for(&entries, host) {
                out.push(Finding::Redirected {
                    vector: "hosts",
                    subject: format!("{} {}", e.ip, e.host),
                    detail: format!("The hosts file maps the backend host to {}", e.ip),
                    allow_keys: vec![e.ip.clone(), format!("{} {}", e.ip, e.host)],
                    severity: Severity::High,
                });
            }
        }
    }

    #[cfg_attr(not(windows), allow(unused_mut))]
    let mut proxies: Vec<redirect::ProxyConfig> = redirect::env_proxy(|k| std::env::var(k).ok())
        .into_iter()
        .collect();
    #[cfg(windows)]
    proxies.extend(windows_net::proxies());
    for p in proxies {
        if redirect::proxy_applies(&p, host) {
            out.push(Finding::Redirected {
                vector: match p.source {
                    "env" => "proxy_env",
                    "winhttp" => "proxy_winhttp",
                    _ => "proxy_wininet",
                },
                subject: p.server.clone(),
                detail: format!(
                    "A {} proxy setting routes backend traffic through {}",
                    p.source, p.server
                ),
                allow_keys: vec![p.server.clone()],
                severity: Severity::Medium,
            });
        }
    }

    #[cfg(windows)]
    for rule in windows_net::nrpt_rules() {
        for ns in &rule.namespaces {
            if redirect::nrpt_applies(ns, host) {
                out.push(Finding::Redirected {
                    vector: "nrpt",
                    subject: ns.clone(),
                    detail: format!(
                        "A DNS policy (NRPT) rule for {ns} resolves the backend via {}",
                        if rule.servers.is_empty() {
                            "a policy-defined server"
                        } else {
                            &rule.servers
                        }
                    ),
                    allow_keys: vec![ns.clone(), rule.servers.clone()],
                    severity: Severity::High,
                });
            }
        }
    }
    out
}

// --- reachability probes ----------------------------------------------------

/// Any HTTP answer, including 401/404, proves the backend is reachable; only a
/// transport failure counts as unreachable.
async fn backend_reachable(backend: &BackendTarget) -> bool {
    let Ok(client) = crate::http::control_client() else {
        return false;
    };
    client
        .head(&backend.url)
        .timeout(PROBE_TIMEOUT)
        .send()
        .await
        .is_ok()
}

async fn probe_reachable(url: &reqwest::Url) -> bool {
    let Ok(client) = reqwest::Client::builder()
        .user_agent("trapd-agent")
        .timeout(PROBE_TIMEOUT)
        .build()
    else {
        return false;
    };
    client.head(url.clone()).send().await.is_ok()
}

// --- report-only pin observation ----------------------------------------------

/// In report-only mode, keep the SPKI hashes the backend presented on disk so
/// an operator can turn them into the pin list.
fn persist_observed_pins(written: &mut Vec<String>) {
    let state = tls_pin::global();
    if state.policy().enforce {
        return;
    }
    let pins = state.observed_pins();
    if pins.is_empty() || pins == *written {
        return;
    }
    let doc = serde_json::json!({ "observed_spki_sha256": pins });
    let path = crate::paths::state_dir().join("observed_spki_pins.json");
    match serde_json::to_vec_pretty(&doc)
        .map_err(anyhow::Error::from)
        .and_then(|b| crate::paths::write_atomic(&path, &b, 0o600))
    {
        Ok(()) => {
            info!(pins = ?pins, file = %path.display(), "TLS: observed backend SPKI pins (report-only)");
            *written = pins;
        }
        Err(e) => warn!(error = %e, "could not persist observed SPKI pins"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backend_url_parsing() {
        let b = parse_backend(" https://api.trapd.eu/ ").unwrap();
        assert_eq!(b.host, "api.trapd.eu");
        assert_eq!(b.port, 443);
        assert_eq!(b.url, "https://api.trapd.eu");
        assert_eq!(parse_backend("http://10.0.0.5:8080").unwrap().port, 8080);
        assert!(parse_backend("not a url").is_none());
    }

    #[test]
    fn probe_url_must_be_plain_https() {
        assert!(valid_probe_url("https://probe.example.eu/ping").is_some());
        assert!(valid_probe_url("http://probe.example.eu").is_none());
        assert!(valid_probe_url("https://user:pw@probe.example.eu").is_none());
        assert!(valid_probe_url("ftp://x").is_none());
        assert!(valid_probe_url("").is_none());
    }

    #[test]
    fn cgroup_path_from_proc() {
        assert_eq!(
            own_cgroup_path("0::/system.slice/trapd-agent.service\n").as_deref(),
            Some("system.slice/trapd-agent.service")
        );
        assert_eq!(own_cgroup_path("12:cpu:/x\n"), None, "cgroup v1 only");
        assert_eq!(own_cgroup_path("0::/\n"), None);
    }

    #[test]
    fn hosts_redirect_becomes_a_high_finding_with_allow_keys() {
        // Pure parts only: the file read is a thin wrapper.
        let entries = redirect::parse_hosts("203.0.113.66 api.trapd.eu\n");
        let hit = redirect::hosts_for(&entries, "api.trapd.eu");
        assert_eq!(hit.len(), 1);
        let s = Settings {
            allow: vec!["203.0.113.66".into()],
            ..Default::default()
        };
        assert!(s.allows(&hit[0].ip));
    }
}
