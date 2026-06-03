//! Vulnerability & compliance assessment for the asset inventory.
//!
//! Three self-contained, offline analyses over the data the inventory already
//! gathers:
//!
//!   * **SBOM** — a CycloneDX 1.5 software bill of materials built from the
//!     installed-package list (`purl` per component).
//!   * **CVE correlation** — installed packages matched against a local feed
//!     (`<config>/cve_feed.json`); a package whose version is below a feed
//!     entry's fixed version is reported as vulnerable.
//!   * **CIS-style hardening checks** — a representative set of host checks
//!     (SSH config, sensitive-file permissions, kernel hardening sysctls).
//!
//! Everything is read-only and dependency-light, so it runs inside the normal
//! inventory snapshot.

use serde::Serialize;

use super::{OsInfo, SoftwarePackage};

/// What to compute (mirrors the `vuln_scan_enabled` / `cis_benchmark_enabled`
/// config switches).
#[derive(Debug, Clone, Copy)]
pub struct ComplianceFlags {
    pub vuln_scan: bool,
    pub cis: bool,
}

impl Default for ComplianceFlags {
    fn default() -> Self {
        Self { vuln_scan: true, cis: true }
    }
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct ComplianceReport {
    pub sbom: Sbom,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub vulnerabilities: Vec<VulnFinding>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub cis_findings: Vec<CisFinding>,
    /// Count of CIS checks that failed (quick backend triage signal).
    pub cis_fail_count: usize,
}

// ── CycloneDX SBOM ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct Sbom {
    #[serde(rename = "bomFormat")]
    pub bom_format: String,
    #[serde(rename = "specVersion")]
    pub spec_version: String,
    pub version: u32,
    pub components: Vec<SbomComponent>,
}

impl Default for Sbom {
    fn default() -> Self {
        Self {
            bom_format: "CycloneDX".into(),
            spec_version: "1.5".into(),
            version: 1,
            components: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct SbomComponent {
    #[serde(rename = "type")]
    pub component_type: String,
    pub name: String,
    pub version: String,
    pub purl: String,
}

/// Build a CycloneDX SBOM from the package list. `pkg_type` is the package
/// universe for the purl (`deb`, `rpm`, …) derived from the inventory source.
pub fn build_sbom(packages: &[SoftwarePackage], pkg_type: &str) -> Sbom {
    let components = packages
        .iter()
        .map(|p| {
            let arch = p
                .architecture
                .as_deref()
                .map(|a| format!("?arch={a}"))
                .unwrap_or_default();
            SbomComponent {
                component_type: "library".into(),
                name: p.name.clone(),
                version: p.version.clone(),
                purl: format!("pkg:{pkg_type}/{}@{}{arch}", p.name, p.version),
            }
        })
        .collect();
    Sbom { components, ..Default::default() }
}

/// Map the inventory `source` (dpkg/rpm/…) to a purl package type.
pub fn purl_type(source: &str) -> &'static str {
    match source {
        "dpkg" => "deb",
        "rpm" => "rpm",
        "pacman" => "alpm",
        "apk" => "apk",
        _ => "generic",
    }
}

// ── CVE correlation ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct VulnFinding {
    pub package: String,
    pub installed_version: String,
    pub cve: String,
    pub severity: String,
    pub fixed_in: String,
}

/// One entry in `<config>/cve_feed.json`.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct CveEntry {
    pub product: String,
    /// Versions strictly below this are vulnerable.
    pub fixed_in: String,
    pub cve: String,
    #[serde(default = "default_severity")]
    pub severity: String,
}

fn default_severity() -> String {
    "unknown".into()
}

#[derive(Debug, Clone, serde::Deserialize, Default)]
pub struct CveFeed {
    #[serde(default)]
    pub entries: Vec<CveEntry>,
}

/// Correlate installed packages against the CVE feed. A package matches a feed
/// entry by exact (case-insensitive) name; it is reported when its version is
/// strictly below `fixed_in`.
pub fn correlate_cves(packages: &[SoftwarePackage], feed: &CveFeed) -> Vec<VulnFinding> {
    let mut out = Vec::new();
    for entry in &feed.entries {
        for pkg in packages {
            if pkg.name.eq_ignore_ascii_case(&entry.product)
                && version_less_than(&pkg.version, &entry.fixed_in)
            {
                out.push(VulnFinding {
                    package: pkg.name.clone(),
                    installed_version: pkg.version.clone(),
                    cve: entry.cve.clone(),
                    severity: entry.severity.clone(),
                    fixed_in: entry.fixed_in.clone(),
                });
            }
        }
    }
    out
}

/// Compare two version strings component-wise: split on non-alphanumeric
/// boundaries, compare numeric chunks numerically and the rest lexically. Good
/// enough for "is the installed version older than the fix" without a full
/// dpkg/rpm version-compare implementation.
pub fn version_less_than(a: &str, b: &str) -> bool {
    let norm = |s: &str| -> Vec<String> {
        // Strip a Debian epoch (`1:`) and split into numeric / non-numeric runs.
        let s = s.split_once(':').map(|(_, r)| r).unwrap_or(s);
        let mut parts = Vec::new();
        let mut cur = String::new();
        let mut cur_numeric = None;
        for c in s.chars() {
            if c == '.' || c == '-' || c == '+' || c == '~' {
                if !cur.is_empty() {
                    parts.push(std::mem::take(&mut cur));
                    cur_numeric = None;
                }
                continue;
            }
            let is_num = c.is_ascii_digit();
            if cur_numeric.is_some_and(|n| n != is_num) {
                parts.push(std::mem::take(&mut cur));
            }
            cur.push(c);
            cur_numeric = Some(is_num);
        }
        if !cur.is_empty() {
            parts.push(cur);
        }
        parts
    };

    let pa = norm(a);
    let pb = norm(b);
    for i in 0..pa.len().max(pb.len()) {
        let x = pa.get(i).map(String::as_str).unwrap_or("0");
        let y = pb.get(i).map(String::as_str).unwrap_or("0");
        match (x.parse::<u64>(), y.parse::<u64>()) {
            (Ok(nx), Ok(ny)) => {
                if nx != ny {
                    return nx < ny;
                }
            }
            _ => {
                if x != y {
                    return x < y;
                }
            }
        }
    }
    false
}

// ── CIS-style hardening checks ───────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct CisFinding {
    pub id: String,
    pub title: String,
    /// CIS level (1 = baseline, 2 = defence-in-depth).
    pub level: u8,
    /// `pass`, `fail`, or `not_applicable`.
    pub status: String,
    pub detail: String,
}

impl CisFinding {
    fn new(id: &str, title: &str, level: u8, status: &str, detail: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            title: title.into(),
            level,
            status: status.into(),
            detail: detail.into(),
        }
    }
}

/// Read a file, returning `None` if it is absent/unreadable.
fn read(path: &str) -> Option<String> {
    std::fs::read_to_string(path).ok()
}

/// Last effective value for an sshd_config directive (case-insensitive key).
fn sshd_directive(cfg: &str, key: &str) -> Option<String> {
    let mut val = None;
    for line in cfg.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        let mut it = line.split_whitespace();
        if let (Some(k), Some(v)) = (it.next(), it.next()) {
            if k.eq_ignore_ascii_case(key) {
                val = Some(v.to_string());
            }
        }
    }
    val
}

/// Pure boolean → finding helper for sysctl-style checks.
fn sysctl_check(id: &str, title: &str, level: u8, path: &str, want: &str) -> CisFinding {
    match read(path) {
        Some(v) => {
            let got = v.trim();
            let status = if got == want { "pass" } else { "fail" };
            CisFinding::new(id, title, level, status, format!("{path} = {got} (want {want})"))
        }
        None => CisFinding::new(id, title, level, "not_applicable", format!("{path} unreadable")),
    }
}

/// Run the built-in CIS-style checks against the live host.
pub fn cis_checks() -> Vec<CisFinding> {
    let mut out = Vec::new();

    // 1.x — kernel hardening sysctls.
    out.push(sysctl_check(
        "1.5.1",
        "Ensure ASLR is enabled",
        1,
        "/proc/sys/kernel/randomize_va_space",
        "2",
    ));
    out.push(sysctl_check(
        "1.5.3",
        "Ensure core dumps from setuid programs are disabled",
        1,
        "/proc/sys/fs/suid_dumpable",
        "0",
    ));
    out.push(sysctl_check(
        "3.2.1",
        "Ensure IP forwarding is disabled",
        1,
        "/proc/sys/net/ipv4/ip_forward",
        "0",
    ));

    // 5.2 — SSH server hardening.
    if let Some(cfg) = read("/etc/ssh/sshd_config") {
        let root = sshd_directive(&cfg, "PermitRootLogin").unwrap_or_else(|| "yes".into());
        let status = if root.eq_ignore_ascii_case("no") || root.eq_ignore_ascii_case("prohibit-password") {
            "pass"
        } else {
            "fail"
        };
        out.push(CisFinding::new(
            "5.2.8",
            "Ensure SSH root login is disabled",
            1,
            status,
            format!("PermitRootLogin = {root}"),
        ));

        let pw = sshd_directive(&cfg, "PasswordAuthentication").unwrap_or_else(|| "yes".into());
        let status = if pw.eq_ignore_ascii_case("no") { "pass" } else { "fail" };
        out.push(CisFinding::new(
            "5.2.10",
            "Ensure SSH password authentication is disabled",
            2,
            status,
            format!("PasswordAuthentication = {pw}"),
        ));
    } else {
        out.push(CisFinding::new(
            "5.2.8",
            "Ensure SSH root login is disabled",
            1,
            "not_applicable",
            "no /etc/ssh/sshd_config",
        ));
    }

    // 6.1 — sensitive-file permissions.
    out.push(perm_check("6.1.2", "Ensure permissions on /etc/passwd are 644 or stricter", "/etc/passwd", 0o644));
    out.push(perm_check("6.1.4", "Ensure permissions on /etc/shadow are 640 or stricter", "/etc/shadow", 0o640));

    out
}

/// Permission check: the file's mode bits must be no broader than `max_mode`.
fn perm_check(id: &str, title: &str, path: &str, max_mode: u32) -> CisFinding {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        match std::fs::metadata(path) {
            Ok(md) => {
                let mode = md.permissions().mode() & 0o777;
                let status = if mode & !max_mode == 0 { "pass" } else { "fail" };
                CisFinding::new(id, title, 1, status, format!("{path} mode = {mode:04o} (max {max_mode:04o})"))
            }
            Err(_) => CisFinding::new(id, title, 1, "not_applicable", format!("{path} absent")),
        }
    }
    #[cfg(not(unix))]
    {
        CisFinding::new(id, title, 1, "not_applicable", "non-unix host")
    }
}

// ── Top-level assessment ─────────────────────────────────────────────────────

/// Load the CVE feed from the config dir (absent → empty).
fn load_cve_feed() -> CveFeed {
    let path = crate::paths::config_dir().join("cve_feed.json");
    match std::fs::read(&path) {
        Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_default(),
        Err(_) => CveFeed::default(),
    }
}

/// Produce the full compliance report for a snapshot.
pub fn assess(
    packages: &[SoftwarePackage],
    source: &str,
    _os: &OsInfo,
    flags: ComplianceFlags,
) -> ComplianceReport {
    let sbom = build_sbom(packages, purl_type(source));

    let vulnerabilities = if flags.vuln_scan {
        correlate_cves(packages, &load_cve_feed())
    } else {
        Vec::new()
    };

    let cis_findings = if flags.cis { cis_checks() } else { Vec::new() };
    let cis_fail_count = cis_findings.iter().filter(|f| f.status == "fail").count();

    ComplianceReport { sbom, vulnerabilities, cis_findings, cis_fail_count }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pkg(name: &str, ver: &str) -> SoftwarePackage {
        SoftwarePackage { name: name.into(), version: ver.into(), architecture: Some("amd64".into()) }
    }

    #[test]
    fn sbom_emits_cyclonedx_with_purls() {
        let s = build_sbom(&[pkg("openssl", "3.0.13")], "deb");
        assert_eq!(s.bom_format, "CycloneDX");
        assert_eq!(s.spec_version, "1.5");
        assert_eq!(s.components.len(), 1);
        assert_eq!(s.components[0].purl, "pkg:deb/openssl@3.0.13?arch=amd64");
    }

    #[test]
    fn version_compare_handles_numeric_and_epoch() {
        assert!(version_less_than("3.0.13", "3.0.14"));
        assert!(!version_less_than("3.0.14", "3.0.14"));
        assert!(!version_less_than("3.0.15", "3.0.14"));
        // Debian epoch is stripped.
        assert!(version_less_than("1:2.4.1", "2.4.2"));
        // Numeric chunks compare numerically (10 > 9), not lexically.
        assert!(version_less_than("1.9.0", "1.10.0"));
        assert!(!version_less_than("1.10.0", "1.9.0"));
    }

    #[test]
    fn cve_correlation_flags_old_versions_only() {
        let feed = CveFeed {
            entries: vec![CveEntry {
                product: "openssl".into(),
                fixed_in: "3.0.14".into(),
                cve: "CVE-2024-4741".into(),
                severity: "high".into(),
            }],
        };
        let vulnerable = correlate_cves(&[pkg("openssl", "3.0.13")], &feed);
        assert_eq!(vulnerable.len(), 1);
        assert_eq!(vulnerable[0].cve, "CVE-2024-4741");

        let patched = correlate_cves(&[pkg("openssl", "3.0.14")], &feed);
        assert!(patched.is_empty());
    }

    #[test]
    fn sshd_directive_takes_last_effective_value() {
        let cfg = "PermitRootLogin yes\n# comment\nPermitRootLogin no\n";
        assert_eq!(sshd_directive(cfg, "permitrootlogin").as_deref(), Some("no"));
        assert_eq!(sshd_directive(cfg, "Missing"), None);
    }

    #[test]
    fn cis_checks_run_and_classify() {
        // Always returns findings; each has a valid status.
        let findings = cis_checks();
        assert!(!findings.is_empty());
        for f in &findings {
            assert!(matches!(f.status.as_str(), "pass" | "fail" | "not_applicable"));
        }
    }
}
