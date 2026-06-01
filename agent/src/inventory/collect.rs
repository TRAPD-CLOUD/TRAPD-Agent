//! Linux inventory gathering.
//!
//! Every helper is best-effort and never panics: a missing file, an absent
//! package manager or an unreadable sysfs node degrades to `None` / an empty
//! list rather than failing the whole snapshot.  Synchronous IO throughout —
//! the caller runs this on the blocking pool.

use std::collections::BTreeMap;
use std::process::Command;

use sysinfo::{Disks, System};

use super::{
    DiskInfo, HardwareInfo, InventorySnapshot, NetInterface, OsInfo, SoftwareInventory,
    SoftwarePackage, UserAccount,
};

// v2 adds the deception `recon_profile` field derived from users + software.
const SCHEMA_VERSION: u32 = 2;

/// Build a full inventory snapshot for this host.
pub fn gather(agent_id: String, device_id: String, hostname: String) -> InventorySnapshot {
    let mut sys = System::new();
    sys.refresh_memory();
    sys.refresh_cpu();

    let software = gather_software();
    let users = gather_users();
    let network = gather_network();
    // Condense the observed context into honeytoken candidates. Pure heuristics
    // over the data just gathered, plus cheap on-host stat()s for plausibility.
    // Host facts (hostname + network) feed the persona so generated bait stays
    // internally consistent.
    let recon_profile =
        crate::deception::build_profile_with_host(&users, &software, &hostname, &network);

    InventorySnapshot {
        schema_version: SCHEMA_VERSION,
        agent_id,
        device_id,
        hostname,
        agent_version: env!("CARGO_PKG_VERSION").to_string(),
        collected_at: chrono::Utc::now(),
        os: gather_os(),
        hardware: gather_hardware(&sys),
        network,
        software,
        users,
        recon_profile,
    }
}

// ── OS ──────────────────────────────────────────────────────────────────────

fn gather_os() -> OsInfo {
    let osr = parse_os_release();
    OsInfo {
        family: "linux".to_string(),
        name: osr.get("NAME").cloned().unwrap_or_else(|| "Linux".to_string()),
        version: osr.get("VERSION_ID").cloned().unwrap_or_default(),
        pretty_name: osr
            .get("PRETTY_NAME")
            .cloned()
            .unwrap_or_else(|| "Linux".to_string()),
        kernel: System::kernel_version().unwrap_or_default(),
        arch: std::env::consts::ARCH.to_string(),
        machine_id: read_trim("/etc/machine-id").or_else(|| read_trim("/var/lib/dbus/machine-id")),
        timezone: read_trim("/etc/timezone").or_else(read_timezone_symlink),
        boot_time_unix: System::boot_time(),
        uptime_secs: System::uptime(),
    }
}

fn parse_os_release() -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    if let Ok(content) = std::fs::read_to_string("/etc/os-release") {
        for line in content.lines() {
            if let Some((k, v)) = line.split_once('=') {
                map.insert(k.trim().to_string(), v.trim().trim_matches('"').to_string());
            }
        }
    }
    map
}

fn read_timezone_symlink() -> Option<String> {
    // /etc/localtime -> /usr/share/zoneinfo/Europe/Berlin
    let target = std::fs::read_link("/etc/localtime").ok()?;
    let s = target.to_string_lossy();
    s.split("zoneinfo/").nth(1).map(|tz| tz.to_string())
}

// ── Hardware ────────────────────────────────────────────────────────────────

fn gather_hardware(sys: &System) -> HardwareInfo {
    let cpus = sys.cpus();
    let cpu_model = cpus
        .first()
        .map(|c| c.brand().trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string());

    HardwareInfo {
        vendor: dmi("sys_vendor"),
        product: dmi("product_name"),
        serial: dmi("product_serial"),
        bios_vendor: dmi("bios_vendor"),
        bios_version: dmi("bios_version"),
        chassis: chassis_type(),
        virtualization: detect_virtualization(),
        cpu_model,
        cpu_physical_cores: sys.physical_core_count().unwrap_or(cpus.len()),
        cpu_logical_cores: cpus.len(),
        memory_total_mb: sys.total_memory() / 1024 / 1024,
        swap_total_mb: sys.total_swap() / 1024 / 1024,
        disks: gather_disks(),
    }
}

fn gather_disks() -> Vec<DiskInfo> {
    let disks = Disks::new_with_refreshed_list();
    disks
        .iter()
        .map(|d| DiskInfo {
            device: d.name().to_string_lossy().into_owned(),
            mount_point: d.mount_point().to_string_lossy().into_owned(),
            fs_type: d.file_system().to_string_lossy().into_owned(),
            total_mb: d.total_space() / 1024 / 1024,
            available_mb: d.available_space() / 1024 / 1024,
            removable: d.is_removable(),
        })
        .collect()
}

/// Read a value from /sys/class/dmi/id (requires the field be world-readable;
/// serials are usually root-only and degrade to None for non-root runs).
fn dmi(field: &str) -> Option<String> {
    read_trim(&format!("/sys/class/dmi/id/{field}")).filter(|s| {
        !s.is_empty()
            && !s.eq_ignore_ascii_case("none")
            && !s.eq_ignore_ascii_case("to be filled by o.e.m.")
            && !s.eq_ignore_ascii_case("default string")
    })
}

fn chassis_type() -> Option<String> {
    // /sys/class/dmi/id/chassis_type is a SMBIOS integer code.
    let raw = read_trim("/sys/class/dmi/id/chassis_type")?;
    let code: u32 = raw.parse().ok()?;
    let label = match code {
        3 | 4 | 5 | 6 | 7 | 15 | 16 | 35 => "desktop",
        8 | 9 | 10 | 11 | 12 | 14 | 31 | 32 => "laptop",
        17 | 23 | 25 | 28 => "server",
        1 | 2 => "other",
        _ => "unknown",
    };
    Some(label.to_string())
}

/// Best-effort virtualization / container detection.
fn detect_virtualization() -> Option<String> {
    // WSL is the common case for this project's test machines.
    if let Some(kernel) = System::kernel_version() {
        if kernel.to_ascii_lowercase().contains("microsoft") {
            return Some("wsl".to_string());
        }
    }
    if std::path::Path::new("/.dockerenv").exists() {
        return Some("docker".to_string());
    }
    if let Some(v) = read_trim("/sys/class/dmi/id/product_name") {
        let lv = v.to_ascii_lowercase();
        if lv.contains("virtualbox") {
            return Some("virtualbox".to_string());
        }
        if lv.contains("vmware") {
            return Some("vmware".to_string());
        }
        if lv.contains("kvm") || lv.contains("qemu") {
            return Some("kvm".to_string());
        }
    }
    // systemd-detect-virt is the authoritative source when present.
    if let Some(out) = run_capture("systemd-detect-virt", &[]) {
        let v = out.trim().to_string();
        if !v.is_empty() && v != "none" {
            return Some(v);
        }
    }
    None
}

// ── Network ─────────────────────────────────────────────────────────────────

fn gather_network() -> Vec<NetInterface> {
    // Enumerate interfaces from sysfs (always present on Linux), then attach
    // IPv4/IPv6 addresses gathered via getifaddrs(3).  MAC + link-state come
    // straight from sysfs so we do not depend on a particular sysinfo version.
    let ip_map = ifaddr_ip_map();

    let mut out = Vec::new();
    let entries = match std::fs::read_dir("/sys/class/net") {
        Ok(e) => e,
        Err(_) => return out,
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let mac = read_trim(&format!("/sys/class/net/{name}/address"))
            .filter(|m| m != "00:00:00:00:00:00");
        let up = read_trim(&format!("/sys/class/net/{name}/operstate"))
            .map(|s| s == "up")
            .unwrap_or(false);
        let (ipv4, ipv6) = ip_map.get(&name).cloned().unwrap_or_default();
        out.push(NetInterface { name, mac, ipv4, ipv6, up });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

/// Map interface name -> (ipv4 list, ipv6 list) via getifaddrs(3).
#[allow(clippy::type_complexity)]
fn ifaddr_ip_map() -> std::collections::HashMap<String, (Vec<String>, Vec<String>)> {
    let mut map: std::collections::HashMap<String, (Vec<String>, Vec<String>)> =
        std::collections::HashMap::new();
    let addrs = match nix::ifaddrs::getifaddrs() {
        Ok(a) => a,
        Err(_) => return map,
    };
    for ifa in addrs {
        let Some(storage) = ifa.address else { continue };
        let entry = map.entry(ifa.interface_name).or_default();
        if let Some(v4) = storage.as_sockaddr_in() {
            entry.0.push(v4.ip().to_string());
        } else if let Some(v6) = storage.as_sockaddr_in6() {
            entry.1.push(v6.ip().to_string());
        }
    }
    map
}

// ── Software ────────────────────────────────────────────────────────────────

fn gather_software() -> SoftwareInventory {
    if let Some(pkgs) = dpkg_packages() {
        return SoftwareInventory { source: "dpkg".into(), package_count: pkgs.len(), packages: pkgs };
    }
    if let Some(pkgs) = rpm_packages() {
        return SoftwareInventory { source: "rpm".into(), package_count: pkgs.len(), packages: pkgs };
    }
    SoftwareInventory { source: "none".into(), package_count: 0, packages: Vec::new() }
}

fn dpkg_packages() -> Option<Vec<SoftwarePackage>> {
    let out = run_capture(
        "dpkg-query",
        &["-W", "-f=${Package}\t${Version}\t${Architecture}\n"],
    )?;
    let pkgs: Vec<SoftwarePackage> = out
        .lines()
        .filter_map(|l| {
            let mut parts = l.split('\t');
            let name = parts.next()?.trim();
            if name.is_empty() {
                return None;
            }
            let version = parts.next().unwrap_or("").trim().to_string();
            let arch = parts.next().map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
            Some(SoftwarePackage { name: name.to_string(), version, architecture: arch })
        })
        .collect();
    if pkgs.is_empty() { None } else { Some(pkgs) }
}

fn rpm_packages() -> Option<Vec<SoftwarePackage>> {
    let out = run_capture(
        "rpm",
        &["-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n"],
    )?;
    let pkgs: Vec<SoftwarePackage> = out
        .lines()
        .filter_map(|l| {
            let mut parts = l.split('\t');
            let name = parts.next()?.trim();
            if name.is_empty() {
                return None;
            }
            let version = parts.next().unwrap_or("").trim().to_string();
            let arch = parts.next().map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
            Some(SoftwarePackage { name: name.to_string(), version, architecture: arch })
        })
        .collect();
    if pkgs.is_empty() { None } else { Some(pkgs) }
}

// ── Users ───────────────────────────────────────────────────────────────────

fn gather_users() -> Vec<UserAccount> {
    let content = match std::fs::read_to_string("/etc/passwd") {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    content
        .lines()
        .filter_map(|line| {
            let f: Vec<&str> = line.split(':').collect();
            if f.len() < 7 {
                return None;
            }
            let username = f[0].to_string();
            let uid: u32 = f[2].parse().ok()?;
            let gid: u32 = f[3].parse().ok()?;
            let home = f[5].to_string();
            let shell = f[6].to_string();
            // "Human" = root, or a normal login uid with a real interactive shell.
            let real_shell = !(shell.ends_with("nologin") || shell.ends_with("false") || shell.is_empty());
            let is_human = real_shell && (uid == 0 || uid >= 1000);
            Some(UserAccount { username, uid, gid, home, shell, is_human })
        })
        .collect()
}

// ── Small helpers ───────────────────────────────────────────────────────────

fn read_trim(path: &str) -> Option<String> {
    std::fs::read_to_string(path).ok().map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

/// Run a command and capture trimmed stdout, or None if it is missing/fails.
fn run_capture(cmd: &str, args: &[&str]) -> Option<String> {
    let out = Command::new(cmd).args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_os_release_format() {
        // We cannot fake /etc, but os-release parsing is exercised on the host.
        let map = parse_os_release();
        // On any Linux CI host PRETTY_NAME or NAME should exist.
        assert!(map.contains_key("NAME") || map.contains_key("PRETTY_NAME") || map.is_empty());
    }

    #[test]
    fn gather_produces_a_snapshot() {
        let s = gather("aid".into(), "did".into(), "host".into());
        assert_eq!(s.schema_version, SCHEMA_VERSION);
        assert_eq!(s.agent_id, "aid");
        assert_eq!(s.os.family, "linux");
        // CPU + memory should be populated on a real host.
        assert!(s.hardware.cpu_logical_cores >= 1);
        assert!(s.hardware.memory_total_mb > 0);
    }

    #[test]
    fn users_include_root() {
        let users = gather_users();
        // /etc/passwd always has root on a Linux host.
        if !users.is_empty() {
            assert!(users.iter().any(|u| u.uid == 0));
        }
    }

    #[test]
    fn software_inventory_has_a_source() {
        let sw = gather_software();
        assert!(["dpkg", "rpm", "none"].contains(&sw.source.as_str()));
        assert_eq!(sw.package_count, sw.packages.len());
    }
}
