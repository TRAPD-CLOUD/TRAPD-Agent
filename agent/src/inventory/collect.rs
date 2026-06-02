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
    DiskInfo, FileCapability, HardwareInfo, InventorySnapshot, KernelModule, ListeningPort,
    NetInterface, OsInfo, SecurityPosture, SoftwareInventory, SoftwarePackage, SuidSgidBinary,
    UserAccount,
};

// v2 adds the deception `recon_profile` field derived from users + software.
// v3 adds the `security_posture` baseline (SUID/SGID, capabilities, listening
// ports, kernel modules + signature status).
const SCHEMA_VERSION: u32 = 3;

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
        security_posture: gather_security_posture(),
        recon_profile,
    }
}

// ── Security posture ──────────────────────────────────────────────────────────

/// Filesystem roots scanned for SUID/SGID binaries and file capabilities. These
/// cover the standard executable locations without walking the whole disk.
const POSTURE_SCAN_ROOTS: &[&str] = &[
    "/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin",
    "/bin", "/sbin", "/usr/lib", "/opt",
];

/// Cap on the number of directory entries visited per scan, so the inventory
/// pass stays bounded even on a pathological filesystem.
const MAX_SCAN_ENTRIES: usize = 200_000;

fn gather_security_posture() -> SecurityPosture {
    let (suid_sgid, file_capabilities) = scan_suid_and_caps();
    SecurityPosture {
        suid_sgid,
        file_capabilities,
        listening_ports: gather_listening_ports(),
        kernel_modules: gather_kernel_modules(),
    }
}

/// Single filesystem walk that collects both SUID/SGID binaries and files
/// carrying a `security.capability` xattr — doing it in one pass avoids walking
/// the executable roots twice.
fn scan_suid_and_caps() -> (Vec<SuidSgidBinary>, Vec<FileCapability>) {
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::fs::PermissionsExt;

    let mut suid = Vec::new();
    let mut caps = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut budget = MAX_SCAN_ENTRIES;

    for &root in POSTURE_SCAN_ROOTS {
        if !std::path::Path::new(root).exists() {
            continue;
        }
        for entry in walkdir::WalkDir::new(root)
            .follow_links(false)
            .into_iter()
            .flatten()
        {
            if budget == 0 {
                break;
            }
            budget -= 1;

            if !entry.file_type().is_file() {
                continue;
            }
            let path = entry.path();
            // Deduplicate hardlinked/aliased paths visited via multiple roots.
            if !seen.insert(path.to_path_buf()) {
                continue;
            }
            let meta = match entry.metadata() {
                Ok(m) => m,
                Err(_) => continue,
            };
            let mode = meta.permissions().mode();
            let setuid = mode & 0o4000 != 0;
            let setgid = mode & 0o2000 != 0;
            let path_str = path.to_string_lossy().into_owned();

            if setuid || setgid {
                suid.push(SuidSgidBinary {
                    mode: format!("{:04o}", mode & 0o7777),
                    setuid,
                    setgid,
                    owner_uid: meta.uid(),
                    owner_gid: meta.gid(),
                    size: meta.len(),
                    sha256: sha256_path(&path_str),
                    path: path_str.clone(),
                });
            }

            if let Some(c) = read_file_capability(&path_str) {
                caps.push(FileCapability {
                    path: path_str,
                    capabilities: c,
                });
            }
        }
    }

    suid.sort_by(|a, b| a.path.cmp(&b.path));
    caps.sort_by(|a, b| a.path.cmp(&b.path));
    (suid, caps)
}

/// SHA256 of a file, formatted `sha256:<hex>`; `None` on any IO error.
fn sha256_path(path: &str) -> Option<String> {
    use sha2::{Digest, Sha256};
    use std::io::Read;

    let mut file = std::fs::File::open(path).ok()?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 65_536];
    loop {
        match file.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => hasher.update(&buf[..n]),
            Err(_) => return None,
        }
    }
    Some(format!("sha256:{}", hex::encode(hasher.finalize())))
}

/// Read and decode the `security.capability` xattr into a `getcap`-style string,
/// e.g. `cap_net_raw,cap_net_admin+ep`. Returns `None` when the file has no
/// capability set (the common case) or the xattr is unreadable.
fn read_file_capability(path: &str) -> Option<String> {
    let raw = read_xattr(path, "security.capability")?;
    decode_vfs_cap(&raw)
}

/// Decode a `VFS_CAP` xattr blob (struct `vfs_cap_data` / `vfs_ns_cap_data`,
/// little-endian) into a human-readable capability string. Supports the v1, v2
/// and v3 layouts.
fn decode_vfs_cap(raw: &[u8]) -> Option<String> {
    if raw.len() < 8 {
        return None;
    }
    let magic = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
    let revision = magic & 0xFF00_0000;

    // permitted/inheritable masks live in two u32 words each from offset 4.
    let read_u32 = |off: usize| -> u32 {
        u32::from_le_bytes([raw[off], raw[off + 1], raw[off + 2], raw[off + 3]])
    };

    // Effective bit is encoded in the magic's low flag bit for v2/v3.
    let effective = magic & 0x0000_0001 != 0;

    let (perm_lo, perm_hi, inh_lo, inh_hi) = match revision {
        // VFS_CAP_REVISION_1 = 0x01000000 (single 32-bit word set)
        0x0100_0000 if raw.len() >= 12 => (read_u32(4), 0, read_u32(8), 0),
        // VFS_CAP_REVISION_2/3 = 0x02000000 / 0x03000000 (two 32-bit words)
        0x0200_0000 | 0x0300_0000 if raw.len() >= 20 => {
            (read_u32(4), read_u32(12), read_u32(8), read_u32(16))
        }
        _ => return None,
    };

    let permitted = (perm_lo as u64) | ((perm_hi as u64) << 32);
    let inheritable = (inh_lo as u64) | ((inh_hi as u64) << 32);
    let mask = permitted | inheritable;
    if mask == 0 {
        return None;
    }

    let mut names: Vec<&str> = Vec::new();
    for (bit, name) in CAP_NAMES.iter().enumerate() {
        if mask & (1u64 << bit) != 0 {
            names.push(name);
        }
    }
    if names.is_empty() {
        return None;
    }

    // Suffix mirrors `getcap`: +e (effective), +p (permitted), +i (inheritable).
    let mut suffix = String::new();
    if effective {
        suffix.push('e');
    }
    if permitted != 0 {
        suffix.push('p');
    }
    if inheritable != 0 {
        suffix.push('i');
    }
    Some(format!("{}+{}", names.join(","), suffix))
}

/// Capability names indexed by bit position (subset through CAP_CHECKPOINT_RESTORE).
const CAP_NAMES: &[&str] = &[
    "cap_chown", "cap_dac_override", "cap_dac_read_search", "cap_fowner",
    "cap_fsetid", "cap_kill", "cap_setgid", "cap_setuid",
    "cap_setpcap", "cap_linux_immutable", "cap_net_bind_service", "cap_net_broadcast",
    "cap_net_admin", "cap_net_raw", "cap_ipc_lock", "cap_ipc_owner",
    "cap_sys_module", "cap_sys_rawio", "cap_sys_chroot", "cap_sys_ptrace",
    "cap_sys_pacct", "cap_sys_admin", "cap_sys_boot", "cap_sys_nice",
    "cap_sys_resource", "cap_sys_time", "cap_sys_tty_config", "cap_mknod",
    "cap_lease", "cap_audit_write", "cap_audit_control", "cap_setfcap",
    "cap_mac_override", "cap_mac_admin", "cap_syslog", "cap_wake_alarm",
    "cap_block_suspend", "cap_audit_read", "cap_perfmon", "cap_bpf",
    "cap_checkpoint_restore",
];

/// Read an extended attribute via `getxattr(2)`. Returns the raw bytes.
fn read_xattr(path: &str, name: &str) -> Option<Vec<u8>> {
    use std::ffi::CString;
    let c_path = CString::new(path).ok()?;
    let c_name = CString::new(name).ok()?;

    // First call with a null buffer to size the value.
    let len = unsafe {
        libc::getxattr(
            c_path.as_ptr(),
            c_name.as_ptr(),
            std::ptr::null_mut(),
            0,
        )
    };
    if len <= 0 {
        return None;
    }
    let mut buf = vec![0u8; len as usize];
    let got = unsafe {
        libc::getxattr(
            c_path.as_ptr(),
            c_name.as_ptr(),
            buf.as_mut_ptr() as *mut libc::c_void,
            buf.len(),
        )
    };
    if got <= 0 {
        return None;
    }
    buf.truncate(got as usize);
    Some(buf)
}

/// Listening sockets: TCP sockets in the LISTEN state plus UDP bound sockets,
/// IPv4 and IPv6, resolved back to the owning process where possible.
fn gather_listening_ports() -> Vec<ListeningPort> {
    use procfs::net::TcpState;

    let inode_map = build_inode_pid_map();
    let mut out = Vec::new();

    let mut push_tcp = |entries: Vec<procfs::net::TcpNetEntry>, proto: &str| {
        for e in entries {
            if e.state != TcpState::Listen {
                continue;
            }
            let (pid, process) = resolve_inode(e.inode, &inode_map);
            out.push(ListeningPort {
                protocol: proto.to_string(),
                address: e.local_address.ip().to_string(),
                port: e.local_address.port(),
                pid,
                process,
            });
        }
    };
    if let Ok(v) = procfs::net::tcp() {
        push_tcp(v, "tcp");
    }
    if let Ok(v) = procfs::net::tcp6() {
        push_tcp(v, "tcp6");
    }

    // UDP has no LISTEN state; a socket bound to a local port with no peer is the
    // service-listening equivalent.
    let mut push_udp = |entries: Vec<procfs::net::UdpNetEntry>, proto: &str| {
        for e in entries {
            if e.remote_address.port() != 0 {
                continue; // connected/ephemeral socket, not a listener
            }
            let (pid, process) = resolve_inode(e.inode, &inode_map);
            out.push(ListeningPort {
                protocol: proto.to_string(),
                address: e.local_address.ip().to_string(),
                port: e.local_address.port(),
                pid,
                process,
            });
        }
    };
    if let Ok(v) = procfs::net::udp() {
        push_udp(v, "udp");
    }
    if let Ok(v) = procfs::net::udp6() {
        push_udp(v, "udp6");
    }

    out.sort_by(|a, b| (a.port, a.protocol.clone()).cmp(&(b.port, b.protocol.clone())));
    out.dedup_by(|a, b| {
        a.port == b.port && a.protocol == b.protocol && a.address == b.address
    });
    out
}

/// Map socket inode → owning pid by scanning `/proc/<pid>/fd`.
fn build_inode_pid_map() -> std::collections::HashMap<u64, i32> {
    let mut map = std::collections::HashMap::new();
    let Ok(proc_dir) = std::fs::read_dir("/proc") else {
        return map;
    };
    for entry in proc_dir.flatten() {
        let name = entry.file_name();
        let Ok(pid) = name.to_string_lossy().parse::<i32>() else {
            continue;
        };
        let Ok(fd_dir) = std::fs::read_dir(format!("/proc/{pid}/fd")) else {
            continue;
        };
        for fd in fd_dir.flatten() {
            if let Ok(link) = std::fs::read_link(fd.path()) {
                let s = link.to_string_lossy();
                if let Some(inode) = s
                    .strip_prefix("socket:[")
                    .and_then(|x| x.strip_suffix(']'))
                    .and_then(|x| x.parse::<u64>().ok())
                {
                    map.insert(inode, pid);
                }
            }
        }
    }
    map
}

fn resolve_inode(
    inode: u64,
    map: &std::collections::HashMap<u64, i32>,
) -> (Option<i32>, Option<String>) {
    match map.get(&inode) {
        Some(&pid) => {
            let comm = std::fs::read_to_string(format!("/proc/{pid}/comm"))
                .ok()
                .map(|s| s.trim().to_string());
            (Some(pid), comm)
        }
        None => (None, None),
    }
}

/// Loaded kernel modules from `/proc/modules`, annotated with a best-effort
/// signature status. The kernel exposes per-module signing only indirectly; we
/// report `signed` when `/sys/module/<name>/taint` lacks the `E` (unsigned)
/// flag, `unsigned` when it carries it, and fall back to the global
/// `module.sig_enforce` / taint state otherwise.
fn gather_kernel_modules() -> Vec<KernelModule> {
    let content = match std::fs::read_to_string("/proc/modules") {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    let mut out = Vec::new();
    for line in content.lines() {
        // Format: name size refcount deps state base_addr [taint]
        let mut f = line.split_whitespace();
        let Some(name) = f.next() else { continue };
        let size = f.next().and_then(|s| s.parse::<u64>().ok()).unwrap_or(0);
        let _refcount = f.next();
        let _deps = f.next();
        let state = f.next().unwrap_or("Unknown").to_string();
        let _base = f.next();
        // A trailing parenthesised taint string (e.g. `(OE)`) flags Out-of-tree /
        // unsigned modules; `E` specifically means "unsigned module loaded".
        let taint = f.next().unwrap_or("");
        let signature = module_signature(name, taint).to_string();

        out.push(KernelModule { name: name.to_string(), size, state, signature });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

fn module_signature(name: &str, proc_taint: &str) -> &'static str {
    // Prefer the per-module taint flags exposed in sysfs when present.
    if let Some(t) = read_trim(&format!("/sys/module/{name}/taint")) {
        if t.contains('E') {
            return "unsigned";
        }
        if !t.is_empty() {
            return "signed";
        }
    }
    // Fall back to the taint column from /proc/modules.
    if proc_taint.contains('E') {
        "unsigned"
    } else if proc_taint.is_empty() {
        "unknown"
    } else {
        "signed"
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

    #[test]
    fn decodes_vfs_cap_v2_blob() {
        // VFS_CAP_REVISION_2 (0x02000000) with the effective flag set, granting
        // cap_net_raw (bit 13) and cap_net_admin (bit 12) in the permitted set.
        let permitted: u32 = (1 << 13) | (1 << 12);
        let mut raw = Vec::new();
        raw.extend_from_slice(&(0x0200_0000u32 | 1).to_le_bytes()); // magic + effective
        raw.extend_from_slice(&permitted.to_le_bytes()); // permitted lo
        raw.extend_from_slice(&0u32.to_le_bytes()); // inheritable lo
        raw.extend_from_slice(&0u32.to_le_bytes()); // permitted hi
        raw.extend_from_slice(&0u32.to_le_bytes()); // inheritable hi

        let decoded = decode_vfs_cap(&raw).unwrap();
        assert!(decoded.contains("cap_net_raw"), "got {decoded}");
        assert!(decoded.contains("cap_net_admin"), "got {decoded}");
        assert!(decoded.ends_with("+ep"), "got {decoded}");
    }

    #[test]
    fn empty_cap_blob_is_none() {
        assert!(decode_vfs_cap(&[]).is_none());
        // Well-formed v2 header but no bits set → None.
        let mut raw = vec![0u8; 20];
        raw[3] = 0x02;
        assert!(decode_vfs_cap(&raw).is_none());
    }

    #[test]
    fn module_signature_reads_taint() {
        // An unsigned-module taint flag ('E') must classify as unsigned.
        assert_eq!(module_signature("definitely_not_a_real_module_xyz", "(OE)"), "unsigned");
        assert_eq!(module_signature("definitely_not_a_real_module_xyz", "(O)"), "signed");
        assert_eq!(module_signature("definitely_not_a_real_module_xyz", ""), "unknown");
    }

    #[test]
    fn snapshot_includes_security_posture() {
        let s = gather("aid".into(), "did".into(), "host".into());
        assert_eq!(s.schema_version, 3);
        // On a real Linux host /proc/modules + listening ports are usually
        // present, but the scan is best-effort, so we only assert the field
        // exists and is internally consistent.
        for p in &s.security_posture.listening_ports {
            assert!(["tcp", "tcp6", "udp", "udp6"].contains(&p.protocol.as_str()));
        }
        for m in &s.security_posture.kernel_modules {
            assert!(["signed", "unsigned", "unknown"].contains(&m.signature.as_str()));
        }
    }
}
