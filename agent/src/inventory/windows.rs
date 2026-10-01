//! Windows inventory: sysinfo hardware/users, registry software and native TCP.
use sysinfo::{Disks, System, Users};
use windows_sys::Win32::System::Registry::{
    KEY_WOW64_32KEY, KEY_WOW64_64KEY, RRF_SUBKEY_WOW6432KEY, RRF_SUBKEY_WOW6464KEY,
};

use super::*;
use crate::collectors::windows::{network, registry};

pub fn gather_with_flags(
    agent_id: String,
    device_id: String,
    hostname: String,
    flags: compliance::ComplianceFlags,
    cve_feed: &[compliance::CveEntry],
) -> InventorySnapshot {
    let sys = System::new_all();
    let reg_path = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall";
    let mut packages = Vec::new();
    for (key_view, value_view, arch) in [
        (KEY_WOW64_64KEY, RRF_SUBKEY_WOW6464KEY, "x86_64"),
        (KEY_WOW64_32KEY, RRF_SUBKEY_WOW6432KEY, "x86"),
    ] {
        for key in registry::subkeys(reg_path, key_view) {
            let path = format!("{reg_path}\\{key}");
            if let Some(name) = registry::string(&path, "DisplayName", value_view) {
                if name.is_empty() {
                    continue;
                }
                packages.push(SoftwarePackage {
                    name,
                    version: registry::string(&path, "DisplayVersion", value_view)
                        .unwrap_or_default(),
                    architecture: Some(arch.into()),
                });
            }
        }
    }
    packages.sort_by(|a, b| {
        (&a.name, &a.version, &a.architecture).cmp(&(&b.name, &b.version, &b.architecture))
    });
    packages.dedup_by(|a, b| {
        a.name == b.name && a.version == b.version && a.architecture == b.architecture
    });
    let software = SoftwareInventory {
        source: "windows_registry".into(),
        package_count: packages.len(),
        packages,
    };
    let users = Users::new_with_refreshed_list()
        .iter()
        .map(|u| UserAccount {
            username: u.name().into(),
            uid: 0,
            gid: 0,
            home: registry::string(
                &format!(
                    "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\{}",
                    **u.id()
                ),
                "ProfileImagePath",
                RRF_SUBKEY_WOW6464KEY,
            )
            .unwrap_or_default(),
            shell: String::new(),
            is_human: true,
        })
        .collect::<Vec<_>>();
    let network = match interfaces() {
        Ok(interfaces) => interfaces,
        Err(e) => {
            tracing::warn!(error = %e, "Windows adapter inventory unavailable");
            Vec::new()
        }
    };
    let os = OsInfo {
        family: "windows".into(),
        name: System::name().unwrap_or_else(|| "Windows".into()),
        version: System::os_version().unwrap_or_default(),
        pretty_name: System::long_os_version().unwrap_or_default(),
        kernel: System::kernel_version().unwrap_or_default(),
        arch: std::env::consts::ARCH.into(),
        machine_id: registry::string(
            "SOFTWARE\\Microsoft\\Cryptography",
            "MachineGuid",
            RRF_SUBKEY_WOW6464KEY,
        ),
        timezone: registry::string(
            "SYSTEM\\CurrentControlSet\\Control\\TimeZoneInformation",
            "TimeZoneKeyName",
            0,
        ),
        boot_time_unix: System::boot_time(),
        uptime_secs: System::uptime(),
    };
    let compliance = compliance::assess(&software.packages, &software.source, &os, flags, cve_feed);
    let recon_profile =
        crate::deception::build_profile_with_host(&users, &software, &hostname, &network);
    let hardware = HardwareInfo {
        vendor: registry::string(
            "HARDWARE\\DESCRIPTION\\System\\BIOS",
            "SystemManufacturer",
            0,
        ),
        product: registry::string(
            "HARDWARE\\DESCRIPTION\\System\\BIOS",
            "SystemProductName",
            0,
        ),
        serial: None,
        bios_vendor: registry::string("HARDWARE\\DESCRIPTION\\System\\BIOS", "BIOSVendor", 0),
        bios_version: registry::string("HARDWARE\\DESCRIPTION\\System\\BIOS", "BIOSVersion", 0),
        chassis: None,
        virtualization: None,
        cpu_model: sys
            .cpus()
            .first()
            .map(|c| c.brand().to_string())
            .unwrap_or_default(),
        cpu_physical_cores: sys.physical_core_count().unwrap_or(0),
        cpu_logical_cores: sys.cpus().len(),
        memory_total_mb: sys.total_memory() / 1024 / 1024,
        swap_total_mb: sys.total_swap() / 1024 / 1024,
        disks: Disks::new_with_refreshed_list()
            .iter()
            .map(|d| DiskInfo {
                device: d.name().to_string_lossy().into_owned(),
                mount_point: d.mount_point().to_string_lossy().into_owned(),
                fs_type: d.file_system().to_string_lossy().into_owned(),
                total_mb: d.total_space() / 1024 / 1024,
                available_mb: d.available_space() / 1024 / 1024,
                removable: d.is_removable(),
            })
            .collect(),
    };
    let listening_ports = match network::snapshot() {
        Ok(rows) => rows
            .into_iter()
            .filter(|r| r.state == "listen")
            .map(|r| ListeningPort {
                protocol: r.protocol,
                address: r.src_addr,
                port: r.src_port,
                pid: r.pid,
                process: r.process,
            })
            .collect(),
        Err(e) => {
            tracing::warn!(error = %e, "Windows listener inventory unavailable");
            Vec::new()
        }
    };
    InventorySnapshot {
        schema_version: 1,
        agent_id,
        device_id,
        hostname,
        agent_version: env!("CARGO_PKG_VERSION").into(),
        collected_at: chrono::Utc::now(),
        os,
        hardware,
        network,
        software,
        users,
        security_posture: SecurityPosture {
            listening_ports,
            ..Default::default()
        },
        recon_profile,
        compliance,
    }
}

fn interfaces() -> anyhow::Result<Vec<NetInterface>> {
    use std::net::{Ipv4Addr, Ipv6Addr};
    use windows_sys::Win32::NetworkManagement::IpHelper::*;
    use windows_sys::Win32::NetworkManagement::Ndis::IfOperStatusUp;
    use windows_sys::Win32::Networking::WinSock::{
        AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR_IN, SOCKADDR_IN6,
    };
    let mut bytes = 15 * 1024u32;
    for _ in 0..3 {
        anyhow::ensure!(
            bytes <= 4 * 1024 * 1024,
            "adapter table exceeds size ceiling"
        );
        let mut buffer = vec![0u64; (bytes as usize).div_ceil(8)];
        // SAFETY: 8-byte aligned storage covers the requested byte size.
        let status = unsafe {
            GetAdaptersAddresses(
                AF_UNSPEC as u32,
                GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
                std::ptr::null(),
                buffer.as_mut_ptr().cast(),
                &mut bytes,
            )
        };
        if status == 111 {
            continue;
        } // buffer overflow: retry with the new size
        anyhow::ensure!(status == 0, "GetAdaptersAddresses failed: {status}");
        let start = buffer.as_ptr() as usize;
        let end = start + buffer.len() * 8;
        let within = |ptr: usize, size: usize| ptr >= start && ptr <= end && size <= end - ptr;
        let mut adapter = buffer.as_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
        let mut out = Vec::new();
        // SAFETY: all linked structure/string/socket pointers are range checked
        // before use. The owning buffer remains alive through the entire walk.
        unsafe {
            while !adapter.is_null() && out.len() < 1024 {
                anyhow::ensure!(
                    within(
                        adapter as usize,
                        std::mem::size_of::<IP_ADAPTER_ADDRESSES_LH>()
                    ),
                    "invalid adapter pointer"
                );
                let a = &*adapter;
                let mut name = Vec::new();
                let mut p = a.FriendlyName;
                while !p.is_null() && within(p as usize, 2) && *p != 0 && name.len() < 1024 {
                    name.push(*p);
                    p = p.add(1);
                }
                let mac_len = (a.PhysicalAddressLength as usize).min(a.PhysicalAddress.len());
                let mut info = NetInterface {
                    name: String::from_utf16_lossy(&name),
                    mac: (mac_len > 0).then(|| {
                        a.PhysicalAddress[..mac_len]
                            .iter()
                            .map(|b| format!("{b:02x}"))
                            .collect::<Vec<_>>()
                            .join(":")
                    }),
                    ipv4: Vec::new(),
                    ipv6: Vec::new(),
                    up: a.OperStatus == IfOperStatusUp,
                };
                let mut addr = a.FirstUnicastAddress;
                let mut count = 0;
                while !addr.is_null() && count < 1024 {
                    anyhow::ensure!(
                        within(
                            addr as usize,
                            std::mem::size_of::<IP_ADAPTER_UNICAST_ADDRESS_LH>()
                        ),
                        "invalid unicast pointer"
                    );
                    let socket = (*addr).Address;
                    if !socket.lpSockaddr.is_null() && within(socket.lpSockaddr as usize, 2) {
                        let family = (*socket.lpSockaddr).sa_family;
                        if family == AF_INET
                            && socket.iSockaddrLength as usize >= std::mem::size_of::<SOCKADDR_IN>()
                            && within(
                                socket.lpSockaddr as usize,
                                std::mem::size_of::<SOCKADDR_IN>(),
                            )
                        {
                            let address =
                                std::ptr::read_unaligned(socket.lpSockaddr.cast::<SOCKADDR_IN>());
                            info.ipv4.push(
                                Ipv4Addr::from(address.sin_addr.S_un.S_addr.to_ne_bytes())
                                    .to_string(),
                            );
                        } else if family == AF_INET6
                            && socket.iSockaddrLength as usize
                                >= std::mem::size_of::<SOCKADDR_IN6>()
                            && within(
                                socket.lpSockaddr as usize,
                                std::mem::size_of::<SOCKADDR_IN6>(),
                            )
                        {
                            let address =
                                std::ptr::read_unaligned(socket.lpSockaddr.cast::<SOCKADDR_IN6>());
                            info.ipv6
                                .push(Ipv6Addr::from(address.sin6_addr.u.Byte).to_string());
                        }
                    }
                    addr = (*addr).Next;
                    count += 1;
                }
                out.push(info);
                adapter = a.Next;
            }
        }
        return Ok(out);
    }
    anyhow::bail!("adapter table repeatedly changed during inventory")
}
