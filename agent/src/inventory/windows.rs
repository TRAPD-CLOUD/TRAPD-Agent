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
    let profiles = windows_user_profiles();
    let now_unix = chrono::Utc::now().timestamp();
    let users = profiles
        .iter()
        .map(|p| UserAccount {
            username: p.name.clone(),
            uid: 0,
            gid: 0,
            home: p.profile_dir.clone(),
            shell: String::new(),
            // Service, system and stale profiles are not people; earlier
            // releases marked every account human.
            is_human: crate::deception::windows_profiler::is_human_profile(p, now_unix),
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
        build: windows_build(),
        display_version: registry::string(
            CURRENT_VERSION_KEY,
            "DisplayVersion",
            RRF_SUBKEY_WOW6464KEY,
        ),
        distro_id: None,
        distro_codename: None,
    };
    let compliance = compliance::assess(&software.packages, &software.source, &os, flags, cve_feed);
    let recon_profile =
        windows_recon_profile(&users, &profiles, &software, &hostname, &network, now_unix);
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
            kernel_modules: super::windows_drivers::loaded(),
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

const CURRENT_VERSION_KEY: &str = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion";

/// Full build "major.minor.build.ubr" (e.g. "10.0.26200.6584"). `None` unless
/// every component is present, so the backend never matches a partial build.
fn windows_build() -> Option<String> {
    let major = registry::dword(
        CURRENT_VERSION_KEY,
        "CurrentMajorVersionNumber",
        RRF_SUBKEY_WOW6464KEY,
    )?;
    let minor = registry::dword(
        CURRENT_VERSION_KEY,
        "CurrentMinorVersionNumber",
        RRF_SUBKEY_WOW6464KEY,
    )?;
    let build = registry::string(
        CURRENT_VERSION_KEY,
        "CurrentBuildNumber",
        RRF_SUBKEY_WOW6464KEY,
    )?;
    let ubr = registry::dword(CURRENT_VERSION_KEY, "UBR", RRF_SUBKEY_WOW6464KEY)?;
    format_windows_build(major, minor, &build, ubr)
}

fn format_windows_build(major: u32, minor: u32, build: &str, ubr: u32) -> Option<String> {
    let build = build.trim();
    if build.is_empty() || !build.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some(format!("{major}.{minor}.{build}.{ubr}"))
}

/// Every local profile with its SID, folder redirection, sync roots and last
/// use. Accounts and registered profiles are combined so logged-off domain or
/// Entra profiles are included; per-user details come from `ProfileList` and,
/// when the user's hive is loaded, `HKEY_USERS\<SID>`.
pub(crate) fn windows_user_profiles() -> Vec<crate::deception::windows_profiler::WindowsUserProfile>
{
    const PROFILE_LIST: &str = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList";
    windows_user_profiles_from(
        registry::Hive::LocalMachine,
        PROFILE_LIST,
        Users::new_with_refreshed_list()
            .iter()
            .map(|u| u.id().to_string())
            .collect(),
    )
}

fn windows_user_profiles_from(
    hive: registry::Hive,
    profile_list: &str,
    accounts: Vec<String>,
) -> Vec<crate::deception::windows_profiler::WindowsUserProfile> {
    use crate::deception::windows_profiler::{
        expand_user_path, filetime_to_unix, synced_roots_from_children, WindowsUserProfile,
    };
    use registry::Hive;
    let mut sids: std::collections::BTreeSet<String> = accounts.into_iter().collect();
    sids.extend(
        registry::subkeys_in(hive, profile_list, KEY_WOW64_64KEY)
            .into_iter()
            .filter(|sid| {
                // ProfileList also contains backup keys ending in .bak. Accept only
                // SID-shaped names, never those backups or unrelated registry keys.
                sid.strip_prefix("S-1-").is_some_and(|tail| {
                    tail.split('-')
                        .all(|part| !part.is_empty() && part.bytes().all(|c| c.is_ascii_digit()))
                })
            }),
    );
    sids.into_iter()
        .map(|sid| {
            let key = format!("{profile_list}\\{sid}");
            let profile_dir = registry::string_in(hive, &key, "ProfileImagePath", RRF_SUBKEY_WOW6464KEY).unwrap_or_default();
            let last_use_unix = match (
                registry::dword_in(hive, &key, "LocalProfileLoadTimeHigh", RRF_SUBKEY_WOW6464KEY),
                registry::dword_in(hive, &key, "LocalProfileLoadTimeLow", RRF_SUBKEY_WOW6464KEY),
            ) {
                (Some(h), Some(l)) => filetime_to_unix(h, l),
                _ => None,
            };
            let documents_dir = registry::string_in(
                Hive::Users,
                &format!("{sid}\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders"),
                "Personal",
                registry::NO_EXPAND,
            )
            .and_then(|raw| expand_user_path(&raw, &profile_dir));
            let mut synced_roots = Vec::new();
            for account in registry::subkeys_in(Hive::Users, &format!("{sid}\\Software\\Microsoft\\OneDrive\\Accounts"), 0) {
                if let Some(folder) = registry::string_in(
                    Hive::Users,
                    &format!("{sid}\\Software\\Microsoft\\OneDrive\\Accounts\\{account}"),
                    "UserFolder",
                    0,
                ) {
                    synced_roots.push(folder);
                }
            }
            if !profile_dir.is_empty() {
                let children: Vec<String> = std::fs::read_dir(&profile_dir)
                    .map(|rd| {
                        rd.take(256)
                            .flatten()
                            .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
                            .filter_map(|e| e.file_name().into_string().ok())
                            .collect()
                    })
                    .unwrap_or_default();
                synced_roots.extend(synced_roots_from_children(&profile_dir, &children));
            }
            synced_roots.sort();
            synced_roots.dedup();
            WindowsUserProfile {
                name: crate::telemetry::identity::windows_sid_account(&sid).unwrap_or_else(|| sid.clone()),
                sid,
                profile_dir,
                documents_dir,
                synced_roots,
                last_use_unix,
            }
        })
        .collect()
}

/// The recon profile for a Windows host: persona as on Linux, but decoy
/// candidates from the Windows profiler (the Unix-path candidates would name
/// `C:\\Users\\x/.ssh` and are never proposed here).
fn windows_recon_profile(
    users: &[UserAccount],
    profiles: &[crate::deception::windows_profiler::WindowsUserProfile],
    software: &SoftwareInventory,
    hostname: &str,
    network: &[NetInterface],
    now_unix: i64,
) -> crate::deception::ReconProfile {
    use crate::deception::windows_profiler::{build_candidates, ProfilerInput, RealDirProbe};
    let mut profile = crate::deception::build_profile_with_host(users, software, hostname, network);
    profile.candidates.clear();
    let names: Vec<String> = software.packages.iter().map(|p| p.name.clone()).collect();
    let activity = crate::deception::activity::current_summaries();
    let (candidates, signals) = build_candidates(
        &ProfilerInput {
            users: profiles,
            software: &names,
            activity: &activity,
            now_unix,
        },
        &RealDirProbe,
    );
    profile.windows_candidates = candidates;
    profile.role_signals = signals;
    profile
}

#[cfg(test)]
mod tests {
    use super::{format_windows_build, windows_user_profiles_from};
    use crate::collectors::windows::registry::Hive;
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegCreateKeyExW, RegDeleteTreeW, RegSetValueExW, HKEY_CURRENT_USER,
        KEY_SET_VALUE, KEY_WOW64_64KEY, REG_OPTION_NON_VOLATILE, REG_SZ,
    };

    struct ProfileRegistry(String);
    impl Drop for ProfileRegistry {
        fn drop(&mut self) {
            let path: Vec<u16> = self.0.encode_utf16().chain(Some(0)).collect();
            // Only remove this fixture's random per-user key, including on panic.
            unsafe { RegDeleteTreeW(HKEY_CURRENT_USER, path.as_ptr()) };
        }
    }

    #[test]
    fn registered_profiles_are_discovered_without_local_accounts_or_live_sessions() {
        let fixture = ProfileRegistry(format!(
            "SOFTWARE\\TRAPD-Profile-Test-{}",
            uuid::Uuid::new_v4()
        ));
        let local = "S-1-5-21-1-2-3-1001";
        let domain = "S-1-5-21-4-5-6-1002";
        let entra = "S-1-12-1-1-2-3-4";
        for (sid, folder) in [
            (local, "C:\\Users\\local"),
            (domain, "D:\\Profiles\\domain"),
            (entra, "E:\\People\\entra"),
            ("S-1-5-21-4-5-6-1002.bak", "D:\\Profiles\\old"),
            ("unrelated", "D:\\Profiles\\invalid"),
        ] {
            let path: Vec<u16> = format!("{}\\{sid}", fixture.0)
                .encode_utf16()
                .chain(Some(0))
                .collect();
            let name: Vec<u16> = "ProfileImagePath".encode_utf16().chain(Some(0)).collect();
            let value: Vec<u16> = folder.encode_utf16().chain(Some(0)).collect();
            let mut key = std::ptr::null_mut();
            // The native fixture requires no HKLM/admin writes and never
            // touches the machine's real ProfileList or user profile hives.
            let status = unsafe {
                RegCreateKeyExW(
                    HKEY_CURRENT_USER,
                    path.as_ptr(),
                    0,
                    std::ptr::null(),
                    REG_OPTION_NON_VOLATILE,
                    KEY_SET_VALUE | KEY_WOW64_64KEY,
                    std::ptr::null(),
                    &mut key,
                    std::ptr::null_mut(),
                )
            };
            assert_eq!(status, 0);
            let status = unsafe {
                RegSetValueExW(
                    key,
                    name.as_ptr(),
                    0,
                    REG_SZ,
                    value.as_ptr().cast(),
                    (value.len() * 2) as u32,
                )
            };
            unsafe { RegCloseKey(key) };
            assert_eq!(status, 0);
        }
        let profiles =
            windows_user_profiles_from(Hive::CurrentUser, &fixture.0, vec![local.into()]);
        assert_eq!(
            profiles.len(),
            3,
            "deduplicate account/registry SIDs and reject backup/non-SID keys"
        );
        for (sid, expected) in [
            (local, "C:\\Users\\local"),
            (domain, "D:\\Profiles\\domain"),
            (entra, "E:\\People\\entra"),
        ] {
            assert_eq!(
                profiles
                    .iter()
                    .find(|profile| profile.sid == sid)
                    .unwrap()
                    .profile_dir,
                expected
            );
        }
        let (mut roots, _) = crate::collectors::fs_plan::ransom_roots(
            profiles
                .iter()
                .map(|profile| (profile.sid.as_str(), profile.profile_dir.as_str())),
            "C:\\Users",
        );
        roots.sort();
        assert_eq!(
            roots,
            vec![
                "c:\\users\\",
                "d:\\profiles\\domain\\",
                "e:\\people\\entra\\"
            ]
        );
    }

    #[test]
    fn formats_full_build_with_update_revision() {
        assert_eq!(
            format_windows_build(10, 0, "26200", 6584).as_deref(),
            Some("10.0.26200.6584")
        );
        assert_eq!(
            format_windows_build(10, 0, " 26100 ", 0).as_deref(),
            Some("10.0.26100.0")
        );
    }

    #[test]
    fn rejects_non_numeric_build_numbers() {
        assert_eq!(format_windows_build(10, 0, "", 1), None);
        assert_eq!(format_windows_build(10, 0, "26200a", 1), None);
    }
}
