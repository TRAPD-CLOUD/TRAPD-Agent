//! Native Windows Defender Firewall containment through INetFwPolicy2.
//! COM objects never cross threads or an await point. Rules belong to our group;
//! profile defaults and operator-managed rules are never rewritten.

use std::{marker::PhantomData, net::IpAddr, rc::Rc};

use anyhow::{anyhow, bail, Context, Result};
use ipnet::IpNet;
use windows::{
    core::{Interface, BSTR, HRESULT},
    Win32::{
        Foundation::{RPC_E_CHANGED_MODE, VARIANT_BOOL},
        NetworkManagement::WindowsFirewall::{
            INetFwPolicy2, INetFwRule, INetFwRules, NetFwPolicy2, NetFwRule, NET_FW_ACTION_BLOCK,
            NET_FW_IP_PROTOCOL_ANY, NET_FW_MODIFY_STATE_OK, NET_FW_PROFILE2_ALL,
            NET_FW_PROFILE_TYPE2, NET_FW_RULE_DIR_IN, NET_FW_RULE_DIR_OUT,
        },
        System::{
            Com::{
                CoCreateInstance, CoInitializeEx, CoUninitialize, CLSCTX_INPROC_SERVER,
                COINIT_APARTMENTTHREADED,
            },
            Ole::{IEnumVARIANT, SafeArrayGetDim, SafeArrayGetLBound, SafeArrayGetUBound},
            Variant::{VariantClear, VARIANT, VT_ARRAY, VT_DISPATCH, VT_EMPTY, VT_NULL},
        },
    },
};

use super::firewall::{self, Direction};

// Serialize paired rule mutations and rollback across the engine/command/TTL
// paths. COM's individual Add calls do not make a two-rule operation atomic.
static MUTATIONS: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn mutation_guard() -> Result<std::sync::MutexGuard<'static, ()>> {
    MUTATIONS
        .lock()
        .map_err(|_| anyhow!("firewall mutation state poisoned"))
}

struct Apartment {
    initialized: bool,
    _thread_bound: PhantomData<Rc<()>>,
}

impl Apartment {
    fn initialize() -> Result<Self> {
        // SAFETY: initialized on and released by this same thread. An existing
        // apartment is usable; only a successful initialization is balanced.
        let status = unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED) };
        if status != RPC_E_CHANGED_MODE {
            status.ok().context("initialize firewall COM apartment")?;
        }
        Ok(Self {
            initialized: status.is_ok(),
            _thread_bound: PhantomData,
        })
    }
}

impl Drop for Apartment {
    fn drop(&mut self) {
        if self.initialized {
            // SAFETY: same thread, balanced with CoInitializeEx, after objects.
            unsafe { CoUninitialize() };
        }
    }
}

struct OwnedVariant(VARIANT);
impl Drop for OwnedVariant {
    fn drop(&mut self) {
        // SAFETY: this owns the VARIANT returned by COM; no array is locked.
        let _ = unsafe { VariantClear(&mut self.0) };
    }
}

pub(super) struct Firewall {
    policy: INetFwPolicy2,
    rules: INetFwRules,
    // Declaration order releases COM interfaces before the apartment.
    _apartment: Apartment,
}

impl Firewall {
    pub(super) fn open() -> Result<Self> {
        let apartment = Apartment::initialize()?;
        // SAFETY: COM initialized; Microsoft's binding owns the returned interface.
        let policy: INetFwPolicy2 =
            unsafe { CoCreateInstance(&NetFwPolicy2, None, CLSCTX_INPROC_SERVER) }
                .context("open Windows Firewall policy")?;
        let rules = unsafe { policy.Rules() }.context("open Windows Firewall rules")?;
        Ok(Self {
            policy,
            rules,
            _apartment: apartment,
        })
    }

    pub(super) fn ensure_enforcing(&self) -> Result<()> {
        // Each getter below uses a live COM object owned by this apartment.
        let active = unsafe { self.policy.CurrentProfileTypes() }
            .context("query active firewall profiles")? as u32;
        let state = unsafe { self.policy.LocalPolicyModifyState() }
            .context("query effective local firewall policy")?;
        if state != NET_FW_MODIFY_STATE_OK {
            bail!(
                "active firewall policy prevents local containment rules (state {})",
                state.0
            );
        }
        let mut profiles = Vec::new();
        for (mask, key) in [
            (1, "DomainProfile"),
            (2, "StandardProfile"),
            (4, "PublicProfile"),
        ] {
            if active & mask == 0 {
                continue;
            }
            let profile = NET_FW_PROFILE_TYPE2(mask as i32);
            let local = unsafe { self.policy.get_FirewallEnabled(profile) }
                .with_context(|| format!("query {key} firewall state"))?
                .0
                != 0;
            // FirewallEnabled is the local setting. Group policy can override
            // it, so read its native registry override and fail on query errors.
            let path = format!("{}\\{key}", firewall::FIREWALL_POLICY_PROFILES);
            let policy = policy_dword(&path, "EnableFirewall")?;
            let merge = policy_dword(&path, "AllowLocalPolicyMerge")?;
            if merge == Some(0) {
                bail!("group policy ignores local containment rules on {key}");
            }
            let excluded = OwnedVariant(
                unsafe { self.policy.get_ExcludedInterfaces(profile) }
                    .with_context(|| format!("query {key} excluded interfaces"))?,
            );
            if has_excluded_interfaces(&excluded.0)? {
                bail!("firewall excludes interfaces on active {key}; containment cannot be guaranteed");
            }
            profiles.push((
                mask,
                firewall::profile_enforcing(policy, Some(u32::from(local))),
            ));
        }
        if !firewall::active_profiles_enforcing(active, &profiles) {
            bail!("Windows Firewall is not enforcing every active profile (mask {active})");
        }
        Ok(())
    }

    pub(super) fn find(&self, name: &str) -> Result<Option<INetFwRule>> {
        match unsafe { self.rules.Item(&BSTR::from(name)) } {
            Ok(rule) => Ok(Some(rule)),
            Err(e) if e.code() == HRESULT::from_win32(2) => Ok(None),
            Err(e) => Err(e).with_context(|| format!("query firewall rule {name}")),
        }
    }

    fn require_owned(rule: &INetFwRule, name: &str) -> Result<()> {
        if unsafe { rule.Grouping() }? != firewall::GROUP {
            bail!("refusing to modify firewall rule {name} outside the TRAPD group");
        }
        Ok(())
    }

    pub(super) fn remove(&self, name: &str) -> Result<bool> {
        let Some(rule) = self.find(name)? else {
            return Ok(false);
        };
        Self::require_owned(&rule, name)?;
        unsafe { self.rules.Remove(&BSTR::from(name)) }
            .with_context(|| format!("remove firewall rule {name}"))?;
        if self.find(name)?.is_some() {
            bail!("firewall rule {name} still exists after removal");
        }
        Ok(true)
    }

    pub(super) fn make_rule(
        name: &str,
        direction: Direction,
        remote: &str,
        description: &str,
        enabled: bool,
    ) -> Result<INetFwRule> {
        // Configure a detached rule fully before publishing it; any property
        // rejection leaves the host's rule collection untouched.
        let rule: INetFwRule = unsafe { CoCreateInstance(&NetFwRule, None, CLSCTX_INPROC_SERVER) }
            .context("create Windows Firewall rule")?;
        unsafe {
            rule.SetName(&BSTR::from(name))?;
            rule.SetDescription(&BSTR::from(description))?;
            rule.SetProtocol(NET_FW_IP_PROTOCOL_ANY.0)?;
            rule.SetDirection(match direction {
                Direction::In => NET_FW_RULE_DIR_IN,
                Direction::Out => NET_FW_RULE_DIR_OUT,
            })?;
            rule.SetAction(NET_FW_ACTION_BLOCK)?;
            rule.SetProfiles(NET_FW_PROFILE2_ALL.0)?;
            rule.SetInterfaceTypes(&BSTR::from("All"))?;
            rule.SetLocalAddresses(&BSTR::from("*"))?;
            rule.SetRemoteAddresses(&BSTR::from(remote))?;
            rule.SetGrouping(&BSTR::from(firewall::GROUP))?;
            rule.SetEdgeTraversal(VARIANT_BOOL(0))?;
            rule.SetEnabled(VARIANT_BOOL(if enabled { -1 } else { 0 }))?;
        }
        Ok(rule)
    }

    fn previous(&self, name: &str) -> Result<Option<INetFwRule>> {
        let Some(old) = self.find(name)? else {
            return Ok(None);
        };
        Self::require_owned(&old, name)?;
        // Snapshot detached properties, since the live object may reflect Add.
        let direction = match unsafe { old.Direction() }? {
            NET_FW_RULE_DIR_IN => Direction::In,
            NET_FW_RULE_DIR_OUT => Direction::Out,
            _ => bail!("invalid previous TRAPD rule direction"),
        };
        let snapshot = Self::make_rule(
            name,
            direction,
            &unsafe { old.RemoteAddresses() }?.to_string(),
            &unsafe { old.Description() }?.to_string(),
            unsafe { old.Enabled() }?.0 != 0,
        )?;
        // Rollback must restore every property that write() can mutate, even
        // when an operator has edited an otherwise unrestricted owned rule.
        unsafe {
            snapshot.SetAction(old.Action()?)?;
            snapshot.SetProfiles(old.Profiles()?)?;
            snapshot.SetInterfaceTypes(&old.InterfaceTypes()?)?;
            snapshot.SetEdgeTraversal(old.EdgeTraversal()?)?;
        }
        Ok(Some(snapshot))
    }

    fn write(&self, name: &str, desired: &INetFwRule) -> Result<()> {
        if let Some(existing) = self.find(name)? {
            Self::require_owned(&existing, name)?;
            // Name is only a display name, not the native rule identifier.
            // Mutate the retrieved object so repeat actions keep its identity.
            // Refuse externally narrowed rules rather than reporting a broad
            // block while application/interface/address restrictions remain.
            unsafe {
                if existing.Protocol()? != NET_FW_IP_PROTOCOL_ANY.0
                    || !existing.ApplicationName()?.is_empty()
                    || !existing.ServiceName()?.is_empty()
                    || existing.LocalAddresses()? != "*"
                    || has_excluded_interfaces(&OwnedVariant(existing.Interfaces()?).0)?
                {
                    bail!("existing TRAPD rule {name} has unexpected traffic restrictions");
                }
                existing.SetDirection(desired.Direction()?)?;
                existing.SetAction(desired.Action()?)?;
                existing.SetProfiles(desired.Profiles()?)?;
                existing.SetInterfaceTypes(&desired.InterfaceTypes()?)?;
                existing.SetEdgeTraversal(desired.EdgeTraversal()?)?;
                existing.SetDescription(&desired.Description()?)?;
                existing.SetRemoteAddresses(&desired.RemoteAddresses()?)?;
                existing.SetEnabled(desired.Enabled()?)?;
            }
        } else {
            unsafe { self.rules.Add(desired) }.context("install containment rule")?;
        }
        Ok(())
    }

    fn install_pair(&self, names: [&str; 2], remote: &str, description: &str) -> Result<()> {
        let old = [self.previous(names[0])?, self.previous(names[1])?];
        let new = [
            Self::make_rule(names[0], Direction::Out, remote, description, true)?,
            Self::make_rule(names[1], Direction::In, remote, description, true)?,
        ];
        let result = (|| -> Result<()> {
            for (name, rule) in names.into_iter().zip(&new) {
                self.write(name, rule)?;
            }
            self.ensure_enforcing()?;
            for name in names {
                let rule = self
                    .find(name)?
                    .context("containment rule missing after add")?;
                Self::require_owned(&rule, name)?;
                if unsafe { rule.Enabled() }?.0 == 0
                    || unsafe { rule.Action() }? != NET_FW_ACTION_BLOCK
                {
                    bail!("containment rule {name} is not enabled as a block");
                }
            }
            Ok(())
        })();
        if let Err(error) = result {
            let mut rollback_errors = Vec::new();
            for (name, previous) in names.into_iter().zip(old) {
                let restored = match previous {
                    Some(rule) => self.write(name, &rule),
                    None => self.remove(name).map(|_| ()),
                };
                if let Err(e) = restored {
                    rollback_errors.push(format!("{name}: {e:#}"));
                }
            }
            if !rollback_errors.is_empty() {
                return Err(anyhow!(
                    "containment failed: {error:#}; rollback failed: {}",
                    rollback_errors.join("; ")
                ));
            }
            return Err(error);
        }
        Ok(())
    }

    /// Snapshot before mutation: removing entries while advancing a live COM
    /// enumerator can skip rules. Interfaces remain on this apartment's thread.
    fn owned_rules(&self) -> Result<Vec<INetFwRule>> {
        let enumerator: IEnumVARIANT = unsafe { self.rules._NewEnum() }?.cast()?;
        let mut owned = Vec::new();
        loop {
            let mut value = OwnedVariant(VARIANT::default());
            let mut fetched = 0;
            unsafe { enumerator.Next(std::slice::from_mut(&mut value.0), &mut fetched) }
                .ok()
                .context("enumerate firewall rules")?;
            if fetched == 0 {
                break;
            }
            // SAFETY: Next initialized this VARIANT. Only read pdispVal when
            // the discriminator selects it; cast retains its own COM reference
            // before OwnedVariant clears the returned dispatch pointer.
            let rule: INetFwRule = unsafe {
                let body = &value.0.Anonymous.Anonymous;
                if body.vt != VT_DISPATCH {
                    bail!("unexpected firewall rule VARIANT type");
                }
                body.Anonymous
                    .pdispVal
                    .as_ref()
                    .context("null firewall rule dispatch")?
                    .cast()?
            };
            if unsafe { rule.Grouping() }? == firewall::GROUP {
                owned.push(rule);
            }
        }
        Ok(owned)
    }

    fn remove_pair(&self, names: [&str; 2]) -> Result<()> {
        let mut errors = Vec::new();
        for name in names {
            if let Err(e) = self.remove(name) {
                errors.push(format!("{name}: {e:#}"));
            }
        }
        if !errors.is_empty() {
            bail!("firewall removal failed: {}", errors.join("; "));
        }
        Ok(())
    }
}

fn has_excluded_interfaces(value: &VARIANT) -> Result<bool> {
    // SAFETY: the native API returned an initialized VARIANT. Read only the
    // arm selected by its discriminator; OwnedVariant frees it afterwards.
    unsafe {
        let body = &value.Anonymous.Anonymous;
        if body.vt == VT_EMPTY || body.vt == VT_NULL {
            return Ok(false);
        }
        if body.vt.0 & VT_ARRAY.0 == 0 {
            bail!("unexpected excluded-interface value type");
        }
        let array = body.Anonymous.parray;
        if array.is_null() {
            return Ok(false);
        }
        if SafeArrayGetDim(array) != 1 {
            bail!("invalid excluded-interface array");
        }
        Ok(SafeArrayGetUBound(array, 1)? >= SafeArrayGetLBound(array, 1)?)
    }
}

fn policy_dword(path: &str, name: &str) -> Result<Option<u32>> {
    use windows_sys::Win32::{
        Foundation::{ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND, ERROR_SUCCESS},
        System::Registry::{
            RegGetValueW, HKEY_LOCAL_MACHINE, RRF_RT_REG_DWORD, RRF_SUBKEY_WOW6464KEY,
        },
    };
    let path: Vec<u16> = path.encode_utf16().chain(Some(0)).collect();
    let name_wide: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
    let mut value = 0u32;
    let mut size = 4u32;
    // SAFETY: NUL-terminated strings and an aligned output buffer of size 4.
    let status = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            path.as_ptr(),
            name_wide.as_ptr(),
            RRF_RT_REG_DWORD | RRF_SUBKEY_WOW6464KEY,
            std::ptr::null_mut(),
            (&mut value as *mut u32).cast(),
            &mut size,
        )
    };
    match status {
        ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND => Ok(None),
        ERROR_SUCCESS if size == 4 && value <= 1 => Ok(Some(value)),
        _ => bail!("cannot read effective firewall policy {name} (status {status})"),
    }
}

pub(super) fn ensure_enforcing() -> Result<()> {
    Firewall::open()?.ensure_enforcing()
}

/// Read the configured DNS servers on active interfaces, using the same native
/// IPHelper API and bounded, aligned storage as Windows interface inventory.
/// This is not a lookup and never changes adapter or resolver configuration.
pub(super) fn management_dns_servers() -> Result<Vec<IpAddr>> {
    use windows_sys::Win32::{
        Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_NO_DATA, ERROR_SUCCESS},
        NetworkManagement::IpHelper::{
            GetAdaptersAddresses, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_MULTICAST,
        },
        Networking::WinSock::AF_UNSPEC,
    };
    let mut bytes = 15 * 1024u32;
    for _ in 0..3 {
        anyhow::ensure!(
            bytes <= 4 * 1024 * 1024,
            "OS DNS adapter table exceeds size ceiling"
        );
        let mut buffer = vec![0u64; (bytes as usize).div_ceil(8)];
        // SAFETY: aligned owned storage covers SizePointer. Include both DNS
        // and unicast addresses to refuse forwarders bound to a local LAN IP.
        let status = unsafe {
            GetAdaptersAddresses(
                AF_UNSPEC as u32,
                GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST,
                std::ptr::null(),
                buffer.as_mut_ptr().cast(),
                &mut bytes,
            )
        };
        match status {
            ERROR_BUFFER_OVERFLOW => continue,
            ERROR_NO_DATA => return Ok(Vec::new()),
            ERROR_SUCCESS => return dns_servers_from_adapters(&buffer),
            _ => bail!("OS DNS adapter query failed (status {status})"),
        }
    }
    bail!("OS DNS adapter table repeatedly changed")
}

fn dns_servers_from_adapters(buffer: &[u64]) -> Result<Vec<IpAddr>> {
    use windows_sys::Win32::NetworkManagement::{
        IpHelper::{
            IP_ADAPTER_ADDRESSES_LH, IP_ADAPTER_DNS_SERVER_ADDRESS_XP,
            IP_ADAPTER_UNICAST_ADDRESS_LH,
        },
        Ndis::IfOperStatusUp,
    };
    let start = buffer.as_ptr() as usize;
    let end = start + std::mem::size_of_val(buffer);
    let within = |ptr: usize, size: usize| ptr >= start && ptr <= end && size <= end - ptr;
    let mut adapter = buffer.as_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
    let mut servers = Vec::new();
    let mut local_ips = Vec::new();
    let mut adapters = 0;
    let mut addresses = 0;
    let mut unicast_addresses = 0;
    // SAFETY: every structure and socket pointer is range checked before an
    // unaligned read. Storage stays alive, counts bound malformed/cyclic lists.
    unsafe {
        while !adapter.is_null() {
            anyhow::ensure!(adapters < 1024, "OS DNS adapter count exceeds limit");
            anyhow::ensure!(
                within(
                    adapter as usize,
                    std::mem::size_of::<IP_ADAPTER_ADDRESSES_LH>()
                ),
                "invalid OS DNS adapter pointer"
            );
            let current = std::ptr::read_unaligned(adapter);
            adapters += 1;
            if current.OperStatus == IfOperStatusUp {
                let mut unicast = current.FirstUnicastAddress;
                while !unicast.is_null() {
                    anyhow::ensure!(
                        unicast_addresses < 4096,
                        "OS DNS unicast address count exceeds limit"
                    );
                    anyhow::ensure!(
                        within(
                            unicast as usize,
                            std::mem::size_of::<IP_ADAPTER_UNICAST_ADDRESS_LH>()
                        ),
                        "invalid OS DNS unicast pointer"
                    );
                    let current_unicast = std::ptr::read_unaligned(unicast);
                    unicast_addresses += 1;
                    local_ips.push(adapter_socket_ip(buffer, current_unicast.Address)?);
                    unicast = current_unicast.Next;
                }
                let mut dns = current.FirstDnsServerAddress;
                while !dns.is_null() {
                    anyhow::ensure!(addresses < 4096, "OS DNS address count exceeds limit");
                    anyhow::ensure!(
                        within(
                            dns as usize,
                            std::mem::size_of::<IP_ADAPTER_DNS_SERVER_ADDRESS_XP>()
                        ),
                        "invalid OS DNS server pointer"
                    );
                    let current_dns = std::ptr::read_unaligned(dns);
                    addresses += 1;
                    let ip = adapter_socket_ip(buffer, current_dns.Address)?;
                    if !servers.contains(&ip) {
                        anyhow::ensure!(servers.len() < 256, "OS DNS resolver count exceeds limit");
                        servers.push(ip);
                    }
                    dns = current_dns.Next;
                }
            }
            adapter = current.Next;
        }
    }
    for server in &servers {
        anyhow::ensure!(!local_ips.iter().any(|local| local.to_canonical() == server.to_canonical()), "management DNS resolver {server} is bound to a local interface; cannot prove upstream coverage, use a literal backend");
    }
    servers.sort();
    Ok(servers)
}

/// Decode both DNS-server and unicast sockets only inside their owned adapter
/// buffer. Native list data must not authorize reads outside this allocation.
fn adapter_socket_ip(
    buffer: &[u64],
    socket: windows_sys::Win32::Networking::WinSock::SOCKET_ADDRESS,
) -> Result<IpAddr> {
    use std::net::{Ipv4Addr, Ipv6Addr};
    use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6, SOCKADDR_IN, SOCKADDR_IN6};
    let start = buffer.as_ptr() as usize;
    let end = start + std::mem::size_of_val(buffer);
    let within = |ptr: usize, size: usize| ptr >= start && ptr <= end && size <= end - ptr;
    anyhow::ensure!(
        !socket.lpSockaddr.is_null()
            && socket.iSockaddrLength >= 2
            && within(socket.lpSockaddr as usize, 2),
        "invalid OS DNS socket pointer or length"
    );
    // SAFETY: check the family first, then the full declared socket size and
    // address range before an unaligned read. The borrowed buffer stays alive.
    unsafe {
        let family = std::ptr::read_unaligned(socket.lpSockaddr.cast::<u16>());
        match family {
            AF_INET => {
                anyhow::ensure!(
                    socket.iSockaddrLength >= std::mem::size_of::<SOCKADDR_IN>() as i32
                        && within(
                            socket.lpSockaddr as usize,
                            std::mem::size_of::<SOCKADDR_IN>()
                        ),
                    "invalid OS DNS IPv4 socket"
                );
                let addr = std::ptr::read_unaligned(socket.lpSockaddr.cast::<SOCKADDR_IN>());
                Ok(IpAddr::V4(Ipv4Addr::from(
                    addr.sin_addr.S_un.S_addr.to_ne_bytes(),
                )))
            }
            AF_INET6 => {
                anyhow::ensure!(
                    socket.iSockaddrLength >= std::mem::size_of::<SOCKADDR_IN6>() as i32
                        && within(
                            socket.lpSockaddr as usize,
                            std::mem::size_of::<SOCKADDR_IN6>()
                        ),
                    "invalid OS DNS IPv6 socket"
                );
                let addr = std::ptr::read_unaligned(socket.lpSockaddr.cast::<SOCKADDR_IN6>());
                Ok(IpAddr::V6(Ipv6Addr::from(addr.sin6_addr.u.Byte)))
            }
            _ => bail!("unsupported OS DNS socket family {family}"),
        }
    }
}

pub(super) fn block(target: &IpNet) -> Result<String> {
    block_with_ttl(target, None, "")
}

pub(super) fn block_with_ttl(target: &IpNet, ttl: Option<u64>, command_id: &str) -> Result<String> {
    block_with_ttl_at(target, ttl, command_id, unix_now()?)
}

fn unix_now() -> Result<u64> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system time before Unix epoch")?
        .as_secs())
}

fn block_with_ttl_at(
    target: &IpNet,
    ttl: Option<u64>,
    command_id: &str,
    now: u64,
) -> Result<String> {
    let description = firewall::block_description(ttl, command_id, now)?;
    let _guard = mutation_guard()?;
    let fw = Firewall::open()?;
    fw.ensure_enforcing()?;
    let remote = firewall::remote_for(&target.trunc());
    let names = [
        firewall::block_rule_name(&remote, Direction::Out),
        firewall::block_rule_name(&remote, Direction::In),
    ];
    fw.install_pair([&names[0], &names[1]], &remote, &description)?;
    tracing::info!(target = %remote, "native windows firewall block rules added");
    Ok(format!("windows-firewall:{remote}"))
}

pub(super) fn unblock(target: &IpNet) -> Result<()> {
    let _guard = mutation_guard()?;
    let remote = firewall::remote_for(&target.trunc());
    let names = [
        firewall::block_rule_name(&remote, Direction::Out),
        firewall::block_rule_name(&remote, Direction::In),
    ];
    Firewall::open()?.remove_pair([&names[0], &names[1]])
}

pub(super) fn isolate(allow: &[IpAddr]) -> Result<()> {
    let _guard = mutation_guard()?;
    let fw = Firewall::open()?;
    fw.ensure_enforcing()?;
    fw.install_pair(
        [firewall::ISOLATE_OUT, firewall::ISOLATE_IN],
        &firewall::complement_ranges(allow).join(","),
        "TRAPD containment: host isolated",
    )
}

pub(super) fn deisolate() -> Result<()> {
    let _guard = mutation_guard()?;
    Firewall::open()?.remove_pair([firewall::ISOLATE_OUT, firewall::ISOLATE_IN])
}

/// Explicit uninstall only: remove the owned group even when the firewall is
/// disabled. Report every failure so MSI cannot remove the binary on failure.
pub(crate) fn cleanup() -> Result<()> {
    let _guard = mutation_guard()?;
    let fw = Firewall::open()?;
    let mut errors = Vec::new();
    for rule in fw.owned_rules()? {
        let name = unsafe { rule.Name() }?.to_string();
        if let Err(error) = fw.remove(&name) {
            errors.push(format!("{name}: {error:#}"));
        }
    }
    if !errors.is_empty() {
        bail!("firewall cleanup failed: {}", errors.join("; "));
    }
    if !fw.owned_rules()?.is_empty() {
        bail!("TRAPD firewall rules remain after cleanup");
    }
    Ok(())
}

pub(crate) struct ExpiredBlock {
    pub target: String,
    pub command_id: String,
}

/// Re-read current persistent metadata under the same lock as block/unblock,
/// so a replacement rule's deadline wins over any previous command's expiry.
pub(super) fn expire_blocks(now: u64) -> Result<Vec<ExpiredBlock>> {
    let _guard = mutation_guard()?;
    let fw = Firewall::open()?;
    let mut removed = std::collections::BTreeMap::new();
    for rule in fw.owned_rules()? {
        let name = unsafe { rule.Name() }?.to_string();
        let expiry = match firewall::block_expiry(&unsafe { rule.Description() }?.to_string()) {
            Ok(Some(expiry)) if expiry.expired(now) => expiry,
            Ok(_) => continue,
            Err(error) => {
                tracing::warn!(%name, %error, "invalid firewall expiry metadata");
                continue;
            }
        };
        let Some((target, _)) = firewall::parse_block_rule_name(&name) else {
            tracing::warn!(%name, "expiry metadata on unexpected firewall rule name");
            continue;
        };
        let remote = firewall::remote_for(&target);
        match fw.remove(&name) {
            Ok(_) => {
                removed.insert(remote, expiry.command_id);
            }
            Err(error) => tracing::warn!(%name, %error, "TTL firewall removal failed; will retry"),
        }
    }
    let mut expired = Vec::new();
    for (target, command_id) in removed {
        // Retain engine dedup state until BOTH directions are gone. A failed
        // half is retried on the next pass without losing its stored deadline.
        if fw
            .find(&firewall::block_rule_name(&target, Direction::Out))?
            .is_none()
            && fw
                .find(&firewall::block_rule_name(&target, Direction::In))?
                .is_none()
        {
            expired.push(ExpiredBlock { target, command_id });
        }
    }
    Ok(expired)
}

pub(crate) fn expire_due_blocks() -> Result<Vec<ExpiredBlock>> {
    expire_blocks(unix_now()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dns_adapter_fixture() -> Vec<u64> {
        use windows_sys::Win32::{
            NetworkManagement::{
                IpHelper::{IP_ADAPTER_ADDRESSES_LH, IP_ADAPTER_DNS_SERVER_ADDRESS_XP},
                Ndis::{IfOperStatusDown, IfOperStatusUp},
            },
            Networking::WinSock::{AF_INET, AF_INET6, SOCKADDR_IN, SOCKADDR_IN6},
        };
        let mut buffer = vec![0u64; 512];
        // SAFETY: the 4 KiB allocation covers two adapters, two DNS nodes and
        // both socket structures. Unaligned writes need no alignment promise.
        unsafe {
            let adapter = buffer.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
            let down = adapter.add(1);
            let dns = down.add(1).cast::<IP_ADAPTER_DNS_SERVER_ADDRESS_XP>();
            let socket_v4 = dns.add(2).cast::<SOCKADDR_IN>();
            let socket_v6 = socket_v4.add(1).cast::<SOCKADDR_IN6>();
            std::ptr::write_unaligned(
                adapter,
                IP_ADAPTER_ADDRESSES_LH {
                    Next: down,
                    FirstDnsServerAddress: dns,
                    OperStatus: IfOperStatusUp,
                    ..Default::default()
                },
            );
            std::ptr::write_unaligned(
                down,
                IP_ADAPTER_ADDRESSES_LH {
                    // An inactive interface cannot provide live DNS coverage.
                    FirstDnsServerAddress: std::ptr::dangling_mut(),
                    FirstUnicastAddress: std::ptr::dangling_mut(),
                    OperStatus: IfOperStatusDown,
                    ..Default::default()
                },
            );
            let mut v4 = SOCKADDR_IN {
                sin_family: AF_INET,
                ..Default::default()
            };
            v4.sin_addr.S_un.S_addr = u32::from_ne_bytes([192, 0, 2, 53]);
            std::ptr::write_unaligned(socket_v4, v4);
            let mut v6 = SOCKADDR_IN6 {
                sin6_family: AF_INET6,
                ..Default::default()
            };
            v6.sin6_addr.u.Byte = "2001:db8::53"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets();
            std::ptr::write_unaligned(socket_v6, v6);
            let mut first = IP_ADAPTER_DNS_SERVER_ADDRESS_XP {
                Next: dns.add(1),
                ..Default::default()
            };
            first.Address.lpSockaddr = socket_v4.cast();
            first.Address.iSockaddrLength = std::mem::size_of::<SOCKADDR_IN>() as i32;
            std::ptr::write_unaligned(dns, first);
            let mut second = IP_ADAPTER_DNS_SERVER_ADDRESS_XP::default();
            second.Address.lpSockaddr = socket_v6.cast();
            second.Address.iSockaddrLength = std::mem::size_of::<SOCKADDR_IN6>() as i32;
            std::ptr::write_unaligned(dns.add(1), second);
        }
        buffer
    }

    #[test]
    fn dns_adapter_parser_rejects_local_lan_forwarders_even_when_explicitly_allowed() {
        use windows_sys::Win32::NetworkManagement::{
            IpHelper::{IP_ADAPTER_ADDRESSES_LH, IP_ADAPTER_UNICAST_ADDRESS_LH},
            Ndis::IfOperStatusUp,
        };
        for (v6, same_adapter) in [(false, true), (true, true), (false, false), (true, false)] {
            let mut buffer = dns_adapter_fixture();
            // SAFETY: spare aligned fixture storage holds the unicast node;
            // its socket points at the already initialized v4/v6 DNS address.
            unsafe {
                let first = buffer.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
                let adapter = if same_adapter { first } else { first.add(1) };
                let dns = (*first).FirstDnsServerAddress.add(usize::from(v6));
                let unicast = buffer
                    .as_mut_ptr()
                    .add(256)
                    .cast::<IP_ADAPTER_UNICAST_ADDRESS_LH>();
                std::ptr::write_unaligned(
                    unicast,
                    IP_ADAPTER_UNICAST_ADDRESS_LH {
                        Address: (*dns).Address,
                        ..Default::default()
                    },
                );
                (*adapter).FirstUnicastAddress = unicast;
                (*adapter).OperStatus = IfOperStatusUp;
                if !same_adapter {
                    (*adapter).FirstDnsServerAddress = std::ptr::null_mut();
                }
            }
            let expected: IpAddr = if v6 { "2001:db8::53" } else { "192.0.2.53" }
                .parse()
                .unwrap();
            assert!(firewall::require_management_dns(
                "control.example.test",
                &[expected],
                &[expected]
            )
            .is_ok());
            let error = dns_servers_from_adapters(&buffer).unwrap_err();
            assert!(error.to_string().contains("local"), "{error:#}");
        }
    }

    #[test]
    fn dns_adapter_parser_rejects_ipv4_mapped_local_forwarders() {
        use windows_sys::Win32::{
            NetworkManagement::IpHelper::{IP_ADAPTER_ADDRESSES_LH, IP_ADAPTER_UNICAST_ADDRESS_LH},
            Networking::WinSock::SOCKADDR_IN6,
        };
        let mut buffer = dns_adapter_fixture();
        // SAFETY: all pointers refer to the owned fixture. Its IPv4 socket is
        // local; the DNS entry names the same host with an IPv4-mapped IPv6 IP.
        unsafe {
            let adapter = buffer.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
            let dns = (*adapter).FirstDnsServerAddress;
            let unicast = buffer
                .as_mut_ptr()
                .add(256)
                .cast::<IP_ADAPTER_UNICAST_ADDRESS_LH>();
            std::ptr::write_unaligned(
                unicast,
                IP_ADAPTER_UNICAST_ADDRESS_LH {
                    Address: (*dns).Address,
                    ..Default::default()
                },
            );
            (*adapter).FirstUnicastAddress = unicast;
            (*adapter).FirstDnsServerAddress = (*dns).Next;
            let socket = (*(*dns).Next).Address.lpSockaddr.cast::<SOCKADDR_IN6>();
            (*socket).sin6_addr.u.Byte = "::ffff:192.0.2.53"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets();
        }
        assert!(dns_servers_from_adapters(&buffer)
            .unwrap_err()
            .to_string()
            .contains("local"));
    }

    #[test]
    fn dns_adapter_parser_reads_both_families_and_ignores_inactive_interfaces() {
        let buffer = dns_adapter_fixture();
        let servers = dns_servers_from_adapters(&buffer).unwrap();
        assert_eq!(
            servers,
            vec![
                "192.0.2.53".parse::<IpAddr>().unwrap(),
                "2001:db8::53".parse().unwrap()
            ]
        );
    }

    #[test]
    fn dns_adapter_parser_rejects_invalid_sockets_and_bounded_list_cycles() {
        use windows_sys::Win32::NetworkManagement::IpHelper::{
            IP_ADAPTER_ADDRESSES_LH, IP_ADAPTER_UNICAST_ADDRESS_LH,
        };
        for failure in [
            "pointer",
            "length",
            "family",
            "cycle",
            "unicast_pointer",
            "unicast_cycle",
            "unicast_socket",
        ] {
            let mut buffer = dns_adapter_fixture();
            // SAFETY: fixture owns valid pointers; mutate only its first node.
            unsafe {
                let adapter = buffer.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
                let dns = (*adapter).FirstDnsServerAddress;
                let unicast = buffer
                    .as_mut_ptr()
                    .add(256)
                    .cast::<IP_ADAPTER_UNICAST_ADDRESS_LH>();
                match failure {
                    "pointer" => (*dns).Address.lpSockaddr = std::ptr::dangling_mut(),
                    "length" => (*dns).Address.iSockaddrLength = -1,
                    "family" => {
                        std::ptr::write_unaligned((*dns).Address.lpSockaddr.cast::<u16>(), 0)
                    }
                    "cycle" => (*dns).Next = dns,
                    "unicast_pointer" => (*adapter).FirstUnicastAddress = std::ptr::dangling_mut(),
                    _ => {
                        std::ptr::write_unaligned(
                            unicast,
                            IP_ADAPTER_UNICAST_ADDRESS_LH {
                                Next: if failure == "unicast_cycle" {
                                    unicast
                                } else {
                                    std::ptr::null_mut()
                                },
                                Address: (*dns).Address,
                                ..Default::default()
                            },
                        );
                        (*adapter).FirstUnicastAddress = unicast;
                        if failure == "unicast_socket" {
                            (*unicast).Address.lpSockaddr = std::ptr::dangling_mut();
                        }
                    }
                }
            }
            assert!(dns_servers_from_adapters(&buffer).is_err(), "{failure}");
        }
    }

    struct Cleanup<'a> {
        firewall: &'a Firewall,
        names: Vec<String>,
    }
    impl Drop for Cleanup<'_> {
        fn drop(&mut self) {
            for name in &self.names {
                let _ = unsafe { self.firewall.rules.Remove(&BSTR::from(name.as_str())) };
            }
        }
    }

    #[test]
    #[ignore = "changes firewall rules; requires elevated Windows host"]
    fn native_windows_firewall_cleanup_preserves_other_groups() {
        let fw = Firewall::open().unwrap();
        let owned = format!("TRAPD-CLEANUP-TEST-{}", std::process::id());
        let external = format!("TRAPD-EXTERNAL-TEST-{}", std::process::id());
        let _cleanup = Cleanup {
            firewall: &fw,
            names: vec![owned.clone(), external.clone()],
        };
        for (name, group) in [(&owned, firewall::GROUP), (&external, "Other-Application")] {
            let rule =
                Firewall::make_rule(name, Direction::Out, "203.0.113.77", "cleanup test", false)
                    .unwrap();
            unsafe {
                rule.SetGrouping(&BSTR::from(group)).unwrap();
                fw.rules.Add(&rule).unwrap();
            }
        }
        cleanup().unwrap();
        assert!(fw.find(&owned).unwrap().is_none());
        assert!(fw.find(&external).unwrap().is_some());
        cleanup().unwrap();
        assert!(fw.find(&external).unwrap().is_some());
    }

    #[test]
    #[ignore = "blocks TEST-NET; requires elevated enforcing Windows host"]
    fn native_windows_firewall_expiry_survives_reopen_and_replacement() {
        let target: IpNet = "203.0.113.78/32".parse().unwrap();
        let names = vec![
            firewall::block_rule_name("203.0.113.78", Direction::Out),
            firewall::block_rule_name("203.0.113.78", Direction::In),
        ];
        let fw = Firewall::open().unwrap();
        let _cleanup = Cleanup {
            firewall: &fw,
            names: names.clone(),
        };
        block_with_ttl_at(&target, Some(60), "command-old", 1_000).unwrap();
        // A fresh COM connection reads the persistent rule description, with
        // no timer or in-memory expiry state inherited from the installer.
        let reopened = Firewall::open().unwrap();
        for name in &names {
            let rule = reopened.find(name).unwrap().unwrap();
            let expiry =
                firewall::block_expiry(&unsafe { rule.Description() }.unwrap().to_string())
                    .unwrap()
                    .unwrap();
            assert_eq!(expiry.deadline, 1_060);
        }
        assert!(expire_blocks(1_059).unwrap().is_empty());
        block_with_ttl_at(&target, Some(120), "command-new", 1_000).unwrap();
        assert!(
            expire_blocks(1_060).unwrap().is_empty(),
            "old deadline must not remove replacement"
        );
        let expired = expire_blocks(1_120).unwrap();
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].target, "203.0.113.78");
        assert_eq!(expired[0].command_id, "command-new");
        for name in &names {
            assert!(reopened.find(name).unwrap().is_none());
        }
        assert!(expire_blocks(1_121).unwrap().is_empty());
        block_with_ttl_at(&target, Some(60), "command-old", 1_000).unwrap();
        block(&target).unwrap();
        assert!(
            expire_blocks(2_000).unwrap().is_empty(),
            "a permanent replacement must remain"
        );
        for name in &names {
            assert!(reopened.find(name).unwrap().is_some());
        }
        unblock(&target).unwrap();
        block_with_ttl_at(&target, Some(0), "command-zero", 2_000).unwrap();
        assert_eq!(expire_blocks(2_000).unwrap().len(), 1);
        // Resume a partially completed expiry (e.g. a crash after removing OUT).
        block_with_ttl_at(&target, Some(10), "command-partial", 3_000).unwrap();
        fw.remove(&names[0]).unwrap();
        let expired = expire_blocks(3_010).unwrap();
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].command_id, "command-partial");
        assert!(fw.find(&names[1]).unwrap().is_none());
    }

    #[test]
    #[ignore = "blocks TEST-NET; requires elevated enforcing Windows host"]
    fn native_windows_firewall_expiry_supports_ipv4_and_ipv6_cidrs() {
        let fw = Firewall::open().unwrap();
        for target in ["203.0.113.128/25", "2001:db8::1/128", "2001:db8::/64"] {
            let target: IpNet = target.parse().unwrap();
            let remote = firewall::remote_for(&target);
            let names = vec![
                firewall::block_rule_name(&remote, Direction::Out),
                firewall::block_rule_name(&remote, Direction::In),
            ];
            let _cleanup = Cleanup {
                firewall: &fw,
                names: names.clone(),
            };
            block_with_ttl_at(&target, Some(10), "command-cidr", 1_000).unwrap();
            let expired = expire_blocks(1_010).unwrap();
            assert_eq!(expired.len(), 1);
            assert_eq!(expired[0].target, remote);
            for name in &names {
                assert!(fw.find(name).unwrap().is_none());
            }
        }
    }

    #[test]
    #[ignore = "changes firewall rule collection; requires elevated Windows host"]
    fn native_windows_firewall_rule_roundtrip() {
        let fw = Firewall::open().unwrap();
        let name = format!("TRAPD-NATIVE-TEST-{}", std::process::id());
        let _cleanup = Cleanup {
            firewall: &fw,
            names: vec![name.clone()],
        };
        let ranges = firewall::complement_ranges(&[
            "192.0.2.10".parse().unwrap(),
            "2001:db8::1".parse().unwrap(),
        ])
        .join(",");
        let rule = Firewall::make_rule(
            &name,
            Direction::Out,
            &ranges,
            "Native containment test (disabled)",
            false,
        )
        .unwrap();
        unsafe { fw.rules.Add(&rule) }.unwrap();
        let read = fw.find(&name).unwrap().unwrap();
        unsafe {
            assert_eq!(read.Enabled().unwrap().0, 0);
            assert_eq!(read.Action().unwrap(), NET_FW_ACTION_BLOCK);
            assert_eq!(read.Direction().unwrap(), NET_FW_RULE_DIR_OUT);
            assert_eq!(read.Grouping().unwrap().to_string(), firewall::GROUP);
            assert!(!read.RemoteAddresses().unwrap().is_empty());
        }
        assert!(fw.remove(&name).unwrap());
        assert!(!fw.remove(&name).unwrap());
        assert!(fw.find(&name).unwrap().is_none());
    }

    #[test]
    #[ignore = "blocks TEST-NET and requires elevated enforcing Windows host"]
    fn native_windows_firewall_block_and_unblock() {
        let target: IpNet = "203.0.113.77/32".parse().unwrap();
        let fw = Firewall::open().unwrap();
        fw.ensure_enforcing().unwrap();
        let names = vec![
            firewall::block_rule_name("203.0.113.77", Direction::Out),
            firewall::block_rule_name("203.0.113.77", Direction::In),
        ];
        let _cleanup = Cleanup {
            firewall: &fw,
            names: names.clone(),
        };
        block(&target).unwrap();
        let count = unsafe { fw.rules.Count() }.unwrap();
        block(&target).unwrap();
        assert_eq!(
            unsafe { fw.rules.Count() }.unwrap(),
            count,
            "re-block must replace, not stack"
        );
        for name in &names {
            assert!(fw.find(name).unwrap().is_some());
        }
        let outbound = fw.find(&names[0]).unwrap().unwrap();
        let inbound = fw.find(&names[1]).unwrap().unwrap();
        let application = BSTR::from(std::env::current_exe().unwrap().to_string_lossy().as_ref());
        let prior_description =
            firewall::block_description(Some(60), "prior-command", 1_000).unwrap();
        unsafe {
            outbound
                .SetDescription(&BSTR::from(prior_description.as_str()))
                .unwrap();
            outbound.SetProfiles(1).unwrap();
            inbound.SetApplicationName(&application).unwrap();
        }
        assert!(
            block(&target).is_err(),
            "an application-specific rule must not be reported as a broad block"
        );
        assert_eq!(unsafe { inbound.ApplicationName() }.unwrap(), application);
        assert_eq!(
            unsafe { outbound.Description() }.unwrap().to_string(),
            prior_description,
            "failed re-block must restore the original expiry metadata"
        );
        assert_eq!(
            unsafe { outbound.Profiles() }.unwrap(),
            1,
            "failed paired update must restore the operator's profile scope"
        );
        unblock(&target).unwrap();
        for name in &names {
            assert!(fw.find(name).unwrap().is_none());
        }
        unblock(&target).unwrap();
    }
}
