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
