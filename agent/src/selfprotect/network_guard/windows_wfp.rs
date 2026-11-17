//! Windows Filtering Platform reader.
//!
//! Windows Firewall rules (`New-NetFirewallRule -Program`, `netsh advfirewall`)
//! are compiled into WFP filters of the "Microsoft Windows Firewall" provider,
//! and EDRSilencer-style tools add filters directly. Enumerating the WFP
//! filters therefore covers both; no separate `INetFwPolicy2` pass is needed.
//!
//! Every filter whose action is block and whose conditions name our
//! application id (`FWPM_CONDITION_ALE_APP_ID`) or a backend address is
//! reported. Filter changes wake the guard through `FwpmFilterSubscribeChanges0`;
//! the periodic scan is the safety net.

use std::collections::HashMap;
use std::ffi::c_void;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::ptr::{null, null_mut};
use std::sync::{Arc, OnceLock};

use tokio::sync::Notify;
use windows_sys::core::GUID;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FwpmEngineClose0, FwpmEngineOpen0, FwpmFilterCreateEnumHandle0, FwpmFilterDestroyEnumHandle0,
    FwpmFilterEnum0, FwpmFilterSubscribeChanges0, FwpmFilterUnsubscribeChanges0, FwpmFreeMemory0,
    FwpmGetAppIdFromFileName0, FwpmLayerGetByKey0, FwpmProviderGetByKey0, FWPM_CHANGE_ADD,
    FWPM_CONDITION_ALE_APP_ID, FWPM_CONDITION_IP_REMOTE_ADDRESS, FWPM_FILTER0, FWPM_FILTER_CHANGE0,
    FWPM_FILTER_CONDITION0, FWPM_FILTER_FLAG_DISABLED, FWPM_FILTER_SUBSCRIPTION0, FWPM_LAYER0,
    FWPM_PROVIDER0, FWP_ACTION_BLOCK, FWP_ACTION_PERMIT, FWP_BYTE_ARRAY16_TYPE, FWP_BYTE_BLOB,
    FWP_BYTE_BLOB_TYPE, FWP_MATCH_EQUAL, FWP_MATCH_RANGE, FWP_RANGE0, FWP_RANGE_TYPE, FWP_UINT32,
    FWP_V4_ADDR_MASK, FWP_V6_ADDR_MASK, FWP_VALUE0,
};

use super::matching::{
    blocks_us, normalize_app_id, AddrMatch, FilterInfo, Reason, Targets, Verdict,
};

/// `RPC_C_AUTHN_DEFAULT`: let the engine pick the authentication service.
const AUTHN_DEFAULT: u32 = 0xFFFF_FFFF;
const BATCH: u32 = 256;
/// Upper bound on filters read per scan (a normal machine has a few thousand).
const MAX_FILTERS: usize = 100_000;

/// WFP engine handle. Handles are process-wide RPC context handles and may be
/// used from any thread.
struct Engine(HANDLE);
// SAFETY: a WFP engine handle is an RPC context handle without thread affinity.
unsafe impl Send for Engine {}

impl Engine {
    fn open() -> Result<Self, u32> {
        let mut h: HANDLE = null_mut();
        // SAFETY: null server/identity/session select the local engine with
        // defaults; `h` is a valid out-pointer.
        let rc = unsafe { FwpmEngineOpen0(null(), AUTHN_DEFAULT, null(), null(), &mut h) };
        if rc == 0 {
            Ok(Self(h))
        } else {
            Err(rc)
        }
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        // SAFETY: handle came from FwpmEngineOpen0 and is closed once.
        unsafe { FwpmEngineClose0(self.0) };
    }
}

/// Application id of an executable as WFP stores it (NT device path, lowercase).
pub fn app_id_for_path(path: &Path) -> Option<String> {
    use std::os::windows::ffi::OsStrExt;
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let mut blob: *mut FWP_BYTE_BLOB = null_mut();
    // SAFETY: NUL-terminated path; out-pointer valid. The blob is freed below.
    let rc = unsafe { FwpmGetAppIdFromFileName0(wide.as_ptr(), &mut blob) };
    if rc != 0 || blob.is_null() {
        return None;
    }
    // SAFETY: the API returned a valid blob that stays alive until freed.
    let id = unsafe { blob_to_string(&*blob) };
    let mut p = blob.cast::<c_void>();
    // SAFETY: memory allocated by the WFP API, freed exactly once.
    unsafe { FwpmFreeMemory0(&mut p) };
    id.map(|s| normalize_app_id(&s))
}

/// UTF-16LE blob (as used for app ids) to a string.
///
/// # Safety
/// `blob.data` must point to `blob.size` readable bytes.
unsafe fn blob_to_string(blob: &FWP_BYTE_BLOB) -> Option<String> {
    if blob.data.is_null() || blob.size < 2 || blob.size > 65_536 {
        return None;
    }
    let bytes = std::slice::from_raw_parts(blob.data, blob.size as usize);
    let units: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        .collect();
    String::from_utf16(&units).ok()
}

/// # Safety
/// `p` is null or a NUL-terminated UTF-16 string.
unsafe fn pwstr(p: *mut u16) -> String {
    if p.is_null() {
        return String::new();
    }
    let mut len = 0;
    while len < 1024 && *p.add(len) != 0 {
        len += 1;
    }
    String::from_utf16_lossy(std::slice::from_raw_parts(p, len))
}

fn v4(u: u32) -> IpAddr {
    IpAddr::V4(Ipv4Addr::from(u))
}

/// # Safety
/// `v` holds the union member its `type` names.
unsafe fn value_ip(v: &FWP_VALUE0) -> Option<IpAddr> {
    if v.r#type == FWP_UINT32 {
        Some(v4(v.Anonymous.uint32))
    } else if v.r#type == FWP_BYTE_ARRAY16_TYPE && !v.Anonymous.byteArray16.is_null() {
        Some(IpAddr::V6(Ipv6Addr::from(
            (*v.Anonymous.byteArray16).byteArray16,
        )))
    } else {
        None
    }
}

/// Remote-address condition to a match; `None` for types we do not model.
///
/// # Safety
/// `c.conditionValue` holds the union member its `type` names.
unsafe fn remote_match(c: &FWPM_FILTER_CONDITION0) -> Option<AddrMatch> {
    let val = &c.conditionValue;
    let t = val.r#type;
    if c.matchType == FWP_MATCH_EQUAL {
        if t == FWP_UINT32 {
            return Some(AddrMatch::Addr(v4(val.Anonymous.uint32)));
        }
        if t == FWP_BYTE_ARRAY16_TYPE && !val.Anonymous.byteArray16.is_null() {
            return Some(AddrMatch::Addr(IpAddr::V6(Ipv6Addr::from(
                (*val.Anonymous.byteArray16).byteArray16,
            ))));
        }
        if t == FWP_V4_ADDR_MASK && !val.Anonymous.v4AddrMask.is_null() {
            let m = &*val.Anonymous.v4AddrMask;
            return Some(AddrMatch::Net(v4(m.addr), m.mask.count_ones() as u8));
        }
        if t == FWP_V6_ADDR_MASK && !val.Anonymous.v6AddrMask.is_null() {
            let m = &*val.Anonymous.v6AddrMask;
            return Some(AddrMatch::Net(
                IpAddr::V6(Ipv6Addr::from(m.addr)),
                m.prefixLength,
            ));
        }
    }
    if (c.matchType == FWP_MATCH_RANGE || c.matchType == FWP_MATCH_EQUAL)
        && t == FWP_RANGE_TYPE
        && !val.Anonymous.rangeValue.is_null()
    {
        let r: &FWP_RANGE0 = &*val.Anonymous.rangeValue;
        return Some(AddrMatch::Range(
            value_ip(&r.valueLow)?,
            value_ip(&r.valueHigh)?,
        ));
    }
    None
}

fn key(g: &GUID) -> (u32, u16, u16, [u8; 8]) {
    (g.data1, g.data2, g.data3, g.data4)
}

fn guid_text(g: &GUID) -> String {
    format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        g.data1,
        g.data2,
        g.data3,
        g.data4[0],
        g.data4[1],
        g.data4[2],
        g.data4[3],
        g.data4[4],
        g.data4[5],
        g.data4[6],
        g.data4[7]
    )
}

/// Reduce one WFP filter to the fields the matcher needs.
///
/// # Safety
/// `f` is a filter returned by `FwpmFilterEnum0` that has not been freed.
unsafe fn filter_info(f: &FWPM_FILTER0) -> FilterInfo {
    let verdict = if f.action.r#type == FWP_ACTION_BLOCK {
        Verdict::Block
    } else if f.action.r#type == FWP_ACTION_PERMIT {
        Verdict::Permit
    } else {
        Verdict::Other
    };
    let mut info = FilterInfo {
        source: "wfp",
        name: pwstr(f.displayData.name),
        provider: String::new(),
        layer: guid_text(&f.layerKey),
        verdict,
        disabled: f.flags & FWPM_FILTER_FLAG_DISABLED != 0,
        app_ids: vec![],
        remote: vec![],
        uid_ranges: vec![],
        cgroup_paths: vec![],
        cgroup_ids: vec![],
    };
    if !f.filterCondition.is_null() && f.numFilterConditions > 0 {
        let conds = std::slice::from_raw_parts(
            f.filterCondition,
            (f.numFilterConditions as usize).min(256),
        );
        for c in conds {
            if key(&c.fieldKey) == key(&FWPM_CONDITION_ALE_APP_ID) {
                if c.matchType == FWP_MATCH_EQUAL
                    && c.conditionValue.r#type == FWP_BYTE_BLOB_TYPE
                    && !c.conditionValue.Anonymous.byteBlob.is_null()
                {
                    if let Some(s) = blob_to_string(&*c.conditionValue.Anonymous.byteBlob) {
                        info.app_ids.push(normalize_app_id(&s));
                    }
                }
            } else if key(&c.fieldKey) == key(&FWPM_CONDITION_IP_REMOTE_ADDRESS) {
                if let Some(m) = remote_match(c) {
                    info.remote.push(m);
                }
            }
        }
    }
    info
}

/// Names of layers and providers, resolved lazily and only for hits.
struct Names<'a> {
    engine: &'a Engine,
    layers: HashMap<(u32, u16, u16, [u8; 8]), String>,
    providers: HashMap<(u32, u16, u16, [u8; 8]), String>,
}

impl Names<'_> {
    fn layer(&mut self, g: &GUID) -> String {
        if let Some(n) = self.layers.get(&key(g)) {
            return n.clone();
        }
        let mut p: *mut FWPM_LAYER0 = null_mut();
        // SAFETY: valid engine, key and out-pointer; freed below.
        let name = if unsafe { FwpmLayerGetByKey0(self.engine.0, g, &mut p) } == 0 && !p.is_null() {
            // SAFETY: `p` is a valid layer until freed.
            let n = unsafe { pwstr((*p).displayData.name) };
            let mut raw = p.cast::<c_void>();
            // SAFETY: WFP-allocated, freed once.
            unsafe { FwpmFreeMemory0(&mut raw) };
            n
        } else {
            guid_text(g)
        };
        self.layers.insert(key(g), name.clone());
        name
    }

    fn provider(&mut self, g: *const GUID) -> String {
        if g.is_null() {
            return "none".into();
        }
        // SAFETY: non-null provider key inside a live filter.
        let g = unsafe { *g };
        if let Some(n) = self.providers.get(&key(&g)) {
            return n.clone();
        }
        let mut p: *mut FWPM_PROVIDER0 = null_mut();
        // SAFETY: valid engine, key and out-pointer; freed below.
        let name =
            if unsafe { FwpmProviderGetByKey0(self.engine.0, &g, &mut p) } == 0 && !p.is_null() {
                // SAFETY: `p` is a valid provider until freed.
                let n = unsafe { pwstr((*p).displayData.name) };
                let mut raw = p.cast::<c_void>();
                // SAFETY: WFP-allocated, freed once.
                unsafe { FwpmFreeMemory0(&mut raw) };
                n
            } else {
                guid_text(&g)
            };
        self.providers.insert(key(&g), name.clone());
        name
    }
}

/// Enumerate all filters and return those that block `targets`, with layer and
/// provider resolved to display names.
pub fn blocking_filters(targets: &Targets) -> Result<Vec<(FilterInfo, Reason)>, u32> {
    let engine = Engine::open()?;
    let mut eh: HANDLE = null_mut();
    // SAFETY: null template enumerates every filter; out-pointer valid.
    let rc = unsafe { FwpmFilterCreateEnumHandle0(engine.0, null(), &mut eh) };
    if rc != 0 {
        return Err(rc);
    }
    let mut names = Names {
        engine: &engine,
        layers: HashMap::new(),
        providers: HashMap::new(),
    };
    let mut hits = Vec::new();
    let mut seen = 0usize;
    let mut status = 0;
    loop {
        let mut entries: *mut *mut FWPM_FILTER0 = null_mut();
        let mut n = 0u32;
        // SAFETY: valid engine + enum handle; out-pointers valid.
        let rc = unsafe { FwpmFilterEnum0(engine.0, eh, BATCH, &mut entries, &mut n) };
        if rc != 0 {
            status = rc;
            break;
        }
        if !entries.is_null() {
            for i in 0..n as usize {
                // SAFETY: the API returned `n` valid filter pointers.
                let f = unsafe { &**entries.add(i) };
                // SAFETY: `f` stays valid until the array is freed below.
                let mut info = unsafe { filter_info(f) };
                if let Some(reason) = blocks_us(&info, targets) {
                    info.layer = names.layer(&f.layerKey);
                    info.provider = names.provider(f.providerKey);
                    hits.push((info, reason));
                }
            }
            let mut raw = entries.cast::<c_void>();
            // SAFETY: WFP-allocated array, freed once.
            unsafe { FwpmFreeMemory0(&mut raw) };
        }
        seen += n as usize;
        if n < BATCH || seen >= MAX_FILTERS {
            break;
        }
    }
    // SAFETY: enum handle from FwpmFilterCreateEnumHandle0, destroyed once.
    unsafe { FwpmFilterDestroyEnumHandle0(engine.0, eh) };
    if status != 0 {
        return Err(status);
    }
    Ok(hits)
}

static CHANGED: OnceLock<Arc<Notify>> = OnceLock::new();

unsafe extern "system" fn on_filter_change(_ctx: *mut c_void, change: *const FWPM_FILTER_CHANGE0) {
    // Runs on a WFP thread: only signal, never block or allocate much.
    if change.is_null() || (*change).changeType != FWPM_CHANGE_ADD {
        return;
    }
    if let Some(n) = CHANGED.get() {
        n.notify_one();
    }
}

/// Keeps the change subscription (and its engine) alive.
pub struct Subscription {
    engine: Engine,
    handle: HANDLE,
}
// SAFETY: both are RPC context handles without thread affinity.
unsafe impl Send for Subscription {}

impl Drop for Subscription {
    fn drop(&mut self) {
        // SAFETY: handle from FwpmFilterSubscribeChanges0, released once, while
        // the engine is still open.
        unsafe { FwpmFilterUnsubscribeChanges0(self.engine.0, self.handle) };
    }
}

/// Wake `notify` whenever a filter is added. `None` when the subscription
/// cannot be made; the periodic scan still runs.
pub fn subscribe(notify: Arc<Notify>) -> Option<Subscription> {
    let _ = CHANGED.set(notify);
    let engine = Engine::open().ok()?;
    let sub = FWPM_FILTER_SUBSCRIPTION0::default();
    let mut handle: HANDLE = null_mut();
    // SAFETY: zeroed subscription (no template) selects all filter changes; the
    // callback is a plain function and needs no context.
    let rc = unsafe {
        FwpmFilterSubscribeChanges0(engine.0, &sub, Some(on_filter_change), null(), &mut handle)
    };
    (rc == 0).then_some(Subscription { engine, handle })
}
