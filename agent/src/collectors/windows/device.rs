//! USB device attach/detach via periodic SetupAPI enumeration.
//!
//! Enumerates present devices of the `USB` (all USB nodes, incl. composite
//! interfaces) and `USBSTOR` (mass-storage) enumerators every few seconds and
//! diffs against the previous snapshot ([`DeviceInventory`]). Chosen over
//! `WM_DEVICECHANGE` (needs a window and message loop in a service) and over
//! Kernel-PnP event ids (not verified on a host). Cost: one enumeration of a
//! handful of nodes per interval. A device that is attached and removed
//! between two polls is not seen; the interval is the documented bound.
//!
//! The first snapshot is a baseline: devices present at start are not reported
//! as attached. Identity comes from the PnP instance id (vendor/product ids,
//! serial only when the id carries a real one and
//! `device_serial_capture_enabled` is on; otherwise the instance segment is
//! hashed, see [`redact_instance_id`]) and the registry properties
//! Windows keeps for the node.

use std::sync::{Arc, RwLock};
use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use tokio::sync::mpsc::Sender;
use windows_sys::Win32::Devices::DeviceAndDriverInstallation::{
    SetupDiDestroyDeviceInfoList, SetupDiEnumDeviceInfo, SetupDiGetClassDevsW,
    SetupDiGetDeviceInstanceIdW, SetupDiGetDeviceRegistryPropertyW, DIGCF_ALLCLASSES,
    DIGCF_PRESENT, SPDRP_CLASS, SPDRP_DEVICEDESC, SPDRP_MFG, SP_DEVINFO_DATA,
};

use crate::collectors::device::{
    clean_text, parse_instance_id, redact_instance_id, DeviceInventory,
};
use crate::collectors::Collector;
use crate::config::AgentConfig;
use crate::schema::{AgentEvent, DeviceEventData, EventAction, EventClass, EventData, Severity};
use crate::telemetry::{metrics::metrics, DropReason};

const POLL: Duration = Duration::from_secs(5);
const ENUMERATORS: [&str; 2] = ["USB", "USBSTOR"];
/// Hard stop on one enumeration (a driver stack gone wrong must not spin).
const MAX_ENUM: u32 = 8192;

pub struct DeviceCollector {
    config: Arc<RwLock<AgentConfig>>,
}

impl DeviceCollector {
    pub fn new(config: Arc<RwLock<AgentConfig>>) -> Self {
        Self { config }
    }
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn utf16_text(buf: &[u16]) -> Option<String> {
    let end = buf.iter().position(|c| *c == 0).unwrap_or(buf.len());
    clean_text(&String::from_utf16_lossy(&buf[..end]))
}

unsafe fn property(
    set: windows_sys::Win32::Devices::DeviceAndDriverInstallation::HDEVINFO,
    info: &SP_DEVINFO_DATA,
    which: u32,
) -> Option<String> {
    let mut buf = [0u16; 256];
    let ok = SetupDiGetDeviceRegistryPropertyW(
        set,
        info,
        which,
        std::ptr::null_mut(),
        buf.as_mut_ptr() as *mut u8,
        (buf.len() * 2) as u32,
        std::ptr::null_mut(),
    );
    (ok != 0).then(|| utf16_text(&buf)).flatten()
}

fn enumerate(enumerator: &str, capture_serial: bool, salt: &str) -> Vec<DeviceEventData> {
    let mut out = Vec::new();
    let name = wide(enumerator);
    // SAFETY: the device-info set is destroyed on every path below and every
    // buffer handed to SetupAPI is a live local of the stated size.
    unsafe {
        let set = SetupDiGetClassDevsW(
            std::ptr::null(),
            name.as_ptr(),
            std::ptr::null_mut(),
            DIGCF_ALLCLASSES | DIGCF_PRESENT,
        );
        if set as isize == -1 {
            return out;
        }
        for index in 0..MAX_ENUM {
            let mut info: SP_DEVINFO_DATA = std::mem::zeroed();
            info.cbSize = std::mem::size_of::<SP_DEVINFO_DATA>() as u32;
            if SetupDiEnumDeviceInfo(set, index, &mut info) == 0 {
                break;
            }
            let mut id = [0u16; 512];
            if SetupDiGetDeviceInstanceIdW(
                set,
                &info,
                id.as_mut_ptr(),
                id.len() as u32,
                std::ptr::null_mut(),
            ) == 0
            {
                continue;
            }
            let Some(instance) = utf16_text(&id) else {
                continue;
            };
            let parsed = parse_instance_id(&instance);
            // Without opt-in the serial is neither reported nor left inside
            // the instance id.
            let (device_id, serial) = if capture_serial {
                (instance, parsed.serial)
            } else {
                (redact_instance_id(&instance, salt), None)
            };
            out.push(DeviceEventData {
                subsystem: parsed.enumerator.clone(),
                device_id,
                device_type: property(set, &info, SPDRP_CLASS),
                vendor_id: parsed.vendor_id,
                product_id: parsed.product_id,
                device_class: None,
                serial,
                product: property(set, &info, SPDRP_DEVICEDESC),
                manufacturer: property(set, &info, SPDRP_MFG),
                devnode: None,
                source: "setupapi".into(),
            });
        }
        SetupDiDestroyDeviceInfoList(set);
    }
    out
}

fn snapshot(capture_serial: bool, salt: &str) -> Vec<DeviceEventData> {
    ENUMERATORS
        .iter()
        .flat_map(|e| enumerate(e, capture_serial, salt))
        .collect()
}

#[async_trait]
impl Collector for DeviceCollector {
    fn name(&self) -> &'static str {
        "WindowsDeviceCollector"
    }

    async fn run(
        &mut self,
        tx: Sender<AgentEvent>,
        agent_id: String,
        hostname: String,
    ) -> Result<()> {
        let mut inventory = DeviceInventory::new();
        loop {
            let capture_serial = self
                .config
                .read()
                .map(|c| c.device_serial_capture_enabled)
                .unwrap_or(false);
            let salt = agent_id.clone();
            let current =
                tokio::task::spawn_blocking(move || snapshot(capture_serial, &salt)).await?;
            let (attached, detached, excess) = inventory.update(current);
            if excess > 0 {
                metrics().events_dropped(DropReason::InternalError, excess as u64);
            }
            for (action, devices) in [
                (EventAction::Create, attached),
                (EventAction::Delete, detached),
            ] {
                for data in devices {
                    let ev = AgentEvent::new(
                        agent_id.clone(),
                        hostname.clone(),
                        EventClass::Device,
                        action.clone(),
                        Severity::Info,
                        EventData::Device(data),
                    );
                    if tx.send(ev).await.is_err() {
                        return Ok(());
                    }
                }
            }
            tokio::select! {
                _ = tx.closed() => return Ok(()),
                _ = tokio::time::sleep(POLL) => {}
            }
        }
    }
}
