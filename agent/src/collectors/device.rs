//! Device attach/detach: platform-neutral parsing and bookkeeping.
//!
//! Linux reads kernel uevents from a `NETLINK_KOBJECT_UEVENT` socket
//! ([`linux::device`](super::linux::device)); Windows diffs a SetupAPI
//! enumeration ([`windows::device`](super::windows::device)). Both end up in
//! [`DeviceEventData`] (`device/create` and `device/delete`). Everything here
//! is pure so it is tested on every build host with synthetic input.
//!
//! Input is hostile: a USB device chooses its own strings, serial number and
//! interface list. Every field is length-capped and stripped of control
//! characters, buffers and field counts are bounded, and the event rate is
//! budgeted ([`RateBudget`]).

#![cfg_attr(not(any(windows, target_os = "linux")), allow(dead_code))]

use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::schema::DeviceEventData;

/// Largest uevent datagram accepted (the kernel's own limit is ~2 KiB).
pub const MAX_UEVENT_BYTES: usize = 8192;
const MAX_UEVENT_FIELDS: usize = 64;
const MAX_FIELD_BYTES: usize = 256;
const MAX_DEVPATH_BYTES: usize = 512;
/// Cap on any identity string copied into an event.
pub const MAX_TEXT_CHARS: usize = 128;

/// Control characters removed, length capped; empty becomes `None`.
pub fn clean_text(s: &str) -> Option<String> {
    let t: String = s
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_TEXT_CHARS)
        .collect();
    let t = t.trim().to_string();
    (!t.is_empty()).then_some(t)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Add,
    Remove,
}

/// A uevent that passed filtering.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Uevent {
    pub action: Action,
    pub devpath: String,
    pub subsystem: String,
    pub devtype: String,
    pub devname: Option<String>,
    pub product: Option<String>,
    pub usb_type: Option<String>,
    pub interface: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Parsed {
    /// A device event worth reporting.
    Event(Box<Uevent>),
    /// Well-formed but not ours (other subsystem, `change`/`bind`, an
    /// internal disk, a udev-format message). Not a loss.
    Ignored,
    /// Not a valid kernel uevent: counted by the caller.
    Malformed,
}

fn hex_u16(s: &str) -> Option<u16> {
    (!s.is_empty() && s.len() <= 4)
        .then(|| u16::from_str_radix(s, 16).ok())
        .flatten()
}

/// `PRODUCT=46d/c52b/1201` → (`046d`, `c52b`).
pub fn parse_product(p: &str) -> Option<(String, String)> {
    let mut it = p.split('/');
    let v = hex_u16(it.next()?)?;
    let d = hex_u16(it.next()?)?;
    Some((format!("{v:04x}"), format!("{d:04x}")))
}

/// First field of `class/subclass/protocol` as two hex digits.
fn class_code(t: &str) -> Option<String> {
    let c = u8::from_str_radix(t.split('/').next()?, 16).ok()?;
    Some(format!("{c:02x}"))
}

fn devpath_ok(p: &str) -> bool {
    p.len() <= MAX_DEVPATH_BYTES
        && p.starts_with("/devices/")
        && !p.split('/').any(|seg| seg == "..")
        && !p.chars().any(|c| c.is_control())
}

/// Block devices that are neither virtual nor internal fixed disks. A disk is
/// reported when its sysfs path runs through a USB host or it is an SD/MMC
/// card; internal disks appearing at boot are not "device attach".
fn block_is_removable_kind(devpath: &str, devname: &str) -> bool {
    const VIRTUAL: [&str; 6] = ["loop", "ram", "zram", "dm-", "md", "nbd"];
    if VIRTUAL.iter().any(|p| devname.starts_with(p)) {
        return false;
    }
    devpath.split('/').any(|seg| seg.starts_with("usb")) || devname.starts_with("mmcblk")
}

/// Parse one datagram from the kernel uevent multicast group.
pub fn parse_uevent(buf: &[u8]) -> Parsed {
    if buf.is_empty() || buf.len() > MAX_UEVENT_BYTES || buf.starts_with(b"libudev\0") {
        return if buf.starts_with(b"libudev\0") {
            Parsed::Ignored
        } else {
            Parsed::Malformed
        };
    }
    let mut parts = buf.split(|b| *b == 0).filter(|p| !p.is_empty());
    let Some(header) = parts.next() else {
        return Parsed::Malformed;
    };
    if !header.contains(&b'@') || header.contains(&b'=') {
        return Parsed::Malformed;
    }
    let mut kv: HashMap<&str, &str> = HashMap::new();
    for (n, part) in parts.enumerate() {
        if n >= MAX_UEVENT_FIELDS || part.len() > MAX_FIELD_BYTES {
            return Parsed::Malformed;
        }
        let Ok(text) = std::str::from_utf8(part) else {
            return Parsed::Malformed;
        };
        if let Some((k, v)) = text.split_once('=') {
            kv.entry(k).or_insert(v);
        }
    }
    let action = match kv.get("ACTION").copied() {
        Some("add") => Action::Add,
        Some("remove") => Action::Remove,
        Some(_) => return Parsed::Ignored,
        None => return Parsed::Malformed,
    };
    let (Some(devpath), Some(subsystem)) = (kv.get("DEVPATH"), kv.get("SUBSYSTEM")) else {
        return Parsed::Malformed;
    };
    if !devpath_ok(devpath) {
        return Parsed::Malformed;
    }
    let devtype = kv.get("DEVTYPE").copied().unwrap_or_default();
    let devname = kv.get("DEVNAME").and_then(|n| clean_text(n));
    let keep = match *subsystem {
        "usb" => matches!(devtype, "usb_device" | "usb_interface"),
        "block" => {
            devtype == "disk"
                && block_is_removable_kind(
                    devpath,
                    devname
                        .as_deref()
                        .unwrap_or_else(|| devpath.rsplit('/').next().unwrap_or_default()),
                )
        }
        _ => false,
    };
    if !keep {
        return Parsed::Ignored;
    }
    Parsed::Event(Box::new(Uevent {
        action,
        devpath: (*devpath).to_string(),
        subsystem: (*subsystem).to_string(),
        devtype: devtype.to_string(),
        devname,
        product: kv.get("PRODUCT").map(|s| s.to_string()),
        usb_type: kv.get("TYPE").map(|s| s.to_string()),
        interface: kv.get("INTERFACE").map(|s| s.to_string()),
    }))
}

/// Strings only sysfs knows (attach time; gone on remove).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SysfsInfo {
    pub serial: Option<String>,
    pub manufacturer: Option<String>,
    pub product: Option<String>,
}

pub fn event_from_uevent(
    u: &Uevent,
    mut sysfs: SysfsInfo,
    capture_serial: bool,
) -> DeviceEventData {
    if !capture_serial {
        sysfs.serial = None;
    }
    let (vendor_id, product_id) = u
        .product
        .as_deref()
        .and_then(parse_product)
        .map_or((None, None), |(v, p)| (Some(v), Some(p)));
    let device_class = match u.devtype.as_str() {
        "usb_interface" => u.interface.as_deref().and_then(class_code),
        "usb_device" => u.usb_type.as_deref().and_then(class_code),
        _ => None,
    };
    DeviceEventData {
        subsystem: u.subsystem.clone(),
        device_id: u.devpath.clone(),
        device_type: Some(u.devtype.clone()).filter(|t| !t.is_empty()),
        vendor_id,
        product_id,
        device_class,
        serial: sysfs.serial,
        product: sysfs.product,
        manufacturer: sysfs.manufacturer,
        devnode: u.devname.clone(),
        source: "netlink_uevent".into(),
    }
}

#[cfg_attr(not(windows), allow(dead_code))]
/// Windows: `USB\VID_046D&PID_C52B&MI_00\7&1F&0&0000` → ids, interface flag
/// and serial. A third segment containing `&` is a Windows-generated
/// instance id, not a device serial, and is never reported as one.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct InstanceId {
    pub enumerator: String,
    pub vendor_id: Option<String>,
    pub product_id: Option<String>,
    pub interface: bool,
    pub serial: Option<String>,
}

#[cfg_attr(not(windows), allow(dead_code))]
pub fn parse_instance_id(id: &str) -> InstanceId {
    let mut seg = id.split('\\');
    let enumerator = seg.next().unwrap_or_default().to_ascii_lowercase();
    let hardware = seg.next().unwrap_or_default();
    let instance = seg.next().unwrap_or_default();
    let field = |name: &str| {
        hardware
            .split('&')
            .find_map(|f| f.strip_prefix(name))
            .and_then(hex_u16)
            .map(|v| format!("{v:04x}"))
    };
    InstanceId {
        enumerator,
        vendor_id: field("VID_"),
        product_id: field("PID_"),
        interface: hardware.split('&').any(|f| f.starts_with("MI_")),
        serial: (!instance.contains('&'))
            .then(|| clean_text(instance))
            .flatten(),
    }
}

/// Windows instance id with the instance segment replaced by a salted hash.
///
/// `USB\VID_0781&PID_5581\<serial>` carries the device serial in its third
/// segment, and for `USBSTOR` it is the serial plus a `&N` suffix, so the
/// segment cannot be reliably told apart from a generated id. Whenever serial
/// capture is off the whole segment is replaced by
/// `h-` + 16 hex chars of `SHA-256(salt || 0x00 || segment)`. The salt is the
/// agent id, so the value is stable per host (attach/detach pairs and repeat
/// attaches of the same stick on one host still correlate) but is neither the
/// serial nor comparable across hosts. Trade-off: the hash of a short serial
/// can be brute-forced by someone who knows the salt; the agent id is not
/// secret from the backend, so this is pseudonymisation, not anonymisation.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn redact_instance_id(id: &str, salt: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut seg = id.splitn(3, '\\');
    let (Some(a), Some(b), Some(instance)) = (seg.next(), seg.next(), seg.next()) else {
        return id.to_string();
    };
    let mut h = Sha256::new();
    h.update(salt.as_bytes());
    h.update([0u8]);
    h.update(instance.as_bytes());
    let hex: String = h.finalize()[..8]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    format!("{a}\\{b}\\h-{hex}")
}

#[cfg_attr(not(windows), allow(dead_code))]
/// Snapshot diff for pollers. The first snapshot is the baseline and reports
/// nothing: devices already present at start are not "attached".
pub struct DeviceInventory {
    known: Option<HashMap<String, DeviceEventData>>,
}

#[cfg_attr(not(windows), allow(dead_code))]
pub const MAX_TRACKED_DEVICES: usize = 4096;

#[cfg_attr(not(windows), allow(dead_code))]
impl DeviceInventory {
    pub fn new() -> Self {
        Self { known: None }
    }

    /// Returns `(attached, detached)`. A snapshot beyond
    /// [`MAX_TRACKED_DEVICES`] is truncated and the excess counted in the
    /// third element, so it is reported as a loss instead of hidden.
    pub fn update(
        &mut self,
        mut current: Vec<DeviceEventData>,
    ) -> (Vec<DeviceEventData>, Vec<DeviceEventData>, usize) {
        let excess = current.len().saturating_sub(MAX_TRACKED_DEVICES);
        current.truncate(MAX_TRACKED_DEVICES);
        let now: HashMap<String, DeviceEventData> = current
            .into_iter()
            .map(|d| (d.device_id.clone(), d))
            .collect();
        let Some(prev) = self.known.replace(now) else {
            return (Vec::new(), Vec::new(), excess);
        };
        let now = self.known.as_ref().expect("just replaced");
        let mut attached: Vec<_> = now
            .iter()
            .filter(|(k, _)| !prev.contains_key(*k))
            .map(|(_, v)| v.clone())
            .collect();
        let mut detached: Vec<_> = prev
            .into_iter()
            .filter(|(k, _)| !now.contains_key(k))
            .map(|(_, v)| v)
            .collect();
        attached.sort_by(|a, b| a.device_id.cmp(&b.device_id));
        detached.sort_by(|a, b| a.device_id.cmp(&b.device_id));
        (attached, detached, excess)
    }
}

/// At most `limit` events per second; the rest are reported as shed.
pub struct RateBudget {
    limit: u32,
    window_start: Instant,
    used: u32,
}

impl RateBudget {
    pub fn new(limit: u32, now: Instant) -> Self {
        Self {
            limit,
            window_start: now,
            used: 0,
        }
    }

    pub fn allow(&mut self, now: Instant) -> bool {
        if now.saturating_duration_since(self.window_start) >= Duration::from_secs(1) {
            self.window_start = now;
            self.used = 0;
        }
        if self.used < self.limit {
            self.used += 1;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msg(header: &str, fields: &[&str]) -> Vec<u8> {
        let mut v = header.as_bytes().to_vec();
        v.push(0);
        for f in fields {
            v.extend_from_slice(f.as_bytes());
            v.push(0);
        }
        v
    }

    const USB_DEV: &str = "/devices/pci0000:00/0000:00:14.0/usb1/1-2";

    fn usb_add() -> Vec<u8> {
        msg(
            &format!("add@{USB_DEV}"),
            &[
                "ACTION=add",
                &format!("DEVPATH={USB_DEV}"),
                "SUBSYSTEM=usb",
                "DEVTYPE=usb_device",
                "DEVNAME=bus/usb/001/005",
                "PRODUCT=46d/c52b/1201",
                "TYPE=0/0/0",
                "SEQNUM=4711",
            ],
        )
    }

    #[test]
    fn usb_device_add_becomes_a_device_event() {
        let Parsed::Event(u) = parse_uevent(&usb_add()) else {
            panic!("not an event");
        };
        assert_eq!(u.action, Action::Add);
        let e = event_from_uevent(
            &u,
            SysfsInfo {
                serial: Some("ABC123".into()),
                manufacturer: Some("Logitech".into()),
                product: Some("Receiver".into()),
            },
            true,
        );
        assert_eq!(e.subsystem, "usb");
        assert_eq!(e.device_id, USB_DEV);
        assert_eq!(e.vendor_id.as_deref(), Some("046d"));
        assert_eq!(e.product_id.as_deref(), Some("c52b"));
        assert_eq!(e.device_class.as_deref(), Some("00"));
        assert_eq!(e.serial.as_deref(), Some("ABC123"));
        assert_eq!(e.devnode.as_deref(), Some("bus/usb/001/005"));
        assert_eq!(e.source, "netlink_uevent");
    }

    #[test]
    fn hid_interface_reports_its_class_for_rubber_ducky_detection() {
        let path = format!("{USB_DEV}/1-2:1.0");
        let m = msg(
            &format!("add@{path}"),
            &[
                "ACTION=add",
                &format!("DEVPATH={path}"),
                "SUBSYSTEM=usb",
                "DEVTYPE=usb_interface",
                "PRODUCT=1234/5678/100",
                "INTERFACE=3/1/1",
            ],
        );
        let Parsed::Event(u) = parse_uevent(&m) else {
            panic!()
        };
        let e = event_from_uevent(&u, SysfsInfo::default(), false);
        assert_eq!(e.device_class.as_deref(), Some("03"));
        assert_eq!(e.device_type.as_deref(), Some("usb_interface"));
    }

    #[test]
    fn usb_disk_is_reported_internal_and_virtual_disks_are_not() {
        let blk = |path: &str, name: &str, action: &str| {
            msg(
                &format!("{action}@{path}"),
                &[
                    &format!("ACTION={action}"),
                    &format!("DEVPATH={path}"),
                    "SUBSYSTEM=block",
                    "DEVTYPE=disk",
                    &format!("DEVNAME={name}"),
                ],
            )
        };
        let usb = format!("{USB_DEV}/1-2:1.0/host6/target6:0:0/6:0:0:0/block/sdb");
        let Parsed::Event(u) = parse_uevent(&blk(&usb, "sdb", "remove")) else {
            panic!()
        };
        assert_eq!(u.action, Action::Remove);
        assert_eq!(
            parse_uevent(&blk(
                "/devices/pci0000:00/0000:00:17.0/ata1/host0/target0:0:0/0:0:0:0/block/sda",
                "sda",
                "add"
            )),
            Parsed::Ignored
        );
        assert_eq!(
            parse_uevent(&blk("/devices/virtual/block/loop0", "loop0", "add")),
            Parsed::Ignored
        );
        assert!(matches!(
            parse_uevent(&blk(
                "/devices/pci0000:00/0000:00:1a.0/mmc_host/mmc0/mmc0:0001/block/mmcblk0",
                "mmcblk0",
                "add"
            )),
            Parsed::Event(_)
        ));
    }

    #[test]
    fn unrelated_and_malformed_input_is_classified_not_trusted() {
        // Other action / subsystem: not ours.
        let m = msg(
            "bind@/devices/x",
            &[
                "ACTION=bind",
                "DEVPATH=/devices/x",
                "SUBSYSTEM=usb",
                "DEVTYPE=usb_device",
            ],
        );
        assert_eq!(parse_uevent(&m), Parsed::Ignored);
        let m = msg(
            "add@/devices/x",
            &["ACTION=add", "DEVPATH=/devices/x", "SUBSYSTEM=net"],
        );
        assert_eq!(parse_uevent(&m), Parsed::Ignored);
        assert_eq!(parse_uevent(b"libudev\0\xfe\xed\xca\xfe"), Parsed::Ignored);
        // Malformed: empty, no header, missing action, traversal, non-UTF-8,
        // oversized, too many fields.
        assert_eq!(parse_uevent(b""), Parsed::Malformed);
        assert_eq!(parse_uevent(b"ACTION=add\0"), Parsed::Malformed);
        assert_eq!(
            parse_uevent(&msg(
                "add@/devices/x",
                &["DEVPATH=/devices/x", "SUBSYSTEM=usb"]
            )),
            Parsed::Malformed
        );
        let m = msg(
            "add@/devices/../etc",
            &[
                "ACTION=add",
                "DEVPATH=/devices/../etc",
                "SUBSYSTEM=usb",
                "DEVTYPE=usb_device",
            ],
        );
        assert_eq!(parse_uevent(&m), Parsed::Malformed);
        let m = msg(
            "add@/devices/x",
            &[
                "ACTION=add",
                "DEVPATH=/devices/x",
                "SUBSYSTEM=usb",
                "DEVTYPE=usb_device",
            ],
        );
        let mut bad = m.clone();
        bad.extend_from_slice(b"X=\xff\xfe\0");
        assert_eq!(parse_uevent(&bad), Parsed::Malformed);
        assert_eq!(
            parse_uevent(&vec![b'a'; MAX_UEVENT_BYTES + 1]),
            Parsed::Malformed
        );
        let many: Vec<String> = (0..80).map(|i| format!("K{i}=v")).collect();
        let refs: Vec<&str> = many.iter().map(String::as_str).collect();
        assert_eq!(
            parse_uevent(&msg("add@/devices/x", &refs)),
            Parsed::Malformed
        );
        let long = format!("K={}", "a".repeat(MAX_FIELD_BYTES + 1));
        assert_eq!(
            parse_uevent(&msg("add@/devices/x", &[&long])),
            Parsed::Malformed
        );
    }

    #[test]
    fn product_and_text_are_sanitised() {
        assert_eq!(
            parse_product("46d/c52b/1201"),
            Some(("046d".into(), "c52b".into()))
        );
        assert_eq!(parse_product("zz/1/1"), None);
        assert_eq!(parse_product("12345/1/1"), None);
        assert_eq!(
            clean_text("  Evil\x1b[31m\nName "),
            Some("Evil[31mName".into())
        );
        assert_eq!(clean_text("\x00\x07"), None);
        assert_eq!(
            clean_text(&"x".repeat(1000)).unwrap().chars().count(),
            MAX_TEXT_CHARS
        );
    }

    #[test]
    fn windows_instance_ids_yield_ids_and_only_real_serials() {
        let a = parse_instance_id("USB\\VID_046D&PID_C52B\\5&2A1B3C&0&2");
        assert_eq!(a.vendor_id.as_deref(), Some("046d"));
        assert_eq!(a.product_id.as_deref(), Some("c52b"));
        assert_eq!(a.serial, None, "generated instance id is not a serial");
        assert!(!a.interface);
        let b = parse_instance_id("USB\\VID_0781&PID_5581\\4C530001230911112345");
        assert_eq!(b.serial.as_deref(), Some("4C530001230911112345"));
        let c = parse_instance_id("USB\\VID_046D&PID_C52B&MI_00\\7&1F&0&0000");
        assert!(c.interface);
        assert_eq!(c.enumerator, "usb");
        let d = parse_instance_id("garbage");
        assert_eq!((d.vendor_id, d.product_id, d.serial), (None, None, None));
    }

    #[test]
    fn serial_is_dropped_from_the_event_unless_capture_is_on() {
        let Parsed::Event(u) = parse_uevent(&usb_add()) else {
            panic!("not an event");
        };
        let info = || SysfsInfo {
            serial: Some("SECRET-SN-42".into()),
            manufacturer: Some("Logitech".into()),
            product: Some("Receiver".into()),
        };
        let off = event_from_uevent(&u, info(), false);
        assert_eq!(off.serial, None);
        assert_eq!(off.vendor_id.as_deref(), Some("046d"));
        assert!(!serde_json::to_string(&off)
            .unwrap()
            .contains("SECRET-SN-42"));
        let on = event_from_uevent(&u, info(), true);
        assert!(serde_json::to_string(&on).unwrap().contains("SECRET-SN-42"));
    }

    #[test]
    fn redacted_instance_id_hides_the_serial_but_stays_stable() {
        for id in [
            "USB\\VID_0781&PID_5581\\4C530001230911112345",
            "USBSTOR\\DISK&VEN_SANDISK&PROD_X&REV_1.00\\4C530001230911112345&0",
        ] {
            let r = redact_instance_id(id, "agent-1");
            assert!(!r.contains("4C5300"), "{r}");
            assert_eq!(r, redact_instance_id(id, "agent-1"));
            assert_ne!(r, redact_instance_id(id, "agent-2"));
            assert!(r.starts_with(id.rsplit_once('\\').unwrap().0));
        }
        assert_eq!(redact_instance_id("garbage", "s"), "garbage");
    }

    fn dev(id: &str) -> DeviceEventData {
        DeviceEventData {
            subsystem: "usb".into(),
            device_id: id.into(),
            device_type: None,
            vendor_id: None,
            product_id: None,
            device_class: None,
            serial: None,
            product: None,
            manufacturer: None,
            devnode: None,
            source: "setupapi".into(),
        }
    }

    #[test]
    fn inventory_baselines_then_reports_attach_and_detach() {
        let mut inv = DeviceInventory::new();
        let (a, d, _) = inv.update(vec![dev("A"), dev("B")]);
        assert!(a.is_empty() && d.is_empty(), "baseline is silent");
        let (a, d, _) = inv.update(vec![dev("B"), dev("C")]);
        assert_eq!(
            a.iter().map(|x| x.device_id.as_str()).collect::<Vec<_>>(),
            ["C"]
        );
        assert_eq!(
            d.iter().map(|x| x.device_id.as_str()).collect::<Vec<_>>(),
            ["A"]
        );
        let (a, d, _) = inv.update(vec![dev("B"), dev("C")]);
        assert!(a.is_empty() && d.is_empty());
    }

    #[test]
    fn inventory_is_bounded_and_reports_the_excess() {
        let mut inv = DeviceInventory::new();
        let many: Vec<_> = (0..MAX_TRACKED_DEVICES + 7)
            .map(|i| dev(&i.to_string()))
            .collect();
        let (_, _, excess) = inv.update(many);
        assert_eq!(excess, 7);
    }

    #[test]
    fn rate_budget_sheds_the_burst_and_refills() {
        let t0 = Instant::now();
        let mut b = RateBudget::new(3, t0);
        assert_eq!((0..5).filter(|_| b.allow(t0)).count(), 3);
        assert!(b.allow(t0 + Duration::from_millis(1100)));
    }

    #[test]
    fn device_payload_round_trips_through_the_untagged_envelope() {
        use crate::schema::{AgentEvent, EventAction, EventClass, EventData, Severity};
        let ev = AgentEvent::new(
            "a".into(),
            "h".into(),
            EventClass::Device,
            EventAction::Create,
            Severity::Info,
            EventData::Device(dev("USB\\VID_0781&PID_5581\\X")),
        );
        let json = serde_json::to_string(&ev).unwrap();
        assert!(json.contains("\"class\":\"device\""), "{json}");
        let back: AgentEvent = serde_json::from_str(&json).unwrap();
        assert!(matches!(back.data, EventData::Device(d) if d.device_id.starts_with("USB")));
    }
}
