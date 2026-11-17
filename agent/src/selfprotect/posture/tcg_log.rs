//! TCG measured-boot event log: bounds-checked parser, per-boot summary and
//! boot-to-boot diff.
//!
//! LIMITS (read before trusting a result):
//!   * The log is *evidence the firmware and boot loader produced*. Code that
//!     runs before measurement (or a compromised firmware) can lie; this does
//!     not replace remote attestation (a TPM quote checked server-side).
//!   * We parse the container (TCG PC Client / crypto-agile `TCG_PCR_EVENT2`,
//!     and the legacy SHA-1 form), replay the SHA-256 PCR banks, extract the
//!     UEFI Secure Boot configuration variables and the boot applications, and
//!     fingerprint Windows' tagged events in PCR 12-14. We do **not** decode
//!     Windows' SIPA event payloads (debug/test-signing/boot-driver detail):
//!     their layout is not stable public API, so a wrong decode would produce
//!     confident false answers. Instead the *set of tagged event ids* is
//!     tracked and a new/removed id is reported as a heuristic. Live
//!     test-signing/debugger state comes from `posture::windows`, not from here.
//!   * Changes of boot applications are expected after Windows servicing
//!     (medium); only a Secure Boot off-switch or a Platform Key change is high.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use trapd_schema::{DetectionData, Severity};

pub const EV_NO_ACTION: u32 = 0x3;
pub const EV_EVENT_TAG: u32 = 0x6;
pub const EV_EFI_VARIABLE_DRIVER_CONFIG: u32 = 0x8000_0001;
pub const EV_EFI_BOOT_SERVICES_APPLICATION: u32 = 0x8000_0003;
const ALG_SHA1: u16 = 0x4;
const ALG_SHA256: u16 = 0xB;
const MAX_EVENTS: usize = 50_000;
const MAX_DIGESTS: u32 = 16;
pub const MAX_LOG_BYTES: usize = 4 * 1024 * 1024;
const SPEC_ID_SIG: &[u8] = b"Spec ID Event03\0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    pub pcr: u32,
    pub event_type: u32,
    pub digests: Vec<(u16, Vec<u8>)>,
    pub data: Vec<u8>,
}

impl Event {
    fn digest(&self, alg: u16) -> Option<&[u8]> {
        self.digests
            .iter()
            .find(|(a, _)| *a == alg)
            .map(|(_, d)| d.as_slice())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedLog {
    pub events: Vec<Event>,
    pub crypto_agile: bool,
    /// The log ended mid-event or hit a limit; events before that are intact.
    pub truncated: bool,
}

struct Cur<'a> {
    b: &'a [u8],
    p: usize,
}

impl<'a> Cur<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.p.checked_add(n)?;
        let s = self.b.get(self.p..end)?;
        self.p = end;
        Some(s)
    }
    fn u16(&mut self) -> Option<u16> {
        Some(u16::from_le_bytes(self.take(2)?.try_into().ok()?))
    }
    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_le_bytes(self.take(4)?.try_into().ok()?))
    }
    fn u64(&mut self) -> Option<u64> {
        Some(u64::from_le_bytes(self.take(8)?.try_into().ok()?))
    }
    fn left(&self) -> usize {
        self.b.len() - self.p
    }
}

fn alg_size(alg: u16) -> Option<usize> {
    match alg {
        0x4 => Some(20),
        0xB => Some(32),
        0xC => Some(48),
        0xD => Some(64),
        0x12 => Some(32),
        _ => None,
    }
}

/// Parse a log. Never panics on malformed input; returns what was readable.
/// `None` only when not even the first event header is present.
pub fn parse(log: &[u8]) -> Option<ParsedLog> {
    let log = &log[..log.len().min(MAX_LOG_BYTES)];
    let mut c = Cur { b: log, p: 0 };
    // First event is always the legacy SHA-1 form.
    let pcr = c.u32()?;
    let etype = c.u32()?;
    let sha1 = c.take(20)?.to_vec();
    let size = c.u32()? as usize;
    let data = c.take(size)?.to_vec();
    let first = Event {
        pcr,
        event_type: etype,
        digests: vec![(ALG_SHA1, sha1)],
        data,
    };
    let agile = etype == EV_NO_ACTION && first.data.starts_with(SPEC_ID_SIG);
    let mut events = vec![first];
    let mut truncated = false;

    if agile {
        let table = parse_spec_id(&events[0].data);
        let Some(table) = table else {
            return Some(ParsedLog {
                events,
                crypto_agile: true,
                truncated: true,
            });
        };
        while c.left() > 0 {
            if events.len() >= MAX_EVENTS {
                truncated = true;
                break;
            }
            match read_event2(&mut c, &table) {
                Some(e) => events.push(e),
                None => {
                    truncated = true;
                    break;
                }
            }
        }
    } else {
        while c.left() > 0 {
            if events.len() >= MAX_EVENTS {
                truncated = true;
                break;
            }
            let ev = (|| {
                let pcr = c.u32()?;
                let t = c.u32()?;
                let d = c.take(20)?.to_vec();
                let n = c.u32()? as usize;
                let data = c.take(n)?.to_vec();
                Some(Event {
                    pcr,
                    event_type: t,
                    digests: vec![(ALG_SHA1, d)],
                    data,
                })
            })();
            match ev {
                Some(e) => events.push(e),
                None => {
                    truncated = true;
                    break;
                }
            }
        }
    }
    Some(ParsedLog {
        events,
        crypto_agile: agile,
        truncated,
    })
}

/// `TCG_EfiSpecIDEvent`: algorithm id -> digest size table.
fn parse_spec_id(data: &[u8]) -> Option<BTreeMap<u16, usize>> {
    let mut c = Cur {
        b: data,
        p: SPEC_ID_SIG.len(),
    };
    c.take(4 + 4)?; // platformClass, spec minor/major/errata/uintnSize
    let n = c.u32()?;
    if n == 0 || n > MAX_DIGESTS {
        return None;
    }
    let mut t = BTreeMap::new();
    for _ in 0..n {
        let alg = c.u16()?;
        let sz = c.u16()? as usize;
        t.insert(alg, sz);
    }
    Some(t)
}

fn read_event2(c: &mut Cur, table: &BTreeMap<u16, usize>) -> Option<Event> {
    let pcr = c.u32()?;
    let event_type = c.u32()?;
    let count = c.u32()?;
    if count > MAX_DIGESTS {
        return None;
    }
    let mut digests = Vec::new();
    for _ in 0..count {
        let alg = c.u16()?;
        let sz = table.get(&alg).copied().or_else(|| alg_size(alg))?;
        digests.push((alg, c.take(sz)?.to_vec()));
    }
    let n = c.u32()? as usize;
    let data = c.take(n)?.to_vec();
    Some(Event {
        pcr,
        event_type,
        digests,
        data,
    })
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// `UEFI_VARIABLE_DATA` of an `EV_EFI_VARIABLE_DRIVER_CONFIG` event:
/// (variable name, variable payload).
pub fn parse_efi_variable(data: &[u8]) -> Option<(String, Vec<u8>)> {
    let mut c = Cur { b: data, p: 0 };
    c.take(16)?; // vendor GUID
    let name_chars = usize::try_from(c.u64()?).ok()?;
    let data_len = usize::try_from(c.u64()?).ok()?;
    if name_chars > 256 {
        return None;
    }
    let raw = c.take(name_chars.checked_mul(2)?)?;
    let units: Vec<u16> = raw
        .as_chunks::<2>()
        .0
        .iter()
        .map(|w| u16::from_le_bytes(*w))
        .collect();
    let name = String::from_utf16(&units).ok()?;
    Some((name, c.take(data_len)?.to_vec()))
}

/// `TCG_PCClientTaggedEvent`: (tag id, payload).
pub fn parse_tagged(data: &[u8]) -> Option<(u32, &[u8])> {
    let mut c = Cur { b: data, p: 0 };
    let id = c.u32()?;
    let n = c.u32()? as usize;
    Some((id, c.take(n)?))
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct BootMeasurements {
    pub boot_id: Option<String>,
    pub event_count: usize,
    pub truncated: bool,
    /// Replayed SHA-256 PCR values (hex), only banks present in the log.
    pub pcr_replay: BTreeMap<u32, String>,
    /// SHA-256 digests of EFI boot applications (PCR 4), in boot order.
    pub boot_apps: Vec<String>,
    /// UEFI Secure Boot configuration variable name -> SHA-256 of its payload.
    pub config_vars: BTreeMap<String, String>,
    pub secure_boot_enabled: Option<bool>,
    /// Windows tagged events in PCR 12-14: `pcrN:tagXXXXXXXX#k` -> SHA-256 of payload.
    pub tagged: BTreeMap<String, String>,
}

pub fn summarize(log: &ParsedLog, boot_id: Option<String>) -> BootMeasurements {
    let mut m = BootMeasurements {
        boot_id,
        event_count: log.events.len(),
        truncated: log.truncated,
        ..Default::default()
    };
    let mut pcrs: BTreeMap<u32, [u8; 32]> = BTreeMap::new();
    let mut tag_seen: BTreeMap<(u32, u32), usize> = BTreeMap::new();
    for e in &log.events {
        if e.event_type != EV_NO_ACTION {
            if let Some(d) = e.digest(ALG_SHA256).filter(|d| d.len() == 32) {
                let cur = pcrs.entry(e.pcr).or_insert([0u8; 32]);
                let mut h = Sha256::new();
                h.update(&cur[..]);
                h.update(d);
                cur.copy_from_slice(&h.finalize());
            }
        }
        match e.event_type {
            EV_EFI_BOOT_SERVICES_APPLICATION if e.pcr == 4 => {
                if let Some(d) = e.digest(ALG_SHA256).or_else(|| e.digest(ALG_SHA1)) {
                    m.boot_apps.push(hex(d));
                }
            }
            EV_EFI_VARIABLE_DRIVER_CONFIG if e.pcr == 7 => {
                if let Some((name, payload)) = parse_efi_variable(&e.data) {
                    if name == "SecureBoot" {
                        m.secure_boot_enabled = payload.first().map(|v| *v == 1);
                    }
                    m.config_vars.insert(name, hex(&Sha256::digest(&payload)));
                }
            }
            EV_EVENT_TAG if (12..=14).contains(&e.pcr) => {
                if let Some((id, payload)) = parse_tagged(&e.data) {
                    let k = tag_seen.entry((e.pcr, id)).or_insert(0);
                    m.tagged.insert(
                        format!("pcr{}:tag{id:08x}#{k}", e.pcr),
                        hex(&Sha256::digest(payload)),
                    );
                    *k += 1;
                }
            }
            _ => {}
        }
    }
    m.pcr_replay = pcrs.into_iter().map(|(k, v)| (k, hex(&v))).collect();
    m
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BootChange {
    pub item: String,
    pub before: Option<String>,
    pub after: Option<String>,
    pub severity: ChangeSeverity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeSeverity {
    Medium,
    High,
}

/// Differences between two boots' measurements. Empty when nothing notable.
pub fn diff(prev: &BootMeasurements, cur: &BootMeasurements) -> Vec<BootChange> {
    let mut out = Vec::new();
    let mut push = |item: &str, b: Option<String>, a: Option<String>, severity| {
        out.push(BootChange {
            item: item.into(),
            before: b,
            after: a,
            severity,
        });
    };

    if prev.secure_boot_enabled == Some(true) && cur.secure_boot_enabled == Some(false) {
        push(
            "secure_boot",
            Some("on".into()),
            Some("off".into()),
            ChangeSeverity::High,
        );
    }
    for key in prev
        .config_vars
        .keys()
        .chain(cur.config_vars.keys())
        .collect::<std::collections::BTreeSet<_>>()
    {
        if key == "SecureBoot" {
            continue; // covered by the explicit on/off rule above
        }
        let (b, a) = (prev.config_vars.get(key), cur.config_vars.get(key));
        if b != a {
            let sev = if key == "PK" {
                ChangeSeverity::High
            } else {
                ChangeSeverity::Medium
            };
            push(&format!("efi_var:{key}"), b.cloned(), a.cloned(), sev);
        }
    }
    if prev.boot_apps != cur.boot_apps {
        push(
            "boot_applications",
            Some(prev.boot_apps.join(",")),
            Some(cur.boot_apps.join(",")),
            ChangeSeverity::Medium,
        );
    }
    // Tag *presence* only: payload hashes may hold volatile data (counters).
    for k in prev.tagged.keys().filter(|k| !cur.tagged.contains_key(*k)) {
        push(
            &format!("tagged_event_removed:{k}"),
            prev.tagged.get(k).cloned(),
            None,
            ChangeSeverity::Medium,
        );
    }
    for k in cur.tagged.keys().filter(|k| !prev.tagged.contains_key(*k)) {
        push(
            &format!("tagged_event_added:{k}"),
            None,
            cur.tagged.get(k).cloned(),
            ChangeSeverity::Medium,
        );
    }
    out
}

pub fn finding(
    changes: &[BootChange],
    prev_boot: Option<&str>,
    cur_boot: Option<&str>,
) -> Option<(Severity, DetectionData)> {
    let top = changes.iter().map(|c| c.severity).max()?;
    let sev = if top == ChangeSeverity::High {
        Severity::High
    } else {
        Severity::Medium
    };
    Some((
        sev,
        DetectionData {
            rule_id: super::snapshot::RULE_ID.into(),
            title: "Measured boot changed since the previous boot".into(),
            category: "defense_evasion".into(),
            mitre_tactic: Some("TA0005 Defense Evasion".into()),
            mitre_technique: Some("T1542".into()),
            confidence: 50,
            subject: "measured_boot".into(),
            detail: format!(
                "Boot measurements differ from the previous boot: {}",
                changes
                    .iter()
                    .map(|c| c.item.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            evidence: serde_json::json!({
                "source": "measured_boot",
                "previous_boot_id": prev_boot,
                "boot_id": cur_boot,
                "changes": changes,
            }),
            ..Default::default()
        },
    ))
}

#[cfg(test)]
pub(crate) mod fixture {
    //! Builder for synthetic crypto-agile logs (no real TPM needed).
    use super::*;

    pub fn legacy_event(pcr: u32, t: u32, sha1: [u8; 20], data: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend(pcr.to_le_bytes());
        v.extend(t.to_le_bytes());
        v.extend(sha1);
        v.extend((data.len() as u32).to_le_bytes());
        v.extend(data);
        v
    }

    pub fn spec_id() -> Vec<u8> {
        let mut d = SPEC_ID_SIG.to_vec();
        d.extend(0u32.to_le_bytes()); // platform class
        d.extend([0, 2, 0, 2]); // minor, major, errata, uintn
        d.extend(2u32.to_le_bytes());
        d.extend(ALG_SHA1.to_le_bytes());
        d.extend(20u16.to_le_bytes());
        d.extend(ALG_SHA256.to_le_bytes());
        d.extend(32u16.to_le_bytes());
        d.push(0); // vendor info size
        legacy_event(0, EV_NO_ACTION, [0; 20], &d)
    }

    pub fn event2(pcr: u32, t: u32, sha256: [u8; 32], data: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend(pcr.to_le_bytes());
        v.extend(t.to_le_bytes());
        v.extend(2u32.to_le_bytes());
        v.extend(ALG_SHA1.to_le_bytes());
        v.extend([0xAA; 20]);
        v.extend(ALG_SHA256.to_le_bytes());
        v.extend(sha256);
        v.extend((data.len() as u32).to_le_bytes());
        v.extend(data);
        v
    }

    pub fn efi_var(name: &str, payload: &[u8]) -> Vec<u8> {
        let units: Vec<u8> = name.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        let mut v = vec![0x11; 16];
        v.extend((name.encode_utf16().count() as u64).to_le_bytes());
        v.extend((payload.len() as u64).to_le_bytes());
        v.extend(units);
        v.extend(payload);
        v
    }

    pub fn tagged(id: u32, payload: &[u8]) -> Vec<u8> {
        let mut v = id.to_le_bytes().to_vec();
        v.extend((payload.len() as u32).to_le_bytes());
        v.extend(payload);
        v
    }

    /// A plausible boot: Secure Boot var, PK, one boot app, two Windows tags.
    pub fn boot(secure_boot: u8, boot_app: u8, tags: &[u32]) -> Vec<u8> {
        let mut log = spec_id();
        log.extend(event2(
            7,
            EV_EFI_VARIABLE_DRIVER_CONFIG,
            [1; 32],
            &efi_var("SecureBoot", &[secure_boot]),
        ));
        log.extend(event2(
            7,
            EV_EFI_VARIABLE_DRIVER_CONFIG,
            [2; 32],
            &efi_var("PK", b"platform-key"),
        ));
        log.extend(event2(
            4,
            EV_EFI_BOOT_SERVICES_APPLICATION,
            [boot_app; 32],
            b"\\EFI\\bootmgfw.efi",
        ));
        for (i, t) in tags.iter().enumerate() {
            log.extend(event2(
                12,
                EV_EVENT_TAG,
                [0x40 + i as u8; 32],
                &tagged(*t, &[i as u8]),
            ));
        }
        log
    }
}

#[cfg(test)]
mod tests {
    use super::fixture::*;
    use super::*;

    #[test]
    fn parses_crypto_agile_log() {
        let p = parse(&boot(1, 9, &[0x1000_0001, 0x1000_0002])).unwrap();
        assert!(p.crypto_agile && !p.truncated);
        assert_eq!(p.events.len(), 6);
        let m = summarize(&p, Some("b".into()));
        assert_eq!(m.secure_boot_enabled, Some(true));
        assert_eq!(m.boot_apps, vec![hex(&[9u8; 32])]);
        assert!(m.config_vars.contains_key("PK"));
        assert_eq!(m.tagged.len(), 2);
        assert!(m.pcr_replay.contains_key(&7) && m.pcr_replay.contains_key(&4));
    }

    #[test]
    fn pcr_replay_matches_manual_extend() {
        let p = parse(&boot(1, 9, &[])).unwrap();
        let m = summarize(&p, None);
        let mut pcr4 = [0u8; 32];
        let mut h = Sha256::new();
        h.update(pcr4);
        h.update([9u8; 32]);
        pcr4.copy_from_slice(&h.finalize());
        assert_eq!(m.pcr_replay[&4], hex(&pcr4));
    }

    #[test]
    fn parses_legacy_sha1_log() {
        let mut log = legacy_event(0, 0x8, [1; 20], b"first");
        log.extend(legacy_event(
            4,
            EV_EFI_BOOT_SERVICES_APPLICATION,
            [7; 20],
            b"app",
        ));
        let p = parse(&log).unwrap();
        assert!(!p.crypto_agile && p.events.len() == 2);
        assert_eq!(summarize(&p, None).boot_apps, vec![hex(&[7u8; 20])]);
    }

    #[test]
    fn truncation_and_garbage_never_panic() {
        let log = boot(1, 9, &[0x1000_0001]);
        assert!(parse(&[]).is_none());
        for n in 0..log.len() {
            if let Some(p) = parse(&log[..n]) {
                // Anything cut short is flagged, unless the cut fell on an event boundary.
                let _ = summarize(&p, None);
            }
        }
        let mut cut = parse(&log[..log.len() - 3]).unwrap();
        assert!(cut.truncated);
        cut.events.clear();
        // Hostile sizes: huge event size and huge digest count must not allocate/overflow.
        let mut evil = spec_id();
        evil.extend(7u32.to_le_bytes());
        evil.extend(1u32.to_le_bytes());
        evil.extend(0xFFFF_FFFFu32.to_le_bytes());
        assert!(parse(&evil).unwrap().truncated);
        let mut evil2 = spec_id();
        evil2.extend(7u32.to_le_bytes());
        evil2.extend(1u32.to_le_bytes());
        evil2.extend(1u32.to_le_bytes());
        evil2.extend(0xBBBBu16.to_le_bytes()); // algorithm not in the table
        assert!(parse(&evil2).unwrap().truncated);
        // Pseudo-random bytes.
        let junk: Vec<u8> = (0..4096u32)
            .map(|i| (i.wrapping_mul(2654435761) >> 13) as u8)
            .collect();
        let _ = parse(&junk).map(|p| summarize(&p, None));
    }

    #[test]
    fn efi_variable_bounds() {
        assert_eq!(
            parse_efi_variable(&efi_var("db", b"xy")),
            Some(("db".into(), b"xy".to_vec()))
        );
        let mut bad = efi_var("db", b"xy");
        bad.truncate(bad.len() - 1);
        assert!(parse_efi_variable(&bad).is_none());
        let mut huge = vec![0u8; 16];
        huge.extend(u64::MAX.to_le_bytes());
        huge.extend(0u64.to_le_bytes());
        assert!(parse_efi_variable(&huge).is_none());
    }

    #[test]
    fn identical_boots_have_no_diff() {
        let a = summarize(
            &parse(&boot(1, 9, &[0x1000_0001])).unwrap(),
            Some("a".into()),
        );
        let b = summarize(
            &parse(&boot(1, 9, &[0x1000_0001])).unwrap(),
            Some("b".into()),
        );
        assert!(diff(&a, &b).is_empty());
    }

    #[test]
    fn secure_boot_off_is_high() {
        let a = summarize(&parse(&boot(1, 9, &[])).unwrap(), Some("a".into()));
        let b = summarize(&parse(&boot(0, 9, &[])).unwrap(), Some("b".into()));
        let ch = diff(&a, &b);
        assert!(ch
            .iter()
            .any(|c| c.item == "secure_boot" && c.severity == ChangeSeverity::High));
        let (sev, d) = finding(&ch, Some("a"), Some("b")).unwrap();
        assert_eq!(sev, Severity::High);
        assert_eq!(d.rule_id, "selfprotect.platform_posture_changed");
        assert_eq!(d.evidence["source"], "measured_boot");
    }

    #[test]
    fn boot_app_and_tag_set_changes_are_medium() {
        let a = summarize(&parse(&boot(1, 9, &[0x1000_0001])).unwrap(), None);
        let b = summarize(
            &parse(&boot(1, 10, &[0x1000_0001, 0x1000_0009])).unwrap(),
            None,
        );
        let ch = diff(&a, &b);
        assert!(ch.iter().any(|c| c.item == "boot_applications"));
        assert!(ch.iter().any(|c| c.item.starts_with("tagged_event_added")));
        assert_eq!(finding(&ch, None, None).unwrap().0, Severity::Medium);
    }

    #[test]
    fn tag_payload_change_alone_is_ignored() {
        let mut a = summarize(&parse(&boot(1, 9, &[0x1000_0001])).unwrap(), None);
        let b = a.clone();
        for v in a.tagged.values_mut() {
            *v = "00".into();
        }
        assert!(diff(&a, &b).is_empty());
    }

    #[test]
    fn platform_key_change_is_high() {
        let a = summarize(&parse(&boot(1, 9, &[])).unwrap(), None);
        let mut b = a.clone();
        b.config_vars.insert("PK".into(), "deadbeef".into());
        let ch = diff(&a, &b);
        assert_eq!(ch.len(), 1);
        assert_eq!(ch[0].severity, ChangeSeverity::High);
    }
}
