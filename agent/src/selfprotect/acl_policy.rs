//! Expected ACLs of the agent's own service, registry keys and directories
//! (self-protection WP2/WP3), and the portable logic around them: constants,
//! an SDDL reader, drift comparison and the two tamper findings.
//!
//! What this is and is not. The DACLs make a casual or scripted change by an
//! elevated administrator fail (`sc stop`, `sc config`, `reg add ... Start`,
//! `Stop-Service`, editing `agent.env`). They are not a boundary against an
//! administrator who is determined: an administrator can still take ownership
//! (`SeTakeOwnershipPrivilege`), enable `SeDebugPrivilege` or boot another OS.
//! That is why a changed ACL is *detected and reported* (`ACL_RULE_ID`,
//! `REGISTRY_RULE_ID`) and re-asserted, rather than trusted to hold.
//!
//! Every DACL carries an `OWNER RIGHTS` (`OW`) ACE with only `READ_CONTROL`.
//! Objects created by a LocalSystem process are owned by
//! `BUILTIN\Administrators` (default-owner policy), and the owner of an object
//! implicitly holds `WRITE_DAC | READ_CONTROL` unless an `OW` ACE exists. Without
//! it every administrator would be able to rewrite the DACL regardless of the
//! other entries.

// Compiled on Linux for its unit tests only; the runtime that uses every item
// is Windows-only.
#![cfg_attr(not(windows), allow(dead_code))]

use sha2::{Digest, Sha256};
use trapd_schema::{AgentEvent, DetectionData, EventAction, EventClass, EventData, Severity};

pub const ACL_RULE_ID: &str = "selfprotect.service_acl_changed";
pub const REGISTRY_RULE_ID: &str = "selfprotect.service_registry_changed";

/// `HKLM\SOFTWARE\TRAPD\Agent` value the MSI writes when installed with
/// `TRAPD_LEGACY_ACLS=1`. The key is protected like everything else the MSI
/// writes, so in hardened mode an administrator cannot set it to mute drift
/// findings.
pub const LEGACY_MARKER_KEY: &str = "SOFTWARE\\TRAPD\\Agent";
pub const LEGACY_MARKER_VALUE: &str = "LegacyAcls";

// ── Service ───────────────────────────────────────────────────────────────────
// Service-specific rights: CC query config, DC change config, LC query status,
// SW enumerate dependents, RP start, WP stop, DT pause, LO interrogate,
// CR user-defined control.

/// SYSTEM full; Administrators query, start, interrogate, read and send the
/// user-defined control that asks the service to look at a maintenance
/// request (it verifies the token itself); no stop, no config change, no
/// delete, no DACL/owner change; interactive/service accounts query only.
pub const SERVICE_DACL_SDDL: &str = "D:P(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCLCSWRPLOCRRC;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)(A;;RC;;;OW)";
/// What earlier releases installed. Rollback target of `TRAPD_LEGACY_ACLS=1`.
pub const SERVICE_DACL_LEGACY_SDDL: &str = "D:P(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRC;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)";

// ── Registry ──────────────────────────────────────────────────────────────────

/// Service key (`Services\trapd-agent`, inherited by `Parameters`) and the
/// agent configuration key (`SOFTWARE\TRAPD\Agent`): SYSTEM full, Administrators
/// read. The same descriptor the MSI applies to the values it writes.
pub const REGISTRY_KEY_SDDL: &str = "D:P(A;CI;KA;;;SY)(A;CI;KR;;;BA)(A;CI;RC;;;OW)";
/// Previous descriptor (Administrators full control). Rollback only.
pub const REGISTRY_KEY_LEGACY_SDDL: &str = "D:P(A;CI;KA;;;SY)(A;CI;KA;;;BA)";

pub const SERVICE_KEY_PATH: &str = "SYSTEM\\CurrentControlSet\\Services\\trapd-agent";
/// Where the SCM keeps the service DACL; its change notification is the only
/// one the service DACL has.
pub const SERVICE_SECURITY_KEY_PATH: &str =
    "SYSTEM\\CurrentControlSet\\Services\\trapd-agent\\Security";
pub const AGENT_KEY_PATH: &str = "SOFTWARE\\TRAPD\\Agent";

// ── Directories ───────────────────────────────────────────────────────────────

/// Data, config and state/log directories: SYSTEM full, Administrators read and
/// execute, no access for standard users (they hold secrets and keys). These
/// are the strings `Package.wxs` applies.
pub const DIR_SDDL: &str = "D:P(A;OICI;FA;;;SY)(A;OICI;FRFX;;;BA)(A;OICI;RC;;;OW)";
/// Install directory (program binaries and the pairing helper, nothing secret):
/// as `DIR_SDDL` plus read and execute for standard users, as Program Files
/// normally grants. Users need it to start the unelevated "Pair this computer"
/// shortcut, which reads `pair.ps1` before it elevates. No write for anyone but
/// SYSTEM. `Package.wxs` applies this string to `INSTALLFOLDER` only.
pub const INSTALL_DIR_SDDL: &str =
    "D:P(A;OICI;FA;;;SY)(A;OICI;FRFX;;;BA)(A;OICI;FRFX;;;BU)(A;OICI;RC;;;OW)";
/// `<state>\maintenance\requests`: Administrators may only add a file
/// (`FILE_ADD_FILE | SYNCHRONIZE`, on the directory itself, not inherited); they
/// cannot list, read, replace or delete requests. The service verifies every
/// token itself, so this only keeps the directory from being a free-for-all.
pub const REQUESTS_DIR_SDDL: &str = "D:P(A;OICI;FA;;;SY)(A;;0x100002;;;BA)(A;OICI;RC;;;OW)";
/// Previous descriptor of the data directories (Administrators full control).
pub const DATA_DIR_LEGACY_SDDL: &str = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";
/// Program Files default as it applied to the install directory before.
pub const INSTALL_DIR_LEGACY_SDDL: &str = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FRFX;;;BU)";

// ── SDDL reader ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Ace {
    pub kind: char,
    pub flags: String,
    pub mask: u32,
    pub sid: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedDacl {
    pub protected: bool,
    pub aces: Vec<Ace>,
}

/// Value of an SDDL rights token (`CC`, `KR`, `FA`, ...) or `0x` hex number.
fn right_value(token: &str) -> Option<u32> {
    Some(match token {
        "CC" => 0x1,
        "DC" => 0x2,
        "LC" => 0x4,
        "SW" => 0x8,
        "RP" => 0x10,
        "WP" => 0x20,
        "DT" => 0x40,
        "LO" => 0x80,
        "CR" => 0x100,
        "SD" => 0x1_0000,
        "RC" => 0x2_0000,
        "WD" => 0x4_0000,
        "WO" => 0x8_0000,
        "GA" => 0x1000_0000,
        "GX" => 0x2000_0000,
        "GW" => 0x4000_0000,
        "GR" => 0x8000_0000,
        "FA" => 0x001F_01FF,
        "FR" => 0x0012_0089,
        "FW" => 0x0012_0116,
        "FX" => 0x0012_00A0,
        "KA" => 0x000F_003F,
        "KR" | "KX" => 0x0002_0019,
        "KW" => 0x0002_0006,
        _ => return None,
    })
}

fn parse_rights(s: &str) -> Option<u32> {
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        return u32::from_str_radix(hex, 16).ok();
    }
    if !s.len().is_multiple_of(2) || !s.is_ascii() {
        return None;
    }
    let mut mask = 0u32;
    for i in (0..s.len()).step_by(2) {
        mask |= right_value(&s[i..i + 2])?;
    }
    Some(mask)
}

/// Parse the `D:` part of an SDDL string. Allow ACEs only; anything else
/// (deny, audit, conditional, object ACEs) is `None` so that it never compares
/// equal to the expected descriptor.
pub fn parse_dacl(sddl: &str) -> Option<ParsedDacl> {
    let start = sddl.find("D:")?;
    let rest = &sddl[start + 2..];
    // Stop at a following SACL section.
    let rest = rest.split("S:").next().unwrap_or(rest);
    let header_end = rest.find('(').unwrap_or(rest.len());
    let header = &rest[..header_end];
    let protected = header.contains('P');
    let mut aces = Vec::new();
    for part in rest[header_end..].split('(').skip(1) {
        let body = part.strip_suffix(')')?;
        let f: Vec<&str> = body.split(';').collect();
        if f.len() != 6 || f[0] != "A" || !f[3].is_empty() || !f[4].is_empty() {
            return None;
        }
        aces.push(Ace {
            kind: 'A',
            flags: f[1].to_string(),
            mask: parse_rights(f[2])?,
            sid: f[5].to_ascii_uppercase(),
        });
    }
    aces.sort();
    Some(ParsedDacl { protected, aces })
}

/// Whether the DACL in `actual` is the one in `expected`. `ACE` order is
/// irrelevant (allow ACEs only), rights letters and hex masks compare equal.
/// The protected-from-inheritance bit counts only where the object kind keeps
/// it (registry keys, files); the service control manager does not.
pub fn dacl_matches(actual: &str, expected: &str, check_protected: bool) -> bool {
    match (parse_dacl(actual), parse_dacl(expected)) {
        (Some(a), Some(e)) => a.aces == e.aces && (!check_protected || a.protected == e.protected),
        _ => false,
    }
}

/// Names of values that were added, removed or modified between two snapshots
/// (value name -> digest). Names only: the data is never copied into a finding.
pub fn changed_values(
    before: &std::collections::BTreeMap<String, String>,
    now: &std::collections::BTreeMap<String, String>,
) -> Vec<String> {
    let mut names: Vec<String> = now
        .iter()
        .filter(|(k, v)| before.get(*k) != Some(*v))
        .map(|(k, _)| k.clone())
        .chain(before.keys().filter(|k| !now.contains_key(*k)).cloned())
        .collect();
    names.sort();
    names.dedup();
    names
}

/// The owner of an SDDL string (`O:<sid>`), if any.
pub fn owner_of(sddl: &str) -> Option<String> {
    let rest = sddl.strip_prefix("O:")?;
    // The owner ends at the next section marker (`G:`, `D:`, `S:`). SID aliases
    // such as `SY` contain those letters, so only a letter followed by ':' counts.
    let bytes = rest.as_bytes();
    let end = (0..bytes.len().saturating_sub(1))
        .find(|&i| matches!(bytes[i], b'G' | b'D' | b'S') && bytes[i + 1] == b':')?;
    Some(rest[..end].to_string())
}

// ── Findings ──────────────────────────────────────────────────────────────────

fn short_digest(text: &str) -> String {
    hex::encode(&Sha256::digest(text.as_bytes())[..8])
}

fn finding(
    rule_id: &str,
    title: &str,
    detail: &str,
    subject: &str,
    dedup_basis: &str,
    evidence: serde_json::Value,
) -> DetectionData {
    DetectionData {
        rule_id: rule_id.into(),
        title: title.into(),
        category: "defense_evasion".into(),
        mitre_tactic: Some("TA0005 Defense Evasion".into()),
        mitre_technique: Some("T1562.001".into()),
        confidence: 90,
        subject: subject.into(),
        detail: detail.into(),
        evidence,
        // Repeats of the same drifted state fold into one finding.
        dedup_key: Some(format!("{rule_id}:{}", short_digest(dedup_basis))),
        ..Default::default()
    }
}

/// The service's access-control list differs from what the installer set.
pub fn service_acl_finding(actual_sddl: &str, reasserted: bool) -> DetectionData {
    finding(
        ACL_RULE_ID,
        "TRAPD agent service permissions were changed",
        "The access-control list of the TRAPD agent service no longer matches the one the \
         installer set. Someone with administrative rights changed who may stop, reconfigure \
         or delete the sensor.",
        "trapd-agent",
        actual_sddl,
        serde_json::json!({
            "object": "service",
            "actual_sddl": actual_sddl,
            "expected_sddl": SERVICE_DACL_SDDL,
            "reasserted": reasserted,
            // The exact descriptor earlier releases installed: an install the
            // MSI has not migrated yet (signed self-update only), not necessarily
            // tampering. Reported either way, because restoring it is also what
            // an administrator regaining the right to stop the service would do.
            "matches_legacy_descriptor": dacl_matches(actual_sddl, SERVICE_DACL_LEGACY_SDDL, false),
        }),
    )
}

/// What changed on a watched registry key.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RegistryChange {
    pub key: String,
    pub dacl_drift: bool,
    pub actual_sddl: Option<String>,
    pub owner_changed: bool,
    pub owner: Option<String>,
    /// Names only: values may hold paths and account names, never copied.
    pub changed_values: Vec<String>,
}

impl RegistryChange {
    pub fn is_empty(&self) -> bool {
        !self.dacl_drift && !self.owner_changed && self.changed_values.is_empty()
    }
}

pub fn registry_finding(change: &RegistryChange, reasserted: bool) -> DetectionData {
    let basis = format!(
        "{}|{}|{}|{}",
        change.key,
        change.actual_sddl.as_deref().unwrap_or(""),
        change.owner.as_deref().unwrap_or(""),
        change.changed_values.join(",")
    );
    finding(
        REGISTRY_RULE_ID,
        "TRAPD agent service registry key was changed",
        "The registry key that defines the TRAPD agent service (start type, image path, \
         account, recovery actions) or its permissions or owner changed while the agent ran.",
        &change.key,
        &basis,
        serde_json::json!({
            "key": change.key,
            "dacl_drift": change.dacl_drift,
            "actual_sddl": change.actual_sddl,
            "expected_sddl": REGISTRY_KEY_SDDL,
            "owner_changed": change.owner_changed,
            "owner": change.owner,
            "changed_values": change.changed_values,
            "reasserted": reasserted,
        }),
    )
}

/// High severity is the agent's stamp; the backend decides from its catalog.
pub fn event(detection: DetectionData, agent_id: &str, hostname: &str) -> AgentEvent {
    AgentEvent::new(
        agent_id.to_string(),
        hostname.to_string(),
        EventClass::Detection,
        EventAction::Detected,
        Severity::High,
        EventData::Detection(Box::new(detection)),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const DC: u32 = 0x2;
    const WP: u32 = 0x20;
    const DT: u32 = 0x40;
    const SD: u32 = 0x1_0000;
    const WD: u32 = 0x4_0000;
    const WO: u32 = 0x8_0000;
    const RP: u32 = 0x10;
    const CR: u32 = 0x100;
    const CC: u32 = 0x1;
    const LC: u32 = 0x4;
    const LO: u32 = 0x80;
    const RC: u32 = 0x2_0000;
    const ALL_SERVICE: u32 = 0x000F_01FF;

    fn aces(sddl: &str) -> Vec<(String, u32)> {
        parse_dacl(sddl)
            .unwrap()
            .aces
            .into_iter()
            .map(|a| (a.sid, a.mask))
            .collect()
    }
    fn mask_of(sddl: &str, sid: &str) -> u32 {
        aces(sddl)
            .into_iter()
            .find(|(s, _)| s == sid)
            .unwrap_or_else(|| panic!("no ACE for {sid}"))
            .1
    }

    #[test]
    fn service_dacl_parses_and_is_protected() {
        let d = parse_dacl(SERVICE_DACL_SDDL).unwrap();
        assert!(d.protected);
        let mut sids: Vec<_> = d.aces.iter().map(|a| a.sid.as_str()).collect();
        sids.sort_unstable();
        assert_eq!(sids, ["BA", "IU", "OW", "SU", "SY"]);
    }

    #[test]
    fn administrators_cannot_stop_reconfigure_delete_or_take_over_the_service() {
        let ba = mask_of(SERVICE_DACL_SDDL, "BA");
        for (name, bit) in [
            ("DC", DC),
            ("WP", WP),
            ("DT", DT),
            ("SD", SD),
            ("WD", WD),
            ("WO", WO),
        ] {
            assert_eq!(ba & bit, 0, "Administrators must not hold {name}");
        }
        // Query, start, interrogate, read and the user-defined control remain.
        for bit in [CC, LC, RP, LO, CR, RC] {
            assert_ne!(ba & bit, 0);
        }
    }

    #[test]
    fn system_keeps_full_control_and_owner_rights_are_neutralised() {
        assert_eq!(mask_of(SERVICE_DACL_SDDL, "SY") & ALL_SERVICE, ALL_SERVICE);
        // The owner (normally Administrators) keeps READ_CONTROL only.
        assert_eq!(mask_of(SERVICE_DACL_SDDL, "OW"), RC);
        assert_eq!(mask_of(REGISTRY_KEY_SDDL, "OW"), RC);
        assert_eq!(mask_of(DIR_SDDL, "OW"), RC);
    }

    #[test]
    fn interactive_and_service_accounts_may_only_query() {
        for sid in ["IU", "SU"] {
            let m = mask_of(SERVICE_DACL_SDDL, sid);
            assert_eq!(m & (DC | WP | DT | SD | WD | WO | RP), 0, "{sid}");
        }
    }

    #[test]
    fn legacy_service_dacl_is_the_previous_one() {
        assert_eq!(
            SERVICE_DACL_LEGACY_SDDL,
            "D:P(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRC;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)"
        );
        let ba = mask_of(SERVICE_DACL_LEGACY_SDDL, "BA");
        assert_ne!(ba & WP, 0, "legacy lets Administrators stop the service");
        assert_ne!(ba & DC, 0);
        assert_eq!(ba & (WD | WO), 0);
        assert!(!dacl_matches(
            SERVICE_DACL_LEGACY_SDDL,
            SERVICE_DACL_SDDL,
            false
        ));
    }

    #[test]
    fn registry_descriptor_gives_administrators_read_only() {
        let ba = mask_of(REGISTRY_KEY_SDDL, "BA");
        assert_eq!(ba, 0x0002_0019, "KEY_READ");
        const KEY_SET_VALUE: u32 = 0x2;
        const KEY_CREATE_SUB_KEY: u32 = 0x4;
        const DELETE: u32 = 0x1_0000;
        assert_eq!(
            ba & (KEY_SET_VALUE | KEY_CREATE_SUB_KEY | DELETE | WD | WO),
            0
        );
        assert_eq!(
            mask_of(REGISTRY_KEY_SDDL, "SY"),
            0x000F_003F,
            "KEY_ALL_ACCESS"
        );
        assert!(parse_dacl(REGISTRY_KEY_SDDL).unwrap().protected);
        assert_eq!(mask_of(REGISTRY_KEY_LEGACY_SDDL, "BA"), 0x000F_003F);
    }

    #[test]
    fn directory_descriptor_gives_administrators_read_and_execute_only() {
        let ba = mask_of(DIR_SDDL, "BA");
        assert_eq!(ba, 0x0012_00A9, "FILE_GENERIC_READ | FILE_GENERIC_EXECUTE");
        const FILE_WRITE_DATA: u32 = 0x2;
        const FILE_APPEND_DATA: u32 = 0x4;
        const FILE_DELETE_CHILD: u32 = 0x40;
        const FILE_WRITE_ATTRIBUTES: u32 = 0x100;
        const DELETE: u32 = 0x1_0000;
        assert_eq!(
            ba & (FILE_WRITE_DATA
                | FILE_APPEND_DATA
                | FILE_DELETE_CHILD
                | FILE_WRITE_ATTRIBUTES
                | DELETE
                | WD
                | WO),
            0
        );
        let d = parse_dacl(DIR_SDDL).unwrap();
        assert!(d.protected);
        assert!(d.aces.iter().all(|a| a.flags == "OICI"));
        assert_eq!(mask_of(DIR_SDDL, "SY"), 0x001F_01FF);
        assert_eq!(mask_of(DATA_DIR_LEGACY_SDDL, "BA"), 0x001F_01FF);
        assert!(parse_dacl(INSTALL_DIR_LEGACY_SDDL).is_some());
    }

    #[test]
    fn install_directory_lets_users_read_and_execute_but_never_write() {
        let d = parse_dacl(INSTALL_DIR_SDDL).unwrap();
        assert!(d.protected);
        assert!(d.aces.iter().all(|a| a.kind == 'A' && a.flags == "OICI"));
        let bu = mask_of(INSTALL_DIR_SDDL, "BU");
        assert_eq!(bu, 0x0012_00A9, "FILE_GENERIC_READ | FILE_GENERIC_EXECUTE");
        // No write, append, delete, delete-child, attribute write, DACL or owner change.
        assert_eq!(bu & (0x2 | 0x4 | 0x40 | 0x100 | 0x1_0000 | WD | WO), 0);
        assert_eq!(mask_of(INSTALL_DIR_SDDL, "BA"), mask_of(DIR_SDDL, "BA"));
        assert_eq!(mask_of(INSTALL_DIR_SDDL, "SY"), 0x001F_01FF);
        assert_eq!(mask_of(INSTALL_DIR_SDDL, "OW"), RC);
        // The data/config/state descriptor stays closed to users.
        assert!(parse_dacl(DIR_SDDL)
            .unwrap()
            .aces
            .iter()
            .all(|a| a.sid != "BU"));
    }

    #[test]
    fn request_directory_is_add_only_for_administrators() {
        let d = parse_dacl(REQUESTS_DIR_SDDL).unwrap();
        let ba = d.aces.iter().find(|a| a.sid == "BA").unwrap();
        assert_eq!(ba.mask, 0x0010_0002, "FILE_ADD_FILE | SYNCHRONIZE");
        assert_eq!(
            ba.flags, "",
            "applies to the directory, not to the files in it"
        );
        // Not list-directory (0x1), delete child (0x40) or any ownership right.
        assert_eq!(ba.mask & (0x1 | 0x40 | 0x1_0000 | WD | WO), 0);
    }

    #[test]
    fn unprotected_and_unsupported_input_never_matches() {
        assert!(parse_dacl("garbage").is_none());
        assert!(parse_dacl("D:P(D;;CC;;;BA)").is_none(), "deny ACE");
        assert!(parse_dacl("D:P(A;;CC;;;BA").is_none(), "unterminated");
        assert!(parse_dacl("D:P(A;;ZZ;;;BA)").is_none(), "unknown right");
        assert!(!dacl_matches("garbage", SERVICE_DACL_SDDL, false));
    }

    #[test]
    fn drift_comparison_ignores_order_hex_and_letter_spelling() {
        // Same ACEs, reordered.
        let reordered = "D:P(A;;RC;;;OW)(A;;CCLCSWLOCRRC;;;SU)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWRPLOCRRC;;;BA)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)";
        assert!(dacl_matches(reordered, SERVICE_DACL_SDDL, true));
        // KEY_READ spelled as hex.
        let hex = "D:P(A;CI;0xf003f;;;SY)(A;CI;0x20019;;;BA)(A;CI;0x20000;;;OW)";
        assert!(dacl_matches(hex, REGISTRY_KEY_SDDL, true));
        // Whatever Windows adds as inheritance marker text on read-back.
        let ai = "D:PAI(A;CI;KA;;;SY)(A;CI;KR;;;BA)(A;CI;RC;;;OW)";
        assert!(dacl_matches(ai, REGISTRY_KEY_SDDL, true));
    }

    #[test]
    fn drift_is_detected_for_added_widened_or_missing_entries() {
        // Administrators regain stop.
        let widened = SERVICE_DACL_SDDL.replace("CCLCSWRPLOCRRC;;;BA", "CCLCSWRPWPLOCRRC;;;BA");
        assert!(!dacl_matches(&widened, SERVICE_DACL_SDDL, false));
        // Extra principal.
        let extra = format!("{SERVICE_DACL_SDDL}(A;;CCLCSWRPWPLOCRRC;;;WD)");
        assert!(!dacl_matches(&extra, SERVICE_DACL_SDDL, false));
        // Missing OWNER RIGHTS entry.
        let missing = SERVICE_DACL_SDDL.replace("(A;;RC;;;OW)", "");
        assert!(!dacl_matches(&missing, SERVICE_DACL_SDDL, false));
        // Legacy equals itself.
        assert!(dacl_matches(
            SERVICE_DACL_LEGACY_SDDL,
            SERVICE_DACL_LEGACY_SDDL,
            true
        ));
    }

    #[test]
    fn inheritance_protection_counts_only_where_requested() {
        let unprotected = REGISTRY_KEY_SDDL.replace("D:P", "D:");
        assert!(!dacl_matches(&unprotected, REGISTRY_KEY_SDDL, true));
        assert!(dacl_matches(&unprotected, REGISTRY_KEY_SDDL, false));
    }

    #[test]
    fn sacl_section_is_not_part_of_the_comparison() {
        let with_sacl = format!("{SERVICE_DACL_SDDL}S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)");
        assert!(dacl_matches(&with_sacl, SERVICE_DACL_SDDL, true));
    }

    #[test]
    fn changed_values_reports_added_removed_and_modified_names() {
        let mk = |pairs: &[(&str, &str)]| -> std::collections::BTreeMap<String, String> {
            pairs
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect()
        };
        let before = mk(&[("Start", "a"), ("ImagePath", "b"), ("Gone", "c")]);
        let now = mk(&[("Start", "x"), ("ImagePath", "b"), ("New", "d")]);
        assert_eq!(changed_values(&before, &now), ["Gone", "New", "Start"]);
        assert!(changed_values(&before, &before).is_empty());
    }

    #[test]
    fn owner_is_read_from_a_full_descriptor() {
        assert_eq!(owner_of("O:BAD:P(A;;CC;;;BA)").as_deref(), Some("BA"));
        assert_eq!(owner_of("O:SYG:SYD:P(A;;CC;;;BA)").as_deref(), Some("SY"));
        assert_eq!(
            owner_of("O:S-1-5-21-1-2-3-500D:P(A;;CC;;;BA)").as_deref(),
            Some("S-1-5-21-1-2-3-500")
        );
        assert_eq!(owner_of("D:P(A;;CC;;;BA)"), None);
    }

    #[test]
    fn service_acl_event_is_high_severity_t1562_001_and_stable_for_dedup() {
        let ev = event(
            service_acl_finding(SERVICE_DACL_LEGACY_SDDL, true),
            "agent_1",
            "host",
        );
        assert_eq!(ev.severity, Severity::High);
        let EventData::Detection(d) = &ev.data else {
            panic!("detection expected")
        };
        assert_eq!(d.rule_id, "selfprotect.service_acl_changed");
        assert_eq!(d.mitre_technique.as_deref(), Some("T1562.001"));
        assert_eq!(d.mitre_tactic.as_deref(), Some("TA0005 Defense Evasion"));
        assert_eq!(d.evidence["reasserted"], true);
        assert_eq!(d.evidence["actual_sddl"], SERVICE_DACL_LEGACY_SDDL);
        assert_eq!(d.evidence["matches_legacy_descriptor"], true);
        let other_ev = service_acl_finding("D:P(A;;CC;;;WD)", false);
        assert_eq!(other_ev.evidence["matches_legacy_descriptor"], false);
        let again = service_acl_finding(SERVICE_DACL_LEGACY_SDDL, false);
        assert_eq!(d.dedup_key, again.dedup_key, "same drift, same key");
        let other = service_acl_finding("D:P(A;;CC;;;WD)", false);
        assert_ne!(d.dedup_key, other.dedup_key);
    }

    #[test]
    fn registry_event_lists_value_names_only() {
        let change = RegistryChange {
            key: SERVICE_KEY_PATH.into(),
            dacl_drift: true,
            actual_sddl: Some("D:(A;;KA;;;WD)".into()),
            owner_changed: true,
            owner: Some("S-1-5-21-1-2-3-1001".into()),
            changed_values: vec!["Start".into(), "ImagePath".into()],
        };
        assert!(!change.is_empty());
        let ev = event(registry_finding(&change, true), "agent_1", "host");
        assert_eq!(ev.severity, Severity::High);
        let EventData::Detection(d) = &ev.data else {
            panic!("detection expected")
        };
        assert_eq!(d.rule_id, "selfprotect.service_registry_changed");
        assert_eq!(d.mitre_technique.as_deref(), Some("T1562.001"));
        assert_eq!(d.subject, SERVICE_KEY_PATH);
        assert_eq!(d.evidence["changed_values"][0], "Start");
        assert_eq!(d.evidence["owner_changed"], true);
        assert!(d
            .dedup_key
            .as_deref()
            .unwrap()
            .starts_with("selfprotect.service_registry_changed:"));
        assert!(RegistryChange::default().is_empty());
    }
}
