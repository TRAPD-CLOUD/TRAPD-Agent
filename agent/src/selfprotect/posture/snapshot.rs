//! Platform posture snapshot, its diff, and the finding built from a diff.
//!
//! Pure and portable: collectors (`linux.rs`, `windows.rs`) produce a
//! [`Snapshot`]; this module decides what counts as a weakening.

use std::collections::{BTreeMap, HashSet};
use std::path::Path;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use trapd_schema::{DetectionData, Severity};

pub const RULE_ID: &str = "selfprotect.platform_posture_changed";
const SNAPSHOT_FILE: &str = "platform_posture.json";
const MAX_SNAPSHOT_BYTES: u64 = 256 * 1024;

/// One observed platform setting. `secure` is `None` when the setting cannot be
/// judged (unreadable, not applicable, legacy BIOS): unknown is never reported
/// as a weakening.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Setting {
    pub value: String,
    pub secure: Option<bool>,
}

impl Setting {
    pub fn new(value: impl Into<String>, secure: Option<bool>) -> Self {
        Self {
            value: value.into(),
            secure,
        }
    }
    pub fn unknown(why: &str) -> Self {
        Self::new(why, None)
    }
    pub fn flag(on: bool) -> Self {
        Self::new(if on { "on" } else { "off" }, Some(on))
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Snapshot {
    pub platform: String,
    pub taken_at: DateTime<Utc>,
    pub settings: BTreeMap<String, Setting>,
}

impl Snapshot {
    pub fn new(platform: &str, settings: BTreeMap<String, Setting>) -> Self {
        Self {
            platform: platform.into(),
            taken_at: Utc::now(),
            settings,
        }
    }

    /// Baseline to persist: the current values, but a setting that is
    /// momentarily unreadable keeps its last known value. Otherwise a read
    /// failure would blank the baseline and hide a later weakening (or raise a
    /// bogus one when the value reappears).
    pub fn merged_over(&self, previous: Option<&Snapshot>) -> Snapshot {
        let mut out = self.clone();
        if let Some(prev) = previous {
            for (k, old) in &prev.settings {
                match out.settings.get(k) {
                    Some(cur) if cur.secure.is_some() => {}
                    _ if old.secure.is_some() => {
                        out.settings.insert(k.clone(), old.clone());
                    }
                    _ => {}
                }
            }
        }
        out
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    Weakened,
    Strengthened,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Change {
    pub key: String,
    pub before: Setting,
    pub after: Setting,
    pub direction: Direction,
}

/// Settings whose secure/insecure judgement flipped between two snapshots.
/// Keys in `ignore` (operator allowlist) are skipped. Settings that are
/// unknown on either side are skipped too.
pub fn diff(prev: &Snapshot, cur: &Snapshot, ignore: &HashSet<String>) -> Vec<Change> {
    let mut out = Vec::new();
    for (key, after) in &cur.settings {
        if ignore.contains(key) {
            continue;
        }
        let Some(before) = prev.settings.get(key) else {
            continue;
        };
        let direction = match (before.secure, after.secure) {
            (Some(true), Some(false)) => Direction::Weakened,
            (Some(false), Some(true)) => Direction::Strengthened,
            _ => continue,
        };
        out.push(Change {
            key: key.clone(),
            before: before.clone(),
            after: after.clone(),
            direction,
        });
    }
    out
}

pub fn severity(changes: &[Change]) -> Severity {
    if changes.iter().any(|c| c.direction == Direction::Weakened) {
        Severity::High
    } else {
        Severity::Info
    }
}

/// Finding for a non-empty change list: high when anything weakened, info when
/// the platform only got stronger. Carries before/after of every change.
pub fn finding(changes: &[Change]) -> Option<(Severity, DetectionData)> {
    if changes.is_empty() {
        return None;
    }
    let sev = severity(changes);
    let weakened: Vec<&str> = changes
        .iter()
        .filter(|c| c.direction == Direction::Weakened)
        .map(|c| c.key.as_str())
        .collect();
    let (title, detail) = if weakened.is_empty() {
        (
            "Platform security posture strengthened".to_string(),
            "A platform security setting changed to a more secure value".to_string(),
        )
    } else {
        (
            "Platform security posture weakened".to_string(),
            format!("Weakened platform settings: {}", weakened.join(", ")),
        )
    };
    Some((
        sev,
        DetectionData {
            rule_id: RULE_ID.into(),
            title,
            category: "defense_evasion".into(),
            mitre_tactic: Some("TA0005 Defense Evasion".into()),
            mitre_technique: Some("T1562".into()),
            confidence: if sev == Severity::High { 70 } else { 90 },
            subject: "platform".into(),
            detail,
            evidence: serde_json::json!({ "source": "posture", "changes": changes }),
            ..Default::default()
        },
    ))
}

pub fn load(dir: &Path) -> Option<Snapshot> {
    let bytes =
        crate::paths::bounded_regular_bytes(&dir.join(SNAPSHOT_FILE), MAX_SNAPSHOT_BYTES).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// Atomic write (temp file + rename) so a crash never leaves a torn baseline.
pub fn store(dir: &Path, snap: &Snapshot) -> std::io::Result<()> {
    write_json_atomic(&dir.join(SNAPSHOT_FILE), snap)
}

pub(super) fn write_json_atomic<T: Serialize>(path: &Path, value: &T) -> std::io::Result<()> {
    let tmp = path.with_extension("json.tmp");
    std::fs::write(
        &tmp,
        serde_json::to_vec(value).map_err(std::io::Error::other)?,
    )?;
    std::fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snap(items: &[(&str, Setting)]) -> Snapshot {
        Snapshot::new(
            "test",
            items
                .iter()
                .map(|(k, v)| (k.to_string(), v.clone()))
                .collect(),
        )
    }

    #[test]
    fn weakening_is_high_with_before_and_after() {
        let a = snap(&[("secure_boot", Setting::flag(true))]);
        let b = snap(&[("secure_boot", Setting::flag(false))]);
        let ch = diff(&a, &b, &HashSet::new());
        assert_eq!(ch.len(), 1);
        assert_eq!(ch[0].direction, Direction::Weakened);
        let (sev, d) = finding(&ch).unwrap();
        assert_eq!(sev, Severity::High);
        assert_eq!(d.rule_id, RULE_ID);
        assert_eq!(d.evidence["changes"][0]["before"]["value"], "on");
        assert_eq!(d.evidence["changes"][0]["after"]["value"], "off");
    }

    #[test]
    fn strengthening_is_info() {
        let a = snap(&[("hvci", Setting::flag(false))]);
        let b = snap(&[("hvci", Setting::flag(true))]);
        let (sev, _) = finding(&diff(&a, &b, &HashSet::new())).unwrap();
        assert_eq!(sev, Severity::Info);
    }

    #[test]
    fn mixed_change_is_high() {
        let a = snap(&[("a", Setting::flag(true)), ("b", Setting::flag(false))]);
        let b = snap(&[("a", Setting::flag(false)), ("b", Setting::flag(true))]);
        let ch = diff(&a, &b, &HashSet::new());
        assert_eq!(ch.len(), 2);
        assert_eq!(severity(&ch), Severity::High);
    }

    #[test]
    fn unknown_and_unchanged_and_new_keys_are_silent() {
        let a = snap(&[
            ("a", Setting::flag(true)),
            ("u", Setting::unknown("unreadable")),
            ("same", Setting::flag(false)),
        ]);
        let b = snap(&[
            ("a", Setting::unknown("unreadable")),
            ("u", Setting::flag(false)),
            ("same", Setting::flag(false)),
            ("new", Setting::flag(false)),
        ]);
        assert!(diff(&a, &b, &HashSet::new()).is_empty());
        assert!(finding(&[]).is_none());
    }

    #[test]
    fn allowlisted_key_is_skipped() {
        let a = snap(&[("kexec", Setting::flag(true))]);
        let b = snap(&[("kexec", Setting::flag(false))]);
        let ignore: HashSet<String> = ["kexec".to_string()].into();
        assert!(diff(&a, &b, &ignore).is_empty());
    }

    #[test]
    fn unreadable_value_keeps_last_known_in_baseline() {
        let prev = snap(&[("a", Setting::flag(true))]);
        let cur = snap(&[("a", Setting::unknown("unreadable"))]);
        let merged = cur.merged_over(Some(&prev));
        assert_eq!(merged.settings["a"], Setting::flag(true));
        // A later weakening is still caught against the retained value.
        let later = snap(&[("a", Setting::flag(false))]);
        assert_eq!(diff(&merged, &later, &HashSet::new()).len(), 1);
    }

    #[test]
    fn persistence_roundtrip_and_corrupt_file() {
        let dir = std::env::temp_dir().join(format!("trapd_posture_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        assert!(load(&dir).is_none());
        let s = snap(&[("a", Setting::flag(true))]);
        store(&dir, &s).unwrap();
        assert_eq!(load(&dir).unwrap(), s);
        std::fs::write(dir.join(SNAPSHOT_FILE), b"{not json").unwrap();
        assert!(load(&dir).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
