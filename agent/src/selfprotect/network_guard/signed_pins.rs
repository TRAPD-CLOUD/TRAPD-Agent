//! Signed delivery of the backend TLS pins.
//!
//! The pins ride in the signed agent config (`backend_spki_pins`,
//! `tls_inspection_ca_pins`, `tls_pinning_disabled`), so removing them needs
//! the operator's signing key, not just root on the host.
//!
//! Decision record:
//! * **Precedence.** A non-empty signed `backend_spki_pins` replaces the
//!   local backend pins (env `TRAPD_BACKEND_SPKI_PINS` / `network_guard.json`).
//!   Local sources can only *add* inspection CA pins; they never remove or
//!   shadow signed ones.
//! * **High-water file.** Once non-empty signed pins were received, the last
//!   received set is persisted in `<state>/tls_pins_high_water.json`. From
//!   then on an empty signed set is *not* read as "pinning off": the agent
//!   keeps enforcing the last known set and reports
//!   `selfprotect.tls_pin_mismatch` with reason `pins_removed` once (also
//!   across restarts). Clearing is only possible with a signed
//!   `tls_pinning_disabled: true`, which also deletes the file.
//!   This is intentionally stricter than "effective set empty": a signed
//!   config that silently drops the pins while local pins exist is just as
//!   suspicious, and the last signed set stays authoritative.
//! * **Limits.** A local administrator can still delete the state directory
//!   (the file, the config watermark and the cached config). The agent then
//!   starts without pins until its next config pull delivers them again;
//!   signed state cannot be forged, but local deletion cannot be prevented.
//!   An unreadable high-water file is treated as "flag set, set unknown": the
//!   removal is reported but nothing can be enforced beyond the local pins
//!   (failing closed would brick the agent without a way to recover).

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tracing::{error, warn};

use super::tls_pin::{PinPolicy, PinState};
use crate::config::AgentConfig;

const FILE: &str = "tls_pins_high_water.json";
const MAX_FILE_BYTES: u64 = 16 * 1024;

pub fn high_water_path() -> PathBuf {
    crate::paths::state_dir().join(FILE)
}

/// The pin fields of a verified, validated signed config.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SignedPins {
    pub pins: Vec<String>,
    pub inspection: Vec<String>,
    pub disabled: bool,
}

impl SignedPins {
    pub fn from_config(c: &AgentConfig) -> Self {
        Self {
            pins: c.backend_spki_pins.clone(),
            inspection: c.tls_inspection_ca_pins.clone(),
            disabled: c.tls_pinning_disabled,
        }
    }

    fn is_empty(&self) -> bool {
        self.pins.is_empty() && self.inspection.is_empty()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HighWater {
    pub pins: Vec<String>,
    #[serde(default)]
    pub inspection: Vec<String>,
    #[serde(default)]
    pub removal_reported: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HighWaterState {
    Absent,
    Known(HighWater),
    /// The file exists but cannot be trusted.
    Unreadable,
}

pub fn load_high_water(path: &Path) -> HighWaterState {
    let meta = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return HighWaterState::Absent,
        Err(_) => return HighWaterState::Unreadable,
    };
    if meta.len() > MAX_FILE_BYTES {
        return HighWaterState::Unreadable;
    }
    let parsed = std::fs::read(path)
        .ok()
        .and_then(|b| serde_json::from_slice::<HighWater>(&b).ok());
    match parsed {
        Some(hw)
            if !hw.pins.is_empty()
                && PinPolicy::from_lists(&hw.pins, &hw.inspection).1.is_none() =>
        {
            HighWaterState::Known(hw)
        }
        _ => HighWaterState::Unreadable,
    }
}

/// What a removal notice tells the operator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemovalNotice {
    /// Pins of the last known signed set that stay enforced (0: set unknown).
    pub enforced_pins: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreAction {
    Keep,
    Write(HighWater),
    Clear,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolution {
    pub policy: PinPolicy,
    pub store: StoreAction,
    pub removal: Option<RemovalNotice>,
}

fn with_local_inspection(signed_insp: &[String], local: &PinPolicy, pins: &[String]) -> PinPolicy {
    let (mut p, _) = PinPolicy::from_lists(pins, signed_insp);
    p.inspection.extend(local.inspection.iter().copied());
    p.enforce = true;
    p
}

/// Pure resolution of the effective policy. `local` is the env/file policy.
pub fn resolve(local: &PinPolicy, signed: &SignedPins, hw: &HighWaterState) -> Resolution {
    if signed.disabled {
        return Resolution {
            policy: local.clone(),
            store: match hw {
                HighWaterState::Absent => StoreAction::Keep,
                _ => StoreAction::Clear,
            },
            removal: None,
        };
    }
    if !signed.is_empty() {
        let new = HighWater {
            pins: signed.pins.clone(),
            inspection: signed.inspection.clone(),
            removal_reported: false,
        };
        let store = if matches!(hw, HighWaterState::Known(k) if *k == new) {
            StoreAction::Keep
        } else {
            StoreAction::Write(new)
        };
        return Resolution {
            policy: with_local_inspection(&signed.inspection, local, &signed.pins),
            store,
            removal: None,
        };
    }
    match hw {
        HighWaterState::Absent => Resolution {
            policy: local.clone(),
            store: StoreAction::Keep,
            removal: None,
        },
        HighWaterState::Known(k) => Resolution {
            policy: with_local_inspection(&k.inspection, local, &k.pins),
            store: StoreAction::Keep,
            removal: (!k.removal_reported).then_some(RemovalNotice {
                enforced_pins: k.pins.len(),
            }),
        },
        HighWaterState::Unreadable => Resolution {
            policy: local.clone(),
            store: StoreAction::Keep,
            removal: Some(RemovalNotice { enforced_pins: 0 }),
        },
    }
}

impl PinState {
    /// Apply the pin fields of a verified signed config. `hw_path` is the
    /// high-water file.
    pub fn apply_signed(&self, signed: &SignedPins, hw_path: &Path) {
        let hw = load_high_water(hw_path);
        let res = resolve(self.local_policy(), signed, &hw);
        match &res.store {
            StoreAction::Keep => {}
            StoreAction::Write(new) => match serde_json::to_vec(new)
                .map_err(anyhow::Error::from)
                .and_then(|b| crate::paths::write_atomic(hw_path, &b, 0o600))
            {
                Ok(()) => {}
                Err(e) => error!(error = %e, "cannot persist the TLS pin high-water file"),
            },
            StoreAction::Clear => {
                if let Err(e) = std::fs::remove_file(hw_path) {
                    if e.kind() != std::io::ErrorKind::NotFound {
                        error!(error = %e, "cannot remove the TLS pin high-water file");
                    }
                }
            }
        }
        if res.removal.is_some() {
            warn!("TLS: signed backend pins were removed without an explicit disable; keeping the last known set");
        }
        if let Ok(mut slot) = self.pins_removed.lock() {
            *slot = res.removal.clone();
        }
        self.set_policy(res.policy);
    }

    /// The `pins_removed` notice, once. Marks it reported in the high-water
    /// file so a restart does not repeat it.
    pub fn take_pins_removed(&self, hw_path: &Path) -> Option<RemovalNotice> {
        let notice = self.pins_removed.lock().ok()?.take()?;
        if let HighWaterState::Known(mut k) = load_high_water(hw_path) {
            k.removal_reported = true;
            let written = serde_json::to_vec(&k)
                .map_err(anyhow::Error::from)
                .and_then(|b| crate::paths::write_atomic(hw_path, &b, 0o600));
            if let Err(e) = written {
                warn!(error = %e, "cannot mark the pins_removed notice as reported");
            }
        }
        Some(notice)
    }
}

/// Apply the pin fields of `cfg` to the process-wide pin state.
pub fn apply_signed_config(cfg: &AgentConfig) {
    super::tls_pin::global().apply_signed(&SignedPins::from_config(cfg), &high_water_path());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::selfprotect::network_guard::tls_pin::{decide, parse_pin, PinDecision};

    const A: &str = "80DnfYEFSfic/R4K/U8B7OAJ9dZwj/hvQu4YmIIF0/c=";
    const B: &str = "tIQn31OoLmnaS0vIiY6tNIGq8Da+KtFNbK1NGmLN5D8=";
    const C: &str = "RgIEHp8ygo95bEkxO3IrSBWdm8cGy1/QoyyqFCtJ6wo=";

    fn pin(s: &str) -> [u8; 32] {
        parse_pin(s).unwrap()
    }
    fn local(pins: &[&str], insp: &[&str]) -> PinPolicy {
        let p: Vec<String> = pins.iter().map(|s| s.to_string()).collect();
        let i: Vec<String> = insp.iter().map(|s| s.to_string()).collect();
        PinPolicy::from_lists(&p, &i).0
    }
    fn signed(pins: &[&str], insp: &[&str], disabled: bool) -> SignedPins {
        SignedPins {
            pins: pins.iter().map(|s| s.to_string()).collect(),
            inspection: insp.iter().map(|s| s.to_string()).collect(),
            disabled,
        }
    }
    fn tmp(name: &str) -> PathBuf {
        let d =
            std::env::temp_dir().join(format!("trapd-signed-pins-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d.join(FILE)
    }
    fn chain(pins: &[&str]) -> Vec<[u8; 32]> {
        pins.iter().map(|p| pin(p)).collect()
    }

    #[test]
    fn signed_pins_take_precedence_over_local_backend_pins() {
        let r = resolve(
            &local(&[C], &[]),
            &signed(&[A], &[], false),
            &HighWaterState::Absent,
        );
        assert!(r.policy.enforce);
        assert_eq!(decide(&r.policy, &chain(&[A])), PinDecision::Match);
        assert_eq!(
            decide(&r.policy, &chain(&[C])),
            PinDecision::Mismatch,
            "local pin must not widen signed pins"
        );
        assert!(matches!(r.store, StoreAction::Write(_)));
        assert!(r.removal.is_none());
    }

    #[test]
    fn local_inspection_pins_only_add() {
        let r = resolve(
            &local(&[], &[C]),
            &signed(&[A], &[B], false),
            &HighWaterState::Absent,
        );
        assert_eq!(
            decide(&r.policy, &chain(&[B])),
            PinDecision::InspectionMatch
        );
        assert_eq!(
            decide(&r.policy, &chain(&[C])),
            PinDecision::InspectionMatch
        );
        assert_eq!(decide(&r.policy, &chain(&[A])), PinDecision::Match);
    }

    #[test]
    fn without_signed_pins_and_without_history_local_sources_apply_unchanged() {
        let r = resolve(
            &local(&[C], &[]),
            &SignedPins::default(),
            &HighWaterState::Absent,
        );
        assert_eq!(decide(&r.policy, &chain(&[C])), PinDecision::Match);
        assert_eq!(r.store, StoreAction::Keep);
        let none = resolve(
            &local(&[], &[]),
            &SignedPins::default(),
            &HighWaterState::Absent,
        );
        assert_eq!(decide(&none.policy, &chain(&[A])), PinDecision::ReportOnly);
        assert!(none.removal.is_none());
    }

    #[test]
    fn removed_pins_keep_enforcing_the_last_known_set_and_report_once() {
        let path = tmp("removal");
        let state = PinState::with_policy(PinPolicy::default());
        state.apply_signed(&signed(&[A], &[B], false), &path);
        assert!(path.exists());
        assert!(state.take_pins_removed(&path).is_none());

        // Later config: signed pins gone, no explicit disable, local sources gone.
        state.apply_signed(&SignedPins::default(), &path);
        let p = state.policy();
        assert!(p.enforce);
        assert_eq!(decide(&p, &chain(&[A])), PinDecision::Match);
        assert_eq!(decide(&p, &chain(&[B])), PinDecision::InspectionMatch);
        assert_eq!(decide(&p, &chain(&[C])), PinDecision::Mismatch);
        assert_eq!(
            state.take_pins_removed(&path),
            Some(RemovalNotice { enforced_pins: 1 })
        );
        // Once: not again, not after re-applying, not after a restart.
        assert!(state.take_pins_removed(&path).is_none());
        state.apply_signed(&SignedPins::default(), &path);
        assert!(state.take_pins_removed(&path).is_none());
        let restarted = PinState::with_policy(PinPolicy::default());
        restarted.apply_signed(&SignedPins::default(), &path);
        assert!(restarted.take_pins_removed(&path).is_none());
        assert_eq!(
            decide(&restarted.policy(), &chain(&[C])),
            PinDecision::Mismatch,
            "restart keeps enforcing"
        );
    }

    #[test]
    fn local_sources_cannot_replace_the_last_known_signed_set() {
        let path = tmp("localcannot");
        let state = PinState::with_policy(local(&[C], &[]));
        state.apply_signed(&signed(&[A], &[], false), &path);
        state.apply_signed(&SignedPins::default(), &path);
        let p = state.policy();
        assert_eq!(decide(&p, &chain(&[A])), PinDecision::Match);
        assert_eq!(decide(&p, &chain(&[C])), PinDecision::Mismatch);
        assert!(state.take_pins_removed(&path).is_some());
    }

    #[test]
    fn explicit_signed_disable_clears_the_pins_and_the_flag() {
        let path = tmp("disable");
        let state = PinState::with_policy(PinPolicy::default());
        state.apply_signed(&signed(&[A], &[], false), &path);
        state.apply_signed(&signed(&[], &[], true), &path);
        assert!(!path.exists());
        assert_eq!(
            decide(&state.policy(), &chain(&[C])),
            PinDecision::ReportOnly
        );
        assert!(state.take_pins_removed(&path).is_none());
        // With the flag gone an empty config is simply "no pins" again.
        state.apply_signed(&SignedPins::default(), &path);
        assert_eq!(
            decide(&state.policy(), &chain(&[C])),
            PinDecision::ReportOnly
        );
        assert!(state.take_pins_removed(&path).is_none());
    }

    #[test]
    fn disable_leaves_local_pins_in_force() {
        let path = tmp("disable-local");
        let state = PinState::with_policy(local(&[C], &[]));
        state.apply_signed(&signed(&[A], &[], false), &path);
        state.apply_signed(&signed(&[], &[], true), &path);
        assert_eq!(decide(&state.policy(), &chain(&[C])), PinDecision::Match);
    }

    #[test]
    fn rotation_replaces_the_signed_set_and_rearms_the_notice() {
        let path = tmp("rotate");
        let state = PinState::with_policy(PinPolicy::default());
        state.apply_signed(&signed(&[A], &[], false), &path);
        state.apply_signed(&signed(&[B], &[], false), &path);
        assert_eq!(decide(&state.policy(), &chain(&[A])), PinDecision::Mismatch);
        assert_eq!(decide(&state.policy(), &chain(&[B])), PinDecision::Match);
        state.apply_signed(&SignedPins::default(), &path);
        assert!(state.take_pins_removed(&path).is_some());
        state.apply_signed(&signed(&[B], &[], false), &path);
        state.apply_signed(&SignedPins::default(), &path);
        assert!(
            state.take_pins_removed(&path).is_some(),
            "a new removal after re-delivery is reported again"
        );
    }

    #[test]
    fn unreadable_high_water_file_reports_removal_without_bricking_the_agent() {
        let path = tmp("corrupt");
        std::fs::write(&path, b"{not json").unwrap();
        let state = PinState::with_policy(PinPolicy::default());
        state.apply_signed(&SignedPins::default(), &path);
        assert_eq!(
            decide(&state.policy(), &chain(&[A])),
            PinDecision::ReportOnly
        );
        assert_eq!(
            state.take_pins_removed(&path),
            Some(RemovalNotice { enforced_pins: 0 })
        );
        // A file with an invalid pin is just as untrusted.
        std::fs::write(&path, br#"{"pins":["nope"]}"#).unwrap();
        assert_eq!(load_high_water(&path), HighWaterState::Unreadable);
        // A valid signed set repairs it.
        state.apply_signed(&signed(&[A], &[], false), &path);
        assert!(matches!(load_high_water(&path), HighWaterState::Known(_)));
    }

    #[test]
    fn identical_signed_set_does_not_rewrite_the_file_or_reset_the_report() {
        let path = tmp("idempotent");
        let state = PinState::with_policy(PinPolicy::default());
        state.apply_signed(&signed(&[A], &[], false), &path);
        state.apply_signed(&SignedPins::default(), &path);
        assert!(state.take_pins_removed(&path).is_some());
        let r = resolve(
            &PinPolicy::default(),
            &signed(&[A], &[], false),
            &load_high_water(&path),
        );
        assert!(
            matches!(r.store, StoreAction::Write(_)),
            "reported flag is reset by a fresh delivery"
        );
        let again = resolve(
            &PinPolicy::default(),
            &signed(&[A], &[], false),
            &HighWaterState::Known(HighWater {
                pins: vec![A.into()],
                inspection: vec![],
                removal_reported: false,
            }),
        );
        assert_eq!(again.store, StoreAction::Keep);
    }
}
