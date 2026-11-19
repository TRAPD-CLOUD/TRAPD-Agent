//! "Authorized stop" marker (phase 08, WP1/WP4 follow-up).
//!
//! A planned stop (MSI upgrade or uninstall, signed self-update restart,
//! maintenance stop) must not look like `selfprotect.service_stop_requested`.
//! The component that is about to stop the service first drops a short-lived
//! marker into `<state>/maintenance/`; the agent consumes it when the stop
//! arrives and reports the informational `selfprotect.service_stop_authorized`
//! instead of the high finding.
//!
//! Limits (stated, not hidden):
//!   * The marker is a plain file. Whoever can write the state directory can
//!     forge one. The directory ACL (SYSTEM + Administrators on Windows today,
//!     root `0700` on Linux) is the only local barrier, so the agent's claim is
//!     never authoritative: `uninstall` / `maintenance` markers must carry the
//!     maintenance token nonce so the backend can match it against its own
//!     consumed-token record, and `upgrade` / `self_update` markers carry the
//!     versions so the backend can match the following version change.
//!   * Single use, <= 5 minutes, strict validation. Anything malformed,
//!     expired or inconsistent is removed and treated as no marker (the stop is
//!     then reported as unauthorized: a false alert is recoverable).

use std::io;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

const FILE_NAME: &str = "authorized_stop.json";
/// A marker is a few hundred bytes; refuse anything larger.
const MAX_MARKER_BYTES: u64 = 2048;
/// Longest accepted lifetime of a marker.
pub const MAX_TTL_SECS: i64 = 300;
/// Tolerated clock difference for a marker that appears to be from the future.
const CLOCK_SKEW_SECS: i64 = 60;
const MAX_VERSION_LEN: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Reason {
    Upgrade,
    SelfUpdate,
    Maintenance,
    Uninstall,
}

impl Reason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Upgrade => "upgrade",
            Self::SelfUpdate => "self_update",
            Self::Maintenance => "maintenance",
            Self::Uninstall => "uninstall",
        }
    }

    /// Reasons backed by a maintenance token must name its nonce.
    fn requires_nonce(self) -> bool {
        matches!(self, Self::Maintenance | Self::Uninstall)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StopMarker {
    pub v: u32,
    pub reason: Reason,
    /// Nonce of the consumed maintenance token (32 lowercase hex), if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_nonce: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to_version: Option<String>,
    /// `upgrade` only: ProductCode (`{GUID}`) of the MSI that is performing the
    /// major upgrade. The old product's uninstall gate accepts an upgrade only
    /// if `UPGRADINGPRODUCTCODE` equals this value (see `upgrade_authorizes`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upgrade_product: Option<String>,
    pub issued_at: i64,
    pub expires_at: i64,
}

impl StopMarker {
    pub fn new(
        reason: Reason,
        token_nonce: Option<String>,
        from_version: Option<String>,
        to_version: Option<String>,
        now: i64,
    ) -> Self {
        Self {
            v: 1,
            reason,
            token_nonce,
            from_version,
            to_version,
            upgrade_product: None,
            issued_at: now,
            expires_at: now + MAX_TTL_SECS,
        }
    }
}

impl StopMarker {
    /// An `upgrade` marker bound to the ProductCode of the upgrading MSI.
    pub fn for_upgrade(product_code: &str, from_version: &str, now: i64) -> Option<Self> {
        let mut marker = Self::new(
            Reason::Upgrade,
            None,
            Some(from_version.to_owned()),
            None,
            now,
        );
        marker.upgrade_product = Some(product_code.to_owned());
        validate(&marker, now).ok().map(|()| marker)
    }

    /// The in-memory authorization of a stop the SYSTEM service ordered itself
    /// after claiming a maintenance token (Windows). Never written to disk; the
    /// backend still matches `token_nonce` against its consumed-token record.
    /// `None` if the nonce is not a well-formed token nonce.
    #[cfg(any(windows, test))]
    pub fn for_claimed_token(nonce: &str, now: i64) -> Option<Self> {
        let marker = Self::new(
            Reason::Maintenance,
            Some(nonce.to_owned()),
            Some(env!("CARGO_PKG_VERSION").to_owned()),
            None,
            now,
        );
        validate(&marker, now).ok().map(|()| marker)
    }
}

fn is_nonce(s: &str) -> bool {
    s.len() == 32 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn is_version(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_VERSION_LEN
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'+'))
}

/// `{8-4-4-4-12}` hex GUID, the form MSI formats `[ProductCode]` in.
pub fn is_product_code(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 38
        && b[0] == b'{'
        && b[37] == b'}'
        && b[1..37].iter().enumerate().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => *c == b'-',
            _ => c.is_ascii_hexdigit(),
        })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Invalid {
    Version,
    Lifetime,
    Expired,
    NotYetValid,
    Nonce,
    FieldFormat,
    Product,
}

/// Pure validation of a parsed marker at `now`.
pub fn validate(m: &StopMarker, now: i64) -> std::result::Result<(), Invalid> {
    if m.v != 1 {
        return Err(Invalid::Version);
    }
    let ttl = m.expires_at.saturating_sub(m.issued_at);
    if ttl <= 0 || ttl > MAX_TTL_SECS {
        return Err(Invalid::Lifetime);
    }
    if now > m.expires_at {
        return Err(Invalid::Expired);
    }
    if m.issued_at > now.saturating_add(CLOCK_SKEW_SECS) {
        return Err(Invalid::NotYetValid);
    }
    match &m.token_nonce {
        Some(n) if !is_nonce(n) => return Err(Invalid::Nonce),
        None if m.reason.requires_nonce() => return Err(Invalid::Nonce),
        _ => {}
    }
    for v in [&m.from_version, &m.to_version].into_iter().flatten() {
        if !is_version(v) {
            return Err(Invalid::FieldFormat);
        }
    }
    match (&m.upgrade_product, m.reason) {
        (Some(p), Reason::Upgrade) if is_product_code(p) => {}
        (None, _) => {}
        _ => return Err(Invalid::Product),
    }
    Ok(())
}

/// Whether the old product's MSI uninstall may skip the token because a real
/// major upgrade is under way: a fresh, valid `upgrade` marker (written by the
/// new package, as SYSTEM, before the old product is removed) naming exactly the
/// product that Windows Installer reports as `UPGRADINGPRODUCTCODE`. The bare
/// property is attacker-controllable (`msiexec /x ... UPGRADINGPRODUCTCODE=1`)
/// and never suffices. Does not consume the marker: the service stop that
/// follows still needs it.
///
/// Limit: the marker is a file, so someone who can already write the state
/// directory as SYSTEM/Administrator can forge it. That is tamper-detected via
/// the backend's version-change match, not prevented.
pub fn upgrade_authorizes(state_dir: &Path, upgrading_product: &str, now: i64) -> bool {
    if !is_product_code(upgrading_product) {
        return false;
    }
    let Ok(bytes) = crate::paths::bounded_regular_bytes(&marker_path(state_dir), MAX_MARKER_BYTES)
    else {
        return false;
    };
    let Ok(m) = serde_json::from_slice::<StopMarker>(&bytes) else {
        return false;
    };
    validate(&m, now).is_ok()
        && m.reason == Reason::Upgrade
        && m.upgrade_product
            .as_deref()
            .is_some_and(|p| p.eq_ignore_ascii_case(upgrading_product))
}

pub fn marker_path(state_dir: &Path) -> PathBuf {
    state_dir.join("maintenance").join(FILE_NAME)
}

/// Write (replace) the marker. Called by the authorised component right before
/// it stops the service. Atomic; the file is `0600` where modes exist.
pub fn write(state_dir: &Path, marker: &StopMarker) -> Result<()> {
    if let Err(e) = validate(marker, marker.issued_at) {
        bail!("refusing to write an invalid stop marker: {e:?}");
    }
    let bytes = serde_json::to_vec(marker).context("encode stop marker")?;
    crate::paths::write_atomic(&marker_path(state_dir), &bytes, 0o600).context("write stop marker")
}

/// Remove the marker (rollback of a planned stop that did not happen).
pub fn clear(state_dir: &Path) {
    let _ = std::fs::remove_file(marker_path(state_dir));
}

/// Read the marker without consuming it (the guard looks at it to learn that a
/// planned stop is under way; only the agent's own stop announcer consumes it).
/// Returns `None` for a missing, unusable or invalid marker and never removes
/// anything.
pub fn peek(state_dir: &Path, now: i64) -> Option<StopMarker> {
    let bytes =
        crate::paths::bounded_regular_bytes(&marker_path(state_dir), MAX_MARKER_BYTES).ok()?;
    serde_json::from_slice::<StopMarker>(&bytes)
        .ok()
        .filter(|m| validate(m, now).is_ok())
}

/// Take the marker for the stop that is happening now. Single use: the file
/// must be removed successfully for the marker to count, so two consumers (or a
/// replay) cannot both succeed. Returns `None` when there is no usable marker;
/// an unusable one is removed.
pub fn consume(state_dir: &Path, now: i64) -> Option<StopMarker> {
    let path = marker_path(state_dir);
    let bytes = match crate::paths::bounded_regular_bytes(&path, MAX_MARKER_BYTES) {
        Ok(b) => b,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return None,
        Err(_) => {
            // A link, a device or an oversized file in this place is not ours.
            let _ = std::fs::remove_file(&path);
            return None;
        }
    };
    let parsed = serde_json::from_slice::<StopMarker>(&bytes).ok();
    let valid = parsed.filter(|m| validate(m, now).is_ok());
    // Remove first: only the process that deletes it may use it.
    if std::fs::remove_file(&path).is_err() {
        return None;
    }
    valid
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_800_000_000;
    const NONCE: &str = "0123456789abcdef0123456789abcdef";

    struct TempDir(PathBuf);
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn tmp() -> TempDir {
        let p = std::env::temp_dir().join(format!("trapd-stopmarker-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&p).unwrap();
        TempDir(p)
    }

    fn upgrade() -> StopMarker {
        StopMarker::new(Reason::Upgrade, None, Some("0.7.9".into()), None, NOW)
    }
    fn uninstall() -> StopMarker {
        StopMarker::new(Reason::Uninstall, Some(NONCE.into()), None, None, NOW)
    }

    #[test]
    fn create_then_consume_returns_the_marker_once() {
        let d = tmp();
        write(&d.0, &uninstall()).unwrap();
        let got = consume(&d.0, NOW + 10).expect("marker");
        assert_eq!(got.reason, Reason::Uninstall);
        assert_eq!(got.token_nonce.as_deref(), Some(NONCE));
        assert!(consume(&d.0, NOW + 11).is_none(), "single use");
        assert!(!marker_path(&d.0).exists());
    }

    #[test]
    fn peek_reads_a_valid_marker_without_consuming_it() {
        let d = tmp();
        write(&d.0, &uninstall()).unwrap();
        assert_eq!(peek(&d.0, NOW + 1), Some(uninstall()));
        assert_eq!(peek(&d.0, NOW + 1), Some(uninstall()));
        assert!(marker_path(&d.0).exists());
        // Expired: not returned, and still not removed by a peek.
        assert_eq!(peek(&d.0, NOW + MAX_TTL_SECS + 1), None);
        assert!(marker_path(&d.0).exists());
    }

    #[test]
    fn no_marker_means_none() {
        assert!(consume(&tmp().0, NOW).is_none());
    }

    #[test]
    fn expired_marker_is_refused_and_removed() {
        let d = tmp();
        write(&d.0, &upgrade()).unwrap();
        assert!(consume(&d.0, NOW + MAX_TTL_SECS + 1).is_none());
        assert!(!marker_path(&d.0).exists());
    }

    #[test]
    fn marker_is_valid_up_to_its_expiry() {
        let d = tmp();
        write(&d.0, &upgrade()).unwrap();
        assert!(consume(&d.0, NOW + MAX_TTL_SECS).is_some());
    }

    #[test]
    fn lifetime_above_five_minutes_is_refused() {
        let mut m = upgrade();
        m.expires_at = NOW + MAX_TTL_SECS + 1;
        assert_eq!(validate(&m, NOW), Err(Invalid::Lifetime));
        m.expires_at = NOW;
        assert_eq!(validate(&m, NOW), Err(Invalid::Lifetime));
        let d = tmp();
        assert!(write(&d.0, &m).is_err());
    }

    #[test]
    fn marker_from_the_future_is_refused() {
        let m = StopMarker::new(Reason::Upgrade, None, None, None, NOW + 3600);
        assert_eq!(validate(&m, NOW), Err(Invalid::NotYetValid));
    }

    #[test]
    fn token_backed_reasons_need_a_nonce() {
        for reason in [Reason::Uninstall, Reason::Maintenance] {
            let m = StopMarker::new(reason, None, None, None, NOW);
            assert_eq!(validate(&m, NOW), Err(Invalid::Nonce));
        }
        let m = StopMarker::new(Reason::Uninstall, Some("NOT-HEX".into()), None, None, NOW);
        assert_eq!(validate(&m, NOW), Err(Invalid::Nonce));
        for reason in [Reason::Upgrade, Reason::SelfUpdate] {
            assert!(validate(&StopMarker::new(reason, None, None, None, NOW), NOW).is_ok());
        }
    }

    #[test]
    fn hostile_version_strings_are_refused() {
        let m = StopMarker::new(Reason::Upgrade, None, Some("1.0\"}{".into()), None, NOW);
        assert_eq!(validate(&m, NOW), Err(Invalid::FieldFormat));
        let long = "9".repeat(MAX_VERSION_LEN + 1);
        let m = StopMarker::new(Reason::Upgrade, None, None, Some(long), NOW);
        assert_eq!(validate(&m, NOW), Err(Invalid::FieldFormat));
    }

    #[test]
    fn garbage_and_unknown_fields_are_removed_and_ignored() {
        let d = tmp();
        let p = marker_path(&d.0);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, b"not json").unwrap();
        assert!(consume(&d.0, NOW).is_none());
        assert!(!p.exists());
        std::fs::write(
            &p,
            format!(
                r#"{{"v":1,"reason":"upgrade","issued_at":{NOW},"expires_at":{},"admin":true}}"#,
                NOW + 10
            ),
        )
        .unwrap();
        assert!(consume(&d.0, NOW).is_none());
        assert!(!p.exists());
    }

    #[test]
    fn oversized_marker_is_ignored() {
        let d = tmp();
        let p = marker_path(&d.0);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, vec![b' '; 4096]).unwrap();
        assert!(consume(&d.0, NOW).is_none());
        assert!(!p.exists());
    }

    const NEW_PRODUCT: &str = "{0D18AC24-8CE9-4513-A1E5-889FD2A01D94}";

    #[test]
    fn product_code_format_is_strict() {
        assert!(is_product_code(NEW_PRODUCT));
        assert!(is_product_code(&NEW_PRODUCT.to_lowercase()));
        for bad in [
            "",
            "1",
            "{}",
            "0D18AC24-8CE9-4513-A1E5-889FD2A01D94",
            "{0D18AC24-8CE9-4513-A1E5-889FD2A01D9G}",
            "{0D18AC24-8CE9-4513-A1E5-889FD2A01D94}x",
        ] {
            assert!(!is_product_code(bad), "{bad}");
        }
    }

    #[test]
    fn upgrade_authorizes_only_with_a_fresh_marker_for_that_product() {
        let d = tmp();
        let m = StopMarker::for_upgrade(NEW_PRODUCT, "0.7.9", NOW).unwrap();
        // No marker: the bare property is worthless.
        assert!(!upgrade_authorizes(&d.0, NEW_PRODUCT, NOW));
        write(&d.0, &m).unwrap();
        assert!(upgrade_authorizes(&d.0, NEW_PRODUCT, NOW + 5));
        assert!(upgrade_authorizes(
            &d.0,
            &NEW_PRODUCT.to_lowercase(),
            NOW + 5
        ));
        // Not consumed (the service stop still needs it).
        assert!(marker_path(&d.0).exists());
        // Wrong, junk or empty property value.
        for bad in ["1", "", "{00000000-0000-0000-0000-000000000000}"] {
            assert!(!upgrade_authorizes(&d.0, bad, NOW + 5), "{bad:?}");
        }
        // Expired.
        assert!(!upgrade_authorizes(
            &d.0,
            NEW_PRODUCT,
            NOW + MAX_TTL_SECS + 1
        ));
    }

    #[test]
    fn other_marker_kinds_never_authorize_an_upgrade_removal() {
        let d = tmp();
        write(&d.0, &uninstall()).unwrap();
        assert!(!upgrade_authorizes(&d.0, NEW_PRODUCT, NOW));
        // A product-less upgrade marker (no binding) does not authorize either.
        write(&d.0, &upgrade()).unwrap();
        assert!(!upgrade_authorizes(&d.0, NEW_PRODUCT, NOW));
    }

    #[test]
    fn a_product_binding_is_only_valid_on_upgrade_markers() {
        let mut m = uninstall();
        m.upgrade_product = Some(NEW_PRODUCT.into());
        assert_eq!(validate(&m, NOW), Err(Invalid::Product));
        let mut m = upgrade();
        m.upgrade_product = Some("1".into());
        assert_eq!(validate(&m, NOW), Err(Invalid::Product));
        assert!(StopMarker::for_upgrade("1", "0.7.9", NOW).is_none());
    }

    #[test]
    fn clear_removes_the_marker() {
        let d = tmp();
        write(&d.0, &upgrade()).unwrap();
        clear(&d.0);
        assert!(consume(&d.0, NOW).is_none());
    }
}
