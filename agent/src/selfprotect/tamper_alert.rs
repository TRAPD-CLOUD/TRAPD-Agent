//! Best-effort alert for a binary-integrity failure before the agent exits.
//!
//! `binary_integrity::check` fails closed: a modified binary never starts, so
//! without this the sensor is silent and the backend sees only a heartbeat
//! gap. On a failure this module
//!
//! 1. writes a small *pending* record to the private state dir (crash safe,
//!    needs no network),
//! 2. makes one bounded ([`SEND_TIMEOUT`]) attempt to deliver
//!    `selfprotect.binary_tampered` with the persisted credentials, and
//! 3. marks the record delivered on a valid backend receipt.
//!
//! Why a direct one-shot send plus a file, not only a queue: at this point in
//! start-up no pipeline, spool or transport exists, and building them would
//! mean running the rest of the agent from an untrusted binary. The one-shot
//! uses the same pinned-TLS client and bearer credential as the transport. If
//! it fails (backend down, not enrolled, offline mode) the pending record is
//! kept and the next *healthy* start delivers it through the normal pipeline
//! ([`take_pending`]); until then the heartbeat gap is the signal.
//!
//! Rate limit: the existing restart-loop guard already spaces restarts
//! (30 s ... 15 min). On top of that a delivered alert is not repeated for the
//! same binary hash within [`RESEND_AFTER`], while an undelivered one is
//! retried on every guarded restart, each attempt bounded by the same timeout.
//!
//! Trust: the state file sits in the agent's private state dir, so only the
//! agent or an admin can write it. It is still parsed strictly (size cap,
//! hash shape, timestamps) and the detection is rebuilt from those fields; no
//! text from the file reaches the event.

use std::path::Path;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use trapd_schema::{AgentEvent, DetectionData, EventAction, EventClass, EventData, Severity};

use super::binary_integrity::IntegrityViolation;

const STATE_FILE: &str = "integrity_alert.json";
const MAX_STATE_BYTES: u64 = 4096;
/// Wall-clock bound for the whole delivery attempt, client setup included.
pub const SEND_TIMEOUT: Duration = Duration::from_secs(3);
/// A delivered alert for the same hash is not repeated sooner than this.
const RESEND_AFTER: chrono::Duration = chrono::Duration::hours(1);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AlertState {
    /// `sha256:<64 hex>` of the failing executable.
    pub hash: String,
    pub detected_at: DateTime<Utc>,
    pub failures: u32,
    pub delivered_at: Option<DateTime<Utc>>,
}

fn valid_hash(hash: &str) -> bool {
    hash.strip_prefix("sha256:")
        .is_some_and(|h| h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit()))
}

pub fn read_state(dir: &Path) -> Option<AlertState> {
    let path = dir.join(STATE_FILE);
    if std::fs::metadata(&path).ok()?.len() > MAX_STATE_BYTES {
        return None;
    }
    let state: AlertState = serde_json::from_slice(&std::fs::read(path).ok()?).ok()?;
    valid_hash(&state.hash).then_some(state)
}

fn write_state(dir: &Path, state: &AlertState) {
    let Ok(raw) = serde_json::to_vec(state) else {
        return;
    };
    if let Err(e) = crate::paths::write_atomic(&dir.join(STATE_FILE), &raw, 0o600) {
        tracing::warn!(error = %e, "could not persist the pending tamper alert");
    }
}

/// Whether a delivery attempt is due for a failure of `hash` at `now`.
pub fn attempt_due(existing: Option<&AlertState>, hash: &str, now: DateTime<Utc>) -> bool {
    match existing {
        Some(s) if s.hash == hash => match s.delivered_at {
            None => true,
            // A clock moved backwards must not silence the alert forever.
            Some(at) => at > now || now - at >= RESEND_AFTER,
        },
        _ => true,
    }
}

/// The record to persist for this failure, keeping the first detection time of
/// an undelivered alert for the same hash.
pub fn next_state(
    existing: Option<&AlertState>,
    hash: &str,
    failures: u32,
    now: DateTime<Utc>,
) -> AlertState {
    let detected_at = match existing {
        Some(s) if s.hash == hash && s.delivered_at.is_none() => s.detected_at,
        _ => now,
    };
    AlertState {
        hash: hash.to_string(),
        detected_at,
        failures,
        delivered_at: None,
    }
}

fn detection(state: &AlertState) -> DetectionData {
    DetectionData {
        rule_id: "selfprotect.binary_tampered".into(),
        title: "Agent binary failed its integrity check".into(),
        category: "defense_evasion".into(),
        mitre_tactic: Some("TA0005 Defense Evasion".into()),
        mitre_technique: Some("T1554".into()),
        confidence: 90,
        subject: "trapd-agent".into(),
        detail: "The agent executable does not match its recorded digest or signature and \
                 refused to start. Sensors are not running on this host."
            .into(),
        evidence: serde_json::json!({
            "current_sha256": state.hash,
            "consecutive_failures": state.failures,
            "detected_at": state.detected_at.to_rfc3339(),
            "agent_running": false,
        }),
        dedup_key: Some(format!("selfprotect.binary_tampered:{}", state.hash)),
        first_seen: Some(state.detected_at),
        last_seen: Some(state.detected_at),
        ..Default::default()
    }
}

pub fn event(state: &AlertState, agent_id: &str, hostname: &str) -> AgentEvent {
    let mut event = AgentEvent::new(
        agent_id.into(),
        hostname.into(),
        EventClass::Detection,
        EventAction::Detected,
        Severity::High,
        EventData::Detection(Box::new(detection(state))),
    );
    event.timestamp = state.detected_at;
    event
}

fn offline() -> bool {
    let truthy = |k: &str| {
        std::env::var(k).is_ok_and(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
    };
    truthy("TRAPD_OFFLINE")
        || std::env::var("TRAPD_BACKEND_URL").map_or(true, |u| u.trim().is_empty())
}

/// Call on the integrity-failure path before holding/exiting. Does nothing for
/// errors that are not an [`IntegrityViolation`]. Never fails and never takes
/// longer than about [`SEND_TIMEOUT`].
pub async fn report(err: &anyhow::Error) {
    let Some(v) = err.downcast_ref::<IntegrityViolation>() else {
        return;
    };
    let dir = crate::paths::state_dir();
    let now = Utc::now();
    let existing = read_state(dir);
    if !attempt_due(existing.as_ref(), &v.hash, now) {
        return;
    }
    let mut state = next_state(existing.as_ref(), &v.hash, v.failures, now);
    // Persist first: if the send is cut off or the host dies, the next healthy
    // start still reports it.
    write_state(dir, &state);
    if offline() {
        return;
    }
    let Some(creds) = crate::enrollment::load_persisted().await else {
        return;
    };
    let hostname = hostname::get()
        .map(|h| h.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "unknown".into());
    let events = [event(&state, &creds.agent_id, &hostname)];
    let backend = std::env::var("TRAPD_BACKEND_URL").unwrap_or_default();
    let sent = tokio::time::timeout(
        SEND_TIMEOUT,
        crate::transport::send_once(&backend, &creds.agent_secret, &events, SEND_TIMEOUT),
    )
    .await;
    match sent {
        Ok(Ok(())) => {
            state.delivered_at = Some(Utc::now());
            write_state(dir, &state);
            tracing::warn!("reported the binary integrity failure to the backend");
        }
        Ok(Err(e)) => tracing::warn!(error = %e, "could not report the binary integrity failure"),
        Err(_) => tracing::warn!("reporting the binary integrity failure timed out"),
    }
}

/// On a healthy start: remove the record and return it when it was never
/// delivered, so the caller can send it through the normal pipeline.
pub fn take_pending(dir: &Path) -> Option<AlertState> {
    let state = read_state(dir);
    let _ = std::fs::remove_file(dir.join(STATE_FILE));
    state.filter(|s| s.delivered_at.is_none())
}

#[cfg(test)]
mod tests {
    use super::*;

    const H1: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000001";
    const H2: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000002";

    fn t(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
    }

    fn tmp(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("trapd_tamper_{tag}_{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn first_failure_and_new_hash_are_due() {
        let now = t("2026-11-15T10:00:00Z");
        assert!(attempt_due(None, H1, now));
        let s = AlertState {
            hash: H1.into(),
            detected_at: now,
            failures: 1,
            delivered_at: Some(now),
        };
        assert!(attempt_due(Some(&s), H2, now));
    }

    #[test]
    fn delivered_alert_is_rate_limited_per_hash() {
        let at = t("2026-11-15T10:00:00Z");
        let s = AlertState {
            hash: H1.into(),
            detected_at: at,
            failures: 3,
            delivered_at: Some(at),
        };
        assert!(!attempt_due(
            Some(&s),
            H1,
            at + chrono::Duration::minutes(15)
        ));
        assert!(attempt_due(
            Some(&s),
            H1,
            at + chrono::Duration::minutes(61)
        ));
        // Clock moved back: do not stay silent.
        assert!(attempt_due(Some(&s), H1, at - chrono::Duration::minutes(5)));
    }

    #[test]
    fn undelivered_alert_is_retried_and_keeps_its_first_time() {
        let first = t("2026-11-15T10:00:00Z");
        let pending = next_state(None, H1, 1, first);
        let later = first + chrono::Duration::minutes(5);
        assert!(attempt_due(Some(&pending), H1, later));
        let again = next_state(Some(&pending), H1, 2, later);
        assert_eq!(again.detected_at, first);
        assert_eq!(again.failures, 2);
        // A different hash starts a new record.
        assert_eq!(next_state(Some(&pending), H2, 1, later).detected_at, later);
    }

    #[test]
    fn event_is_high_severity_and_carries_only_validated_fields() {
        let s = next_state(None, H1, 4, t("2026-11-15T10:00:00Z"));
        let e = event(&s, "agent-1", "host");
        assert_eq!(e.severity, Severity::High);
        assert_eq!(e.timestamp, s.detected_at);
        let EventData::Detection(d) = &e.data else {
            panic!("not a detection")
        };
        assert_eq!(d.rule_id, "selfprotect.binary_tampered");
        assert_eq!(d.evidence["current_sha256"], H1);
        assert_eq!(d.evidence["consecutive_failures"], 4);
    }

    #[test]
    fn pending_file_round_trips_and_is_taken_once() {
        let dir = tmp("pending");
        let s = next_state(None, H1, 1, t("2026-11-15T10:00:00Z"));
        write_state(&dir, &s);
        assert_eq!(read_state(&dir), Some(s.clone()));
        assert_eq!(take_pending(&dir), Some(s));
        assert!(take_pending(&dir).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn delivered_record_is_cleared_but_not_resent() {
        let dir = tmp("delivered");
        let mut s = next_state(None, H1, 1, t("2026-11-15T10:00:00Z"));
        s.delivered_at = Some(s.detected_at);
        write_state(&dir, &s);
        assert!(take_pending(&dir).is_none());
        assert!(read_state(&dir).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn forged_or_oversized_state_is_rejected() {
        let dir = tmp("forged");
        let bad = r#"{"hash":"sha256:<script>","detected_at":"2026-11-15T10:00:00Z","failures":1,"delivered_at":null}"#;
        std::fs::write(dir.join(STATE_FILE), bad).unwrap();
        assert!(read_state(&dir).is_none());
        std::fs::write(dir.join(STATE_FILE), vec![b' '; 8192]).unwrap();
        assert!(read_state(&dir).is_none());
        std::fs::write(dir.join(STATE_FILE), b"nope").unwrap();
        assert!(read_state(&dir).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
