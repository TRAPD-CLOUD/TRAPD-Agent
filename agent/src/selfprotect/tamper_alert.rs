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
//! ([`handoff_pending`]); until then the heartbeat gap is the signal.
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
use uuid::Uuid;

use super::binary_integrity::IntegrityViolation;
use crate::pipeline::Spool;

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
    /// Id of the alert event, kept across retries so the backend can dedupe on
    /// it (delivery is at-least-once). Nil only in state files written before
    /// this field existed; `read_state` replaces and persists it.
    #[serde(default)]
    pub event_id: Uuid,
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
    // A malformed `event_id` fails the parse like any other bad field.
    let mut state: AlertState = serde_json::from_slice(&std::fs::read(path).ok()?).ok()?;
    if !valid_hash(&state.hash) {
        return None;
    }
    if state.event_id.is_nil() {
        // Legacy record: assign the id once and persist it so every retry and
        // the healthy-start delivery share it.
        state.event_id = Uuid::new_v4();
        write_state(dir, &state);
    }
    Some(state)
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
    let (detected_at, event_id) = match existing {
        Some(s) if s.hash == hash && s.delivered_at.is_none() && !s.event_id.is_nil() => {
            (s.detected_at, s.event_id)
        }
        Some(s) if s.hash == hash && s.delivered_at.is_none() => (s.detected_at, Uuid::new_v4()),
        _ => (now, Uuid::new_v4()),
    };
    AlertState {
        hash: hash.to_string(),
        detected_at,
        failures,
        delivered_at: None,
        event_id,
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
    event.event_id = state.event_id;
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
    let creds = crate::enrollment::load_persisted().await;
    let hostname = hostname::get()
        .map(|h| h.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "unknown".into());
    let agent_id = creds.as_ref().map_or("unenrolled", |c| c.agent_id.as_str());
    let events = [event(&state, agent_id, &hostname)];
    // This event bypasses the consumer, where every other selfprotect event
    // reaches the local security log; write it here, before any network, so
    // the host's own log shows the refused start even when nothing is sent.
    crate::selfprotect::local_log::record(&events[0]);
    if offline() {
        return;
    }
    let Some(creds) = creds else {
        return;
    };
    let backend = std::env::var("TRAPD_BACKEND_URL").unwrap_or_default();
    let sent = tokio::time::timeout(SEND_TIMEOUT, async {
        let bearer = crate::identity::SessionTokens::for_cli(&backend, &creds)
            .current()
            .await;
        crate::transport::send_once(&backend, &bearer, &events, SEND_TIMEOUT).await
    })
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

/// On a healthy start: move a never-delivered alert into the spool and only
/// then drop the pending record.
///
/// The record is the only persisted copy until the spool holds the event, so it
/// is removed only after the push succeeded *and* the journal was synced. A
/// crash in between at worst re-sends the same event (same `event_id`, the
/// backend dedupes on it), never loses it. An in-memory or degraded spool is
/// not a durable handoff: the record stays and is retried on the next start.
/// A record that was already delivered is just cleaned up.
pub fn handoff_pending(dir: &Path, agent_id: &str, hostname: &str, spool: &mut Spool) {
    let Some(state) = read_state(dir) else {
        return;
    };
    if state.delivered_at.is_none() {
        if spool.push(event(&state, agent_id, hostname)).is_err() {
            return;
        }
        spool.checkpoint();
        if !spool.is_durable() {
            return;
        }
    }
    let _ = std::fs::remove_file(dir.join(STATE_FILE));
}

/// Offline counterpart of [`handoff_pending`]. An offline start has only an
/// in-memory spool that nothing drains, so the local output is the sole
/// system of record: write the alert there (like the stop announcer does) and
/// drop the pending record only once that write succeeded.
///
/// The alert is written directly, never through the consumer's policy path, so
/// a signed suppression or shadow rule cannot hide it. With `OutputMode::Off`
/// nothing can be written, so the record stays for a later online start.
pub async fn handoff_pending_offline(
    dir: &Path,
    agent_id: &str,
    hostname: &str,
    mode: &crate::output::OutputMode,
) {
    handoff_pending_offline_with(dir, agent_id, hostname, |event| async move {
        !matches!(mode, crate::output::OutputMode::Off)
            && crate::output::write_events(std::slice::from_ref(&event), mode)
                .await
                .is_ok()
    })
    .await;
}

async fn handoff_pending_offline_with<W, Fut>(
    dir: &Path,
    agent_id: &str,
    hostname: &str,
    write_local: W,
) where
    W: FnOnce(AgentEvent) -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let Some(state) = read_state(dir) else {
        return;
    };
    if state.delivered_at.is_none() && !write_local(event(&state, agent_id, hostname)).await {
        tracing::warn!("pending tamper alert could not be written to the local output");
        return;
    }
    let _ = std::fs::remove_file(dir.join(STATE_FILE));
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
            event_id: Uuid::new_v4(),
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
            event_id: Uuid::new_v4(),
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
    fn pending_file_round_trips() {
        let dir = tmp("pending");
        let s = next_state(None, H1, 1, t("2026-11-15T10:00:00Z"));
        write_state(&dir, &s);
        assert_eq!(read_state(&dir), Some(s));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn pending_alert_is_removed_only_after_a_durable_spool_push() {
        let dir = tmp("handoff");
        let s = next_state(None, H1, 1, t("2026-11-15T10:00:00Z"));
        write_state(&dir, &s);
        // Non-durable spool: the record must survive for the next start.
        let mut mem = Spool::in_memory(10);
        handoff_pending(&dir, "a", "h", &mut mem);
        assert_eq!(read_state(&dir), Some(s.clone()));
        // Rejected push (zero capacity): still kept.
        let mut full = Spool::in_memory(0);
        handoff_pending(&dir, "a", "h", &mut full);
        assert_eq!(read_state(&dir), Some(s.clone()));
        // Durable spool: event is queued with the persisted id, record gone.
        let journal = dir.join("queue.journal");
        let mut spool = Spool::durable_at(journal.clone(), 10);
        handoff_pending(&dir, "a", "h", &mut spool);
        assert!(read_state(&dir).is_none());
        assert_eq!(spool.len(), 1);
        drop(spool);
        // A crash right after the push loses nothing: reopen finds the event.
        let reopened = Spool::durable_at(journal, 10);
        assert_eq!(reopened.peek_batch(1)[0].event.event_id, s.event_id);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn offline_pending_alert_reaches_local_output_then_the_record_is_removed() {
        let dir = tmp("offline");
        let s = next_state(None, H1, 1, t("2026-11-15T10:00:00Z"));
        write_state(&dir, &s);
        let written = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        // A failing local write keeps the record for the next start.
        handoff_pending_offline_with(&dir, "a", "h", |_| async { false }).await;
        assert_eq!(read_state(&dir), Some(s.clone()));
        let sink = std::sync::Arc::clone(&written);
        handoff_pending_offline_with(&dir, "a", "h", move |e| async move {
            sink.lock().unwrap().push(e);
            true
        })
        .await;
        let written = written.lock().unwrap();
        assert_eq!(written.len(), 1);
        assert_eq!(written[0].event_id, s.event_id);
        assert!(read_state(&dir).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn offline_without_a_local_output_keeps_the_record() {
        let dir = tmp("offline_off");
        let s = next_state(None, H1, 1, t("2026-11-15T10:00:00Z"));
        write_state(&dir, &s);
        handoff_pending_offline(&dir, "a", "h", &crate::output::OutputMode::Off).await;
        assert_eq!(read_state(&dir), Some(s));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn crash_before_removal_resends_the_same_event_id() {
        let dir = tmp("resend");
        let s = next_state(None, H1, 1, t("2026-11-15T10:00:00Z"));
        write_state(&dir, &s);
        let mut first = Spool::durable_at(dir.join("q.journal"), 10);
        handoff_pending(&dir, "a", "h", &mut first);
        // Simulate the crash window: the record reappears after the push.
        write_state(&dir, &s);
        handoff_pending(&dir, "a", "h", &mut first);
        let ids: Vec<_> = first
            .peek_batch(10)
            .iter()
            .map(|e| e.event.event_id)
            .collect();
        assert_eq!(ids, vec![s.event_id, s.event_id]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn retries_and_the_healthy_start_reuse_the_event_id() {
        let first = t("2026-11-15T10:00:00Z");
        let pending = next_state(None, H1, 1, first);
        let again = next_state(Some(&pending), H1, 2, first + chrono::Duration::minutes(5));
        assert_eq!(again.event_id, pending.event_id);
        assert_eq!(
            event(&again, "a", "h").event_id,
            event(&pending, "a", "h").event_id
        );
        // A new hash or an already delivered alert is a new alert.
        assert_ne!(
            next_state(Some(&pending), H2, 1, first).event_id,
            pending.event_id
        );
        let mut delivered = pending.clone();
        delivered.delivered_at = Some(first);
        assert_ne!(
            next_state(Some(&delivered), H1, 1, first).event_id,
            pending.event_id
        );
        // Persisted and read back for the next process.
        let dir = tmp("eventid");
        write_state(&dir, &pending);
        assert_eq!(read_state(&dir).unwrap().event_id, pending.event_id);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn legacy_state_without_an_event_id_gets_one_and_keeps_it() {
        let dir = tmp("legacy");
        let legacy = format!(
            r#"{{"hash":"{H1}","detected_at":"2026-11-15T10:00:00Z","failures":2,"delivered_at":null}}"#
        );
        std::fs::write(dir.join(STATE_FILE), legacy).unwrap();
        let first = read_state(&dir).unwrap();
        assert!(!first.event_id.is_nil());
        // Persisted: a second read, a retry and the event all agree.
        assert_eq!(read_state(&dir).unwrap().event_id, first.event_id);
        let retry = next_state(Some(&first), H1, 3, first.detected_at);
        assert_eq!(retry.event_id, first.event_id);
        assert_eq!(event(&retry, "a", "h").event_id, first.event_id);
        // A malformed id invalidates the record.
        let bad = format!(
            r#"{{"hash":"{H1}","detected_at":"2026-11-15T10:00:00Z","failures":2,"delivered_at":null,"event_id":"x"}}"#
        );
        std::fs::write(dir.join(STATE_FILE), bad).unwrap();
        assert!(read_state(&dir).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn delivered_record_is_cleared_but_not_resent() {
        let dir = tmp("delivered");
        let mut s = next_state(None, H1, 1, t("2026-11-15T10:00:00Z"));
        s.delivered_at = Some(s.detected_at);
        write_state(&dir, &s);
        let mut spool = Spool::durable_at(dir.join("q.journal"), 10);
        handoff_pending(&dir, "a", "h", &mut spool);
        assert_eq!(spool.len(), 0);
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
