//! Liveness echo: proof that the *event pipeline* is alive, not only the
//! heartbeat thread.
//!
//! The heartbeat response may carry a random `liveness_nonce`. The agent
//! answers it with an `agent.liveness_echo` detection event that travels
//! through the normal telemetry pipeline (channel -> spool -> transport), not
//! through the heartbeat. The backend clears the challenge when the event
//! arrives; a host whose heartbeats are forged, or whose pipeline is suspended,
//! never echoes and is reported (`agent.liveness_echo_missing`).
//!
//! Trust: the nonce is backend-provided and untrusted input. It is accepted
//! only in a strict shape (bounded length, URL-safe alphabet), echoed back
//! verbatim and never interpreted. The backend repeats an unanswered challenge on
//! every beat. Handing an echo to the channel is not delivery: the spool may evict it during an
//! outage. So a repeated challenge is answered again, but bounded: not before
//! [`RESEND_AFTER`] has passed and at most [`MAX_RESENDS`] extra times per nonce.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::Deserialize;
use tokio::sync::mpsc::WeakSender;
use trapd_schema::{AgentEvent, DetectionData, EventAction, EventClass, EventData, Severity};

pub const RULE_ID: &str = "agent.liveness_echo";
/// Upper bound for a heartbeat response body that is even looked at.
pub const MAX_RESPONSE_BYTES: usize = 4096;

/// A repeated challenge is answered again only after this long...
const RESEND_AFTER: Duration = Duration::from_secs(120);
/// ...and at most this many extra times.
const MAX_RESENDS: u32 = 3;

const MIN_NONCE_LEN: usize = 16;
const MAX_NONCE_LEN: usize = 128;

#[derive(Deserialize)]
struct Response {
    liveness_nonce: Option<String>,
}

/// The challenge in a heartbeat response body, if it is well formed.
pub fn parse_nonce(body: &[u8]) -> Option<String> {
    if body.len() > MAX_RESPONSE_BYTES {
        return None;
    }
    let nonce = serde_json::from_slice::<Response>(body)
        .ok()?
        .liveness_nonce?;
    let shaped = (MIN_NONCE_LEN..=MAX_NONCE_LEN).contains(&nonce.len())
        && nonce
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    shaped.then_some(nonce)
}

/// The echo event for a nonce. Info severity: it is plumbing, not a finding
/// (the backend consumes it and never promotes it to a signal).
pub fn echo_event(agent_id: &str, hostname: &str, nonce: &str) -> AgentEvent {
    AgentEvent::new(
        agent_id.to_string(),
        hostname.to_string(),
        EventClass::Detection,
        EventAction::Detected,
        Severity::Info,
        EventData::Detection(Box::new(DetectionData {
            rule_id: RULE_ID.into(),
            title: "Agent liveness echo".into(),
            category: "agent_health".into(),
            confidence: 100,
            subject: "trapd-agent".into(),
            detail: "Answer to a backend liveness challenge".into(),
            evidence: serde_json::json!({ "nonce": nonce }),
            ..Default::default()
        })),
    )
}

/// Answers heartbeat challenges through the event pipeline.
pub struct LivenessEcho {
    agent_id: String,
    hostname: String,
    /// Weak, so the echo never keeps the event pipeline open at shutdown.
    tx: WeakSender<AgentEvent>,
    /// The last nonce handed to the pipeline, when, and how often it was resent.
    last: Mutex<Option<Sent>>,
}

struct Sent {
    nonce: String,
    at: Instant,
    resends: u32,
}

impl LivenessEcho {
    pub fn new(agent_id: String, hostname: String, tx: WeakSender<AgentEvent>) -> Self {
        Self {
            agent_id,
            hostname,
            tx,
            last: Mutex::new(None),
        }
    }

    /// Enqueue an echo for the challenge in `body`. Returns whether an event
    /// was handed to the pipeline. A full channel drops the echo (counted as a drop), and the
    /// nonce stays unanswered so the repeat is tried.
    pub fn handle(&self, body: &[u8]) -> bool {
        self.handle_at(body, Instant::now())
    }

    fn handle_at(&self, body: &[u8], now: Instant) -> bool {
        let Some(nonce) = parse_nonce(body) else {
            return false;
        };
        let Ok(mut last) = self.last.lock() else {
            return false;
        };
        let resends = match last.as_ref() {
            Some(sent) if sent.nonce == nonce => {
                if sent.resends >= MAX_RESENDS || now.duration_since(sent.at) < RESEND_AFTER {
                    return false;
                }
                sent.resends + 1
            }
            _ => 0,
        };
        let Some(tx) = self.tx.upgrade() else {
            return false;
        };
        let event = echo_event(&self.agent_id, &self.hostname, &nonce);
        // Counted and attributed like every other event the pipeline refuses.
        if !crate::pipeline::try_emit(&tx, event, "liveness_echo") {
            return false;
        }
        *last = Some(Sent {
            nonce,
            at: now,
            resends,
        });
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NONCE: &str = "Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MA";

    fn body(nonce: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({ "ok": true, "liveness_nonce": nonce })).unwrap()
    }

    #[test]
    fn a_well_formed_nonce_is_parsed() {
        assert_eq!(parse_nonce(&body(NONCE)).as_deref(), Some(NONCE));
    }

    #[test]
    fn a_response_without_a_challenge_yields_nothing() {
        assert_eq!(parse_nonce(br#"{"ok":true}"#), None);
        assert_eq!(parse_nonce(br#"{"ok":true,"liveness_nonce":null}"#), None);
        assert_eq!(parse_nonce(b"not json"), None);
        assert_eq!(parse_nonce(b""), None);
    }

    #[test]
    fn malformed_or_hostile_nonces_are_rejected() {
        for bad in [
            "short",
            &"a".repeat(MAX_NONCE_LEN + 1),
            "has space in it......",
            "semi;colon;;;;;;;;;;;",
            "new\nline................",
            "\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}",
        ] {
            assert_eq!(parse_nonce(&body(bad)), None, "{bad:?}");
        }
        assert_eq!(
            parse_nonce(&body(&"a".repeat(MAX_NONCE_LEN))).map(|n| n.len()),
            Some(MAX_NONCE_LEN)
        );
    }

    #[test]
    fn an_oversized_body_is_not_parsed() {
        let mut big = body(NONCE);
        big.extend(std::iter::repeat_n(b' ', MAX_RESPONSE_BYTES));
        assert_eq!(parse_nonce(&big), None);
    }

    #[test]
    fn the_echo_event_is_an_info_detection_carrying_the_nonce() {
        let ev = serde_json::to_value(echo_event("agent-1", "host", NONCE)).unwrap();
        assert_eq!(ev["class"], "detection");
        assert_eq!(ev["severity"], "info");
        assert_eq!(ev["data"]["rule_id"], RULE_ID);
        assert_eq!(ev["data"]["evidence"]["nonce"], NONCE);
    }

    #[tokio::test]
    async fn a_challenge_is_echoed_once_through_the_event_channel() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(4);
        let echo = LivenessEcho::new("agent-1".into(), "host".into(), tx.downgrade());
        assert!(echo.handle(&body(NONCE)));
        // The backend repeats an unanswered challenge on every beat: not echoed again at once.
        assert!(!echo.handle(&body(NONCE)));
        let ev = serde_json::to_value(rx.try_recv().unwrap()).unwrap();
        assert_eq!(ev["data"]["evidence"]["nonce"], NONCE);
        assert!(rx.try_recv().is_err());
        // A fresh challenge is echoed again.
        let next = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo";
        assert!(echo.handle(&body(next)));
        assert!(rx.try_recv().is_ok());
    }

    #[tokio::test]
    async fn a_full_channel_drops_the_echo_and_allows_a_retry() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        let echo = LivenessEcho::new("agent-1".into(), "host".into(), tx.downgrade());
        tx.try_send(echo_event("x", "y", NONCE)).unwrap();
        assert!(!echo.handle(&body(NONCE)), "channel full");
        let _ = rx.try_recv();
        assert!(
            echo.handle(&body(NONCE)),
            "the repeated challenge is tried again"
        );
    }

    #[tokio::test]
    async fn garbage_never_reaches_the_pipeline() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(4);
        let echo = LivenessEcho::new("agent-1".into(), "host".into(), tx.downgrade());
        assert!(!echo.handle(&body("bad nonce")));
        assert!(!echo.handle(b"<html>"));
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn a_closed_pipeline_is_not_kept_alive_or_written_to() {
        let (tx, rx) = tokio::sync::mpsc::channel(4);
        let echo = LivenessEcho::new("agent-1".into(), "host".into(), tx.downgrade());
        drop(tx);
        assert!(!echo.handle(&body(NONCE)));
        drop(rx);
    }

    #[tokio::test]
    async fn an_unanswered_challenge_is_resent_after_a_delay_but_only_a_few_times() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(16);
        let echo = LivenessEcho::new("agent-1".into(), "host".into(), tx.downgrade());
        let t0 = Instant::now();
        assert!(echo.handle_at(&body(NONCE), t0));
        // The first echo may have been evicted from the spool: after the delay it is sent again.
        assert!(!echo.handle_at(&body(NONCE), t0 + RESEND_AFTER - Duration::from_secs(1)));
        let mut at = t0;
        for _ in 0..MAX_RESENDS {
            at += RESEND_AFTER;
            assert!(echo.handle_at(&body(NONCE), at), "resend");
        }
        at += RESEND_AFTER;
        assert!(
            !echo.handle_at(&body(NONCE), at),
            "bounded: no endless retransmission"
        );
        assert_eq!(
            std::iter::from_fn(|| rx.try_recv().ok()).count(),
            1 + MAX_RESENDS as usize
        );
        // A new challenge starts over.
        assert!(echo.handle_at(&body("QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo"), at));
    }
}
