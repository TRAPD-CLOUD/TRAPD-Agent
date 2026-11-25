//! Sends command results from the outbox to the backend until acknowledged.
//!
//! Backend endpoint:
//!   `POST /api/v1/agents/{agent_id}/commands/{command_id}/result`
//!
//! The backend answers 200 only after its database committed the result and
//! repeats that answer for the same `event_id`, so a retry after a lost reply
//! is harmless. 404 (unknown command, or a backend without the endpoint) and
//! 409 (another result already ended the command) are final: the record is
//! dropped, the telemetry copy of the result was sent anyway.

use std::sync::Arc;

use serde::Serialize;
use tokio::time::Duration;
use tracing::{debug, warn};

use super::result_outbox::{Entry, ResultOutbox, ResultStatus};

const RETRY_INTERVAL: Duration = Duration::from_secs(30);

#[derive(Debug, PartialEq, Eq)]
enum Disposition {
    /// Stored by the backend; drop the record.
    Acknowledged,
    /// Never going to be accepted; drop the record.
    Final,
    /// Credentials need renewing; retry later.
    Unauthorized,
    /// Backend or network trouble; retry later.
    Retry,
}

fn disposition(status: reqwest::StatusCode) -> Disposition {
    match status.as_u16() {
        200..=299 => Disposition::Acknowledged,
        401 => Disposition::Unauthorized,
        // 400/413: the body itself is refused; resending cannot help.
        400 | 404 | 409 | 413 => Disposition::Final,
        _ => Disposition::Retry,
    }
}

#[derive(Serialize)]
struct ResultBody<'a> {
    event_id: String,
    status: ResultStatus,
    action: &'a str,
    reason: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<&'a serde_json::Value>,
    reported_at: String,
}

fn body(entry: &Entry) -> Option<ResultBody<'_>> {
    let outcome = entry.outcome.as_ref()?;
    Some(ResultBody {
        event_id: entry.event_id.to_string(),
        status: outcome.status,
        action: &entry.kind,
        reason: &outcome.reason,
        details: outcome.details.as_ref(),
        reported_at: outcome
            .reported_at
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
    })
}

pub struct ResultReporter {
    client: reqwest::Client,
    base: String,
    tokens: Arc<crate::identity::SessionTokens>,
    outbox: Arc<ResultOutbox>,
}

impl ResultReporter {
    pub fn new(
        backend_url: &str,
        agent_id: &str,
        tokens: Arc<crate::identity::SessionTokens>,
        outbox: Arc<ResultOutbox>,
    ) -> anyhow::Result<Self> {
        let base = crate::http::normalize_base_url(backend_url);
        Ok(Self {
            client: crate::http::control_client()?,
            base: format!("{base}/api/v1/agents/{agent_id}/commands"),
            tokens,
            outbox,
        })
    }

    pub async fn run(self) {
        loop {
            self.flush().await;
            tokio::select! {
                _ = self.outbox.wait_ready() => {}
                _ = tokio::time::sleep(RETRY_INTERVAL) => {}
            }
        }
    }

    /// Send every finished record once; stop at the first retryable failure.
    async fn flush(&self) {
        for entry in self.outbox.pending() {
            let Some(payload) = body(&entry) else {
                continue;
            };
            let bearer = self.tokens.current().await;
            let url = format!("{}/{}/result", self.base, entry.command_id);
            let sent = self
                .client
                .post(&url)
                .bearer_auth(&bearer)
                .json(&payload)
                .send()
                .await;
            let status = match sent {
                Ok(resp) => resp.status(),
                Err(error) => {
                    debug!(%error, "command result not delivered; will retry");
                    return;
                }
            };
            match disposition(status) {
                Disposition::Acknowledged => self.outbox.remove(entry.command_id),
                Disposition::Final => {
                    warn!(command_id = %entry.command_id, %status, "backend refused command result for good");
                    self.outbox.remove(entry.command_id);
                }
                Disposition::Unauthorized => {
                    self.tokens.report_unauthorized(&bearer).await;
                    return;
                }
                Disposition::Retry => {
                    debug!(%status, "command result endpoint unavailable; will retry");
                    return;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prevention::result_outbox::Outcome;
    use reqwest::StatusCode;

    #[test]
    fn only_acknowledged_or_final_answers_drop_a_record() {
        assert_eq!(disposition(StatusCode::OK), Disposition::Acknowledged);
        for final_status in [400, 404, 409, 413] {
            assert_eq!(
                disposition(StatusCode::from_u16(final_status).unwrap()),
                Disposition::Final
            );
        }
        assert_eq!(
            disposition(StatusCode::UNAUTHORIZED),
            Disposition::Unauthorized
        );
        for retry in [403, 408, 429, 500, 502, 503] {
            assert_eq!(
                disposition(StatusCode::from_u16(retry).unwrap()),
                Disposition::Retry,
                "{retry}"
            );
        }
    }

    #[test]
    fn body_matches_the_backend_contract() {
        let entry = Entry {
            command_id: uuid::Uuid::new_v4(),
            event_id: uuid::Uuid::parse_str("44444444-4444-4444-8444-444444444444").unwrap(),
            kind: "kill_pid".into(),
            started_at: chrono::Utc::now(),
            outcome: Some(Outcome {
                status: ResultStatus::InterruptedUnknown,
                reason: "stopped".into(),
                details: None,
                reported_at: chrono::DateTime::parse_from_rfc3339("2026-11-25T12:00:00Z")
                    .unwrap()
                    .with_timezone(&chrono::Utc),
            }),
        };
        let json = serde_json::to_value(body(&entry).unwrap()).unwrap();
        assert_eq!(
            json,
            serde_json::json!({
                "event_id": "44444444-4444-4444-8444-444444444444",
                "status": "interrupted_unknown",
                "action": "kill_pid",
                "reason": "stopped",
                "reported_at": "2026-11-25T12:00:00.000Z",
            })
        );
        let open = Entry {
            outcome: None,
            ..entry
        };
        assert!(body(&open).is_none(), "an open intent is never sent");
    }
}
