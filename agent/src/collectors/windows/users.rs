//! Logged-on user sessions — the Windows counterpart of the session half of
//! `collectors::linux::authlog`.
//!
//! Polls the interactive/RDP session list via `quser.exe` (a.k.a.
//! `query user`, present on Pro/Enterprise/Server editions) and diffs it,
//! emitting `user/session_open` / `user/session_close` events with the same
//! [`UserSessionData`] payload the Linux agent produces. On editions without
//! `quser` the collector logs once and idles — telemetry degrades, the agent
//! does not.

use std::collections::HashSet;

use anyhow::Result;
use async_trait::async_trait;
use tokio::sync::mpsc::Sender;
use tokio::time::{interval, Duration};
use tracing::warn;

use crate::collectors::Collector;
use crate::schema::{AgentEvent, EventAction, EventClass, EventData, Severity, UserSessionData};

const POLL_INTERVAL: Duration = Duration::from_secs(60);

pub struct UserSessionCollector {
    initialized: bool,
    known: HashSet<String>,
}

impl UserSessionCollector {
    pub fn new() -> Self {
        Self {
            initialized: false,
            known: HashSet::new(),
        }
    }
}

impl Default for UserSessionCollector {
    fn default() -> Self {
        Self::new()
    }
}

/// Run `quser` and parse the usernames out of its fixed-ish column output:
///
/// ```text
///  USERNAME              SESSIONNAME        ID  STATE   IDLE TIME  LOGON TIME
/// >alice                 console             1  Active      none   1/2/2026 9:00 AM
/// ```
///
/// The current session is prefixed with `>`. `quser` exits non-zero when *no
/// one* is logged on, so a failure with empty output is treated as "no
/// sessions", not an error.
async fn query_sessions() -> Result<HashSet<String>> {
    let out = tokio::process::Command::new("quser").output().await?;

    let mut users = HashSet::new();
    let stdout = String::from_utf8_lossy(&out.stdout);
    for line in stdout.lines().skip(1) {
        let name = line.trim_start().trim_start_matches('>');
        if let Some(user) = name.split_whitespace().next() {
            if !user.is_empty() {
                users.insert(user.to_ascii_lowercase());
            }
        }
    }
    Ok(users)
}

#[async_trait]
impl Collector for UserSessionCollector {
    fn name(&self) -> &'static str {
        "UserSessionCollector"
    }

    async fn run(
        &mut self,
        tx: Sender<AgentEvent>,
        agent_id: String,
        hostname: String,
    ) -> Result<()> {
        let mut ticker = interval(POLL_INTERVAL);

        loop {
            ticker.tick().await;

            let current = match query_sessions().await {
                Ok(s) => s,
                Err(e) => {
                    // quser.exe missing entirely (e.g. Home edition): give up
                    // quietly rather than spamming a warning every minute.
                    warn!("user-session telemetry unavailable (quser failed): {e}");
                    return Ok(());
                }
            };

            if self.initialized {
                for user in current.difference(&self.known) {
                    let event = AgentEvent::new(
                        agent_id.clone(),
                        hostname.clone(),
                        EventClass::User,
                        EventAction::SessionOpen,
                        Severity::Info,
                        EventData::UserSession(UserSessionData {
                            username: user.clone(),
                        }),
                    );
                    if tx.send(event).await.is_err() {
                        return Ok(());
                    }
                }
                for user in self.known.difference(&current) {
                    let event = AgentEvent::new(
                        agent_id.clone(),
                        hostname.clone(),
                        EventClass::User,
                        EventAction::SessionClose,
                        Severity::Info,
                        EventData::UserSession(UserSessionData {
                            username: user.clone(),
                        }),
                    );
                    if tx.send(event).await.is_err() {
                        return Ok(());
                    }
                }
            }

            self.known = current;
            self.initialized = true;
        }
    }
}
