//! Logged-on user sessions — the Windows counterpart of the session half of
//! `collectors::linux::authlog`.
//!
//! Uses the native Terminal Services API for interactive/RDP sessions,
//! emitting `user/session_open` / `user/session_close` in the shared schema.
//! This avoids parsing localized command output or depending on quser.exe.

use std::collections::HashSet;

use anyhow::{bail, Result};
use async_trait::async_trait;
use tokio::sync::mpsc::Sender;
use tokio::time::{interval, Duration};
use tracing::warn;
use windows_sys::Win32::System::RemoteDesktop::*;

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

struct WtsMemory(*mut std::ffi::c_void);
impl Drop for WtsMemory {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: pointer was allocated by a WTS API and is freed once.
            unsafe { WTSFreeMemory(self.0) };
        }
    }
}

fn session_text(id: u32, field: WTS_INFO_CLASS) -> Result<String> {
    let mut buffer = std::ptr::null_mut();
    let mut bytes = 0;
    // SAFETY: valid output pointers; null server selects the local machine.
    let ok = unsafe {
        WTSQuerySessionInformationW(std::ptr::null_mut(), id, field, &mut buffer, &mut bytes)
    };
    let _memory = WtsMemory(buffer.cast());
    if ok == 0 {
        bail!(
            "WTS session query failed: {}",
            std::io::Error::last_os_error()
        );
    }
    if buffer.is_null() || bytes == 0 {
        return Ok(String::new());
    }
    if bytes > 65536 || bytes % 2 != 0 {
        bail!("invalid WTS string size");
    }
    let text = unsafe { std::slice::from_raw_parts(buffer, bytes as usize / 2) };
    let length = text.iter().position(|c| *c == 0).unwrap_or(text.len());
    Ok(String::from_utf16(&text[..length])?)
}

fn query_sessions() -> Result<HashSet<String>> {
    let mut sessions = std::ptr::null_mut();
    let mut count = 0;
    // SAFETY: valid output pointers and documented enumeration version 1.
    let ok =
        unsafe { WTSEnumerateSessionsW(std::ptr::null_mut(), 0, 1, &mut sessions, &mut count) };
    let _memory = WtsMemory(sessions.cast());
    if ok == 0 {
        bail!(
            "WTS enumeration failed: {}",
            std::io::Error::last_os_error()
        );
    }
    if count > 16384 || (count != 0 && sessions.is_null()) {
        bail!("invalid WTS session count");
    }
    let mut users = HashSet::new();
    if count == 0 {
        return Ok(users);
    }
    for session in unsafe { std::slice::from_raw_parts(sessions, count as usize) } {
        let name = session_text(session.SessionId, WTSUserName)?;
        if name.is_empty() {
            continue;
        }
        let domain = session_text(session.SessionId, WTSDomainName)?;
        users.insert(
            if domain.is_empty() {
                name
            } else {
                format!("{domain}\\{name}")
            }
            .to_lowercase(),
        );
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

            let current = match tokio::task::spawn_blocking(query_sessions).await? {
                Ok(s) => s,
                Err(e) => {
                    warn!("user-session telemetry unavailable: {e}");
                    crate::telemetry::metrics::metrics().collector_failed();
                    continue;
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
