use anyhow::Result;
use async_trait::async_trait;
use tokio::fs::File;
use tokio::io::{AsyncBufReadExt, AsyncSeekExt, BufReader};
use tokio::sync::mpsc::Sender;
use tokio::time::{interval, Duration};
use tracing::warn;

use crate::collectors::Collector;
use crate::schema::{
    AgentEvent, EventAction, EventClass, EventData, Severity, UserLogonData, UserSessionData,
};

const AUTH_LOG: &str = "/var/log/auth.log";

pub struct AuthLogCollector;

impl AuthLogCollector {
    pub fn new() -> Self {
        Self
    }
}

impl Default for AuthLogCollector {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Collector for AuthLogCollector {
    fn name(&self) -> &'static str {
        "AuthLogCollector"
    }

    async fn run(
        &mut self,
        tx:       Sender<AgentEvent>,
        agent_id: String,
        hostname: String,
    ) -> Result<()> {
        let mut file = match File::open(AUTH_LOG).await {
            Ok(f) => f,
            Err(e) => {
                warn!("AuthLogCollector: {AUTH_LOG} not found ({e}), skipping");
                return Ok(());
            }
        };

        // Seek to end — ignore historical entries
        file.seek(std::io::SeekFrom::End(0)).await?;

        let mut reader = BufReader::new(file);
        let mut ticker = interval(Duration::from_secs(2));
        let mut line   = String::new();

        loop {
            ticker.tick().await;

            loop {
                line.clear();
                let n = reader.read_line(&mut line).await?;
                if n == 0 {
                    break; // no new data yet
                }
                let trimmed = line.trim_end();
                if let Some(event) = parse_auth_line(trimmed, agent_id.clone(), hostname.clone()) {
                    if tx.send(event).await.is_err() {
                        return Ok(()); // channel closed
                    }
                }
            }
        }
    }
}

fn parse_auth_line(line: &str, agent_id: String, hostname: String) -> Option<AgentEvent> {
    if let Some(ev) = parse_accepted(line, "password") {
        return Some(AgentEvent::new(
            agent_id.clone(), hostname.clone(),
            EventClass::User, EventAction::Logon,
            Severity::Info,
            EventData::UserLogon(ev),
        ));
    }

    if let Some(ev) = parse_accepted(line, "publickey") {
        return Some(AgentEvent::new(
            agent_id.clone(), hostname.clone(),
            EventClass::User, EventAction::Logon,
            Severity::Info,
            EventData::UserLogon(ev),
        ));
    }

    if let Some(ev) = parse_failed(line) {
        return Some(AgentEvent::new(
            agent_id.clone(), hostname.clone(),
            EventClass::User, EventAction::LogonFailed,
            Severity::Medium,
            EventData::UserLogon(ev),
        ));
    }

    if let Some(ev) = parse_session(line, true) {
        return Some(AgentEvent::new(
            agent_id.clone(), hostname.clone(),
            EventClass::User, EventAction::SessionOpen,
            Severity::Info,
            EventData::UserSession(ev),
        ));
    }

    if let Some(ev) = parse_session(line, false) {
        return Some(AgentEvent::new(
            agent_id.clone(), hostname.clone(),
            EventClass::User, EventAction::SessionClose,
            Severity::Info,
            EventData::UserSession(ev),
        ));
    }

    None
}

fn parse_accepted(line: &str, method: &str) -> Option<UserLogonData> {
    let marker = format!("Accepted {method} for ");
    let pos    = line.find(marker.as_str())?;
    let rest   = &line[pos + marker.len()..];

    // "<user> from <ip> port <port> ssh2"
    let parts: Vec<&str> = rest.split_whitespace().collect();
    if parts.len() < 5 {
        return None;
    }
    let username = parts[0].to_string();
    // parts[1] == "from"
    let src_addr = Some(parts[2].to_string());
    // parts[3] == "port"
    let src_port = parts[4].parse::<u16>().ok();

    Some(UserLogonData {
        username,
        src_addr,
        src_port,
        auth_method: Some(method.to_string()),
        success: true,
    })
}

fn parse_failed(line: &str) -> Option<UserLogonData> {
    let pos  = line.find("Failed password for ")?;
    let rest = &line[pos + 20..];

    // rest = "[invalid user ]<user> from <ip> [port <port>] ..."
    let (user_part, addr_rest) = rest.split_once(" from ")?;
    let username = user_part
        .strip_prefix("invalid user ")
        .unwrap_or(user_part)
        .to_string();

    let addr_parts: Vec<&str> = addr_rest.split_whitespace().collect();
    let src_addr = addr_parts.first().map(|s| s.to_string());
    // "from <ip> port <port>" — port may or may not be present
    let src_port = addr_parts
        .get(2)
        .and_then(|s| s.parse::<u16>().ok());

    Some(UserLogonData {
        username,
        src_addr,
        src_port,
        auth_method: Some("password".to_string()),
        success: false,
    })
}

fn parse_session(line: &str, opened: bool) -> Option<UserSessionData> {
    let marker = if opened {
        "session opened for user "
    } else {
        "session closed for user "
    };
    let pos      = line.find(marker)?;
    let rest     = &line[pos + marker.len()..];
    let username = rest.split_whitespace().next()?.to_string();
    Some(UserSessionData { username })
}
