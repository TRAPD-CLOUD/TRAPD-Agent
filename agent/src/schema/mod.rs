use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentEvent {
    pub event_id:  Uuid,
    pub agent_id:  Uuid,
    pub hostname:  String,
    pub timestamp: DateTime<Utc>,
    pub class:     EventClass,
    pub action:    EventAction,
    pub severity:  Severity,
    pub data:      EventData,
}

impl AgentEvent {
    pub fn new(
        agent_id: Uuid,
        hostname: String,
        class: EventClass,
        action: EventAction,
        severity: Severity,
        data: EventData,
    ) -> Self {
        Self {
            event_id:  Uuid::new_v4(),
            agent_id,
            hostname,
            timestamp: Utc::now(),
            class,
            action,
            severity,
            data,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EventClass {
    Process,
    Network,
    System,
    User,
}

// snake_case covers all existing single-word variants unchanged ("create", "terminate", etc.)
// and correctly serializes new multi-word variants ("logon_failed", "session_open", etc.).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventAction {
    Create,
    Terminate,
    Connection,
    Snapshot,
    Logon,
    LogonFailed,
    SessionOpen,
    SessionClose,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum EventData {
    ProcessCreate(ProcessCreateData),
    ProcessTerminate(ProcessTerminateData),
    NetworkConnection(NetworkConnectionData),
    SystemSnapshot(SystemSnapshotData),
    UserLogon(UserLogonData),
    UserSession(UserSessionData),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessCreateData {
    pub pid:      i32,
    pub ppid:     i32,
    pub name:     String,
    pub exe:      String,
    pub cmdline:  String,
    pub uid:      u32,
    pub username: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessTerminateData {
    pub pid:  i32,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConnectionData {
    pub protocol: String,
    pub src_addr: String,
    pub src_port: u16,
    pub dst_addr: String,
    pub dst_port: u16,
    pub state:    String,
    pub pid:      Option<i32>,
    pub process:  Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemSnapshotData {
    pub os:               String,
    pub kernel:           String,
    pub distro:           String,
    pub cpu_count:        usize,
    pub cpu_usage_pct:    f32,
    pub memory_total_mb:  u64,
    pub memory_used_mb:   u64,
    pub memory_free_mb:   u64,
    pub uptime_secs:      u64,
    pub load_avg:         [f64; 3],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserLogonData {
    pub username:    String,
    pub src_addr:    Option<String>,
    pub src_port:    Option<u16>,
    pub auth_method: Option<String>,
    pub success:     bool,
}

/// Used for session_open / session_close events where only the username is known.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserSessionData {
    pub username: String,
}

#[cfg(test)]
mod tests;
