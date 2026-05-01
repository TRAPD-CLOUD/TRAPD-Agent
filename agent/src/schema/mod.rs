use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentEvent {
    pub event_id:  Uuid,
    /// Server-assigned agent identifier (e.g. "agent_AbCdEf123").
    pub agent_id:  String,
    pub hostname:  String,
    pub timestamp: DateTime<Utc>,
    pub class:     EventClass,
    pub action:    EventAction,
    pub severity:  Severity,
    pub data:      EventData,
}

impl AgentEvent {
    pub fn new(
        agent_id: String,
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
    Filesystem,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventAction {
    Create,
    Terminate,
    /// execve(2) — process image replacement detected via eBPF tracepoint.
    /// Faster and more complete than polling-based Create detection.
    Exec,
    Connection,
    Snapshot,
    Logon,
    LogonFailed,
    SessionOpen,
    SessionClose,
    Delete,
    Modify,
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
    /// Real-time exec event from eBPF — one per execve(2), zero polling lag.
    ProcessExec(ExecEventData),
    NetworkConnection(NetworkConnectionData),
    SystemSnapshot(SystemSnapshotData),
    UserLogon(UserLogonData),
    UserSession(UserSessionData),
    FileEvent(FileEventData),
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

/// Exec event captured via eBPF sched/sched_process_exec tracepoint.
///
/// Represents a single execve(2) call — fired the moment the kernel commits
/// to replacing the process image. Short-lived processes (one-shot scripts,
/// C2 loaders, shell injections) that vanish before the next poll interval
/// are fully captured.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecEventData {
    /// User-space visible PID
    pub pid: i32,
    /// Parent PID (from /proc)
    pub ppid: i32,
    /// Real UID
    pub uid: u32,
    /// Real GID
    pub gid: u32,
    /// Username resolved from /etc/passwd
    pub username: String,
    /// Short process name from kernel task_struct.comm (≤ 15 chars)
    pub comm: String,
    /// Absolute path of the exec'd binary
    pub exe: String,
    /// Full command line including arguments (from /proc/<pid>/cmdline)
    pub cmdline: String,
    /// Working directory at time of exec (from /proc/<pid>/cwd)
    pub cwd: String,
    /// Short container ID (12 hex chars) if running inside a container
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container_id: Option<String>,
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
    pub os:              String,
    pub kernel:          String,
    pub distro:          String,
    pub cpu_count:       usize,
    pub cpu_usage_pct:   f32,
    pub memory_total_mb: u64,
    pub memory_used_mb:  u64,
    pub memory_free_mb:  u64,
    pub uptime_secs:     u64,
    pub load_avg:        [f64; 3],
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEventData {
    pub path: String,
}

#[cfg(test)]
mod tests;
