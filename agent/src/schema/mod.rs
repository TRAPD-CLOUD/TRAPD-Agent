use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentEvent {
    pub event_id:  Uuid,
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
    /// Anonymous/executable memory mappings (fileless malware).
    Memory,
    /// Kernel-level events (module loads).
    Kernel,
    /// Inter-process communication (shared memory).
    Ipc,
    /// Active prevention / response actions taken by the agent.
    Prevention,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventAction {
    Create,
    Terminate,
    Exec,
    Connection,
    Snapshot,
    Logon,
    LogonFailed,
    SessionOpen,
    SessionClose,
    Delete,
    Modify,
    // ── New eBPF-sourced actions ─────────────────────────────────────
    Open,
    Bind,
    Accept,
    Fork,
    Unlink,
    Rename,
    Chmod,
    Chown,
    Mmap,
    Ptrace,
    ModuleLoad,
    Shmget,
    Shmat,
    NsChange,
    DnsQuery,
    IntegrityViolation,
    RansomwareIndicator,
    AgentTamper,
    WriteRateAnomaly,
    KillAttempt,
    // ── Prevention actions (active response) ────────────────────────────────────
    /// Process was terminated (SIGKILL) by the prevention engine.
    ProcessBlocked,
    /// Host placed into full network isolation (only management channel reachable).
    NetworkIsolated,
    /// Network isolation lifted.
    NetworkDeisolated,
    /// A specific IP/CIDR was added to the network deny-list.
    IpBlocked,
    /// A previously-blocked IP/CIDR was removed from the deny-list.
    IpUnblocked,
    /// File was quarantined (moved + chmod 000 + chattr +i).
    FileQuarantined,
    /// File was restored from quarantine to its original path.
    FileRestored,
    /// An IoC policy was updated (rules added, removed, reloaded).
    PolicyUpdated,
    /// A signed response command was rejected (bad signature, expired, replay).
    CommandRejected,
    /// A signed response command was accepted and executed.
    CommandAccepted,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum EventData {
    ProcessCreate(ProcessCreateData),
    ProcessTerminate(ProcessTerminateData),
    ProcessExec(ExecEventData),
    NetworkConnection(NetworkConnectionData),
    SystemSnapshot(SystemSnapshotData),
    UserLogon(UserLogonData),
    UserSession(UserSessionData),
    FileEvent(FileEventData),
    // ── eBPF-sourced event data ──────────────────────────────────────
    FileOpen(FileOpenData),
    NetworkSocket(NetworkSocketData),
    Fork(ForkData),
    FileUnlink(FileUnlinkData),
    FileRename(FileRenameData),
    FileChmod(FileChmodData),
    FileChown(FileChownData),
    Mmap(MmapData),
    Ptrace(PtraceData),
    ModuleLoad(ModuleLoadData),
    Shm(ShmData),
    NsChange(NsChangeData),
    Dns(DnsData),
    IntegrityViolation(IntegrityViolationData),
    RansomwareIndicator(RansomwareIndicatorData),
    AgentTamper(AgentTamperData),
    WriteRateAnomaly(WriteRateAnomalyData),
    KillAttempt(KillAttemptData),
    // ── Prevention event payload ────────────────────────────────────────
    Prevention(PreventionEventData),
}

// ── Existing data structs ────────────────────────────────────────────────────────────────────────

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
pub struct ExecEventData {
    pub pid:      i32,
    pub ppid:     i32,
    pub uid:      u32,
    pub gid:      u32,
    pub username: String,
    pub comm:     String,
    pub exe:      String,
    pub cmdline:  String,
    pub cwd:      String,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserSessionData {
    pub username: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEventData {
    pub path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileOpenData {
    pub pid:      i32,
    pub uid:      u32,
    pub gid:      u32,
    pub username: String,
    pub comm:     String,
    pub path:     String,
    pub flags:    u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkSocketData {
    pub pid:      i32,
    pub uid:      u32,
    pub gid:      u32,
    pub username: String,
    pub comm:     String,
    pub op:       String,
    pub family:   String,
    pub addr:     String,
    pub port:     u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForkData {
    pub parent_pid:  i32,
    pub child_pid:   i32,
    pub parent_comm: String,
    pub child_comm:  String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileUnlinkData {
    pub pid:      i32,
    pub uid:      u32,
    pub gid:      u32,
    pub username: String,
    pub comm:     String,
    pub path:     String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileRenameData {
    pub pid:      i32,
    pub uid:      u32,
    pub gid:      u32,
    pub username: String,
    pub comm:     String,
    pub old_path: String,
    pub new_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileChmodData {
    pub pid:      i32,
    pub uid:      u32,
    pub gid:      u32,
    pub username: String,
    pub comm:     String,
    pub path:     String,
    pub mode:     u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileChownData {
    pub pid:      i32,
    pub uid:      u32,
    pub gid:      u32,
    pub username: String,
    pub comm:     String,
    pub path:     String,
    pub new_uid:  u32,
    pub new_gid:  u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MmapData {
    pub pid:   i32,
    pub uid:   u32,
    pub gid:   u32,
    pub username: String,
    pub comm:  String,
    pub addr:  u64,
    pub len:   u64,
    pub prot:  u32,
    pub flags: u32,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PtraceData {
    pub pid:        i32,
    pub uid:        u32,
    pub gid:        u32,
    pub username:   String,
    pub comm:       String,
    pub request:    u32,
    pub target_pid: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleLoadData {
    pub pid:     i32,
    pub uid:     u32,
    pub gid:     u32,
    pub username: String,
    pub name:    String,
    pub taints:  u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShmData {
    pub pid:      i32,
    pub uid:      u32,
    pub gid:      u32,
    pub username: String,
    pub comm:     String,
    pub op:       String,
    pub key:      i32,
    pub size:     u64,
    pub flags:    i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NsChangeData {
    pub pid:      i32,
    pub uid:      u32,
    pub gid:      u32,
    pub username: String,
    pub comm:     String,
    pub op:       String,
    pub namespaces: String,
    pub flags:    u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsData {
    pub pid:      i32,
    pub uid:      u32,
    pub gid:      u32,
    pub username: String,
    pub comm:     String,
    pub dst_addr: String,
    pub dst_port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrityViolationData {
    pub path:          String,
    pub expected_hash: String,
    pub actual_hash:   String,
    pub size_delta:    i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RansomwareIndicatorData {
    pub indicator_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path:           Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid:            Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comm:           Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entropy:        Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub write_rate:     Option<u64>,
    pub details:        String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentTamperData {
    pub path:   String,
    pub action: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WriteRateAnomalyData {
    pub pid:             i32,
    pub uid:             u32,
    pub gid:             u32,
    pub username:        String,
    pub comm:            String,
    pub write_count:     u64,
    pub burst_threshold: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KillAttemptData {
    pub sender_pid: u32,
    pub sender_uid: u32,
    pub sender_gid: u32,
    pub sender_comm: String,
    pub target_pid:  i32,
    pub signal:      i32,
    pub signal_name: String,
}

// ── Prevention event payload ─────────────────────────────────────────────────────────

/// One uniform payload type for every prevention/response action emitted by the
/// agent.  The `kind` field is a stable string discriminator so the backend can
/// route without exhaustively matching on Rust enums:
///
///   "process_block"        — process killed
///   "network_isolate"      — full host isolation enabled
///   "network_deisolate"    — full host isolation lifted
///   "ip_block"/"ip_unblock"
///   "quarantine"/"restore"
///   "policy_update"
///   "command_rejected"/"command_accepted"
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreventionEventData {
    pub kind:   String,
    /// The thing being acted on:  PID, IP, file path, command id, …
    pub target: String,
    /// Whether the underlying syscall / shell-out succeeded.
    pub success: bool,
    /// Free-form human-readable reason or error message.
    pub reason: String,
    /// Optional IoC rule id that triggered this action.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_id:    Option<String>,
    /// Optional id of the signed command that requested this action.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command_id: Option<String>,
    /// Free-form structured details (process metadata, hashes, etc.).
    #[serde(skip_serializing_if = "serde_json::Value::is_null", default)]
    pub details:    serde_json::Value,
}

#[cfg(test)]
mod tests;
