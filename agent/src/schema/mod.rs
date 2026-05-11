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
    // ── New eBPF-sourced actions ──────────────────────────────────────────────
    /// openat(2) with write/create/truncate flags.
    Open,
    /// bind(2) – process registering a listening socket.
    Bind,
    /// accept4(2) – process accepting an incoming connection.
    Accept,
    /// clone(2)/fork(2) – child process creation.
    Fork,
    /// unlinkat(2) – file deletion.
    Unlink,
    /// renameat2(2) – file rename/move.
    Rename,
    /// fchmodat(2) – permission change.
    Chmod,
    /// fchownat(2) – ownership change.
    Chown,
    /// mmap(2) with executable or RWX flags.
    Mmap,
    /// ptrace(2) – debugging / injection.
    Ptrace,
    /// Kernel module loaded (insmod/modprobe).
    ModuleLoad,
    /// shmget(2) – shared memory segment created.
    Shmget,
    /// shmat(2) – shared memory segment attached.
    Shmat,
    /// unshare(2)/setns(2) – namespace change (potential container escape).
    NsChange,
    /// UDP sendmsg to port 53 – DNS query.
    DnsQuery,
    /// SHA256 hash mismatch against trusted baseline (FIM).
    IntegrityViolation,
    /// Ransomware behavioral indicator (high entropy, mass rename, backup deletion, write burst).
    RansomwareIndicator,
    /// Tampering with agent-owned configuration files.
    AgentTamper,
    /// Abnormal write-syscall rate per process (eBPF).
    WriteRateAnomaly,
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
    // ── New eBPF-sourced event data ───────────────────────────────────────────
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
    // ── FIM + Ransomware + Agent-protection ──────────────────────────────────
    IntegrityViolation(IntegrityViolationData),
    RansomwareIndicator(RansomwareIndicatorData),
    AgentTamper(AgentTamperData),
    WriteRateAnomaly(WriteRateAnomalyData),
}

// ── Existing data structs ────────────────────────────────────────────────────

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

// ── New eBPF-sourced data structs ────────────────────────────────────────────

/// File open event (openat with write/create/truncate flags).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileOpenData {
    pub pid:      i32,
    pub uid:      u32,
    pub gid:      u32,
    pub username: String,
    pub comm:     String,
    pub path:     String,
    /// Raw openat(2) flags bitmask.
    pub flags:    u64,
}

/// Network socket operation: connect, bind, or accept.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkSocketData {
    pub pid:      i32,
    pub uid:      u32,
    pub gid:      u32,
    pub username: String,
    pub comm:     String,
    /// "connect" | "bind" | "accept"
    pub op:       String,
    /// "ipv4" | "ipv6" | "unknown"
    pub family:   String,
    pub addr:     String,
    pub port:     u16,
}

/// Process fork/clone event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForkData {
    pub parent_pid:  i32,
    pub child_pid:   i32,
    pub parent_comm: String,
    pub child_comm:  String,
}

/// File deletion (unlinkat).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileUnlinkData {
    pub pid:      i32,
    pub uid:      u32,
    pub gid:      u32,
    pub username: String,
    pub comm:     String,
    pub path:     String,
}

/// File rename/move (renameat2).
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

/// Permission change (fchmodat).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileChmodData {
    pub pid:      i32,
    pub uid:      u32,
    pub gid:      u32,
    pub username: String,
    pub comm:     String,
    pub path:     String,
    /// New mode in octal (e.g. 0o755).
    pub mode:     u32,
}

/// Ownership change (fchownat).
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

/// Suspicious mmap (anonymous+executable or writable+executable).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MmapData {
    pub pid:   i32,
    pub uid:   u32,
    pub gid:   u32,
    pub username: String,
    pub comm:  String,
    pub addr:  u64,
    pub len:   u64,
    /// Raw PROT_* bitmask.
    pub prot:  u32,
    /// Raw MAP_* bitmask.
    pub flags: u32,
    /// Human-readable flags summary, e.g. "anon|exec" or "rwx".
    pub description: String,
}

/// ptrace(2) call.
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

/// Kernel module loaded.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleLoadData {
    pub pid:     i32,
    pub uid:     u32,
    pub gid:     u32,
    pub username: String,
    pub name:    String,
    pub taints:  u32,
}

/// Shared memory syscall (shmget or shmat).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShmData {
    pub pid:      i32,
    pub uid:      u32,
    pub gid:      u32,
    pub username: String,
    pub comm:     String,
    /// "shmget" or "shmat"
    pub op:       String,
    pub key:      i32,
    pub size:     u64,
    pub flags:    i32,
}

/// Namespace change (unshare or setns).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NsChangeData {
    pub pid:      i32,
    pub uid:      u32,
    pub gid:      u32,
    pub username: String,
    pub comm:     String,
    /// "unshare" or "setns"
    pub op:       String,
    /// Comma-separated namespace types, e.g. "pid,net,mnt".
    pub namespaces: String,
    pub flags:    u64,
}

/// DNS query detected via kprobe on udp_sendmsg.
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

// ── FIM / Ransomware / Agent-protection data structs ────────────────────────

/// SHA256 hash mismatch between trusted baseline and current file state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrityViolationData {
    pub path:          String,
    /// Baseline hash stored at last trusted snapshot, format: "sha256:<hex>".
    pub expected_hash: String,
    /// Hash computed at detection time, format: "sha256:<hex>".
    pub actual_hash:   String,
    /// Difference in file size (bytes): positive = grown, negative = shrunk.
    pub size_delta:    i64,
}

/// Ransomware behavioral indicator detected in userspace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RansomwareIndicatorData {
    /// One of: "high_entropy" | "suspicious_extension" | "backup_deletion" | "high_write_rate"
    pub indicator_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path:           Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid:            Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comm:           Option<String>,
    /// Shannon entropy of the file (bits per byte). Present for "high_entropy".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entropy:        Option<f64>,
    /// Modifications per window. Present for "high_write_rate".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub write_rate:     Option<u64>,
    pub details:        String,
}

/// Tampering with agent-owned configuration or data files.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentTamperData {
    pub path:   String,
    /// "create" | "modify" | "delete" | "move"
    pub action: String,
}

/// Per-process write-syscall burst detected by the eBPF write tracer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WriteRateAnomalyData {
    pub pid:             i32,
    pub uid:             u32,
    pub gid:             u32,
    pub username:        String,
    pub comm:            String,
    /// Accumulated write count at the time of emission.
    pub write_count:     u64,
    /// Threshold that triggered this event.
    pub burst_threshold: u64,
}

#[cfg(test)]
mod tests;
