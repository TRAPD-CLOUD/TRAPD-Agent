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
    /// A behavioural/IOC detection raised by the local detection engine.
    Detection,
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
    // ── New security-monitoring actions ─────────────────────────────────────────
    Setuid,
    MemfdCreate,
    MemoryAnomaly,
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
    /// The local detection engine raised a finding (see `DetectionData`).
    Detected,
    // ── Software / asset management actions ─────────────────────────────────
    /// A package was installed via a signed command.
    PackageInstalled,
    /// A package was removed via a signed command.
    PackageRemoved,
    /// A package (or all packages) were upgraded via a signed command.
    PackageUpgraded,
    // ── Deception / honeytoken actions ──────────────────────────────────────
    /// A honeytoken was placed on disk via a signed command.
    HoneytokenDeployed,
    /// A previously-deployed honeytoken was removed via a signed command.
    HoneytokenRevoked,
    /// A honeytoken was *accessed* (opened) — by definition an intrusion signal.
    HoneytokenAccess,
    /// A process was frozen (SIGSTOP) for forensic capture instead of killed
    /// ("freeze, snapshot, then decide" — issue #32, point 5).
    ProcessFrozen,
    /// A previously-frozen process was resumed (SIGCONT).
    ProcessThawed,
    /// Deception escalation triggered by a confirmed honeytoken hit — the agent's
    /// signal for the backend to deploy more bait / redirect into a honeypot /
    /// tarpit (issue #32, point 5).
    DeceptionEscalation,
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
    // Boxed: with the P1 telemetry-depth fields (image hash, library inventory,
    // env, decoded scripts, K8s context) this is by far the largest variant;
    // boxing keeps `EventData` compact (clippy::large_enum_variant).
    ProcessExec(Box<ExecEventData>),
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
    Setuid(SetuidData),
    MemfdCreate(MemfdCreateData),
    MemoryAnomaly(MemoryAnomalyData),
    // ── Prevention event payload ────────────────────────────────────────
    Prevention(PreventionEventData),
    // ── Detection engine payload ────────────────────────────────────────
    Detection(DetectionData),
    // ── Honeytoken access (deception) ───────────────────────────────────
    // Boxed: the forensic session/lineage payload is much larger than the other
    // variants, so boxing keeps `EventData` compact (clippy::large_enum_variant).
    HoneytokenAccess(Box<HoneytokenAccessData>),
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ld_preload: Option<String>,
    // ── Telemetry-depth enrichment (P1) ──────────────────────────────────────
    /// SHA256 of the executed binary image (`sha256:<hex>`) — the Falcon-style
    /// image hash that anchors IOC / reputation matching. `None` when the binary
    /// could not be read (process exited, oversize, permission).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    /// Shared objects mapped into the process (the Linux "loaded module"
    /// inventory; the DLL-equivalent), from `/proc/<pid>/maps`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub loaded_libraries: Vec<String>,
    /// Curated, secret-redacted environment of the process.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub env: std::collections::BTreeMap<String, String>,
    /// Decoded interpreter script context (`python -c`, base64 chains, …).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interpreter: Option<InterpreterContext>,
    /// Container runtime (`docker`/`containerd`/`crio`/`podman`/`kubepods`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container_runtime: Option<String>,
    /// Container image reference (`registry/name:tag`), from the runtime state.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container_image: Option<String>,
    /// Container image content digest (`sha256:…`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container_image_digest: Option<String>,
    /// Kubernetes pod context, when the process runs in a pod.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub k8s: Option<K8sContext>,
}

/// Aggregated process-enrichment payload produced by
/// [`crate::collectors::linux::proc_enrich`]; flattened into [`ExecEventData`].
#[derive(Debug, Clone, Default)]
pub struct ExecEnrichment {
    pub sha256:           Option<String>,
    pub loaded_libraries: Vec<String>,
    pub interpreter:      Option<InterpreterContext>,
    pub env:              std::collections::BTreeMap<String, String>,
    pub container_id:     Option<String>,
    pub container_runtime: Option<String>,
    pub container_image:  Option<String>,
    pub container_image_digest: Option<String>,
    pub k8s:              Option<K8sContext>,
}

/// Decoded view of a script interpreter invocation — the inline program body
/// and any base64 payloads recovered from the command line, tagged with
/// suspicious-pattern indicators.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterpreterContext {
    /// Interpreter language (`python`/`bash`/`perl`/`node`/…).
    pub lang: String,
    /// Inline script passed via `-c`/`-e`, when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inline_script: Option<String>,
    /// Base64 blobs decoded out of the command line (obfuscation chains).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub decoded_payloads: Vec<String>,
    /// Matched suspicious-pattern tags (`base64_decode`, `reverse_shell`, …).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub indicators: Vec<String>,
}

/// Kubernetes pod context for a process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct K8sContext {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pod_uid:   Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pod_name:  Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    /// Orchestration labels (`io.kubernetes.*`, custom pod labels).
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub labels: std::collections::BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConnectionData {
    pub protocol: String,
    pub src_addr: String,
    pub src_port: u16,
    pub dst_addr: String,
    pub dst_port: u16,
    /// `established` / `open` on flow start; `closed` on the flow-end record.
    pub state:    String,
    pub pid:      Option<i32>,
    pub process:  Option<String>,
    /// Flow lifetime in milliseconds, measured from first observation to the
    /// flow-close record (set only on the `closed` event).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
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

// ── Detection engine payload ──────────────────────────────────────────────────

/// One finding from the local detection engine.  The engine correlates raw
/// telemetry (process exec, network connections, file events) against rules,
/// IOC feeds and behavioural heuristics, and maps each hit to MITRE ATT&CK so
/// the backend can route and prioritise without re-deriving context.
///
/// This type is deliberately platform-neutral: the same engine and schema will
/// back the future Windows agent, only the *collectors* feeding it differ.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionData {
    /// Stable rule identifier, e.g. `lolbin.shell_spawns_downloader`.
    pub rule_id:    String,
    /// Human-readable title of what was detected.
    pub title:      String,
    /// Detection family: `ioc`, `lolbin`, `reverse_shell`, `beaconing`, …
    pub category:   String,
    /// MITRE ATT&CK tactic (e.g. `TA0011 Command and Control`), if mapped.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mitre_tactic: Option<String>,
    /// MITRE ATT&CK technique (e.g. `T1059.004`), if mapped.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mitre_technique: Option<String>,
    /// Confidence 0–100 that this is a true positive.
    pub confidence: u8,
    /// What the detection fired on: pid, ip:port, file path, hash, …
    pub subject:    String,
    /// Free-form explanation, including the matched evidence.
    pub detail:     String,
    /// Optional structured evidence (matched IOC, observed cadence, …).
    #[serde(skip_serializing_if = "serde_json::Value::is_null", default)]
    pub evidence:   serde_json::Value,
}

// ── Honeytoken access payload (deception, step 2) ─────────────────────────────

/// A honeytoken file was opened.  By construction no legitimate workflow reads a
/// honeytoken, so this is a high-confidence intrusion signal.  The payload binds
/// the access to its full process lineage (the "flight recorder" idea): the
/// accessor plus its parent chain, so the backend can reconstruct *how* the
/// process that touched the bait came to exist.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HoneytokenAccessData {
    /// Id of the deployed token (matches `HoneytokenRecord::id`).
    pub token_id: String,
    /// Absolute path of the token that was opened.
    pub path: String,
    /// Token family (`ssh_private_key`, `aws_credentials`, …).
    pub kind: String,
    /// How the token was touched — `open`/`openat2`/`exec`/`stat`/`readlink`/
    /// `hardlink`/`unlink`/`rename`. Lets the backend distinguish a content
    /// read (intrusion) from metadata recon or a tamper/evasion attempt.
    #[serde(default)]
    pub access_kind: String,
    /// open(2) flags the accessor used (read-only access still fires).
    pub open_flags: u64,
    /// Confidence 0–100 that this is a true positive. Content access/execution
    /// scores 100; metadata recon and tamper score below that.
    pub confidence: u8,
    pub mitre_tactic: String,
    pub mitre_technique: String,
    /// The accessing process and its ancestry.
    pub accessor: ProcessLineage,
    /// Session / execution context of the accessor (issue #32, point 5):
    /// login session, TTY, originating remote IP, container/namespace/cgroup.
    /// `None` when `/proc` could not be read (e.g. the process already exited).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionContext>,
}

/// Session / execution context of a process, captured from `/proc` at detection
/// time (issue #32, point 5). Binds a honeytoken access to *who* and *where*: the
/// login session, controlling terminal, the originating remote IP (correlated
/// from auth.log), and the container / namespace / cgroup it ran in — so the
/// backend can attribute the hit to a real session and attacker.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct SessionContext {
    /// Audit login uid (`/proc/<pid>/loginuid`); `u32::MAX` (unset) maps to `None`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub loginuid: Option<u32>,
    /// Username resolved from [`loginuid`](Self::loginuid).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub login_user: Option<String>,
    /// Kernel audit session id (`/proc/<pid>/sessionid`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audit_session_id: Option<u32>,
    /// Controlling terminal (e.g. `pts/3`, `tty1`), or `None` when detached.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tty: Option<String>,
    /// Current working directory of the accessor.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    /// Most specific cgroup path the accessor belongs to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cgroup: Option<String>,
    /// Container id parsed from the cgroup path, when the process is containerised.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container_id: Option<String>,
    /// Container runtime inferred from the cgroup path (`docker`/`containerd`/
    /// `podman`/`kubepods`/`libpod`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container_runtime: Option<String>,
    /// Namespace inode ids the accessor runs in (distinguishes host vs container).
    #[serde(default, skip_serializing_if = "NamespaceIds::is_empty")]
    pub namespaces: NamespaceIds,
    /// Remote source address of the login session, correlated best-effort from
    /// recent auth.log logons.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_addr: Option<String>,
    /// Remote source port of that login session, when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_port: Option<u16>,
}

/// Namespace inode ids of a process (`/proc/<pid>/ns/*`). Equal ids across
/// processes mean the same namespace; differing from PID 1's means containerised.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct NamespaceIds {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub net: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mnt: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cgroup: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipc: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uts: Option<u64>,
}

impl NamespaceIds {
    /// True when no namespace id was resolved (used to omit the field entirely).
    pub fn is_empty(&self) -> bool {
        self.pid.is_none()
            && self.net.is_none()
            && self.mnt.is_none()
            && self.user.is_none()
            && self.cgroup.is_none()
            && self.ipc.is_none()
            && self.uts.is_none()
    }
}

/// A process plus its parent chain, resolved from `/proc` at detection time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessLineage {
    pub pid: i32,
    pub uid: u32,
    pub gid: u32,
    pub username: String,
    pub comm: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exe: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cmdline: Option<String>,
    /// Parent chain, nearest parent first, walking up towards PID 1.
    pub ancestors: Vec<ProcessAncestor>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessAncestor {
    pub pid: i32,
    pub comm: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exe: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cmdline: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetuidData {
    pub pid:     i32,
    pub old_uid: u32,
    pub new_uid: u32,
    pub comm:    String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemfdCreateData {
    pub pid:   i32,
    pub comm:  String,
    pub name:  String,
    pub flags: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryAnomalyData {
    pub pid:    i32,
    pub region: String,
    pub perms:  String,
}

#[cfg(test)]
mod tests;
