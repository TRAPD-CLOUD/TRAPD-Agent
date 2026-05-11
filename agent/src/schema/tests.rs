use uuid::Uuid;

use super::{
    AgentEvent, DnsData, EventAction, EventClass, EventData, FileOpenData, ForkData, MmapData,
    ModuleLoadData, NetworkSocketData, NsChangeData, ProcessCreateData, PtraceData, Severity,
    ShmData, SystemSnapshotData,
};

fn process_create_event() -> AgentEvent {
    AgentEvent::new(
        Uuid::new_v4().to_string(),
        "test-host".to_string(),
        EventClass::Process,
        EventAction::Create,
        Severity::Info,
        EventData::ProcessCreate(ProcessCreateData {
            pid:      1234,
            ppid:     1,
            name:     "nginx".to_string(),
            exe:      "/usr/sbin/nginx".to_string(),
            cmdline:  "nginx -g daemon off;".to_string(),
            uid:      33,
            username: "www-data".to_string(),
        }),
    )
}

#[test]
fn test_agent_event_has_all_required_fields() {
    let event = process_create_event();
    let json  = serde_json::to_string(&event).expect("serialization must succeed");
    let val: serde_json::Value = serde_json::from_str(&json).expect("must be valid JSON");

    assert!(val["event_id"].is_string(),  "event_id must be present");
    assert!(val["agent_id"].is_string(),  "agent_id must be present");
    assert!(val["hostname"].is_string(),  "hostname must be present");
    assert!(val["timestamp"].is_string(), "timestamp must be present");
    assert!(val["class"].is_string(),     "class must be present");
    assert!(val["action"].is_string(),    "action must be present");
    assert!(val["severity"].is_string(),  "severity must be present");
    assert!(val["data"].is_object(),      "data must be present");
}

#[test]
fn test_process_create_class_and_action_strings() {
    let event = process_create_event();
    let json  = serde_json::to_string(&event).expect("serialization must succeed");
    let val: serde_json::Value = serde_json::from_str(&json).expect("must be valid JSON");

    assert_eq!(val["class"],  "process");
    assert_eq!(val["action"], "create");
    assert_eq!(val["data"]["pid"],  1234);
    assert_eq!(val["data"]["name"], "nginx");
    assert_eq!(val["data"]["exe"],  "/usr/sbin/nginx");
}

#[test]
fn test_timestamp_is_rfc3339() {
    let event = process_create_event();
    let json  = serde_json::to_string(&event).expect("serialization must succeed");
    let val: serde_json::Value = serde_json::from_str(&json).expect("must be valid JSON");

    let ts = val["timestamp"].as_str().expect("timestamp must be a string");
    assert!(ts.contains('T'), "RFC3339 timestamps contain 'T' separator");
    chrono::DateTime::parse_from_rfc3339(ts)
        .expect("timestamp must be a valid RFC3339 string");
}

#[test]
fn test_system_snapshot_class_and_action() {
    let event = AgentEvent::new(
        Uuid::new_v4().to_string(),
        "host".to_string(),
        EventClass::System,
        EventAction::Snapshot,
        Severity::Info,
        EventData::SystemSnapshot(SystemSnapshotData {
            os:               "Linux".to_string(),
            kernel:           "6.8.0".to_string(),
            distro:           "Ubuntu 24.04".to_string(),
            cpu_count:        4,
            cpu_usage_pct:    5.0,
            memory_total_mb:  8192,
            memory_used_mb:   4096,
            memory_free_mb:   4096,
            uptime_secs:      3600,
            load_avg:         [0.5, 0.4, 0.3],
        }),
    );

    let json = serde_json::to_string(&event).expect("serialization must succeed");
    let val: serde_json::Value = serde_json::from_str(&json).expect("must be valid JSON");

    assert_eq!(val["class"],  "system");
    assert_eq!(val["action"], "snapshot");
    assert_eq!(val["data"]["os"], "Linux");
}

#[test]
fn test_snake_case_action_variants() {
    let logon_failed = EventAction::LogonFailed;
    let session_open = EventAction::SessionOpen;
    let session_close = EventAction::SessionClose;

    let lf = serde_json::to_string(&logon_failed).expect("must serialize");
    let so = serde_json::to_string(&session_open).expect("must serialize");
    let sc = serde_json::to_string(&session_close).expect("must serialize");

    assert_eq!(lf, r#""logon_failed""#);
    assert_eq!(so, r#""session_open""#);
    assert_eq!(sc, r#""session_close""#);
}

#[test]
fn test_new_ebpf_action_serialization() {
    let cases: &[(&str, EventAction)] = &[
        ("\"open\"",       EventAction::Open),
        ("\"bind\"",       EventAction::Bind),
        ("\"accept\"",     EventAction::Accept),
        ("\"fork\"",       EventAction::Fork),
        ("\"unlink\"",     EventAction::Unlink),
        ("\"rename\"",     EventAction::Rename),
        ("\"chmod\"",      EventAction::Chmod),
        ("\"chown\"",      EventAction::Chown),
        ("\"mmap\"",       EventAction::Mmap),
        ("\"ptrace\"",     EventAction::Ptrace),
        ("\"module_load\"",EventAction::ModuleLoad),
        ("\"shmget\"",     EventAction::Shmget),
        ("\"shmat\"",      EventAction::Shmat),
        ("\"ns_change\"",  EventAction::NsChange),
        ("\"dns_query\"",  EventAction::DnsQuery),
    ];
    for (expected, action) in cases {
        let got = serde_json::to_string(action).expect("must serialize");
        assert_eq!(&got, expected, "wrong serialization for {expected}");
    }
}

#[test]
fn test_new_ebpf_class_serialization() {
    assert_eq!(serde_json::to_string(&EventClass::Memory).unwrap(), r#""memory""#);
    assert_eq!(serde_json::to_string(&EventClass::Kernel).unwrap(), r#""kernel""#);
    assert_eq!(serde_json::to_string(&EventClass::Ipc).unwrap(),    r#""ipc""#);
}

#[test]
fn test_file_open_event_roundtrip() {
    let event = AgentEvent::new(
        Uuid::new_v4().to_string(),
        "host".to_string(),
        EventClass::Filesystem,
        EventAction::Open,
        Severity::Info,
        EventData::FileOpen(FileOpenData {
            pid:      42,
            uid:      1000,
            gid:      1000,
            username: "alice".to_string(),
            comm:     "vim".to_string(),
            path:     "/etc/passwd".to_string(),
            flags:    0x241,
        }),
    );
    let json = serde_json::to_string(&event).expect("must serialize");
    let val: serde_json::Value = serde_json::from_str(&json).expect("must be valid JSON");
    assert_eq!(val["class"],         "filesystem");
    assert_eq!(val["action"],        "open");
    assert_eq!(val["data"]["path"],  "/etc/passwd");
    assert_eq!(val["data"]["pid"],   42);
    assert_eq!(val["data"]["flags"], 0x241_u64);
}

#[test]
fn test_fork_event_roundtrip() {
    let event = AgentEvent::new(
        Uuid::new_v4().to_string(),
        "host".to_string(),
        EventClass::Process,
        EventAction::Fork,
        Severity::Info,
        EventData::Fork(ForkData {
            parent_pid:  100,
            child_pid:   200,
            parent_comm: "bash".to_string(),
            child_comm:  "bash".to_string(),
        }),
    );
    let json = serde_json::to_string(&event).expect("must serialize");
    let val: serde_json::Value = serde_json::from_str(&json).expect("must be valid JSON");
    assert_eq!(val["class"],              "process");
    assert_eq!(val["action"],             "fork");
    assert_eq!(val["data"]["parent_pid"], 100);
    assert_eq!(val["data"]["child_pid"],  200);
}

#[test]
fn test_mmap_event_roundtrip() {
    let event = AgentEvent::new(
        Uuid::new_v4().to_string(),
        "host".to_string(),
        EventClass::Memory,
        EventAction::Mmap,
        Severity::Medium,
        EventData::Mmap(MmapData {
            pid:         1337,
            uid:         0,
            gid:         0,
            username:    "root".to_string(),
            comm:        "loader".to_string(),
            addr:        0x7fff_0000,
            len:         4096,
            prot:        0x4,
            flags:       0x22,
            description: "anon|exec".to_string(),
        }),
    );
    let json = serde_json::to_string(&event).expect("must serialize");
    let val: serde_json::Value = serde_json::from_str(&json).expect("must be valid JSON");
    assert_eq!(val["class"],  "memory");
    assert_eq!(val["action"], "mmap");
    assert_eq!(val["data"]["description"], "anon|exec");
    assert_eq!(val["severity"], "medium");
}

#[test]
fn test_ptrace_event_roundtrip() {
    let event = AgentEvent::new(
        Uuid::new_v4().to_string(),
        "host".to_string(),
        EventClass::Process,
        EventAction::Ptrace,
        Severity::High,
        EventData::Ptrace(PtraceData {
            pid:        666,
            uid:        0,
            gid:        0,
            username:   "root".to_string(),
            comm:       "gdb".to_string(),
            request:    16,
            target_pid: 1000,
        }),
    );
    let json = serde_json::to_string(&event).expect("must serialize");
    let val: serde_json::Value = serde_json::from_str(&json).expect("must be valid JSON");
    assert_eq!(val["class"],              "process");
    assert_eq!(val["action"],             "ptrace");
    assert_eq!(val["severity"],           "high");
    assert_eq!(val["data"]["request"],    16);
    assert_eq!(val["data"]["target_pid"], 1000);
}

#[test]
fn test_module_load_event_roundtrip() {
    let event = AgentEvent::new(
        Uuid::new_v4().to_string(),
        "host".to_string(),
        EventClass::Kernel,
        EventAction::ModuleLoad,
        Severity::High,
        EventData::ModuleLoad(ModuleLoadData {
            pid:      1,
            uid:      0,
            gid:      0,
            username: "root".to_string(),
            name:     "evil_rootkit".to_string(),
            taints:   0,
        }),
    );
    let json = serde_json::to_string(&event).expect("must serialize");
    let val: serde_json::Value = serde_json::from_str(&json).expect("must be valid JSON");
    assert_eq!(val["class"],          "kernel");
    assert_eq!(val["action"],         "module_load");
    assert_eq!(val["data"]["name"],   "evil_rootkit");
    assert_eq!(val["data"]["taints"], 0);
}

#[test]
fn test_network_socket_event_roundtrip() {
    let event = AgentEvent::new(
        Uuid::new_v4().to_string(),
        "host".to_string(),
        EventClass::Network,
        EventAction::Connection,
        Severity::Info,
        EventData::NetworkSocket(NetworkSocketData {
            pid:      42,
            uid:      1000,
            gid:      1000,
            username: "alice".to_string(),
            comm:     "curl".to_string(),
            op:       "connect".to_string(),
            family:   "ipv4".to_string(),
            addr:     "93.184.216.34".to_string(),
            port:     443,
        }),
    );
    let json = serde_json::to_string(&event).expect("must serialize");
    let val: serde_json::Value = serde_json::from_str(&json).expect("must be valid JSON");
    assert_eq!(val["class"],        "network");
    assert_eq!(val["data"]["op"],   "connect");
    assert_eq!(val["data"]["port"], 443);
}

#[test]
fn test_dns_event_roundtrip() {
    let event = AgentEvent::new(
        Uuid::new_v4().to_string(),
        "host".to_string(),
        EventClass::Network,
        EventAction::DnsQuery,
        Severity::Info,
        EventData::Dns(DnsData {
            pid:      99,
            uid:      1000,
            gid:      1000,
            username: "nobody".to_string(),
            comm:     "systemd-resolved".to_string(),
            dst_addr: "8.8.8.8".to_string(),
            dst_port: 53,
        }),
    );
    let json = serde_json::to_string(&event).expect("must serialize");
    let val: serde_json::Value = serde_json::from_str(&json).expect("must be valid JSON");
    assert_eq!(val["class"],            "network");
    assert_eq!(val["action"],           "dns_query");
    assert_eq!(val["data"]["dst_addr"], "8.8.8.8");
    assert_eq!(val["data"]["dst_port"], 53);
}

#[test]
fn test_ns_change_event_roundtrip() {
    let event = AgentEvent::new(
        Uuid::new_v4().to_string(),
        "host".to_string(),
        EventClass::Process,
        EventAction::NsChange,
        Severity::Medium,
        EventData::NsChange(NsChangeData {
            pid:        777,
            uid:        0,
            gid:        0,
            username:   "root".to_string(),
            comm:       "runc".to_string(),
            op:         "unshare".to_string(),
            namespaces: "pid,net,mnt".to_string(),
            flags:      0x6002_0000,
        }),
    );
    let json = serde_json::to_string(&event).expect("must serialize");
    let val: serde_json::Value = serde_json::from_str(&json).expect("must be valid JSON");
    assert_eq!(val["class"],              "process");
    assert_eq!(val["action"],             "ns_change");
    assert_eq!(val["data"]["op"],         "unshare");
    assert_eq!(val["data"]["namespaces"], "pid,net,mnt");
}

#[test]
fn test_shm_event_roundtrip() {
    let event = AgentEvent::new(
        Uuid::new_v4().to_string(),
        "host".to_string(),
        EventClass::Ipc,
        EventAction::Shmget,
        Severity::Low,
        EventData::Shm(ShmData {
            pid:      500,
            uid:      1000,
            gid:      1000,
            username: "bob".to_string(),
            comm:     "app".to_string(),
            op:       "shmget".to_string(),
            key:      12345,
            size:     65536,
            flags:    0o600,
        }),
    );
    let json = serde_json::to_string(&event).expect("must serialize");
    let val: serde_json::Value = serde_json::from_str(&json).expect("must be valid JSON");
    assert_eq!(val["class"],        "ipc");
    assert_eq!(val["action"],       "shmget");
    assert_eq!(val["data"]["key"],  12345);
    assert_eq!(val["data"]["size"], 65536);
}
