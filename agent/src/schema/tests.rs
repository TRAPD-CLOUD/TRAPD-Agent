use uuid::Uuid;

use super::{
    AgentEvent, DnsData, EbpfDropsData, EventAction, EventClass, EventData, FileOpenData,
    FilesystemEventData, FilesystemOperation, FilesystemSource, ForkData, HoneytokenAccessData,
    IntegrityStatus, MmapData, ModuleLoadData, NamespaceIds, NetworkSocketData, NsChangeData,
    ProcessCreateData, ProcessLineage, PtraceData, SessionContext, Severity, ShmData,
    SystemSnapshotData,
};

fn process_create_event() -> AgentEvent {
    AgentEvent::new(
        Uuid::new_v4().to_string(),
        "test-host".to_string(),
        EventClass::Process,
        EventAction::Create,
        Severity::Info,
        EventData::ProcessCreate(ProcessCreateData {
            pid: 1234,
            ppid: 1,
            name: "nginx".to_string(),
            exe: "/usr/sbin/nginx".to_string(),
            cmdline: "nginx -g daemon off;".to_string(),
            uid: 33,
            username: "www-data".to_string(),
            exe_sha256: None,
            ..Default::default()
        }),
    )
}

#[test]
fn test_agent_event_has_all_required_fields() {
    let event = process_create_event();
    let json = serde_json::to_string(&event).expect("serialization must succeed");
    let val: serde_json::Value = serde_json::from_str(&json).expect("must be valid JSON");

    assert!(val["event_id"].is_string(), "event_id must be present");
    assert!(val["agent_id"].is_string(), "agent_id must be present");
    assert!(val["hostname"].is_string(), "hostname must be present");
    assert!(val["timestamp"].is_string(), "timestamp must be present");
    assert!(val["class"].is_string(), "class must be present");
    assert!(val["action"].is_string(), "action must be present");
    assert!(val["severity"].is_string(), "severity must be present");
    assert!(val["data"].is_object(), "data must be present");
}

#[test]
fn test_process_create_class_and_action_strings() {
    let event = process_create_event();
    let json = serde_json::to_string(&event).expect("serialization must succeed");
    let val: serde_json::Value = serde_json::from_str(&json).expect("must be valid JSON");

    assert_eq!(val["class"], "process");
    assert_eq!(val["action"], "create");
    assert_eq!(val["data"]["pid"], 1234);
    assert_eq!(val["data"]["name"], "nginx");
    assert_eq!(val["data"]["exe"], "/usr/sbin/nginx");
}

#[test]
fn test_timestamp_is_rfc3339() {
    let event = process_create_event();
    let json = serde_json::to_string(&event).expect("serialization must succeed");
    let val: serde_json::Value = serde_json::from_str(&json).expect("must be valid JSON");

    let ts = val["timestamp"]
        .as_str()
        .expect("timestamp must be a string");
    assert!(ts.contains('T'), "RFC3339 timestamps contain 'T' separator");
    chrono::DateTime::parse_from_rfc3339(ts).expect("timestamp must be a valid RFC3339 string");
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
            os: "Linux".to_string(),
            kernel: "6.8.0".to_string(),
            distro: "Ubuntu 24.04".to_string(),
            cpu_count: 4,
            cpu_usage_pct: 5.0,
            memory_total_mb: 8192,
            memory_used_mb: 4096,
            memory_free_mb: 4096,
            uptime_secs: 3600,
            load_avg: [0.5, 0.4, 0.3],
        }),
    );

    let json = serde_json::to_string(&event).expect("serialization must succeed");
    let val: serde_json::Value = serde_json::from_str(&json).expect("must be valid JSON");

    assert_eq!(val["class"], "system");
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
        ("\"open\"", EventAction::Open),
        ("\"bind\"", EventAction::Bind),
        ("\"accept\"", EventAction::Accept),
        ("\"fork\"", EventAction::Fork),
        ("\"unlink\"", EventAction::Unlink),
        ("\"rename\"", EventAction::Rename),
        ("\"chmod\"", EventAction::Chmod),
        ("\"chown\"", EventAction::Chown),
        ("\"mmap\"", EventAction::Mmap),
        ("\"ptrace\"", EventAction::Ptrace),
        ("\"module_load\"", EventAction::ModuleLoad),
        ("\"shmget\"", EventAction::Shmget),
        ("\"shmat\"", EventAction::Shmat),
        ("\"ns_change\"", EventAction::NsChange),
        ("\"dns_query\"", EventAction::DnsQuery),
    ];
    for (expected, action) in cases {
        let got = serde_json::to_string(action).expect("must serialize");
        assert_eq!(&got, expected, "wrong serialization for {expected}");
    }
}

#[test]
fn test_new_ebpf_class_serialization() {
    assert_eq!(
        serde_json::to_string(&EventClass::Memory).unwrap(),
        r#""memory""#
    );
    assert_eq!(
        serde_json::to_string(&EventClass::Kernel).unwrap(),
        r#""kernel""#
    );
    assert_eq!(serde_json::to_string(&EventClass::Ipc).unwrap(), r#""ipc""#);
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
            pid: 42,
            uid: 1000,
            gid: 1000,
            username: "alice".to_string(),
            comm: "vim".to_string(),
            path: "/etc/passwd".to_string(),
            flags: 0x241,
        }),
    );
    let json = serde_json::to_string(&event).expect("must serialize");
    let val: serde_json::Value = serde_json::from_str(&json).expect("must be valid JSON");
    assert_eq!(val["class"], "filesystem");
    assert_eq!(val["action"], "open");
    assert_eq!(val["data"]["path"], "/etc/passwd");
    assert_eq!(val["data"]["pid"], 42);
    assert_eq!(val["data"]["flags"], 0x241_u64);
}

#[test]
fn filesystem_notifications_share_one_wire_model() {
    let event = AgentEvent::new(
        "agent".into(),
        "host".into(),
        EventClass::Filesystem,
        EventAction::Modify,
        Severity::High,
        EventData::Filesystem(FilesystemEventData {
            path: "/etc/ssh/sshd_config".into(),
            operation: FilesystemOperation::Modified,
            source: FilesystemSource::PeriodicScan,
            integrity: IntegrityStatus::Violation,
            expected_hash: Some("old".into()),
            actual_hash: Some("new".into()),
            size_delta: Some(12),
        }),
    );
    let value: serde_json::Value =
        serde_json::from_str(&serde_json::to_string(&event).unwrap()).unwrap();

    assert_eq!(value["action"], "modify");
    assert_eq!(value["data"]["source"], "periodic_scan");
    assert_eq!(value["data"]["integrity"], "violation");
    assert_eq!(value["data"]["expected_hash"], "old");
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
            parent_pid: 100,
            child_pid: 200,
            parent_comm: "bash".to_string(),
            child_comm: "bash".to_string(),
        }),
    );
    let json = serde_json::to_string(&event).expect("must serialize");
    let val: serde_json::Value = serde_json::from_str(&json).expect("must be valid JSON");
    assert_eq!(val["class"], "process");
    assert_eq!(val["action"], "fork");
    assert_eq!(val["data"]["parent_pid"], 100);
    assert_eq!(val["data"]["child_pid"], 200);
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
            pid: 1337,
            uid: 0,
            gid: 0,
            username: "root".to_string(),
            comm: "loader".to_string(),
            addr: 0x7fff_0000,
            len: 4096,
            prot: 0x4,
            flags: 0x22,
            description: "anon|exec".to_string(),
        }),
    );
    let json = serde_json::to_string(&event).expect("must serialize");
    let val: serde_json::Value = serde_json::from_str(&json).expect("must be valid JSON");
    assert_eq!(val["class"], "memory");
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
            pid: 666,
            uid: 0,
            gid: 0,
            username: "root".to_string(),
            comm: "gdb".to_string(),
            request: 16,
            target_pid: 1000,
        }),
    );
    let json = serde_json::to_string(&event).expect("must serialize");
    let val: serde_json::Value = serde_json::from_str(&json).expect("must be valid JSON");
    assert_eq!(val["class"], "process");
    assert_eq!(val["action"], "ptrace");
    assert_eq!(val["severity"], "high");
    assert_eq!(val["data"]["request"], 16);
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
            pid: 1,
            uid: 0,
            gid: 0,
            username: "root".to_string(),
            name: "evil_rootkit".to_string(),
            taints: 0,
        }),
    );
    let json = serde_json::to_string(&event).expect("must serialize");
    let val: serde_json::Value = serde_json::from_str(&json).expect("must be valid JSON");
    assert_eq!(val["class"], "kernel");
    assert_eq!(val["action"], "module_load");
    assert_eq!(val["data"]["name"], "evil_rootkit");
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
            pid: 42,
            uid: 1000,
            gid: 1000,
            username: "alice".to_string(),
            comm: "curl".to_string(),
            op: "connect".to_string(),
            family: "ipv4".to_string(),
            addr: "93.184.216.34".to_string(),
            port: 443,
        }),
    );
    let json = serde_json::to_string(&event).expect("must serialize");
    let val: serde_json::Value = serde_json::from_str(&json).expect("must be valid JSON");
    assert_eq!(val["class"], "network");
    assert_eq!(val["data"]["op"], "connect");
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
            pid: 99,
            uid: 1000,
            gid: 1000,
            username: "nobody".to_string(),
            comm: "systemd-resolved".to_string(),
            dst_addr: "8.8.8.8".to_string(),
            dst_port: 53,
        }),
    );
    let json = serde_json::to_string(&event).expect("must serialize");
    let val: serde_json::Value = serde_json::from_str(&json).expect("must be valid JSON");
    assert_eq!(val["class"], "network");
    assert_eq!(val["action"], "dns_query");
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
            pid: 777,
            uid: 0,
            gid: 0,
            username: "root".to_string(),
            comm: "runc".to_string(),
            op: "unshare".to_string(),
            namespaces: "pid,net,mnt".to_string(),
            flags: 0x6002_0000,
        }),
    );
    let json = serde_json::to_string(&event).expect("must serialize");
    let val: serde_json::Value = serde_json::from_str(&json).expect("must be valid JSON");
    assert_eq!(val["class"], "process");
    assert_eq!(val["action"], "ns_change");
    assert_eq!(val["data"]["op"], "unshare");
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
            pid: 500,
            uid: 1000,
            gid: 1000,
            username: "bob".to_string(),
            comm: "app".to_string(),
            op: "shmget".to_string(),
            key: 12345,
            size: 65536,
            flags: 0o600,
        }),
    );
    let json = serde_json::to_string(&event).expect("must serialize");
    let val: serde_json::Value = serde_json::from_str(&json).expect("must be valid JSON");
    assert_eq!(val["class"], "ipc");
    assert_eq!(val["action"], "shmget");
    assert_eq!(val["data"]["key"], 12345);
    assert_eq!(val["data"]["size"], 65536);
}

#[test]
fn test_ebpf_drops_event_roundtrip() {
    // The eBPF ring-buffer drop report (issue #52): a System-class observability
    // event carrying per-program cumulative drop counts plus the interval delta.
    let mut per_program = std::collections::BTreeMap::new();
    per_program.insert("exec".to_string(), 42u64);
    per_program.insert("dns".to_string(), 7u64);
    let event = AgentEvent::new(
        Uuid::new_v4().to_string(),
        "host".to_string(),
        EventClass::System,
        EventAction::EbpfDrops,
        Severity::Medium,
        EventData::EbpfDrops(EbpfDropsData {
            per_program,
            total: 49,
            delta: 5,
        }),
    );
    let json = serde_json::to_string(&event).expect("must serialize");
    let val: serde_json::Value = serde_json::from_str(&json).expect("must be valid JSON");
    assert_eq!(val["class"], "system");
    assert_eq!(val["action"], "ebpf_drops");
    assert_eq!(val["data"]["total"], 49);
    assert_eq!(val["data"]["delta"], 5);
    assert_eq!(val["data"]["per_program"]["exec"], 42);
    assert_eq!(val["data"]["per_program"]["dns"], 7);
}

#[test]
fn test_honeytoken_access_event_with_session_roundtrip() {
    // Exercises the boxed `HoneytokenAccess` variant and the point-5 session
    // forensics: it must serialize and deserialize losslessly.
    let session = SessionContext {
        loginuid: Some(1000),
        login_user: Some("alice".to_string()),
        audit_session_id: Some(42),
        tty: Some("pts/3".to_string()),
        cwd: Some("/home/alice".to_string()),
        cgroup: Some("/system.slice/sshd.service".to_string()),
        container_id: None,
        container_runtime: None,
        namespaces: NamespaceIds {
            net: Some(4026531992),
            ..Default::default()
        },
        remote_addr: Some("203.0.113.7".to_string()),
        remote_port: Some(40222),
    };
    let data = HoneytokenAccessData {
        token_id: "tok-1".to_string(),
        path: "/home/alice/.aws/credentials".to_string(),
        kind: "aws_credentials".to_string(),
        access_kind: "open".to_string(),
        open_flags: 0,
        confidence: 100,
        mitre_tactic: "TA0006 Credential Access".to_string(),
        mitre_technique: "T1552.001".to_string(),
        accessor: ProcessLineage {
            pid: 4242,
            uid: 1000,
            gid: 1000,
            username: "alice".to_string(),
            comm: "cat".to_string(),
            exe: Some("/bin/cat".to_string()),
            cmdline: Some("cat .aws/credentials".to_string()),
            ancestors: Vec::new(),
        },
        session: Some(session),
    };
    let event = AgentEvent::new(
        Uuid::new_v4().to_string(),
        "test-host".to_string(),
        EventClass::Detection,
        EventAction::HoneytokenAccess,
        Severity::Critical,
        EventData::HoneytokenAccess(Box::new(data)),
    );

    // `EventData` is `#[serde(untagged)]` — the backend routes by class+action,
    // so (like the other schema tests) we assert the serialized JSON shape.
    let json = serde_json::to_string(&event).expect("must serialize");
    let val: serde_json::Value = serde_json::from_str(&json).expect("must be valid JSON");
    assert_eq!(val["class"], "detection");
    assert_eq!(val["action"], "honeytoken_access");
    assert_eq!(val["data"]["confidence"], 100);
    assert_eq!(val["data"]["session"]["login_user"], "alice");
    assert_eq!(val["data"]["session"]["tty"], "pts/3");
    assert_eq!(val["data"]["session"]["remote_addr"], "203.0.113.7");
    assert_eq!(val["data"]["session"]["remote_port"], 40222);
    assert_eq!(val["data"]["session"]["namespaces"]["net"], 4026531992u64);
    // An unset namespace id is omitted entirely (skip_serializing_if).
    assert!(val["data"]["session"]["namespaces"].get("mnt").is_none());
}

#[test]
fn test_point5_event_actions_serialize_snake_case() {
    for (action, want) in [
        (EventAction::ProcessFrozen, "process_frozen"),
        (EventAction::ProcessThawed, "process_thawed"),
        (EventAction::DeceptionEscalation, "deception_escalation"),
    ] {
        let json = serde_json::to_string(&action).expect("serialize action");
        assert_eq!(json, format!("\"{want}\""));
    }
}

// ── Event identity & provenance ──────────────────────────────────────────────

/// Build an exec event with the given command line and enrichment notes.
fn exec_event(cmdline: &str, enrichment: crate::telemetry::Enrichment) -> AgentEvent {
    AgentEvent::new(
        "agent-1".into(),
        "host-1".into(),
        EventClass::Process,
        EventAction::Exec,
        Severity::Info,
        EventData::ProcessExec(Box::new(super::ExecEventData {
            pid: 1234,
            ppid: 1,
            cmdline: cmdline.into(),
            exe: "/usr/bin/bash".into(),
            comm: "bash".into(),
            process_start_time: Some(987_654),
            parent_start_time: Some(12),
            enrichment,
            ..Default::default()
        })),
    )
}

#[test]
fn every_event_carries_provenance() {
    let event = process_create_event();
    let val: serde_json::Value =
        serde_json::from_str(&serde_json::to_string(&event).unwrap()).unwrap();

    let origin = &val["origin"];
    assert!(origin["boot_id"].is_string(), "boot_id must be present");
    assert!(
        origin["sequence_number"].as_u64().unwrap() > 0,
        "sequence numbers start at 1 so a gap is detectable"
    );
    assert!(
        origin["monotonic_timestamp_ns"].as_u64().unwrap() > 0,
        "a wall-clock step must not be able to reorder events"
    );
}

#[test]
fn sequence_numbers_increase_across_events() {
    let a = process_create_event();
    let b = process_create_event();
    assert!(
        b.sequence_number().unwrap() > a.sequence_number().unwrap(),
        "consecutive events must take consecutive sequence numbers"
    );
}

#[test]
fn event_ids_are_unique_per_event() {
    let a = process_create_event();
    let b = process_create_event();
    assert_ne!(a.event_id, b.event_id);
}

#[test]
fn with_source_names_the_collector_without_reassigning_identity() {
    let event = process_create_event();
    let id = event.event_id;
    let seq = event.sequence_number();

    let tagged = event.with_source("ebpf_exec");
    assert_eq!(
        tagged.origin.as_ref().unwrap().source.as_deref(),
        Some("ebpf_exec")
    );
    assert_eq!(tagged.event_id, id, "tagging must not mint a new event_id");
    assert_eq!(
        tagged.sequence_number(),
        seq,
        "nor consume another sequence"
    );
}

#[test]
fn process_events_carry_a_start_time_for_pid_reuse() {
    let val: serde_json::Value = serde_json::from_str(
        &serde_json::to_string(&exec_event("bash -i", Default::default())).unwrap(),
    )
    .unwrap();
    assert_eq!(
        val["data"]["process_start_time"], 987_654,
        "a bare PID is not an identity — the start time is what disambiguates reuse"
    );
    assert_eq!(val["data"]["parent_start_time"], 12);
}

// ── Enrichment on the wire ───────────────────────────────────────────────────

#[test]
fn a_fully_enriched_event_carries_no_enrichment_overhead() {
    let event = exec_event("bash -i", crate::telemetry::Enrichment::new().finish(3));
    let val: serde_json::Value =
        serde_json::from_str(&serde_json::to_string(&event).unwrap()).unwrap();

    assert!(val["data"]["enrichment_status"].is_null());
    assert!(val["data"]["enrichment_errors"].is_null());
    assert!(val["data"]["truncated_fields"].is_null());
    assert_eq!(val["data"]["cmdline"], "bash -i");
}

#[test]
fn a_partially_enriched_event_says_which_field_failed_and_why() {
    // The raw kernel record still ships; only the /proc-sourced field is
    // missing, and it says so.
    let mut notes = crate::telemetry::Enrichment::new();
    notes.fail("cmdline", crate::telemetry::EnrichmentError::ProcessExited);
    let event = exec_event("", notes.finish(3));

    let val: serde_json::Value =
        serde_json::from_str(&serde_json::to_string(&event).unwrap()).unwrap();
    assert_eq!(val["data"]["enrichment_status"], "partial");
    assert_eq!(
        val["data"]["enrichment_errors"]["cmdline"],
        "process_exited"
    );
    assert_eq!(
        val["data"]["exe"], "/usr/bin/bash",
        "the kernel-sourced fields must survive an enrichment failure"
    );
    assert_eq!(val["data"]["pid"], 1234);
}

#[test]
fn a_truncated_command_line_is_marked_with_both_lengths() {
    let long = "a".repeat(131_072);
    let (cut, truncation) =
        crate::telemetry::limits::truncate_str(&long, crate::telemetry::limits::MAX_CMDLINE_BYTES);
    let mut notes = crate::telemetry::Enrichment::new();
    notes.truncated("cmdline", truncation);
    let event = exec_event(&cut, notes.finish(3));

    let val: serde_json::Value =
        serde_json::from_str(&serde_json::to_string(&event).unwrap()).unwrap();
    let marker = &val["data"]["truncated_fields"]["cmdline"];
    assert_eq!(marker["truncated"], true);
    assert_eq!(marker["original_length"], 131_072);
    assert_eq!(marker["captured_length"], 16_384);
    assert_eq!(
        val["data"]["cmdline"].as_str().unwrap().len(),
        16_384,
        "the captured prefix must match what the marker claims"
    );
}

// ── Round-tripping (the journal replays these) ───────────────────────────────

#[test]
fn an_event_with_enrichment_notes_round_trips() {
    // `EventData` is an untagged enum and the enrichment block is flattened
    // into it, which is exactly the combination most likely to break silently.
    let mut notes = crate::telemetry::Enrichment::new();
    notes.fail("cwd", crate::telemetry::EnrichmentError::PermissionDenied);
    notes.truncated(
        "cmdline",
        Some(crate::telemetry::limits::Truncation::new(100, 10)),
    );
    let event = exec_event("aaaaaaaaaa", notes.finish(3));

    let json = serde_json::to_string(&event).unwrap();
    let back: AgentEvent = serde_json::from_str(&json).expect("must round-trip");

    assert_eq!(back.event_id, event.event_id);
    assert_eq!(back.sequence_number(), event.sequence_number());
    let EventData::ProcessExec(data) = &back.data else {
        panic!(
            "untagged deserialization picked the wrong variant: {:?}",
            back.data
        );
    };
    assert_eq!(data.pid, 1234);
    assert_eq!(data.process_start_time, Some(987_654));
    assert_eq!(
        data.enrichment.status(),
        crate::telemetry::enrichment::EnrichmentStatus::Partial
    );
    assert_eq!(
        data.enrichment.enrichment_errors["cwd"],
        crate::telemetry::EnrichmentError::PermissionDenied
    );
    assert_eq!(
        data.enrichment.truncated_fields["cmdline"].original_length,
        100
    );
}

#[test]
fn an_event_without_the_new_fields_still_parses() {
    // Journals written by an older agent must remain replayable — otherwise an
    // upgrade would discard every queued event.
    let legacy = r#"{
        "event_id": "6f1c9b1e-0000-4000-8000-000000000001",
        "agent_id": "a",
        "hostname": "h",
        "timestamp": "2026-01-01T00:00:00Z",
        "class": "process",
        "action": "create",
        "severity": "info",
        "data": {
            "pid": 7, "ppid": 1, "name": "sh", "exe": "/bin/sh",
            "cmdline": "sh", "uid": 0, "username": "root"
        }
    }"#;

    let event: AgentEvent = serde_json::from_str(legacy).expect("legacy events must still parse");
    assert!(event.origin.is_none(), "absent provenance stays absent");
    let EventData::ProcessCreate(data) = &event.data else {
        panic!("wrong variant: {:?}", event.data);
    };
    assert_eq!(data.pid, 7);
    assert_eq!(data.process_start_time, None);
    assert!(data.enrichment.is_clean());
}
