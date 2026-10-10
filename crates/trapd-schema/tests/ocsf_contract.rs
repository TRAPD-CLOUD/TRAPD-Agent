//! Independent source fixtures consumed by scripts/ocsf/validate.py.
use serde_json::{json, Value};
use trapd_schema::{ocsf, EventAction, EventClass};

fn all_eventclass() -> Vec<EventClass> {
    vec![
        EventClass::Process,
        EventClass::Network,
        EventClass::System,
        EventClass::User,
        EventClass::Filesystem,
        EventClass::Memory,
        EventClass::Kernel,
        EventClass::Ipc,
        EventClass::Prevention,
        EventClass::Detection,
        EventClass::Log,
        EventClass::Registry,
    ]
}

fn cover_eventclass(value: &EventClass) {
    match value {
        EventClass::Process => {}
        EventClass::Network => {}
        EventClass::System => {}
        EventClass::User => {}
        EventClass::Filesystem => {}
        EventClass::Memory => {}
        EventClass::Kernel => {}
        EventClass::Ipc => {}
        EventClass::Prevention => {}
        EventClass::Detection => {}
        EventClass::Log => {}
        EventClass::Registry => {}
    }
}

fn all_eventaction() -> Vec<EventAction> {
    vec![
        EventAction::Create,
        EventAction::Terminate,
        EventAction::Exec,
        EventAction::Connection,
        EventAction::Snapshot,
        EventAction::Logon,
        EventAction::LogonFailed,
        EventAction::SessionOpen,
        EventAction::SessionClose,
        EventAction::Delete,
        EventAction::Modify,
        EventAction::Open,
        EventAction::Bind,
        EventAction::Accept,
        EventAction::Fork,
        EventAction::Unlink,
        EventAction::Rename,
        EventAction::Chmod,
        EventAction::Chown,
        EventAction::Mmap,
        EventAction::Ptrace,
        EventAction::ModuleLoad,
        EventAction::Shmget,
        EventAction::Shmat,
        EventAction::NsChange,
        EventAction::DnsQuery,
        EventAction::DnsResponse,
        EventAction::TlsHandshake,
        EventAction::IntegrityViolation,
        EventAction::RansomwareIndicator,
        EventAction::AgentTamper,
        EventAction::WriteRateAnomaly,
        EventAction::KillAttempt,
        EventAction::Setuid,
        EventAction::MemfdCreate,
        EventAction::MemoryAnomaly,
        EventAction::ProcessBlocked,
        EventAction::NetworkIsolated,
        EventAction::NetworkDeisolated,
        EventAction::IpBlocked,
        EventAction::IpUnblocked,
        EventAction::FileQuarantined,
        EventAction::FileRestored,
        EventAction::PolicyUpdated,
        EventAction::CommandRejected,
        EventAction::CommandAccepted,
        EventAction::Detected,
        EventAction::PackageInstalled,
        EventAction::PackageRemoved,
        EventAction::PackageUpgraded,
        EventAction::HoneytokenDeployed,
        EventAction::HoneytokenRevoked,
        EventAction::HoneytokenHealth,
        EventAction::HoneytokenAccess,
        EventAction::ProcessFrozen,
        EventAction::ProcessThawed,
        EventAction::DeceptionEscalation,
        EventAction::EbpfDrops,
        EventAction::Log,
    ]
}

fn cover_eventaction(value: &EventAction) {
    match value {
        EventAction::Create => {}
        EventAction::Terminate => {}
        EventAction::Exec => {}
        EventAction::Connection => {}
        EventAction::Snapshot => {}
        EventAction::Logon => {}
        EventAction::LogonFailed => {}
        EventAction::SessionOpen => {}
        EventAction::SessionClose => {}
        EventAction::Delete => {}
        EventAction::Modify => {}
        EventAction::Open => {}
        EventAction::Bind => {}
        EventAction::Accept => {}
        EventAction::Fork => {}
        EventAction::Unlink => {}
        EventAction::Rename => {}
        EventAction::Chmod => {}
        EventAction::Chown => {}
        EventAction::Mmap => {}
        EventAction::Ptrace => {}
        EventAction::ModuleLoad => {}
        EventAction::Shmget => {}
        EventAction::Shmat => {}
        EventAction::NsChange => {}
        EventAction::DnsQuery => {}
        EventAction::DnsResponse => {}
        EventAction::TlsHandshake => {}
        EventAction::IntegrityViolation => {}
        EventAction::RansomwareIndicator => {}
        EventAction::AgentTamper => {}
        EventAction::WriteRateAnomaly => {}
        EventAction::KillAttempt => {}
        EventAction::Setuid => {}
        EventAction::MemfdCreate => {}
        EventAction::MemoryAnomaly => {}
        EventAction::ProcessBlocked => {}
        EventAction::NetworkIsolated => {}
        EventAction::NetworkDeisolated => {}
        EventAction::IpBlocked => {}
        EventAction::IpUnblocked => {}
        EventAction::FileQuarantined => {}
        EventAction::FileRestored => {}
        EventAction::PolicyUpdated => {}
        EventAction::CommandRejected => {}
        EventAction::CommandAccepted => {}
        EventAction::Detected => {}
        EventAction::PackageInstalled => {}
        EventAction::PackageRemoved => {}
        EventAction::PackageUpgraded => {}
        EventAction::HoneytokenDeployed => {}
        EventAction::HoneytokenRevoked => {}
        EventAction::HoneytokenHealth => {}
        EventAction::HoneytokenAccess => {}
        EventAction::ProcessFrozen => {}
        EventAction::ProcessThawed => {}
        EventAction::DeceptionEscalation => {}
        EventAction::EbpfDrops => {}
        EventAction::Log => {}
    }
}

fn source(class: Value, action: Value, data: Value) -> Value {
    json!({"event_id":"cbd68d02-60d2-4ef7-8ed0-5c763245ffb4", "agent_id":"contract-agent", "hostname":"contract-host",
        "timestamp":"2026-10-09T12:34:56.789Z", "class":class, "action":action, "severity":"medium", "data":data})
}

fn fixture(name: String, source: Value) -> Value {
    let ocsf = ocsf::to_ocsf(&source).unwrap_or_else(|e| panic!("{name}: {e}"));
    json!({"name":name,"source":source,"ocsf":ocsf})
}

#[test]
fn emit_contract() {
    let mut fixtures = Vec::new();
    let data = json!({"pid":123,"ppid":1,"target_pid":124,"child_pid":125,"name":"test-process",
        "exe":"/usr/bin/test","cmdline":"test --fixture","username":"fixture-user","path":"/tmp/fixture.txt",
        "old_path":"/tmp/fixture-old.txt","src_addr":"192.0.2.1","src_port":12345,"dst_addr":"198.51.100.1",
        "dst_port":443,"addr":"127.0.0.1","port":8080,"protocol":"tcp","state":"established",
        "qname":"example.test","qtype":"A","resolved_ips":["203.0.113.1"],"server_addr":"192.0.2.53",
        "client_addr":"192.0.2.1","command_id":"contract-command","success":true,"description":"Fixture"});
    for class in all_eventclass() {
        cover_eventclass(&class);
        for action in all_eventaction() {
            cover_eventaction(&action);
            let c = serde_json::to_value(&class).unwrap();
            let a = serde_json::to_value(&action).unwrap();
            let mut payload = data.clone();
            if a == "logon_failed" {
                payload["success"] = json!(false);
            }
            fixtures.push(fixture(
                format!("matrix/{}/{}", c.as_str().unwrap(), a.as_str().unwrap()),
                source(c, a, payload),
            ));
        }
    }
    // Serialize actual typed collector payloads as well as the exhaustive matrix.
    fixtures.push(fixture(
        "typed/process-create".into(),
        source(
            json!("process"),
            json!("create"),
            serde_json::to_value(trapd_schema::ProcessCreateData {
                pid: 123,
                ppid: 1,
                name: "worker".into(),
                exe: "/usr/bin/worker".into(),
                cmdline: "worker".into(),
                username: "fixture".into(),
                ..Default::default()
            })
            .unwrap(),
        ),
    ));
    fixtures.push(fixture(
        "typed/process-exec".into(),
        source(
            json!("process"),
            json!("exec"),
            serde_json::to_value(trapd_schema::ExecEventData {
                pid: 123,
                ppid: 1,
                comm: "worker".into(),
                exe: "/usr/bin/worker".into(),
                cmdline: "worker".into(),
                username: "fixture".into(),
                ..Default::default()
            })
            .unwrap(),
        ),
    ));
    fixtures.push(fixture(
        "typed/process-terminate".into(),
        source(
            json!("process"),
            json!("terminate"),
            serde_json::to_value(trapd_schema::ProcessTerminateData {
                pid: 123,
                name: "worker".into(),
            })
            .unwrap(),
        ),
    ));
    fixtures.push(fixture(
        "typed/dns-query-without-qname".into(),
        source(
            json!("network"),
            json!("dns_query"),
            serde_json::to_value(trapd_schema::DnsData {
                pid: 123,
                uid: 1000,
                gid: 1000,
                username: "fixture".into(),
                comm: "worker".into(),
                dst_addr: "192.0.2.53".into(),
                dst_port: 53,
            })
            .unwrap(),
        ),
    ));
    fixtures.push(fixture(
        "typed/dns-response".into(),
        source(
            json!("network"),
            json!("dns_response"),
            serde_json::to_value(trapd_schema::DnsResolutionData {
                qname: "example.test".into(),
                qtype: "A".into(),
                resolved_ips: vec!["203.0.113.1".into()],
                cnames: vec![],
                server_addr: "192.0.2.53".into(),
                client_addr: "192.0.2.1".into(),
                transaction_id: 42,
                rcode: "NOERROR".into(),
                pid: None,
                process: None,
                process_start_time: None,
            })
            .unwrap(),
        ),
    ));
    fixtures.push(fixture(
        "typed/file-open".into(),
        source(
            json!("filesystem"),
            json!("open"),
            serde_json::to_value(trapd_schema::FileOpenData {
                pid: 42,
                uid: 1000,
                gid: 1000,
                username: "fixture".into(),
                comm: "cat".into(),
                path: "/tmp/fixture.txt".into(),
                flags: 0,
            })
            .unwrap(),
        ),
    ));
    fixtures.push(fixture(
        "typed/user-logon".into(),
        source(
            json!("user"),
            json!("logon"),
            serde_json::to_value(trapd_schema::UserLogonData {
                username: "fixture".into(),
                src_addr: None,
                src_port: None,
                auth_method: Some("password".into()),
                success: true,
                ..Default::default()
            })
            .unwrap(),
        ),
    ));
    fixtures.push(fixture(
        "typed/system-snapshot".into(),
        source(
            json!("system"),
            json!("snapshot"),
            serde_json::to_value(trapd_schema::SystemSnapshotData {
                os: "Linux".into(),
                kernel: "6.8".into(),
                distro: "Debian".into(),
                cpu_count: 4,
                cpu_usage_pct: 10.0,
                memory_total_mb: 4096,
                memory_used_mb: 1024,
                memory_free_mb: 3072,
                uptime_secs: 3600,
                load_avg: [0.1, 0.2, 0.3],
            })
            .unwrap(),
        ),
    ));
    fixtures.push(fixture(
        "typed/prevention".into(),
        source(
            json!("prevention"),
            json!("process_blocked"),
            serde_json::to_value(trapd_schema::PreventionEventData {
                kind: "process_block".into(),
                target: "123".into(),
                success: true,
                reason: "fixture".into(),
                rule_id: None,
                command_id: Some("contract-command".into()),
                details: Value::Null,
            })
            .unwrap(),
        ),
    ));
    fixtures.push(fixture(
        "typed/detection".into(),
        source(
            json!("detection"),
            json!("detected"),
            serde_json::to_value(trapd_schema::DetectionData {
                rule_id: "fixture.rule".into(),
                title: "Finding title".into(),
                detail: "Finding explanation".into(),
                ..Default::default()
            })
            .unwrap(),
        ),
    ));
    fixtures.push(fixture(
        "typed/network-connection".into(),
        source(
            json!("network"),
            json!("connection"),
            serde_json::to_value(
                serde_json::from_value::<trapd_schema::NetworkConnectionData>(data.clone())
                    .unwrap(),
            )
            .unwrap(),
        ),
    ));
    fixtures.push(fixture(
        "typed/windows-etw-dns".into(),
        source(
            json!("network"),
            json!("dns_response"),
            serde_json::to_value(trapd_schema::DnsResolutionData {
                qname: "actualsource.example".into(),
                qtype: "A".into(),
                resolved_ips: vec!["203.0.113.7".into()],
                cnames: vec![],
                server_addr: "".into(),
                client_addr: "".into(),
                transaction_id: 0,
                rcode: "NOERROR".into(),
                pid: None,
                process: None,
                process_start_time: None,
            })
            .unwrap(),
        ),
    ));
    fixtures.push(fixture(
        "typed/ptrace".into(),
        source(
            json!("process"),
            json!("ptrace"),
            serde_json::to_value(trapd_schema::PtraceData {
                pid: 77,
                uid: 1000,
                gid: 1000,
                username: "fixture".into(),
                comm: "gdb".into(),
                request: 16,
                target_pid: 88,
            })
            .unwrap(),
        ),
    ));
    fixtures.push(fixture(
        "typed/user-logon-failure".into(),
        source(
            json!("user"),
            json!("logon"),
            serde_json::to_value(trapd_schema::UserLogonData {
                username: "fixture".into(),
                src_addr: None,
                src_port: None,
                auth_method: Some("password".into()),
                success: false,
                ..Default::default()
            })
            .unwrap(),
        ),
    ));
    fixtures.push(fixture(
        "typed/process-create-hash".into(),
        source(
            json!("process"),
            json!("create"),
            serde_json::to_value(trapd_schema::ProcessCreateData {
                pid: 123,
                ppid: 1,
                name: "worker".into(),
                exe: "/usr/bin/worker".into(),
                cmdline: "worker".into(),
                username: "fixture".into(),
                exe_sha256: Some("a".repeat(64)),
                ..Default::default()
            })
            .unwrap(),
        ),
    ));
    let mut finding_failure = data.clone();
    finding_failure["success"] = json!(false);
    fixtures.push(fixture(
        "finding/false-outcome".into(),
        source(json!("detection"), json!("detected"), finding_failure),
    ));
    fixtures.push(fixture(
        "typed/user-logon-invalid-ip".into(),
        source(
            json!("user"),
            json!("logon"),
            serde_json::to_value(trapd_schema::UserLogonData {
                username: "fixture".into(),
                src_addr: Some("not-an-ip".into()),
                src_port: None,
                auth_method: Some("password".into()),
                success: true,
                ..Default::default()
            })
            .unwrap(),
        ),
    ));
    fixtures.push(fixture(
        "filesystem/username-only".into(),
        source(
            json!("filesystem"),
            json!("open"),
            json!({"username":"fixture","path":"/tmp/fixture.txt"}),
        ),
    ));
    let mut closed = data.clone();
    closed["state"] = json!("closed");
    fixtures.push(fixture(
        "network/closed".into(),
        source(json!("network"), json!("connection"), closed),
    ));
    let mut no_command = data.clone();
    no_command.as_object_mut().unwrap().remove("command_id");
    fixtures.push(fixture(
        "prevention/local-no-command".into(),
        source(json!("prevention"), json!("process_blocked"), no_command),
    ));
    if let Ok(path) = std::env::var("OCSF_CONTRACT_FIXTURE_FILE") {
        std::fs::write(path, serde_json::to_vec_pretty(&fixtures).unwrap()).unwrap();
    }
    assert!(fixtures.len() > 600);
}

#[test]
fn process_identifier_overflow_is_rejected() {
    for (class, action, data) in [
        ("process", "create", json!({"pid":u64::MAX})),
        ("process", "create", json!({"pid":1,"ppid":u64::MAX})),
        ("process", "ptrace", json!({"pid":u64::MAX,"target_pid":88})),
        (
            "filesystem",
            "open",
            json!({"path":"/tmp/fixture","pid":u64::MAX}),
        ),
        (
            "network",
            "connection",
            json!({"src_addr":"192.0.2.1","pid":u64::MAX}),
        ),
    ] {
        let result = ocsf::to_ocsf(&source(json!(class), json!(action), data));
        assert!(
            result.is_err(),
            "{class}/{action}: overflowing process identifier accepted"
        );
    }
}
