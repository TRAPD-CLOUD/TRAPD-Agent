use uuid::Uuid;

use super::{
    AgentEvent, EventAction, EventClass, EventData, ProcessCreateData, Severity,
    SystemSnapshotData,
};

fn process_create_event() -> AgentEvent {
    AgentEvent::new(
        Uuid::new_v4(),
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
        Uuid::new_v4(),
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
