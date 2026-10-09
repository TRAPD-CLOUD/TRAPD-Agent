use std::{
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::Instant,
};
use trapd_detection::{
    gate::{FindingGate, SuppressionAction, SuppressionRule},
    runtime::{Paths, Runtime},
    DetectionEngine,
};
use trapd_schema::{
    AgentEvent, DetectionData, DetectionMode, EventAction, EventClass, EventData, Severity,
};
#[derive(Default)]
struct Host {
    suppressed: AtomicU64,
    aggregated: AtomicU64,
    shadows: AtomicU64,
    writes: Mutex<Vec<(PathBuf, Vec<u8>)>>,
}
impl Runtime for Host {
    fn detection_suppressed(&self) {
        self.suppressed.fetch_add(1, Ordering::Relaxed);
    }
    fn detection_aggregated(&self) {
        self.aggregated.fetch_add(1, Ordering::Relaxed);
    }
    fn shadow_hit(&self, _rule: &str) {
        self.shadows.fetch_add(1, Ordering::Relaxed);
    }
    fn write_baseline(&self, path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
        self.writes
            .lock()
            .unwrap()
            .push((path.into(), bytes.into()));
        Ok(())
    }
}
fn finding(mode: DetectionMode) -> AgentEvent {
    AgentEvent::new(
        "agent".into(),
        "host".into(),
        EventClass::Detection,
        EventAction::Detected,
        Severity::High,
        EventData::Detection(Box::new(DetectionData {
            rule_id: "test.rule".into(),
            dedup_key: Some("same".into()),
            mode: Some(mode),
            ..Default::default()
        })),
    )
}
#[test]
fn gate_reports_shadow_suppression_and_aggregation_to_host() {
    let host = Arc::new(Host::default());
    let mut gate = FindingGate::with_runtime(host.clone());
    let now = Instant::now();
    assert!(gate.admit(finding(DetectionMode::Shadow), now).is_empty());
    let rule: SuppressionRule =
        serde_json::from_value(serde_json::json!({"id":"s", "rule":"test.*", "action":"drop"}))
            .unwrap();
    assert_eq!(rule.action, SuppressionAction::Drop);
    gate.set_suppressions(vec![rule]);
    assert!(gate.admit(finding(DetectionMode::Alert), now).is_empty());
    gate.set_suppressions(vec![]);
    assert_eq!(gate.admit(finding(DetectionMode::Alert), now).len(), 1);
    assert!(gate.admit(finding(DetectionMode::Alert), now).is_empty());
    assert_eq!(gate.flush(now, true).len(), 1);
    assert_eq!(host.shadows.load(Ordering::Relaxed), 1);
    assert_eq!(host.suppressed.load(Ordering::Relaxed), 1);
    assert_eq!(host.aggregated.load(Ordering::Relaxed), 2);
}
#[test]
fn engine_loads_explicit_ioc_path_and_delegates_baseline_persistence() {
    let dir = std::env::temp_dir().join(format!("trapd-crate-test-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&dir).unwrap();
    let iocs = dir.join("iocs.json");
    std::fs::write(&iocs, br#"{"ips":["203.0.113.5"]}"#).unwrap();
    let baseline = dir.join("baseline.json");
    let host = Arc::new(Host::default());
    let engine = DetectionEngine::with_runtime(
        "a".into(),
        "h".into(),
        Paths {
            iocs: Some(iocs.clone()),
            baseline: Some(baseline.clone()),
            sigma: None,
        },
        host.clone(),
    );
    assert_eq!(engine.ioc_count(), 1);
    std::fs::write(&iocs, br#"{"ips":["203.0.113.5","203.0.113.6"]}"#).unwrap();
    engine.reload_iocs();
    assert_eq!(engine.ioc_count(), 2);
    engine.persist_baseline();
    let writes = host.writes.lock().unwrap();
    assert_eq!(writes.len(), 1);
    assert_eq!(writes[0].0, baseline);
    assert!(serde_json::from_slice::<serde_json::Value>(&writes[0].1).is_ok());
    drop(writes);
    std::fs::remove_dir_all(dir).unwrap();
}
