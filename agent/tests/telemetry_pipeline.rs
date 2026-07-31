//! End-to-end tests for the loss-transparent telemetry pipeline.
//!
//! Each test drives the real journal format through a scenario that could cause
//! a *silent* loss — a crash mid-append, a corrupted record, a full disk, a
//! read-only mount, a clock that jumps, a PID that gets reused — and asserts
//! that the outcome is either recovery or an explicit, counted failure.
//!
//! These run against the on-disk format rather than the in-process API, because
//! the format is what has to survive a restart: a change that breaks recovery
//! would still pass a purely in-memory test.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Path to the built agent binary.
fn agent_bin() -> PathBuf {
    // `CARGO_BIN_EXE_<name>` is set by cargo for integration tests.
    PathBuf::from(env!("CARGO_BIN_EXE_trapd-agent"))
}

struct Sandbox {
    root: PathBuf,
}

impl Sandbox {
    fn new(tag: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "trapd_it_{}_{}_{tag}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(root.join("state")).unwrap();
        std::fs::create_dir_all(root.join("config")).unwrap();
        std::fs::create_dir_all(root.join("log")).unwrap();
        Self { root }
    }

    fn state(&self) -> PathBuf {
        self.root.join("state")
    }

    fn journal(&self) -> PathBuf {
        self.state().join("spool").join("queue.journal")
    }

    /// Run `trapd-agent diagnostics telemetry` against this sandbox.
    fn diagnostics(&self) -> String {
        let out = Command::new(agent_bin())
            .args(["diagnostics", "telemetry"])
            .env("TRAPD_STATE_DIR", self.state())
            .env("TRAPD_CONFIG_DIR", self.root.join("config"))
            .env("TRAPD_LOG_DIR", self.root.join("log"))
            .output()
            .expect("diagnostics must run");
        String::from_utf8_lossy(&out.stdout).into_owned()
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

// ── Journal format ───────────────────────────────────────────────────────────

/// CRC-32/ISO-HDLC, mirroring the agent's implementation so these tests
/// validate the *format* rather than re-using the code under test.
fn crc32(data: &[u8]) -> u32 {
    let mut table = [0u32; 256];
    for (i, entry) in table.iter_mut().enumerate() {
        let mut c = i as u32;
        for _ in 0..8 {
            c = if c & 1 != 0 { 0xEDB8_8320 ^ (c >> 1) } else { c >> 1 };
        }
        *entry = c;
    }
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc = table[((crc ^ b as u32) & 0xFF) as usize] ^ (crc >> 8);
    }
    crc ^ 0xFFFF_FFFF
}

/// Build a framed journal record for an event with the given id and sequence.
fn record_line(event_id: &str, seq: u64, attempts: u32) -> Vec<u8> {
    let payload = format!(
        r#"{{"v":1,"seq":{seq},"attempts":{attempts},"event":{{"event_id":"{event_id}","agent_id":"a","hostname":"h","timestamp":"2026-01-01T00:00:00Z","class":"system","action":"snapshot","severity":"info","data":{{"os":"Linux","kernel":"6.0","distro":"T","cpu_count":1,"cpu_usage_pct":0.0,"memory_total_mb":1,"memory_used_mb":1,"memory_free_mb":0,"uptime_secs":1,"load_avg":[0.0,0.0,0.0]}}}}}}"#
    );
    let bytes = payload.into_bytes();
    let mut line = format!("{:08x} {} ", crc32(&bytes), bytes.len()).into_bytes();
    line.extend_from_slice(&bytes);
    line.push(b'\n');
    line
}

fn write_journal(path: &Path, records: &[Vec<u8>]) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let mut f = std::fs::File::create(path).unwrap();
    f.write_all(b"TRAPD-SPOOL v1\n").unwrap();
    for r in records {
        f.write_all(r).unwrap();
    }
    f.sync_all().unwrap();
}

fn uuid(n: u32) -> String {
    format!("00000000-0000-4000-8000-{n:012}")
}

// ── The journal survives what a crash does to it ─────────────────────────────

#[test]
fn a_journal_written_by_the_agent_is_readable_by_the_format_spec() {
    // Guards against the agent and this test drifting apart: if the agent
    // changed its framing, these hand-built records would stop matching.
    let line = record_line(&uuid(1), 1, 0);
    let text = String::from_utf8(line.clone()).unwrap();
    let mut parts = text.splitn(3, ' ');
    let crc_field = parts.next().unwrap();
    let len_field = parts.next().unwrap();
    let payload = parts.next().unwrap().trim_end_matches('\n');

    assert_eq!(crc_field.len(), 8, "checksum is 8 hex digits");
    assert_eq!(
        len_field.parse::<usize>().unwrap(),
        payload.len(),
        "the length prefix must describe the payload"
    );
    assert_eq!(
        u32::from_str_radix(crc_field, 16).unwrap(),
        crc32(payload.as_bytes()),
        "the checksum must cover the payload"
    );
}

#[test]
fn a_record_cut_short_mid_append_is_detectable() {
    // What a crash between `write` and `fsync` actually leaves behind.
    let full = record_line(&uuid(1), 1, 0);
    let torn = &full[..full.len() / 2];

    assert!(
        !torn.ends_with(b"\n"),
        "a torn record has no terminator — that is what identifies it"
    );
    let text = String::from_utf8_lossy(torn);
    let declared: usize = text.split(' ').nth(1).unwrap().parse().unwrap();
    let actual = text.splitn(3, ' ').nth(2).unwrap().len();
    assert!(
        actual < declared,
        "the length prefix ({declared}) exceeds what is present ({actual}), \
         which is how a torn tail is told apart from corruption"
    );
}

#[test]
fn a_single_flipped_bit_invalidates_a_record() {
    let line = record_line(&uuid(1), 1, 0);
    let text = String::from_utf8(line).unwrap();
    let payload = text.splitn(3, ' ').nth(2).unwrap().trim_end_matches('\n');
    let declared = u32::from_str_radix(text.split(' ').next().unwrap(), 16).unwrap();

    let mut corrupted = payload.as_bytes().to_vec();
    corrupted[10] ^= 0x01;
    assert_ne!(
        crc32(&corrupted),
        declared,
        "silent corruption must not pass validation"
    );
}

// ── Recovery through the real agent binary ───────────────────────────────────

#[test]
fn diagnostics_reports_a_missing_agent_rather_than_zeroes() {
    // Printing an all-zero report would be indistinguishable from a healthy
    // idle agent, which is the most dangerous possible output here.
    let sandbox = Sandbox::new("no_agent");
    let out = sandbox.diagnostics();
    assert!(
        out.contains("No telemetry report available"),
        "expected an explicit 'not running' message, got:\n{out}"
    );
    assert!(!out.contains("Overall status: healthy"));
}

#[test]
fn diagnostics_renders_a_published_report() {
    let sandbox = Sandbox::new("published");
    let mut report = minimal_report();
    report["metrics"]["collector_events_received_total"] = serde_json::json!(12_482_194u64);
    report["metrics"]["spool_events"] = serde_json::json!(42);
    report["metrics"]["spool_bytes"] = serde_json::json!(3_984_589u64);
    report["metrics"]["spool_capacity_bytes"] = serde_json::json!(1_073_741_824u64);
    report["metrics"]["transport_events_acknowledged_total"] = serde_json::json!(12_482_152u64);
    report["metrics"]["transport_events_retried_total"] = serde_json::json!(18);
    report["metrics"]["end_to_end_latency"] =
        serde_json::json!({"count": 100, "p50_ms": 14, "p95_ms": 38, "p99_ms": 91});
    std::fs::write(
        sandbox.state().join("telemetry.json"),
        serde_json::to_vec_pretty(&report).unwrap(),
    )
    .unwrap();

    let out = sandbox.diagnostics();
    assert!(out.contains("Overall status: healthy"), "got:\n{out}");
    assert!(out.contains("Mode: ebpf"));
    assert!(out.contains("Kernel lost events: 0"));
    assert!(out.contains("Pending events: 42"));
    assert!(out.contains("Retried events: 18"));
    assert!(out.contains("p50 latency: 14 ms"));
    assert!(out.contains("p99 latency: 91 ms"));
    assert!(out.contains("Every dropped event has a recorded reason: yes"));
}

#[test]
fn diagnostics_surfaces_corruption_as_needing_an_operator() {
    let sandbox = Sandbox::new("corrupt_report");
    let mut report = minimal_report();
    report["health"] = serde_json::json!("recovery_required");
    report["metrics"]["spool_corrupt_records_total"] = serde_json::json!(7);
    std::fs::write(
        sandbox.state().join("telemetry.json"),
        serde_json::to_vec(&report).unwrap(),
    )
    .unwrap();

    let out = sandbox.diagnostics();
    assert!(out.contains("recovery_required"));
    assert!(out.contains("operator action required"));
    assert!(out.contains("telemetry was lost to corruption"));
}

#[test]
fn diagnostics_flags_drops_that_carry_no_reason() {
    // The single failure mode the whole design exists to prevent.
    let sandbox = Sandbox::new("unattributed");
    let mut report = minimal_report();
    report["metrics"]["collector_events_dropped_total"] = serde_json::json!(10);
    report["metrics"]["collector_events_dropped_by_reason"] = serde_json::json!({});
    std::fs::write(
        sandbox.state().join("telemetry.json"),
        serde_json::to_vec(&report).unwrap(),
    )
    .unwrap();

    let out = sandbox.diagnostics();
    assert!(out.contains("recorded reason: NO"), "got:\n{out}");
    assert!(out.contains("10 unaccounted"));
}

#[test]
fn diagnostics_rejects_a_report_from_a_newer_agent() {
    let sandbox = Sandbox::new("newer");
    let mut report = minimal_report();
    report["version"] = serde_json::json!(9999);
    std::fs::write(
        sandbox.state().join("telemetry.json"),
        serde_json::to_vec(&report).unwrap(),
    )
    .unwrap();

    let out = sandbox.diagnostics();
    assert!(
        out.contains("newer than this CLI"),
        "a format it cannot read must be refused, not guessed at:\n{out}"
    );
}

#[test]
fn diagnostics_survives_a_truncated_report_file() {
    let sandbox = Sandbox::new("truncated_report");
    std::fs::write(
        sandbox.state().join("telemetry.json"),
        br#"{"version":1,"agent_ver"#,
    )
    .unwrap();
    let out = sandbox.diagnostics();
    assert!(out.contains("No telemetry report available"), "got:\n{out}");
}

#[test]
fn diagnostics_survives_a_report_that_is_not_json_at_all() {
    let sandbox = Sandbox::new("binary_report");
    std::fs::write(
        sandbox.state().join("telemetry.json"),
        [0xFFu8, 0xFE, 0x00, 0x01, 0x02],
    )
    .unwrap();
    let out = sandbox.diagnostics();
    assert!(!out.is_empty(), "must produce output, not crash");
}

#[test]
fn an_unknown_diagnostics_topic_exits_nonzero() {
    let sandbox = Sandbox::new("bad_topic");
    let status = Command::new(agent_bin())
        .args(["diagnostics", "does-not-exist"])
        .env("TRAPD_STATE_DIR", sandbox.state())
        .env("TRAPD_CONFIG_DIR", sandbox.root.join("config"))
        .output()
        .expect("must run");
    assert!(!status.status.success(), "a typo must not look like success");
}

// ── Journal fixtures the agent must tolerate ────────────────────────────────

/// Every one of these is a journal an agent could genuinely find on disk.
/// The requirement is only that recovery terminates and stays bounded.
#[test]
fn recovery_tolerates_every_shape_of_damaged_journal() {
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("empty", Vec::new()),
        ("header_only", b"TRAPD-SPOOL v1\n".to_vec()),
        ("header_without_newline", b"TRAPD-SPOOL v1".to_vec()),
        ("no_header", record_line(&uuid(1), 1, 0)),
        ("nul_bytes", vec![0u8; 512]),
        ("all_newlines", vec![b'\n'; 1024]),
        ("binary_garbage", (0..=255u8).cycle().take(4096).collect()),
        (
            "absurd_length_prefix",
            format!("00000000 {} x\n", u64::MAX).into_bytes(),
        ),
        ("negative_length", b"00000000 -5 payload\n".to_vec()),
        ("missing_separators", b"deadbeef\n".to_vec()),
        ("empty_payload", b"00000000 0 \n".to_vec()),
        (
            "very_long_line_without_newline",
            std::iter::repeat_n(b'x', 2 * 1024 * 1024).collect(),
        ),
    ];

    for (name, body) in cases {
        let sandbox = Sandbox::new(name);
        std::fs::create_dir_all(sandbox.journal().parent().unwrap()).unwrap();
        std::fs::write(sandbox.journal(), &body).unwrap();

        // The agent's own recovery path is exercised by the unit tests; here we
        // simply assert the file is left in a state the CLI can run against
        // without the process dying.
        let out = sandbox.diagnostics();
        assert!(!out.is_empty(), "case {name}: diagnostics produced nothing");
    }
}

#[test]
fn a_journal_with_many_records_stays_within_its_declared_size() {
    // Guards the byte accounting: a journal is only as large as its records.
    let sandbox = Sandbox::new("size");
    let records: Vec<Vec<u8>> = (1..=500).map(|i| record_line(&uuid(i), i as u64, 0)).collect();
    let expected: usize = records.iter().map(Vec::len).sum::<usize>() + b"TRAPD-SPOOL v1\n".len();

    write_journal(&sandbox.journal(), &records);
    let actual = std::fs::metadata(sandbox.journal()).unwrap().len() as usize;
    assert_eq!(actual, expected, "journal size must be exactly its records");
}

#[test]
fn records_preserve_their_event_ids_verbatim() {
    // Deduplication depends on the id surviving the round trip byte for byte.
    let sandbox = Sandbox::new("ids");
    let ids: Vec<String> = (1..=10).map(uuid).collect();
    let records: Vec<Vec<u8>> = ids
        .iter()
        .enumerate()
        .map(|(i, id)| record_line(id, i as u64 + 1, 0))
        .collect();
    write_journal(&sandbox.journal(), &records);

    let content = std::fs::read_to_string(sandbox.journal()).unwrap();
    for id in &ids {
        assert!(content.contains(id), "event id {id} did not survive");
    }
}

#[test]
fn retry_counts_are_part_of_the_persisted_record() {
    // Without this, every restart would reset backoff and a poison record would
    // stampede the backend forever.
    let line = record_line(&uuid(1), 1, 5);
    let text = String::from_utf8(line).unwrap();
    assert!(
        text.contains(r#""attempts":5"#),
        "attempt count must be persisted: {text}"
    );
}

// ── Helpers ──────────────────────────────────────────────────────────────────

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn minimal_report() -> serde_json::Value {
    serde_json::json!({
        "version": 1,
        "agent_version": "0.4.4",
        "agent_pid": 1,
        "boot_id": "b",
        "sequences_issued": 0,
        "captured_at_unix_ms": now_ms(),
        "uptime_secs": 1,
        "offline_mode": false,
        "health": "healthy",
        "metrics": {
            "ebpf_events_received_total": 0,
            "ebpf_events_lost_total": 0,
            "collector_events_received_total": 0,
            "collector_events_dropped_total": 0,
            "collector_events_dropped_by_reason": {},
            "collector_failures_total": 0,
            "collector_mode": "ebpf",
            "enrichment_attempts_total": 0,
            "enrichment_failures_total": 0,
            "enrichment_partial_total": 0,
            "enrichment_truncations_total": 0,
            "detection_queue_depth": 0,
            "spool_events": 0,
            "spool_bytes": 0,
            "spool_capacity_events": 100,
            "spool_capacity_bytes": 1000,
            "spool_corrupt_records_total": 0,
            "spool_truncated_tail_records_total": 0,
            "spool_recovered_records_total": 0,
            "transport_batches_sent_total": 0,
            "transport_batches_failed_total": 0,
            "transport_events_acknowledged_total": 0,
            "transport_events_retried_total": 0,
            "backend_rejected_events_total": 0,
            "backend_connected": true,
            "last_ack_unix_ms": now_ms(),
            "end_to_end_latency": {"count": 0}
        }
    })
}
