#![no_main]

use libfuzzer_sys::fuzz_target;
use trapd_schema as schema;
mod telemetry {
    pub use trapd_schema::limits;
}

#[allow(dead_code)]
#[path = "../../agent/src/pipeline/journal.rs"]
mod journal;

fuzz_target!(|fields: [u8; 16]| {
    let mut sequence = [0; 8];
    sequence.copy_from_slice(&fields[..8]);
    let sequence = u64::from_le_bytes(sequence);
    let attempts = u32::from_le_bytes([fields[8], fields[9], fields[10], fields[11]]);
    // Keep UUID and timestamps fixed across replays of the same generator input.
    let event = serde_json::from_value(serde_json::json!({
        "event_id":"a2522ab9-4f09-4c6f-93cb-61f91c716224",
        "agent_id":"agent-1","hostname":format!("host-{}", u16::from_le_bytes([fields[14], fields[15]])),"timestamp":"2024-01-15T12:00:00Z",
        "class":"system","action":"snapshot","severity":"info",
        "data":{"os":"Linux","kernel":"6.0","distro":"Test","cpu_count":1,
            "cpu_usage_pct":0.0,"memory_total_mb":255,"memory_used_mb":fields[12],
            "memory_free_mb":255-fields[12],"uptime_secs":sequence,"load_avg":[0.0,0.0,0.0]}
    }))
    .unwrap();
    let mut record = journal::JournalRecord::new(sequence, event);
    record.attempts = attempts;
    let framed = journal::encode(&record).unwrap();
    let mut line = Vec::new();
    let chunk = usize::from(fields[13]) + 1;
    let mut reader = std::io::BufReader::with_capacity(chunk, framed.as_slice());
    assert_eq!(
        journal::read_line_bounded(&mut reader, schema::limits::MAX_RECORD_BYTES, &mut line)
            .unwrap(),
        journal::LineRead::Complete
    );
    let journal::RecordOutcome::Valid(recovered) = journal::decode(&line, true) else {
        panic!("encoded system snapshot failed journal recovery");
    };
    assert_eq!(journal::encode(&recovered).unwrap(), framed);
});
