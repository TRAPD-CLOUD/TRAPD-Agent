#![no_main]

// Arbitrary rendered Windows event XML. Event data fields are written by
// providers and, for some channels, by unprivileged processes.

use libfuzzer_sys::fuzz_target;
use trapd_detection as detection;
use trapd_schema as schema;

mod telemetry {
    pub use trapd_schema::limits;
    pub mod metrics {
        pub struct Metrics;
        impl Metrics {
            pub fn enrichment_truncation(&self) {}
        }
        pub fn metrics() -> Metrics {
            Metrics
        }
    }
}

#[path = "../../agent/src/collectors/windows/eventlog_xml.rs"]
mod eventlog_xml;

const CHANNELS: [&str; 4] = [
    "Security",
    "System",
    "Microsoft-Windows-Sysmon/Operational",
    "Microsoft-Windows-PowerShell/Operational",
];

fuzz_target!(|data: &[u8]| {
    let Some((&selector, rest)) = data.split_first() else {
        return;
    };
    let Ok(xml) = std::str::from_utf8(rest) else {
        return;
    };
    let channel = CHANNELS[usize::from(selector) % CHANNELS.len()];
    let Ok((record_id, log, _auth)) = eventlog_xml::parse(xml, channel) else {
        return;
    };
    // Size limits must hold for any input, or one event can exhaust the queue.
    assert_eq!(log.offset, Some(record_id));
    assert!(log.message.len() <= 64 * 1024);
    assert!(log.fields.len() <= 258);
    for value in log.fields.values() {
        if let Some(text) = value.as_str() {
            assert!(text.len() <= 16 * 1024);
        }
    }
});
