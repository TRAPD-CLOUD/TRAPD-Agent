#![no_main]

// Arbitrary bytes from `journalctl --output=json`: journald stores fields
// written by any local process, so every line is attacker-influenced.

use libfuzzer_sys::fuzz_target;
use trapd_schema as schema;

#[allow(dead_code)]
#[path = "../../agent/src/config/logs.rs"]
mod config;
#[allow(dead_code)]
#[path = "../../agent/src/collectors/logs/framing.rs"]
mod framing;
#[path = "../../agent/src/collectors/logs/journal_json.rs"]
mod journal_json;
#[allow(dead_code)]
#[path = "../../agent/src/collectors/logs/parser.rs"]
mod parser;

use parser::ParsedLog;

fuzz_target!(|data: &[u8]| {
    let Ok(line) = std::str::from_utf8(data) else {
        return;
    };
    let Some((parsed, cursor)) = journal_json::parse_journal_json(line) else {
        return;
    };
    // The cursor is the only field the checkpoint trusts; it must come from
    // `__CURSOR` and never stay behind in the forwarded fields.
    assert!(!parsed.fields.contains_key("__CURSOR"));
    let _ = cursor;
    assert_eq!(parsed.category, "syslog");
});
