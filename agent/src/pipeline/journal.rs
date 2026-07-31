//! On-disk record framing for the persistent queue.
//!
//! The journal is an append-only file of length-prefixed, CRC-checked records.
//! Its job is to make a crash recoverable *and legible*: after an unclean stop
//! the agent must be able to say, for every byte in the file, whether it is a
//! good record, a record damaged by the storage layer, or the expected torn
//! tail of an interrupted append — and those three cases have different
//! meanings, so they are never collapsed into "skip the bad line".
//!
//! ## Record format
//!
//! ```text
//! TRAPD-SPOOL v1\n            ← file header, once
//! <crc32:8hex> <len:dec> <payload-json>\n
//! ```
//!
//! - `crc32` is CRC-32/ISO-HDLC over the payload bytes.
//! - `len` is the payload length in bytes, validated **before** any allocation.
//! - The payload is compact JSON, which never contains a literal newline (they
//!   are escaped inside strings), so the framing stays unambiguous.
//!
//! Both a checksum *and* a length are carried because they fail differently: a
//! wrong length identifies a record cut short by a crash mid-`write`, while a
//! wrong checksum identifies content silently altered on disk. Distinguishing
//! them is what lets an interrupted append be treated as normal (the last
//! record simply never completed) while real corruption escalates to
//! `recovery_required`.

use std::io::{self, BufRead};

use serde::{Deserialize, Serialize};

use crate::schema::AgentEvent;
use crate::telemetry::limits::MAX_RECORD_BYTES;

/// File header identifying the format and its version.
pub const JOURNAL_HEADER: &str = "TRAPD-SPOOL v1";

/// Record schema version.  A record carrying a higher version is counted as
/// [`crate::telemetry::DropReason::UnsupportedEventVersion`] rather than being
/// parsed on a guess.
pub const RECORD_VERSION: u32 = 1;

/// A queued event plus the delivery state that has to survive a restart.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JournalRecord {
    /// Record schema version.
    pub v: u32,
    /// Position in the spool's own ordering; the handle used to acknowledge.
    pub seq: u64,
    /// Delivery attempts so far.  Persisted so a poison record does not reset
    /// its backoff every time the agent restarts.
    #[serde(default)]
    pub attempts: u32,
    /// The event itself.  Its `event_id` is assigned once at creation and is
    /// never regenerated here — that stability is what makes backend
    /// deduplication work across retries and restarts.
    pub event: AgentEvent,
}

impl JournalRecord {
    /// Used by the recovery tests to build fixtures; the spool constructs
    /// records inline so it can reuse an already-serialized event.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn new(seq: u64, event: AgentEvent) -> Self {
        Self {
            v: RECORD_VERSION,
            seq,
            attempts: 0,
            event,
        }
    }
}

/// Outcome of parsing one line from the journal.
#[derive(Debug)]
pub enum RecordOutcome {
    /// A valid record.
    Valid(Box<JournalRecord>),
    /// Framing intact but the checksum did not match, or the payload was not
    /// parseable — the storage layer altered the bytes.
    Corrupt(&'static str),
    /// The final record of a file cut short mid-append.  Expected after a
    /// crash, and **not** counted as corruption.
    TruncatedTail,
    /// A record schema version this build cannot read.
    UnsupportedVersion(u32),
    /// A blank line (e.g. trailing newline at EOF).
    Blank,
}

/// Serialize a record into its framed on-disk form, including the trailing
/// newline.
pub fn encode(record: &JournalRecord) -> Result<Vec<u8>, serde_json::Error> {
    let payload = serde_json::to_vec(record)?;
    let crc = crc32(&payload);
    let mut out = Vec::with_capacity(payload.len() + 24);
    out.extend_from_slice(format!("{crc:08x} {} ", payload.len()).as_bytes());
    out.extend_from_slice(&payload);
    out.push(b'\n');
    Ok(out)
}

/// Parse one framed line.
///
/// `line` excludes the trailing newline.  `saw_newline` reports whether the
/// reader actually found a terminator: without one, this is the torn tail of an
/// interrupted append rather than damaged content.
pub fn decode(line: &[u8], saw_newline: bool) -> RecordOutcome {
    if line.is_empty() {
        return RecordOutcome::Blank;
    }

    // Split `<crc> <len> <payload>` — exactly two spaces before the payload,
    // and the payload may itself contain spaces.
    let Some(sp1) = line.iter().position(|&b| b == b' ') else {
        return if saw_newline {
            RecordOutcome::Corrupt("missing checksum separator")
        } else {
            RecordOutcome::TruncatedTail
        };
    };
    let rest = &line[sp1 + 1..];
    let Some(sp2) = rest.iter().position(|&b| b == b' ') else {
        return if saw_newline {
            RecordOutcome::Corrupt("missing length separator")
        } else {
            RecordOutcome::TruncatedTail
        };
    };

    let crc_field = &line[..sp1];
    let len_field = &rest[..sp2];
    let payload = &rest[sp2 + 1..];

    let Some(expected_crc) = std::str::from_utf8(crc_field)
        .ok()
        .and_then(|s| u32::from_str_radix(s, 16).ok())
    else {
        return RecordOutcome::Corrupt("unparseable checksum field");
    };

    let Some(expected_len) = std::str::from_utf8(len_field)
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
    else {
        return RecordOutcome::Corrupt("unparseable length field");
    };

    // Validate the declared length *before* trusting it for anything. A corrupt
    // prefix must never drive an allocation.
    if expected_len > MAX_RECORD_BYTES {
        return RecordOutcome::Corrupt("declared length exceeds the record limit");
    }

    if payload.len() != expected_len {
        // Short payload with no terminator is the classic interrupted append.
        return if !saw_newline && payload.len() < expected_len {
            RecordOutcome::TruncatedTail
        } else {
            RecordOutcome::Corrupt("payload length does not match its prefix")
        };
    }

    if crc32(payload) != expected_crc {
        return RecordOutcome::Corrupt("checksum mismatch");
    }

    match serde_json::from_slice::<JournalRecord>(payload) {
        Ok(rec) if rec.v > RECORD_VERSION => RecordOutcome::UnsupportedVersion(rec.v),
        Ok(rec) => RecordOutcome::Valid(Box::new(rec)),
        // A payload that checksums correctly but will not parse means the
        // schema moved under us, not that the disk lied.
        Err(_) => RecordOutcome::Corrupt("payload is not a valid record"),
    }
}

/// Result of reading one line with a hard length bound.
#[derive(Debug, PartialEq, Eq)]
pub enum LineRead {
    /// A complete, newline-terminated line.
    Complete,
    /// Bytes were present but the file ended without a newline.
    Unterminated,
    /// The line exceeded the byte bound; it was skipped without buffering.
    Overlong,
    /// End of file with nothing pending.
    Eof,
}

/// Read one line into `out`, never buffering more than `max` bytes.
///
/// `BufRead::read_until` grows its buffer without limit, so a journal with a
/// corrupt (or maliciously crafted) length prefix and no newline could drive an
/// unbounded allocation during recovery. This variant caps the buffer and skips
/// the remainder of an overlong line instead.
pub fn read_line_bounded<R: BufRead>(
    reader: &mut R,
    max: usize,
    out: &mut Vec<u8>,
) -> io::Result<LineRead> {
    out.clear();
    let mut overlong = false;

    loop {
        let available = match reader.fill_buf() {
            Ok(b) => b,
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };

        if available.is_empty() {
            return Ok(if overlong {
                LineRead::Overlong
            } else if out.is_empty() {
                LineRead::Eof
            } else {
                LineRead::Unterminated
            });
        }

        match available.iter().position(|&b| b == b'\n') {
            Some(idx) => {
                if !overlong {
                    if out.len() + idx > max {
                        out.clear();
                        overlong = true;
                    } else {
                        out.extend_from_slice(&available[..idx]);
                    }
                }
                reader.consume(idx + 1);
                return Ok(if overlong {
                    LineRead::Overlong
                } else {
                    LineRead::Complete
                });
            }
            None => {
                let n = available.len();
                if !overlong {
                    if out.len() + n > max {
                        // Stop buffering, but keep scanning for the terminator
                        // so the next record is still found.
                        out.clear();
                        overlong = true;
                    } else {
                        out.extend_from_slice(available);
                    }
                }
                reader.consume(n);
            }
        }
    }
}

/// CRC-32/ISO-HDLC (the `zlib`/`gzip` polynomial), computed with a lazily-built
/// lookup table.
///
/// Implemented here rather than pulled in as a dependency: it is ~20 lines, it
/// is on the write path for every queued event, and the journal format is
/// something the agent must be able to read years from now without a crate
/// bump changing the checksum under it.
pub fn crc32(data: &[u8]) -> u32 {
    static TABLE: std::sync::OnceLock<[u32; 256]> = std::sync::OnceLock::new();
    let table = TABLE.get_or_init(|| {
        let mut t = [0u32; 256];
        for (i, entry) in t.iter_mut().enumerate() {
            let mut c = i as u32;
            for _ in 0..8 {
                c = if c & 1 != 0 { 0xEDB8_8320 ^ (c >> 1) } else { c >> 1 };
            }
            *entry = c;
        }
        t
    });

    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc = table[((crc ^ b as u32) & 0xFF) as usize] ^ (crc >> 8);
    }
    crc ^ 0xFFFF_FFFF
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{EventAction, EventClass, EventData, Severity, SystemSnapshotData};

    fn event() -> AgentEvent {
        AgentEvent::new(
            "agent-1".into(),
            "host-1".into(),
            EventClass::System,
            EventAction::Snapshot,
            Severity::Info,
            EventData::SystemSnapshot(SystemSnapshotData {
                os: "Linux".into(),
                kernel: "6.0".into(),
                distro: "Test".into(),
                cpu_count: 1,
                cpu_usage_pct: 0.0,
                memory_total_mb: 1,
                memory_used_mb: 1,
                memory_free_mb: 0,
                uptime_secs: 1,
                load_avg: [0.0, 0.0, 0.0],
            }),
        )
    }

    fn record() -> JournalRecord {
        JournalRecord::new(1, event())
    }

    // ── CRC ─────────────────────────────────────────────────────────────────

    #[test]
    fn crc32_matches_known_vectors() {
        // Standard CRC-32/ISO-HDLC check values.
        assert_eq!(crc32(b""), 0x0000_0000);
        assert_eq!(crc32(b"a"), 0xE8B7_BE43);
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32(b"The quick brown fox jumps over the lazy dog"), 0x414F_A339);
    }

    #[test]
    fn crc32_detects_single_bit_flips() {
        let data = b"the payload we are protecting".to_vec();
        let base = crc32(&data);
        for byte in 0..data.len() {
            for bit in 0..8 {
                let mut flipped = data.clone();
                flipped[byte] ^= 1 << bit;
                assert_ne!(crc32(&flipped), base, "bit {bit} of byte {byte} went undetected");
            }
        }
    }

    // ── Encode / decode ─────────────────────────────────────────────────────

    #[test]
    fn encoded_records_round_trip() {
        let rec = record();
        let encoded = encode(&rec).unwrap();
        assert_eq!(*encoded.last().unwrap(), b'\n', "records are newline-framed");

        let line = &encoded[..encoded.len() - 1];
        match decode(line, true) {
            RecordOutcome::Valid(back) => {
                assert_eq!(back.seq, rec.seq);
                assert_eq!(back.event.event_id, rec.event.event_id);
                assert_eq!(back.v, RECORD_VERSION);
            }
            other => panic!("expected a valid record, got {other:?}"),
        }
    }

    #[test]
    fn event_id_survives_the_journal_unchanged() {
        // The whole deduplication story rests on this.
        let rec = record();
        let original = rec.event.event_id;
        let encoded = encode(&rec).unwrap();
        let RecordOutcome::Valid(back) = decode(&encoded[..encoded.len() - 1], true) else {
            panic!("record must decode");
        };
        assert_eq!(back.event.event_id, original);
    }

    #[test]
    fn attempts_are_persisted() {
        let mut rec = record();
        rec.attempts = 7;
        let encoded = encode(&rec).unwrap();
        let RecordOutcome::Valid(back) = decode(&encoded[..encoded.len() - 1], true) else {
            panic!("record must decode");
        };
        assert_eq!(back.attempts, 7, "backoff state must survive a restart");
    }

    #[test]
    fn a_flipped_payload_byte_is_reported_as_corrupt() {
        let encoded = encode(&record()).unwrap();
        let mut line = encoded[..encoded.len() - 1].to_vec();
        let last = line.len() - 1;
        line[last] ^= 0xFF;
        assert!(
            matches!(decode(&line, true), RecordOutcome::Corrupt(_)),
            "a mangled payload must be detected, not parsed"
        );
    }

    #[test]
    fn a_flipped_checksum_is_reported_as_corrupt() {
        let encoded = encode(&record()).unwrap();
        let mut line = encoded[..encoded.len() - 1].to_vec();
        line[0] = if line[0] == b'0' { b'1' } else { b'0' };
        assert!(matches!(decode(&line, true), RecordOutcome::Corrupt(_)));
    }

    #[test]
    fn an_interrupted_append_is_a_torn_tail_not_corruption() {
        // Crashing mid-write leaves a short, unterminated final record. That is
        // expected after an unclean stop and must not raise the corruption
        // alarm, which means "the disk altered data".
        let encoded = encode(&record()).unwrap();
        let half = &encoded[..encoded.len() / 2];
        assert!(
            matches!(decode(half, false), RecordOutcome::TruncatedTail),
            "an unterminated short record is a torn tail"
        );
    }

    #[test]
    fn a_short_record_that_was_terminated_is_corrupt() {
        // A newline means the write completed, so a length mismatch here is
        // real damage rather than an interrupted append.
        let encoded = encode(&record()).unwrap();
        let half = &encoded[..encoded.len() / 2];
        assert!(matches!(decode(half, true), RecordOutcome::Corrupt(_)));
    }

    #[test]
    fn a_declared_length_beyond_the_limit_is_refused_before_allocating() {
        let line = format!("00000000 {} payload", MAX_RECORD_BYTES + 1);
        assert!(
            matches!(decode(line.as_bytes(), true), RecordOutcome::Corrupt(_)),
            "an absurd length prefix must be rejected, never trusted"
        );
    }

    #[test]
    fn a_newer_record_version_is_flagged_not_guessed() {
        let mut rec = record();
        rec.v = RECORD_VERSION + 1;
        let encoded = encode(&rec).unwrap();
        match decode(&encoded[..encoded.len() - 1], true) {
            RecordOutcome::UnsupportedVersion(v) => assert_eq!(v, RECORD_VERSION + 1),
            other => panic!("expected UnsupportedVersion, got {other:?}"),
        }
    }

    #[test]
    fn blank_lines_are_ignored() {
        assert!(matches!(decode(b"", true), RecordOutcome::Blank));
    }

    #[test]
    fn garbage_lines_never_panic() {
        for junk in [
            &b"not a record"[..],
            b"zzzzzzzz 5 hello",
            b"00000000 notanumber hello",
            b"00000000",
            b"  ",
            b"\x00\x01\x02\x03",
            b"00000000 0 ",
            b"ffffffff 99999999999999999999 x",
        ] {
            // The contract is simply: classify it, do not crash.
            let _ = decode(junk, true);
            let _ = decode(junk, false);
        }
    }

    // ── Bounded line reading ────────────────────────────────────────────────

    #[test]
    fn reads_complete_lines() {
        let data = b"first\nsecond\n";
        let mut r = io::BufReader::new(&data[..]);
        let mut buf = Vec::new();

        assert_eq!(read_line_bounded(&mut r, 100, &mut buf).unwrap(), LineRead::Complete);
        assert_eq!(buf, b"first");
        assert_eq!(read_line_bounded(&mut r, 100, &mut buf).unwrap(), LineRead::Complete);
        assert_eq!(buf, b"second");
        assert_eq!(read_line_bounded(&mut r, 100, &mut buf).unwrap(), LineRead::Eof);
    }

    #[test]
    fn an_unterminated_final_line_is_reported_as_such() {
        let data = b"complete\npartial";
        let mut r = io::BufReader::new(&data[..]);
        let mut buf = Vec::new();

        assert_eq!(read_line_bounded(&mut r, 100, &mut buf).unwrap(), LineRead::Complete);
        assert_eq!(
            read_line_bounded(&mut r, 100, &mut buf).unwrap(),
            LineRead::Unterminated
        );
        assert_eq!(buf, b"partial");
    }

    #[test]
    fn an_overlong_line_is_skipped_without_buffering_it() {
        // A 1 MiB line with a 16-byte bound: the reader must not allocate a
        // megabyte to discover the line is too long.
        let mut data = vec![b'x'; 1024 * 1024];
        data.push(b'\n');
        data.extend_from_slice(b"short\n");

        let mut r = io::BufReader::new(&data[..]);
        let mut buf = Vec::new();

        assert_eq!(read_line_bounded(&mut r, 16, &mut buf).unwrap(), LineRead::Overlong);
        assert!(buf.len() <= 16, "the oversized line must not be buffered");

        // Recovery continues with the next record.
        assert_eq!(read_line_bounded(&mut r, 16, &mut buf).unwrap(), LineRead::Complete);
        assert_eq!(buf, b"short");
    }

    #[test]
    fn an_unterminated_overlong_line_is_still_overlong() {
        let data = vec![b'x'; 1000];
        let mut r = io::BufReader::new(&data[..]);
        let mut buf = Vec::new();
        assert_eq!(read_line_bounded(&mut r, 10, &mut buf).unwrap(), LineRead::Overlong);
    }

    #[test]
    fn empty_input_reads_as_eof() {
        let mut r = io::BufReader::new(&b""[..]);
        let mut buf = Vec::new();
        assert_eq!(read_line_bounded(&mut r, 10, &mut buf).unwrap(), LineRead::Eof);
    }

    #[test]
    fn a_line_exactly_at_the_bound_is_accepted() {
        let data = b"0123456789\n";
        let mut r = io::BufReader::new(&data[..]);
        let mut buf = Vec::new();
        assert_eq!(read_line_bounded(&mut r, 10, &mut buf).unwrap(), LineRead::Complete);
        assert_eq!(buf, b"0123456789");
    }

    // ── Fuzzing ─────────────────────────────────────────────────────────────
    //
    // A journal is attacker-adjacent: anyone who can write to the spool
    // directory, or any storage fault, can hand these parsers arbitrary bytes.
    // The requirement is that they always terminate, never panic, and never
    // allocate based on unvalidated input. A seeded PRNG keeps failures
    // reproducible in CI, which a nondeterministic fuzzer would not.

    /// xorshift64* — a few lines, no dependency, and identical on every
    /// platform so a CI failure reproduces locally from the seed alone.
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            self.0 = x;
            x.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }

        fn below(&mut self, n: usize) -> usize {
            (self.next() % n as u64) as usize
        }

        fn byte(&mut self) -> u8 {
            (self.next() >> 33) as u8
        }
    }

    #[test]
    fn decode_never_panics_on_random_bytes() {
        let mut rng = Rng(0x5EED_1234_ABCD_0001);
        for iteration in 0..20_000u32 {
            let len = rng.below(300);
            let line: Vec<u8> = (0..len).map(|_| rng.byte()).collect();
            // The contract is total: classify anything, crash on nothing.
            let outcome = decode(&line, iteration.is_multiple_of(2));
            // A random byte string must never be accepted as a valid record.
            if let RecordOutcome::Valid(_) = outcome {
                panic!("random bytes decoded as a valid record: {line:?}");
            }
        }
    }

    #[test]
    fn decode_never_panics_on_mutated_valid_records() {
        // Bit-flips and splices of a real record — the shapes a failing disk
        // actually produces, and far likelier to reach deep code paths than
        // uniform random bytes.
        let encoded = encode(&record()).unwrap();
        let base = &encoded[..encoded.len() - 1];
        let mut rng = Rng(0x5EED_1234_ABCD_0002);

        for _ in 0..20_000 {
            let mut line = base.to_vec();
            match rng.below(4) {
                // Flip a bit.
                0 => {
                    let i = rng.below(line.len());
                    line[i] ^= 1 << rng.below(8);
                }
                // Truncate.
                1 => {
                    let i = rng.below(line.len());
                    line.truncate(i);
                }
                // Splice in random bytes.
                2 => {
                    let i = rng.below(line.len());
                    let n = rng.below(16);
                    for k in 0..n {
                        if i + k < line.len() {
                            line[i + k] = rng.byte();
                        }
                    }
                }
                // Extend.
                _ => {
                    let n = rng.below(32);
                    line.extend((0..n).map(|_| rng.byte()));
                }
            }
            let _ = decode(&line, rng.next().is_multiple_of(2));
        }
    }

    #[test]
    fn decode_never_trusts_a_length_prefix_it_did_not_validate() {
        // A hostile length prefix must be refused before it can drive an
        // allocation. Each of these declares far more than is present.
        let mut rng = Rng(0x5EED_1234_ABCD_0003);
        for _ in 0..2_000 {
            let declared = rng.next();
            let payload_len = rng.below(32);
            let payload: String = (0..payload_len).map(|_| 'x').collect();
            let line = format!("{:08x} {declared} {payload}", rng.next() as u32);
            match decode(line.as_bytes(), true) {
                RecordOutcome::Valid(_) => {
                    panic!("a bogus length prefix was accepted: {line}")
                }
                _ => continue,
            }
        }
    }

    #[test]
    fn bounded_reader_never_exceeds_its_bound_on_random_input() {
        let mut rng = Rng(0x5EED_1234_ABCD_0004);
        for _ in 0..2_000 {
            let len = rng.below(4096);
            let data: Vec<u8> = (0..len).map(|_| rng.byte()).collect();
            let max = 1 + rng.below(128);

            let mut reader = io::BufReader::new(&data[..]);
            let mut buf = Vec::new();
            let mut guard = 0;
            loop {
                guard += 1;
                assert!(guard < 100_000, "reader failed to terminate");
                match read_line_bounded(&mut reader, max, &mut buf).unwrap() {
                    LineRead::Eof => break,
                    _ => assert!(
                        buf.len() <= max,
                        "buffered {} bytes with a bound of {max}",
                        buf.len()
                    ),
                }
            }
        }
    }

    #[test]
    fn a_full_journal_of_random_lines_always_terminates_recovery() {
        // The whole-file path: many lines, arbitrary content, arbitrary framing.
        let mut rng = Rng(0x5EED_1234_ABCD_0005);
        for _ in 0..200 {
            let mut body = Vec::new();
            for _ in 0..rng.below(50) {
                match rng.below(3) {
                    0 => body.extend_from_slice(&encode(&record()).unwrap()),
                    1 => {
                        let n = rng.below(200);
                        body.extend((0..n).map(|_| rng.byte()));
                        body.push(b'\n');
                    }
                    _ => body.extend_from_slice(b"\n"),
                }
            }

            let mut reader = io::BufReader::new(&body[..]);
            let mut buf = Vec::new();
            let mut lines = 0;
            loop {
                lines += 1;
                assert!(lines < 10_000, "recovery failed to terminate");
                match read_line_bounded(&mut reader, MAX_RECORD_BYTES, &mut buf).unwrap() {
                    LineRead::Eof => break,
                    LineRead::Overlong => continue,
                    other => {
                        let _ = decode(&buf, other == LineRead::Complete);
                    }
                }
            }
        }
    }
}
