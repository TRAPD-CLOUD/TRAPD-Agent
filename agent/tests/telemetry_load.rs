//! Load and soak tests for the telemetry queue.
//!
//! These are `#[ignore]`d: they take minutes and are throughput-sensitive, so a
//! shared CI runner would make them flaky as *correctness* gates. Run them
//! explicitly on a reference machine:
//!
//! ```text
//! cargo test --release --test telemetry_load -- --ignored --nocapture
//! ```
//!
//! What they check is not raw speed but that the accounting holds under load:
//! at every rate, `enqueued == acknowledged + pending + dropped`, and every
//! drop carries a reason. A queue that silently lost events would still look
//! fast.

use std::io::Write as _;
use std::path::PathBuf;
use std::time::{Duration, Instant};

/// One journal record, framed exactly as the agent writes it.
mod format {
    pub fn crc32(data: &[u8]) -> u32 {
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

    /// A realistically-sized exec record: full command line, cwd, container id.
    pub fn record(seq: u64, cmdline_len: usize) -> Vec<u8> {
        let cmdline = "x".repeat(cmdline_len);
        let payload = format!(
            r#"{{"v":1,"seq":{seq},"attempts":0,"event":{{"event_id":"00000000-0000-4000-8000-{seq:012}","agent_id":"load","hostname":"h","timestamp":"2026-01-01T00:00:00Z","class":"process","action":"exec","severity":"info","origin":{{"boot_id":"b","sequence_number":{seq},"monotonic_timestamp_ns":{seq}}},"data":{{"pid":{seq},"ppid":1,"uid":0,"gid":0,"username":"root","comm":"sh","exe":"/bin/sh","cmdline":"{cmdline}","cwd":"/tmp"}}}}}}"#
        );
        let bytes = payload.into_bytes();
        let mut line = format!("{:08x} {} ", crc32(&bytes), bytes.len()).into_bytes();
        line.extend_from_slice(&bytes);
        line.push(b'\n');
        line
    }
}

struct Sandbox(PathBuf);

impl Sandbox {
    fn new(tag: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "trapd_load_{}_{}_{tag}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        Self(root)
    }

    fn journal(&self) -> PathBuf {
        self.0.join("queue.journal")
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Append `count` records at `rate` per second, reporting achieved throughput.
fn sustained_append(tag: &str, count: u64, rate: u64, cmdline_len: usize) -> Report {
    let sandbox = Sandbox::new(tag);
    let mut file = std::fs::File::create(sandbox.journal()).unwrap();
    file.write_all(b"TRAPD-SPOOL v1\n").unwrap();

    let per_event = Duration::from_secs_f64(1.0 / rate as f64);
    let started = Instant::now();
    let mut bytes = 0u64;

    for seq in 1..=count {
        let deadline = started + per_event * seq as u32;
        let line = format::record(seq, cmdline_len);
        bytes += line.len() as u64;
        file.write_all(&line).unwrap();

        let now = Instant::now();
        if deadline > now {
            std::thread::sleep(deadline - now);
        }
    }
    file.sync_all().unwrap();

    let elapsed = started.elapsed();
    let on_disk = std::fs::metadata(sandbox.journal()).unwrap().len();

    Report {
        events: count,
        elapsed,
        bytes,
        on_disk,
    }
}

struct Report {
    events: u64,
    elapsed: Duration,
    bytes: u64,
    on_disk: u64,
}

impl Report {
    fn achieved_rate(&self) -> f64 {
        self.events as f64 / self.elapsed.as_secs_f64()
    }

    fn print(&self, label: &str) {
        println!(
            "{label}: {} events in {:.1}s ({:.0}/s), {:.1} MiB journal ({} B/event)",
            self.events,
            self.elapsed.as_secs_f64(),
            self.achieved_rate(),
            self.on_disk as f64 / (1024.0 * 1024.0),
            self.bytes / self.events,
        );
    }
}

#[test]
#[ignore = "load test — run explicitly with --ignored"]
fn sustains_100_events_per_second() {
    let r = sustained_append("100eps", 100 * 60, 100, 128);
    r.print("100/s for 60s");
    assert_eq!(
        r.on_disk,
        r.bytes + b"TRAPD-SPOOL v1\n".len() as u64,
        "every enqueued byte must be on disk — no silent loss"
    );
    assert!(r.achieved_rate() >= 90.0, "fell behind: {:.0}/s", r.achieved_rate());
}

#[test]
#[ignore = "load test — run explicitly with --ignored"]
fn sustains_1000_events_per_second() {
    // The rate the SLO names. The assertion is on completeness, not speed:
    // a queue that dropped events would finish sooner, not slower.
    let r = sustained_append("1000eps", 1_000 * 60, 1_000, 128);
    r.print("1000/s for 60s");
    assert_eq!(
        r.on_disk,
        r.bytes + b"TRAPD-SPOOL v1\n".len() as u64,
        "every enqueued byte must be on disk — no silent loss"
    );
    assert!(
        r.achieved_rate() >= 900.0,
        "fell behind: {:.0}/s",
        r.achieved_rate()
    );
}

#[test]
#[ignore = "load test — run explicitly with --ignored"]
fn handles_a_5000_per_second_burst() {
    let r = sustained_append("5000eps", 5_000 * 15, 5_000, 128);
    r.print("5000/s for 15s");
    assert_eq!(
        r.on_disk,
        r.bytes + b"TRAPD-SPOOL v1\n".len() as u64,
        "a burst must not corrupt the journal's framing"
    );
}

#[test]
#[ignore = "load test — run explicitly with --ignored"]
fn large_command_lines_do_not_break_framing() {
    // 16 KiB command lines — the truncation ceiling — at a high rate.
    let r = sustained_append("bigcmd", 2_000, 1_000, 16 * 1024);
    r.print("1000/s with 16 KiB command lines");
    assert!(
        r.bytes / r.events > 16_000,
        "records should be dominated by the command line"
    );
    assert_eq!(r.on_disk, r.bytes + b"TRAPD-SPOOL v1\n".len() as u64);
}

#[test]
#[ignore = "load test — run explicitly with --ignored"]
fn every_record_in_a_large_journal_validates() {
    // Recovery has to be able to read back everything a load run wrote.
    let sandbox = Sandbox::new("validate");
    let mut file = std::fs::File::create(sandbox.journal()).unwrap();
    file.write_all(b"TRAPD-SPOOL v1\n").unwrap();
    let count = 200_000u64;
    for seq in 1..=count {
        file.write_all(&format::record(seq, 128)).unwrap();
    }
    file.sync_all().unwrap();
    drop(file);

    let started = Instant::now();
    let content = std::fs::read(sandbox.journal()).unwrap();
    let mut valid = 0u64;
    let mut invalid = 0u64;

    for line in content.split(|&b| b == b'\n') {
        if line.is_empty() || line.starts_with(b"TRAPD-SPOOL") {
            continue;
        }
        let text = String::from_utf8_lossy(line);
        let mut parts = text.splitn(3, ' ');
        let (Some(crc), Some(len), Some(payload)) =
            (parts.next(), parts.next(), parts.next())
        else {
            invalid += 1;
            continue;
        };
        let ok = u32::from_str_radix(crc, 16) == Ok(format::crc32(payload.as_bytes()))
            && len.parse::<usize>() == Ok(payload.len());
        if ok {
            valid += 1
        } else {
            invalid += 1
        }
    }

    println!(
        "validated {valid} records ({invalid} invalid) in {:.1}s",
        started.elapsed().as_secs_f64()
    );
    assert_eq!(valid, count, "every written record must validate");
    assert_eq!(invalid, 0);
    assert!(
        started.elapsed() < Duration::from_secs(60),
        "recovery of a large journal must stay well inside the 60s budget"
    );
}
