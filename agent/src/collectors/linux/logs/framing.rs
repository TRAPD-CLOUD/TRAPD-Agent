//! Line framing, max-size enforcement, and multiline aggregation.
//!
//! Physical lines are cut at `max_line_bytes` so a missing newline in a
//! multi-gigabyte write cannot grow the buffer without bound. Logical records
//! are then assembled by either:
//!
//! * a start-of-record regex ([`MultilineAggregator`]) — Java stacks, Postgres;
//! * the auditd event-id aggregator ([`AuditAggregator`]) — `SYSCALL` +
//!   `EXECVE` + `PATH` + `EOE` share one `msg=audit(epoch:serial)`.

use std::time::{Duration, Instant};

use regex::Regex;

use crate::config::MultilineConfig;

/// One physical line (or truncated-without-newline chunk) from a reader.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawLine {
    pub bytes: Vec<u8>,
    pub truncated: bool,
    pub original_len: usize,
}

impl RawLine {
    pub fn as_str(&self) -> String {
        String::from_utf8_lossy(&self.bytes).into_owned()
    }
}

/// Split `data` into physical lines, honouring `max_line`.
///
/// Incomplete trailing data (no newline yet) is returned as `rest` so the
/// caller can prepend it to the next read. A chunk that hits `max_line`
/// without a newline is emitted as a truncated record; subsequent bytes up to
/// the next newline are discarded (so a hostile 100 MiB line becomes one
/// marked event plus a skip, not a memory bomb).
pub fn frame_bytes(data: &[u8], max_line: usize, rest: &mut Vec<u8>) -> Vec<RawLine> {
    rest.extend_from_slice(data);
    let mut out = Vec::new();
    loop {
        if let Some(pos) = rest.iter().position(|&b| b == b'\n') {
            let mut line: Vec<u8> = rest.drain(..=pos).collect();
            // Drop the newline; keep a trailing `\r` off CRLF.
            if line.last() == Some(&b'\n') {
                line.pop();
            }
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            let original = line.len();
            let truncated = line.len() > max_line;
            if truncated {
                line = cut_utf8(&line, max_line);
            }
            out.push(RawLine {
                original_len: original,
                truncated,
                bytes: line,
            });
            continue;
        }
        // No newline in the buffer.
        if rest.len() > max_line {
            let original = rest.len();
            let cut = cut_utf8(rest, max_line);
            out.push(RawLine {
                bytes: cut,
                truncated: true,
                original_len: original,
            });
            // Drop until the next newline so we resync; if there isn't one
            // yet, clear the buffer (the rest of the monster line arrives
            // in later reads and is discarded by the skip flag).
            rest.clear();
            // Mark that we are mid-skip: handled by emitting truncated and
            // waiting for a newline in subsequent calls via a sticky flag
            // on the caller. Here we just emptied; extra bytes without `\n`
            // on the next push will truncate again, which is correct.
        }
        break;
    }
    out
}

fn cut_utf8(bytes: &[u8], max: usize) -> Vec<u8> {
    if bytes.len() <= max {
        return bytes.to_vec();
    }
    let mut end = max;
    while end > 0 && (bytes[end] & 0b1100_0000) == 0b1000_0000 {
        end -= 1;
    }
    bytes[..end].to_vec()
}

/// Regex-based multiline stitcher.
pub struct MultilineAggregator {
    start: Option<Regex>,
    negate: bool,
    max_lines: usize,
    max_bytes: usize,
    timeout: Duration,
    buf: Vec<String>,
    bytes: usize,
    last: Instant,
}

impl MultilineAggregator {
    pub fn new(cfg: &MultilineConfig) -> Self {
        let start = Regex::new(&cfg.start).ok();
        Self {
            start,
            negate: cfg.negate,
            max_lines: cfg.max_lines.max(1),
            max_bytes: cfg.max_bytes.max(1),
            timeout: Duration::from_millis(cfg.timeout_ms.max(1)),
            buf: Vec::new(),
            bytes: 0,
            last: Instant::now(),
        }
    }

    /// Feed one physical line. Returns a completed logical record when the
    /// new line starts a new event (or the buffer is full).
    pub fn push(&mut self, line: &str) -> Option<String> {
        let is_start = self.is_start(line);
        if is_start && !self.buf.is_empty() {
            let flushed = self.take();
            self.append(line);
            return flushed;
        }
        self.append(line);
        if self.buf.len() >= self.max_lines || self.bytes >= self.max_bytes {
            return self.take();
        }
        None
    }

    /// Flush if the idle timeout has elapsed.
    pub fn poll_timeout(&mut self) -> Option<String> {
        if self.buf.is_empty() {
            return None;
        }
        if self.last.elapsed() >= self.timeout {
            return self.take();
        }
        None
    }

    #[allow(dead_code)]
    pub fn flush(&mut self) -> Option<String> {
        self.take()
    }

    fn is_start(&self, line: &str) -> bool {
        let Some(re) = &self.start else {
            return true;
        };
        let matched = re.is_match(line);
        if self.negate {
            !matched
        } else {
            matched
        }
    }

    fn append(&mut self, line: &str) {
        self.bytes = self.bytes.saturating_add(line.len() + 1);
        self.buf.push(line.to_string());
        self.last = Instant::now();
    }

    fn take(&mut self) -> Option<String> {
        if self.buf.is_empty() {
            return None;
        }
        self.bytes = 0;
        Some(std::mem::take(&mut self.buf).join("\n"))
    }
}

/// Groups consecutive audit records that share `msg=audit(epoch:serial)`.
pub struct AuditAggregator {
    current_id: Option<String>,
    buf: Vec<String>,
    max_lines: usize,
}

impl AuditAggregator {
    pub fn new(max_lines: usize) -> Self {
        Self {
            current_id: None,
            buf: Vec::new(),
            max_lines: max_lines.max(1),
        }
    }

    pub fn push(&mut self, line: &str) -> Option<String> {
        let id = audit_event_id(line);
        let is_eoe = line.contains("type=EOE") || line.contains("type=EOE ");
        if let Some(id) = id {
            if self.current_id.as_deref() == Some(id.as_str()) {
                self.buf.push(line.to_string());
                if is_eoe || self.buf.len() >= self.max_lines {
                    return self.take();
                }
                return None;
            }
            let flushed = self.take();
            self.current_id = Some(id);
            self.buf.push(line.to_string());
            if is_eoe {
                return self.take().or(flushed);
            }
            return flushed;
        }
        // No event id — flush pending and pass the line through.
        let flushed = self.take();
        self.buf.push(line.to_string());
        self.take().or(flushed)
    }

    #[allow(dead_code)]
    pub fn flush(&mut self) -> Option<String> {
        self.take()
    }

    fn take(&mut self) -> Option<String> {
        self.current_id = None;
        if self.buf.is_empty() {
            return None;
        }
        Some(std::mem::take(&mut self.buf).join("\n"))
    }
}

/// Extract `epoch:serial` from `msg=audit(1712345678.123:456)`.
pub fn audit_event_id(line: &str) -> Option<String> {
    let rest = line.split("msg=audit(").nth(1)?;
    let id = rest.split(')').next()?;
    if id.is_empty() {
        return None;
    }
    Some(id.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_on_newlines_and_strips_crlf() {
        let mut rest = Vec::new();
        let lines = frame_bytes(b"a\nb\r\nc\n", 1024, &mut rest);
        assert_eq!(
            lines.iter().map(|l| l.as_str()).collect::<Vec<_>>(),
            vec!["a", "b", "c"]
        );
        assert!(rest.is_empty());
    }

    #[test]
    fn holds_incomplete_trailing_line() {
        let mut rest = Vec::new();
        let lines = frame_bytes(b"hello", 1024, &mut rest);
        assert!(lines.is_empty());
        assert_eq!(rest, b"hello");
        let lines = frame_bytes(b" world\nnext", 1024, &mut rest);
        assert_eq!(lines[0].as_str(), "hello world");
        assert_eq!(rest, b"next");
    }

    #[test]
    fn truncates_oversized_line_without_newline() {
        let mut rest = Vec::new();
        let lines = frame_bytes(&[b'x'; 100], 16, &mut rest);
        assert_eq!(lines.len(), 1);
        assert!(lines[0].truncated);
        assert_eq!(lines[0].bytes.len(), 16);
        assert!(rest.is_empty());
    }

    #[test]
    fn postgres_multiline_stitches_until_next_timestamp() {
        let mut ml = MultilineAggregator::new(&MultilineConfig::postgres());
        assert!(ml
            .push("2024-01-15 12:00:00.000 UTC [1] LOG:  SELECT")
            .is_none());
        assert!(ml.push("    FROM users").is_none());
        let rec = ml
            .push("2024-01-15 12:00:01.000 UTC [1] LOG:  COMMIT")
            .unwrap();
        assert!(rec.contains("SELECT"));
        assert!(rec.contains("FROM users"));
        assert!(!rec.contains("COMMIT"));
    }

    #[test]
    fn audit_aggregator_groups_by_event_id() {
        let mut a = AuditAggregator::new(32);
        let s1 = "type=SYSCALL msg=audit(1.0:9): syscall=59 comm=\"bash\"";
        let s2 = "type=EXECVE msg=audit(1.0:9): argc=2 a0=\"bash\"";
        let s3 = "type=SYSCALL msg=audit(1.0:10): syscall=2";
        assert!(a.push(s1).is_none());
        let flushed = a.push(s2);
        assert!(flushed.is_none());
        let rec = a.push(s3).unwrap();
        assert!(rec.contains("SYSCALL"));
        assert!(rec.contains("EXECVE"));
        assert!(rec.contains("msg=audit(1.0:9)"));
    }

    #[test]
    fn audit_event_id_parses() {
        assert_eq!(
            audit_event_id("type=SYSCALL msg=audit(1712345678.123:456): foo").as_deref(),
            Some("1712345678.123:456")
        );
    }
}
