//! Line and multiline framing.
//!
//! Physical lines are assembled first (CRLF-aware, max-line cut). A second
//! stage optionally glues them into logical records: stack traces, postgres
//! statements, Java exceptions. Limits (`max_lines`, `max_bytes`, `timeout`)
//! are hard — an unterminated multiline cannot grow without bound.

use std::time::{Duration, Instant};

use regex::Regex;

use crate::config::MultilineConfig;
use crate::telemetry::limits::truncate_str;

/// One logical record ready for a parser.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub text: String,
    pub truncated: bool,
    pub multiline: bool,
    /// Bytes consumed from the file (including newlines) to produce this frame.
    pub bytes: u64,
}

/// Byte-oriented line splitter. Partial lines stay in `buf` across reads.
pub struct LineAssembler {
    buf: Vec<u8>,
    max_line: usize,
}

impl LineAssembler {
    pub fn new(max_line: usize) -> Self {
        Self {
            buf: Vec::with_capacity(4096),
            max_line: max_line.max(1),
        }
    }

    /// Push a newly-read chunk. Complete lines (and oversized truncated
    /// lines) come out; a trailing partial line stays buffered.
    pub fn push(&mut self, chunk: &[u8]) -> Vec<Frame> {
        self.buf.extend_from_slice(chunk);
        self.drain(false)
    }

    /// Emit a leftover partial line (file was truncated or rotated out from
    /// under us). No-op when the buffer is empty.
    pub fn flush(&mut self) -> Option<Frame> {
        let mut v = self.drain(true);
        v.pop()
    }

    fn drain(&mut self, flush_partial: bool) -> Vec<Frame> {
        let mut out = Vec::new();
        loop {
            match find_newline(&self.buf) {
                Some((nl_at, nl_len)) => {
                    let mut line: Vec<u8> = self.buf.drain(..=nl_at + nl_len - 1).collect();
                    let consumed = line.len() as u64;
                    line.truncate(line.len() - nl_len);
                    // Drop a preceding CR if we split on LF of a CRLF pair
                    // that `find_newline` reported as a single LF (defensive).
                    if line.last() == Some(&b'\r') {
                        line.pop();
                    }
                    out.push(bytes_to_frame(&line, consumed, self.max_line));
                }
                None => {
                    if self.buf.len() > self.max_line {
                        // No newline and already over the ceiling: emit a
                        // truncated frame and keep scanning for the next NL
                        // so we resynchronise rather than concatenating the
                        // remainder onto the next record.
                        let overflow: Vec<u8> = self.buf.drain(..self.max_line).collect();
                        let consumed = overflow.len() as u64;
                        let mut f = bytes_to_frame(&overflow, consumed, self.max_line);
                        f.truncated = true;
                        out.push(f);
                        // Drop until the next newline so the next record is clean.
                        if let Some((nl_at, nl_len)) = find_newline(&self.buf) {
                            let _ = self.buf.drain(..=nl_at + nl_len - 1);
                        } else {
                            self.buf.clear();
                        }
                        continue;
                    }
                    if flush_partial && !self.buf.is_empty() {
                        let rest: Vec<u8> = std::mem::take(&mut self.buf);
                        let consumed = rest.len() as u64;
                        out.push(bytes_to_frame(&rest, consumed, self.max_line));
                    }
                    break;
                }
            }
        }
        out
    }
}

fn find_newline(buf: &[u8]) -> Option<(usize, usize)> {
    for (i, b) in buf.iter().enumerate() {
        if *b == b'\n' {
            return Some((i, 1));
        }
        if *b == b'\r' {
            let len = if buf.get(i + 1) == Some(&b'\n') { 2 } else { 1 };
            return Some((i, len));
        }
    }
    None
}

fn bytes_to_frame(bytes: &[u8], consumed: u64, max_line: usize) -> Frame {
    let lossy = String::from_utf8_lossy(bytes);
    let (text, trunc) = truncate_str(lossy.as_ref(), max_line);
    Frame {
        text,
        truncated: trunc.is_some(),
        multiline: false,
        bytes: consumed,
    }
}

/// Assembles physical lines into logical records using a start-of-record regex.
pub struct MultilineFramer {
    start: Regex,
    negate: bool,
    timeout: Duration,
    max_lines: usize,
    max_bytes: usize,
    pending: Option<Pending>,
}

struct Pending {
    text: String,
    truncated: bool,
    bytes: u64,
    lines: usize,
    last: Instant,
}

impl MultilineFramer {
    pub fn new(
        cfg: &MultilineConfig,
        max_lines: usize,
        max_bytes: usize,
    ) -> Result<Self, regex::Error> {
        Ok(Self {
            start: Regex::new(&cfg.pattern)?,
            negate: cfg.negate,
            timeout: Duration::from_millis(cfg.timeout_ms()),
            max_lines: max_lines.max(2),
            max_bytes: max_bytes.max(1024),
            pending: None,
        })
    }

    /// `true` when `line` starts a new logical record (match-after, default)
    /// or is a continuation (match-before when `negate`).
    fn is_start(&self, line: &str) -> bool {
        let matched = self.start.is_match(line);
        if self.negate {
            !matched
        } else {
            matched
        }
    }

    pub fn push(&mut self, line: Frame) -> Option<Frame> {
        let is_start = self.is_start(&line.text);
        match self.pending.take() {
            None => {
                self.pending = Some(Pending::from_line(line));
                None
            }
            Some(mut p) => {
                if is_start {
                    let flushed = p.into_frame();
                    self.pending = Some(Pending::from_line(line));
                    Some(flushed)
                } else {
                    p.append(&line, self.max_bytes);
                    let over = p.lines >= self.max_lines || p.text.len() >= self.max_bytes;
                    if over {
                        Some(p.into_frame())
                    } else {
                        self.pending = Some(p);
                        None
                    }
                }
            }
        }
    }

    pub fn poll_timeout(&mut self) -> Option<Frame> {
        let p = self.pending.as_ref()?;
        if p.last.elapsed() >= self.timeout {
            self.pending.take().map(Pending::into_frame)
        } else {
            None
        }
    }

    pub fn flush(&mut self) -> Option<Frame> {
        self.pending.take().map(Pending::into_frame)
    }
}

impl Pending {
    fn from_line(line: Frame) -> Self {
        Self {
            truncated: line.truncated,
            bytes: line.bytes,
            lines: 1,
            last: Instant::now(),
            text: line.text,
        }
    }

    fn append(&mut self, line: &Frame, max_bytes: usize) {
        self.bytes += line.bytes;
        self.lines += 1;
        self.truncated |= line.truncated;
        self.last = Instant::now();
        if self.text.len() >= max_bytes {
            self.truncated = true;
            return;
        }
        self.text.push('\n');
        let room = max_bytes.saturating_sub(self.text.len());
        if line.text.len() > room {
            self.text
                .push_str(&line.text[..floor_char_boundary(&line.text, room)]);
            self.truncated = true;
        } else {
            self.text.push_str(&line.text);
        }
    }

    fn into_frame(self) -> Frame {
        Frame {
            text: self.text,
            truncated: self.truncated,
            multiline: self.lines > 1,
            bytes: self.bytes,
        }
    }
}

fn floor_char_boundary(s: &str, mut i: usize) -> usize {
    if i >= s.len() {
        return s.len();
    }
    while i > 0 && !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_lf_and_crlf() {
        let mut a = LineAssembler::new(1024);
        let frames = a.push(b"one\ntwo\r\nthree\r");
        // "three\r" is a complete CR-terminated line.
        assert_eq!(frames.len(), 3);
        assert_eq!(frames[0].text, "one");
        assert_eq!(frames[1].text, "two");
        assert_eq!(frames[2].text, "three");
        assert!(a.buf.is_empty());
    }

    #[test]
    fn holds_partial_line() {
        let mut a = LineAssembler::new(1024);
        let frames = a.push(b"hello ");
        assert!(frames.is_empty());
        let frames = a.push(b"world\n");
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].text, "hello world");
        assert_eq!(frames[0].bytes, 12); // "hello world\n"
    }

    #[test]
    fn truncates_oversize_line_and_resyncs() {
        let mut a = LineAssembler::new(8);
        let frames = a.push(b"abcdefghijklmnop\nnext\n");
        assert!(frames[0].truncated);
        assert_eq!(frames[0].text, "abcdefgh");
        // After the oversized line we skip to the newline, so "next" is intact.
        let last = frames.last().unwrap();
        assert_eq!(last.text, "next");
        assert!(!last.truncated);
    }

    #[test]
    fn multiline_glues_continuations() {
        let cfg = MultilineConfig {
            pattern: r"^\d{4}-".into(),
            negate: false,
            timeout_ms: 5_000,
        };
        let mut m = MultilineFramer::new(&cfg, 20, 4096).unwrap();
        assert!(m
            .push(Frame {
                text: "2024-01-01 first".into(),
                truncated: false,
                multiline: false,
                bytes: 16,
            })
            .is_none());
        assert!(m
            .push(Frame {
                text: "    continuation".into(),
                truncated: false,
                multiline: false,
                bytes: 16,
            })
            .is_none());
        let flushed = m
            .push(Frame {
                text: "2024-01-02 second".into(),
                truncated: false,
                multiline: false,
                bytes: 17,
            })
            .expect("start of second record flushes the first");
        assert!(flushed.multiline);
        assert!(flushed.text.contains("first"));
        assert!(flushed.text.contains("continuation"));
        assert!(!flushed.text.contains("second"));
        let rest = m.flush().unwrap();
        assert_eq!(rest.text, "2024-01-02 second");
    }

    #[test]
    fn multiline_flushes_on_max_lines() {
        let cfg = MultilineConfig {
            pattern: r"^START".into(),
            negate: false,
            timeout_ms: 60_000,
        };
        let mut m = MultilineFramer::new(&cfg, 3, 4096).unwrap();
        assert!(m
            .push(Frame {
                text: "START".into(),
                truncated: false,
                multiline: false,
                bytes: 5,
            })
            .is_none());
        assert!(m
            .push(Frame {
                text: "a".into(),
                truncated: false,
                multiline: false,
                bytes: 1,
            })
            .is_none());
        let flushed = m
            .push(Frame {
                text: "b".into(),
                truncated: false,
                multiline: false,
                bytes: 1,
            })
            .expect("third line hits max_lines");
        assert_eq!(flushed.text, "START\na\nb");
    }
}
