//! Hard size limits and explicit truncation.
//!
//! Every variable-length field an attacker can influence — a command line, a
//! whole event, a delivery batch — needs a ceiling, otherwise a single hostile
//! `execve` with a megabyte of argv can exhaust the spool, blow the batch size
//! and stall delivery for every other event on the host.
//!
//! The rule is **truncate, mark, and keep going**: a field that exceeds its
//! limit is cut down and the event carries an explicit marker recording that it
//! was cut and how much was lost.  A consumer can then tell "the command line
//! was `foo`" from "the command line *started with* `foo`", which a silent trim
//! makes impossible.

use serde::{Deserialize, Serialize};

/// Maximum captured command line.  Linux's `ARG_MAX` is typically 2 MiB, so a
/// full capture is not bounded by the kernel; 16 KiB keeps the common case
/// lossless (the 99.9th percentile of real command lines is well under 4 KiB)
/// while capping the hostile case.
pub const MAX_CMDLINE_BYTES: usize = 16 * 1024;

// Environment-value and process-lineage ceilings deliberately live with the
// code that builds those fields (`proc_enrich::MAX_ENV_VAL`,
// `detection::honeytoken::MAX_LINEAGE_DEPTH`) rather than here. Restating them
// would create a second source of truth that could drift from the one actually
// enforced — worse than having no constant at all.

/// Maximum serialized size of a single event.  An event still over this after
/// field-level truncation is dropped as [`crate::telemetry::DropReason::EventTooLarge`]
/// rather than being allowed to wedge the batch.
pub const MAX_EVENT_BYTES: usize = 256 * 1024;

/// Maximum serialized size of one ingest batch.
pub const MAX_BATCH_BYTES: usize = 4 * 1024 * 1024;

/// Maximum events per ingest batch.
pub const MAX_BATCH_EVENTS: usize = 100;

/// Maximum size of a single persisted queue record, validated **before** any
/// allocation while replaying the journal.  A corrupt length prefix must not be
/// able to make the agent allocate an arbitrary buffer.
pub const MAX_RECORD_BYTES: usize = MAX_EVENT_BYTES + 4096;

/// Record of a field that did not fit.
///
/// Serialized flat into the owning payload, so a truncated `cmdline` renders as
/// `cmdline_truncated` / `cmdline_original_length` / `cmdline_captured_length`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Truncation {
    /// Always `true` — present only when truncation happened, so its mere
    /// presence is the signal.
    pub truncated: bool,
    /// Size of the field before truncation, in bytes.
    pub original_length: usize,
    /// Size actually captured, in bytes.
    pub captured_length: usize,
}

impl Truncation {
    pub fn new(original: usize, captured: usize) -> Self {
        Self {
            truncated: true,
            original_length: original,
            captured_length: captured,
        }
    }

    /// Bytes lost to truncation.
    pub fn lost_bytes(&self) -> usize {
        self.original_length.saturating_sub(self.captured_length)
    }
}

/// Truncate `s` to at most `max` bytes on a UTF-8 character boundary.
///
/// Returns the (possibly unchanged) string and `Some(Truncation)` when bytes
/// were dropped.  Cutting at a boundary matters: slicing mid-character would
/// panic on `String::from_utf8` or produce a replacement character that changes
/// the field's meaning — a command line is evidence, so it must not be silently
/// corrupted on its way to the backend.
pub fn truncate_str(s: &str, max: usize) -> (String, Option<Truncation>) {
    if s.len() <= max {
        return (s.to_string(), None);
    }
    // Walk back to the nearest char boundary at or below `max`.
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    let cut = &s[..end];
    (cut.to_string(), Some(Truncation::new(s.len(), cut.len())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_strings_pass_through_unchanged() {
        let (s, t) = truncate_str("hello", 100);
        assert_eq!(s, "hello");
        assert!(t.is_none(), "no marker when nothing was cut");
    }

    #[test]
    fn exact_length_is_not_truncated() {
        let (s, t) = truncate_str("abcde", 5);
        assert_eq!(s, "abcde");
        assert!(t.is_none(), "boundary case must not report truncation");
    }

    #[test]
    fn oversized_strings_are_cut_and_marked() {
        let input = "a".repeat(100);
        let (s, t) = truncate_str(&input, 10);
        assert_eq!(s.len(), 10);
        let t = t.expect("truncation must be reported");
        assert!(t.truncated);
        assert_eq!(t.original_length, 100);
        assert_eq!(t.captured_length, 10);
        assert_eq!(t.lost_bytes(), 90);
    }

    #[test]
    fn multibyte_characters_are_never_split() {
        // '€' is 3 bytes; cutting at 4 must fall back to 3.
        let input = "€€€€";
        let (s, t) = truncate_str(input, 4);
        assert_eq!(s, "€", "must cut on a character boundary");
        assert!(s.is_char_boundary(s.len()));
        assert_eq!(t.unwrap().captured_length, 3);
    }

    #[test]
    fn truncating_below_the_first_character_yields_empty() {
        let (s, t) = truncate_str("€", 1);
        assert_eq!(s, "", "no whole character fits");
        assert_eq!(t.unwrap().captured_length, 0);
    }

    #[test]
    fn zero_max_truncates_everything() {
        let (s, t) = truncate_str("abc", 0);
        assert_eq!(s, "");
        assert_eq!(t.unwrap().original_length, 3);
    }

    #[test]
    fn empty_input_is_never_truncated() {
        let (s, t) = truncate_str("", 0);
        assert_eq!(s, "");
        assert!(t.is_none());
    }

    #[test]
    fn truncation_round_trips_through_json() {
        let t = Truncation::new(131_072, 16_384);
        let json = serde_json::to_value(&t).unwrap();
        assert_eq!(json["truncated"], true);
        assert_eq!(json["original_length"], 131_072);
        assert_eq!(json["captured_length"], 16_384);
        let back: Truncation = serde_json::from_value(json).unwrap();
        assert_eq!(back, t);
    }

    // These relationships are compile-time invariants, so they are checked at
    // compile time: a build that violates one must not get as far as running.
    const _: () = {
        // A record must have room for its framing on top of the event.
        assert!(MAX_RECORD_BYTES > MAX_EVENT_BYTES);
        // A single maximal event must always fit inside a batch.
        assert!(MAX_BATCH_BYTES > MAX_EVENT_BYTES);
        // A command line alone must never be able to fill an event.
        assert!(MAX_CMDLINE_BYTES < MAX_EVENT_BYTES);
    };
}
