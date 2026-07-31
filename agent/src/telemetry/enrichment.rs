//! Partial enrichment.
//!
//! A kernel exec record arrives complete: PID, UID, the executed path.  Everything
//! else — the full argv, the working directory, the container — is read from
//! `/proc` *after the fact*, and by then the process may already be gone.  That
//! race is not an edge case: catching short-lived processes is precisely why the
//! eBPF tracer exists, so the processes we most want to see are the ones most
//! likely to exit before enrichment runs.
//!
//! Discarding the event when `/proc` comes up empty would therefore blind the
//! agent exactly where it matters most.  Instead the raw kernel record always
//! ships, and this module records *what could not be resolved and why*, so a
//! missing `cmdline` is distinguishable from an empty one.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::limits::Truncation;
use super::metrics::metrics;

/// How complete an event's `/proc` enrichment is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnrichmentStatus {
    /// Every field resolved.
    Complete,
    /// At least one field could not be resolved; the rest are present.
    Partial,
    /// No field could be resolved — only the raw kernel record is available.
    Failed,
}

impl EnrichmentStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            EnrichmentStatus::Complete => "complete",
            EnrichmentStatus::Partial => "partial",
            EnrichmentStatus::Failed => "failed",
        }
    }
}

/// Why a single enrichment field is missing.
///
/// These are causes, not severities: `ProcessExited` is the expected outcome for
/// a short-lived process and says nothing is wrong, while `PermissionDenied`
/// points at a misconfigured deployment.  Collapsing them into one "failed"
/// would hide that difference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnrichmentError {
    /// The process exited before `/proc` could be read — expected for
    /// short-lived processes, and not a defect.
    ProcessExited,
    /// `/proc` entry exists but is not readable by this agent (missing
    /// capabilities, or a hardened `hidepid` mount).
    PermissionDenied,
    /// The read exceeded its deadline.
    Timeout,
    /// The file was read but its contents could not be parsed.
    ParseFailed,
    /// The field is not available on this platform or kernel.
    Unsupported,
    /// Any other I/O failure.
    IoError,
}

impl EnrichmentError {
    pub const fn as_str(self) -> &'static str {
        match self {
            EnrichmentError::ProcessExited => "process_exited",
            EnrichmentError::PermissionDenied => "permission_denied",
            EnrichmentError::Timeout => "timeout",
            EnrichmentError::ParseFailed => "parse_failed",
            EnrichmentError::Unsupported => "unsupported",
            EnrichmentError::IoError => "io_error",
        }
    }

    /// Classify a `std::io::Error` from a `/proc` read.
    ///
    /// Named `from_io` rather than implementing `From`: the mapping is only
    /// correct in the `/proc`-enrichment context (`NotFound` means the process
    /// exited), so a blanket conversion would be wrong elsewhere.
    #[allow(clippy::wrong_self_convention)]
    ///
    /// `NotFound` means the `/proc` entry vanished, i.e. the process exited —
    /// the benign, expected case.
    pub fn from_io(e: &std::io::Error) -> Self {
        match e.kind() {
            std::io::ErrorKind::NotFound => EnrichmentError::ProcessExited,
            std::io::ErrorKind::PermissionDenied => EnrichmentError::PermissionDenied,
            std::io::ErrorKind::TimedOut => EnrichmentError::Timeout,
            _ => EnrichmentError::IoError,
        }
    }
}

/// Per-field enrichment outcome, flattened into the owning event payload.
///
/// Absent (all-`None`, empty maps) when enrichment was fully successful, so a
/// complete event carries no extra bytes on the wire.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Enrichment {
    /// Overall status; omitted when [`EnrichmentStatus::Complete`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enrichment_status: Option<EnrichmentStatus>,
    /// `field -> cause`, e.g. `{"cmdline": "process_exited"}`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub enrichment_errors: BTreeMap<String, EnrichmentError>,
    /// `field -> truncation record` for every field that exceeded its limit.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub truncated_fields: BTreeMap<String, Truncation>,
}

impl Enrichment {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record that `field` could not be resolved.
    pub fn fail(&mut self, field: &str, err: EnrichmentError) -> &mut Self {
        self.enrichment_errors.insert(field.to_string(), err);
        metrics().enrichment_failure();
        self
    }

    /// Record that `field` was truncated.  `None` is a no-op, so call sites can
    /// pass the result of [`super::limits::truncate_str`] straight through.
    pub fn truncated(&mut self, field: &str, t: Option<Truncation>) -> &mut Self {
        if let Some(t) = t {
            self.truncated_fields.insert(field.to_string(), t);
            metrics().enrichment_truncation();
        }
        self
    }

    /// Finalise the status from what was recorded.
    ///
    /// `expected_fields` is how many fields enrichment tried to fill; when every
    /// one of them failed the status is [`EnrichmentStatus::Failed`] rather than
    /// `Partial`, which is the signal that `/proc` is unusable (hidepid, missing
    /// capabilities) rather than that one process raced us.
    pub fn finish(mut self, expected_fields: usize) -> Self {
        let failed = self.enrichment_errors.len();
        self.enrichment_status = if failed == 0 {
            None // Complete — omitted from the wire format.
        } else if expected_fields > 0 && failed >= expected_fields {
            Some(EnrichmentStatus::Failed)
        } else {
            metrics().enrichment_partial();
            Some(EnrichmentStatus::Partial)
        };
        self
    }

    /// Effective status, treating an absent marker as complete.
    pub fn status(&self) -> EnrichmentStatus {
        self.enrichment_status.unwrap_or(EnrichmentStatus::Complete)
    }

    /// True when nothing needed recording — the common, fully-enriched case.
    pub fn is_clean(&self) -> bool {
        self.enrichment_status.is_none()
            && self.enrichment_errors.is_empty()
            && self.truncated_fields.is_empty()
    }

    /// True when any field was truncated.
    pub fn has_truncation(&self) -> bool {
        !self.truncated_fields.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::super::limits::{truncate_str, Truncation};
    use super::*;

    #[test]
    fn a_clean_enrichment_serializes_to_nothing() {
        let e = Enrichment::new().finish(3);
        assert!(e.is_clean());
        assert_eq!(e.status(), EnrichmentStatus::Complete);
        let json = serde_json::to_value(&e).unwrap();
        assert_eq!(
            json,
            serde_json::json!({}),
            "a fully-enriched event must not carry enrichment overhead"
        );
    }

    #[test]
    fn one_failed_field_of_several_is_partial() {
        let mut e = Enrichment::new();
        e.fail("cmdline", EnrichmentError::ProcessExited);
        let e = e.finish(3);
        assert_eq!(e.status(), EnrichmentStatus::Partial);
        assert_eq!(
            e.enrichment_errors["cmdline"],
            EnrichmentError::ProcessExited
        );
    }

    #[test]
    fn every_field_failing_is_failed_not_partial() {
        let mut e = Enrichment::new();
        e.fail("cmdline", EnrichmentError::PermissionDenied);
        e.fail("cwd", EnrichmentError::PermissionDenied);
        let e = e.finish(2);
        assert_eq!(
            e.status(),
            EnrichmentStatus::Failed,
            "total failure points at /proc being unusable, not a process race"
        );
    }

    #[test]
    fn partial_enrichment_matches_the_documented_wire_shape() {
        let mut e = Enrichment::new();
        e.fail("cmdline", EnrichmentError::ProcessExited);
        let json = serde_json::to_value(e.finish(3)).unwrap();
        assert_eq!(json["enrichment_status"], "partial");
        assert_eq!(json["enrichment_errors"]["cmdline"], "process_exited");
    }

    #[test]
    fn truncation_is_recorded_per_field() {
        let long = "x".repeat(131_072);
        let (cut, t) = truncate_str(&long, 16_384);
        let mut e = Enrichment::new();
        e.truncated("cmdline", t);
        let e = e.finish(1);

        assert_eq!(cut.len(), 16_384);
        assert!(e.has_truncation());
        assert_eq!(
            e.truncated_fields["cmdline"],
            Truncation::new(131_072, 16_384)
        );
        assert_eq!(
            e.status(),
            EnrichmentStatus::Complete,
            "truncation is not an enrichment failure — the field resolved"
        );
    }

    #[test]
    fn truncation_of_none_is_a_noop() {
        let mut e = Enrichment::new();
        e.truncated("cmdline", None);
        assert!(e.finish(1).is_clean());
    }

    #[test]
    fn io_errors_are_classified_by_kind() {
        use std::io::{Error, ErrorKind};
        assert_eq!(
            EnrichmentError::from_io(&Error::new(ErrorKind::NotFound, "gone")),
            EnrichmentError::ProcessExited,
            "a vanished /proc entry means the process exited"
        );
        assert_eq!(
            EnrichmentError::from_io(&Error::new(ErrorKind::PermissionDenied, "nope")),
            EnrichmentError::PermissionDenied
        );
        assert_eq!(
            EnrichmentError::from_io(&Error::new(ErrorKind::TimedOut, "slow")),
            EnrichmentError::Timeout
        );
        assert_eq!(
            EnrichmentError::from_io(&Error::other("?")),
            EnrichmentError::IoError
        );
    }

    #[test]
    fn round_trips_through_json() {
        let mut e = Enrichment::new();
        e.fail("cwd", EnrichmentError::Timeout);
        e.truncated("cmdline", Some(Truncation::new(100, 10)));
        let e = e.finish(2);

        let back: Enrichment = serde_json::from_str(&serde_json::to_string(&e).unwrap()).unwrap();
        assert_eq!(back, e);
        assert_eq!(back.status(), EnrichmentStatus::Partial);
    }

    #[test]
    fn error_labels_are_stable() {
        for (err, label) in [
            (EnrichmentError::ProcessExited, "process_exited"),
            (EnrichmentError::PermissionDenied, "permission_denied"),
            (EnrichmentError::Timeout, "timeout"),
            (EnrichmentError::ParseFailed, "parse_failed"),
            (EnrichmentError::Unsupported, "unsupported"),
            (EnrichmentError::IoError, "io_error"),
        ] {
            assert_eq!(err.as_str(), label);
            assert_eq!(serde_json::to_value(err).unwrap(), label);
        }
    }
}
