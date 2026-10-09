//! Source-aware policy shared by online admission, replay and local response.
//! A weak observation is retained as evidence; tamper cannot hide behind flags.
use trapd_schema::{
    DetectionMode, HoneytokenAccessData, HoneytokenAssessment as A, HoneytokenSensor as S, Severity,
};

pub struct HoneytokenAssessmentOutcome {
    pub severity: Severity,
    pub mode: DetectionMode,
    pub reasons: Vec<String>,
}

pub fn assess(data: &HoneytokenAccessData, reported: Severity) -> HoneytokenAssessmentOutcome {
    let kind = data.access_kind.as_str();
    let (severity, mode, reason) =
        if matches!(kind, "modify" | "unlink" | "rename" | "hardlink" | "exec") {
            (
                Severity::Critical,
                DetectionMode::Alert,
                "tamper_or_execution",
            )
        } else if matches!(kind, "stat" | "statx" | "readlink" | "getdents") {
            (Severity::Low, DetectionMode::Signal, "metadata_only")
        } else if data.sensor == Some(S::WindowsLastAccess) {
            (Severity::Low, DetectionMode::Signal, "timestamp_only")
        } else if data.allowlisted_accessor && data.scheduled_sweep {
            (
                Severity::Low,
                DetectionMode::Signal,
                "verified_scheduled_sweep",
            )
        } else if data.sensor == Some(S::WindowsAudit)
            && data.assessment == Some(A::OwnerInteractive)
        {
            (
                Severity::High,
                DetectionMode::Alert,
                "owner_interactive_read",
            )
        } else if data.confidence < 50 {
            (Severity::Low, DetectionMode::Signal, "low_confidence")
        } else {
            (
                reported.max(Severity::High),
                DetectionMode::Alert,
                "content_access_or_unknown",
            )
        };
    let mut reasons = vec![reason.into()];
    for code in data.assessment_reasons.iter().take(8) {
        if matches!(
            code.as_str(),
            "remote_owner_session" | "outside_learned_hours"
        ) && !reasons.contains(code)
        {
            reasons.push(code.clone());
        }
    }
    HoneytokenAssessmentOutcome {
        severity,
        mode,
        reasons,
    }
}
