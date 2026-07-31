//! `trapd-agent diagnostics telemetry` — the operator-facing view of the
//! pipeline.
//!
//! This command answers one question: *is telemetry from this host actually
//! reaching the backend, and if not, where is it stopping?* It renders the
//! report the running agent publishes, walking the pipeline in order so the
//! first stage showing losses is the one to investigate.
//!
//! Rendering is a pure function of a [`TelemetryReport`], so the whole output
//! is testable without running an agent.

use std::fmt::Write as _;

use super::drops::DropReason;
use super::metrics::now_unix_ms;
use super::snapshot::TelemetryReport;

/// Render the human-readable report.
pub fn render(report: &TelemetryReport, now_unix_ms: u64) -> String {
    let m = &report.metrics;
    let mut out = String::with_capacity(2048);

    let _ = writeln!(out, "Overall status: {}", report.health.as_str());
    if report.health.needs_attention() {
        let _ = writeln!(out, "  ** operator action required **");
    }
    if report.is_stale(now_unix_ms) {
        let _ = writeln!(
            out,
            "  ** report is {} old — the agent may not be running **",
            humanize_ms(report.age_ms(now_unix_ms))
        );
    }
    let _ = writeln!(
        out,
        "Agent: v{} pid {} up {} (boot {})",
        report.agent_version,
        report.agent_pid,
        humanize_secs(report.uptime_secs),
        short_boot(&report.boot_id),
    );
    if report.offline_mode {
        let _ = writeln!(out, "Mode: offline — telemetry is written locally only");
    }

    // ── Collector ───────────────────────────────────────────────────────────
    let _ = writeln!(out, "\nCollector:");
    let _ = writeln!(out, "  Mode: {}", m.collector_mode);
    let _ = writeln!(
        out,
        "  Events received: {}",
        thousands(m.collector_events_received_total)
    );
    let _ = writeln!(
        out,
        "  Kernel lost events: {}",
        thousands(m.ebpf_events_lost_total)
    );
    let _ = writeln!(
        out,
        "  Userspace drops: {}",
        thousands(m.collector_events_dropped_total)
    );
    if m.collector_failures_total > 0 {
        let _ = writeln!(out, "  Collector failures: {}", m.collector_failures_total);
    }

    // Per-reason breakdown — the point of the whole exercise.
    if m.collector_events_dropped_total > 0 {
        let _ = writeln!(out, "\nDrops by reason:");
        for reason in DropReason::ALL {
            if let Some(count) = m.collector_events_dropped_by_reason.get(reason.as_str()) {
                if *count > 0 {
                    let _ = writeln!(out, "  {:<26} {}", reason.as_str(), thousands(*count));
                }
            }
        }
        let unattributed = m
            .collector_events_dropped_total
            .saturating_sub(m.total_attributed_drops());
        if unattributed > 0 {
            let _ = writeln!(
                out,
                "  {:<26} {}   ** unattributed — this is a bug **",
                "(no reason recorded)", unattributed
            );
        }
    }

    // ── Enrichment ──────────────────────────────────────────────────────────
    if m.enrichment_attempts_total > 0 {
        let _ = writeln!(out, "\nEnrichment:");
        let _ = writeln!(out, "  Attempts: {}", thousands(m.enrichment_attempts_total));
        let _ = writeln!(
            out,
            "  Field failures: {} (events kept, fields marked)",
            thousands(m.enrichment_failures_total)
        );
        let _ = writeln!(
            out,
            "  Partial events: {}",
            thousands(m.enrichment_partial_total)
        );
        let _ = writeln!(
            out,
            "  Truncated fields: {}",
            thousands(m.enrichment_truncations_total)
        );
        if let Some(p95) = m.enrichment_duration.p95_ms {
            let _ = writeln!(out, "  p95 duration: {p95} ms");
        }
    }

    // ── Queue ───────────────────────────────────────────────────────────────
    let _ = writeln!(out, "\nPersistent queue:");
    let _ = writeln!(out, "  Events: {}", thousands(m.spool_events));
    let _ = writeln!(
        out,
        "  Used: {} of {} ({:.1}%)",
        humanize_bytes(m.spool_bytes),
        humanize_bytes(m.spool_capacity_bytes),
        m.spool_utilization() * 100.0
    );
    let _ = writeln!(
        out,
        "  Corrupt records: {}{}",
        m.spool_corrupt_records_total,
        if m.spool_corrupt_records_total > 0 {
            "   ** telemetry was lost to corruption **"
        } else {
            ""
        }
    );
    if m.spool_truncated_tail_records_total > 0 {
        let _ = writeln!(
            out,
            "  Torn tail records: {} (expected after an unclean stop)",
            m.spool_truncated_tail_records_total
        );
    }
    if m.spool_recovered_records_total > 0 {
        let _ = writeln!(
            out,
            "  Recovered on start: {}",
            thousands(m.spool_recovered_records_total)
        );
    }

    // ── Transport ───────────────────────────────────────────────────────────
    let _ = writeln!(out, "\nTransport:");
    let _ = writeln!(
        out,
        "  Backend: {}",
        if report.offline_mode {
            "not configured (offline)"
        } else if m.backend_connected {
            "connected"
        } else {
            "unreachable"
        }
    );
    let _ = writeln!(
        out,
        "  Last acknowledgement: {}",
        match m.last_ack_unix_ms {
            Some(ts) => format!("{} ago", humanize_ms(now_unix_ms.saturating_sub(ts))),
            None => "never".to_string(),
        }
    );
    let _ = writeln!(
        out,
        "  Events acknowledged: {}",
        thousands(m.transport_events_acknowledged_total)
    );
    let _ = writeln!(out, "  Pending events: {}", thousands(m.spool_events));
    let _ = writeln!(
        out,
        "  Retried events: {}",
        thousands(m.transport_events_retried_total)
    );
    if m.backend_rejected_events_total > 0 {
        let _ = writeln!(
            out,
            "  Rejected by backend: {}   ** permanent loss **",
            thousands(m.backend_rejected_events_total)
        );
    }
    let _ = writeln!(
        out,
        "  Batches: {} sent, {} failed",
        thousands(m.transport_batches_sent_total),
        thousands(m.transport_batches_failed_total)
    );

    // ── Latency ─────────────────────────────────────────────────────────────
    let _ = writeln!(out, "\nEnd-to-end:");
    if m.end_to_end_latency.count == 0 {
        let _ = writeln!(out, "  No acknowledged events yet");
    } else {
        for (label, value) in [
            ("p50", m.end_to_end_latency.p50_ms),
            ("p95", m.end_to_end_latency.p95_ms),
            ("p99", m.end_to_end_latency.p99_ms),
        ] {
            if let Some(v) = value {
                let _ = writeln!(out, "  {label} latency: {v} ms");
            }
        }
        let _ = writeln!(out, "  Samples: {}", thousands(m.end_to_end_latency.count));
    }

    // ── Accounting invariant ────────────────────────────────────────────────
    let _ = writeln!(out, "\nAccounting:");
    let _ = writeln!(
        out,
        "  Sequence numbers issued: {}",
        thousands(report.sequences_issued)
    );
    if m.drops_fully_attributed() {
        let _ = writeln!(
            out,
            "  Every dropped event has a recorded reason: yes"
        );
    } else {
        let _ = writeln!(
            out,
            "  Every dropped event has a recorded reason: NO — {} unaccounted",
            m.collector_events_dropped_total
                .saturating_sub(m.total_attributed_drops())
        );
    }

    out
}

/// Entry point for the `diagnostics telemetry` subcommand.
///
/// Returns the rendered report, or an explanation of why it is unavailable —
/// never a zeroed report, which would be indistinguishable from a healthy idle
/// agent.
pub fn run() -> String {
    let path = TelemetryReport::default_path();
    match TelemetryReport::read(&path) {
        Ok(report) => render(&report, now_unix_ms()),
        Err(e) => format!(
            "No telemetry report available at {}: {e}\n\n\
             The report is published by a running agent. If the agent is running, check that \
             it can write to its state directory (TRAPD_STATE_DIR).\n",
            path.display()
        ),
    }
}

// ── Formatting helpers ───────────────────────────────────────────────────────

/// Thousands separators, so a seven-digit event count is readable at a glance.
fn thousands(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

fn humanize_bytes(bytes: u64) -> String {
    const UNITS: [(&str, u64); 4] = [
        ("GiB", 1024 * 1024 * 1024),
        ("MiB", 1024 * 1024),
        ("KiB", 1024),
        ("B", 1),
    ];
    for (unit, size) in UNITS {
        if bytes >= size {
            return if size == 1 {
                format!("{bytes} B")
            } else {
                format!("{:.1} {unit}", bytes as f64 / size as f64)
            };
        }
    }
    "0 B".to_string()
}

fn humanize_secs(secs: u64) -> String {
    match secs {
        s if s < 60 => format!("{s}s"),
        s if s < 3600 => format!("{}m{}s", s / 60, s % 60),
        s if s < 86_400 => format!("{}h{}m", s / 3600, (s % 3600) / 60),
        s => format!("{}d{}h", s / 86_400, (s % 86_400) / 3600),
    }
}

fn humanize_ms(ms: u64) -> String {
    if ms < 1000 {
        format!("{ms}ms")
    } else {
        humanize_secs(ms / 1000)
    }
}

/// First segment of a boot id — enough to tell two boots apart in a log line.
fn short_boot(boot_id: &str) -> &str {
    boot_id.split('-').next().unwrap_or(boot_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::telemetry::health::HealthState;
    use crate::telemetry::histogram::LatencySnapshot;
    use crate::telemetry::metrics::MetricsSnapshot;

    const NOW: u64 = 1_700_000_000_000;

    fn healthy_report() -> TelemetryReport {
        TelemetryReport {
            version: 1,
            agent_version: "0.4.4".into(),
            agent_pid: 4242,
            boot_id: "abcd1234-0000-0000-0000-000000000000".into(),
            sequences_issued: 12_482_194,
            captured_at_unix_ms: NOW - 1000,
            uptime_secs: 7265,
            offline_mode: false,
            health: HealthState::Healthy,
            metrics: MetricsSnapshot {
                collector_mode: "ebpf".into(),
                collector_events_received_total: 12_482_194,
                ebpf_events_lost_total: 0,
                collector_events_dropped_total: 0,
                spool_events: 42,
                spool_bytes: 3_984_589,
                spool_capacity_events: 50_000,
                spool_capacity_bytes: 1024 * 1024 * 1024,
                transport_events_acknowledged_total: 12_482_152,
                transport_events_retried_total: 18,
                transport_batches_sent_total: 1000,
                backend_connected: true,
                last_ack_unix_ms: Some(NOW - 3000),
                end_to_end_latency: LatencySnapshot {
                    count: 12_482_152,
                    p50_ms: Some(14),
                    p95_ms: Some(38),
                    p99_ms: Some(91),
                    max_ms: Some(400),
                },
                ..Default::default()
            },
        }
    }

    #[test]
    fn the_report_covers_every_mandated_section() {
        let out = render(&healthy_report(), NOW);
        for section in [
            "Overall status:",
            "Collector:",
            "Mode:",
            "Events received:",
            "Kernel lost events:",
            "Userspace drops:",
            "Persistent queue:",
            "Events:",
            "Used:",
            "Corrupt records:",
            "Transport:",
            "Backend:",
            "Last acknowledgement:",
            "Pending events:",
            "Retried events:",
            "End-to-end:",
            "p50 latency:",
            "p95 latency:",
            "p99 latency:",
        ] {
            assert!(out.contains(section), "missing {section:?} in:\n{out}");
        }
    }

    #[test]
    fn a_healthy_agent_reports_healthy_without_alarms() {
        let out = render(&healthy_report(), NOW);
        assert!(out.contains("Overall status: healthy"));
        assert!(!out.contains("operator action required"));
        assert!(!out.contains("**"), "no alarm markers expected:\n{out}");
        assert!(out.contains("Every dropped event has a recorded reason: yes"));
    }

    #[test]
    fn latency_percentiles_are_shown() {
        let out = render(&healthy_report(), NOW);
        assert!(out.contains("p50 latency: 14 ms"));
        assert!(out.contains("p95 latency: 38 ms"));
        assert!(out.contains("p99 latency: 91 ms"));
    }

    #[test]
    fn drops_are_broken_down_by_reason() {
        // The operator has to be able to see *where* events are being lost.
        let mut r = healthy_report();
        r.health = HealthState::Backpressured;
        r.metrics.collector_events_dropped_total = 150;
        r.metrics
            .collector_events_dropped_by_reason
            .insert("userspace_channel_full".into(), 100);
        r.metrics
            .collector_events_dropped_by_reason
            .insert("event_too_large".into(), 50);

        let out = render(&r, NOW);
        assert!(out.contains("Drops by reason:"));
        assert!(out.contains("userspace_channel_full"));
        assert!(out.contains("event_too_large"));
        assert!(out.contains("Every dropped event has a recorded reason: yes"));
    }

    #[test]
    fn an_unattributed_drop_is_called_out_as_a_bug() {
        // This is the failure the whole design exists to prevent, so it must be
        // impossible to miss in the output.
        let mut r = healthy_report();
        r.metrics.collector_events_dropped_total = 10;
        r.metrics
            .collector_events_dropped_by_reason
            .insert("internal_error".into(), 4);

        let out = render(&r, NOW);
        assert!(out.contains("unattributed"), "must flag the gap:\n{out}");
        assert!(out.contains("recorded reason: NO"));
        assert!(out.contains("6 unaccounted"), "must quantify it:\n{out}");
    }

    #[test]
    fn corruption_is_flagged_prominently() {
        let mut r = healthy_report();
        r.health = HealthState::RecoveryRequired;
        r.metrics.spool_corrupt_records_total = 3;

        let out = render(&r, NOW);
        assert!(out.contains("Overall status: recovery_required"));
        assert!(out.contains("operator action required"));
        assert!(out.contains("telemetry was lost to corruption"));
    }

    #[test]
    fn a_torn_tail_is_shown_as_expected_not_as_damage() {
        let mut r = healthy_report();
        r.metrics.spool_truncated_tail_records_total = 1;
        let out = render(&r, NOW);
        assert!(out.contains("expected after an unclean stop"));
        assert!(!out.contains("lost to corruption"));
    }

    #[test]
    fn backend_rejections_are_marked_as_permanent_loss() {
        let mut r = healthy_report();
        r.metrics.backend_rejected_events_total = 12;
        let out = render(&r, NOW);
        assert!(out.contains("Rejected by backend: 12"));
        assert!(out.contains("permanent loss"));
    }

    #[test]
    fn a_stale_report_warns_that_the_agent_may_be_gone() {
        let mut r = healthy_report();
        r.captured_at_unix_ms = NOW - 600_000; // ten minutes old
        let out = render(&r, NOW);
        assert!(out.contains("the agent may not be running"), "got:\n{out}");
    }

    #[test]
    fn offline_mode_is_stated_rather_than_shown_as_a_fault() {
        let mut r = healthy_report();
        r.offline_mode = true;
        r.metrics.backend_connected = false;
        r.metrics.last_ack_unix_ms = None;

        let out = render(&r, NOW);
        assert!(out.contains("Mode: offline"));
        assert!(out.contains("not configured (offline)"));
        assert!(!out.contains("unreachable"), "offline is not a failure:\n{out}");
    }

    #[test]
    fn an_unreachable_backend_is_named() {
        let mut r = healthy_report();
        r.health = HealthState::Offline;
        r.metrics.backend_connected = false;
        let out = render(&r, NOW);
        assert!(out.contains("Backend: unreachable"));
    }

    #[test]
    fn a_never_acknowledged_agent_says_never() {
        let mut r = healthy_report();
        r.metrics.last_ack_unix_ms = None;
        assert!(render(&r, NOW).contains("Last acknowledgement: never"));
    }

    #[test]
    fn latency_section_handles_no_samples() {
        let mut r = healthy_report();
        r.metrics.end_to_end_latency = LatencySnapshot::default();
        let out = render(&r, NOW);
        assert!(out.contains("No acknowledged events yet"));
    }

    #[test]
    fn rendering_never_panics_on_extreme_values() {
        let mut r = healthy_report();
        r.metrics.collector_events_received_total = u64::MAX;
        r.metrics.spool_bytes = u64::MAX;
        r.metrics.spool_capacity_bytes = 0; // division guard
        r.metrics.last_ack_unix_ms = Some(u64::MAX); // clock skew
        r.captured_at_unix_ms = u64::MAX;
        r.sequences_issued = u64::MAX;
        let out = render(&r, NOW);
        assert!(!out.is_empty());
    }

    // ── Formatting ──────────────────────────────────────────────────────────

    #[test]
    fn thousands_separators_are_placed_correctly() {
        assert_eq!(thousands(0), "0");
        assert_eq!(thousands(1), "1");
        assert_eq!(thousands(999), "999");
        assert_eq!(thousands(1_000), "1,000");
        assert_eq!(thousands(12_482_194), "12,482,194");
        assert_eq!(thousands(1_000_000_000), "1,000,000,000");
    }

    #[test]
    fn byte_sizes_are_humanized() {
        assert_eq!(humanize_bytes(0), "0 B");
        assert_eq!(humanize_bytes(512), "512 B");
        assert_eq!(humanize_bytes(1024), "1.0 KiB");
        assert_eq!(humanize_bytes(3_984_589), "3.8 MiB");
        assert_eq!(humanize_bytes(1024 * 1024 * 1024), "1.0 GiB");
    }

    #[test]
    fn durations_are_humanized() {
        assert_eq!(humanize_secs(45), "45s");
        assert_eq!(humanize_secs(90), "1m30s");
        assert_eq!(humanize_secs(7265), "2h1m");
        assert_eq!(humanize_secs(90_000), "1d1h");
        assert_eq!(humanize_ms(500), "500ms");
        assert_eq!(humanize_ms(90_000), "1m30s");
    }

    #[test]
    fn boot_ids_are_shortened_for_display() {
        assert_eq!(short_boot("abcd1234-0000-0000-0000-000000000000"), "abcd1234");
        assert_eq!(short_boot("nodashes"), "nodashes");
        assert_eq!(short_boot(""), "");
    }
}
