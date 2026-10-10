//! File-activity heuristics shared by the Linux (inotify) and Windows
//! (`ReadDirectoryChangesW`) filesystem collectors: ransomware indicators,
//! event coalescing and agent-tamper timing.
//!
//! Everything here is platform-neutral and pure, so the rules that decide *what
//! counts as ransomware-like behaviour* are identical on both platforms and are
//! unit-tested on every CI host. The collectors own only the I/O: how events are
//! obtained and how paths are normalised before they are passed in.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::schema::{
    AgentEvent, EventAction, EventClass, EventData, RansomwareIndicatorData, Severity,
};

// ── Thresholds ────────────────────────────────────────────────────────────────

/// Shannon entropy above this value (bits/byte) is treated as likely encrypted.
pub const ENTROPY_THRESHOLD: f64 = 7.2;

/// Maximum file size read for entropy analysis (8 MiB).
pub const MAX_ENTROPY_BYTES: u64 = 8 * 1024 * 1024;

/// A "high_write_rate" indicator fires after this many *distinct* paths were
/// modified within [`MASS_MOD_WINDOW`].
pub const MASS_MOD_THRESHOLD: usize = 50;
pub const MASS_MOD_WINDOW: Duration = Duration::from_secs(10);

/// A burst of files appearing under ransomware extensions (typically renames
/// of the victim's documents) is reported once it reaches this many distinct
/// paths within [`RENAME_BURST_WINDOW`], and again at each higher tier of
/// [`burst_severity`]. One such file alone is only weak evidence (an archive
/// someone named `.locked`), thirty in seconds is an encryption run.
pub const RENAME_BURST_MIN: usize = 10;
pub const RENAME_BURST_CRITICAL: usize = 30;
pub const RENAME_BURST_WINDOW: Duration = Duration::from_secs(10);
/// Distinct modified files at which `high_write_rate` is critical, not high.
pub const MASS_MOD_CRITICAL: usize = 200;

/// Identical generic notifications inside this window collapse into one.
pub const GENERIC_COALESCE_WINDOW: Duration = Duration::from_secs(2);

/// Ransomware-associated file extension suffixes (lower-case).
pub const RANSOM_EXTENSIONS: &[&str] = &[
    ".locked",
    ".encrypted",
    ".crypt",
    ".crypted",
    ".crypto",
    ".enc",
    ".locky",
    ".wannacry",
    ".ryuk",
    ".maze",
    ".sodinokibi",
    ".revil",
    ".darkside",
    ".conti",
    ".lockbit",
    ".babuk",
    ".blackcat",
    ".hive",
    ".alphv",
];

/// Formats that are high-entropy by construction. A rewrite of a `.zip`, `.jpg`
/// or `.docx` says nothing about encryption — and encrypting one cannot raise
/// its entropy further — so entropy is never evaluated for them. (Ransomware
/// that renames them is caught by the extension rule instead.)
const COMPRESSED_BY_NATURE: &[&str] = &[
    ".zip", ".7z", ".rar", ".gz", ".tgz", ".bz2", ".xz", ".zst", ".cab", ".jar", ".apk", ".docx",
    ".xlsx", ".pptx", ".odt", ".ods", ".odp", ".pdf", ".jpg", ".jpeg", ".png", ".gif", ".webp",
    ".heic", ".mp3", ".mp4", ".m4a", ".mkv", ".mov", ".avi", ".webm", ".flac", ".ogg", ".msi",
    ".nupkg", ".whl",
];

// ── Pure helpers ──────────────────────────────────────────────────────────────

pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// Entropy of the file at `path`, or `None` when it is empty, too large or
/// unreadable, or of a format that is compressed by nature.
pub fn file_entropy(path: &str) -> Option<f64> {
    if is_compressed_by_nature(path) {
        return None;
    }
    let meta = std::fs::metadata(path).ok()?;
    let len = meta.len();
    if len == 0 || len > MAX_ENTROPY_BYTES {
        return None;
    }
    let data = std::fs::read(path).ok()?;
    Some(shannon_entropy(&data))
}

pub fn is_compressed_by_nature(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    COMPRESSED_BY_NATURE.iter().any(|ext| lower.ends_with(ext))
}

pub fn has_ransom_extension(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    RANSOM_EXTENSIONS.iter().any(|ext| lower.ends_with(ext))
}

/// Sliding window of *distinct* modified paths. Editors and sync clients touch
/// one file many times per write; counting notifications instead of files would
/// turn a single large save into a "mass modification".
#[derive(Default)]
pub struct MassModification {
    seen: HashMap<String, Instant>,
    reported_tier: u8,
}

impl MassModification {
    /// Report once at the high tier and again at the critical tier. Retain
    /// the window between tiers; rearm when it falls below the high threshold.
    pub fn record(&mut self, path: &str, now: Instant) -> Option<usize> {
        self.seen
            .retain(|_, last| now.duration_since(*last) <= MASS_MOD_WINDOW);
        // Check before inserting so a new path cannot hide an expired burst.
        if self.seen.len() < MASS_MOD_THRESHOLD {
            self.reported_tier = 0;
        }
        self.seen.insert(path.to_string(), now);
        // Only the most recent critical-threshold paths are needed to decide
        // either tier. Bound memory even during a sustained modification storm.
        if self.seen.len() > MASS_MOD_CRITICAL {
            let oldest = self
                .seen
                .iter()
                .min_by_key(|(_, last)| **last)
                .map(|(path, _)| path.clone());
            if let Some(oldest) = oldest {
                self.seen.remove(&oldest);
            }
        }
        let n = self.seen.len();
        let tier = if n >= MASS_MOD_CRITICAL {
            2
        } else if n >= MASS_MOD_THRESHOLD {
            1
        } else {
            0
        };
        if tier > self.reported_tier {
            self.reported_tier = tier;
            Some(n)
        } else {
            None
        }
    }
}

/// Severity of a burst of `count` distinct files in one window: from the size
/// of the burst, not from any single file name.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn burst_severity(count: usize) -> Severity {
    if count >= RENAME_BURST_CRITICAL {
        Severity::Critical
    } else if count >= RENAME_BURST_MIN {
        Severity::High
    } else {
        Severity::Medium
    }
}

/// Counts distinct files that appeared under a ransomware extension and
/// reports when the burst first crosses [`RENAME_BURST_MIN`] and again when it
/// crosses [`RENAME_BURST_CRITICAL`] (each tier at most once per burst).
#[derive(Default)]
pub struct RenameBurst {
    seen: HashMap<String, Instant>,
    reported_tier: u8,
}

impl RenameBurst {
    /// Returns `Some(distinct_count)` when this file moves the burst into a
    /// new severity tier.
    pub fn record(&mut self, path: &str, now: Instant) -> Option<usize> {
        self.seen
            .retain(|_, last| now.duration_since(*last) <= RENAME_BURST_WINDOW);
        self.seen.insert(path.to_string(), now);
        let n = self.seen.len();
        let tier = if n >= RENAME_BURST_CRITICAL {
            2
        } else if n >= RENAME_BURST_MIN {
            1
        } else {
            0
        };
        if tier == 0 {
            // The burst is over: a later one reports again.
            self.reported_tier = 0;
            return None;
        }
        if tier > self.reported_tier {
            self.reported_tier = tier;
            return Some(n);
        }
        None
    }
}

/// Collapses repeated identical notifications. Security-critical paths bypass
/// both the noise filter and the coalescing, so a persistence or credential
/// change is never swallowed.
#[derive(Default)]
pub struct Coalescer {
    recent: HashMap<(String, &'static str), Instant>,
}

impl Coalescer {
    /// `true` when this event should be dropped.
    pub fn suppress(
        &mut self,
        path: &str,
        action: &'static str,
        critical: bool,
        noisy: bool,
        now: Instant,
    ) -> bool {
        if critical {
            return false;
        }
        if noisy {
            return true;
        }
        let key = (path.to_string(), action);
        if self
            .recent
            .get(&key)
            .is_some_and(|last| now.duration_since(*last) < GENERIC_COALESCE_WINDOW)
        {
            return true;
        }
        self.recent.insert(key, now);
        if self.recent.len() > 4096 {
            self.recent
                .retain(|_, seen| now.duration_since(*seen) < GENERIC_COALESCE_WINDOW);
        }
        false
    }
}

/// Rate-limits an expensive per-path check (reading a file for entropy): once
/// per path per `interval`, and at most `burst` checks per second overall.
#[cfg_attr(not(windows), allow(dead_code))]
pub struct CheckThrottle {
    interval: Duration,
    burst: usize,
    per_path: HashMap<String, Instant>,
    window_start: Instant,
    in_window: usize,
}

#[cfg_attr(not(windows), allow(dead_code))]
impl CheckThrottle {
    pub fn new(interval: Duration, burst: usize, now: Instant) -> Self {
        Self {
            interval,
            burst,
            per_path: HashMap::new(),
            window_start: now,
            in_window: 0,
        }
    }

    pub fn allow(&mut self, path: &str, now: Instant) -> bool {
        if now.duration_since(self.window_start) >= Duration::from_secs(1) {
            self.window_start = now;
            self.in_window = 0;
        }
        if self.in_window >= self.burst {
            return false;
        }
        if self
            .per_path
            .get(path)
            .is_some_and(|last| now.duration_since(*last) < self.interval)
        {
            return false;
        }
        self.per_path.insert(path.to_string(), now);
        self.in_window += 1;
        if self.per_path.len() > 8192 {
            let interval = self.interval;
            self.per_path
                .retain(|_, seen| now.duration_since(*seen) < interval);
        }
        true
    }
}

// ── Event construction ────────────────────────────────────────────────────────

pub fn indicator_event(
    agent_id: &str,
    hostname: &str,
    indicator_type: &str,
    path: Option<String>,
    entropy: Option<f64>,
    write_rate: Option<u64>,
    details: String,
) -> AgentEvent {
    indicator_event_with(
        agent_id,
        hostname,
        Severity::High,
        indicator_type,
        path,
        entropy,
        write_rate,
        details,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn indicator_event_with(
    agent_id: &str,
    hostname: &str,
    severity: Severity,
    indicator_type: &str,
    path: Option<String>,
    entropy: Option<f64>,
    write_rate: Option<u64>,
    details: String,
) -> AgentEvent {
    AgentEvent::new(
        agent_id.to_string(),
        hostname.to_string(),
        EventClass::Filesystem,
        EventAction::RansomwareIndicator,
        severity,
        EventData::RansomwareIndicator(RansomwareIndicatorData {
            process_start_time: None,
            indicator_type: indicator_type.to_string(),
            path,
            pid: None,
            comm: None,
            entropy,
            write_rate,
            details,
        }),
    )
}

pub fn high_entropy_event(agent_id: &str, hostname: &str, path: &str, entropy: f64) -> AgentEvent {
    indicator_event(
        agent_id,
        hostname,
        "high_entropy",
        Some(path.to_string()),
        Some(entropy),
        None,
        format!("Shannon entropy {entropy:.2} bits/byte (threshold {ENTROPY_THRESHOLD})"),
    )
}

pub fn high_write_rate_event(agent_id: &str, hostname: &str, rate: u64) -> AgentEvent {
    indicator_event_with(
        agent_id,
        hostname,
        if rate as usize >= MASS_MOD_CRITICAL {
            Severity::Critical
        } else {
            Severity::High
        },
        "high_write_rate",
        None,
        None,
        Some(rate),
        format!(
            "{rate} file modifications in {}s (threshold {MASS_MOD_THRESHOLD})",
            MASS_MOD_WINDOW.as_secs()
        ),
    )
}

/// One file under a ransomware extension is weak evidence on its own, so a
/// single event is medium; the burst indicator ([`rename_burst_event`]) carries
/// the severity of an actual encryption run.
pub fn suspicious_extension_event(agent_id: &str, hostname: &str, path: &str) -> AgentEvent {
    indicator_event_with(
        agent_id,
        hostname,
        Severity::Medium,
        "suspicious_extension",
        Some(path.to_string()),
        None,
        None,
        format!("File appeared with ransomware-associated extension: {path}"),
    )
}

#[cfg_attr(not(windows), allow(dead_code))]
pub fn rename_burst_event(agent_id: &str, hostname: &str, count: usize) -> AgentEvent {
    indicator_event_with(
        agent_id,
        hostname,
        burst_severity(count),
        "rename_burst",
        None,
        None,
        Some(count as u64),
        format!(
            "{count} distinct files appeared under ransomware extensions in {}s",
            RENAME_BURST_WINDOW.as_secs()
        ),
    )
}

pub fn backup_deletion_event(agent_id: &str, hostname: &str, path: &str) -> AgentEvent {
    indicator_event(
        agent_id,
        hostname,
        "backup_deletion",
        Some(path.to_string()),
        None,
        None,
        format!("Backup path deleted or moved: {path}"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_separates_text_from_random_bytes() {
        assert_eq!(shannon_entropy(&[]), 0.0);
        assert!(shannon_entropy(b"aaaaaaaaaaaaaaaa") < 0.01);
        // A uniform byte distribution is the maximum: 8 bits/byte.
        let uniform: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
        assert!((shannon_entropy(&uniform) - 8.0).abs() < 1e-9);
        assert!(shannon_entropy(&uniform) >= ENTROPY_THRESHOLD);
        assert!(
            shannon_entropy(b"the quick brown fox jumps over the lazy dog") < ENTROPY_THRESHOLD
        );
    }

    #[test]
    fn natively_compressed_formats_are_exempt_from_entropy() {
        assert!(is_compressed_by_nature("C:\\Users\\a\\Pictures\\IMG_1.JPG"));
        assert!(is_compressed_by_nature("/home/a/report.docx"));
        assert!(!is_compressed_by_nature("/home/a/report.txt"));
        assert!(!is_compressed_by_nature("/home/a/report.docx.locked"));
        // A file we cannot judge is `None`, never a guess.
        assert!(file_entropy("/definitely/not/there.bin").is_none());
        assert!(file_entropy("/home/a/photo.png").is_none());
    }

    #[test]
    fn ransom_extensions_match_case_insensitively_at_the_end_only() {
        assert!(has_ransom_extension(
            "C:\\Users\\a\\Documents\\budget.xlsx.LOCKED"
        ));
        assert!(has_ransom_extension("/home/a/x.lockbit"));
        assert!(!has_ransom_extension("/home/a/locked-notes.txt"));
        assert!(!has_ransom_extension("/home/a/x.docx"));
    }

    #[test]
    fn mass_modification_counts_distinct_files_not_notifications() {
        let t0 = Instant::now();
        let mut m = MassModification::default();
        // One file saved a thousand times is not a mass modification.
        for i in 0..1000 {
            assert!(m
                .record("/home/a/big.db", t0 + Duration::from_millis(i))
                .is_none());
        }
        // Fifty distinct files within the window is.
        let mut m = MassModification::default();
        let mut fired = None;
        for i in 0..MASS_MOD_THRESHOLD {
            fired = m.record(
                &format!("/home/a/f{i}.txt"),
                t0 + Duration::from_millis(i as u64),
            );
        }
        assert_eq!(fired, Some(MASS_MOD_THRESHOLD));
        // Repeated notifications do not report the same tier again.
        assert!(m
            .record("/home/a/f0.txt", t0 + Duration::from_millis(100))
            .is_none());
    }

    #[test]
    fn mass_modification_escalates_once_per_tier_and_rearms_after_expiry() {
        let now = Instant::now();
        let mut m = MassModification::default();
        let mut alarms = Vec::new();
        for i in 0..250 {
            if let Some(count) = m.record(&format!("/doc{i}.txt"), now) {
                alarms.push((
                    count,
                    high_write_rate_event("agent", "host", count as u64).severity,
                ));
            }
        }
        assert_eq!(
            alarms,
            vec![(50, Severity::High), (200, Severity::Critical)]
        );
        for i in 0..250 {
            assert_eq!(m.record(&format!("/doc{i}.txt"), now), None);
        }
        let later = now + Duration::from_secs(11);
        let mut alarms = Vec::new();
        for i in 0..200 {
            if let Some(count) = m.record(&format!("/doc{i}.txt"), later) {
                alarms.push(count);
            }
        }
        assert_eq!(alarms, vec![50, 200]);
    }

    #[test]
    fn mass_modification_retains_recent_paths_with_bounded_memory() {
        let now = Instant::now();
        let mut m = MassModification::default();
        for i in 0..1000 {
            m.record(&format!("/old{i}"), now + Duration::from_millis(i));
            assert!(m.seen.len() <= MASS_MOD_CRITICAL);
        }
        // Refresh the most recent files just before the original window ends.
        for i in 800..1000 {
            assert_eq!(
                m.record(&format!("/old{i}"), now + Duration::from_secs(10)),
                None
            );
        }
        assert_eq!(m.record("/new", now + Duration::from_secs(11)), None);
        assert_eq!(m.seen.len(), 200);
        // Once enough files expire, the next burst can report high again.
        for i in 0..50 {
            let report = m.record(&format!("/later{i}"), now + Duration::from_secs(22));
            assert_eq!(report, (i == 49).then_some(50));
        }
    }

    #[test]
    fn modifications_outside_the_window_do_not_accumulate() {
        let t0 = Instant::now();
        let mut m = MassModification::default();
        for i in 0..MASS_MOD_THRESHOLD {
            // One new file every 5 s: never 50 inside 10 s.
            assert!(m
                .record(&format!("/f{i}"), t0 + Duration::from_secs(5 * i as u64))
                .is_none());
        }
    }

    #[test]
    fn repeated_modifications_keep_one_timestamp_and_refresh_the_window() {
        let now = Instant::now();
        let mut m = MassModification::default();
        for i in 0..2_000 {
            assert_eq!(m.record("/one.db", now + Duration::from_micros(i)), None);
        }
        assert_eq!(
            m.seen.len(),
            1,
            "notification history must stay bounded by paths"
        );
        m.record("/one.db", now + Duration::from_secs(9));
        let mut fired = None;
        for i in 0..MASS_MOD_THRESHOLD - 1 {
            fired = m.record(&format!("/{i}"), now + Duration::from_secs(11));
        }
        assert_eq!(
            fired,
            Some(MASS_MOD_THRESHOLD),
            "the last modification is still in the window"
        );
    }

    #[test]
    fn coalescer_drops_repeats_but_never_critical_paths() {
        let now = Instant::now();
        let mut c = Coalescer::default();
        assert!(!c.suppress("/tmp/x", "modify", false, false, now));
        assert!(c.suppress(
            "/tmp/x",
            "modify",
            false,
            false,
            now + Duration::from_millis(10)
        ));
        assert!(
            !c.suppress("/tmp/x", "create", false, false, now),
            "other action"
        );
        assert!(!c.suppress(
            "/tmp/x",
            "modify",
            false,
            false,
            now + GENERIC_COALESCE_WINDOW
        ));
        assert!(
            c.suppress("/tmp/a.swp", "modify", false, true, now),
            "noise"
        );
        for _ in 0..3 {
            assert!(
                !c.suppress("/etc/shadow", "modify", true, true, now),
                "critical"
            );
        }
    }

    #[test]
    fn throttle_limits_per_path_and_overall_rate() {
        let t0 = Instant::now();
        let mut t = CheckThrottle::new(Duration::from_secs(5), 3, t0);
        assert!(t.allow("a", t0));
        assert!(
            !t.allow("a", t0 + Duration::from_millis(100)),
            "same path too soon"
        );
        assert!(t.allow("b", t0 + Duration::from_millis(200)));
        assert!(t.allow("c", t0 + Duration::from_millis(300)));
        assert!(
            !t.allow("d", t0 + Duration::from_millis(400)),
            "burst of 3 per second exhausted"
        );
        assert!(t.allow("d", t0 + Duration::from_millis(1100)), "new second");
        assert!(
            t.allow("a", t0 + Duration::from_secs(6)),
            "interval elapsed"
        );
    }

    #[test]
    fn indicator_events_carry_the_documented_fields() {
        let e = high_write_rate_event("a", "h", 77);
        match e.data {
            EventData::RansomwareIndicator(d) => {
                assert_eq!(d.indicator_type, "high_write_rate");
                assert_eq!(d.write_rate, Some(77));
            }
            other => panic!("unexpected {other:?}"),
        }
        let e = high_entropy_event("a", "h", "/x", 7.9);
        assert!(matches!(e.data, EventData::RansomwareIndicator(d) if d.entropy == Some(7.9)));
    }

    #[test]
    fn burst_severity_scales_with_size() {
        assert_eq!(burst_severity(1), Severity::Medium);
        assert_eq!(burst_severity(9), Severity::Medium);
        assert_eq!(burst_severity(10), Severity::High);
        assert_eq!(burst_severity(29), Severity::High);
        assert_eq!(burst_severity(30), Severity::Critical);
    }

    #[test]
    fn thirty_renames_in_seconds_report_high_then_critical_once_each() {
        let t = Instant::now();
        let mut b = RenameBurst::default();
        let mut reports = Vec::new();
        for i in 0..40 {
            if let Some(n) = b.record(
                &format!("f{i}.docx.locked"),
                t + Duration::from_millis(i * 50),
            ) {
                reports.push(n);
            }
        }
        assert_eq!(reports, vec![RENAME_BURST_MIN, RENAME_BURST_CRITICAL]);
    }

    #[test]
    fn a_few_or_slow_renames_never_report_a_burst() {
        let t = Instant::now();
        let mut b = RenameBurst::default();
        for i in 0..9 {
            assert!(b.record(&format!("f{i}.locked"), t).is_none());
        }
        // One file every 3 s never accumulates 10 inside the window.
        let mut b = RenameBurst::default();
        for i in 0..50 {
            assert!(b
                .record(&format!("g{i}.locked"), t + Duration::from_secs(3 * i))
                .is_none());
        }
        // The same file renamed repeatedly is one file.
        let mut b = RenameBurst::default();
        for _ in 0..100 {
            assert!(b.record("same.locked", t).is_none());
        }
    }

    #[test]
    fn a_new_burst_after_a_quiet_period_reports_again() {
        let t = Instant::now();
        let mut b = RenameBurst::default();
        for i in 0..12 {
            b.record(&format!("a{i}"), t);
        }
        let later = t + Duration::from_secs(60);
        assert!(b.record("b0", later).is_none());
        let mut got = None;
        for i in 1..12 {
            got = got.or(b.record(&format!("b{i}"), later));
        }
        assert_eq!(got, Some(RENAME_BURST_MIN));
    }

    #[test]
    fn single_events_stay_medium_and_big_write_bursts_go_critical() {
        let e = suspicious_extension_event("a", "h", "C:\\x.locked");
        assert_eq!(e.severity, Severity::Medium);
        assert_eq!(high_write_rate_event("a", "h", 60).severity, Severity::High);
        assert_eq!(
            high_write_rate_event("a", "h", 250).severity,
            Severity::Critical
        );
        let e = rename_burst_event("a", "h", 30);
        assert_eq!(e.severity, Severity::Critical);
        assert!(matches!(
            e.data,
            EventData::RansomwareIndicator(d)
                if d.indicator_type == "rename_burst" && d.write_rate == Some(30)
        ));
    }
}
