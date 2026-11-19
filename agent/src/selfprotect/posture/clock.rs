//! Boot identity and local clock-jump detection.
//!
//! A jump is a divergence between wall-clock and monotonic time. The monotonic
//! source must keep counting through suspend (Linux `CLOCK_BOOTTIME`, Windows
//! `GetTickCount64`), otherwise every laptop resume would look like a jump.
//!
//! This only *reports* a manipulated clock; all expiry decisions (session
//! tokens, certificates) stay server-side. A wall-clock change smaller than the
//! threshold (NTP slew, small steps) is deliberately ignored.

use std::path::Path;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use trapd_schema::{DetectionData, Severity};

pub const RULE_ID: &str = "selfprotect.time_jump";
pub const DEFAULT_THRESHOLD_SECS: i64 = 120;
const ANCHOR_FILE: &str = "clock_anchor.json";

/// Identifier of the current boot: Linux `boot_id`, Windows prefetcher boot
/// counter. `None` when neither can be read.
pub fn boot_id() -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        let s = std::fs::read_to_string("/proc/sys/kernel/random/boot_id").ok()?;
        let t = s.trim();
        (!t.is_empty()).then(|| t.to_string())
    }
    #[cfg(windows)]
    {
        use windows_sys::Win32::System::Registry::RRF_SUBKEY_WOW6464KEY;
        crate::collectors::windows::registry::dword(
            "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\\PrefetchParameters",
            "BootId",
            RRF_SUBKEY_WOW6464KEY,
        )
        .map(|v| format!("win-{v}"))
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        None
    }
}

/// Milliseconds on a monotonic clock that includes suspend time.
pub fn monotonic_ms() -> u64 {
    #[cfg(target_os = "linux")]
    {
        let mut ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: valid out-parameter; CLOCK_BOOTTIME exists on Linux >= 2.6.39.
        if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut ts) } == 0 {
            return (ts.tv_sec as u64) * 1000 + (ts.tv_nsec as u64) / 1_000_000;
        }
    }
    #[cfg(windows)]
    {
        // SAFETY: no arguments, no preconditions.
        return unsafe { windows_sys::Win32::System::SystemInformation::GetTickCount64() };
    }
    #[allow(unreachable_code)]
    {
        static START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
        START
            .get_or_init(std::time::Instant::now)
            .elapsed()
            .as_millis() as u64
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Jump {
    pub wall_delta_secs: i64,
    pub mono_delta_secs: i64,
    /// Positive: wall clock moved forward more than real time; negative: back.
    pub skew_secs: i64,
    pub across_reboot: bool,
}

/// Compares wall and monotonic deltas between observations.
#[derive(Debug)]
pub struct ClockWatch {
    last_mono_ms: u64,
    last_wall: DateTime<Utc>,
    threshold_secs: i64,
}

impl ClockWatch {
    pub fn new(mono_ms: u64, wall: DateTime<Utc>, threshold_secs: i64) -> Self {
        Self {
            last_mono_ms: mono_ms,
            last_wall: wall,
            threshold_secs: threshold_secs.max(1),
        }
    }

    pub fn observe(&mut self, mono_ms: u64, wall: DateTime<Utc>) -> Option<Jump> {
        let mono_delta = (mono_ms as i64 - self.last_mono_ms as i64) / 1000;
        let wall_delta = (wall - self.last_wall).num_seconds();
        self.last_mono_ms = mono_ms;
        self.last_wall = wall;
        let skew = wall_delta - mono_delta;
        (skew.abs() > self.threshold_secs).then_some(Jump {
            wall_delta_secs: wall_delta,
            mono_delta_secs: mono_delta,
            skew_secs: skew,
            across_reboot: false,
        })
    }
}

/// Last observation, persisted so a jump made while the agent was stopped is
/// still seen at the next start.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Anchor {
    pub boot_id: Option<String>,
    pub mono_ms: u64,
    pub wall: DateTime<Utc>,
}

/// Judge a restart against the persisted anchor. Same boot: full wall-vs-
/// monotonic comparison. New boot: monotonic time restarted, so only a wall
/// clock that went *backwards* beyond the threshold is suspicious (RTC reset or
/// manipulated before boot); forward gaps are just downtime.
pub fn check_against_anchor(
    anchor: &Anchor,
    boot_id: Option<&str>,
    mono_ms: u64,
    wall: DateTime<Utc>,
    threshold_secs: i64,
) -> Option<Jump> {
    let same_boot = matches!((&anchor.boot_id, boot_id), (Some(a), Some(b)) if a == b);
    if same_boot {
        let mut w = ClockWatch::new(anchor.mono_ms, anchor.wall, threshold_secs);
        return w.observe(mono_ms, wall);
    }
    let back = (wall - anchor.wall).num_seconds();
    (back < -threshold_secs.max(1)).then_some(Jump {
        wall_delta_secs: back,
        mono_delta_secs: 0,
        skew_secs: back,
        across_reboot: true,
    })
}

pub fn finding(j: &Jump) -> (Severity, DetectionData) {
    let dir = if j.skew_secs < 0 {
        "backward"
    } else {
        "forward"
    };
    (
        Severity::Medium,
        DetectionData {
            rule_id: RULE_ID.into(),
            title: "System clock jumped".into(),
            category: "defense_evasion".into(),
            mitre_tactic: Some("TA0005 Defense Evasion".into()),
            mitre_technique: Some("T1070.006".into()),
            confidence: 60,
            subject: "system_clock".into(),
            detail: format!(
                "Wall clock moved {dir} by {}s relative to monotonic time",
                j.skew_secs.abs()
            ),
            evidence: serde_json::json!({
                "direction": dir,
                "skew_secs": j.skew_secs,
                "wall_delta_secs": j.wall_delta_secs,
                "mono_delta_secs": j.mono_delta_secs,
                "across_reboot": j.across_reboot,
            }),
            ..Default::default()
        },
    )
}

pub fn load_anchor(dir: &Path) -> Option<Anchor> {
    let b = crate::paths::bounded_regular_bytes(&dir.join(ANCHOR_FILE), 4096).ok()?;
    serde_json::from_slice(&b).ok()
}

pub fn store_anchor(dir: &Path, a: &Anchor) -> std::io::Result<()> {
    super::snapshot::write_json_atomic(&dir.join(ANCHOR_FILE), a)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, TimeZone};

    fn t0() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 1, 1, 12, 0, 0).unwrap()
    }

    #[test]
    fn steady_clock_and_small_drift_are_silent() {
        let mut w = ClockWatch::new(0, t0(), 120);
        assert!(w.observe(30_000, t0() + Duration::seconds(30)).is_none());
        assert!(w.observe(60_000, t0() + Duration::seconds(75)).is_none()); // 45 s slew
    }

    #[test]
    fn forward_and_backward_jumps() {
        let mut w = ClockWatch::new(0, t0(), 120);
        let j = w.observe(30_000, t0() + Duration::hours(2)).unwrap();
        assert!(j.skew_secs > 7000 && !j.across_reboot);
        // Continues from the new wall time: no repeat alert.
        assert!(w
            .observe(60_000, t0() + Duration::hours(2) + Duration::seconds(30))
            .is_none());
        let j = w.observe(90_000, t0() - Duration::days(1)).unwrap();
        assert!(j.skew_secs < -86_000);
        let (sev, d) = finding(&j);
        assert_eq!(sev, Severity::Medium);
        assert_eq!(d.rule_id, RULE_ID);
        assert_eq!(d.evidence["direction"], "backward");
    }

    #[test]
    fn suspend_counted_by_monotonic_is_not_a_jump() {
        // 8 h suspend: both clocks advance 8 h.
        let mut w = ClockWatch::new(0, t0(), 120);
        assert!(w
            .observe(8 * 3600 * 1000, t0() + Duration::hours(8))
            .is_none());
    }

    #[test]
    fn anchor_same_boot_detects_jump_while_agent_was_down() {
        let a = Anchor {
            boot_id: Some("b1".into()),
            mono_ms: 1_000_000,
            wall: t0(),
        };
        // Agent restarted 60 s later (monotonic) but the clock moved a day back.
        let j =
            check_against_anchor(&a, Some("b1"), 1_060_000, t0() - Duration::days(1), 120).unwrap();
        assert!(j.skew_secs < 0 && !j.across_reboot);
        assert!(
            check_against_anchor(&a, Some("b1"), 1_060_000, t0() + Duration::seconds(61), 120)
                .is_none()
        );
    }

    #[test]
    fn anchor_new_boot_flags_only_backward() {
        let a = Anchor {
            boot_id: Some("b1".into()),
            mono_ms: 9_000_000,
            wall: t0(),
        };
        assert!(
            check_against_anchor(&a, Some("b2"), 5_000, t0() + Duration::days(3), 120).is_none()
        );
        let j =
            check_against_anchor(&a, Some("b2"), 5_000, t0() - Duration::hours(5), 120).unwrap();
        assert!(j.across_reboot);
        // Unknown boot id on either side is treated as a new boot.
        assert!(check_against_anchor(&a, None, 5_000, t0() + Duration::seconds(5), 120).is_none());
    }

    #[test]
    fn anchor_persistence_roundtrip() {
        let dir = std::env::temp_dir().join(format!("trapd_clock_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        assert!(load_anchor(&dir).is_none());
        let a = Anchor {
            boot_id: None,
            mono_ms: 7,
            wall: t0(),
        };
        store_anchor(&dir, &a).unwrap();
        assert_eq!(load_anchor(&dir).unwrap(), a);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn monotonic_source_advances() {
        let a = monotonic_ms();
        std::thread::sleep(std::time::Duration::from_millis(20));
        assert!(monotonic_ms() >= a);
    }
}
