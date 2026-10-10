//! Conservative on-host online learning. Novelty is evidence, never an allowlist.
use crate::schema::DetectionData;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::time::{Duration, Instant};

const MAX_ENTITIES: usize = 8192;
/// Per-user cap on confirmed and on pending binaries. A Windows workstation
/// runs hundreds of distinct executables; at 64 the confirmed set filled up
/// within days and every further binary stayed "novel" forever.
const MAX_CHILDREN: usize = 512;
const MAX_STATE_BYTES: u64 = 8 * 1024 * 1024;
const MAX_PROFILE_BYTES: usize = 4 * 1024 * 1024;
const DAY: u64 = 86_400;
/// A once-seen candidate that has not recurred for this long no longer holds a slot.
const PENDING_TTL: u64 = 14 * DAY;
const RATE_WARMUP: u32 = 5;
const RATE_Z_THRESHOLD: f64 = 4.0;

/// Exponentially-weighted rolling mean + variance (Welford-style EWMA).
#[derive(Debug, Clone)]
struct Ewma {
    mean: f64,
    var: f64,
    count: u32,
    alpha: f64,
}

impl Ewma {
    fn new(alpha: f64) -> Self {
        Self {
            mean: 0.0,
            var: 0.0,
            count: 0,
            alpha,
        }
    }

    /// Z-score of `x` against the current distribution (0 until warmed up).
    ///
    /// Count data tends to be Poisson-like, so the standard deviation is floored
    /// at `sqrt(mean)`: this prevents a perfectly-constant baseline (measured
    /// variance ≈ 0) from making every deviation infinite, while still scaling
    /// the tolerance with the baseline volume (a high-traffic user needs a much
    /// bigger absolute jump to look anomalous).
    fn zscore(&self, x: f64) -> f64 {
        if self.count < 2 {
            return 0.0;
        }
        let std = self.var.sqrt().max(self.mean.max(1.0).sqrt());
        (x - self.mean) / std
    }

    fn update(&mut self, x: f64) {
        if self.count == 0 {
            self.mean = x;
            self.var = 0.0;
        } else {
            let diff = x - self.mean;
            let incr = self.alpha * diff;
            self.mean += incr;
            // EWMA variance (West, 1979).
            self.var = (1.0 - self.alpha) * (self.var + diff * incr);
        }
        self.count = self.count.saturating_add(1);
    }
}

#[derive(Debug, Clone)]
struct RateProfile {
    window_start: Instant,
    window_count: u32,
    learning_eligible: bool,
    stat: Ewma,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Candidate {
    first_seen: u64,
    last_seen: u64,
    count: u32,
}
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct BinaryProfile {
    first_seen: u64,
    confirmed: HashSet<String>,
    pending: HashMap<String, Candidate>,
}

pub struct BaselineEngine {
    profiles: HashMap<String, BinaryProfile>,
    rates: HashMap<String, RateProfile>,
    profile_bytes: usize,
}

fn valid_text(value: &str) -> bool {
    !value.trim().is_empty()
        && value.len() <= 4096
        && !value.chars().any(char::is_control)
        && !value.eq_ignore_ascii_case("unknown")
}
fn identity(user: &str, exe: &str) -> Option<(String, String)> {
    if !valid_text(user) || !valid_text(exe) {
        return None;
    }
    let windows = exe.contains('\\') || exe.as_bytes().get(1) == Some(&b':');
    Some(if windows {
        (
            user.to_ascii_lowercase(),
            exe.replace('\\', "/").to_ascii_lowercase(),
        )
    } else {
        (user.to_string(), exe.to_string())
    })
}

/// Images under admin-only Windows install locations (input is the normalised,
/// lower-cased identity form). A first run there is routine servicing and
/// feature rollout (Store apps, SystemApps, updated vendor helpers), not a
/// novel binary; planting one needs admin and is covered by the integrity,
/// FIM and persistence rules. The binary is still learned.
fn is_os_protected_image(exe: &str) -> bool {
    use crate::collectors::win_mem_rules::{install_roots, under_install_roots};
    const WINDOWS_SUBDIRS: &[&str] = &[
        "system32/",
        "syswow64/",
        "systemapps/",
        "winsxs/",
        "immersivecontrolpanel/",
        "servicing/",
    ];
    under_install_roots(exe, install_roots(), WINDOWS_SUBDIRS, true)
}

impl BaselineEngine {
    pub fn new() -> Self {
        Self {
            profiles: HashMap::new(),
            rates: HashMap::new(),
            profile_bytes: 0,
        }
    }

    pub fn observe_exec_at(
        &mut self,
        user: &str,
        exe: &str,
        now: Instant,
        wall: u64,
        eligible: bool,
    ) -> Option<DetectionData> {
        let (user, exe) = identity(user, exe)?;
        if wall == 0 {
            return None;
        }
        if !self.profiles.contains_key(&user) {
            if !eligible
                || self.profiles.len() >= MAX_ENTITIES
                || self.profile_bytes + user.len() * 2 + 256 > MAX_PROFILE_BYTES
            {
                return None;
            }
            self.profile_bytes += user.len() * 2 + 256;
            self.profiles.insert(
                user.clone(),
                BinaryProfile {
                    first_seen: wall,
                    ..Default::default()
                },
            );
        }
        let profile = self.profiles.get_mut(&user)?;
        if wall < profile.first_seen {
            profile.first_seen = wall; // Clock rollback restarts warmup; never matures it.
            self.profile_bytes = self
                .profile_bytes
                .saturating_sub(profile.pending.keys().map(|exe| exe.len() + 128).sum());
            profile.pending.clear();
        }
        let known = profile.confirmed.contains(&exe);
        let mature = profile.confirmed.len() >= 3 && wall.saturating_sub(profile.first_seen) >= DAY;
        if !known && eligible {
            if profile.pending.len() >= MAX_CHILDREN && !profile.pending.contains_key(&exe) {
                let stale: Vec<String> = profile
                    .pending
                    .iter()
                    .filter(|(_, c)| wall.saturating_sub(c.last_seen) > PENDING_TTL)
                    .map(|(k, _)| k.clone())
                    .collect();
                for key in stale {
                    profile.pending.remove(&key);
                    self.profile_bytes = self.profile_bytes.saturating_sub(key.len() + 128);
                }
            }
            if !profile.pending.contains_key(&exe)
                && profile.pending.len() < MAX_CHILDREN
                && self.profile_bytes + exe.len() + 128 <= MAX_PROFILE_BYTES
            {
                self.profile_bytes += exe.len() + 128;
                profile.pending.insert(
                    exe.clone(),
                    Candidate {
                        first_seen: wall,
                        last_seen: wall,
                        count: 0,
                    },
                );
            }
            if let Some(candidate) = profile.pending.get_mut(&exe) {
                if wall >= candidate.last_seen {
                    candidate.count = candidate.count.saturating_add(1);
                    candidate.last_seen = wall;
                }
                if candidate.count >= 3
                    && wall.saturating_sub(candidate.first_seen) >= DAY
                    && profile.confirmed.len() < MAX_CHILDREN
                {
                    profile.confirmed.insert(exe.clone());
                    profile.pending.remove(&exe);
                }
            }
        } else if !eligible && profile.pending.remove(&exe).is_some() {
            self.profile_bytes = self.profile_bytes.saturating_sub(exe.len() + 128);
        }
        let novelty = (!known && mature && !is_os_protected_image(&exe)).then(|| DetectionData {
            rule_id: "anomaly.rare_binary_for_user".into(), title: "Anomalous binary for user".into(), category: "anomaly".into(),
            mitre_tactic: Some("TA0002 Execution".into()), mitre_technique: Some("T1059".into()), confidence: 55,
            subject: format!("{user}: {exe}"), detail: "Executable is absent from the confirmed local baseline".into(),
            evidence: serde_json::json!({"user":user,"exe":exe,"baseline_kind":"per_user_binary_novelty", "confirmed_binaries":profile.confirmed.len(),"history_seconds":wall.saturating_sub(profile.first_seen),"learning_eligible":eligible}),
            ..Default::default()
        });
        let rate = self.update_rate_eligible(&user, now, eligible);
        novelty.or(rate)
    }

    #[cfg(test)]
    fn update_rate(&mut self, user: &str, now: Instant) -> Option<DetectionData> {
        self.update_rate_eligible(user, now, true)
    }

    fn update_rate_eligible(
        &mut self,
        user: &str,
        now: Instant,
        eligible: bool,
    ) -> Option<DetectionData> {
        if !valid_text(user) || (!self.rates.contains_key(user) && self.rates.len() >= MAX_ENTITIES)
        {
            return None;
        }
        let p = self
            .rates
            .entry(user.into())
            .or_insert_with(|| RateProfile {
                window_start: now,
                window_count: 0,
                learning_eligible: true,
                stat: Ewma::new(0.3),
            });
        let elapsed = now
            .checked_duration_since(p.window_start)
            .unwrap_or(Duration::ZERO);
        if elapsed < Duration::from_secs(60) {
            p.window_count = p.window_count.saturating_add(1);
            p.learning_eligible &= eligible;
            return None;
        }
        let completed = p.window_count as f64;
        let mean = p.stat.mean;
        let z = p.stat.zscore(completed);
        let warmed = p.stat.count >= RATE_WARMUP;
        let valid = elapsed <= Duration::from_secs(120) && p.window_count > 0;
        if valid && p.learning_eligible && z < RATE_Z_THRESHOLD {
            p.stat.update(completed);
        }
        p.window_start = now;
        p.window_count = 1;
        p.learning_eligible = eligible;
        (valid && warmed && z >= RATE_Z_THRESHOLD).then(|| DetectionData {
            rule_id: "anomaly.exec_rate_spike".into(), title: "Anomalous process-creation rate for user".into(), category: "anomaly".into(),
            mitre_tactic: Some("TA0002 Execution".into()), confidence: 50, subject: user.into(),
            detail: format!("{completed:.0} processes against learned mean {mean:.1} (z={z:.1}); anomalous window excluded from learning"),
            evidence: serde_json::json!({"user":user,"window_count":completed,"zscore":z,"baseline_mean":mean,"samples":p.stat.count,"baseline_kind":"exec_rate"}),
            ..Default::default()
        })
    }

    pub fn snapshot(&self) -> BaselineSnapshot {
        BaselineSnapshot {
            version: 2,
            profiles: self.profiles.clone(),
            binaries: HashMap::new(),
            rates: self
                .rates
                .iter()
                .map(|(u, p)| (u.clone(), (p.stat.mean, p.stat.var, p.stat.count)))
                .collect(),
        }
    }
    pub fn from_snapshot(snap: BaselineSnapshot, now: Instant) -> Self {
        let mut engine = Self::new();
        if snap.version > 2 {
            return engine;
        }
        // Version-0/1 binary sets had no confirmation evidence: never import as trusted.
        if snap.version == 2 {
            for (user, mut p) in snap.profiles.into_iter().take(MAX_ENTITIES) {
                if !valid_text(&user) || p.first_seen == 0 {
                    continue;
                }
                p.confirmed = p
                    .confirmed
                    .into_iter()
                    .filter(|b| valid_text(b))
                    .take(MAX_CHILDREN)
                    .collect();
                p.pending = p
                    .pending
                    .into_iter()
                    .filter(|(b, c)| {
                        valid_text(b) && c.first_seen > 0 && c.last_seen >= c.first_seen
                    })
                    .take(MAX_CHILDREN)
                    .collect();
                let bytes = user.len() * 2
                    + 256
                    + p.confirmed.iter().map(|b| b.len() + 128).sum::<usize>()
                    + p.pending.keys().map(|b| b.len() + 128).sum::<usize>();
                if engine.profile_bytes + bytes > MAX_PROFILE_BYTES {
                    continue;
                }
                engine.profile_bytes += bytes;
                engine.profiles.insert(user, p);
            }
        }
        for (user, (mean, var, count)) in snap.rates.into_iter().take(MAX_ENTITIES) {
            if !engine.profiles.contains_key(&user)
                || !mean.is_finite()
                || !var.is_finite()
                || mean < 0.0
                || var < 0.0
            {
                continue;
            }
            engine.rates.insert(
                user,
                RateProfile {
                    window_start: now,
                    window_count: 0,
                    learning_eligible: true,
                    stat: Ewma {
                        mean,
                        var,
                        count,
                        alpha: 0.3,
                    },
                },
            );
        }
        engine
    }
    pub fn load(path: &Path, now: Instant) -> Self {
        use std::io::Read;
        let Ok(file) = std::fs::File::open(path) else {
            return Self::new();
        };
        let mut bytes = Vec::new();
        if file
            .take(MAX_STATE_BYTES + 1)
            .read_to_end(&mut bytes)
            .is_err()
            || bytes.len() as u64 > MAX_STATE_BYTES
        {
            return Self::new();
        }
        serde_json::from_slice(&bytes)
            .map(|s| Self::from_snapshot(s, now))
            .unwrap_or_else(|_| Self::new())
    }
    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        let bytes = serde_json::to_vec(&self.snapshot())?;
        anyhow::ensure!(
            bytes.len() as u64 <= MAX_STATE_BYTES,
            "baseline exceeds state limit"
        );
        crate::paths::write_atomic(path, &bytes, 0o600)
    }
}
impl Default for BaselineEngine {
    fn default() -> Self {
        Self::new()
    }
}
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct BaselineSnapshot {
    #[serde(default)]
    version: u32,
    #[serde(default)]
    profiles: HashMap<String, BinaryProfile>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    binaries: HashMap<String, Vec<String>>,
    #[serde(default)]
    rates: HashMap<String, (f64, f64, u32)>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mature_engine() -> (BaselineEngine, Instant) {
        let mut e = BaselineEngine::new();
        let t = Instant::now();
        // Four distinct binaries seen three times over more than a day.
        for exe in ["a", "b", "c", "d"] {
            for wall in [100_000, 150_000, 200_000] {
                e.observe_exec_at("bob", &format!("/opt/{exe}"), t, wall, true);
            }
        }
        assert_eq!(e.profiles["bob"].confirmed.len(), 4);
        (e, t)
    }

    #[test]
    fn learning_keeps_up_beyond_the_old_64_binary_cap() {
        let mut e = BaselineEngine::new();
        let t = Instant::now();
        for i in 0..200 {
            for wall in [100_000, 150_000, 200_000] {
                e.observe_exec_at("bob", &format!("/opt/app{i}"), t, wall, true);
            }
        }
        assert_eq!(e.profiles["bob"].confirmed.len(), 200);
        // A confirmed binary beyond the old cap stays quiet.
        assert!(e
            .observe_exec_at("bob", "/opt/app150", t, 300_000, true)
            .is_none());
    }

    #[test]
    fn novel_binary_in_user_writable_location_still_flags() {
        let (mut e, t) = mature_engine();
        let d = e
            .observe_exec_at(
                "bob",
                "C:\\Users\\bob\\AppData\\Local\\Temp\\x.exe",
                t,
                300_000,
                true,
            )
            .expect("novel temp binary must flag");
        assert_eq!(d.rule_id, "anomaly.rare_binary_for_user");
        assert!(e
            .observe_exec_at("bob", "/tmp/dropper", t, 300_001, true)
            .is_some());
    }

    #[test]
    fn novel_binary_in_admin_only_windows_location_is_learned_but_not_flagged() {
        let (mut e, t) = mature_engine();
        for exe in [
            "C:\\Windows\\SystemApps\\Microsoft.LockApp_cw5n1h2txyewy\\LockApp.exe",
            "C:\\Program Files\\Cloudflare\\Cloudflare WARP\\warp-svc.exe",
            "C:\\Windows\\System32\\RuntimeBroker.exe",
        ] {
            assert!(e.observe_exec_at("bob", exe, t, 300_000, true).is_none());
        }
        assert!(e.profiles["bob"].pending.len() >= 3);
    }

    #[test]
    fn stale_candidates_do_not_block_learning_forever() {
        let mut b = BaselineEngine::new();
        let t = Instant::now();
        for i in 0..MAX_CHILDREN {
            b.observe_exec_at("alice", &format!("/opt/once{i}"), t, 100_000, true);
        }
        assert_eq!(b.profiles["alice"].pending.len(), MAX_CHILDREN);
        let later = 100_000 + PENDING_TTL + 1;
        b.observe_exec_at("alice", "/bin/new", t, later, true);
        let pending = &b.profiles["alice"].pending;
        assert_eq!(pending.len(), 1);
        assert!(pending.contains_key("/bin/new"));
    }

    #[test]
    fn rejected_candidates_release_their_capacity() {
        let mut b = BaselineEngine::new();
        let now = Instant::now();
        b.observe_exec_at("alice", "/tmp/rejected", now, 1, true);
        let allocated = b.profile_bytes;
        for _ in 0..1000 {
            b.observe_exec_at("alice", "/tmp/rejected", now, 1, false);
            b.observe_exec_at("alice", "/tmp/rejected", now, 1, true);
        }
        assert_eq!(b.profile_bytes, allocated);
        assert_eq!(b.profiles["alice"].pending.len(), 1);
    }

    #[test]
    fn rejected_exec_cannot_teach_normality_and_confirmation_takes_a_day() {
        let mut b = BaselineEngine::new();
        let t = Instant::now();
        for offset in [0, 1, 86400] {
            for exe in ["/bin/ls", "/bin/cat", "/bin/sh"] {
                b.observe_exec_at(
                    "alice",
                    exe,
                    t + Duration::from_secs(offset),
                    100000 + offset,
                    true,
                );
            }
        }
        for offset in [86401, 86402, 172802] {
            let d = b.observe_exec_at(
                "alice",
                "/tmp/evil",
                t + Duration::from_secs(offset),
                100000 + offset,
                false,
            );
            assert_eq!(
                d.expect("suspicious binary was learned").rule_id,
                "anomaly.rare_binary_for_user"
            );
        }
        let d = b.observe_exec_at(
            "alice",
            "/tmp/evil",
            t + Duration::from_secs(172803),
            272803,
            true,
        );
        assert!(d.is_some());
        assert_eq!(b.profiles["alice"].confirmed.len(), 3);
    }

    #[test]
    fn unknown_users_and_large_gaps_do_not_train_profiles() {
        let mut b = BaselineEngine::new();
        let t = Instant::now();
        b.observe_exec_at("unknown", "/bin/sh", t, 100000, true);
        assert!(b.profiles.is_empty());
        assert!(b.rates.is_empty());
        b.observe_exec_at("alice", "/bin/sh", t, 100000, true);
        b.observe_exec_at(
            "alice",
            "/bin/sh",
            t + Duration::from_secs(3600),
            103600,
            true,
        );
        assert_eq!(b.rates["alice"].stat.count, 0);
    }

    #[test]
    fn anomalous_rate_does_not_move_the_mean() {
        let mut b = BaselineEngine::new();
        let mut t = Instant::now();
        for _ in 0..8 {
            b.update_rate("svc", t);
            b.update_rate("svc", t);
            t += Duration::from_secs(61);
        }
        let mean = b.rates["svc"].stat.mean;
        for _ in 0..200 {
            b.update_rate("svc", t);
        }
        b.update_rate("svc", t + Duration::from_secs(61));
        assert_eq!(b.rates["svc"].stat.mean, mean);
    }

    #[test]
    fn snapshot_preserves_confirmed_binaries_but_legacy_sets_are_not_trust() {
        let now = Instant::now();
        let mut e = BaselineEngine::new();
        for offset in [0, 1, 86400] {
            for exe in ["/bin/bash", "/bin/ls", "/bin/cat"] {
                e.observe_exec_at(
                    "alice",
                    exe,
                    now + Duration::from_secs(offset),
                    100000 + offset,
                    true,
                );
            }
        }
        let mut restored = BaselineEngine::from_snapshot(e.snapshot(), now);
        assert!(restored
            .observe_exec_at("alice", "/bin/ls", now, 186401, true)
            .is_none());
        assert!(restored
            .observe_exec_at("alice", "/tmp/new", now, 186401, true)
            .is_some());
        let old: BaselineSnapshot =
            serde_json::from_value(serde_json::json!({"binaries":{"alice":["/tmp/old"]}})).unwrap();
        let legacy = BaselineEngine::from_snapshot(old, now);
        assert!(legacy.profiles.is_empty());
    }

    #[test]
    fn malformed_rates_and_oversized_state_are_rejected() {
        let snap: BaselineSnapshot = serde_json::from_value(
            serde_json::json!({"version":2,"rates":{"alice":[-1.0,2.0,100]}}),
        )
        .unwrap();
        assert!(BaselineEngine::from_snapshot(snap, Instant::now())
            .rates
            .is_empty());
        let missing = std::env::temp_dir().join(format!("trapd-bl-{}.json", uuid::Uuid::new_v4()));
        assert!(BaselineEngine::load(&missing, Instant::now())
            .profiles
            .is_empty());
    }

    #[test]
    fn save_load_preserves_candidates_and_windows_path_case() {
        let t = Instant::now();
        let mut e = BaselineEngine::new();
        e.observe_exec_at("CORP\\Alice", "C:\\Tools\\App.exe", t, 100000, true);
        e.observe_exec_at("CORP\\alice", "c:/tools/app.exe", t, 100001, true);
        assert_eq!(e.profiles["corp\\alice"].pending.len(), 1);
        let path = std::env::temp_dir().join(format!("trapd-bl-{}.json", uuid::Uuid::new_v4()));
        e.save(&path).unwrap();
        let loaded = BaselineEngine::load(&path, t);
        assert_eq!(loaded.profiles["corp\\alice"].pending.len(), 1);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn novelty_is_silent_until_history_matures() {
        let mut b = BaselineEngine::new();
        let t = Instant::now();
        for exe in ["/bin/a", "/bin/b", "/bin/c", "/bin/d"] {
            assert!(b.observe_exec_at("alice", exe, t, 100000, true).is_none());
        }
    }

    #[test]
    fn ewma_zscore_is_zero_until_warmed() {
        let mut e = Ewma::new(0.3);
        assert_eq!(e.zscore(10.0), 0.0);
        e.update(5.0);
        assert_eq!(e.zscore(100.0), 0.0);
    }

    #[test]
    fn exec_rate_spike_flags_burst_after_baseline() {
        let mut b = BaselineEngine::new();
        let mut t = Instant::now();
        for _ in 0..8 {
            b.update_rate("svc", t);
            b.update_rate("svc", t);
            t += Duration::from_secs(61);
        }
        for _ in 0..200 {
            b.update_rate("svc", t);
        }
        let d = b.update_rate("svc", t + Duration::from_secs(61));
        assert_eq!(d.unwrap().rule_id, "anomaly.exec_rate_spike");
    }
}
