//! Local activity learning for decoy placement — opt-in, on-host only.
//!
//! What a user does decides which decoys fit them (an admin who runs WinSCP
//! daily, a developer with ten repositories) and where they would *not* stumble
//! over one (folders written this week). This module keeps the minimum needed
//! for those two questions:
//!
//!   * per tool (executable **basename**): how often it ran, per day;
//!   * per directory: when the user last saved something into it;
//!   * a bounded sample of file **names** the user saved (naming style only);
//!   * an hour-of-day histogram of interactive activity (to put a later decoy
//!     access into context: 03:00 on a 9-to-5 workstation is unusual);
//!   * host-wide: internal host names seen in DNS, so generated bait never
//!     names a server that really exists.
//!
//! Privacy by construction (DSGVO Art. 25):
//!   * off unless the signed config enables it
//!     (`deception_activity_learning_enabled`), and **purged** when disabled;
//!   * nothing here is ever emitted as telemetry or sent to the backend — only
//!     the derived candidates in [`super::windows_profiler`] leave the host;
//!   * no file contents, no full command lines, no window titles, no URLs;
//!   * retention 30 days, hard caps on every collection;
//!   * stored in the agent's state directory (SYSTEM/Administrators only) and
//!     removed on uninstall.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::naming::NamingStyle;
use super::windows_profiler::COLD_AFTER_DAYS;

pub const RETENTION_DAYS: i64 = 30;
const DAY: i64 = 86_400;
const MAX_USERS: usize = 64;
const MAX_TOOLS_PER_USER: usize = 256;
const MAX_DIRS_PER_USER: usize = 2_000;
const MAX_NAME_SAMPLES: usize = 300;
const MAX_HOSTNAMES: usize = 4_000;
/// The persisted file is refused beyond this size (corruption / tampering).
const MAX_STATE_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct UserActivity {
    /// tool basename → (day index → count)
    tools: BTreeMap<String, BTreeMap<i64, u32>>,
    /// lowercase directory path → last write (unix seconds)
    dirs: BTreeMap<String, i64>,
    /// recently saved file names (style inference only)
    names: VecDeque<(i64, String)>,
    /// interactive activity per hour of day (local time unknown → UTC hour)
    hours: BTreeMap<i64, [u32; 24]>,
    first_seen_unix: i64,
    #[serde(default)]
    last_bootstrap_unix: i64,
}

/// What the profiler needs from a user's activity.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct UserActivitySummary {
    pub tool_uses: BTreeMap<String, u32>,
    /// Lowercase paths of directories written within the cold threshold.
    pub hot_dirs: BTreeSet<String>,
    pub naming: Option<NamingStyle>,
    pub hours: [u32; 24],
    pub learning_days: i64,
}

impl UserActivitySummary {
    /// Whether `hour` (0–23) is outside the user's usual activity, once at
    /// least a week of data exists. "Usual" = an hour holding ≥ 2% of activity.
    pub fn is_unusual_hour(&self, hour: u32) -> Option<bool> {
        if self.learning_days < 7 {
            return None;
        }
        let total: u64 = self.hours.iter().map(|n| *n as u64).sum();
        if total < 50 {
            return None;
        }
        let share = self.hours[(hour % 24) as usize] as f64 / total as f64;
        Some(share < 0.02)
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ActivityStore {
    #[serde(default)]
    users: BTreeMap<String, UserActivity>,
    #[serde(default)]
    hostnames: BTreeMap<String, i64>,
}

fn basename(path: &str) -> String {
    path.rsplit(['\\', '/'])
        .next()
        .unwrap_or(path)
        .to_ascii_lowercase()
}

impl ActivityStore {
    fn user(&mut self, user: &str, now: i64) -> Option<&mut UserActivity> {
        let key = user.to_lowercase();
        if now < 0
            || key.is_empty()
            || key == "unknown"
            || key.len() > 256
            || key.chars().any(char::is_control)
        {
            return None;
        }
        if !self.users.contains_key(&key) && self.users.len() >= MAX_USERS {
            return None;
        }
        let u = self.users.entry(key).or_insert_with(|| UserActivity {
            first_seen_unix: now,
            ..Default::default()
        });
        Some(u)
    }

    /// A process the user started. Only the executable's basename is kept.
    pub fn observe_exec(&mut self, user: &str, exe: &str, now: i64) {
        let tool = basename(exe);
        if tool.is_empty() || tool.len() > 256 || tool.chars().any(char::is_control) {
            return;
        }
        let Some(u) = self.user(user, now) else {
            return;
        };
        if !u.tools.contains_key(&tool) && u.tools.len() >= MAX_TOOLS_PER_USER {
            return;
        }
        let days = u.tools.entry(tool).or_default();
        days.retain(|day, _| *day >= now / DAY - RETENTION_DAYS && *day <= now / DAY);
        let count = days.entry(now / DAY).or_insert(0);
        *count = count.saturating_add(1);
        u.hours
            .retain(|day, _| *day >= now / DAY - RETENTION_DAYS && *day <= now / DAY);
        let count = &mut u.hours.entry(now / DAY).or_insert([0; 24])[((now % DAY) / 3600) as usize];
        *count = count.saturating_add(1);
    }

    /// A file the user saved. Keeps the directory's last-write time and the
    /// file's name (for style), nothing else.
    pub fn observe_write(&mut self, user: &str, path: &Path, now: i64) {
        let Some(dir) = path.parent() else { return };
        let Some(name) = path.file_name().map(|n| n.to_string_lossy().into_owned()) else {
            return;
        };
        // Normalise the separator so the key matches regardless of whether the
        // path arrived with `\` (Windows) or `/`: `cold_dirs` keys the same way.
        let key = dir.to_string_lossy().replace('\\', "/").to_lowercase();
        if key.len() > 1024
            || name.len() > 512
            || key.chars().any(char::is_control)
            || name.chars().any(char::is_control)
        {
            return;
        }
        let Some(u) = self.user(user, now) else {
            return;
        };
        if !u.dirs.contains_key(&key) && u.dirs.len() >= MAX_DIRS_PER_USER {
            // Evict the coldest directory: it is the least useful entry.
            if let Some(oldest) = u
                .dirs
                .iter()
                .min_by_key(|(_, t)| **t)
                .map(|(k, _)| k.clone())
            {
                u.dirs.remove(&oldest);
            }
        }
        u.dirs.insert(key, now);
        if !name.starts_with('~') && !name.starts_with('.') {
            u.names.push_back((now, name));
            while u.names.len() > MAX_NAME_SAMPLES {
                u.names.pop_front();
            }
        }
    }

    /// An internal host name resolved on this machine (first label only).
    pub fn observe_hostname(&mut self, qname: &str) {
        self.observe_hostname_at(qname, now_unix());
    }

    pub fn observe_hostname_at(&mut self, qname: &str, now: i64) {
        let label = qname
            .trim_end_matches('.')
            .split('.')
            .next()
            .unwrap_or("")
            .to_ascii_lowercase();
        if now < 0
            || label.is_empty()
            || label.len() > 63
            || !label
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-')
            || (!self.hostnames.contains_key(&label) && self.hostnames.len() >= MAX_HOSTNAMES)
        {
            return;
        }
        self.hostnames.insert(label, now);
    }

    pub fn known_hostnames(&self) -> BTreeSet<String> {
        self.hostnames.keys().cloned().collect()
    }

    /// Drop everything older than the retention window.
    pub fn prune(&mut self, now: i64) {
        let horizon_day = (now - RETENTION_DAYS * DAY) / DAY;
        for u in self.users.values_mut() {
            for days in u.tools.values_mut() {
                days.retain(|d, _| *d > horizon_day && *d <= now / DAY);
            }
            u.tools.retain(|_, days| !days.is_empty());
            u.dirs
                .retain(|_, t| *t >= now - RETENTION_DAYS * DAY && *t <= now);
            u.names
                .retain(|(t, _)| *t >= now - RETENTION_DAYS * DAY && *t <= now);
            u.hours
                .retain(|day, _| *day > horizon_day && *day <= now / DAY);
        }
        self.users.retain(|_, u| {
            !u.tools.is_empty() || !u.dirs.is_empty() || !u.names.is_empty() || !u.hours.is_empty()
        });
        self.hostnames
            .retain(|_, t| *t >= now - RETENTION_DAYS * DAY && *t <= now);
    }

    pub fn summary(&self, user: &str, now: i64) -> Option<UserActivitySummary> {
        let u = self.users.get(&user.to_lowercase())?;
        let horizon_day = (now - RETENTION_DAYS * DAY) / DAY;
        let tool_uses = u
            .tools
            .iter()
            .map(|(t, days)| {
                (
                    t.clone(),
                    days.iter()
                        .filter(|(d, _)| **d > horizon_day && **d <= now / DAY)
                        .fold(0u32, |sum, (_, c)| sum.saturating_add(*c)),
                )
            })
            .filter(|(_, c): &(String, u32)| *c > 0)
            .collect();
        let hot_dirs = u
            .dirs
            .iter()
            .filter(|(_, t)| **t <= now && now - **t < COLD_AFTER_DAYS * DAY)
            .map(|(d, _)| d.clone())
            .collect();
        let names: Vec<&String> = u
            .names
            .iter()
            .filter(|(t, _)| *t <= now && *t >= now - RETENTION_DAYS * DAY)
            .map(|(_, name)| name)
            .collect();
        let mut hours = [0u32; 24];
        for (_, daily) in u
            .hours
            .iter()
            .filter(|(d, _)| **d > horizon_day && **d <= now / DAY)
        {
            for (out, count) in hours.iter_mut().zip(daily) {
                *out = out.saturating_add(*count);
            }
        }
        Some(UserActivitySummary {
            tool_uses,
            hot_dirs,
            naming: (!names.is_empty()).then(|| NamingStyle::infer(&names)),
            hours,
            learning_days: ((now - u.first_seen_unix) / DAY).clamp(0, RETENTION_DAYS),
        })
    }

    pub fn summaries(&self, now: i64) -> BTreeMap<String, UserActivitySummary> {
        self.users
            .keys()
            .filter_map(|u| self.summary(u, now).map(|s| (u.clone(), s)))
            .collect()
    }

    pub fn is_empty(&self) -> bool {
        self.users.is_empty() && self.hostnames.is_empty()
    }

    // ── persistence ──────────────────────────────────────────────────────────

    pub fn load(path: &Path) -> Self {
        let Ok(meta) = std::fs::metadata(path) else {
            return Self::default();
        };
        if meta.len() > MAX_STATE_BYTES {
            tracing::warn!(path = %path.display(), "activity state too large; starting fresh");
            return Self::default();
        }
        use std::io::Read;
        let Ok(file) = std::fs::File::open(path) else {
            return Self::default();
        };
        let mut bytes = Vec::new();
        if file
            .take(MAX_STATE_BYTES + 1)
            .read_to_end(&mut bytes)
            .is_err()
            || bytes.len() as u64 > MAX_STATE_BYTES
        {
            return Self::default();
        }
        let mut store: Self = serde_json::from_slice(&bytes).unwrap_or_default();
        store.users = store
            .users
            .into_iter()
            .filter(|(u, _)| !u.is_empty() && u.len() <= 256)
            .take(MAX_USERS)
            .collect();
        for u in store.users.values_mut() {
            u.tools = std::mem::take(&mut u.tools)
                .into_iter()
                .filter(|(t, _)| !t.is_empty() && t.len() <= 256)
                .take(MAX_TOOLS_PER_USER)
                .collect();
            for days in u.tools.values_mut() {
                *days = std::mem::take(days)
                    .into_iter()
                    .rev()
                    .take(RETENTION_DAYS as usize + 1)
                    .collect();
            }
            u.dirs = std::mem::take(&mut u.dirs)
                .into_iter()
                .filter(|(p, _)| p.len() <= 1024)
                .take(MAX_DIRS_PER_USER)
                .collect();
            u.names = std::mem::take(&mut u.names)
                .into_iter()
                .filter(|(_, n)| n.len() <= 512)
                .rev()
                .take(MAX_NAME_SAMPLES)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect();
            u.hours = std::mem::take(&mut u.hours)
                .into_iter()
                .rev()
                .take(RETENTION_DAYS as usize + 1)
                .collect();
        }
        store.hostnames = store
            .hostnames
            .into_iter()
            .filter(|(h, _)| h.len() <= 63)
            .take(MAX_HOSTNAMES)
            .collect();
        store
    }

    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        let bytes = serde_json::to_vec(self)?;
        anyhow::ensure!(
            bytes.len() as u64 <= MAX_STATE_BYTES,
            "activity state exceeds size limit"
        );
        crate::paths::write_atomic(path, &bytes, 0o600)
    }

    /// Remove the persisted state (learning disabled or agent uninstalled).
    pub fn purge(path: &Path) {
        match std::fs::remove_file(path) {
            Ok(()) => tracing::info!("activity learning disabled: local activity profile deleted"),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => tracing::warn!(error = %e, "could not delete local activity profile"),
        }
    }
}

pub fn state_path() -> PathBuf {
    crate::paths::state_dir().join("deception_activity.json")
}

// ── Process-wide store (Windows agent) ──────────────────────────────────────

static ENABLED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

fn global() -> &'static std::sync::Mutex<ActivityStore> {
    static STORE: std::sync::OnceLock<std::sync::Mutex<ActivityStore>> = std::sync::OnceLock::new();
    STORE.get_or_init(|| std::sync::Mutex::new(ActivityStore::default()))
}

/// Apply the config switch. Enabling loads the persisted profile; disabling
/// clears memory **and deletes the file** — switching learning off must not
/// leave a behavioural profile behind.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn set_enabled(on: bool) {
    if let Ok(mut store) = global().lock() {
        let was = ENABLED.swap(on, std::sync::atomic::Ordering::SeqCst);
        if on && !was {
            *store = ActivityStore::load(&state_path());
            store.prune(now_unix());
            tracing::info!("deception activity learning enabled (local only)");
        } else if !on {
            *store = ActivityStore::default();
            ActivityStore::purge(&state_path()); // also on first startup with opt-in off
        }
    }
}

#[cfg_attr(not(windows), allow(dead_code))]
pub fn enabled() -> bool {
    ENABLED.load(std::sync::atomic::Ordering::Relaxed)
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Record a process start (no-op unless learning is enabled).
#[cfg_attr(not(windows), allow(dead_code))]
pub fn record_exec(user: &str, exe: &str) {
    if enabled() {
        if let Ok(mut s) = global().lock() {
            if !enabled() {
                return;
            }
            s.observe_exec(user, exe, now_unix());
        }
    }
}

/// Record a file saved by `user` (no-op unless learning is enabled).
#[cfg_attr(not(windows), allow(dead_code))]
pub fn record_write(user: &str, path: &Path) {
    if enabled() {
        if let Ok(mut s) = global().lock() {
            if !enabled() {
                return;
            }
            s.observe_write(user, path, now_unix());
        }
    }
}

/// Record a resolved host name (no-op unless learning is enabled).
#[cfg_attr(not(windows), allow(dead_code))]
pub fn record_hostname(qname: &str) {
    if enabled() {
        if let Ok(mut s) = global().lock() {
            if !enabled() {
                return;
            }
            s.observe_hostname(qname);
        }
    }
}

/// Seed a user's profile from disk metadata (first enablement).
#[cfg_attr(not(windows), allow(dead_code))]
pub fn bootstrap(user: &str, root: &Path) {
    if enabled() {
        if let Ok(mut s) = global().lock() {
            if !enabled() {
                return;
            }
            let now = now_unix();
            let previous = s
                .users
                .get(&user.to_lowercase())
                .map(|u| u.last_bootstrap_unix)
                .unwrap_or(0);
            if now.saturating_sub(previous) >= DAY {
                bootstrap_from_disk(&mut s, user, root, now);
                if let Some(u) = s.users.get_mut(&user.to_lowercase()) {
                    u.last_bootstrap_unix = now;
                }
            }
        }
    }
}

/// Current summaries (empty when learning is disabled).
#[cfg_attr(not(windows), allow(dead_code))]
pub fn current_summaries() -> BTreeMap<String, UserActivitySummary> {
    if !enabled() {
        return BTreeMap::new();
    }
    global()
        .lock()
        .map(|s| {
            if enabled() {
                s.summaries(now_unix())
            } else {
                BTreeMap::new()
            }
        })
        .unwrap_or_default()
}

/// Internal host names seen on this machine (empty when disabled).
#[cfg_attr(not(windows), allow(dead_code))]
pub fn current_hostnames() -> BTreeSet<String> {
    if !enabled() {
        return BTreeSet::new();
    }
    global()
        .lock()
        .map(|s| {
            if enabled() {
                s.known_hostnames()
            } else {
                BTreeSet::new()
            }
        })
        .unwrap_or_default()
}

/// Prune and persist (periodic, and on shutdown).
#[cfg_attr(not(windows), allow(dead_code))]
pub fn persist() {
    if !enabled() {
        return;
    }
    if let Ok(mut s) = global().lock() {
        if !enabled() {
            return;
        }
        s.prune(now_unix());
        if let Err(e) = s.save(&state_path()) {
            tracing::warn!(error = %e, "could not persist local activity profile");
        }
    }
}

/// Bootstrap from what is already on disk: file names and write times below
/// `root` (depth-bounded), so placement does not need weeks of observation.
/// Reads directory metadata only, never file contents.
pub fn bootstrap_from_disk(store: &mut ActivityStore, user: &str, root: &Path, now: i64) {
    const MAX_DEPTH: usize = 3;
    const MAX_FILES: usize = 5_000;
    let mut seen = 0usize;
    let mut stack = vec![(root.to_path_buf(), 0usize)];
    while let Some((dir, depth)) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in rd.flatten() {
            if seen >= MAX_FILES {
                return;
            }
            let Ok(meta) = entry.path().symlink_metadata() else {
                continue;
            };
            if meta.file_type().is_symlink() {
                continue;
            }
            let name = entry.file_name().to_string_lossy().to_lowercase();
            if meta.is_dir() {
                if depth < MAX_DEPTH && !name.starts_with('.') && name != "appdata" {
                    stack.push((entry.path(), depth + 1));
                }
                continue;
            }
            seen += 1;
            let Some(mtime) = meta
                .modified()
                .ok()
                .and_then(|m| m.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs() as i64)
            else {
                continue;
            };
            // Only recent writes mark a directory hot; older files still teach
            // the naming style.
            if mtime <= now && now - mtime < RETENTION_DAYS * DAY {
                store.observe_write(user, &entry.path(), mtime);
            } else if let Some(u) = store.user(user, now) {
                let n = entry.file_name().to_string_lossy().into_owned();
                if u.names.len() < MAX_NAME_SAMPLES && !n.starts_with('.') && !n.starts_with('~') {
                    u.names.push_back((now, n));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_790_000_000;

    #[test]
    fn expired_names_hours_and_hostnames_are_actually_removed() {
        let mut s = ActivityStore::default();
        s.observe_exec("anna", "tool.exe", NOW - 31 * DAY);
        s.observe_write(
            "anna",
            Path::new("/d/2020-01-01_secret.txt"),
            NOW - 31 * DAY,
        );
        s.observe_hostname_at("old.internal", NOW - 31 * DAY);
        s.prune(NOW);
        assert!(s.summary("anna", NOW).is_none());
        assert!(s.known_hostnames().is_empty());
    }

    #[test]
    fn rollback_drops_future_activity_and_counters_saturate() {
        let mut s = ActivityStore::default();
        s.observe_exec("anna", "a.exe", NOW + DAY);
        s.prune(NOW);
        assert!(s.summary("anna", NOW).is_none());
    }

    #[test]
    fn keeps_only_tool_basenames_and_counts_per_day() {
        let mut s = ActivityStore::default();
        s.observe_exec("Anna", "C:\\Program Files\\WinSCP\\WinSCP.exe", NOW);
        s.observe_exec("anna", "C:\\Program Files\\WinSCP\\WinSCP.exe", NOW + 60);
        s.observe_exec("unknown", "C:\\x.exe", NOW);
        let sum = s.summary("ANNA", NOW).unwrap();
        assert_eq!(sum.tool_uses.get("winscp.exe"), Some(&2));
        assert!(s.summary("unknown", NOW).is_none());
        let json = serde_json::to_string(&s).unwrap();
        assert!(
            !json.contains("Program Files"),
            "full paths must not be stored: {json}"
        );
    }

    #[test]
    fn hot_dirs_expire_into_cold_and_retention_prunes() {
        let mut s = ActivityStore::default();
        s.observe_write(
            "anna",
            Path::new("/Users/anna/Documents/Aktuell/Angebot.docx"),
            NOW - 2 * DAY,
        );
        s.observe_write(
            "anna",
            Path::new("/Users/anna/Documents/Alt/Notiz.txt"),
            NOW - 25 * DAY,
        );
        let sum = s.summary("anna", NOW).unwrap();
        assert!(sum.hot_dirs.contains("/users/anna/documents/aktuell"));
        assert!(!sum.hot_dirs.contains("/users/anna/documents/alt"));
        s.observe_exec("anna", "old.exe", NOW - 40 * DAY);
        s.prune(NOW);
        assert!(s.summary("anna", NOW).unwrap().tool_uses.is_empty());
    }

    #[test]
    fn naming_style_comes_from_saved_names() {
        let mut s = ActivityStore::default();
        for n in [
            "2024-01-02_Angebot_A.docx",
            "2024-02-03_Rechnung_B.pdf",
            "2024-03-04_Vertrag_C.pdf",
        ] {
            s.observe_write("anna", &Path::new("/d").join(n), NOW);
        }
        let style = s.summary("anna", NOW).unwrap().naming.unwrap();
        assert!(style.date.is_some());
    }

    #[test]
    fn caps_bound_memory() {
        let mut s = ActivityStore::default();
        for i in 0..(MAX_USERS + 10) {
            s.observe_exec(&format!("u{i}"), "a.exe", NOW);
        }
        assert_eq!(s.users.len(), MAX_USERS);
        for i in 0..(MAX_DIRS_PER_USER + 50) {
            s.observe_write("u0", &PathBuf::from(format!("/d{i}/f.txt")), NOW + i as i64);
        }
        assert_eq!(s.users["u0"].dirs.len(), MAX_DIRS_PER_USER);
        assert!(s.users["u0"].names.len() <= MAX_NAME_SAMPLES);
    }

    #[test]
    fn unusual_hours_need_enough_history() {
        let mut sum = UserActivitySummary::default();
        for h in 8..18 {
            sum.hours[h] = 20;
        }
        assert_eq!(
            sum.is_unusual_hour(3),
            None,
            "no verdict before a week of data"
        );
        sum.learning_days = 10;
        assert_eq!(sum.is_unusual_hour(3), Some(true));
        assert_eq!(sum.is_unusual_hour(10), Some(false));
    }

    #[test]
    fn hostnames_keep_first_label_only() {
        let mut s = ActivityStore::default();
        s.observe_hostname("BER-SQL01.corp.example.eu.");
        assert!(s.known_hostnames().contains("ber-sql01"));
    }

    #[test]
    fn persistence_round_trip_and_purge() {
        let dir = std::env::temp_dir().join(format!("trapd-activity-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("a.json");
        let mut s = ActivityStore::default();
        s.observe_exec("anna", "mstsc.exe", NOW);
        s.save(&path).unwrap();
        let loaded = ActivityStore::load(&path);
        assert_eq!(
            loaded
                .summary("anna", NOW)
                .unwrap()
                .tool_uses
                .get("mstsc.exe"),
            Some(&1)
        );
        ActivityStore::purge(&path);
        assert!(!path.exists());
        assert!(ActivityStore::load(&path).is_empty());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn bootstrap_reads_names_and_recent_writes_only() {
        let root = std::env::temp_dir().join(format!("trapd-boot-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(root.join("Projekte")).unwrap();
        std::fs::write(
            root.join("Projekte").join("2024-01-01_Plan.txt"),
            b"secret content",
        )
        .unwrap();
        let mut s = ActivityStore::default();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        bootstrap_from_disk(&mut s, "anna", &root, now);
        let json = serde_json::to_string(&s).unwrap();
        assert!(!json.contains("secret content"));
        assert!(s
            .summary("anna", now)
            .unwrap()
            .hot_dirs
            .iter()
            .any(|d| d.ends_with("projekte")));
        std::fs::remove_dir_all(root).unwrap();
    }
}
