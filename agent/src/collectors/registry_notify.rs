//! Real-time wake-ups for the registry watcher: the pure core.
//!
//! `registry_watch.rs` finds *what* changed by snapshot and diff; this module
//! only decides *when* to take the next snapshot. A Windows thread holds one
//! `RegNotifyChangeKeyValue` registration per watched key (see
//! `windows/regnotify.rs`) and every notification wakes the existing poll loop
//! early. The events that result are produced by the unchanged snapshot/diff
//! path, so their wire shape (class `registry`, `key_path`, `value_name`,
//! `new_value`, `category`) and their stable event ids do not change.
//!
//! What this gives: latency drops from the poll interval to about a second,
//! with no SACL, no Sysmon and no kernel session. What it cannot give: the
//! writing process or the written value; a notification carries neither. The
//! snapshot diff supplies the value. Writer attribution is the job of an ETW
//! `Microsoft-Windows-Kernel-Registry` subscription, see "Writer attribution".
//!
//! Bounds and failure handling:
//! * at most [`MAX_WATCHED_KEYS`] open registrations (one handle pair each),
//!   machine keys first; the remainder is counted as `over_capacity`;
//! * wake-ups are debounced and rate limited by [`WakeScheduler`], so a noisy
//!   subtree costs at most one snapshot per [`MIN_GAP`];
//! * a key that cannot be opened or re-armed is dropped, counted under a named
//!   [`FallbackReason`] and retried at the next reconcile. The periodic
//!   snapshot poll stays on regardless, so every fallback degrades to the old
//!   polling latency and never to silence.
//!
//! Writer attribution (design, not implemented): an ETW session on
//! `Microsoft-Windows-Kernel-Registry` (keyword for SetValueKey/CreateKey/
//! DeleteValueKey) carries the writer pid and the key name. It would run
//! beside this module, filter in-agent by [`WatchTarget`] prefixes (the
//! provider is high volume; a bounded prefix filter and a bounded
//! `(key, value) -> pid, process_start_time` ring with a short TTL are
//! required), and the snapshot diff would look up the ring by
//! `key_path`/`value_name` to fill `process`-style context on the event. Until
//! that exists, events from this path carry no writer, exactly like polling.

// Consumed only by the Windows collector; tests cover it on every platform.
#![cfg_attr(not(any(windows, test)), allow(dead_code))]

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use super::registry_watch::{is_user_sid, RegRoot, Scope, Shape, Spec, MAX_USERS};

/// Registrations held at once. `WaitForMultipleObjects` accepts 64 handles;
/// two are kept free for the stop signal and growth.
pub const MAX_WATCHED_KEYS: usize = 62;
/// A burst of notifications is folded into one snapshot after this delay.
pub const DEBOUNCE: Duration = Duration::from_millis(500);
/// Minimum spacing between two notification-driven snapshots.
pub const MIN_GAP: Duration = Duration::from_secs(2);
/// How often the target set is recomputed (new logons, keys that appeared).
#[cfg_attr(not(windows), allow(dead_code))]
pub const RECONCILE_EVERY: Duration = Duration::from_secs(10);

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct WatchTarget {
    pub root: RegRoot,
    /// Path relative to `root`, e.g. `SOFTWARE\...\Run` or `<sid>\Software\...`.
    pub path: String,
    /// `Children` specs need the whole subtree; `Values` specs only the key.
    pub subtree: bool,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct TargetPlan {
    pub targets: Vec<WatchTarget>,
    /// Targets that did not fit under the cap.
    pub over_capacity: usize,
}

/// Why a target is not event-driven right now. Stable counter labels.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum FallbackReason {
    OverCapacity,
    /// Key does not exist (yet). Benign, retried at the next reconcile.
    KeyMissing,
    OpenFailed,
    ArmFailed,
    WaitFailed,
}

impl FallbackReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::OverCapacity => "over_capacity",
            Self::KeyMissing => "key_missing",
            Self::OpenFailed => "open_failed",
            Self::ArmFailed => "arm_failed",
            Self::WaitFailed => "wait_failed",
        }
    }
}

/// Win32 `ERROR_FILE_NOT_FOUND` / `ERROR_PATH_NOT_FOUND`.
fn open_reason(status: u32) -> FallbackReason {
    if status == 2 || status == 3 {
        FallbackReason::KeyMissing
    } else {
        FallbackReason::OpenFailed
    }
}

/// Watch targets for `specs` given the loaded `HKU` hive names. Machine keys
/// come first so that, over the cap, user hives are what falls back to polling.
pub fn plan_targets(specs: &[Spec], hives: &[String], cap: usize) -> TargetPlan {
    let mut users: Vec<&str> = hives
        .iter()
        .map(String::as_str)
        .filter(|h| is_user_sid(h))
        .collect();
    users.sort_unstable();
    users.truncate(MAX_USERS);
    let mut machine: BTreeMap<String, bool> = BTreeMap::new();
    let mut per_user: BTreeMap<String, bool> = BTreeMap::new();
    for spec in specs {
        let subtree = matches!(spec.shape, Shape::Children { .. });
        let add = |map: &mut BTreeMap<String, bool>, path: String| {
            let entry = map.entry(path).or_insert(false);
            *entry |= subtree;
        };
        match spec.scope {
            Scope::Machine => add(&mut machine, spec.path.to_string()),
            Scope::User => {
                for sid in &users {
                    add(&mut per_user, format!("{sid}\\{}", spec.path));
                }
            }
            Scope::UserClasses => {
                for sid in &users {
                    let classes = format!("{sid}_Classes");
                    if hives.iter().any(|h| h == &classes) {
                        add(&mut per_user, format!("{classes}\\{}", spec.path));
                    }
                }
            }
        }
    }
    let mut targets: Vec<WatchTarget> = machine
        .into_iter()
        .map(|(path, subtree)| WatchTarget {
            root: RegRoot::LocalMachine,
            path,
            subtree,
        })
        .chain(per_user.into_iter().map(|(path, subtree)| WatchTarget {
            root: RegRoot::Users,
            path,
            subtree,
        }))
        .collect();
    let over_capacity = targets.len().saturating_sub(cap);
    targets.truncate(cap);
    TargetPlan {
        targets,
        over_capacity,
    }
}

/// The OS side of change notification. Dropping a key must release its
/// handles.
pub trait NotifyBackend {
    type Key;
    /// Open `target` and arm a notification. `Err` is the Win32 status.
    fn open(&mut self, target: &WatchTarget) -> Result<Self::Key, u32>;
    /// Arm the next notification after one fired.
    fn rearm(&mut self, key: &mut Self::Key) -> Result<(), u32>;
    /// Wait up to `timeout` and return the indices of keys that signalled.
    /// With no keys it should simply wait out the timeout.
    fn wait(&mut self, keys: &[&Self::Key], timeout: Duration) -> Result<Vec<usize>, u32>;
}

struct Entry<K> {
    target: WatchTarget,
    key: K,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NotifyStats {
    pub watched: usize,
    pub fallbacks: BTreeMap<&'static str, usize>,
}

/// The registrations currently held, bounded by [`MAX_WATCHED_KEYS`].
pub struct WatchSet<K> {
    entries: Vec<Entry<K>>,
    fallbacks: Vec<(WatchTarget, FallbackReason)>,
    over_capacity: usize,
}

impl<K> Default for WatchSet<K> {
    fn default() -> Self {
        Self {
            entries: Vec::new(),
            fallbacks: Vec::new(),
            over_capacity: 0,
        }
    }
}

impl<K> WatchSet<K> {
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn stats(&self) -> NotifyStats {
        let mut fallbacks: BTreeMap<&'static str, usize> = BTreeMap::new();
        for (_, reason) in &self.fallbacks {
            *fallbacks.entry(reason.as_str()).or_default() += 1;
        }
        if self.over_capacity > 0 {
            *fallbacks
                .entry(FallbackReason::OverCapacity.as_str())
                .or_default() += self.over_capacity;
        }
        NotifyStats {
            watched: self.entries.len(),
            fallbacks,
        }
    }

    /// Bring the held registrations in line with `plan`: release those no
    /// longer wanted, keep the live ones, try to open the rest. Failures are
    /// recorded, never fatal.
    pub fn reconcile<B: NotifyBackend<Key = K>>(&mut self, backend: &mut B, plan: TargetPlan) {
        self.entries
            .retain(|entry| plan.targets.contains(&entry.target));
        self.fallbacks.clear();
        self.over_capacity = plan.over_capacity;
        for target in plan.targets {
            if self.entries.iter().any(|entry| entry.target == target) {
                continue;
            }
            if self.entries.len() >= MAX_WATCHED_KEYS {
                self.over_capacity += 1;
                continue;
            }
            match backend.open(&target) {
                Ok(key) => self.entries.push(Entry { target, key }),
                Err(status) => self.fallbacks.push((target, open_reason(status))),
            }
        }
    }

    /// Wait for notifications and re-arm every key that fired *before*
    /// returning, so a change made while the caller snapshots signals again.
    /// Returns how many keys fired. A wait failure releases everything; the
    /// next reconcile rebuilds the set and the poll loop covers the gap.
    pub fn wait<B: NotifyBackend<Key = K>>(&mut self, backend: &mut B, timeout: Duration) -> usize {
        let fired = {
            let keys: Vec<&K> = self.entries.iter().map(|entry| &entry.key).collect();
            backend.wait(&keys, timeout)
        };
        let mut fired = match fired {
            Ok(fired) => fired,
            Err(_) => {
                let dropped = std::mem::take(&mut self.entries);
                self.fallbacks.extend(
                    dropped
                        .into_iter()
                        .map(|e| (e.target, FallbackReason::WaitFailed)),
                );
                return 0;
            }
        };
        fired.retain(|&index| index < self.entries.len());
        fired.sort_unstable();
        fired.dedup();
        let count = fired.len();
        // Highest index first so removals do not shift pending ones.
        for &index in fired.iter().rev() {
            if backend.rearm(&mut self.entries[index].key).is_err() {
                let dropped = self.entries.remove(index);
                self.fallbacks
                    .push((dropped.target, FallbackReason::ArmFailed));
            }
        }
        count
    }
}

/// Decides when a notification-driven snapshot may run. Pure; the caller owns
/// the clock and the sleeping.
#[derive(Debug)]
pub struct WakeScheduler {
    debounce: Duration,
    min_gap: Duration,
    pending_since: Option<Instant>,
    last_run: Option<Instant>,
}

impl WakeScheduler {
    pub fn new(debounce: Duration, min_gap: Duration) -> Self {
        Self {
            debounce,
            min_gap,
            pending_since: None,
            last_run: None,
        }
    }

    /// A notification arrived. Later ones fold into the pending run and do not
    /// push it back, so a constant stream still yields a run every
    /// `max(debounce, min_gap)`.
    pub fn notify(&mut self, now: Instant) {
        self.pending_since.get_or_insert(now);
    }

    /// When the pending run may start, `None` if nothing is pending.
    pub fn due_at(&self) -> Option<Instant> {
        let by_debounce = self.pending_since? + self.debounce;
        Some(match self.last_run {
            Some(last) => by_debounce.max(last + self.min_gap),
            None => by_debounce,
        })
    }

    /// A snapshot starts now, whatever triggered it (timer or notification).
    pub fn mark_run(&mut self, now: Instant) {
        self.last_run = Some(now);
        self.pending_since = None;
    }
}

impl Default for WakeScheduler {
    fn default() -> Self {
        Self::new(DEBOUNCE, MIN_GAP)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collectors::registry_watch::SPECS;
    use std::cell::Cell;
    use std::collections::{BTreeSet, VecDeque};
    use std::rc::Rc;

    fn sid(n: u32) -> String {
        format!("S-1-5-21-1-2-3-{}", 1000 + n)
    }

    fn hives(users: u32) -> Vec<String> {
        let mut v = vec![".DEFAULT".to_string(), "S-1-5-18".to_string()];
        for n in 0..users {
            v.push(sid(n));
            v.push(format!("{}_Classes", sid(n)));
        }
        v
    }

    #[test]
    fn plan_is_machine_first_deduplicated_and_marks_subtrees() {
        let plan = plan_targets(SPECS, &hives(1), 1000);
        let machine = plan
            .targets
            .iter()
            .take_while(|t| t.root == RegRoot::LocalMachine)
            .count();
        assert!(machine > 0);
        assert!(plan.targets[machine..]
            .iter()
            .all(|t| t.root == RegRoot::Users));
        let unique: BTreeSet<_> = plan.targets.iter().map(|t| (t.root, &t.path)).collect();
        assert_eq!(
            unique.len(),
            plan.targets.len(),
            "no duplicate registrations"
        );
        // Services has both a Values-less Children spec and a deeper one: subtree wins.
        let services = plan
            .targets
            .iter()
            .find(|t| t.path == r"SYSTEM\CurrentControlSet\Services")
            .expect("services watched");
        assert!(services.subtree);
        let run = plan
            .targets
            .iter()
            .find(|t| t.path == r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run")
            .expect("run key watched");
        assert!(!run.subtree);
        assert!(plan
            .targets
            .iter()
            .any(|t| t.root == RegRoot::Users && t.path.starts_with(&sid(0))));
    }

    #[test]
    fn plan_ignores_service_hives_and_requires_loaded_classes_hive() {
        let mut h = vec!["S-1-5-18".to_string(), sid(0)];
        let without_classes = plan_targets(SPECS, &h, 1000);
        assert!(without_classes
            .targets
            .iter()
            .all(|t| !t.path.starts_with("S-1-5-18")));
        assert!(without_classes
            .targets
            .iter()
            .all(|t| !t.path.contains("_Classes")));
        h.push(format!("{}_Classes", sid(0)));
        let with_classes = plan_targets(SPECS, &h, 1000);
        assert!(with_classes
            .targets
            .iter()
            .any(|t| t.path.contains("_Classes")));
    }

    #[test]
    fn plan_never_exceeds_cap_and_counts_overflow() {
        let full = plan_targets(SPECS, &hives(64), 100_000);
        assert!(
            full.targets.len() > MAX_WATCHED_KEYS,
            "scenario must overflow"
        );
        let capped = plan_targets(SPECS, &hives(64), MAX_WATCHED_KEYS);
        assert_eq!(capped.targets.len(), MAX_WATCHED_KEYS);
        assert_eq!(capped.over_capacity, full.targets.len() - MAX_WATCHED_KEYS);
        // Machine keys survive the cut.
        let machine_total = full
            .targets
            .iter()
            .filter(|t| t.root == RegRoot::LocalMachine)
            .count();
        assert!(machine_total <= MAX_WATCHED_KEYS);
        assert!(capped
            .targets
            .iter()
            .take(machine_total)
            .all(|t| t.root == RegRoot::LocalMachine));
    }

    #[derive(Default)]
    struct Fake {
        open_failures: BTreeMap<String, u32>,
        rearm_failures: BTreeSet<String>,
        wait_script: VecDeque<Result<Vec<usize>, u32>>,
        opened: usize,
        live: Rc<Cell<usize>>,
        rearmed: Vec<String>,
    }

    struct FakeKey {
        path: String,
        live: Rc<Cell<usize>>,
    }

    impl Drop for FakeKey {
        fn drop(&mut self) {
            self.live.set(self.live.get() - 1);
        }
    }

    impl NotifyBackend for Fake {
        type Key = FakeKey;
        fn open(&mut self, target: &WatchTarget) -> Result<FakeKey, u32> {
            if let Some(status) = self.open_failures.get(&target.path) {
                return Err(*status);
            }
            self.opened += 1;
            self.live.set(self.live.get() + 1);
            Ok(FakeKey {
                path: target.path.clone(),
                live: self.live.clone(),
            })
        }
        fn rearm(&mut self, key: &mut FakeKey) -> Result<(), u32> {
            if self.rearm_failures.contains(&key.path) {
                return Err(1018);
            }
            self.rearmed.push(key.path.clone());
            Ok(())
        }
        fn wait(&mut self, _: &[&FakeKey], _: Duration) -> Result<Vec<usize>, u32> {
            self.wait_script.pop_front().unwrap_or(Ok(Vec::new()))
        }
    }

    fn target(path: &str) -> WatchTarget {
        WatchTarget {
            root: RegRoot::LocalMachine,
            path: path.into(),
            subtree: false,
        }
    }

    fn plan(paths: &[&str]) -> TargetPlan {
        TargetPlan {
            targets: paths.iter().map(|p| target(p)).collect(),
            over_capacity: 0,
        }
    }

    #[test]
    fn handles_are_bounded_even_if_the_plan_is_oversized() {
        let paths: Vec<String> = (0..MAX_WATCHED_KEYS + 10)
            .map(|i| format!("K{i}"))
            .collect();
        let refs: Vec<&str> = paths.iter().map(String::as_str).collect();
        let mut fake = Fake::default();
        let mut set = WatchSet::default();
        set.reconcile(&mut fake, plan(&refs));
        assert_eq!(set.len(), MAX_WATCHED_KEYS);
        assert_eq!(fake.live.get(), MAX_WATCHED_KEYS);
        assert_eq!(set.stats().fallbacks["over_capacity"], 10);
    }

    #[test]
    fn reconcile_keeps_live_keys_releases_removed_and_retries_failures() {
        let mut fake = Fake::default();
        fake.open_failures.insert("Late".into(), 2);
        let mut set = WatchSet::default();
        set.reconcile(&mut fake, plan(&["A", "B", "Late"]));
        assert_eq!(set.len(), 2);
        assert_eq!(set.stats().fallbacks["key_missing"], 1);
        assert_eq!(fake.opened, 2);

        fake.open_failures.clear();
        set.reconcile(&mut fake, plan(&["A", "Late"]));
        assert_eq!(set.len(), 2, "B released, Late now open");
        assert_eq!(fake.opened, 3, "A was not reopened");
        assert_eq!(fake.live.get(), 2, "B's handle was released");
        assert!(set.stats().fallbacks.is_empty());
    }

    #[test]
    fn access_denied_is_reported_as_open_failed_not_missing() {
        let mut fake = Fake::default();
        fake.open_failures.insert("A".into(), 5);
        let mut set = WatchSet::default();
        set.reconcile(&mut fake, plan(&["A"]));
        assert_eq!(set.stats().fallbacks["open_failed"], 1);
        assert!(!set.stats().fallbacks.contains_key("key_missing"));
    }

    #[test]
    fn fired_keys_are_rearmed_before_wait_returns() {
        let mut fake = Fake::default();
        let mut set = WatchSet::default();
        set.reconcile(&mut fake, plan(&["A", "B", "C"]));
        fake.wait_script.push_back(Ok(vec![2, 0, 2, 9]));
        let n = set.wait(&mut fake, Duration::from_millis(1));
        assert_eq!(n, 2, "duplicates and out-of-range indices are ignored");
        assert_eq!(fake.rearmed, vec!["C".to_string(), "A".to_string()]);
        assert_eq!(set.len(), 3);
        assert_eq!(set.wait(&mut fake, Duration::from_millis(1)), 0);
    }

    #[test]
    fn rearm_failure_drops_key_counts_reason_and_still_reports_the_change() {
        let mut fake = Fake::default();
        let mut set = WatchSet::default();
        set.reconcile(&mut fake, plan(&["A", "B"]));
        fake.rearm_failures.insert("A".into());
        fake.wait_script.push_back(Ok(vec![0, 1]));
        assert_eq!(set.wait(&mut fake, Duration::ZERO), 2);
        assert_eq!(set.len(), 1);
        assert_eq!(fake.live.get(), 1);
        assert_eq!(set.stats().fallbacks["arm_failed"], 1);
        // The next reconcile retries it.
        fake.rearm_failures.clear();
        set.reconcile(&mut fake, plan(&["A", "B"]));
        assert_eq!(set.len(), 2);
        assert!(set.stats().fallbacks.is_empty());
    }

    #[test]
    fn wait_failure_releases_everything_and_recovers_on_reconcile() {
        let mut fake = Fake::default();
        let mut set = WatchSet::default();
        set.reconcile(&mut fake, plan(&["A", "B"]));
        fake.wait_script.push_back(Err(6));
        assert_eq!(set.wait(&mut fake, Duration::ZERO), 0);
        assert!(set.is_empty());
        assert_eq!(fake.live.get(), 0);
        assert_eq!(set.stats().fallbacks["wait_failed"], 2);
        set.reconcile(&mut fake, plan(&["A", "B"]));
        assert_eq!(set.len(), 2);
        assert!(set.stats().fallbacks.is_empty());
    }

    #[test]
    fn scheduler_is_idle_without_notifications() {
        let s = WakeScheduler::default();
        assert_eq!(s.due_at(), None);
    }

    #[test]
    fn scheduler_debounces_a_burst_into_one_run() {
        let t0 = Instant::now();
        let mut s = WakeScheduler::new(Duration::from_millis(500), Duration::from_secs(2));
        s.notify(t0);
        s.notify(t0 + Duration::from_millis(300));
        s.notify(t0 + Duration::from_millis(450));
        // Later notifications do not push the run back.
        assert_eq!(s.due_at(), Some(t0 + Duration::from_millis(500)));
        s.mark_run(t0 + Duration::from_millis(500));
        assert_eq!(s.due_at(), None);
    }

    #[test]
    fn scheduler_rate_limits_after_a_run_including_timer_runs() {
        let t0 = Instant::now();
        let mut s = WakeScheduler::new(Duration::from_millis(500), Duration::from_secs(2));
        s.mark_run(t0); // e.g. the safety-net timer
        s.notify(t0 + Duration::from_millis(100));
        assert_eq!(s.due_at(), Some(t0 + Duration::from_secs(2)));
        // Far from the last run, only the debounce applies.
        s.mark_run(t0 + Duration::from_secs(2));
        s.notify(t0 + Duration::from_secs(30));
        assert_eq!(s.due_at(), Some(t0 + Duration::from_millis(30_500)));
    }

    #[test]
    fn scheduler_sustained_noise_runs_once_per_gap() {
        let t0 = Instant::now();
        let mut s = WakeScheduler::new(Duration::from_millis(500), Duration::from_secs(2));
        let mut now = t0;
        let mut runs = 0;
        for _ in 0..100 {
            // a notification every 100 ms for 10 s
            s.notify(now);
            if s.due_at().is_some_and(|due| due <= now) {
                s.mark_run(now);
                runs += 1;
            }
            now += Duration::from_millis(100);
        }
        assert!((4..=6).contains(&runs), "runs = {runs}");
    }
}
