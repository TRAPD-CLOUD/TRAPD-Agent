//! Registry persistence watcher: the pure core (watch table, snapshot, diff,
//! storm protection). The Windows collector in `windows/regwatch.rs` supplies
//! the actual registry reads, so everything here replays and is tested on
//! every platform.
//!
//! Approach: poll-and-diff of a fixed table of persistence locations instead
//! of `RegNotifyChangeKeyValue`. Change notification needs one handle and wait
//! per watched key (hundreds for Services/IFEO/COM subtrees), cannot watch
//! hives that load later (new logons) and still needs a snapshot to learn
//! *what* changed. Polling every few seconds reuses the same read helpers,
//! handles per-user hives uniformly and keeps the attack surface small; the
//! cost is a few seconds of latency and no attribution of the writing process.
//!
//! The first snapshot is the baseline and emits nothing. Changes made while
//! the agent was not running are not reported (documented gap).

// Consumed only by the Windows collector; tests cover it on every platform.
#![cfg_attr(not(any(windows, test)), allow(dead_code))]

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::time::{Duration, Instant};

use crate::schema::{EventAction, RegistryEventData};

/// Longest value data kept in an event; longer data is cut on a char boundary.
pub const MAX_VALUE_CHARS: usize = 1024;
/// Loaded user hives watched per poll.
pub const MAX_USERS: usize = 64;
/// Total tracked values; a runaway subtree cannot grow memory unbounded.
pub const MAX_ENTRIES: usize = 50_000;
/// Events per category per [`STORM_WINDOW`]; the rest fold into one summary.
pub const STORM_MAX_PER_WINDOW: u32 = 40;
pub const STORM_WINDOW: Duration = Duration::from_secs(60);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum RegRoot {
    LocalMachine,
    Users,
}

/// Registry reads the watcher needs. Failures read as "nothing there".
pub trait RegistryReader {
    fn subkeys(&self, root: RegRoot, path: &str) -> Vec<String>;
    /// `(name, rendered data)`; the unnamed value has name `""`.
    fn values(&self, root: RegRoot, path: &str) -> Vec<(String, String)>;
}

#[derive(Clone, Copy, Debug)]
pub enum Scope {
    /// `HKLM\<path>`.
    Machine,
    /// `HKU\<sid>\<path>` for every loaded user hive (the HKCU equivalent).
    User,
    /// `HKU\<sid>_Classes\<path>` (the HKCU\Software\Classes view).
    UserClasses,
}

#[derive(Clone, Copy, Debug)]
pub enum Shape {
    /// Values directly under the key. Empty `names` means all values.
    Values(&'static [&'static str]),
    /// For every subkey, the values of `<subkey>[\child]`.
    Children {
        child: Option<&'static str>,
        names: &'static [&'static str],
    },
}

#[derive(Clone, Copy, Debug)]
pub struct Spec {
    pub category: &'static str,
    pub scope: Scope,
    pub path: &'static str,
    pub shape: Shape,
}

const fn spec(category: &'static str, scope: Scope, path: &'static str, shape: Shape) -> Spec {
    Spec {
        category,
        scope,
        path,
        shape,
    }
}

const ALL: Shape = Shape::Values(&[]);

/// What gets watched. Machine paths include the `WOW6432Node` twins because a
/// 32-bit writer lands there and the native path would never show it.
pub const SPECS: &[Spec] = &[
    // Run / RunOnce, machine and every loaded user.
    spec(
        "run_key",
        Scope::Machine,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        ALL,
    ),
    spec(
        "run_key",
        Scope::Machine,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        ALL,
    ),
    spec(
        "run_key",
        Scope::Machine,
        r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
        ALL,
    ),
    spec(
        "run_key",
        Scope::Machine,
        r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
        ALL,
    ),
    spec(
        "run_key",
        Scope::Machine,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
        ALL,
    ),
    spec(
        "run_key",
        Scope::User,
        r"Software\Microsoft\Windows\CurrentVersion\Run",
        ALL,
    ),
    spec(
        "run_key",
        Scope::User,
        r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
        ALL,
    ),
    spec(
        "run_key",
        Scope::User,
        r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
        ALL,
    ),
    // Logon script and per-user shell override.
    spec(
        "startup_env",
        Scope::User,
        r"Environment",
        Shape::Values(&["UserInitMprLogonScript"]),
    ),
    // Services: image, start type, account, and svchost-hosted DLLs.
    spec(
        "service",
        Scope::Machine,
        r"SYSTEM\CurrentControlSet\Services",
        Shape::Children {
            child: None,
            names: &["ImagePath", "Start", "Type", "ObjectName"],
        },
    ),
    spec(
        "service",
        Scope::Machine,
        r"SYSTEM\CurrentControlSet\Services",
        Shape::Children {
            child: Some("Parameters"),
            names: &["ServiceDll"],
        },
    ),
    // Image File Execution Options: debugger hijack, silent process exit.
    spec(
        "ifeo",
        Scope::Machine,
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
        Shape::Children {
            child: None,
            names: &["Debugger", "GlobalFlag", "VerifierDlls"],
        },
    ),
    spec(
        "ifeo",
        Scope::Machine,
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit",
        Shape::Children {
            child: None,
            names: &["MonitorProcess", "ReportingMode"],
        },
    ),
    // Winlogon.
    spec(
        "winlogon",
        Scope::Machine,
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
        Shape::Values(&["Shell", "Userinit", "Taskman"]),
    ),
    spec(
        "winlogon",
        Scope::User,
        r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon",
        Shape::Values(&["Shell"]),
    ),
    // AppInit_DLLs.
    spec(
        "appinit",
        Scope::Machine,
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",
        Shape::Values(&["AppInit_DLLs"]),
    ),
    spec(
        "appinit",
        Scope::Machine,
        r"SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows",
        Shape::Values(&["AppInit_DLLs"]),
    ),
    // Microsoft Defender exclusions (local and policy) and disable switches.
    spec(
        "defender",
        Scope::Machine,
        r"SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths",
        ALL,
    ),
    spec(
        "defender",
        Scope::Machine,
        r"SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions",
        ALL,
    ),
    spec(
        "defender",
        Scope::Machine,
        r"SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes",
        ALL,
    ),
    spec(
        "defender",
        Scope::Machine,
        r"SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths",
        ALL,
    ),
    spec(
        "defender",
        Scope::Machine,
        r"SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Extensions",
        ALL,
    ),
    spec(
        "defender",
        Scope::Machine,
        r"SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Processes",
        ALL,
    ),
    spec(
        "defender",
        Scope::Machine,
        r"SOFTWARE\Policies\Microsoft\Windows Defender",
        Shape::Values(&["DisableAntiSpyware", "DisableAntiVirus"]),
    ),
    spec(
        "defender",
        Scope::Machine,
        r"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection",
        Shape::Values(&["DisableRealtimeMonitoring", "DisableBehaviorMonitoring"]),
    ),
    // COM hijack: a per-user CLSID registration shadows the machine one.
    spec(
        "com_hijack",
        Scope::UserClasses,
        r"CLSID",
        Shape::Children {
            child: Some("InprocServer32"),
            names: &[""],
        },
    ),
    spec(
        "com_hijack",
        Scope::UserClasses,
        r"CLSID",
        Shape::Children {
            child: Some("LocalServer32"),
            names: &[""],
        },
    ),
    // Scheduled tasks: new top-level task names appear in the TaskCache tree
    // without needing the 4698 audit policy.
    spec(
        "scheduled_task",
        Scope::Machine,
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree",
        Shape::Children {
            child: None,
            names: &["Id"],
        },
    ),
];

/// One watched value. Ordered so a snapshot diff is deterministic.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct EntryKey {
    pub category: &'static str,
    pub user_sid: Option<String>,
    pub key_path: String,
    pub value_name: String,
}

#[derive(Clone, Debug, Default)]
pub struct Snapshot {
    pub entries: BTreeMap<EntryKey, String>,
    /// User hives that were loaded (and readable) when the snapshot was taken.
    pub users: BTreeSet<String>,
}

fn name_wanted(names: &[&str], value: &str) -> bool {
    names.is_empty() || names.iter().any(|n| n.eq_ignore_ascii_case(value))
}

pub fn truncate_value(v: &str) -> String {
    match v.char_indices().nth(MAX_VALUE_CHARS) {
        Some((i, _)) => v[..i].to_string(),
        None => v.to_string(),
    }
}

/// Interactive-style account SIDs. Excludes `S-1-5-18/19/20` (service
/// accounts, no Run keys of interest) and the `_Classes` companions.
fn is_user_sid(name: &str) -> bool {
    (name.starts_with("S-1-5-21-") || name.starts_with("S-1-12-1-")) && !name.ends_with("_Classes")
}

pub fn snapshot(reader: &dyn RegistryReader, specs: &[Spec]) -> Snapshot {
    let mut snap = Snapshot::default();
    let sids: Vec<String> = reader
        .subkeys(RegRoot::Users, "")
        .into_iter()
        .filter(|s| is_user_sid(s))
        .take(MAX_USERS)
        .collect();
    snap.users = sids.iter().cloned().collect();

    for s in specs {
        let targets: Vec<(Option<&str>, RegRoot, String, String)> = match s.scope {
            Scope::Machine => vec![(
                None,
                RegRoot::LocalMachine,
                s.path.to_string(),
                format!("HKLM\\{}", s.path),
            )],
            Scope::User => sids
                .iter()
                .map(|sid| {
                    (
                        Some(sid.as_str()),
                        RegRoot::Users,
                        format!("{sid}\\{}", s.path),
                        format!("HKU\\{sid}\\{}", s.path),
                    )
                })
                .collect(),
            Scope::UserClasses => sids
                .iter()
                .map(|sid| {
                    (
                        Some(sid.as_str()),
                        RegRoot::Users,
                        format!("{sid}_Classes\\{}", s.path),
                        format!("HKU\\{sid}_Classes\\{}", s.path),
                    )
                })
                .collect(),
        };
        for (sid, root, read_path, shown) in targets {
            let mut read = |read_path: &str, shown: &str| {
                let names = match s.shape {
                    Shape::Values(n) => n,
                    Shape::Children { names, .. } => names,
                };
                for (name, data) in reader.values(root, read_path) {
                    if snap.entries.len() >= MAX_ENTRIES {
                        return;
                    }
                    if name_wanted(names, &name) {
                        let value_name = if name.is_empty() {
                            "(Default)".to_string()
                        } else {
                            name
                        };
                        snap.entries.insert(
                            EntryKey {
                                category: s.category,
                                user_sid: sid.map(str::to_string),
                                key_path: shown.to_string(),
                                value_name,
                            },
                            truncate_value(&data),
                        );
                    }
                }
            };
            match s.shape {
                Shape::Values(_) => read(&read_path, &shown),
                Shape::Children { child, .. } => {
                    for sub in reader.subkeys(root, &read_path) {
                        let (p, d) = match child {
                            Some(c) => (
                                format!("{read_path}\\{sub}\\{c}"),
                                format!("{shown}\\{sub}\\{c}"),
                            ),
                            None => (format!("{read_path}\\{sub}"), format!("{shown}\\{sub}")),
                        };
                        read(&p, &d);
                    }
                }
            }
        }
    }
    snap
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Change {
    pub key: EntryKey,
    pub old: Option<String>,
    pub new: Option<String>,
}

impl Change {
    pub fn action(&self) -> EventAction {
        match (&self.old, &self.new) {
            (None, Some(_)) => EventAction::Create,
            (Some(_), None) => EventAction::Delete,
            _ => EventAction::Modify,
        }
    }
}

/// Value-level differences. Entries of a user hive that was not loaded in both
/// snapshots are skipped: a logoff/logon would otherwise look like a mass
/// delete followed by a mass create of that user's Run keys.
pub fn diff(old: &Snapshot, new: &Snapshot) -> Vec<Change> {
    let comparable = |k: &EntryKey| {
        k.user_sid
            .as_ref()
            .is_none_or(|sid| old.users.contains(sid) && new.users.contains(sid))
    };
    let mut out = Vec::new();
    for (k, v) in &new.entries {
        if !comparable(k) {
            continue;
        }
        match old.entries.get(k) {
            None => out.push(Change {
                key: k.clone(),
                old: None,
                new: Some(v.clone()),
            }),
            Some(prev) if prev != v => out.push(Change {
                key: k.clone(),
                old: Some(prev.clone()),
                new: Some(v.clone()),
            }),
            _ => {}
        }
    }
    for (k, v) in &old.entries {
        if comparable(k) && !new.entries.contains_key(k) {
            out.push(Change {
                key: k.clone(),
                old: Some(v.clone()),
                new: None,
            });
        }
    }
    out
}

impl From<&Change> for RegistryEventData {
    fn from(c: &Change) -> Self {
        RegistryEventData {
            key_path: c.key.key_path.clone(),
            value_name: c.key.value_name.clone(),
            category: c.key.category.to_string(),
            user_sid: c.key.user_sid.clone(),
            old_value: c.old.clone(),
            new_value: c.new.clone(),
            suppressed: None,
        }
    }
}

#[derive(Default)]
struct Bucket {
    start: Option<Instant>,
    used: u32,
    suppressed: u32,
}

/// Per-category event budget. A noisy category (an installer writing hundreds
/// of services) cannot starve a quiet, high-value one (IFEO, Winlogon), and
/// what is dropped is reported as one summary instead of silently lost.
#[derive(Default)]
pub struct StormGate {
    buckets: HashMap<&'static str, Bucket>,
}

impl StormGate {
    pub fn admit(&mut self, category: &'static str, now: Instant) -> bool {
        let b = self.buckets.entry(category).or_default();
        b.start.get_or_insert(now);
        if b.used < STORM_MAX_PER_WINDOW {
            b.used += 1;
            true
        } else {
            b.suppressed = b.suppressed.saturating_add(1);
            false
        }
    }

    /// Close elapsed windows; returns `(category, suppressed)` for those that
    /// dropped events. Call before admitting a poll's changes.
    pub fn flush(&mut self, now: Instant) -> Vec<(&'static str, u32)> {
        let mut out = Vec::new();
        for (cat, b) in self.buckets.iter_mut() {
            if b.start
                .is_some_and(|s| now.duration_since(s) >= STORM_WINDOW)
            {
                if b.suppressed > 0 {
                    out.push((*cat, b.suppressed));
                }
                *b = Bucket::default();
            }
        }
        out.sort();
        out
    }
}

/// Summary event for events dropped by the [`StormGate`].
pub fn storm_event(category: &str, suppressed: u32) -> RegistryEventData {
    RegistryEventData {
        key_path: String::new(),
        value_name: String::new(),
        category: "storm".into(),
        user_sid: None,
        old_value: None,
        new_value: Some(category.to_string()),
        suppressed: Some(suppressed),
    }
}

/// One poll: diff, then rate-limit. Returns the events to emit.
pub fn plan_events(
    old: &Snapshot,
    new: &Snapshot,
    gate: &mut StormGate,
    now: Instant,
) -> Vec<(EventAction, RegistryEventData)> {
    let mut out: Vec<(EventAction, RegistryEventData)> = gate
        .flush(now)
        .into_iter()
        .map(|(cat, n)| (EventAction::Modify, storm_event(cat, n)))
        .collect();
    for c in diff(old, new) {
        if gate.admit(c.key.category, now) {
            out.push((c.action(), RegistryEventData::from(&c)));
        }
    }
    out
}

#[cfg(test)]
pub mod tests {
    use super::*;

    /// In-memory registry: path (lowercase-insensitive not needed) -> values.
    #[derive(Default, Clone)]
    pub struct FakeReg {
        pub values: BTreeMap<(RegRoot, String), Vec<(String, String)>>,
        pub keys: BTreeMap<(RegRoot, String), Vec<String>>,
    }

    impl FakeReg {
        pub fn set(&mut self, root: RegRoot, path: &str, name: &str, data: &str) {
            let vals = self.values.entry((root, path.into())).or_default();
            vals.retain(|(n, _)| n != name);
            vals.push((name.into(), data.into()));
            // Register ancestors so subkey enumeration works.
            let mut parts: Vec<&str> = path.split('\\').collect();
            while let Some(last) = parts.pop() {
                let parent = parts.join("\\");
                let subs = self.keys.entry((root, parent)).or_default();
                if !subs.iter().any(|s| s == last) {
                    subs.push(last.to_string());
                }
            }
        }
        pub fn remove(&mut self, root: RegRoot, path: &str, name: &str) {
            if let Some(v) = self.values.get_mut(&(root, path.to_string())) {
                v.retain(|(n, _)| n != name);
            }
        }
    }

    impl RegistryReader for FakeReg {
        fn subkeys(&self, root: RegRoot, path: &str) -> Vec<String> {
            self.keys
                .get(&(root, path.to_string()))
                .cloned()
                .unwrap_or_default()
        }
        fn values(&self, root: RegRoot, path: &str) -> Vec<(String, String)> {
            self.values
                .get(&(root, path.to_string()))
                .cloned()
                .unwrap_or_default()
        }
    }

    const SID: &str = "S-1-5-21-1-2-3-1001";
    const RUN: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";

    fn user_run(reg: &mut FakeReg, name: &str, data: &str) {
        reg.set(RegRoot::Users, &format!("{SID}\\{RUN}"), name, data);
    }

    #[test]
    fn hkcu_run_value_added_is_a_create_event() {
        // `reg add HKCU\...\Run /v trapdtest /d "cmd /c echo x"`
        let mut reg = FakeReg::default();
        reg.set(RegRoot::Users, SID, "", ""); // hive present
        let base = snapshot(&reg, SPECS);
        user_run(&mut reg, "trapdtest", "cmd /c echo x");
        let after = snapshot(&reg, SPECS);

        let mut gate = StormGate::default();
        let ev = plan_events(&base, &after, &mut gate, Instant::now());
        assert_eq!(ev.len(), 1);
        let (action, data) = &ev[0];
        assert!(matches!(action, EventAction::Create));
        assert_eq!(data.category, "run_key");
        assert_eq!(data.value_name, "trapdtest");
        assert_eq!(data.new_value.as_deref(), Some("cmd /c echo x"));
        assert_eq!(data.user_sid.as_deref(), Some(SID));
        assert!(data.key_path.starts_with(&format!("HKU\\{SID}\\Software")));
    }

    #[test]
    fn modify_and_delete_are_reported() {
        let mut reg = FakeReg::default();
        reg.set(RegRoot::Users, SID, "", "");
        user_run(&mut reg, "a", "one");
        user_run(&mut reg, "b", "two");
        let s0 = snapshot(&reg, SPECS);
        user_run(&mut reg, "a", "changed");
        reg.remove(RegRoot::Users, &format!("{SID}\\{RUN}"), "b");
        let s1 = snapshot(&reg, SPECS);
        let ch = diff(&s0, &s1);
        assert_eq!(ch.len(), 2);
        assert!(ch
            .iter()
            .any(|c| matches!(c.action(), EventAction::Modify) && c.old.as_deref() == Some("one")));
        assert!(ch
            .iter()
            .any(|c| matches!(c.action(), EventAction::Delete) && c.key.value_name == "b"));
    }

    #[test]
    fn unchanged_snapshot_has_no_changes() {
        let mut reg = FakeReg::default();
        reg.set(
            RegRoot::LocalMachine,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "x",
            "y",
        );
        let s = snapshot(&reg, SPECS);
        assert!(diff(&s, &snapshot(&reg, SPECS)).is_empty());
    }

    #[test]
    fn user_logon_does_not_replay_that_users_run_keys() {
        let mut reg = FakeReg::default();
        reg.set(RegRoot::LocalMachine, "x", "", "");
        let before = snapshot(&reg, SPECS); // nobody logged on
        reg.set(RegRoot::Users, SID, "", "");
        user_run(
            &mut reg,
            "OneDrive",
            r"C:\Program Files\OneDrive\OneDrive.exe",
        );
        let after = snapshot(&reg, SPECS);
        assert!(after.users.contains(SID));
        assert!(
            diff(&before, &after).is_empty(),
            "newly loaded hive is baseline"
        );
        // logoff
        assert!(diff(&after, &before).is_empty());
    }

    #[test]
    fn services_ifeo_com_and_defender_are_covered() {
        let mut reg = FakeReg::default();
        reg.set(RegRoot::Users, SID, "", "");
        let base = snapshot(&reg, SPECS);
        reg.set(
            RegRoot::LocalMachine,
            r"SYSTEM\CurrentControlSet\Services\evil",
            "ImagePath",
            r"C:\Users\Public\a.exe",
        );
        reg.set(
            RegRoot::LocalMachine,
            r"SYSTEM\CurrentControlSet\Services\evil",
            "DisplayName", // not watched
            "x",
        );
        reg.set(
            RegRoot::LocalMachine,
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe",
            "Debugger",
            "cmd.exe",
        );
        reg.set(
            RegRoot::LocalMachine,
            r"SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths",
            r"C:\Temp",
            "0",
        );
        reg.set(
            RegRoot::Users,
            &format!("{SID}_Classes\\CLSID\\{{abc}}\\InprocServer32"),
            "",
            r"C:\Users\u\AppData\x.dll",
        );
        reg.set(
            RegRoot::LocalMachine,
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
            "Shell",
            r"explorer.exe, evil.exe",
        );
        reg.set(
            RegRoot::LocalMachine,
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",
            "AppInit_DLLs",
            r"C:\x.dll",
        );
        let ch = diff(&base, &snapshot(&reg, SPECS));
        let cats: BTreeSet<&str> = ch.iter().map(|c| c.key.category).collect();
        for c in [
            "service",
            "ifeo",
            "defender",
            "com_hijack",
            "winlogon",
            "appinit",
        ] {
            assert!(cats.contains(c), "missing {c}: {cats:?}");
        }
        assert!(!ch.iter().any(|c| c.key.value_name == "DisplayName"));
        let com = ch.iter().find(|c| c.key.category == "com_hijack").unwrap();
        assert_eq!(com.key.value_name, "(Default)");
        assert!(com.key.key_path.ends_with("InprocServer32"));
    }

    #[test]
    fn storm_gate_caps_per_category_and_summarises() {
        let mut gate = StormGate::default();
        let t0 = Instant::now();
        let admitted = (0..100).filter(|_| gate.admit("service", t0)).count();
        assert_eq!(admitted as u32, STORM_MAX_PER_WINDOW);
        // A different category is unaffected.
        assert!(gate.admit("ifeo", t0));
        assert!(gate.flush(t0).is_empty(), "window still open");
        let later = t0 + STORM_WINDOW;
        assert_eq!(
            gate.flush(later),
            vec![("service", 100 - STORM_MAX_PER_WINDOW)]
        );
        assert!(gate.admit("service", later), "budget restored");
    }

    #[test]
    fn plan_events_limits_a_burst_and_emits_one_summary_later() {
        let reg0 = FakeReg::default();
        let base = snapshot(&reg0, SPECS);
        let mut reg = FakeReg::default();
        for i in 0..200 {
            reg.set(
                RegRoot::LocalMachine,
                &format!(r"SYSTEM\CurrentControlSet\Services\s{i}"),
                "ImagePath",
                "x",
            );
        }
        let new = snapshot(&reg, SPECS);
        let mut gate = StormGate::default();
        let t0 = Instant::now();
        let ev = plan_events(&base, &new, &mut gate, t0);
        assert_eq!(ev.len() as u32, STORM_MAX_PER_WINDOW);
        let ev2 = plan_events(&new, &new, &mut gate, t0 + STORM_WINDOW);
        assert_eq!(ev2.len(), 1);
        assert_eq!(ev2[0].1.category, "storm");
        assert_eq!(ev2[0].1.suppressed, Some(200 - STORM_MAX_PER_WINDOW));
    }

    #[test]
    fn values_are_truncated_on_char_boundaries() {
        let long = "ä".repeat(MAX_VALUE_CHARS + 50);
        assert_eq!(truncate_value(&long).chars().count(), MAX_VALUE_CHARS);
        assert_eq!(truncate_value("short"), "short");
    }

    #[test]
    fn service_account_hives_are_not_watched_as_users() {
        assert!(is_user_sid("S-1-5-21-1-2-3-500"));
        assert!(is_user_sid("S-1-12-1-9-9-9-9"));
        assert!(!is_user_sid("S-1-5-18"));
        assert!(!is_user_sid("S-1-5-21-1-2-3-500_Classes"));
        assert!(!is_user_sid(".DEFAULT"));
    }
}
