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
//! The first installation captures a silent baseline. The Windows collector
//! persists it so later starts report changes made while the agent was stopped.

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

/// Registry reads the watcher needs. Checked reads distinguish failures from missing keys.
pub trait RegistryReader {
    fn subkeys(&self, root: RegRoot, path: &str) -> Vec<String>;
    /// `(name, rendered data)`; the unnamed value has name `""`.
    fn values(&self, root: RegRoot, path: &str) -> Vec<(String, String)>;
    fn checked_subkeys(&self, root: RegRoot, path: &str) -> Result<Vec<String>, u32> {
        Ok(self.subkeys(root, path))
    }
    fn checked_values(&self, root: RegRoot, path: &str) -> Result<Vec<(String, String)>, u32> {
        Ok(self.values(root, path))
    }
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
    pub unavailable: BTreeSet<String>,
    pub incomplete: bool,
}

/// Bound both file reads and JSON encoding; raw values retain the existing
/// telemetry truncation and are stored only in the protected agent state dir.
pub const MAX_BASELINE_BYTES: usize = 16 * 1024 * 1024;
const BASELINE_VERSION: u32 = 1;

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SavedBaseline {
    version: u32,
    users: BTreeSet<String>,
    unavailable: BTreeSet<String>,
    entries: Vec<SavedEntry>,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SavedEntry {
    category: String,
    user_sid: Option<String>,
    key_path: String,
    value_name: String,
    value: String,
}

fn validate_snapshot(snapshot: &Snapshot) -> anyhow::Result<()> {
    anyhow::ensure!(!snapshot.incomplete, "registry snapshot incomplete");
    anyhow::ensure!(
        snapshot.entries.len() <= MAX_ENTRIES,
        "too many registry entries"
    );
    anyhow::ensure!(snapshot.users.len() <= MAX_USERS, "too many registry users");
    anyhow::ensure!(
        snapshot.users.iter().all(|sid| valid_sid(sid)),
        "invalid registry user"
    );
    let mut raw_bytes = snapshot.users.iter().map(String::len).sum::<usize>()
        + snapshot.unavailable.iter().map(String::len).sum::<usize>();
    anyhow::ensure!(
        snapshot.unavailable.len() <= MAX_ENTRIES
            && raw_bytes <= MAX_BASELINE_BYTES
            && snapshot
                .unavailable
                .iter()
                .all(|prefix| valid_unavailable_prefix(prefix)),
        "invalid registry availability markers"
    );
    for (key, value) in &snapshot.entries {
        raw_bytes = raw_bytes
            .saturating_add(key.key_path.len())
            .saturating_add(key.value_name.len())
            .saturating_add(value.len())
            .saturating_add(key.category.len())
            .saturating_add(key.user_sid.as_ref().map_or(0, String::len));
        anyhow::ensure!(
            raw_bytes <= MAX_BASELINE_BYTES,
            "registry baseline too large"
        );
        anyhow::ensure!(
            key.key_path.encode_utf16().count() <= 32768
                && key.value_name.encode_utf16().count() <= 16383
                && value.chars().count() <= MAX_VALUE_CHARS,
            "registry field too large"
        );
        anyhow::ensure!(
            category_for_path(&key.key_path, &key.value_name) == Some(key.category),
            "invalid registry location"
        );
        let mut parts = key.key_path.split('\\');
        let root = parts.next().unwrap_or_default();
        let hive = parts.next().unwrap_or_default();
        let identity_matches = match &key.user_sid {
            Some(sid) => {
                snapshot.users.contains(sid)
                    && root.eq_ignore_ascii_case("HKU")
                    && (hive == sid || hive == format!("{sid}_Classes"))
            }
            None => root.eq_ignore_ascii_case("HKLM"),
        };
        anyhow::ensure!(identity_matches, "registry user does not match location");
    }
    Ok(())
}

fn valid_unavailable_prefix(path: &str) -> bool {
    if path == "HKU" {
        return true;
    }
    let Some((root, tail)) = path.split_once('\\') else {
        return false;
    };
    let (scope, relative) = if root == "HKLM" {
        (Scope::Machine, tail)
    } else if root == "HKU" {
        let (hive, relative) = tail.split_once('\\').unwrap_or((tail, ""));
        let sid = hive.strip_suffix("_Classes").unwrap_or(hive);
        if !valid_sid(sid) {
            return false;
        }
        if relative.is_empty() {
            return true;
        }
        (
            if hive.ends_with("_Classes") {
                Scope::UserClasses
            } else {
                Scope::User
            },
            relative,
        )
    } else {
        return false;
    };
    SPECS.iter().any(|spec| {
        std::mem::discriminant(&spec.scope) == std::mem::discriminant(&scope)
            && match spec.shape {
                Shape::Values(_) => relative.eq_ignore_ascii_case(spec.path),
                Shape::Children { .. } => below(relative, spec.path),
            }
    })
}

fn valid_sid(sid: &str) -> bool {
    sid.len() <= 184
        && is_user_sid(sid)
        && sid
            .bytes()
            .all(|b| b.is_ascii_digit() || b == b'-' || b == b'S')
}

pub fn encode_baseline(snapshot: &Snapshot) -> anyhow::Result<Vec<u8>> {
    validate_snapshot(snapshot)?;
    let saved = SavedBaseline {
        version: BASELINE_VERSION,
        users: snapshot.users.clone(),
        unavailable: snapshot.unavailable.clone(),
        entries: snapshot
            .entries
            .iter()
            .map(|(key, value)| SavedEntry {
                category: key.category.into(),
                user_sid: key.user_sid.clone(),
                key_path: key.key_path.clone(),
                value_name: key.value_name.clone(),
                value: value.clone(),
            })
            .collect(),
    };
    struct Bounded(Vec<u8>);
    impl std::io::Write for Bounded {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if bytes.len() > MAX_BASELINE_BYTES.saturating_sub(self.0.len()) {
                return Err(std::io::Error::other("registry baseline too large"));
            }
            self.0.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut output = Bounded(Vec::new());
    serde_json::to_writer(&mut output, &saved)?;
    Ok(output.0)
}

pub fn decode_baseline(bytes: &[u8]) -> anyhow::Result<Snapshot> {
    anyhow::ensure!(
        bytes.len() <= MAX_BASELINE_BYTES,
        "registry baseline too large"
    );
    let saved: SavedBaseline = serde_json::from_slice(bytes)
        .map_err(|_| anyhow::anyhow!("invalid registry baseline JSON"))?;
    anyhow::ensure!(
        saved.version == BASELINE_VERSION,
        "unsupported registry baseline version"
    );
    anyhow::ensure!(
        saved.entries.len() <= MAX_ENTRIES,
        "too many registry entries"
    );
    let mut snapshot = Snapshot {
        users: saved.users,
        unavailable: saved.unavailable,
        ..Snapshot::default()
    };
    for entry in saved.entries {
        let category = SPECS
            .iter()
            .find(|s| s.category == entry.category)
            .map(|s| s.category)
            .ok_or_else(|| anyhow::anyhow!("unknown registry category"))?;
        let key = EntryKey {
            category,
            user_sid: entry.user_sid,
            key_path: entry.key_path,
            value_name: entry.value_name,
        };
        anyhow::ensure!(
            snapshot.entries.insert(key, entry.value).is_none(),
            "duplicate registry entry"
        );
    }
    validate_snapshot(&snapshot)?;
    Ok(snapshot)
}

pub fn load_baseline(path: &std::path::Path) -> anyhow::Result<Option<Snapshot>> {
    use std::io::Read;
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    anyhow::ensure!(
        metadata.is_file() && metadata.len() <= MAX_BASELINE_BYTES as u64,
        "registry baseline is not a bounded regular file"
    );
    let file = std::fs::File::open(path)?;
    let mut bytes = Vec::new();
    file.take(MAX_BASELINE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    decode_baseline(&bytes).map(Some)
}

fn below(path: &str, prefix: &str) -> bool {
    path.eq_ignore_ascii_case(prefix)
        || (path
            .get(..prefix.len())
            .is_some_and(|p| p.eq_ignore_ascii_case(prefix))
            && path.as_bytes().get(prefix.len()) == Some(&b'\\'))
}

fn prefix_index(prefixes: &BTreeSet<String>) -> BTreeSet<String> {
    prefixes
        .iter()
        .map(|prefix| prefix.to_ascii_lowercase())
        .collect()
}

/// Check ancestors with logarithmic set lookups instead of scanning every
/// failed scope for every value. Paths and prefixes compare ASCII case-insensitively.
fn unavailable(index: &BTreeSet<String>, path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    let mut ancestor = lower.as_str();
    loop {
        if index.contains(ancestor) {
            return true;
        }
        let Some((parent, _)) = ancestor.rsplit_once('\\') else {
            return false;
        };
        ancestor = parent;
    }
}

/// Keep offline hives and failed reads so recovery compares against the last
/// known state. At capacity retain no partial baseline: the caller skips it.
pub fn retain_unavailable(previous: &Snapshot, mut current: Snapshot) -> anyhow::Result<Snapshot> {
    anyhow::ensure!(!current.incomplete, "registry snapshot incomplete");
    let failed_index = prefix_index(&current.unavailable);
    for (key, value) in &previous.entries {
        if key
            .user_sid
            .as_ref()
            .is_some_and(|sid| !current.users.contains(sid))
            || unavailable(&failed_index, &key.key_path)
        {
            current.entries.insert(key.clone(), value.clone());
        }
    }
    let observed_users = current.users.clone();
    // An empty observed hive is still a baseline: losing its identity would
    // hide persistence created while it was unloaded. At capacity fail visibly.
    current.users.extend(previous.users.iter().cloned());
    // Mark only scopes that have never had a readable baseline. Failed reads
    // of known scopes retain their values and must still report recovery changes.
    let failed_scopes = std::mem::take(&mut current.unavailable);
    let unknown_index = prefix_index(&previous.unavailable);
    let unknown_originals: BTreeMap<String, &String> = previous
        .unavailable
        .iter()
        .map(|prefix| (prefix.to_ascii_lowercase(), prefix))
        .collect();
    for failed in &failed_scopes {
        if unavailable(&unknown_index, failed) {
            current.unavailable.insert(failed.clone());
        } else {
            let descendants = format!("{}\\", failed.to_ascii_lowercase());
            for (_, unknown) in unknown_originals
                .range(descendants.clone()..)
                .take_while(|(path, _)| path.starts_with(&descendants))
            {
                current.unavailable.insert((*unknown).clone());
            }
        }
    }
    for prefix in &previous.unavailable {
        let hive = prefix
            .strip_prefix("HKU\\")
            .and_then(|path| path.split('\\').next())
            .map(|hive| hive.strip_suffix("_Classes").unwrap_or(hive));
        if hive.is_some_and(|hive| previous.users.contains(hive) && !observed_users.contains(hive))
        {
            current.unavailable.insert(prefix.clone());
        }
    }
    validate_snapshot(&current)?;
    Ok(current)
}

/// Canonical HKLM/HKU paths only; reuse the watcher table for native audit events.
pub fn category_for_path(path: &str, name: &str) -> Option<&'static str> {
    let (root, tail) = path.split_once('\\')?;
    let (scope, relative) = if root.eq_ignore_ascii_case("HKLM") {
        (Scope::Machine, tail)
    } else if root.eq_ignore_ascii_case("HKU") {
        let (hive, relative) = tail.split_once('\\')?;
        if let Some(sid) = hive.strip_suffix("_Classes") {
            if !valid_sid(sid) {
                return None;
            }
            (Scope::UserClasses, relative)
        } else {
            if !valid_sid(hive) {
                return None;
            }
            (Scope::User, relative)
        }
    } else {
        return None;
    };
    // Audit providers sometimes resolve CurrentControlSet to its numbered
    // alias. Preserve the native event path, but classify all configured sets.
    let numbered = relative.split_once('\\').and_then(|(system, rest)| {
        let (set, tail) = rest.split_once('\\')?;
        (system.eq_ignore_ascii_case("SYSTEM")
            && set.len() == 13
            && set
                .get(..10)
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case("ControlSet"))
            && set.as_bytes()[10..].iter().all(u8::is_ascii_digit))
        .then(|| format!("SYSTEM\\CurrentControlSet\\{tail}"))
    });
    let relative = numbered.as_deref().unwrap_or(relative);
    let name = if name == "(Default)" { "" } else { name };
    SPECS.iter().find_map(|spec| {
        if std::mem::discriminant(&spec.scope) != std::mem::discriminant(&scope) {
            return None;
        }
        let matches = match spec.shape {
            Shape::Values(names) => {
                relative.eq_ignore_ascii_case(spec.path) && name_wanted(names, name)
            }
            Shape::Children { child, names } => {
                if !below(relative, spec.path) || relative.len() <= spec.path.len() {
                    return None;
                }
                let rest = relative.get(spec.path.len() + 1..)?;
                let shape_matches = match child {
                    None => !rest.is_empty() && !rest.contains('\\'),
                    Some(child) => rest.split_once('\\').is_some_and(|(sub, tail)| {
                        !sub.is_empty() && tail.eq_ignore_ascii_case(child)
                    }),
                };
                shape_matches && name_wanted(names, name)
            }
        };
        matches.then_some(spec.category)
    })
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

fn mark_unavailable(snapshot: &mut Snapshot, raw_bytes: &mut usize, prefix: String) {
    if snapshot.incomplete || snapshot.unavailable.contains(&prefix) {
        return;
    }
    if snapshot.unavailable.len() >= MAX_ENTRIES
        || prefix.len() > MAX_BASELINE_BYTES.saturating_sub(*raw_bytes)
    {
        snapshot.incomplete = true;
        return;
    }
    *raw_bytes += prefix.len();
    snapshot.unavailable.insert(prefix);
}

pub fn snapshot(reader: &dyn RegistryReader, specs: &[Spec]) -> Snapshot {
    let mut snap = Snapshot::default();
    let mut raw_bytes = 0usize;
    let hives = match reader.checked_subkeys(RegRoot::Users, "") {
        Ok(hives) => hives,
        Err(_) => {
            mark_unavailable(&mut snap, &mut raw_bytes, "HKU".into());
            Vec::new()
        }
    };
    let sids: Vec<String> = hives
        .iter()
        .filter(|s| is_user_sid(s))
        .take(MAX_USERS)
        .cloned()
        .collect();
    snap.users = sids.iter().cloned().collect();

    raw_bytes += snap.users.iter().map(String::len).sum::<usize>();
    for s in specs {
        if snap.incomplete {
            break;
        }
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
                .filter(|sid| {
                    let loaded = hives.iter().any(|hive| hive == &format!("{sid}_Classes"));
                    if !loaded {
                        mark_unavailable(&mut snap, &mut raw_bytes, format!("HKU\\{sid}_Classes"));
                    }
                    loaded
                })
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
            if snap.incomplete {
                break;
            }
            let mut read = |read_path: &str, shown: &str| {
                if snap.incomplete {
                    return false;
                }
                let names = match s.shape {
                    Shape::Values(n) => n,
                    Shape::Children { names, .. } => names,
                };
                let values = match reader.checked_values(root, read_path) {
                    Ok(values) => values,
                    Err(_) => {
                        mark_unavailable(&mut snap, &mut raw_bytes, shown.to_string());
                        return !snap.incomplete;
                    }
                };
                for (name, data) in values {
                    if name_wanted(names, &name) {
                        if snap.entries.len() >= MAX_ENTRIES {
                            snap.incomplete = true;
                            return false;
                        }
                        let value_name = if name.is_empty() {
                            "(Default)".to_string()
                        } else {
                            name
                        };
                        let data = truncate_value(&data);
                        let size = shown.len()
                            + value_name.len()
                            + data.len()
                            + s.category.len()
                            + sid.map_or(0, str::len);
                        if size > MAX_BASELINE_BYTES.saturating_sub(raw_bytes) {
                            snap.incomplete = true;
                            return false;
                        }
                        raw_bytes += size;
                        snap.entries.insert(
                            EntryKey {
                                category: s.category,
                                user_sid: sid.map(str::to_string),
                                key_path: shown.to_string(),
                                value_name,
                            },
                            data,
                        );
                    }
                }
                true
            };
            match s.shape {
                Shape::Values(_) => {
                    read(&read_path, &shown);
                }
                Shape::Children { child, .. } => {
                    let children = match reader.checked_subkeys(root, &read_path) {
                        Ok(children) => children,
                        Err(_) => {
                            mark_unavailable(&mut snap, &mut raw_bytes, shown.clone());
                            continue;
                        }
                    };
                    for sub in children {
                        let (p, d) = match child {
                            Some(c) => (
                                format!("{read_path}\\{sub}\\{c}"),
                                format!("{shown}\\{sub}\\{c}"),
                            ),
                            None => (format!("{read_path}\\{sub}"), format!("{shown}\\{sub}")),
                        };
                        if !read(&p, &d) {
                            break;
                        }
                    }
                }
            }
        }
    }
    if snap.incomplete {
        return snap;
    }
    // A hive can unload during a poll. Discard its partial read and retain
    // the last complete view rather than interpreting missing keys as deletes.
    match reader.checked_subkeys(RegRoot::Users, "") {
        Ok(loaded) => {
            snap.users.retain(|sid| loaded.contains(sid));
            for hive in hives.iter().filter(|hive| !loaded.contains(hive)) {
                mark_unavailable(&mut snap, &mut raw_bytes, format!("HKU\\{hive}"));
            }
        }
        Err(_) => {
            snap.users.clear();
            mark_unavailable(&mut snap, &mut raw_bytes, "HKU".into());
        }
    }
    let failed_index = prefix_index(&snap.unavailable);
    snap.entries.retain(|key, _| {
        !unavailable(&failed_index, &key.key_path)
            && key
                .user_sid
                .as_ref()
                .is_none_or(|sid| snap.users.contains(sid))
    });
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
    let old_unknown = prefix_index(&old.unavailable);
    let new_failed = prefix_index(&new.unavailable);
    let comparable = |k: &EntryKey| {
        !unavailable(&old_unknown, &k.key_path)
            && !unavailable(&new_failed, &k.key_path)
            && k.user_sid
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

#[derive(Clone, Default)]
struct Bucket {
    start: Option<Instant>,
    used: u32,
    suppressed: u32,
}

/// Per-category event budget. A noisy category (an installer writing hundreds
/// of services) cannot starve a quiet, high-value one (IFEO, Winlogon), and
/// what is dropped is reported as one summary instead of silently lost.
#[derive(Clone, Default)]
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
        pub failed_values: BTreeSet<(RegRoot, String)>,
        pub all_values_unreadable: bool,
        pub failed_subkeys: BTreeSet<(RegRoot, String)>,
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
        fn checked_values(&self, root: RegRoot, path: &str) -> Result<Vec<(String, String)>, u32> {
            if self.all_values_unreadable || self.failed_values.contains(&(root, path.into())) {
                Err(5)
            } else {
                Ok(self.values(root, path))
            }
        }
        fn checked_subkeys(&self, root: RegRoot, path: &str) -> Result<Vec<String>, u32> {
            if self.failed_subkeys.contains(&(root, path.into())) {
                Err(5)
            } else {
                Ok(self.subkeys(root, path))
            }
        }
    }

    const SID: &str = "S-1-5-21-1-2-3-1001";
    const RUN: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";

    fn user_run(reg: &mut FakeReg, name: &str, data: &str) {
        reg.set(RegRoot::Users, &format!("{SID}\\{RUN}"), name, data);
    }

    #[test]
    fn persisted_baseline_detects_offline_modifications() {
        let mut reg = FakeReg::default();
        user_run(&mut reg, "persist", "before");
        let saved = encode_baseline(&snapshot(&reg, SPECS)).unwrap();
        user_run(&mut reg, "persist", "after");
        let baseline = decode_baseline(&saved).unwrap();
        let changes = diff(&baseline, &snapshot(&reg, SPECS));
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].old.as_deref(), Some("before"));
        assert_eq!(changes[0].new.as_deref(), Some("after"));
    }

    #[test]
    fn unloaded_hives_keep_baseline_until_reloaded() {
        let mut reg = FakeReg::default();
        user_run(&mut reg, "persist", "before");
        let previous = snapshot(&reg, SPECS);
        let absent = snapshot(&FakeReg::default(), SPECS);
        assert!(diff(&previous, &absent).is_empty());
        let retained = retain_unavailable(&previous, absent).unwrap();
        user_run(&mut reg, "persist", "after");
        assert_eq!(diff(&retained, &snapshot(&reg, SPECS)).len(), 1);
    }

    #[test]
    fn corrupt_and_oversized_baselines_are_rejected() {
        assert!(decode_baseline(b"broken").is_err());
        assert!(decode_baseline(br#"{"version":999,"users":[],"entries":[]}"#).is_err());
        assert!(decode_baseline(&vec![b' '; MAX_BASELINE_BYTES + 1]).is_err());
    }

    #[test]
    fn unreadable_keys_do_not_delete_and_recovery_detects_change() {
        let mut reg = FakeReg::default();
        reg.set(
            RegRoot::LocalMachine,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "a",
            "old",
        );
        let old = snapshot(&reg, SPECS);
        let mut failed = Snapshot::default();
        failed
            .unavailable
            .insert(r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run".into());
        assert!(diff(&old, &failed).is_empty());
        let retained = retain_unavailable(&old, failed).unwrap();
        reg.set(
            RegRoot::LocalMachine,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "a",
            "changed",
        );
        assert_eq!(diff(&retained, &snapshot(&reg, SPECS)).len(), 1);
    }

    #[test]
    fn persisted_baseline_file_is_bounded_and_missing_is_first_install() {
        let directory =
            std::env::temp_dir().join(format!("trapd_registry_baseline_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("baseline.json");
        assert!(load_baseline(&path).unwrap().is_none());
        let mut reg = FakeReg::default();
        user_run(&mut reg, "persist", "before");
        crate::paths::write_atomic(
            &path,
            &encode_baseline(&snapshot(&reg, SPECS)).unwrap(),
            0o600,
        )
        .unwrap();
        assert_eq!(load_baseline(&path).unwrap().unwrap().entries.len(), 1);
        std::fs::write(&path, "invalid").unwrap();
        assert!(load_baseline(&path).is_err());
        std::fs::File::create(&path)
            .unwrap()
            .set_len(MAX_BASELINE_BYTES as u64 + 1)
            .unwrap();
        assert!(load_baseline(&path).is_err());
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn numbered_control_sets_classify_native_registry_events() {
        assert_eq!(
            category_for_path(r"HKLM\SYSTEM\ControlSet001\Services\demo", "ImagePath"),
            Some("service")
        );
        assert_eq!(
            category_for_path(r"HKLM\SYSTEM\ControlSetXYZ\Services\demo", "ImagePath"),
            None
        );
    }

    #[test]
    fn registry_path_category_matches_shapes_and_names() {
        assert_eq!(
            category_for_path(r"HKLM\system\CurrentControlSet\Services\demo", "ImagePath"),
            Some("service")
        );
        assert_eq!(
            category_for_path(
                r"HKLM\SYSTEM\CurrentControlSet\Services\demo\Parameters",
                "ServiceDll"
            ),
            Some("service")
        );
        assert_eq!(
            category_for_path(r"HKLM\SYSTEM\CurrentControlSet\Services\demo", "Unrelated"),
            None
        );
        assert_eq!(
            category_for_path(
                r"HKLM\SYSTEM\CurrentControlSet\Services\demo\Other",
                "ImagePath"
            ),
            None
        );
        assert_eq!(
            category_for_path(
                &format!(r"HKU\{SID}_Classes\CLSID\{{abc}}\InprocServer32"),
                ""
            ),
            Some("com_hijack")
        );
        assert_eq!(
            category_for_path(&format!(r"HKU\{SID}\{RUN}"), "tool"),
            Some("run_key")
        );
    }

    #[test]
    fn failed_registry_reads_retain_values_without_false_deletes() {
        let mut reg = FakeReg::default();
        let machine_run = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
        reg.set(RegRoot::LocalMachine, machine_run, "a", "old");
        user_run(&mut reg, "b", "old");
        let previous = snapshot(&reg, SPECS);
        reg.failed_values
            .insert((RegRoot::LocalMachine, machine_run.into()));
        reg.failed_subkeys.insert((RegRoot::Users, String::new()));
        let failed = snapshot(&reg, SPECS);
        assert!(diff(&previous, &failed).is_empty());
        let retained = retain_unavailable(&previous, failed).unwrap();
        assert_eq!(retained.entries, previous.entries);
        reg.failed_values.clear();
        reg.failed_subkeys.clear();
        reg.set(RegRoot::LocalMachine, machine_run, "a", "new");
        assert_eq!(diff(&retained, &snapshot(&reg, SPECS)).len(), 1);
    }

    #[test]
    fn oversized_registry_names_cannot_grow_snapshot_past_byte_budget() {
        let mut reg = FakeReg::default();
        reg.values.insert(
            (
                RegRoot::LocalMachine,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run".into(),
            ),
            (0..3000)
                .map(|i| (format!("{i}{}", "x".repeat(8192)), "value".into()))
                .collect(),
        );
        let captured = snapshot(&reg, SPECS);
        assert!(captured.incomplete);
        assert!(captured.entries.len() < 3000);
    }

    #[test]
    fn incomplete_snapshots_cannot_replace_baseline() {
        let mut reg = FakeReg::default();
        reg.values.insert(
            (
                RegRoot::LocalMachine,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run".into(),
            ),
            (0..=MAX_ENTRIES)
                .map(|i| (format!("a{i}"), "x".into()))
                .collect(),
        );
        let oversized = snapshot(&reg, SPECS);
        assert!(oversized.incomplete);
        assert_eq!(oversized.entries.len(), MAX_ENTRIES);
        assert!(retain_unavailable(&Snapshot::default(), oversized.clone()).is_err());
        assert!(encode_baseline(&oversized).is_err());
    }

    #[test]
    fn persisted_baseline_rejects_invalid_fields_and_duplicate_entries() {
        let mut reg = FakeReg::default();
        user_run(&mut reg, "persist", "before");
        let snapshot = snapshot(&reg, SPECS);
        let encoded = encode_baseline(&snapshot).unwrap();
        let mut saved: SavedBaseline = serde_json::from_slice(&encoded).unwrap();
        saved.entries.push(SavedEntry {
            category: "run_key".into(),
            user_sid: Some(SID.into()),
            key_path: format!(r"HKU\{SID}\{RUN}"),
            value_name: "persist".into(),
            value: "different".into(),
        });
        assert!(decode_baseline(&serde_json::to_vec(&saved).unwrap()).is_err());
        let mut invalid = snapshot;
        invalid
            .entries
            .values_mut()
            .for_each(|value| *value = "a".repeat(MAX_VALUE_CHARS + 1));
        assert!(encode_baseline(&invalid).is_err());
    }

    #[test]
    fn initially_unreadable_scope_gets_silent_baseline_after_restart_and_recovery() {
        let mut reg = FakeReg::default();
        let path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
        reg.set(RegRoot::LocalMachine, path, "preexisting", "old");
        reg.failed_values
            .insert((RegRoot::LocalMachine, path.into()));
        let initial = snapshot(&reg, SPECS);
        let initial = decode_baseline(&encode_baseline(&initial).unwrap()).unwrap();
        reg.failed_values.clear();
        let recovered = snapshot(&reg, SPECS);
        assert!(diff(&initial, &recovered).is_empty());
        let baseline = retain_unavailable(&initial, recovered).unwrap();
        reg.set(RegRoot::LocalMachine, path, "preexisting", "new");
        assert_eq!(diff(&baseline, &snapshot(&reg, SPECS)).len(), 1);
    }

    #[test]
    fn unknown_scope_does_not_expand_when_entire_user_root_is_unreadable() {
        let mut reg = FakeReg::default();
        user_run(&mut reg, "known", "old");
        let initial = snapshot(&reg, SPECS);
        assert!(initial
            .unavailable
            .iter()
            .any(|scope| scope.contains("_Classes")));
        reg.failed_subkeys.insert((RegRoot::Users, String::new()));
        let failed = retain_unavailable(&initial, snapshot(&reg, SPECS)).unwrap();
        assert!(!failed.unavailable.contains("HKU"));
        reg.failed_subkeys.clear();
        user_run(&mut reg, "known", "new");
        assert_eq!(diff(&failed, &snapshot(&reg, SPECS)).len(), 1);
    }

    #[test]
    fn persisted_baseline_reports_offline_create_and_delete() {
        let mut reg = FakeReg::default();
        user_run(&mut reg, "removed", "old");
        let baseline = decode_baseline(&encode_baseline(&snapshot(&reg, SPECS)).unwrap()).unwrap();
        reg.remove(RegRoot::Users, &format!(r"{SID}\{RUN}"), "removed");
        user_run(&mut reg, "added", "new");
        let changes = diff(&baseline, &snapshot(&reg, SPECS));
        assert_eq!(changes.len(), 2);
        assert!(changes
            .iter()
            .any(|change| matches!(change.action(), EventAction::Create)));
        assert!(changes
            .iter()
            .any(|change| matches!(change.action(), EventAction::Delete)));
    }

    #[test]
    fn encoded_baseline_size_is_bounded_after_json_escaping() {
        let mut reg = FakeReg::default();
        reg.values.insert(
            (
                RegRoot::LocalMachine,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run".into(),
            ),
            (0..1100)
                .map(|i| (format!("{i}{}", "\"".repeat(8192)), "x".into()))
                .collect(),
        );
        let captured = snapshot(&reg, SPECS);
        assert!(!captured.incomplete);
        assert!(encode_baseline(&captured).is_err());
    }

    #[test]
    fn previously_empty_user_hive_reports_offline_creation_after_unload_and_restart() {
        let mut reg = FakeReg::default();
        reg.set(RegRoot::Users, SID, "", "");
        let known_empty = snapshot(&reg, SPECS);
        assert!(known_empty.entries.is_empty());
        let unloaded =
            retain_unavailable(&known_empty, snapshot(&FakeReg::default(), SPECS)).unwrap();
        let restored = decode_baseline(&encode_baseline(&unloaded).unwrap()).unwrap();
        user_run(&mut reg, "offline", "new");
        let changes = diff(&restored, &snapshot(&reg, SPECS));
        assert_eq!(changes.len(), 1);
        assert!(matches!(changes[0].action(), EventAction::Create));
    }

    #[test]
    fn unread_classes_hive_keeps_unknown_marker_across_logoff_and_restart() {
        let mut reg = FakeReg::default();
        reg.set(RegRoot::Users, SID, "", "");
        let initial = snapshot(&reg, SPECS);
        let marker = format!(r"HKU\{SID}_Classes");
        assert!(initial.unavailable.contains(&marker));
        let unloaded = retain_unavailable(&initial, snapshot(&FakeReg::default(), SPECS)).unwrap();
        let restored = decode_baseline(&encode_baseline(&unloaded).unwrap()).unwrap();
        assert!(restored.unavailable.contains(&marker));
        reg.set(
            RegRoot::Users,
            &format!(r"{SID}_Classes\CLSID\{{known}}\InprocServer32"),
            "",
            "existing.dll",
        );
        assert!(diff(&restored, &snapshot(&reg, SPECS)).is_empty());
    }

    #[test]
    fn unreadable_child_scopes_are_bounded_while_scanning() {
        for suffix in ["x".repeat(240), String::new()] {
            let mut reg = FakeReg {
                all_values_unreadable: true,
                ..FakeReg::default()
            };
            for index in 0..7 {
                let sid = format!("S-1-5-21-1-2-3-{}", 1000 + index);
                reg.set(RegRoot::Users, &sid, "", "");
                reg.set(RegRoot::Users, &format!("{sid}_Classes"), "", "");
                reg.keys.insert(
                    (RegRoot::Users, format!(r"{sid}_Classes\CLSID")),
                    (0..8192).map(|index| format!("{index}{suffix}")).collect(),
                );
            }
            let captured = snapshot(&reg, SPECS);
            assert!(captured.incomplete);
            assert!(captured.unavailable.len() <= MAX_ENTRIES);
            assert!(
                captured.unavailable.iter().map(String::len).sum::<usize>() <= MAX_BASELINE_BYTES
            );
            if suffix.is_empty() {
                assert_eq!(captured.unavailable.len(), MAX_ENTRIES);
            }
        }
    }

    #[test]
    fn unavailable_index_matches_case_insensitively_on_path_boundaries() {
        let index = prefix_index(&BTreeSet::from([r"HKLM\Software\Run".into()]));
        assert!(unavailable(&index, r"hklm\SOFTWARE\run"));
        assert!(unavailable(&index, r"hklm\SOFTWARE\run\child"));
        assert!(!unavailable(&index, r"HKLM\Software\RunOnce"));
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
        // COM creation is observable only when the Classes hive was already
        // loaded at baseline; a newly loaded hive may contain old registrations.
        reg.set(RegRoot::Users, &format!("{SID}_Classes"), "", "");
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
