//! Kernel module monitoring.
//!
//! A loadable kernel module is the most direct way to own a Linux host, so the
//! module list is worth watching from more than one angle:
//!
//! * **`/proc/modules`** — the canonical list, and the one a rootkit unlinks
//!   itself from first, because that is what `lsmod` reads.
//! * **`/sys/module/<name>/`** — a separate sysfs tree that a module has to be
//!   removed from separately. Unlinking from one and not the other is the
//!   classic tell.
//! * **eBPF `module_load` sightings** — recorded below both, so a module that
//!   loaded and then removed itself from the lists leaves a trace anyway.
//! * **`/lib/modules/<release>/`** — where the distribution's modules live. A
//!   loaded module with no file there came from somewhere else.
//!
//! Load events themselves are already reported in real time by the eBPF
//! syscall collector, so this module deliberately does not duplicate them; it
//! covers the gaps — unload, concealment, provenance and the module tree.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde_json::json;

use super::kernel_view::normalize_module_name;
use super::{Confirmation, Finding};
use crate::schema::Severity;

/// Module names published by rootkits that have been seen in the wild. This is
/// only ever an *escalation* hint: a hit here raises an already-standalone
/// finding to certainty, and a miss changes nothing, so the list going stale
/// costs no coverage.
pub const KNOWN_ROOTKIT_MODULES: &[&str] = &[
    "diamorphine",
    "reptile",
    "reptile_module",
    "suterusu",
    "adore",
    "adore_ng",
    "knark",
    "enyelkm",
    "modhide",
    "kbeast",
    "sebek",
    "phalanx",
    "rkit",
    "nurupo",
    "puszek",
    "brootus",
    "lilyofthevalley",
    "vlany",
    "rootkit",
];

/// A change touching more files than this is a kernel package being installed,
/// not a rootkit dropping a module. Reported once, quietly, instead of as a
/// storm of individual findings.
const TREE_BULK_THRESHOLD: usize = 20;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcModule {
    pub name: String,
    pub size: u64,
    pub state: String,
    /// Taint flags from `/proc/modules`; `E` means an unsigned module.
    pub taint: String,
}

impl ProcModule {
    fn unsigned(&self) -> bool {
        self.taint.contains('E')
    }
}

#[derive(Debug, Default, Clone)]
pub struct ModuleViews {
    pub proc_modules: BTreeMap<String, ProcModule>,
    /// Loadable modules present in `/sys/module` (built-ins excluded).
    pub sysfs_loadable: BTreeSet<String>,
    /// Modules the eBPF tracer saw being loaded.
    pub kernel_loaded: BTreeSet<String>,
    /// Module names with a file in the distribution's module tree.
    pub on_disk: BTreeSet<String>,
    /// False when the module tree could not be read, which makes the
    /// provenance check unanswerable rather than negative.
    pub on_disk_readable: bool,
}

/// Cross-sweep state: what the previous sweep saw, so unloads and first
/// sightings can be recognised.
#[derive(Debug, Default)]
pub struct ModuleHistory {
    pub previously_loaded: Option<BTreeSet<String>>,
    /// Every module ever seen in `/proc/modules`. A module that was once listed
    /// and is now gone was unloaded; only a module that was *never* listed
    /// despite a load sighting is a concealment candidate.
    pub ever_listed: BTreeSet<String>,
}

pub fn analyze(views: &ModuleViews, history: &mut ModuleHistory) -> Vec<Finding> {
    let mut out = Vec::new();
    let listed: BTreeSet<String> = views.proc_modules.keys().cloned().collect();

    // Unlinked from /proc/modules but still present in sysfs.
    for name in views.sysfs_loadable.difference(&listed) {
        out.push(Finding {
            rule_id: "rootkit.module_hidden_from_proc_modules",
            title: "Kernel module present in /sys/module but absent from /proc/modules",
            confirmation: Confirmation::Corroborate,
            severity: Severity::Critical,
            confidence: 90,
            mitre_tactic: "TA0003 Persistence",
            mitre_technique: "T1547.006",
            subject: format!("module:{name}"),
            detail: format!(
                "Module {name} has a live /sys/module entry but does not appear in \
                 /proc/modules. Removing itself from the module list while sysfs still \
                 carries it is how a kernel rootkit hides from lsmod."
            ),
            evidence: json!({
                "module": name,
                "views": { "sysfs": true, "proc_modules": false },
            }),
        });
    }

    // Seen loading from below, never listed since.
    for name in &views.kernel_loaded {
        if listed.contains(name)
            || views.sysfs_loadable.contains(name)
            || history.ever_listed.contains(name)
        {
            continue;
        }
        out.push(Finding {
            rule_id: "rootkit.module_hidden_after_load",
            title: "Kernel module observed loading never appeared in the module lists",
            confirmation: Confirmation::Corroborate,
            severity: Severity::High,
            confidence: 70,
            mitre_tactic: "TA0003 Persistence",
            mitre_technique: "T1547.006",
            subject: format!("module:{name}"),
            detail: format!(
                "The eBPF module tracer saw {name} load, but it has never appeared in \
                 /proc/modules or /sys/module since. A module that unloads cleanly is \
                 normally listed at least once first."
            ),
            evidence: json!({
                "module": name,
                "views": { "ebpf": true, "proc_modules": false, "sysfs": false },
            }),
        });
    }

    for (name, module) in &views.proc_modules {
        if module.unsigned() {
            out.push(Finding {
                rule_id: "rootkit.module_unsigned",
                title: "Unsigned kernel module loaded",
                confirmation: Confirmation::Corroborate,
                severity: Severity::Medium,
                confidence: 45,
                mitre_tactic: "TA0003 Persistence",
                mitre_technique: "T1547.006",
                subject: format!("module:{name}"),
                detail: format!(
                    "Module {name} is loaded with the E taint flag, meaning the kernel \
                     accepted it without a valid signature. Out-of-tree drivers built \
                     locally (DKMS) look the same, so this is context, not a verdict."
                ),
                evidence: json!({ "module": name, "taint": module.taint, "state": module.state }),
            });
        }

        if views.on_disk_readable && !views.on_disk.contains(name) {
            out.push(Finding {
                rule_id: "rootkit.module_not_in_module_tree",
                title: "Loaded kernel module has no file in the distribution module tree",
                confirmation: Confirmation::Corroborate,
                severity: Severity::High,
                confidence: 70,
                mitre_tactic: "TA0003 Persistence",
                mitre_technique: "T1547.006",
                subject: format!("module:{name}"),
                detail: format!(
                    "Module {name} is loaded but no matching .ko file exists under the \
                     running kernel's module tree, so it was loaded from somewhere else."
                ),
                evidence: json!({ "module": name, "size": module.size, "state": module.state }),
            });
        }
    }

    // Unloads. Loads are already reported in real time by the eBPF tracer, so
    // reporting them again here would only duplicate them.
    if let Some(previous) = &history.previously_loaded {
        for name in previous.difference(&listed) {
            out.push(Finding {
                rule_id: "rootkit.module_unloaded",
                title: "Kernel module unloaded",
                confirmation: Confirmation::Immediate,
                severity: Severity::Low,
                confidence: 30,
                mitre_tactic: "TA0005 Defense Evasion",
                mitre_technique: "T1547.006",
                subject: format!("module:{name}"),
                detail: format!(
                    "Module {name} was loaded at the previous sweep and is no longer in \
                     /proc/modules."
                ),
                evidence: json!({ "module": name }),
            });
        }
    }

    let all_known: BTreeSet<&String> = listed
        .iter()
        .chain(views.sysfs_loadable.iter())
        .chain(views.kernel_loaded.iter())
        .collect();
    for name in all_known {
        if !KNOWN_ROOTKIT_MODULES.contains(&name.as_str()) {
            continue;
        }
        out.push(Finding {
            rule_id: "rootkit.known_rootkit_module",
            title: "Module name matches a known rootkit",
            confirmation: Confirmation::Corroborate,
            severity: Severity::Critical,
            confidence: 95,
            mitre_tactic: "TA0003 Persistence",
            mitre_technique: "T1547.006",
            subject: format!("module:{name}"),
            detail: format!("Module {name} matches a publicly known Linux rootkit module."),
            evidence: json!({ "module": name }),
        });
    }

    history.ever_listed.extend(listed.iter().cloned());
    history.previously_loaded = Some(listed);
    out
}

// ── Module tree ─────────────────────────────────────────────────────────────

/// Path → (size, mtime) for every module file in the tree. Size and mtime
/// rather than a digest: the tree holds thousands of files and hashing all of
/// them on a schedule would cost more than the check is worth.
pub type TreeSnapshot = BTreeMap<String, (u64, i64)>;

pub fn analyze_tree(previous: &TreeSnapshot, current: &TreeSnapshot) -> Vec<Finding> {
    let mut added = Vec::new();
    let mut modified = Vec::new();
    let mut removed = Vec::new();

    for (path, meta) in current {
        match previous.get(path) {
            None => added.push(path.clone()),
            Some(before) if before != meta => modified.push(path.clone()),
            Some(_) => {}
        }
    }
    for path in previous.keys() {
        if !current.contains_key(path) {
            removed.push(path.clone());
        }
    }

    let total = added.len() + modified.len() + removed.len();
    if total == 0 {
        return Vec::new();
    }

    if total > TREE_BULK_THRESHOLD {
        return vec![Finding {
            rule_id: "rootkit.module_tree_bulk_change",
            title: "Kernel module tree changed in bulk",
            confirmation: Confirmation::Immediate,
            severity: Severity::Low,
            confidence: 30,
            mitre_tactic: "TA0003 Persistence",
            mitre_technique: "T1547.006",
            subject: "module_tree".to_string(),
            detail: format!(
                "{total} module files changed at once ({} added, {} modified, {} removed), \
                 which is the shape of a kernel package being installed rather than a \
                 single module being planted.",
                added.len(),
                modified.len(),
                removed.len()
            ),
            evidence: json!({
                "added": added.len(),
                "modified": modified.len(),
                "removed": removed.len(),
            }),
        }];
    }

    let mut out = Vec::new();
    for (paths, change, severity, confidence) in [
        (added, "added", Severity::Medium, 60),
        (modified, "modified", Severity::Medium, 55),
        (removed, "removed", Severity::Low, 35),
    ] {
        for path in paths {
            out.push(Finding {
                rule_id: "rootkit.module_file_changed",
                title: "Kernel module file changed outside a package update",
                confirmation: Confirmation::Immediate,
                severity,
                confidence,
                mitre_tactic: "TA0003 Persistence",
                mitre_technique: "T1547.006",
                subject: path.clone(),
                detail: format!(
                    "Module file {path} was {change} in the running kernel's module tree \
                     without the bulk pattern of a package update."
                ),
                evidence: json!({ "path": path, "change": change }),
            });
        }
    }
    out
}

// ── Parsing ─────────────────────────────────────────────────────────────────

/// Parse `/proc/modules`: `name size refcount deps state base_addr [taint]`.
pub fn parse_proc_modules(content: &str) -> BTreeMap<String, ProcModule> {
    let mut out = BTreeMap::new();
    for line in content.lines() {
        let mut fields = line.split_whitespace();
        let Some(raw_name) = fields.next() else {
            continue;
        };
        let name = normalize_module_name(raw_name);
        let size = fields.next().and_then(|s| s.parse().ok()).unwrap_or(0);
        let _refcount = fields.next();
        let _deps = fields.next();
        let state = fields.next().unwrap_or("Unknown").to_string();
        let _base = fields.next();
        let taint = fields
            .next()
            .unwrap_or("")
            .trim_matches(|c| c == '(' || c == ')')
            .to_string();
        out.insert(
            name.clone(),
            ProcModule {
                name,
                size,
                state,
                taint,
            },
        );
    }
    out
}

/// Module name for a file in the module tree, unwrapping the compression
/// suffixes distributions use (`.ko`, `.ko.xz`, `.ko.zst`, `.ko.gz`).
pub fn module_name_from_file(path: &Path) -> Option<String> {
    let name = path.file_name()?.to_str()?;
    let stem = match name.rsplit_once('.') {
        Some((head, "xz" | "zst" | "gz" | "bz2" | "lz4")) => head,
        _ => name,
    };
    stem.strip_suffix(".ko").map(normalize_module_name)
}

// ── Host collection ─────────────────────────────────────────────────────────

/// Release string of the running kernel, which names its module directory.
fn kernel_release() -> Option<String> {
    std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Loadable modules in `/sys/module`.
///
/// The directory also contains every module compiled *into* the kernel, which
/// has no `/proc/modules` entry and would otherwise look like hundreds of
/// hidden modules. Only a loadable module gets an `initstate` file, so that is
/// the discriminator.
fn sysfs_loadable_modules() -> BTreeSet<String> {
    let Ok(entries) = std::fs::read_dir("/sys/module") else {
        return BTreeSet::new();
    };
    entries
        .flatten()
        .filter(|e| e.path().join("initstate").exists())
        .filter_map(|e| e.file_name().to_str().map(normalize_module_name))
        .collect()
}

/// Per-module taint from sysfs, which is more precise than the `/proc/modules`
/// taint column when both are present.
fn apply_sysfs_taint(modules: &mut BTreeMap<String, ProcModule>) {
    for (name, module) in modules.iter_mut() {
        if let Ok(taint) = std::fs::read_to_string(format!("/sys/module/{name}/taint")) {
            let taint = taint.trim();
            if !taint.is_empty() {
                module.taint = taint.to_string();
            }
        }
    }
}

fn scan_module_tree(release: &str) -> Option<(BTreeSet<String>, TreeSnapshot)> {
    let root = format!("/lib/modules/{release}");
    if !Path::new(&root).is_dir() {
        return None;
    }
    let mut names = BTreeSet::new();
    let mut tree = TreeSnapshot::new();
    for entry in walkdir::WalkDir::new(&root)
        .follow_links(false)
        .into_iter()
        .filter_map(Result::ok)
    {
        if !entry.file_type().is_file() {
            continue;
        }
        let Some(name) = module_name_from_file(entry.path()) else {
            continue;
        };
        names.insert(name);
        if let Ok(meta) = entry.metadata() {
            use std::os::unix::fs::MetadataExt;
            tree.insert(
                entry.path().to_string_lossy().into_owned(),
                (meta.len(), meta.mtime()),
            );
        }
    }
    Some((names, tree))
}

/// Read every module view from this host.
pub fn gather(kernel_loaded: &[String]) -> (ModuleViews, TreeSnapshot) {
    let mut proc_modules =
        parse_proc_modules(&std::fs::read_to_string("/proc/modules").unwrap_or_default());
    apply_sysfs_taint(&mut proc_modules);

    let (on_disk, tree, on_disk_readable) =
        match kernel_release().and_then(|r| scan_module_tree(&r)) {
            Some((names, tree)) => (names, tree, true),
            None => (BTreeSet::new(), TreeSnapshot::new(), false),
        };

    (
        ModuleViews {
            proc_modules,
            sysfs_loadable: sysfs_loadable_modules(),
            kernel_loaded: kernel_loaded.iter().cloned().collect(),
            on_disk,
            on_disk_readable,
        },
        tree,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn views(listed: &[(&str, &str)], sysfs: &[&str], on_disk: &[&str]) -> ModuleViews {
        ModuleViews {
            proc_modules: listed
                .iter()
                .map(|(name, taint)| {
                    (
                        name.to_string(),
                        ProcModule {
                            name: name.to_string(),
                            size: 16384,
                            state: "Live".into(),
                            taint: taint.to_string(),
                        },
                    )
                })
                .collect(),
            sysfs_loadable: sysfs.iter().map(|s| s.to_string()).collect(),
            on_disk: on_disk.iter().map(|s| s.to_string()).collect(),
            on_disk_readable: true,
            ..Default::default()
        }
    }

    fn rule_ids(findings: &[Finding]) -> Vec<&str> {
        findings.iter().map(|f| f.rule_id).collect()
    }

    #[test]
    fn parses_proc_modules_including_the_taint_column() {
        let parsed = parse_proc_modules(
            "nf_tables 274432 1 - Live 0x0000000000000000\n\
             vboxdrv 663552 3 - Live 0x0000000000000000 (OE)\n",
        );
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed["nf_tables"].size, 274432);
        assert!(!parsed["nf_tables"].unsigned());
        assert_eq!(parsed["vboxdrv"].taint, "OE");
        assert!(parsed["vboxdrv"].unsigned());
    }

    #[test]
    fn module_names_are_normalised_when_parsed() {
        let parsed = parse_proc_modules("snd-hda-intel 1024 0 - Live 0x0\n");
        assert!(parsed.contains_key("snd_hda_intel"));
    }

    #[test]
    fn a_module_in_sysfs_but_not_proc_modules_is_hidden() {
        let mut history = ModuleHistory::default();
        let found = analyze(
            &views(&[], &["diamorphine"], &["diamorphine"]),
            &mut history,
        );
        assert!(rule_ids(&found).contains(&"rootkit.module_hidden_from_proc_modules"));
        assert!(rule_ids(&found).contains(&"rootkit.known_rootkit_module"));
    }

    #[test]
    fn an_agreeing_module_list_produces_nothing() {
        let mut history = ModuleHistory::default();
        let found = analyze(
            &views(&[("nf_tables", "")], &["nf_tables"], &["nf_tables"]),
            &mut history,
        );
        assert!(found.is_empty(), "got {:?}", rule_ids(&found));
    }

    #[test]
    fn built_in_modules_cannot_be_reported_as_hidden() {
        // Built-ins are filtered out of the sysfs view at gather time, so they
        // never reach the difference; this pins the expectation.
        let mut history = ModuleHistory::default();
        let found = analyze(&views(&[("ext4", "")], &[], &["ext4"]), &mut history);
        assert!(found.is_empty(), "got {:?}", rule_ids(&found));
    }

    #[test]
    fn an_unsigned_module_is_context_not_a_verdict() {
        let mut history = ModuleHistory::default();
        let found = analyze(
            &views(&[("vboxdrv", "OE")], &[], &["vboxdrv"]),
            &mut history,
        );
        assert_eq!(rule_ids(&found), vec!["rootkit.module_unsigned"]);
        assert!(matches!(found[0].severity, Severity::Medium));
        assert!(found[0].confidence < 50);
    }

    #[test]
    fn a_module_with_no_file_in_the_tree_is_reported() {
        let mut history = ModuleHistory::default();
        let found = analyze(&views(&[("mystery", "")], &["mystery"], &[]), &mut history);
        assert_eq!(rule_ids(&found), vec!["rootkit.module_not_in_module_tree"]);
    }

    #[test]
    fn an_unreadable_module_tree_does_not_accuse_every_module() {
        let mut v = views(&[("nf_tables", "")], &["nf_tables"], &[]);
        v.on_disk_readable = false;
        let mut history = ModuleHistory::default();
        assert!(analyze(&v, &mut history).is_empty());
    }

    #[test]
    fn an_unload_is_reported_but_a_load_is_left_to_the_ebpf_tracer() {
        let mut history = ModuleHistory::default();
        analyze(
            &views(
                &[("nf_tables", ""), ("dummy", "")],
                &[],
                &["nf_tables", "dummy"],
            ),
            &mut history,
        );
        let found = analyze(
            &views(
                &[("nf_tables", ""), ("br_netfilter", "")],
                &[],
                &["nf_tables", "br_netfilter"],
            ),
            &mut history,
        );
        let ids = rule_ids(&found);
        assert_eq!(ids, vec!["rootkit.module_unloaded"]);
        assert_eq!(found[0].subject, "module:dummy");
    }

    #[test]
    fn a_module_that_was_listed_before_is_an_unload_not_concealment() {
        let mut history = ModuleHistory::default();
        let mut v = views(&[("dkms_thing", "")], &[], &["dkms_thing"]);
        v.kernel_loaded = ["dkms_thing".to_string()].into_iter().collect();
        analyze(&v, &mut history);

        let mut gone = views(&[], &[], &["dkms_thing"]);
        gone.kernel_loaded = ["dkms_thing".to_string()].into_iter().collect();
        let found = analyze(&gone, &mut history);
        let ids = rule_ids(&found);
        assert!(ids.contains(&"rootkit.module_unloaded"));
        assert!(
            !ids.contains(&"rootkit.module_hidden_after_load"),
            "a module that was once listed then removed was unloaded, not hidden"
        );
    }

    #[test]
    fn a_load_sighting_never_confirmed_by_either_list_is_reported() {
        let mut v = views(&[], &[], &[]);
        v.on_disk_readable = false;
        v.kernel_loaded = ["ghost".to_string()].into_iter().collect();
        let mut history = ModuleHistory::default();
        assert_eq!(
            rule_ids(&analyze(&v, &mut history)),
            vec!["rootkit.module_hidden_after_load"]
        );
    }

    #[test]
    fn module_file_names_unwrap_compression_suffixes() {
        assert_eq!(
            module_name_from_file(Path::new("/lib/modules/6.1/kernel/fs/ext4/ext4.ko.zst")),
            Some("ext4".into())
        );
        assert_eq!(
            module_name_from_file(Path::new("snd-hda-intel.ko")),
            Some("snd_hda_intel".into())
        );
        assert_eq!(module_name_from_file(Path::new("modules.dep")), None);
    }

    #[test]
    fn a_single_planted_module_file_is_reported_individually() {
        let previous = TreeSnapshot::new();
        let mut current = TreeSnapshot::new();
        current.insert("/lib/modules/6.1/extra/evil.ko".into(), (4096, 100));
        let found = analyze_tree(&previous, &current);
        assert_eq!(rule_ids(&found), vec!["rootkit.module_file_changed"]);
    }

    #[test]
    fn a_kernel_package_update_collapses_into_one_quiet_finding() {
        let previous = TreeSnapshot::new();
        let current: TreeSnapshot = (0..500)
            .map(|i| (format!("/lib/modules/6.1/kernel/m{i}.ko"), (4096, 100)))
            .collect();
        let found = analyze_tree(&previous, &current);
        assert_eq!(rule_ids(&found), vec!["rootkit.module_tree_bulk_change"]);
        assert!(matches!(found[0].severity, Severity::Low));
    }

    #[test]
    fn an_unchanged_module_tree_produces_nothing() {
        let mut snapshot = TreeSnapshot::new();
        snapshot.insert("/lib/modules/6.1/kernel/ext4.ko".into(), (4096, 100));
        assert!(analyze_tree(&snapshot, &snapshot).is_empty());
    }
}
