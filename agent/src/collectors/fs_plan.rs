//! Turns a stream of Windows file-change notifications into the actions the
//! collector must take — telemetry, ransomware indicators, agent-tamper — as a
//! pure, deterministic planner.
//!
//! The Windows collector owns only the I/O (watching directories, reading a
//! file for entropy, sending events). *What a change means* lives here, so the
//! rules are unit-tested on every CI host instead of only on a Windows runner,
//! and they build on the same heuristics the Linux collector uses
//! ([`super::fs_heuristics`]).

// Only the Windows collector drives the planner; the logic is compiled (and
// tested) everywhere.
#![cfg_attr(not(windows), allow(dead_code))]

use std::time::{Duration, Instant};

use super::fs_heuristics::{
    is_compressed_by_nature, is_expected_self_write, CheckThrottle, Coalescer, MassModification,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Change {
    Created,
    Modified,
    /// Attribute / security change: telemetry, never a content signal.
    Attrib,
    Deleted,
    RenamedFrom,
    RenamedTo,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Action {
    /// Plain telemetry for a watched path.
    Generic { path: String, change: Change },
    /// A change inside the agent's own configuration directory.
    Tamper { path: String, action: &'static str },
    /// A file appeared under a known ransomware extension.
    RansomExtension { path: String },
    /// Read the file and evaluate its entropy (I/O: done by the collector).
    EntropyCheck { path: String },
    /// Many distinct files changed in a short window.
    WriteRate { rate: usize },
    /// A file in a backup location was removed or moved.
    BackupDeletion { path: String },
}

/// Watched locations, already lower-cased with `\` separators and a trailing
/// separator (see [`normalise_root`]).
#[derive(Default, Clone)]
pub struct Roots {
    pub generic: Vec<String>,
    pub ransom: Vec<String>,
    pub backup: Vec<String>,
    pub tamper: Vec<String>,
}

/// Lower-case, `\`-separated form used for every comparison. Windows paths are
/// case-insensitive and tools mix `/` and `\`.
pub fn normalise(path: &str) -> String {
    let mut p = path.replace('/', "\\").to_ascii_lowercase();
    if let Some(rest) = p.strip_prefix("\\\\?\\") {
        p = rest.to_string();
    }
    p
}

/// A root in comparison form: normalised and ending in exactly one `\`, so
/// `c:\users` can never match `c:\users-backup\x`.
pub fn normalise_root(root: &str) -> String {
    let mut r = normalise(root);
    while r.ends_with('\\') {
        r.pop();
    }
    r.push('\\');
    r
}

fn under(normalised_path: &str, roots: &[String]) -> bool {
    roots
        .iter()
        .any(|r| normalised_path.starts_with(r.as_str()))
}

/// Application caches and other churn that must not count as "user data being
/// modified". `AppData` is excluded except its `Temp`, the Windows analogue of
/// `/tmp` that ransomware loaders and droppers actually use.
pub fn is_user_noise(normalised_path: &str) -> bool {
    (normalised_path.contains("\\appdata\\")
        && !normalised_path.contains("\\appdata\\local\\temp\\"))
        || normalised_path.contains("\\node_modules\\")
        || normalised_path.contains("\\.git\\")
        || normalised_path.contains("\\$recycle.bin\\")
}

/// Never filtered or coalesced: persistence and name-resolution targets.
pub fn is_security_critical(normalised_path: &str) -> bool {
    normalised_path.contains("\\microsoft\\windows\\start menu\\programs\\startup\\")
        || normalised_path.ends_with("\\system32\\drivers\\etc\\hosts")
        || normalised_path.contains("\\windows\\system32\\tasks\\")
        || normalised_path.contains("\\programdata\\trapd\\")
}

/// Low-value write amplification (editor/Office lock files, caches, partial
/// downloads).
pub fn is_noisy(normalised_path: &str) -> bool {
    let name = normalised_path
        .rsplit('\\')
        .next()
        .unwrap_or(normalised_path);
    name.starts_with("~$")
        || name.ends_with(".tmp")
        || name.ends_with(".swp")
        || name.ends_with('~')
        || name.ends_with(".crdownload")
        || name.ends_with(".part")
        || matches!(name, "thumbs.db" | "desktop.ini")
        || normalised_path.contains("\\appdata\\local\\microsoft\\")
        || normalised_path.contains("\\appdata\\local\\google\\")
        || normalised_path.contains("\\appdata\\local\\packages\\")
}

pub struct Planner {
    roots: Roots,
    mass: MassModification,
    coalescer: Coalescer,
    throttle: CheckThrottle,
}

impl Planner {
    pub fn new(roots: Roots, now: Instant) -> Self {
        Self {
            roots,
            mass: MassModification::default(),
            coalescer: Coalescer::default(),
            // A modified file is read for entropy at most once per 5 s, and at
            // most 8 reads per second overall: enough for ransomware (which
            // rewrites many *different* files) without letting a busy build
            // directory turn the agent into a disk reader.
            throttle: CheckThrottle::new(Duration::from_secs(5), 8, now),
        }
    }

    pub fn set_generic_roots(&mut self, generic: Vec<String>) {
        self.roots.generic = generic;
    }

    pub fn plan(
        &mut self,
        change: Change,
        path: &str,
        now: Instant,
        process_uptime: Duration,
        update_in_flight: bool,
    ) -> Vec<Action> {
        let norm = normalise(path);
        let mut out = Vec::new();

        // Agent configuration: any foreign change is critical.
        if under(&norm, &self.roots.tamper) {
            let file = norm.rsplit('\\').next().unwrap_or(&norm);
            if !is_expected_self_write(file, process_uptime, update_in_flight) {
                let action = match change {
                    Change::Deleted | Change::RenamedFrom => "delete",
                    Change::Created | Change::RenamedTo => "create",
                    Change::Modified | Change::Attrib => "modify",
                };
                out.push(Action::Tamper {
                    path: path.to_string(),
                    action,
                });
            }
        }

        // Backup sabotage is evaluated on its own roots, not only user data.
        if matches!(change, Change::Deleted | Change::RenamedFrom)
            && under(&norm, &self.roots.backup)
        {
            out.push(Action::BackupDeletion {
                path: path.to_string(),
            });
        }

        // Ransomware behaviour on user data.
        if under(&norm, &self.roots.ransom) && !is_user_noise(&norm) {
            match change {
                Change::Created | Change::RenamedTo => {
                    if super::fs_heuristics::has_ransom_extension(&norm) {
                        out.push(Action::RansomExtension {
                            path: path.to_string(),
                        });
                    }
                }
                Change::Modified => {
                    if !is_compressed_by_nature(&norm) && self.throttle.allow(&norm, now) {
                        out.push(Action::EntropyCheck {
                            path: path.to_string(),
                        });
                    }
                    if let Some(rate) = self.mass.record(&norm, now) {
                        out.push(Action::WriteRate { rate });
                    }
                }
                _ => {}
            }
        }

        // Telemetry for explicitly watched paths, coalesced.
        if under(&norm, &self.roots.generic) {
            let key = match change {
                Change::Created | Change::RenamedTo => "create",
                Change::Deleted | Change::RenamedFrom => "delete",
                Change::Modified | Change::Attrib => "modify",
            };
            if !self.coalescer.suppress(
                &norm,
                key,
                is_security_critical(&norm),
                is_noisy(&norm),
                now,
            ) {
                out.push(Action::Generic {
                    path: path.to_string(),
                    change,
                });
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roots() -> Roots {
        Roots {
            generic: vec![normalise_root("C:\\Windows\\System32\\drivers\\etc")],
            ransom: vec![normalise_root("C:\\Users")],
            backup: vec![normalise_root("C:\\Backup")],
            tamper: vec![normalise_root("C:\\ProgramData\\TRAPD\\config")],
        }
    }

    fn plan(p: &mut Planner, c: Change, path: &str, t: Instant) -> Vec<Action> {
        p.plan(c, path, t, Duration::from_secs(3600), false)
    }

    #[test]
    fn roots_compare_on_directory_boundaries_and_ignore_case() {
        assert_eq!(normalise_root("C:/Users"), "c:\\users\\");
        let r = vec![normalise_root("C:\\Users")];
        assert!(under(&normalise("c:\\USERS\\Bob\\a.txt"), &r));
        assert!(under(&normalise("\\\\?\\C:\\Users\\Bob\\a.txt"), &r));
        assert!(!under(&normalise("C:\\Users-old\\a.txt"), &r));
    }

    #[test]
    fn a_ransom_extension_in_a_user_profile_is_flagged() {
        let t = Instant::now();
        let mut p = Planner::new(roots(), t);
        let a = plan(
            &mut p,
            Change::Created,
            "C:\\Users\\bob\\Documents\\q3.xlsx.LOCKED",
            t,
        );
        assert!(a
            .iter()
            .any(|x| matches!(x, Action::RansomExtension { .. })));
        let a = plan(
            &mut p,
            Change::RenamedTo,
            "C:\\Users\\bob\\Desktop\\a.lockbit",
            t,
        );
        assert!(a
            .iter()
            .any(|x| matches!(x, Action::RansomExtension { .. })));
        // The same name outside the watched profiles tree is not evaluated.
        assert!(plan(&mut p, Change::Created, "D:\\data\\a.locked", t).is_empty());
    }

    #[test]
    fn app_data_churn_is_ignored_but_temp_is_not() {
        let t = Instant::now();
        let mut p = Planner::new(roots(), t);
        let cache = "C:\\Users\\bob\\AppData\\Local\\Google\\Chrome\\Cache\\f_0001";
        assert!(plan(&mut p, Change::Modified, cache, t).is_empty());
        let roaming = "C:\\Users\\bob\\AppData\\Roaming\\app\\state.json.locked";
        assert!(plan(&mut p, Change::Created, roaming, t).is_empty());
        let temp = "C:\\Users\\bob\\AppData\\Local\\Temp\\dropper.encrypted";
        assert!(plan(&mut p, Change::Created, temp, t)
            .iter()
            .any(|x| matches!(x, Action::RansomExtension { .. })));
    }

    #[test]
    fn modifications_request_an_entropy_check_once_and_skip_compressed_formats() {
        let t = Instant::now();
        let mut p = Planner::new(roots(), t);
        let doc = "C:\\Users\\bob\\Documents\\notes.txt";
        assert!(plan(&mut p, Change::Modified, doc, t)
            .iter()
            .any(|x| matches!(x, Action::EntropyCheck { .. })));
        // The same file again within the throttle interval: no second read.
        assert!(!plan(
            &mut p,
            Change::Modified,
            doc,
            t + Duration::from_millis(500)
        )
        .iter()
        .any(|x| matches!(x, Action::EntropyCheck { .. })));
        // A photo is high-entropy by nature: never read.
        assert!(!plan(
            &mut p,
            Change::Modified,
            "C:\\Users\\bob\\Pictures\\a.JPG",
            t
        )
        .iter()
        .any(|x| matches!(x, Action::EntropyCheck { .. })));
    }

    #[test]
    fn fifty_distinct_files_trigger_one_write_rate_indicator() {
        let t = Instant::now();
        let mut p = Planner::new(roots(), t);
        let mut rates = Vec::new();
        for i in 0..60 {
            for a in plan(
                &mut p,
                Change::Modified,
                &format!("C:\\Users\\bob\\Documents\\f{i}.docx"),
                t + Duration::from_millis(i),
            ) {
                if let Action::WriteRate { rate } = a {
                    rates.push(rate);
                }
            }
        }
        assert_eq!(rates.len(), 1, "one burst, one alert: {rates:?}");
        // One file saved repeatedly never does.
        let mut p = Planner::new(roots(), t);
        for i in 0..500 {
            let a = plan(
                &mut p,
                Change::Modified,
                "C:\\Users\\bob\\Documents\\big.docx",
                t + Duration::from_millis(i),
            );
            assert!(!a.iter().any(|x| matches!(x, Action::WriteRate { .. })));
        }
    }

    #[test]
    fn deleting_from_a_backup_location_is_flagged_even_outside_user_data() {
        let t = Instant::now();
        let mut p = Planner::new(roots(), t);
        for c in [Change::Deleted, Change::RenamedFrom] {
            assert!(plan(&mut p, c, "C:\\Backup\\2026-10-01.vhdx", t)
                .iter()
                .any(|x| matches!(x, Action::BackupDeletion { .. })));
        }
        assert!(!plan(&mut p, Change::Created, "C:\\Backup\\new.vhdx", t)
            .iter()
            .any(|x| matches!(x, Action::BackupDeletion { .. })));
    }

    #[test]
    fn foreign_changes_in_the_agent_config_directory_are_tamper() {
        let t = Instant::now();
        let mut p = Planner::new(roots(), t);
        let key = "C:\\ProgramData\\TRAPD\\config\\command_signing.pub";
        for (c, want) in [
            (Change::Modified, "modify"),
            (Change::Deleted, "delete"),
            (Change::Created, "create"),
            (Change::RenamedFrom, "delete"),
        ] {
            let a = plan(&mut p, c, key, t);
            assert_eq!(
                a,
                vec![Action::Tamper {
                    path: key.into(),
                    action: want
                }]
            );
        }
    }

    #[test]
    fn the_agents_own_start_up_write_is_not_reported_as_tamper() {
        let t = Instant::now();
        let mut p = Planner::new(roots(), t);
        let baseline = "C:\\ProgramData\\TRAPD\\config\\binary.sha256";
        let early = p.plan(Change::Modified, baseline, t, Duration::from_secs(5), false);
        assert!(early.is_empty(), "{early:?}");
        let late = p.plan(
            Change::Modified,
            baseline,
            t,
            Duration::from_secs(7200),
            false,
        );
        assert!(matches!(late.as_slice(), [Action::Tamper { .. }]));
        let updating = p.plan(
            Change::Modified,
            baseline,
            t,
            Duration::from_secs(7200),
            true,
        );
        assert!(updating.is_empty());
    }

    #[test]
    fn generic_telemetry_is_coalesced_but_the_hosts_file_never_is() {
        let t = Instant::now();
        let mut p = Planner::new(roots(), t);
        let hosts = "C:\\Windows\\System32\\drivers\\etc\\hosts";
        for i in 0..3 {
            let a = plan(
                &mut p,
                Change::Modified,
                hosts,
                t + Duration::from_millis(i),
            );
            assert!(
                matches!(a.as_slice(), [Action::Generic { .. }]),
                "hosts always reported"
            );
        }
        let other = "C:\\Windows\\System32\\drivers\\etc\\services";
        assert_eq!(plan(&mut p, Change::Modified, other, t).len(), 1);
        assert!(plan(
            &mut p,
            Change::Modified,
            other,
            t + Duration::from_millis(5)
        )
        .is_empty());
        let lock = "C:\\Windows\\System32\\drivers\\etc\\~$lock";
        assert!(plan(&mut p, Change::Modified, lock, t).is_empty(), "noise");
    }
}
