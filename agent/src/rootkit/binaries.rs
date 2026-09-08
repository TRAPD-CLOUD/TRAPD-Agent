//! Integrity of the system binaries an intruder has to replace.
//!
//! Trojanising `ps`, `ss` or `ls` is the userland half of hiding: the kernel
//! still reports the truth, but the tools an operator uses to ask stop
//! relaying it. Detecting that means knowing what those binaries are *supposed*
//! to contain.
//!
//! ## No hardcoded list of paths
//!
//! Two things are derived from the host rather than baked in:
//!
//! * **Which files to watch.** A curated set of *tool names* per role
//!   ([`WATCHED_TOOL_ROLES`]) is resolved through the host's own `PATH`, so
//!   `ss` is watched at whatever path this distribution puts it in, and only
//!   if it is installed at all. Every setuid and setgid executable found in
//!   those directories is added too — that set is discovered entirely at
//!   runtime and is where distribution-specific privileged tooling shows up.
//! * **What they should contain.** The expected digest comes from the
//!   distribution's own package database (`dpkg` md5sums, `rpm --verify`), not
//!   from a list shipped with the agent. That is the only source that can tell
//!   a legitimate package upgrade from tampering: after an upgrade the file
//!   changed *and* still matches its package, so it is silently accepted;
//!   after tampering it changed and no longer matches, which is a certainty
//!   rather than a guess.
//!
//! Where no package database is available the agent falls back to a digest
//! baseline it records itself. That can only report *change*, not *wrongness*,
//! so those findings are deliberately weaker.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::debug;

use super::{Confirmation, Finding};
use crate::schema::Severity;

/// Tool *names* grouped by the visibility or privilege they control, resolved
/// against the host's `PATH`. Names rather than paths is the whole point: the
/// same role lives in `/bin`, `/usr/bin` or `/usr/sbin` depending on the
/// distribution, and half of these are not installed on a given host.
pub const WATCHED_TOOL_ROLES: &[(&str, &[&str])] = &[
    (
        "process_visibility",
        &["ps", "top", "htop", "pidof", "pstree", "lsof", "fuser"],
    ),
    (
        "network_visibility",
        &["ss", "netstat", "ip", "ifconfig", "arp", "route", "tcpdump"],
    ),
    (
        "filesystem_visibility",
        &["ls", "dir", "find", "stat", "du", "df", "readlink"],
    ),
    (
        "module_management",
        &["lsmod", "insmod", "rmmod", "modprobe", "kmod", "depmod"],
    ),
    (
        "authentication",
        &[
            "login", "su", "sudo", "passwd", "sshd", "ssh", "chsh", "chfn", "newgrp",
        ],
    ),
    ("shell", &["sh", "bash", "dash", "zsh", "ksh", "busybox"]),
    (
        "session_history",
        &[
            "last",
            "lastlog",
            "who",
            "w",
            "utmpdump",
            "dmesg",
            "journalctl",
        ],
    ),
    (
        "integrity_tooling",
        &["md5sum", "sha1sum", "sha256sum", "strings", "strace", "ldd"],
    ),
    ("scheduling", &["crontab", "at", "systemctl", "service"]),
];

/// Directories a core system tool is expected to resolve from. A resolution
/// outside these while a copy inside them exists is `PATH` shadowing.
const SYSTEM_BIN_DIRS: &[&str] = &["/bin", "/sbin", "/usr/bin", "/usr/sbin"];

const FALLBACK_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

/// More changed binaries than this in one sweep is a package upgrade.
const BULK_CHANGE_THRESHOLD: usize = 10;

/// The baseline file name inside the state directory.
pub const BASELINE_FILE: &str = "rootkit_binaries.json";

// ── Discovery ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatchedBinary {
    pub path: PathBuf,
    /// Why this file is watched: a role from [`WATCHED_TOOL_ROLES`], or
    /// `setuid`/`setgid` for runtime-discovered privileged executables.
    pub role: String,
    pub tool: String,
}

/// `PATH` search directories: the agent's own `PATH` if it has one, plus the
/// standard system directories, keeping only those that exist.
pub fn search_dirs() -> Vec<PathBuf> {
    let path = std::env::var("PATH").unwrap_or_default();
    let mut out: Vec<PathBuf> = Vec::new();
    for dir in path
        .split(':')
        .chain(FALLBACK_PATH.split(':'))
        .filter(|d| !d.is_empty())
    {
        let dir = PathBuf::from(dir);
        if dir.is_dir() && !out.contains(&dir) {
            out.push(dir);
        }
    }
    out
}

/// Every path a tool name resolves to, in `PATH` order.
fn resolve_all(tool: &str, dirs: &[PathBuf]) -> Vec<PathBuf> {
    dirs.iter()
        .map(|d| d.join(tool))
        .filter(|p| p.is_file())
        .collect()
}

/// Decide whether a tool is being shadowed by a copy outside the system
/// directories.
///
/// Returns the shadowing path and the system path it hides. `/usr/local/bin`
/// legitimately precedes `/usr/bin` for locally built software, but a core
/// visibility tool resolving from there while the packaged copy still exists
/// is exactly how a trojanised `ps` gets used without touching the original.
pub fn shadowing(matches: &[PathBuf]) -> Option<(PathBuf, PathBuf)> {
    let first = matches.first()?;
    if is_system_dir(first) {
        return None;
    }
    let shadowed = matches.iter().find(|p| is_system_dir(p))?;
    Some((first.clone(), shadowed.clone()))
}

fn is_system_dir(path: &Path) -> bool {
    path.parent()
        .map(|parent| SYSTEM_BIN_DIRS.iter().any(|d| parent == Path::new(d)))
        .unwrap_or(false)
}

/// Resolve the watched roles against this host and add every setuid/setgid
/// executable found along the way.
pub fn discover(dirs: &[PathBuf]) -> (Vec<WatchedBinary>, Vec<Finding>) {
    let mut binaries: BTreeMap<PathBuf, WatchedBinary> = BTreeMap::new();
    let mut findings = Vec::new();

    for (role, tools) in WATCHED_TOOL_ROLES {
        for tool in *tools {
            let matches = resolve_all(tool, dirs);
            let Some(effective) = matches.first() else {
                continue; // not installed on this host
            };
            binaries.insert(
                effective.clone(),
                WatchedBinary {
                    path: effective.clone(),
                    role: (*role).to_string(),
                    tool: (*tool).to_string(),
                },
            );
            if let Some((shadowing_path, shadowed)) = shadowing(&matches) {
                findings.push(Finding {
                    rule_id: "rootkit.system_binary_shadowed",
                    title: "System tool resolves from outside the system directories",
                    confirmation: Confirmation::Corroborate,
                    severity: Severity::High,
                    confidence: 65,
                    mitre_tactic: "TA0005 Defense Evasion",
                    mitre_technique: "T1036.005",
                    subject: shadowing_path.to_string_lossy().into_owned(),
                    detail: format!(
                        "`{tool}` resolves to {} before the packaged copy at {}. A tool that \
                         reports what is running or listening being replaced earlier in PATH \
                         means the packaged binary can be left untouched while every caller \
                         gets the substitute.",
                        shadowing_path.display(),
                        shadowed.display()
                    ),
                    evidence: json!({
                        "tool": tool,
                        "role": role,
                        "resolves_to": shadowing_path.to_string_lossy(),
                        "shadowed": shadowed.to_string_lossy(),
                    }),
                });
            }
        }
    }

    for dir in dirs {
        let Ok(entries) = std::fs::read_dir(dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(meta) = entry.metadata() else { continue };
            if !meta.is_file() {
                continue;
            }
            let mode = meta.mode();
            let role = if mode & libc::S_ISUID != 0 {
                "setuid"
            } else if mode & libc::S_ISGID != 0 {
                "setgid"
            } else {
                continue;
            };
            let path = entry.path();
            let tool = path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            binaries.entry(path.clone()).or_insert(WatchedBinary {
                path,
                role: role.to_string(),
                tool,
            });
        }
    }

    (binaries.into_values().collect(), findings)
}

// ── Package-manager verification ────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackageVerdict {
    /// The file matches what its package says it should be.
    Match,
    /// The file does not match its package's recorded digest.
    Mismatch,
    /// No package owns the file, or no package database is available.
    Unknown,
}

/// Parse one dpkg `.md5sums` file: `<md5>  <path relative to />`.
pub fn parse_md5sums(content: &str) -> Vec<(String, String)> {
    content
        .lines()
        .filter_map(|line| {
            let (digest, path) = line.split_once(char::is_whitespace)?;
            let path = path.trim();
            if digest.len() != 32 || path.is_empty() {
                return None;
            }
            Some((
                format!("/{}", path.trim_start_matches('/')),
                digest.to_string(),
            ))
        })
        .collect()
}

/// Expected md5 digests for `wanted`, read out of the dpkg file database.
///
/// The whole database is scanned once and only the paths of interest are kept,
/// which is far cheaper than one `dpkg-query -S` process per binary.
fn dpkg_digests(wanted: &BTreeSet<PathBuf>) -> HashMap<PathBuf, String> {
    let mut out = HashMap::new();
    let Ok(entries) = std::fs::read_dir("/var/lib/dpkg/info") else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("md5sums") {
            continue;
        }
        let Ok(content) = std::fs::read_to_string(&path) else {
            continue;
        };
        for (file, digest) in parse_md5sums(&content) {
            let file = PathBuf::from(file);
            if wanted.contains(&file) {
                out.insert(file, digest);
            }
        }
    }
    out
}

/// Interpret `rpm --verify` output for one file.
///
/// rpm prints a line only for attributes that *differ*, so silence means the
/// file is intact. Column 3 of the flag field is the digest check.
pub fn parse_rpm_verify(output: &str, target: &Path) -> PackageVerdict {
    for line in output.lines() {
        let mut fields = line.split_whitespace();
        let Some(flags) = fields.next() else { continue };
        let Some(path) = line.split_whitespace().last() else {
            continue;
        };
        if Path::new(path) != target {
            continue;
        }
        if flags == "missing" {
            return PackageVerdict::Mismatch;
        }
        if flags.chars().nth(2) == Some('5') {
            return PackageVerdict::Mismatch;
        }
        // Some other attribute (mtime, mode, ownership) differs; the content
        // still matches its package, so this is not tampering evidence.
        return PackageVerdict::Match;
    }
    PackageVerdict::Match
}

fn rpm_verify(path: &Path) -> PackageVerdict {
    // rpm exits non-zero when verification fails, so the status is deliberately
    // ignored — the output is the answer.
    let Ok(out) = Command::new("rpm").arg("-Vf").arg(path).output() else {
        return PackageVerdict::Unknown;
    };
    let stderr = String::from_utf8_lossy(&out.stderr);
    if stderr.contains("not owned by any package") {
        return PackageVerdict::Unknown;
    }
    parse_rpm_verify(&String::from_utf8_lossy(&out.stdout), path)
}

/// Which package database, if any, this host has.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PackageSource {
    Dpkg,
    Rpm,
    None,
}

fn detect_package_source() -> PackageSource {
    if Path::new("/var/lib/dpkg/info").is_dir() {
        PackageSource::Dpkg
    } else if Path::new("/var/lib/rpm").is_dir() {
        PackageSource::Rpm
    } else {
        PackageSource::None
    }
}

/// Verifier bound to whatever package database the host actually has.
pub struct PackageVerifier {
    source: PackageSource,
    dpkg: HashMap<PathBuf, String>,
}

impl PackageVerifier {
    pub fn new(wanted: &BTreeSet<PathBuf>) -> Self {
        let source = detect_package_source();
        let dpkg = if source == PackageSource::Dpkg {
            dpkg_digests(wanted)
        } else {
            HashMap::new()
        };
        Self { source, dpkg }
    }

    pub fn available(&self) -> bool {
        self.source != PackageSource::None
    }

    /// `canonical` must be the symlink-resolved path, because that is the form
    /// package databases record (usrmerge means `/bin/ls` is recorded as
    /// `/usr/bin/ls`).
    pub fn verify(&self, canonical: &Path) -> PackageVerdict {
        match self.source {
            PackageSource::Dpkg => match self.dpkg.get(canonical) {
                Some(expected) => match md5_file(canonical) {
                    Some(actual) if actual.eq_ignore_ascii_case(expected) => PackageVerdict::Match,
                    Some(_) => PackageVerdict::Mismatch,
                    None => PackageVerdict::Unknown,
                },
                None => PackageVerdict::Unknown,
            },
            PackageSource::Rpm => rpm_verify(canonical),
            PackageSource::None => PackageVerdict::Unknown,
        }
    }
}

fn md5_file(path: &Path) -> Option<String> {
    use md5::{Digest, Md5};
    let bytes = std::fs::read(path).ok()?;
    let mut hasher = Md5::new();
    hasher.update(&bytes);
    Some(hex::encode(hasher.finalize()))
}

// ── Baseline ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct BinaryRecord {
    pub sha256: String,
    pub size: u64,
    pub mtime: i64,
    /// Whether the package database agreed the last time it was consulted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package_verified: Option<bool>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Baseline {
    #[serde(default)]
    pub binaries: BTreeMap<String, BinaryRecord>,
}

impl Baseline {
    pub fn load(state_dir: &Path) -> Self {
        std::fs::read_to_string(state_dir.join(BASELINE_FILE))
            .ok()
            .and_then(|raw| serde_json::from_str(&raw).ok())
            .unwrap_or_default()
    }

    pub fn store(&self, state_dir: &Path) {
        let path = state_dir.join(BASELINE_FILE);
        let Ok(raw) = serde_json::to_vec_pretty(self) else {
            return;
        };
        if let Err(e) = crate::paths::write_atomic(&path, &raw, 0o600) {
            debug!("rootkit: could not persist binary baseline: {e}");
        }
    }
}

/// What one sweep observed about a single binary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observation {
    pub path: String,
    pub role: String,
    pub tool: String,
    pub previous: Option<BinaryRecord>,
    pub current: BinaryRecord,
    pub verdict: PackageVerdict,
}

impl Observation {
    fn digest_changed(&self) -> bool {
        matches!(&self.previous, Some(prev) if prev.sha256 != self.current.sha256)
    }
}

/// Turn observations into findings.
///
/// Ordering matters here: a package verdict of `Mismatch` is reported whether
/// or not the digest changed on our watch, because a host that was already
/// compromised before the agent was installed has nothing to change *from*.
pub fn analyze(observations: &[Observation]) -> Vec<Finding> {
    let mut out = Vec::new();
    let mut unexplained = Vec::new();

    for obs in observations {
        if obs.verdict == PackageVerdict::Mismatch {
            out.push(Finding {
                rule_id: "rootkit.system_binary_tampered",
                title: "System binary does not match its package's recorded digest",
                confirmation: Confirmation::Immediate,
                severity: Severity::Critical,
                confidence: 95,
                mitre_tactic: "TA0005 Defense Evasion",
                mitre_technique: "T1554",
                subject: obs.path.clone(),
                detail: format!(
                    "{} ({}) does not match the digest its own package database records for \
                     it. The distribution's copy of this file and the one on disk are \
                     different, which an upgrade cannot explain.",
                    obs.path, obs.role
                ),
                evidence: json!({
                    "path": obs.path,
                    "role": obs.role,
                    "tool": obs.tool,
                    "sha256": obs.current.sha256,
                    "package_verified": false,
                }),
            });
            continue;
        }

        if !obs.digest_changed() {
            continue;
        }
        if obs.verdict == PackageVerdict::Match {
            // Changed and still matches its package: an upgrade, not tampering.
            // This is the single most valuable thing the package database buys.
            continue;
        }
        unexplained.push(obs);
    }

    if unexplained.len() > BULK_CHANGE_THRESHOLD {
        out.push(Finding {
            rule_id: "rootkit.system_binaries_bulk_change",
            title: "Many system binaries changed at once",
            confirmation: Confirmation::Immediate,
            severity: Severity::Low,
            confidence: 25,
            mitre_tactic: "TA0005 Defense Evasion",
            mitre_technique: "T1554",
            subject: "system_binaries".to_string(),
            detail: format!(
                "{} watched binaries changed in a single sweep with no package database to \
                 explain them, which is the shape of a system upgrade rather than targeted \
                 tampering.",
                unexplained.len()
            ),
            evidence: json!({
                "changed": unexplained.len(),
                "paths": unexplained.iter().take(20).map(|o| o.path.clone()).collect::<Vec<_>>(),
            }),
        });
        return out;
    }

    for obs in unexplained {
        out.push(Finding {
            rule_id: "rootkit.system_binary_changed",
            title: "System binary changed with no package record to check it against",
            confirmation: Confirmation::Immediate,
            severity: Severity::Medium,
            confidence: 55,
            mitre_tactic: "TA0005 Defense Evasion",
            mitre_technique: "T1554",
            subject: obs.path.clone(),
            detail: format!(
                "The contents of {} ({}) changed since the last sweep. No package owns the \
                 file, so whether the new contents are legitimate cannot be established \
                 from the host itself.",
                obs.path, obs.role
            ),
            evidence: json!({
                "path": obs.path,
                "role": obs.role,
                "tool": obs.tool,
                "previous_sha256": obs.previous.as_ref().map(|p| p.sha256.clone()),
                "sha256": obs.current.sha256,
            }),
        });
    }

    out
}

/// `/etc/ld.so.preload` forces a library into every dynamically linked process
/// started on the host. It is empty or absent on a normal system and is the
/// standard foothold for a userland rootkit, so its mere presence is worth
/// reporting regardless of content.
pub fn ld_preload_finding() -> Option<Finding> {
    let path = "/etc/ld.so.preload";
    let content = std::fs::read_to_string(path).ok()?;
    let entries: Vec<&str> = content
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();
    if entries.is_empty() {
        return None;
    }
    Some(Finding {
        rule_id: "rootkit.ld_preload_configured",
        title: "Global library preload configured in /etc/ld.so.preload",
        confirmation: Confirmation::Corroborate,
        severity: Severity::High,
        confidence: 80,
        mitre_tactic: "TA0005 Defense Evasion",
        mitre_technique: "T1574.006",
        subject: path.to_string(),
        detail: format!(
            "{path} lists {} library/libraries that are loaded into every dynamically \
             linked process on this host. This is how a userland rootkit intercepts the \
             calls that ps, ls and netstat rely on.",
            entries.len()
        ),
        evidence: json!({ "path": path, "entries": entries }),
    })
}

// ── Host collection ─────────────────────────────────────────────────────────

/// What a sweep looked at, for the `diagnostics rootkit` report.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Summary {
    pub watched: usize,
    pub package_db_available: bool,
    /// Files whose size or mtime changed, so their digest was recomputed.
    pub rehashed: usize,
    pub baseline_existed: bool,
}

/// Run one binary-integrity sweep, updating the persisted baseline.
pub fn sweep(state_dir: &Path) -> Vec<Finding> {
    observe(state_dir, true).0
}

/// Run one binary-integrity sweep.
///
/// `persist` is false for the read-only diagnostics path, which must not move
/// the baseline a running agent is comparing against.
pub fn observe(state_dir: &Path, persist: bool) -> (Vec<Finding>, Summary) {
    observe_in(&search_dirs(), state_dir, persist)
}

/// [`observe`] against an explicit set of search directories, so the baseline
/// round-trip can be exercised without depending on the host's `PATH`.
pub fn observe_in(dirs: &[PathBuf], state_dir: &Path, persist: bool) -> (Vec<Finding>, Summary) {
    let (watched, mut findings) = discover(dirs);

    let mut baseline = Baseline::load(state_dir);
    let first_run = baseline.binaries.is_empty();

    // Canonical paths are what package databases record; usrmerge means
    // /bin/ls and /usr/bin/ls are the same file under two names.
    let canonical: HashMap<PathBuf, PathBuf> = watched
        .iter()
        .map(|w| {
            let canonical = std::fs::canonicalize(&w.path).unwrap_or_else(|_| w.path.clone());
            (w.path.clone(), canonical)
        })
        .collect();
    let wanted: BTreeSet<PathBuf> = canonical.values().cloned().collect();
    let verifier = PackageVerifier::new(&wanted);

    let mut observations = Vec::new();
    let mut next = BTreeMap::new();

    for binary in &watched {
        let key = binary.path.to_string_lossy().into_owned();
        let Ok(meta) = std::fs::metadata(&binary.path) else {
            continue;
        };
        let previous = baseline.binaries.get(&key).cloned();

        // Unchanged size and mtime: nothing to re-hash and nothing to re-check.
        // A rootkit can forge both, which is why the first sweep verifies
        // everything against the package database rather than trusting them.
        if let Some(prev) = &previous {
            if prev.size == meta.len() && prev.mtime == meta.mtime() && !prev.sha256.is_empty() {
                next.insert(key, prev.clone());
                continue;
            }
        }

        let Some(sha256) = crate::collectors::linux::exehash::sha256_file(&binary.path) else {
            continue;
        };
        let canonical_path = canonical.get(&binary.path).cloned().unwrap_or_default();
        let verdict = verifier.verify(&canonical_path);
        let current = BinaryRecord {
            sha256,
            size: meta.len(),
            mtime: meta.mtime(),
            package_verified: match verdict {
                PackageVerdict::Match => Some(true),
                PackageVerdict::Mismatch => Some(false),
                PackageVerdict::Unknown => None,
            },
        };
        next.insert(key.clone(), current.clone());
        observations.push(Observation {
            path: key,
            role: binary.role.clone(),
            tool: binary.tool.clone(),
            previous,
            current,
            verdict,
        });
    }

    findings.extend(analyze(&observations));
    findings.extend(ld_preload_finding());

    let summary = Summary {
        watched: watched.len(),
        package_db_available: verifier.available(),
        rehashed: observations.len(),
        baseline_existed: !first_run,
    };

    if persist {
        baseline.binaries = next;
        baseline.store(state_dir);
        if first_run {
            debug!(
                watched = summary.watched,
                package_db = summary.package_db_available,
                "rootkit: binary integrity baseline established"
            );
        }
    }
    (findings, summary)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(sha: &str) -> BinaryRecord {
        BinaryRecord {
            sha256: sha.into(),
            size: 100,
            mtime: 1,
            package_verified: None,
        }
    }

    fn observation(path: &str, previous: Option<&str>, verdict: PackageVerdict) -> Observation {
        Observation {
            path: path.into(),
            role: "process_visibility".into(),
            tool: "ps".into(),
            previous: previous.map(record),
            current: record("new"),
            verdict,
        }
    }

    #[test]
    fn a_package_digest_mismatch_is_reported_even_without_a_prior_baseline() {
        // The already-compromised-host case: nothing to compare against
        // locally, but the package database still knows what the file was.
        let found = analyze(&[observation("/usr/bin/ps", None, PackageVerdict::Mismatch)]);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].rule_id, "rootkit.system_binary_tampered");
        assert!(matches!(found[0].severity, Severity::Critical));
    }

    #[test]
    fn a_package_upgrade_is_not_tampering() {
        // Changed contents that still match the package: exactly what an
        // upgrade looks like, and the reason package data is worth reading.
        let found = analyze(&[observation(
            "/usr/bin/ps",
            Some("old"),
            PackageVerdict::Match,
        )]);
        assert!(found.is_empty());
    }

    #[test]
    fn an_unowned_binary_that_changes_is_reported_more_weakly() {
        let found = analyze(&[observation(
            "/usr/local/bin/ps",
            Some("old"),
            PackageVerdict::Unknown,
        )]);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].rule_id, "rootkit.system_binary_changed");
        assert!(matches!(found[0].severity, Severity::Medium));
        assert!(found[0].confidence < 60);
    }

    #[test]
    fn a_first_sighting_only_establishes_the_baseline() {
        let found = analyze(&[observation("/usr/bin/ps", None, PackageVerdict::Unknown)]);
        assert!(found.is_empty());
    }

    #[test]
    fn a_system_wide_upgrade_collapses_into_one_quiet_finding() {
        let observations: Vec<Observation> = (0..40)
            .map(|i| {
                observation(
                    &format!("/usr/local/bin/tool{i}"),
                    Some("old"),
                    PackageVerdict::Unknown,
                )
            })
            .collect();
        let found = analyze(&observations);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].rule_id, "rootkit.system_binaries_bulk_change");
        assert!(matches!(found[0].severity, Severity::Low));
    }

    #[test]
    fn a_tampered_binary_is_still_reported_during_a_bulk_change() {
        let mut observations: Vec<Observation> = (0..40)
            .map(|i| {
                observation(
                    &format!("/usr/local/bin/tool{i}"),
                    Some("old"),
                    PackageVerdict::Unknown,
                )
            })
            .collect();
        observations.push(observation(
            "/usr/bin/ps",
            Some("old"),
            PackageVerdict::Mismatch,
        ));
        let ids: Vec<&str> = analyze(&observations).iter().map(|f| f.rule_id).collect();
        assert!(ids.contains(&"rootkit.system_binary_tampered"));
        assert!(ids.contains(&"rootkit.system_binaries_bulk_change"));
    }

    #[test]
    fn parses_dpkg_md5sums_into_absolute_paths() {
        let parsed = parse_md5sums(
            "d41d8cd98f00b204e9800998ecf8427e  usr/bin/ls\n\
             0123456789abcdef0123456789abcdef  bin/ps\n\
             garbage line\n",
        );
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].0, "/usr/bin/ls");
        assert_eq!(parsed[1].0, "/bin/ps");
    }

    #[test]
    fn rpm_silence_means_the_file_is_intact() {
        assert_eq!(
            parse_rpm_verify("", Path::new("/usr/bin/ps")),
            PackageVerdict::Match
        );
    }

    #[test]
    fn rpm_digest_column_marks_tampering() {
        assert_eq!(
            parse_rpm_verify("..5....T.    /usr/bin/ps\n", Path::new("/usr/bin/ps")),
            PackageVerdict::Mismatch
        );
        assert_eq!(
            parse_rpm_verify("missing     /usr/bin/ps\n", Path::new("/usr/bin/ps")),
            PackageVerdict::Mismatch
        );
    }

    #[test]
    fn rpm_non_digest_differences_are_not_tampering() {
        // Only mtime differs: the content still matches the package.
        assert_eq!(
            parse_rpm_verify(".......T.    /usr/bin/ps\n", Path::new("/usr/bin/ps")),
            PackageVerdict::Match
        );
    }

    #[test]
    fn rpm_output_for_other_files_in_the_package_is_ignored() {
        assert_eq!(
            parse_rpm_verify("..5....T.  c /etc/sudoers\n", Path::new("/usr/bin/sudo")),
            PackageVerdict::Match
        );
    }

    #[test]
    fn a_tool_resolving_from_a_system_dir_is_not_shadowed() {
        let matches = vec![PathBuf::from("/usr/bin/ps"), PathBuf::from("/bin/ps")];
        assert!(shadowing(&matches).is_none());
    }

    #[test]
    fn a_tool_resolving_from_elsewhere_over_a_system_copy_is_shadowed() {
        let matches = vec![
            PathBuf::from("/usr/local/bin/ps"),
            PathBuf::from("/usr/bin/ps"),
        ];
        let (shadowing_path, shadowed) = shadowing(&matches).unwrap();
        assert_eq!(shadowing_path, PathBuf::from("/usr/local/bin/ps"));
        assert_eq!(shadowed, PathBuf::from("/usr/bin/ps"));
    }

    #[test]
    fn a_tool_that_only_exists_outside_the_system_dirs_is_not_shadowing_anything() {
        let matches = vec![PathBuf::from("/opt/tools/htop")];
        assert!(shadowing(&matches).is_none());
    }

    #[test]
    fn the_baseline_round_trip_turns_a_second_look_into_a_finding() {
        // End-to-end over the persisted baseline: the first sweep records, the
        // second compares. A tool discovered outside any package is the
        // "change detectable, tampering not provable" path.
        let root = std::env::temp_dir().join(format!("trapd-rk-{}", std::process::id()));
        let bin_dir = root.join("bin");
        let state_dir = root.join("state");
        std::fs::create_dir_all(&bin_dir).unwrap();
        std::fs::create_dir_all(&state_dir).unwrap();
        let tool = bin_dir.join("ls");
        std::fs::write(&tool, b"#!/bin/sh\ntrue\n").unwrap();

        let dirs = vec![bin_dir.clone()];
        let (first, summary) = observe_in(&dirs, &state_dir, true);
        assert!(!summary.baseline_existed);
        assert_eq!(summary.watched, 1);
        assert!(
            !first
                .iter()
                .any(|f| f.rule_id == "rootkit.system_binary_changed"),
            "a first sighting establishes the baseline, it does not accuse"
        );
        assert!(state_dir.join(BASELINE_FILE).exists());

        std::fs::write(&tool, b"#!/bin/sh\necho trojaned; true\n").unwrap();
        let (second, summary) = observe_in(&dirs, &state_dir, true);
        assert!(summary.baseline_existed);
        let changed: Vec<&Finding> = second
            .iter()
            .filter(|f| f.rule_id == "rootkit.system_binary_changed")
            .collect();
        assert_eq!(changed.len(), 1);
        assert_eq!(changed[0].subject, tool.to_string_lossy());

        // Third look, nothing touched: the finding must not repeat forever.
        let (third, _) = observe_in(&dirs, &state_dir, true);
        assert!(!third
            .iter()
            .any(|f| f.rule_id == "rootkit.system_binary_changed"));

        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn roles_name_tools_not_paths() {
        // The contract that keeps this distribution-independent.
        for (_, tools) in WATCHED_TOOL_ROLES {
            for tool in *tools {
                assert!(
                    !tool.contains('/'),
                    "{tool} is a path; watched entries must be names resolved through PATH"
                );
            }
        }
    }
}
