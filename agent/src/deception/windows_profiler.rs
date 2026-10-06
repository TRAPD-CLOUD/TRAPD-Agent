//! Windows decoy profiler: which bait fits *this* user, and where it goes.
//!
//! The Linux profiler ([`super::profiler`]) proposes tokens at the paths real
//! tools read (`~/.ssh/id_rsa`, `~/.aws/credentials`, …). On Windows that rule
//! has to be inverted for one reason: a decoy at a path legitimate software
//! reads on its own (`.git-credentials`, `pgpass.conf`, an SSMS server list)
//! is opened by that software every day — a false alarm generator. Windows
//! decoys are therefore *documents an admin would keep*, never live config.
//!
//! Three questions decide a candidate:
//!
//!   1. **Fit** — does the user's role make this artefact plausible? Roles come
//!      from evidence: installed software (weak), per-user tool footprints such
//!      as `%USERPROFILE%\.aws` (strong), and — when the operator enabled local
//!      learning — which tools the user actually runs ([`super::activity`]).
//!      No evidence, no candidate: a WinSCP export on a host without WinSCP
//!      *is* the tell.
//!   2. **Accidental access** — would the owner open it by chance? Decoys go
//!      into *cold* directories: owned by the user, with files, untouched for
//!      weeks. Never the desktop, never a synced folder (OneDrive, Dropbox,
//!      Nextcloud — a sync client reads every file, and the bait would leave
//!      the host), never a network or redirected folder (no local audit).
//!   3. **Attractiveness** — how much would an intruder want it (ATT&CK T1552
//!      unsecured credentials)?
//!
//! Privacy: placement is resolved **on the host**. What leaves the host is the
//! candidate (kind, user, location *class*, score, rationale) — never the
//! directory names, file names or activity it was derived from. The concrete
//! path is reported only after the operator approved the candidate and the
//! agent planted it (the operator must be able to find and remove it).
//!
//! The module is pure over a [`DirProbe`], so the heuristics are tested on any
//! platform against a temporary directory tree.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::activity::UserActivitySummary;
use super::naming::NamingStyle;

/// A directory untouched for this long counts as cold.
pub const COLD_AFTER_DAYS: i64 = 21;
/// Profiles not used for this long are not decoy targets (left-over accounts).
pub const STALE_PROFILE_DAYS: i64 = 90;
/// How deep below the documents root cold directories are searched.
const MAX_DEPTH: usize = 3;
/// Bound on directories inspected per user (keeps the scan cheap).
const MAX_DIRS: usize = 400;

/// One local Windows user profile, as the inventory sees it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowsUserProfile {
    pub name: String,
    pub sid: String,
    /// `ProfileImagePath`, e.g. `C:\Users\anna`.
    pub profile_dir: String,
    /// The user's documents folder when known (it may be redirected).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub documents_dir: Option<String>,
    /// Roots that a sync client mirrors (OneDrive, Dropbox, Nextcloud, …).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub synced_roots: Vec<String>,
    /// Last profile use (unix seconds), from `LocalProfileLoadTime*`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_use_unix: Option<i64>,
}

/// Built-in or service accounts that are never a person.
const NON_HUMAN_NAMES: &[&str] = &[
    "defaultaccount",
    "wdagutilityaccount",
    "guest",
    "gast",
    "defaultuser0",
    "defaultuser100000",
    "defaultuser1",
];

/// Whether a profile belongs to a person who still uses this machine.
///
/// Only `S-1-5-21-…` SIDs are real local or domain accounts; `S-1-5-18/19/20`
/// are SYSTEM/LocalService/NetworkService, `S-1-5-80-…` service SIDs,
/// `S-1-5-82-…` IIS app pools, `S-1-5-90-…` window manager, `S-1-5-96-…` font
/// drivers.
pub fn is_human_profile(p: &WindowsUserProfile, now_unix: i64) -> bool {
    let name = p.name.to_ascii_lowercase();
    if !p.sid.starts_with("S-1-5-21-") {
        return false;
    }
    if NON_HUMAN_NAMES.contains(&name.as_str())
        || name.starts_with("defaultuser")
        || name.ends_with('$')
    {
        return false;
    }
    let dir = p.profile_dir.to_ascii_lowercase();
    if dir.is_empty() || dir.contains("\\windows\\") || dir.starts_with("\\\\") {
        return false;
    }
    match p.last_use_unix {
        Some(t) => now_unix - t <= STALE_PROFILE_DAYS * 86_400,
        None => true,
    }
}

/// Expand the per-user variables of a `User Shell Folders` value
/// (`%USERPROFILE%\\Documents`) against *that* user's profile, never the
/// service's own environment. Unknown variables make the value unusable.
pub fn expand_user_path(raw: &str, profile_dir: &str) -> Option<String> {
    let mut out = raw.trim().to_string();
    for var in ["%USERPROFILE%", "%userprofile%", "%UserProfile%"] {
        out = out.replace(var, profile_dir);
    }
    (!out.contains('%') && !out.is_empty()).then_some(out)
}

/// Folder names a sync client creates in the profile.
const SYNC_FOLDER_PREFIXES: &[&str] = &[
    "onedrive",
    "dropbox",
    "nextcloud",
    "owncloud",
    "google drive",
    "icloud drive",
    "iclouddrive",
    "pcloud",
    "seafile",
    "box",
    "tresorit",
];

/// Sync roots among the direct children of a profile directory.
pub fn synced_roots_from_children(profile_dir: &str, children: &[String]) -> Vec<String> {
    children
        .iter()
        .filter(|c| {
            let l = c.to_lowercase();
            SYNC_FOLDER_PREFIXES.iter().any(|p| {
                l == *p || l.starts_with(&format!("{p} ")) || l.starts_with(&format!("{p} -"))
            })
        })
        .map(|c| {
            Path::new(profile_dir)
                .join(c)
                .to_string_lossy()
                .into_owned()
        })
        .collect()
}

/// `LocalProfileLoadTimeHigh/Low` (FILETIME halves) → unix seconds.
pub fn filetime_to_unix(high: u32, low: u32) -> Option<i64> {
    let ticks = ((high as u64) << 32) | low as u64;
    if ticks == 0 {
        return None;
    }
    Some((ticks / 10_000_000) as i64 - 11_644_473_600)
}

// ── Roles ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    AdminTooling,
    Developer,
    CloudOps,
    DbAdmin,
    Office,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Role::AdminTooling => "admin_tooling",
            Role::Developer => "developer",
            Role::CloudOps => "cloud_ops",
            Role::DbAdmin => "db_admin",
            Role::Office => "office",
        }
    }
}

/// Installed software (display name substring, lowercase) → role. Host-wide
/// and therefore weak evidence: the software may belong to another user.
const SOFTWARE_ROLES: &[(&str, Role)] = &[
    ("winscp", Role::AdminTooling),
    ("filezilla", Role::AdminTooling),
    ("putty", Role::AdminTooling),
    ("mremoteng", Role::AdminTooling),
    ("remote desktop connection manager", Role::AdminTooling),
    ("royal ts", Role::AdminTooling),
    ("remote server administration tools", Role::AdminTooling),
    ("sql server management studio", Role::DbAdmin),
    ("pgadmin", Role::DbAdmin),
    ("dbeaver", Role::DbAdmin),
    ("heidisql", Role::DbAdmin),
    ("mysql workbench", Role::DbAdmin),
    ("visual studio", Role::Developer),
    ("git", Role::Developer),
    ("docker desktop", Role::Developer),
    ("jetbrains", Role::Developer),
    ("node.js", Role::Developer),
    ("python", Role::Developer),
    ("aws command line interface", Role::CloudOps),
    ("microsoft azure cli", Role::CloudOps),
    ("google cloud sdk", Role::CloudOps),
    ("terraform", Role::CloudOps),
    ("microsoft 365", Role::Office),
    ("microsoft office", Role::Office),
    ("libreoffice", Role::Office),
];

/// Per-user footprint (relative to the profile) → role. Strong evidence: it
/// exists because this user used the tool.
const FOOTPRINT_ROLES: &[(&str, Role)] = &[
    (".aws", Role::CloudOps),
    (".azure", Role::CloudOps),
    (".kube", Role::CloudOps),
    (".ssh", Role::AdminTooling),
    ("AppData\\Roaming\\FileZilla", Role::AdminTooling),
    ("AppData\\Roaming\\mRemoteNG", Role::AdminTooling),
    ("source\\repos", Role::Developer),
    (".vscode", Role::Developer),
    (".gitconfig", Role::Developer),
    ("Documents\\SQL Server Management Studio", Role::DbAdmin),
    ("AppData\\Roaming\\DBeaverData", Role::DbAdmin),
];

/// Executable basenames (lowercase) the user runs → role (activity learning).
pub const TOOL_ROLES: &[(&str, Role)] = &[
    ("mstsc.exe", Role::AdminTooling),
    ("winscp.exe", Role::AdminTooling),
    ("putty.exe", Role::AdminTooling),
    ("filezilla.exe", Role::AdminTooling),
    ("mremoteng.exe", Role::AdminTooling),
    ("mmc.exe", Role::AdminTooling),
    ("ssh.exe", Role::AdminTooling),
    ("code.exe", Role::Developer),
    ("devenv.exe", Role::Developer),
    ("git.exe", Role::Developer),
    ("docker.exe", Role::Developer),
    ("aws.exe", Role::CloudOps),
    ("az.cmd", Role::CloudOps),
    ("kubectl.exe", Role::CloudOps),
    ("terraform.exe", Role::CloudOps),
    ("ssms.exe", Role::DbAdmin),
    ("sqlcmd.exe", Role::DbAdmin),
    ("pgadmin4.exe", Role::DbAdmin),
    ("dbeaver.exe", Role::DbAdmin),
    ("winword.exe", Role::Office),
    ("excel.exe", Role::Office),
    ("outlook.exe", Role::Office),
];

/// Evidence strength per role, 0–100, with the reasons that produced it.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct RoleEvidence {
    pub strength: BTreeMap<Role, u8>,
    pub reasons: BTreeMap<Role, Vec<String>>,
}

impl RoleEvidence {
    fn add(&mut self, role: Role, strength: u8, reason: String) {
        let s = self.strength.entry(role).or_insert(0);
        *s = (*s).max(strength);
        let r = self.reasons.entry(role).or_default();
        if r.len() < 4 && !r.contains(&reason) {
            r.push(reason);
        }
    }

    pub fn of(&self, role: Role) -> u8 {
        self.strength.get(&role).copied().unwrap_or(0)
    }

    pub fn roles(&self) -> Vec<Role> {
        self.strength.keys().copied().collect()
    }
}

/// Collect role evidence for one user. Reasons name the *tool*, never a path
/// of the user's own data.
pub fn role_evidence(
    user: &WindowsUserProfile,
    software: &[String],
    activity: Option<&UserActivitySummary>,
    fs: &dyn DirProbe,
) -> RoleEvidence {
    let mut ev = RoleEvidence::default();
    for name in software {
        let lower = name.to_ascii_lowercase();
        for (needle, role) in SOFTWARE_ROLES {
            // "git" must not match "digital"; require a word start.
            if contains_word(&lower, needle) {
                ev.add(*role, 40, format!("installed: {needle}"));
            }
        }
    }
    let profile = Path::new(&user.profile_dir);
    for (rel, role) in FOOTPRINT_ROLES {
        if fs.exists(&join_win(profile, rel)) {
            ev.add(
                *role,
                75,
                format!("user footprint: {}", rel.replace('\\', "/")),
            );
        }
    }
    if let Some(a) = activity {
        for (tool, role) in TOOL_ROLES {
            let uses = a.tool_uses.get(*tool).copied().unwrap_or(0);
            if uses >= 3 {
                ev.add(*role, 90, format!("uses {tool} ({uses}x in 30 days)"));
            } else if uses > 0 {
                ev.add(*role, 60, format!("used {tool}"));
            }
        }
    }
    // Every interactive user plausibly keeps a personal notes file; the role is
    // weak on purpose so it never outranks real evidence.
    ev.add(Role::Office, 30, "interactive user".into());
    ev
}

fn contains_word(haystack: &str, needle: &str) -> bool {
    haystack.match_indices(needle).any(|(i, _)| {
        let before_ok = i == 0 || !haystack.as_bytes()[i - 1].is_ascii_alphanumeric();
        let end = i + needle.len();
        let after_ok = end == haystack.len() || !haystack.as_bytes()[end].is_ascii_alphabetic();
        before_ok && after_ok
    })
}

/// Join a Windows-style relative path (`a\b`) onto a base, component-wise, so
/// the same tables work on every platform.
fn join_win(base: &Path, rel: &str) -> PathBuf {
    rel.split(['\\', '/'])
        .filter(|c| !c.is_empty())
        .fold(base.to_path_buf(), |p, c| p.join(c))
}

// ── Decoy kinds ───────────────────────────────────────────────────────────────

/// Where a kind of decoy belongs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocationClass {
    /// A cold folder below the user's documents.
    ColdDocuments,
    /// A cold project folder (below `source\repos` or a documents project dir).
    ColdProject,
    /// Next to an existing cloud CLI configuration (`.aws`).
    CloudConfig,
}

impl LocationClass {
    pub fn as_str(self) -> &'static str {
        match self {
            LocationClass::ColdDocuments => "cold_documents",
            LocationClass::ColdProject => "cold_project",
            LocationClass::CloudConfig => "cloud_config",
        }
    }
}

/// One decoy kind the Windows agent can generate faithfully
/// ([`super::windows_bait::generate_kind`]).
#[derive(Debug, Clone, Copy)]
pub struct KindSpec {
    pub kind: &'static str,
    pub roles: &'static [Role],
    /// ATT&CK attractiveness, 0–100.
    pub attractiveness: u8,
    pub mitre: &'static str,
    pub location: LocationClass,
}

pub const WINDOWS_KINDS: &[KindSpec] = &[
    KindSpec {
        kind: "rdp_connection",
        roles: &[Role::AdminTooling],
        attractiveness: 85,
        mitre: "T1552.001",
        location: LocationClass::ColdDocuments,
    },
    KindSpec {
        kind: "winscp_ini",
        roles: &[Role::AdminTooling],
        attractiveness: 90,
        mitre: "T1552.001",
        location: LocationClass::ColdDocuments,
    },
    KindSpec {
        kind: "filezilla_sitemanager",
        roles: &[Role::AdminTooling],
        attractiveness: 90,
        mitre: "T1552.001",
        location: LocationClass::ColdDocuments,
    },
    KindSpec {
        kind: "map_drives_script",
        roles: &[Role::AdminTooling],
        attractiveness: 80,
        mitre: "T1552.001",
        location: LocationClass::ColdDocuments,
    },
    KindSpec {
        kind: "unattend_xml",
        roles: &[Role::AdminTooling],
        attractiveness: 85,
        mitre: "T1552.001",
        location: LocationClass::ColdDocuments,
    },
    KindSpec {
        kind: "appsettings_json",
        roles: &[Role::Developer],
        attractiveness: 80,
        mitre: "T1552.001",
        location: LocationClass::ColdProject,
    },
    KindSpec {
        kind: "web_config",
        roles: &[Role::Developer],
        attractiveness: 80,
        mitre: "T1552.001",
        location: LocationClass::ColdProject,
    },
    KindSpec {
        kind: "env_file",
        roles: &[Role::Developer],
        attractiveness: 85,
        mitre: "T1552.001",
        location: LocationClass::ColdProject,
    },
    KindSpec {
        kind: "aws_credentials_backup",
        roles: &[Role::CloudOps],
        attractiveness: 95,
        mitre: "T1552.001",
        location: LocationClass::CloudConfig,
    },
    KindSpec {
        kind: "db_connection_notes",
        roles: &[Role::DbAdmin],
        attractiveness: 85,
        mitre: "T1552.001",
        location: LocationClass::ColdDocuments,
    },
    KindSpec {
        kind: "password_note",
        roles: &[Role::AdminTooling, Role::DbAdmin, Role::Office],
        attractiveness: 75,
        mitre: "T1552.001",
        location: LocationClass::ColdDocuments,
    },
    KindSpec {
        kind: "credential_csv",
        roles: &[Role::AdminTooling, Role::Office],
        attractiveness: 75,
        mitre: "T1552.001",
        location: LocationClass::ColdDocuments,
    },
    KindSpec {
        kind: "recovery_key",
        roles: &[Role::AdminTooling, Role::Office],
        attractiveness: 60,
        mitre: "T1552.001",
        location: LocationClass::ColdDocuments,
    },
];

pub fn kind_spec(kind: &str) -> Option<&'static KindSpec> {
    WINDOWS_KINDS.iter().find(|k| k.kind == kind)
}

// ── Filesystem probe ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryInfo {
    pub name: String,
    pub is_dir: bool,
    /// Last write, unix seconds.
    pub modified_unix: i64,
}

/// Read-only view of the filesystem (mockable in tests).
pub trait DirProbe {
    fn exists(&self, path: &Path) -> bool;
    /// Direct children of `dir` (bounded), excluding reparse points/links.
    fn entries(&self, dir: &Path) -> Vec<EntryInfo>;
}

/// Bounded real-filesystem probe (used by the Windows inventory path).
#[cfg_attr(not(windows), allow(dead_code))]
pub struct RealDirProbe;

#[cfg_attr(not(windows), allow(dead_code))]
const MAX_ENTRIES_PER_DIR: usize = 512;

impl DirProbe for RealDirProbe {
    fn exists(&self, path: &Path) -> bool {
        path.symlink_metadata().is_ok()
    }
    fn entries(&self, dir: &Path) -> Vec<EntryInfo> {
        let Ok(rd) = std::fs::read_dir(dir) else {
            return Vec::new();
        };
        rd.take(MAX_ENTRIES_PER_DIR)
            .flatten()
            .filter_map(|e| {
                let meta = e.path().symlink_metadata().ok()?;
                if meta.file_type().is_symlink() || is_reparse_point(&meta) {
                    return None;
                }
                let modified_unix = meta
                    .modified()
                    .ok()?
                    .duration_since(std::time::UNIX_EPOCH)
                    .ok()?
                    .as_secs() as i64;
                Some(EntryInfo {
                    name: e.file_name().into_string().ok()?,
                    is_dir: meta.is_dir(),
                    modified_unix,
                })
            })
            .collect()
    }
}

#[cfg(windows)]
fn is_reparse_point(meta: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    meta.file_attributes() & 0x400 != 0
}

#[cfg(not(windows))]
#[allow(dead_code)]
fn is_reparse_point(_meta: &std::fs::Metadata) -> bool {
    false
}

// ── Cold directories ──────────────────────────────────────────────────────────

/// A directory a decoy may go into, with what made it a fit.
#[derive(Debug, Clone, PartialEq)]
pub struct ColdDir {
    pub path: PathBuf,
    /// Newest write of any direct child (unix seconds).
    pub newest_unix: i64,
    /// Oldest write of any direct child (unix seconds).
    pub oldest_unix: i64,
    pub file_names: Vec<String>,
    /// Lowercased folder name hints a role (e.g. "it", "server", "admin").
    pub topical: bool,
}

/// Folder names that make credentials plausible in them.
const TOPICAL_DIR_WORDS: &[&str] = &[
    "it",
    "admin",
    "server",
    "infra",
    "netzwerk",
    "network",
    "projekte",
    "projects",
    "kunden",
    "customers",
    "archiv",
    "archive",
    "backup",
    "doku",
    "docs",
    "dokumentation",
    "setup",
    "install",
    "migration",
    "vpn",
    "zugang",
    "access",
    "scripts",
    "tools",
];

/// Directories never used for decoys, wherever they appear (lowercase names).
const EXCLUDED_DIR_NAMES: &[&str] = &[
    "desktop",
    "downloads",
    "appdata",
    "onedrive",
    "dropbox",
    "nextcloud",
    "google drive",
    "icloud drive",
    "my music",
    "my pictures",
    "my videos",
    "eigene musik",
    "eigene bilder",
    "eigene videos",
    "node_modules",
    ".git",
    "bin",
    "obj",
    "target",
    ".vs",
];

/// Find cold, plausible directories below `root`.
///
/// A candidate directory:
///   * holds at least two files (a folder someone actually used),
///   * has no direct child written within [`COLD_AFTER_DAYS`],
///   * is not hot according to activity learning (when available),
///   * lies outside every synced root and every excluded folder.
pub fn cold_dirs(
    root: &Path,
    synced_roots: &[PathBuf],
    hot_dirs: &BTreeSet<String>,
    now_unix: i64,
    fs: &dyn DirProbe,
) -> Vec<ColdDir> {
    let mut out = Vec::new();
    let mut queue = vec![(root.to_path_buf(), 0usize)];
    let mut visited = 0usize;
    while let Some((dir, depth)) = queue.pop() {
        visited += 1;
        if visited > MAX_DIRS {
            break;
        }
        if synced_roots.iter().any(|s| dir.starts_with(s)) {
            continue;
        }
        let entries = fs.entries(&dir);
        let files: Vec<&EntryInfo> = entries.iter().filter(|e| !e.is_dir).collect();
        if depth > 0 && files.len() >= 2 {
            let newest = files.iter().map(|f| f.modified_unix).max().unwrap_or(0);
            let oldest = files.iter().map(|f| f.modified_unix).min().unwrap_or(0);
            let key = dir.to_string_lossy().to_lowercase();
            if now_unix - newest >= COLD_AFTER_DAYS * 86_400 && !hot_dirs.contains(&key) {
                let name = dir
                    .file_name()
                    .map(|n| n.to_string_lossy().to_lowercase())
                    .unwrap_or_default();
                let topical = name
                    .split(|c: char| !c.is_alphanumeric())
                    .any(|w| TOPICAL_DIR_WORDS.contains(&w));
                out.push(ColdDir {
                    path: dir.clone(),
                    newest_unix: newest,
                    oldest_unix: oldest,
                    file_names: files.iter().map(|f| f.name.clone()).collect(),
                    topical,
                });
            }
        }
        if depth < MAX_DEPTH {
            for e in entries.iter().filter(|e| e.is_dir) {
                let lower = e.name.to_lowercase();
                if lower.starts_with('.') || EXCLUDED_DIR_NAMES.contains(&lower.as_str()) {
                    continue;
                }
                queue.push((dir.join(&e.name), depth + 1));
            }
        }
    }
    // Stable order: topical first, then the coldest.
    out.sort_by(|a, b| {
        b.topical
            .cmp(&a.topical)
            .then(a.newest_unix.cmp(&b.newest_unix))
            .then(a.path.cmp(&b.path))
    });
    out
}

// ── Candidates ────────────────────────────────────────────────────────────────

/// What the backend sees: a proposal without any local path or file name
/// (the wire types live with the recon profile schema).
pub use super::profiler::{
    RoleSignalWire as UserRoleSignals, WindowsCandidateWire as WindowsDecoyCandidate,
};

pub fn candidate_id(sid: &str, kind: &str) -> String {
    let digest = Sha256::digest(format!("trapd-windows-decoy|{sid}|{kind}").as_bytes());
    format!("wd_{}", &hex::encode(digest)[..20])
}

/// Where a kind would go for this user, and how risky that place is.
#[derive(Debug, Clone, PartialEq)]
pub struct Placement {
    pub dir: PathBuf,
    /// Accidental-access risk 0–100 (lower is better).
    pub risk: u8,
    /// Sibling files (for naming and timestamp mimicry).
    pub neighbors: Vec<String>,
    pub newest_unix: i64,
    pub oldest_unix: i64,
}

/// Input for the profiler, per host.
pub struct ProfilerInput<'a> {
    pub users: &'a [WindowsUserProfile],
    pub software: &'a [String],
    pub activity: &'a BTreeMap<String, UserActivitySummary>,
    pub now_unix: i64,
}

/// The documents root of a user (redirected folder if known).
fn documents_root(user: &WindowsUserProfile) -> PathBuf {
    user.documents_dir
        .as_deref()
        .map(PathBuf::from)
        .unwrap_or_else(|| join_win(Path::new(&user.profile_dir), "Documents"))
}

/// A folder redirected to a share (`\\server\…`) has no local audit trail.
fn is_local_path(p: &Path) -> bool {
    let s = p.to_string_lossy();
    !(s.starts_with("\\\\") || s.starts_with("//"))
}

/// Resolve the best local placement for `spec` and `user`.
pub fn resolve_placement(
    spec: &KindSpec,
    user: &WindowsUserProfile,
    activity: Option<&UserActivitySummary>,
    now_unix: i64,
    fs: &dyn DirProbe,
) -> Option<Placement> {
    let synced: Vec<PathBuf> = user.synced_roots.iter().map(PathBuf::from).collect();
    let hot = activity.map(|a| a.hot_dirs.clone()).unwrap_or_default();
    let profile = Path::new(&user.profile_dir);
    match spec.location {
        LocationClass::CloudConfig => {
            let dir = join_win(profile, ".aws");
            if !fs.exists(&dir) || synced.iter().any(|s| dir.starts_with(s)) {
                return None;
            }
            let entries = fs.entries(&dir);
            let files: Vec<&EntryInfo> = entries.iter().filter(|e| !e.is_dir).collect();
            // The real `credentials`/`config` must be there: the backup is
            // only plausible next to them.
            if !files.iter().any(|f| {
                f.name.eq_ignore_ascii_case("credentials") || f.name.eq_ignore_ascii_case("config")
            }) {
                return None;
            }
            Some(Placement {
                dir,
                // The CLI reads `credentials`, never `*.bak`: low risk.
                risk: 15,
                neighbors: files.iter().map(|f| f.name.clone()).collect(),
                newest_unix: files
                    .iter()
                    .map(|f| f.modified_unix)
                    .max()
                    .unwrap_or(now_unix),
                oldest_unix: files
                    .iter()
                    .map(|f| f.modified_unix)
                    .min()
                    .unwrap_or(now_unix),
            })
        }
        LocationClass::ColdProject => {
            let repos = join_win(profile, "source\\repos");
            let roots = [repos, documents_root(user)];
            roots
                .iter()
                .filter(|r| is_local_path(r) && fs.exists(r))
                .flat_map(|r| cold_dirs(r, &synced, &hot, now_unix, fs))
                .find(|d| looks_like_project(&d.file_names))
                .map(|d| placement_from(d, 20))
        }
        LocationClass::ColdDocuments => {
            let docs = documents_root(user);
            if !is_local_path(&docs)
                || !fs.exists(&docs)
                || synced.iter().any(|s| docs.starts_with(s))
            {
                return None;
            }
            cold_dirs(&docs, &synced, &hot, now_unix, fs)
                .into_iter()
                .next()
                .map(|d| {
                    let risk = if d.topical { 15 } else { 25 };
                    placement_from(d, risk)
                })
        }
    }
}

fn placement_from(d: ColdDir, risk: u8) -> Placement {
    Placement {
        dir: d.path,
        risk,
        neighbors: d.file_names,
        newest_unix: d.newest_unix,
        oldest_unix: d.oldest_unix,
    }
}

fn looks_like_project(files: &[String]) -> bool {
    files.iter().any(|f| {
        let l = f.to_ascii_lowercase();
        l.ends_with(".sln")
            || l.ends_with(".csproj")
            || l == "package.json"
            || l == "program.cs"
            || l == "readme.md"
            || l == "dockerfile"
            || l.ends_with(".py")
            || l == "pom.xml"
    })
}

/// Score and collect every plausible candidate for the host.
pub fn build_candidates(
    input: &ProfilerInput<'_>,
    fs: &dyn DirProbe,
) -> (Vec<WindowsDecoyCandidate>, Vec<UserRoleSignals>) {
    let mut candidates = Vec::new();
    let mut signals = Vec::new();
    for user in input
        .users
        .iter()
        .filter(|u| is_human_profile(u, input.now_unix))
    {
        let activity = input.activity.get(&user.name.to_lowercase());
        let evidence = role_evidence(user, input.software, activity, fs);
        signals.push(UserRoleSignals {
            user: user.name.clone(),
            roles: evidence
                .roles()
                .into_iter()
                .filter(|r| evidence.of(*r) >= 40)
                .map(|r| r.as_str().to_string())
                .collect(),
        });
        for spec in WINDOWS_KINDS {
            let Some((role, fit)) = spec
                .roles
                .iter()
                .map(|r| (*r, evidence.of(*r)))
                .max_by_key(|(_, s)| *s)
            else {
                continue;
            };
            // Fidelity rule: weak host-wide evidence alone is not enough for
            // role-specific bait; the generic office kinds may use it.
            let min_fit = if spec.roles.contains(&Role::Office) {
                30
            } else {
                60
            };
            if fit < min_fit {
                continue;
            }
            let Some(place) = resolve_placement(spec, user, activity, input.now_unix, fs) else {
                continue;
            };
            let score = (spec.attractiveness as u32 * fit as u32 * (100 - place.risk as u32)
                / 10_000) as u8;
            let mut rationale = evidence.reasons.get(&role).cloned().unwrap_or_default();
            rationale.push(format!(
                "placement: {} directory untouched for {}+ days",
                spec.location.as_str(),
                (input.now_unix - place.newest_unix) / 86_400
            ));
            candidates.push(WindowsDecoyCandidate {
                id: candidate_id(&user.sid, spec.kind),
                kind: spec.kind.to_string(),
                user: user.name.clone(),
                location_class: spec.location.as_str().to_string(),
                score,
                mitre_technique: spec.mitre.to_string(),
                rationale,
            });
        }
    }
    candidates.sort_by(|a, b| b.score.cmp(&a.score).then(a.id.cmp(&b.id)));
    (candidates, signals)
}

/// The concrete file for an approved candidate: directory, name and the
/// timestamp to mimic. `taken` lists names that already exist in the directory.
#[derive(Debug, Clone, PartialEq)]
pub struct ResolvedDecoy {
    pub path: PathBuf,
    /// Plausible last-write time (unix seconds) inside the neighbours' range.
    pub mimic_unix: i64,
}

/// Choose a file name for `spec` in `place`, in the user's naming style.
pub fn resolve_file(
    spec: &KindSpec,
    place: &Placement,
    style: &NamingStyle,
    pick: u64,
) -> Option<ResolvedDecoy> {
    let taken: BTreeSet<String> = place.neighbors.iter().map(|n| n.to_lowercase()).collect();
    let date_unix = mimic_time(place, pick);
    let candidates = super::naming::file_names_for(spec.kind, style, date_unix, pick);
    let name = candidates
        .into_iter()
        .find(|n| !taken.contains(&n.to_lowercase()))?;
    Some(ResolvedDecoy {
        path: place.dir.join(name),
        mimic_unix: date_unix,
    })
}

/// A write time between the oldest and newest neighbour, never in the future.
fn mimic_time(place: &Placement, pick: u64) -> i64 {
    let lo = place.oldest_unix.min(place.newest_unix);
    let hi = place.newest_unix.max(lo);
    if hi == lo {
        return lo;
    }
    lo + (pick % (hi - lo) as u64) as i64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deception::activity::UserActivitySummary;

    const DAY: i64 = 86_400;
    const NOW: i64 = 1_790_000_000;

    /// In-memory tree: path → entries.
    #[derive(Default)]
    struct MemFs {
        dirs: BTreeMap<PathBuf, Vec<EntryInfo>>,
        files: BTreeSet<PathBuf>,
    }

    impl MemFs {
        fn dir(&mut self, path: &str) -> &mut Self {
            let p = PathBuf::from(path);
            let mut cur = PathBuf::new();
            for c in p.components() {
                let parent = cur.clone();
                cur.push(c);
                if parent.as_os_str().is_empty() {
                    continue;
                }
                let name = c.as_os_str().to_string_lossy().to_string();
                let list = self.dirs.entry(parent).or_default();
                if !list.iter().any(|e| e.name == name) {
                    list.push(EntryInfo {
                        name,
                        is_dir: true,
                        modified_unix: NOW - 400 * DAY,
                    });
                }
            }
            self.dirs.entry(p).or_default();
            self
        }
        fn file(&mut self, dir: &str, name: &str, age_days: i64) -> &mut Self {
            self.dir(dir);
            self.dirs
                .get_mut(&PathBuf::from(dir))
                .unwrap()
                .push(EntryInfo {
                    name: name.into(),
                    is_dir: false,
                    modified_unix: NOW - age_days * DAY,
                });
            self.files.insert(PathBuf::from(dir).join(name));
            self
        }
    }

    impl DirProbe for MemFs {
        fn exists(&self, path: &Path) -> bool {
            self.dirs.contains_key(path) || self.files.contains(path)
        }
        fn entries(&self, dir: &Path) -> Vec<EntryInfo> {
            self.dirs.get(dir).cloned().unwrap_or_default()
        }
    }

    fn user(name: &str) -> WindowsUserProfile {
        WindowsUserProfile {
            name: name.into(),
            sid: format!("S-1-5-21-1-2-3-{}", 1000 + name.len()),
            profile_dir: format!("/Users/{name}"),
            last_use_unix: Some(NOW - DAY),
            ..Default::default()
        }
    }

    #[test]
    fn only_recent_real_accounts_are_human() {
        assert!(is_human_profile(&user("anna"), NOW));
        let mut svc = user("svc");
        svc.sid = "S-1-5-80-123".into();
        assert!(!is_human_profile(&svc, NOW));
        let mut sys = user("system");
        sys.sid = "S-1-5-18".into();
        assert!(!is_human_profile(&sys, NOW));
        assert!(!is_human_profile(&user("defaultuser0"), NOW));
        assert!(!is_human_profile(&user("WDAGUtilityAccount"), NOW));
        let mut stale = user("old");
        stale.last_use_unix = Some(NOW - 200 * DAY);
        assert!(!is_human_profile(&stale, NOW));
        let mut unc = user("roam");
        unc.profile_dir = "\\\\fs01\\profiles\\roam".into();
        assert!(!is_human_profile(&unc, NOW));
    }

    #[test]
    fn profile_helpers() {
        assert_eq!(
            expand_user_path("%USERPROFILE%\\Documents", "C:\\Users\\anna").as_deref(),
            Some("C:\\Users\\anna\\Documents")
        );
        assert_eq!(
            expand_user_path("%OneDrive%\\Documents", "C:\\Users\\anna"),
            None
        );
        let roots = synced_roots_from_children(
            "/Users/anna",
            &[
                "OneDrive - Contoso GmbH".into(),
                "Dropbox".into(),
                "Documents".into(),
                "OneDriveX".into(),
                "Boxes".into(),
            ],
        );
        assert_eq!(
            roots,
            vec![
                "/Users/anna/OneDrive - Contoso GmbH".to_string(),
                "/Users/anna/Dropbox".to_string()
            ]
        );
        // 2020-01-01T00:00:00Z = 132223104000000000 ticks.
        let t: u64 = 132_223_104_000_000_000;
        assert_eq!(
            filetime_to_unix((t >> 32) as u32, t as u32),
            Some(1_577_836_800)
        );
        assert_eq!(filetime_to_unix(0, 0), None);
    }

    #[test]
    fn git_does_not_match_digital() {
        assert!(contains_word("git version 2.44", "git"));
        assert!(contains_word("git", "git"));
        assert!(!contains_word("digital editions", "git"));
        assert!(!contains_word("gitkraken", "git"));
    }

    #[test]
    fn cold_dirs_skip_hot_synced_desktop_and_sparse_folders() {
        let mut fs = MemFs::default();
        fs.file("/Users/anna/Documents/IT Doku", "Netzplan.vsdx", 120)
            .file("/Users/anna/Documents/IT Doku", "Server-Liste.xlsx", 90)
            .file("/Users/anna/Documents/Aktuell", "Angebot.docx", 2)
            .file("/Users/anna/Documents/Aktuell", "Notizen.txt", 1)
            .file("/Users/anna/Documents/Leer", "eine.txt", 300)
            .file("/Users/anna/Documents/OneDrive/Alt", "a.txt", 300)
            .file("/Users/anna/Documents/OneDrive/Alt", "b.txt", 300)
            .file("/Users/anna/Documents/Kunden", "k1.txt", 60)
            .file("/Users/anna/Documents/Kunden", "k2.txt", 50);
        let docs = PathBuf::from("/Users/anna/Documents");
        let dirs = cold_dirs(&docs, &[], &BTreeSet::new(), NOW, &fs);
        let names: Vec<String> = dirs
            .iter()
            .map(|d| d.path.file_name().unwrap().to_string_lossy().into())
            .collect();
        assert_eq!(
            names,
            vec!["IT Doku", "Kunden"],
            "topical cold dirs only, IT first: {names:?}"
        );

        // Activity marks a dir hot even when its files look old.
        let hot: BTreeSet<String> = ["/users/anna/documents/it doku".to_string()].into();
        let dirs = cold_dirs(&docs, &[], &hot, NOW, &fs);
        assert!(dirs.iter().all(|d| !d.path.ends_with("IT Doku")));

        // A synced root excludes everything below it.
        let dirs = cold_dirs(&docs, &[docs.join("Kunden")], &BTreeSet::new(), NOW, &fs);
        assert!(dirs.iter().all(|d| !d.path.ends_with("Kunden")));
    }

    #[test]
    fn candidates_require_role_evidence_and_a_cold_place() {
        let mut fs = MemFs::default();
        fs.file("/Users/anna/Documents/IT", "router.txt", 100)
            .file("/Users/anna/Documents/IT", "switch.txt", 80)
            .dir("/Users/anna/AppData/Roaming/FileZilla");
        let users = [user("anna")];
        let activity = BTreeMap::new();
        let input = ProfilerInput {
            users: &users,
            software: &[],
            activity: &activity,
            now_unix: NOW,
        };
        let (cands, signals) = build_candidates(&input, &fs);
        let kinds: BTreeSet<&str> = cands.iter().map(|c| c.kind.as_str()).collect();
        assert!(kinds.contains("filezilla_sitemanager"), "{kinds:?}");
        assert!(kinds.contains("password_note"));
        // No developer, cloud or db evidence → no such bait.
        assert!(!kinds.contains("appsettings_json"));
        assert!(!kinds.contains("aws_credentials_backup"));
        assert!(!kinds.contains("db_connection_notes"));
        assert!(signals[0].roles.contains(&"admin_tooling".to_string()));
        // Rationale never carries the user's own folder names.
        for c in &cands {
            assert!(
                c.rationale
                    .iter()
                    .all(|r| !r.contains("IT") && !r.contains("router")),
                "{:?}",
                c.rationale
            );
            assert_eq!(c.id, candidate_id(&users[0].sid, &c.kind));
        }
    }

    #[test]
    fn host_software_alone_does_not_justify_role_specific_bait() {
        let mut fs = MemFs::default();
        fs.file("/Users/anna/Documents/Archiv", "a.txt", 100).file(
            "/Users/anna/Documents/Archiv",
            "b.txt",
            100,
        );
        let users = [user("anna")];
        let activity = BTreeMap::new();
        let software = vec!["WinSCP 6.3".to_string()];
        let input = ProfilerInput {
            users: &users,
            software: &software,
            activity: &activity,
            now_unix: NOW,
        };
        let (cands, _) = build_candidates(&input, &fs);
        assert!(cands.iter().all(|c| c.kind != "winscp_ini"));

        // Learned usage turns it into strong evidence.
        let mut activity = BTreeMap::new();
        let mut a = UserActivitySummary::default();
        a.tool_uses.insert("winscp.exe".into(), 7);
        activity.insert("anna".to_string(), a);
        let input = ProfilerInput {
            users: &users,
            software: &software,
            activity: &activity,
            now_unix: NOW,
        };
        let (cands, _) = build_candidates(&input, &fs);
        let winscp = cands
            .iter()
            .find(|c| c.kind == "winscp_ini")
            .expect("winscp candidate");
        assert!(winscp.rationale.iter().any(|r| r.contains("winscp.exe")));
    }

    #[test]
    fn aws_backup_only_next_to_a_real_cli_config() {
        let mut fs = MemFs::default();
        fs.dir("/Users/anna/.aws");
        let spec = kind_spec("aws_credentials_backup").unwrap();
        assert!(resolve_placement(spec, &user("anna"), None, NOW, &fs).is_none());
        fs.file("/Users/anna/.aws", "credentials", 30);
        let p = resolve_placement(spec, &user("anna"), None, NOW, &fs).unwrap();
        assert_eq!(p.dir, PathBuf::from("/Users/anna/.aws"));
    }

    #[test]
    fn project_bait_needs_a_cold_project_folder() {
        let mut fs = MemFs::default();
        fs.file("/Users/dev/source/repos/Billing", "Billing.sln", 90)
            .file("/Users/dev/source/repos/Billing", "README.md", 90)
            .file("/Users/dev/source/repos/Current", "Current.sln", 1)
            .file("/Users/dev/source/repos/Current", "README.md", 1);
        let spec = kind_spec("env_file").unwrap();
        let p = resolve_placement(spec, &user("dev"), None, NOW, &fs).unwrap();
        assert!(p.dir.ends_with("Billing"));
    }

    #[test]
    fn redirected_or_synced_documents_are_refused() {
        let mut fs = MemFs::default();
        fs.file("/Users/anna/OneDrive/Documents/IT", "a.txt", 100)
            .file("/Users/anna/OneDrive/Documents/IT", "b.txt", 100);
        let mut u = user("anna");
        u.documents_dir = Some("/Users/anna/OneDrive/Documents".into());
        u.synced_roots = vec!["/Users/anna/OneDrive".into()];
        let spec = kind_spec("password_note").unwrap();
        assert!(resolve_placement(spec, &u, None, NOW, &fs).is_none());
        u.documents_dir = Some("\\\\fs01\\home\\anna".into());
        u.synced_roots.clear();
        assert!(resolve_placement(spec, &u, None, NOW, &fs).is_none());
    }

    #[test]
    fn resolved_file_avoids_collisions_and_stays_in_the_neighbour_range() {
        let place = Placement {
            dir: PathBuf::from("/Users/anna/Documents/IT"),
            risk: 15,
            neighbors: vec!["WinSCP.ini".into()],
            newest_unix: NOW - 30 * DAY,
            oldest_unix: NOW - 300 * DAY,
        };
        let spec = kind_spec("winscp_ini").unwrap();
        let style = NamingStyle::default();
        let r = resolve_file(spec, &place, &style, 12345).unwrap();
        assert_ne!(
            r.path.file_name().unwrap().to_string_lossy().to_lowercase(),
            "winscp.ini"
        );
        assert!(r.mimic_unix >= place.oldest_unix && r.mimic_unix <= place.newest_unix);
    }
}
