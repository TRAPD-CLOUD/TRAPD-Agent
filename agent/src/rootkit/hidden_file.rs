//! Files and directories that exist but do not appear in their own directory.
//!
//! Hiding a file is the most common thing a rootkit does, and it is done by
//! filtering directory reads — `getdents64` in the kernel, or `readdir` in libc
//! for a userland rootkit installed through `/etc/ld.so.preload`. The file is
//! still there: opening it, stat-ing it or reading its parent's link count all
//! go through different code paths and still tell the truth. Three checks
//! exploit exactly that.
//!
//! ## 1. Directory link count vs. the subdirectories that are listed
//!
//! A directory's `st_nlink` is `2` (for `.` and `..`) plus one per
//! subdirectory, maintained by the filesystem as an inode field — not by the
//! code that answers directory reads. If the listing shows fewer
//! subdirectories than the link count accounts for, subdirectories are being
//! filtered out. This check needs **no candidate name at all**, which makes it
//! the only one that can find a directory nobody has touched.
//!
//! It is only run on filesystems that maintain the invariant (ext2/3/4, XFS,
//! tmpfs). btrfs reports `1` for every directory, and overlayfs — what a
//! container's root usually is — does not maintain it reliably; on those the
//! check is skipped rather than allowed to fire constantly.
//!
//! ## 2. libc `readdir` vs. the raw `getdents64` syscall
//!
//! The same directory is enumerated twice through deliberately different code:
//! once via libc (`opendir`/`readdir`, what almost every tool uses, and what an
//! `LD_PRELOAD` rootkit interposes) and once by issuing `getdents64` directly.
//! A name the syscall returns and libc does not means libc is lying, which
//! localises the compromise to userspace.
//!
//! ## 3. A known name vs. its parent's listing
//!
//! Given a name, `lstat` answers directly and never consults the directory
//! listing. So a file that stats successfully but is absent from its parent's
//! listing is hidden. The whole difficulty is *getting* the name, because a
//! filtered listing will not supply it. Three sources do:
//!
//! * paths the eBPF collectors saw being written, created, unlinked or renamed,
//!   observed at the tracepoint layer below anything userspace can hook;
//! * the targets of every open file descriptor in `/proc/<pid>/fd`, which name
//!   a hidden file that is currently open — rootkits keep theirs open;
//! * the file-backed regions in `/proc/<pid>/maps`, which name a hidden shared
//!   library that is currently mapped.
//!
//! ## Races, not rootkits
//!
//! Files are created and deleted constantly, and both look like concealment if
//! sampled carelessly. Every candidate is therefore `lstat`-ed **before and
//! after** the parent listing is read, and only reported when both calls
//! succeed with the same inode. That proves the file existed for the entire
//! window in which the listing was taken, so its absence from that listing
//! cannot be explained by timing.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use serde_json::json;

use super::kernel_view::PathSighting;
use super::{Confirmation, Finding, RootkitConfig};
use crate::schema::Severity;

/// Directories checked when nothing else is configured: where system binaries
/// and configuration live, plus the world-writable directories that are the
/// usual landing spots for dropped files.
pub const DEFAULT_ROOTS: &[&str] = &[
    "/etc",
    "/bin",
    "/sbin",
    "/lib",
    "/usr/bin",
    "/usr/sbin",
    "/usr/lib",
    "/usr/local",
    "/boot",
    "/root",
    "/tmp",
    "/var/tmp",
    "/dev/shm",
];

/// A discrepancy count this large is a broken assumption, not a rootkit, and is
/// collapsed into a single quiet finding instead of a storm of critical ones.
const BULK_THRESHOLD: usize = 25;

/// Names listed in evidence before it is truncated.
const EVIDENCE_NAMES: usize = 20;

/// One directory, enumerated through both interfaces.
#[derive(Debug, Default, Clone)]
pub struct DirectoryViews {
    pub path: PathBuf,
    /// Entry names as libc `readdir` reports them.
    pub libc: BTreeSet<Vec<u8>>,
    /// Entry names as a direct `getdents64` reports them.
    pub syscall: BTreeSet<Vec<u8>>,
    /// `st_nlink` of the directory, when the filesystem maintains it as a
    /// subdirectory count and every entry's type was resolved.
    pub nlink: Option<u64>,
    /// Subdirectories seen in the `getdents64` view.
    pub subdirs: usize,
}

/// A candidate name, before it has been looked up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateName {
    /// Where the name came from: `ebpf`, `proc_fd` or `proc_maps`.
    pub source: &'static str,
    /// Command name of the process that revealed the path, when known.
    pub revealed_by: Option<String>,
    /// For eBPF sightings, the operation that revealed it.
    pub operation: Option<&'static str>,
}

/// A candidate name, resolved against its parent's listing.
#[derive(Debug, Clone)]
pub struct ResolvedCandidate {
    pub path: PathBuf,
    pub name: CandidateName,
    pub inode: u64,
    /// Whether the parent's listing contains the name.
    pub listed: bool,
}

/// What the sweep managed to look at, so an empty result can be distinguished
/// from a sweep that never got off the ground.
#[derive(Debug, Default, Clone)]
pub struct FileScanSummary {
    pub directories: usize,
    /// Directories where the link-count invariant was applicable.
    pub nlink_checked: usize,
    pub candidates: usize,
    /// True when the directory cap stopped the walk early.
    pub truncated: bool,
}

/// Compare the views and return the disagreements.
pub fn analyze(dirs: &[DirectoryViews], candidates: &[ResolvedCandidate]) -> Vec<Finding> {
    let mut out = Vec::new();
    out.extend(libc_filtering_findings(dirs));
    out.extend(link_count_findings(dirs));
    out.extend(candidate_findings(candidates));
    out
}

/// Names the raw syscall returns that libc does not.
///
/// The reverse direction is not reported: libc reads the directory in chunks
/// and can legitimately observe an entry created after the syscall read.
fn libc_filtering_findings(dirs: &[DirectoryViews]) -> Vec<Finding> {
    let mut out = Vec::new();
    for dir in dirs {
        let hidden: Vec<&Vec<u8>> = dir.syscall.difference(&dir.libc).collect();
        if hidden.is_empty() {
            continue;
        }
        out.push(Finding {
            rule_id: "rootkit.dir_entry_hidden_from_libc",
            title: "Directory entries returned by getdents64 but withheld by libc readdir",
            confirmation: Confirmation::Corroborate,
            severity: Severity::Critical,
            confidence: 85,
            mitre_tactic: "TA0005 Defense Evasion",
            mitre_technique: "T1014",
            subject: format!("dir:{}", dir.path.display()),
            detail: format!(
                "{} entr{} of {} are returned by the getdents64 syscall but not by libc's \
                 readdir. The kernel and the C library disagree about the contents of a \
                 directory, which is what a preloaded library that filters readdir looks like.",
                hidden.len(),
                if hidden.len() == 1 { "y" } else { "ies" },
                dir.path.display()
            ),
            evidence: json!({
                "directory": dir.path.display().to_string(),
                "hidden_count": hidden.len(),
                "hidden_entries": render_names(hidden.iter().copied()),
                "views": { "getdents64": dir.syscall.len(), "libc_readdir": dir.libc.len() },
            }),
        });
    }
    out
}

/// Subdirectories the inode's link count accounts for but the listing omits.
///
/// Only a *deficit* is reported. A surplus means the filesystem does not
/// maintain the invariant the way this check assumes, which is a reason to
/// distrust the check rather than the host.
fn link_count_findings(dirs: &[DirectoryViews]) -> Vec<Finding> {
    let mut out = Vec::new();
    for dir in dirs {
        let Some(nlink) = dir.nlink else { continue };
        let accounted = nlink.saturating_sub(2) as usize;
        if accounted <= dir.subdirs {
            continue;
        }
        let missing = accounted - dir.subdirs;
        out.push(Finding {
            rule_id: "rootkit.subdirectory_hidden_from_listing",
            title: "Directory link count accounts for more subdirectories than are listed",
            confirmation: Confirmation::Corroborate,
            severity: Severity::Critical,
            confidence: 80,
            mitre_tactic: "TA0005 Defense Evasion",
            mitre_technique: "T1014",
            subject: format!("dir:{}", dir.path.display()),
            detail: format!(
                "{} has a link count of {}, which accounts for {} subdirector{}, but only {} \
                 appear when it is read. {} subdirector{} is present in the inode and absent \
                 from every listing of it.",
                dir.path.display(),
                nlink,
                accounted,
                if accounted == 1 { "y" } else { "ies" },
                dir.subdirs,
                missing,
                if missing == 1 { "y" } else { "ies" },
            ),
            evidence: json!({
                "directory": dir.path.display().to_string(),
                "nlink": nlink,
                "subdirectories_accounted": accounted,
                "subdirectories_listed": dir.subdirs,
                "missing": missing,
            }),
        });
    }
    out
}

/// Candidates that stat successfully and are absent from their parent's listing.
fn candidate_findings(candidates: &[ResolvedCandidate]) -> Vec<Finding> {
    let hidden: Vec<&ResolvedCandidate> = candidates.iter().filter(|c| !c.listed).collect();
    if hidden.is_empty() {
        return Vec::new();
    }

    // A whole directory tree's worth of "hidden" files means the comparison
    // itself is wrong — an unusual filesystem, a bind mount shadowing a
    // directory — not that a rootkit hid a thousand files one by one.
    if hidden.len() > BULK_THRESHOLD {
        return vec![Finding {
            rule_id: "rootkit.file_listing_inconsistent",
            title: "Many known paths are absent from their directory listings",
            confirmation: Confirmation::Corroborate,
            severity: Severity::Low,
            confidence: 30,
            mitre_tactic: "TA0005 Defense Evasion",
            mitre_technique: "T1014",
            subject: "host".to_string(),
            detail: format!(
                "{} paths that stat successfully are missing from their parent directory \
                 listings. At this scale the likeliest cause is a filesystem whose listings \
                 this check cannot compare rather than deliberate concealment, so it is \
                 reported once for review instead of as individual hidden files.",
                hidden.len()
            ),
            evidence: json!({
                "count": hidden.len(),
                "examples": hidden
                    .iter()
                    .take(EVIDENCE_NAMES)
                    .map(|c| c.path.display().to_string())
                    .collect::<Vec<_>>(),
            }),
        }];
    }

    hidden
        .into_iter()
        .map(|c| Finding {
            rule_id: "rootkit.file_hidden_from_listing",
            title: "File exists and is readable but does not appear in its directory",
            confirmation: Confirmation::Corroborate,
            severity: Severity::Critical,
            confidence: 90,
            mitre_tactic: "TA0005 Defense Evasion",
            mitre_technique: "T1014",
            subject: format!("path:{}", c.path.display()),
            detail: format!(
                "{} can be stat-ed directly, with the same inode ({}) before and after the \
                 directory was read, yet its name is absent from that listing. Directory \
                 reads are being filtered for this entry — the file is hidden, not gone. \
                 The name was recovered from {}.",
                c.path.display(),
                c.inode,
                describe_source(&c.name),
            ),
            evidence: json!({
                "path": c.path.display().to_string(),
                "inode": c.inode,
                "name_source": c.name.source,
                "kernel_operation": c.name.operation,
                "revealed_by": c.name.revealed_by,
                "views": { "lstat": true, "parent_listing": false },
            }),
        })
        .collect()
}

fn describe_source(name: &CandidateName) -> String {
    match (name.source, name.operation) {
        ("ebpf", Some(op)) => format!("an eBPF-observed {op} at the syscall layer"),
        ("ebpf", None) => "an eBPF syscall-layer observation".to_string(),
        ("proc_fd", _) => "an open file descriptor in /proc/<pid>/fd".to_string(),
        ("proc_maps", _) => "a file-backed mapping in /proc/<pid>/maps".to_string(),
        _ => "an independent path observation".to_string(),
    }
}

fn render_names<'a, I: Iterator<Item = &'a Vec<u8>>>(names: I) -> Vec<String> {
    names
        .take(EVIDENCE_NAMES)
        .map(|n| String::from_utf8_lossy(n).into_owned())
        .collect()
}

// ── Directory enumeration ───────────────────────────────────────────────────

/// Parse a `getdents64` buffer into `(name, d_type)` pairs, skipping `.`/`..`.
///
/// The kernel packs variable-length records, so a record whose declared length
/// does not fit the buffer ends the parse rather than being read past.
pub fn parse_dirents64(buf: &[u8]) -> Vec<(Vec<u8>, u8)> {
    // struct linux_dirent64 { u64 d_ino; i64 d_off; u16 d_reclen; u8 d_type; char d_name[]; }
    const NAME_OFFSET: usize = 19;
    let mut out = Vec::new();
    let mut off = 0usize;
    while off + NAME_OFFSET <= buf.len() {
        let reclen = u16::from_ne_bytes([buf[off + 16], buf[off + 17]]) as usize;
        if reclen < NAME_OFFSET || off + reclen > buf.len() {
            break;
        }
        let d_type = buf[off + 18];
        let raw = &buf[off + NAME_OFFSET..off + reclen];
        let end = raw.iter().position(|b| *b == 0).unwrap_or(raw.len());
        let name = &raw[..end];
        if !name.is_empty() && name != b"." && name != b".." {
            out.push((name.to_vec(), d_type));
        }
        off += reclen;
    }
    out
}

/// A directory fd that closes itself.
struct DirFd(i32);

impl Drop for DirFd {
    fn drop(&mut self) {
        // SAFETY: the fd was returned by open() and is owned exclusively here.
        unsafe { libc::close(self.0) };
    }
}

/// Open a directory for enumeration.
///
/// The walk passes `follow: false` so it cannot be redirected out of the tree
/// it was asked to check. Candidate resolution passes `follow: true`, because
/// the path it is checking is one a process really resolved — and on a
/// merged-`/usr` distribution `/bin` and `/lib` are symlinks, so refusing to
/// follow would skip most of the system.
fn open_dir(path: &Path, follow: bool) -> Option<DirFd> {
    let c = CString::new(path.as_os_str().as_bytes()).ok()?;
    let mut flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC;
    if !follow {
        flags |= libc::O_NOFOLLOW;
    }
    // SAFETY: `c` is a NUL-terminated path valid for the duration of the call.
    let fd = unsafe { libc::open(c.as_ptr(), flags) };
    (fd >= 0).then_some(DirFd(fd))
}

/// Enumerate a directory by issuing `getdents64` directly.
fn read_dir_syscall(path: &Path, follow: bool) -> Option<Vec<(Vec<u8>, u8)>> {
    let fd = open_dir(path, follow)?;
    let mut buf = vec![0u8; 32 * 1024];
    let mut out = Vec::new();
    loop {
        // SAFETY: `buf` is a live allocation of exactly the declared length.
        let n = unsafe {
            libc::syscall(
                libc::SYS_getdents64,
                fd.0,
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
            )
        };
        match n {
            0 => break,
            n if n < 0 => return None,
            n => out.extend(parse_dirents64(&buf[..n as usize])),
        }
    }
    Some(out)
}

/// Enumerate a directory through libc, which is what an `LD_PRELOAD` rootkit
/// interposes. `std::fs::read_dir` uses `opendir`/`readdir` underneath.
fn read_dir_libc(path: &Path) -> Option<BTreeSet<Vec<u8>>> {
    let entries = std::fs::read_dir(path).ok()?;
    Some(
        entries
            .flatten()
            .map(|e| e.file_name().as_bytes().to_vec())
            .collect(),
    )
}

// ── Filesystem classification ───────────────────────────────────────────────

const EXT_SUPER_MAGIC: i64 = 0xEF53;
const XFS_SUPER_MAGIC: i64 = 0x5846_5342;
const TMPFS_MAGIC: i64 = 0x0102_1994;

/// Filesystems whose directory `st_nlink` is a subdirectory count.
fn nlink_is_a_subdir_count(fs_type: i64) -> bool {
    matches!(fs_type, EXT_SUPER_MAGIC | XFS_SUPER_MAGIC | TMPFS_MAGIC)
}

/// Filesystems where a listing that differs from a direct lookup proves
/// nothing: the synthetic kernel trees, whose entries are generated per read,
/// and the filesystems whose contents are answered by something other than
/// local disk (a FUSE daemon, a remote server) and may be legitimately stale.
///
/// Overlayfs is deliberately **not** here. It is what a container's root
/// filesystem usually is, so excluding it would silently disable this whole
/// detector exactly where containers are concerned; its merged listing is a
/// real listing and `lstat` resolves through the same merge. Only its
/// directory link count is untrustworthy, which
/// [`nlink_is_a_subdir_count`] handles separately.
fn is_synthetic(fs_type: i64) -> bool {
    const PROC_SUPER_MAGIC: i64 = 0x9fa0;
    const SYSFS_MAGIC: i64 = 0x6265_6572;
    const CGROUP_SUPER_MAGIC: i64 = 0x0027_e0eb;
    const CGROUP2_SUPER_MAGIC: i64 = 0x6367_7270;
    const DEBUGFS_MAGIC: i64 = 0x6462_6720;
    const TRACEFS_MAGIC: i64 = 0x7472_6163;
    const DEVPTS_SUPER_MAGIC: i64 = 0x1cd1;
    const SECURITYFS_MAGIC: i64 = 0x7363_6673;
    const SELINUX_MAGIC: i64 = 0xf97c_ff8c;
    const BPF_FS_MAGIC: i64 = 0xcafe_4a11;
    const NSFS_MAGIC: i64 = 0x6e73_6673;
    const AUTOFS_SUPER_MAGIC: i64 = 0x0187;
    const FUSE_SUPER_MAGIC: i64 = 0x6573_5546;
    const NFS_SUPER_MAGIC: i64 = 0x6969;
    const CIFS_MAGIC: i64 = 0xff53_4d42;

    matches!(
        fs_type,
        PROC_SUPER_MAGIC
            | SYSFS_MAGIC
            | CGROUP_SUPER_MAGIC
            | CGROUP2_SUPER_MAGIC
            | DEBUGFS_MAGIC
            | TRACEFS_MAGIC
            | DEVPTS_SUPER_MAGIC
            | SECURITYFS_MAGIC
            | SELINUX_MAGIC
            | BPF_FS_MAGIC
            | NSFS_MAGIC
            | AUTOFS_SUPER_MAGIC
            | FUSE_SUPER_MAGIC
            | NFS_SUPER_MAGIC
            | CIFS_MAGIC
    )
}

fn fs_type(path: &Path) -> Option<i64> {
    let c = CString::new(path.as_os_str().as_bytes()).ok()?;
    let mut buf: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: `c` outlives the call and `buf` is a live, correctly sized statfs.
    if unsafe { libc::statfs(c.as_ptr(), &mut buf) } != 0 {
        return None;
    }
    Some(buf.f_type as i64)
}

/// `lstat`, returning the fields the checks need without following symlinks.
fn lstat(path: &Path) -> Option<libc::stat> {
    let c = CString::new(path.as_os_str().as_bytes()).ok()?;
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: `c` outlives the call and `st` is a live, correctly sized stat.
    if unsafe { libc::lstat(c.as_ptr(), &mut st) } != 0 {
        return None;
    }
    Some(st)
}

// ── Host collection ─────────────────────────────────────────────────────────

/// Walk the configured roots and resolve every candidate name.
pub fn gather(
    cfg: &RootkitConfig,
    kernel_paths: &[(String, PathSighting)],
) -> (Vec<DirectoryViews>, Vec<ResolvedCandidate>, FileScanSummary) {
    let mut summary = FileScanSummary::default();
    let mut dirs = Vec::new();

    for root in canonical_roots(&cfg.file_roots) {
        if dirs.len() >= cfg.dir_scan_max {
            summary.truncated = true;
            break;
        }
        walk(&root, cfg, &mut dirs, &mut summary);
    }
    summary.directories = dirs.len();
    summary.nlink_checked = dirs.iter().filter(|d| d.nlink.is_some()).count();

    let candidates = resolve_candidates(collect_candidate_names(kernel_paths));
    summary.candidates = candidates.len();

    (dirs, candidates, summary)
}

/// Resolve the configured roots and drop duplicates.
///
/// On a merged-`/usr` distribution `/bin`, `/sbin` and `/lib` are symlinks into
/// `/usr`, so the configured list names the same three trees twice. Resolving
/// first means the walk neither skips them (the walk does not follow symlinks)
/// nor covers them twice.
fn canonical_roots(roots: &[String]) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for root in roots {
        let resolved = std::fs::canonicalize(root).unwrap_or_else(|_| PathBuf::from(root));
        if !out.contains(&resolved) {
            out.push(resolved);
        }
    }
    out
}

/// Depth-first walk that stays on one filesystem and never follows a symlink.
///
/// Crossing a mount boundary would drag network and pseudo filesystems into a
/// comparison they cannot answer; a mount that appeared where it should not is
/// [`super::hidden_mount`]'s job, not this one's.
fn walk(
    root: &Path,
    cfg: &RootkitConfig,
    out: &mut Vec<DirectoryViews>,
    sum: &mut FileScanSummary,
) {
    let Some(root_st) = lstat(root) else { return };
    if root_st.st_mode & libc::S_IFMT != libc::S_IFDIR {
        return;
    }
    let Some(fs) = fs_type(root) else { return };
    if is_synthetic(fs) {
        return;
    }
    let device = root_st.st_dev;
    let nlink_meaningful = nlink_is_a_subdir_count(fs);

    let mut stack = vec![(root.to_path_buf(), 0usize)];
    while let Some((dir, depth)) = stack.pop() {
        if out.len() >= cfg.dir_scan_max {
            sum.truncated = true;
            return;
        }
        let Some(entries) = read_dir_syscall(&dir, false) else {
            continue;
        };

        let mut subdirs = 0usize;
        let mut unresolved_types = false;
        let mut syscall = BTreeSet::new();
        for (name, d_type) in &entries {
            syscall.insert(name.clone());
            match *d_type {
                libc::DT_DIR => {
                    subdirs += 1;
                    if depth < cfg.dir_scan_depth {
                        let child = dir.join(std::ffi::OsStr::from_bytes(name));
                        if lstat(&child).is_some_and(|st| st.st_dev == device) {
                            stack.push((child, depth + 1));
                        }
                    }
                }
                libc::DT_UNKNOWN => unresolved_types = true,
                _ => {}
            }
        }

        // Without an entry type for every name the subdirectory count is a
        // lower bound, and a lower bound would make the link-count check fire
        // on a directory that is perfectly fine.
        let nlink = match (nlink_meaningful && !unresolved_types, lstat(&dir)) {
            // `st_nlink` is 64-bit on x86_64 and 32-bit on aarch64, so the
            // widening is redundant on one target and required on the other.
            #[allow(clippy::unnecessary_cast)]
            (true, Some(st)) if st.st_nlink >= 2 => Some(st.st_nlink as u64),
            _ => None,
        };

        out.push(DirectoryViews {
            libc: read_dir_libc(&dir).unwrap_or_default(),
            syscall,
            nlink,
            subdirs,
            path: dir,
        });
    }
}

/// Gather candidate names from the sources a filtered listing cannot suppress.
fn collect_candidate_names(
    kernel_paths: &[(String, PathSighting)],
) -> BTreeMap<PathBuf, CandidateName> {
    let mut out: BTreeMap<PathBuf, CandidateName> = BTreeMap::new();

    // eBPF sightings come first and are never displaced: they were observed
    // below every interface userspace can hook, which makes them the strongest
    // provenance a candidate can have.
    for (path, sighting) in kernel_paths {
        if let Some(p) = usable_candidate(Path::new(path)) {
            out.insert(
                p,
                CandidateName {
                    source: "ebpf",
                    revealed_by: Some(sighting.comm.clone()),
                    operation: Some(sighting.op),
                },
            );
        }
    }

    let Ok(entries) = std::fs::read_dir("/proc") else {
        return out;
    };
    for pid in entries
        .flatten()
        .filter_map(|e| e.file_name().to_string_lossy().parse::<i32>().ok())
    {
        let comm = std::fs::read_to_string(format!("/proc/{pid}/comm"))
            .ok()
            .map(|s| s.trim().to_string());

        if let Ok(fds) = std::fs::read_dir(format!("/proc/{pid}/fd")) {
            for target in fds
                .flatten()
                .filter_map(|e| std::fs::read_link(e.path()).ok())
            {
                if let Some(p) = usable_candidate(&target) {
                    out.entry(p).or_insert_with(|| CandidateName {
                        source: "proc_fd",
                        revealed_by: comm.clone(),
                        operation: None,
                    });
                }
            }
        }

        if let Ok(maps) = std::fs::read_to_string(format!("/proc/{pid}/maps")) {
            for path in mapped_paths(&maps) {
                if let Some(p) = usable_candidate(Path::new(&path)) {
                    out.entry(p).or_insert_with(|| CandidateName {
                        source: "proc_maps",
                        revealed_by: comm.clone(),
                        operation: None,
                    });
                }
            }
        }
    }
    out
}

/// File-backed mapping paths from a `/proc/<pid>/maps` body.
///
/// The path is the sixth field and may contain spaces, so it is taken as the
/// remainder of the line rather than by splitting.
pub fn mapped_paths(maps: &str) -> Vec<String> {
    maps.lines()
        .filter_map(|line| {
            let mut fields = line.splitn(6, char::is_whitespace);
            let path = fields.nth(5)?.trim();
            path.starts_with('/').then(|| path.to_string())
        })
        .collect()
}

/// Reject paths that cannot answer the question being asked of them.
///
/// `/proc/<pid>/fd` symlinks point at sockets, pipes and anonymous inodes as
/// well as files, and a deleted file's target is suffixed. None of those have a
/// directory entry to be missing from, so treating them as candidates would
/// report every pipe on the host as a hidden file.
pub fn usable_candidate(path: &Path) -> Option<PathBuf> {
    let s = path.to_str()?;
    if !s.starts_with('/') || s.ends_with(" (deleted)") {
        return None;
    }
    if path.components().any(|c| c.as_os_str() == "..") {
        return None;
    }
    let parent = path.parent()?;
    if parent.as_os_str().is_empty() || path.file_name().is_none() {
        return None;
    }
    // Synthetic trees answer directory reads from live kernel state, so a name
    // that is absent from one is genuinely absent rather than concealed.
    for prefix in ["/proc/", "/sys/", "/dev/pts/", "/dev/mqueue/"] {
        if s.starts_with(prefix) {
            return None;
        }
    }
    Some(path.to_path_buf())
}

/// Look every candidate up against its parent's listing.
///
/// Candidates are grouped by parent so one listing read serves all of them, and
/// each is `lstat`-ed before and after that read: identical inodes on both sides
/// prove the file was present for the whole window the listing was taken in.
fn resolve_candidates(names: BTreeMap<PathBuf, CandidateName>) -> Vec<ResolvedCandidate> {
    let mut by_parent: BTreeMap<PathBuf, Vec<(PathBuf, CandidateName)>> = BTreeMap::new();
    for (path, name) in names {
        if let Some(parent) = path.parent() {
            by_parent
                .entry(parent.to_path_buf())
                .or_default()
                .push((path, name));
        }
    }

    let mut out = Vec::new();
    for (parent, children) in by_parent {
        if fs_type(&parent).is_none_or(is_synthetic) {
            continue;
        }

        let before: Vec<Option<u64>> = children
            .iter()
            .map(|(p, _)| lstat(p).map(|st| st.st_ino))
            .collect();
        let Some(listing) = read_dir_syscall(&parent, true) else {
            continue;
        };
        let listed: BTreeSet<Vec<u8>> = listing.into_iter().map(|(name, _)| name).collect();

        for ((path, name), inode) in children.into_iter().zip(before) {
            let Some(inode) = inode else { continue };
            // Gone or replaced since the listing: the absence is explained.
            if lstat(&path).map(|st| st.st_ino) != Some(inode) {
                continue;
            }
            let Some(file_name) = path.file_name() else {
                continue;
            };
            out.push(ResolvedCandidate {
                listed: listed.contains(file_name.as_bytes()),
                path,
                name,
                inode,
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(path: &str, libc: &[&str], syscall: &[&str]) -> DirectoryViews {
        DirectoryViews {
            path: PathBuf::from(path),
            libc: libc.iter().map(|n| n.as_bytes().to_vec()).collect(),
            syscall: syscall.iter().map(|n| n.as_bytes().to_vec()).collect(),
            nlink: None,
            subdirs: 0,
        }
    }

    fn candidate(path: &str, listed: bool) -> ResolvedCandidate {
        ResolvedCandidate {
            path: PathBuf::from(path),
            name: CandidateName {
                source: "ebpf",
                revealed_by: Some("sh".into()),
                operation: Some("write"),
            },
            inode: 42,
            listed,
        }
    }

    fn rule_ids(findings: &[Finding]) -> Vec<&str> {
        findings.iter().map(|f| f.rule_id).collect()
    }

    #[test]
    fn an_entry_the_syscall_returns_and_libc_hides_is_reported() {
        let d = dir("/tmp", &["a", "b"], &["a", "b", ".x"]);
        let found = libc_filtering_findings(&[d]);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].rule_id, "rootkit.dir_entry_hidden_from_libc");
        assert!(matches!(found[0].severity, Severity::Critical));
        assert_eq!(found[0].subject, "dir:/tmp");
    }

    #[test]
    fn an_entry_only_libc_reports_is_not_a_finding() {
        // libc reads in chunks and can pick up a file created after the
        // syscall read; that direction is a race, not concealment.
        let d = dir("/tmp", &["a", "new"], &["a"]);
        assert!(libc_filtering_findings(&[d]).is_empty());
    }

    #[test]
    fn agreeing_enumerations_produce_nothing() {
        let d = dir("/tmp", &["a", "b"], &["b", "a"]);
        assert!(libc_filtering_findings(&[d]).is_empty());
    }

    #[test]
    fn non_utf8_names_still_compare() {
        // A lossily decoded name would never match its raw counterpart and
        // every such entry would look hidden.
        let raw = vec![0xffu8, 0xfe];
        let d = DirectoryViews {
            path: PathBuf::from("/tmp"),
            libc: [raw.clone()].into_iter().collect(),
            syscall: [raw].into_iter().collect(),
            ..Default::default()
        };
        assert!(libc_filtering_findings(&[d]).is_empty());
    }

    #[test]
    fn a_link_count_deficit_means_a_hidden_subdirectory() {
        let d = DirectoryViews {
            path: PathBuf::from("/etc"),
            nlink: Some(5), // . + .. + 3 subdirectories
            subdirs: 2,
            ..Default::default()
        };
        let found = link_count_findings(&[d]);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].rule_id, "rootkit.subdirectory_hidden_from_listing");
        assert_eq!(found[0].evidence["missing"], 1);
    }

    #[test]
    fn a_matching_link_count_produces_nothing() {
        let d = DirectoryViews {
            nlink: Some(4),
            subdirs: 2,
            ..Default::default()
        };
        assert!(link_count_findings(&[d]).is_empty());
    }

    #[test]
    fn a_link_count_surplus_is_never_reported() {
        // Filesystems that do not maintain the invariant show up this way;
        // distrust the check, not the host.
        let d = DirectoryViews {
            nlink: Some(2),
            subdirs: 9,
            ..Default::default()
        };
        assert!(link_count_findings(&[d]).is_empty());
    }

    #[test]
    fn a_filesystem_without_a_usable_link_count_is_skipped() {
        let d = DirectoryViews {
            nlink: None,
            subdirs: 0,
            ..Default::default()
        };
        assert!(link_count_findings(&[d]).is_empty());
    }

    #[test]
    fn only_ext_xfs_and_tmpfs_link_counts_are_trusted() {
        assert!(nlink_is_a_subdir_count(EXT_SUPER_MAGIC));
        assert!(nlink_is_a_subdir_count(TMPFS_MAGIC));
        // btrfs reports 1 for every directory, overlayfs is unreliable.
        assert!(!nlink_is_a_subdir_count(0x9123_683E));
        assert!(!nlink_is_a_subdir_count(0x794c_7630));
    }

    #[test]
    fn overlayfs_listings_stay_comparable_even_though_its_link_count_does_not() {
        // A container's root is normally overlayfs. Treating it as synthetic
        // would disable the whole detector on exactly those hosts.
        const OVERLAYFS_MAGIC: i64 = 0x794c_7630;
        assert!(!is_synthetic(OVERLAYFS_MAGIC));
        assert!(!nlink_is_a_subdir_count(OVERLAYFS_MAGIC));
    }

    #[test]
    fn synthetic_and_remote_trees_are_excluded() {
        for magic in [
            0x9fa0,      // procfs
            0x6265_6572, // sysfs
            0x6367_7270, // cgroup2
            0x6573_5546, // fuse
            0x6969,      // nfs
        ] {
            assert!(is_synthetic(magic), "{magic:#x} cannot answer this check");
        }
        assert!(!is_synthetic(EXT_SUPER_MAGIC));
        assert!(!is_synthetic(TMPFS_MAGIC));
    }

    #[test]
    fn a_known_path_missing_from_its_listing_is_hidden() {
        let found = candidate_findings(&[candidate("/tmp/.sshd", false)]);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].rule_id, "rootkit.file_hidden_from_listing");
        assert_eq!(found[0].confidence, 90);
        assert_eq!(found[0].subject, "path:/tmp/.sshd");
        assert_eq!(found[0].mitre_technique, "T1014");
    }

    #[test]
    fn a_listed_path_is_not_a_finding() {
        assert!(candidate_findings(&[candidate("/tmp/normal", true)]).is_empty());
    }

    #[test]
    fn a_flood_of_unlisted_paths_collapses_into_one_quiet_finding() {
        let many: Vec<ResolvedCandidate> = (0..200)
            .map(|i| candidate(&format!("/tmp/f{i}"), false))
            .collect();
        let found = candidate_findings(&many);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].rule_id, "rootkit.file_listing_inconsistent");
        assert!(matches!(found[0].severity, Severity::Low));
        assert_eq!(found[0].evidence["count"], 200);
    }

    #[test]
    fn analyze_reports_every_check_together() {
        let dirs = vec![
            dir("/tmp", &["a"], &["a", "hidden"]),
            DirectoryViews {
                path: PathBuf::from("/etc"),
                nlink: Some(6),
                subdirs: 1,
                ..Default::default()
            },
        ];
        let found = analyze(&dirs, &[candidate("/tmp/.x", false)]);
        let ids = rule_ids(&found);
        assert!(ids.contains(&"rootkit.dir_entry_hidden_from_libc"));
        assert!(ids.contains(&"rootkit.subdirectory_hidden_from_listing"));
        assert!(ids.contains(&"rootkit.file_hidden_from_listing"));
    }

    #[test]
    fn a_clean_host_produces_nothing() {
        let dirs = vec![DirectoryViews {
            path: PathBuf::from("/etc"),
            libc: [b"passwd".to_vec()].into_iter().collect(),
            syscall: [b"passwd".to_vec()].into_iter().collect(),
            nlink: Some(2),
            subdirs: 0,
        }];
        assert!(analyze(&dirs, &[candidate("/etc/passwd", true)]).is_empty());
    }

    #[test]
    fn findings_wait_for_a_second_sweep() {
        // Every check here compares standing state, so a single observation is
        // a race candidate and must not alert on its own.
        let found = analyze(&[dir("/tmp", &[], &["x"])], &[candidate("/tmp/.y", false)]);
        assert!(found
            .iter()
            .all(|f| f.confirmation == Confirmation::Corroborate));
    }

    // ── dirent parsing ──────────────────────────────────────────────────────

    fn dirent(ino: u64, name: &[u8], d_type: u8) -> Vec<u8> {
        let reclen = 19 + name.len() + 1;
        let mut rec = Vec::new();
        rec.extend_from_slice(&ino.to_ne_bytes());
        rec.extend_from_slice(&0i64.to_ne_bytes());
        rec.extend_from_slice(&(reclen as u16).to_ne_bytes());
        rec.push(d_type);
        rec.extend_from_slice(name);
        rec.push(0);
        rec
    }

    #[test]
    fn dirent_records_are_parsed_and_dot_entries_dropped() {
        let mut buf = dirent(1, b".", libc::DT_DIR);
        buf.extend(dirent(2, b"..", libc::DT_DIR));
        buf.extend(dirent(3, b"etc", libc::DT_DIR));
        buf.extend(dirent(4, b"passwd", libc::DT_REG));

        let parsed = parse_dirents64(&buf);
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0], (b"etc".to_vec(), libc::DT_DIR));
        assert_eq!(parsed[1], (b"passwd".to_vec(), libc::DT_REG));
    }

    #[test]
    fn a_truncated_dirent_buffer_stops_the_parse() {
        let full = dirent(3, b"etc", libc::DT_DIR);
        let parsed = parse_dirents64(&full[..full.len() - 2]);
        assert!(parsed.is_empty(), "a partial record must not be read past");
    }

    #[test]
    fn a_nonsense_record_length_cannot_loop_forever() {
        let mut rec = dirent(3, b"etc", libc::DT_DIR);
        rec[16] = 0;
        rec[17] = 0;
        assert!(parse_dirents64(&rec).is_empty());
    }

    // ── candidate filtering ─────────────────────────────────────────────────

    #[test]
    fn anonymous_and_deleted_fd_targets_are_not_candidates() {
        for target in [
            "socket:[12345]",
            "pipe:[678]",
            "anon_inode:[eventpoll]",
            "/tmp/gone (deleted)",
            "/proc/1/status",
            "/sys/kernel/notes",
            "/dev/pts/3",
            "relative/path",
            "/etc/../etc/passwd",
        ] {
            assert!(
                usable_candidate(Path::new(target)).is_none(),
                "{target} has no directory entry to be missing from"
            );
        }
    }

    #[test]
    fn a_real_file_path_is_a_candidate() {
        assert_eq!(
            usable_candidate(Path::new("/usr/lib/.libx.so")),
            Some(PathBuf::from("/usr/lib/.libx.so"))
        );
        // /dev/shm is a real tmpfs and a favourite drop location.
        assert!(usable_candidate(Path::new("/dev/shm/.x")).is_some());
    }

    #[test]
    fn mapped_paths_keeps_file_backed_regions_with_spaces() {
        let maps = "\
55a0-55a1 r-xp 00000000 fe:01 131 /usr/bin/my app
7f00-7f01 rw-p 00000000 00:00 0 
7f10-7f11 r--p 00000000 fe:01 999 /usr/lib/.libx.so
7f20-7f21 rw-p 00000000 00:00 0 [heap]
";
        assert_eq!(
            mapped_paths(maps),
            vec!["/usr/bin/my app", "/usr/lib/.libx.so"]
        );
    }

    // ── live host ───────────────────────────────────────────────────────────

    #[test]
    fn unresolvable_roots_are_kept_verbatim_and_duplicates_dropped() {
        let roots = canonical_roots(&[
            "/definitely/not/here".to_string(),
            "/definitely/not/here".to_string(),
        ]);
        assert_eq!(roots, vec![PathBuf::from("/definitely/not/here")]);
    }

    #[test]
    #[ignore = "reads the live filesystem"]
    fn merged_usr_symlink_roots_collapse_onto_one_tree() {
        // On Debian and Ubuntu /bin is a symlink to usr/bin. Walking the
        // configured names directly would skip it (the walk does not follow
        // symlinks) and then cover /usr/bin twice.
        let roots = canonical_roots(&["/bin".into(), "/usr/bin".into()]);
        if std::fs::symlink_metadata("/bin").is_ok_and(|m| m.file_type().is_symlink()) {
            assert_eq!(roots.len(), 1, "both names resolve to the same tree");
        }
        assert!(roots.iter().all(|r| r.is_dir()));
    }

    #[test]
    #[ignore = "reads the live filesystem"]
    fn both_enumerations_agree_on_a_real_directory() {
        let libc = read_dir_libc(Path::new("/etc")).expect("libc readdir");
        let syscall: BTreeSet<Vec<u8>> = read_dir_syscall(Path::new("/etc"), true)
            .expect("getdents64")
            .into_iter()
            .map(|(n, _)| n)
            .collect();
        assert!(!syscall.is_empty());
        assert!(
            syscall.difference(&libc).next().is_none(),
            "an uncompromised host must agree with itself"
        );
    }

    #[test]
    #[ignore = "reads the live filesystem"]
    fn a_freshly_created_file_is_found_in_its_listing() {
        let dir = std::env::temp_dir().join(format!("trapd-hf-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join(".dotted");
        std::fs::write(&file, b"x").unwrap();

        let names: BTreeMap<PathBuf, CandidateName> = [(
            file.clone(),
            CandidateName {
                source: "ebpf",
                revealed_by: None,
                operation: Some("write"),
            },
        )]
        .into_iter()
        .collect();
        let resolved = resolve_candidates(names);

        assert_eq!(resolved.len(), 1);
        assert!(
            resolved[0].listed,
            "a file this process just created must appear in its own directory"
        );
        std::fs::remove_dir_all(&dir).ok();
    }
}
