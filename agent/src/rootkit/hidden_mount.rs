//! Mounts that only some of the kernel's own interfaces admit to.
//!
//! Mounting over a directory is the laziest way to hide files: the real
//! contents are still on disk, untouched and passing every integrity check,
//! but nothing can see them any more. It is also how an attacker swaps a single
//! binary or configuration file without modifying it, since a bind mount leaves
//! the original inode alone.
//!
//! The mount table is exposed three times by three different pieces of kernel
//! code, and a rootkit that filters one of them routinely forgets the others:
//!
//! * `/proc/mounts` — the classic `fstab`-shaped table.
//! * `/proc/self/mountinfo` — the richer per-mount format with ids and
//!   propagation, produced by an entirely separate show routine.
//! * `/proc/self/mountstats` — a third formatter, intended for NFS statistics,
//!   which still names every mount on the way past.
//!
//! A mount that appears in one and not another is not a mount being hidden
//! *from* the kernel — the kernel knows about it — it is one of these files
//! being edited on its way to userspace.
//!
//! Separately, a bind mount whose target is a *file* under a system directory
//! is reported on its own. Nothing legitimate shadows `/bin/ps` that way;
//! container runtimes do it constantly for `/etc/hosts` and friends, which is
//! why those are excluded by name rather than by hoping they score low.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde_json::json;

use super::{Confirmation, Finding};
use crate::schema::Severity;

/// File-level mounts every container runtime creates. Excluded by name because
/// they are indistinguishable, mechanically, from a malicious bind mount.
const EXPECTED_FILE_MOUNTS: &[&str] = &[
    "/etc/hosts",
    "/etc/hostname",
    "/etc/resolv.conf",
    "/etc/localtime",
    "/etc/timezone",
    "/etc/machine-id",
    "/etc/mtab",
];

/// Trees where a file-level mount is ordinary: device nodes, runtime state and
/// the synthetic filesystems.
const UNREMARKABLE_MOUNT_PREFIXES: &[&str] =
    &["/dev/", "/proc/", "/sys/", "/run/", "/var/run/", "/tmp/"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountEntry {
    pub source: String,
    pub target: String,
    pub fstype: String,
}

/// The same mount table as three of the kernel's interfaces describe it.
#[derive(Debug, Default, Clone)]
pub struct MountViews {
    pub mounts: BTreeMap<String, MountEntry>,
    pub mountinfo: BTreeMap<String, MountEntry>,
    /// Targets only; the format carries no information the others lack.
    pub mountstats: BTreeSet<String>,
    /// False on kernels that do not expose `mountstats`, where its absence
    /// must not be read as "this interface hid everything".
    pub mountstats_readable: bool,
    /// Mount targets that are regular files rather than directories.
    pub file_mounts: Vec<MountEntry>,
}

pub fn analyze(views: &MountViews) -> Vec<Finding> {
    let mut out = disagreement_findings(views);
    out.extend(file_mount_findings(&views.file_mounts));
    out
}

/// Mounts that some interfaces list and others do not.
fn disagreement_findings(views: &MountViews) -> Vec<Finding> {
    // Nothing to compare against: a single readable view cannot disagree with
    // itself, and reporting on it would be reporting on its own emptiness.
    if views.mounts.is_empty() || views.mountinfo.is_empty() {
        return Vec::new();
    }

    let mut targets: BTreeSet<&String> = BTreeSet::new();
    targets.extend(views.mounts.keys());
    targets.extend(views.mountinfo.keys());
    if views.mountstats_readable {
        targets.extend(views.mountstats.iter());
    }

    let mut out = Vec::new();
    for target in targets {
        let in_mounts = views.mounts.contains_key(target);
        let in_mountinfo = views.mountinfo.contains_key(target);
        let in_mountstats = views.mountstats.contains(target);

        let mut seen = vec![];
        let mut missing = vec![];
        for (name, present) in [
            ("/proc/mounts", in_mounts),
            ("/proc/self/mountinfo", in_mountinfo),
        ] {
            if present {
                seen.push(name)
            } else {
                missing.push(name)
            }
        }
        if views.mountstats_readable {
            if in_mountstats {
                seen.push("/proc/self/mountstats");
            } else {
                missing.push("/proc/self/mountstats");
            }
        }
        if missing.is_empty() {
            continue;
        }

        let entry = views
            .mounts
            .get(target)
            .or_else(|| views.mountinfo.get(target));
        out.push(Finding {
            rule_id: "rootkit.mount_hidden_from_interface",
            title: "Mount listed by some of the kernel's mount interfaces and not others",
            confirmation: Confirmation::Corroborate,
            severity: Severity::Critical,
            confidence: 80,
            mitre_tactic: "TA0005 Defense Evasion",
            mitre_technique: "T1014",
            subject: format!("mount:{target}"),
            detail: format!(
                "The mount on {} is reported by {} but not by {}. All of these are rendered \
                 from the same kernel mount table, so they cannot legitimately disagree — one \
                 of them is being filtered on its way to userspace, which hides whatever the \
                 mount covers.",
                target,
                seen.join(", "),
                missing.join(", "),
            ),
            evidence: json!({
                "target": target,
                "source": entry.map(|e| e.source.clone()),
                "fstype": entry.map(|e| e.fstype.clone()),
                "views": {
                    "proc_mounts": in_mounts,
                    "proc_self_mountinfo": in_mountinfo,
                    "proc_self_mountstats": views.mountstats_readable.then_some(in_mountstats),
                },
            }),
        });
    }
    out
}

/// Bind mounts that shadow a single system file.
fn file_mount_findings(file_mounts: &[MountEntry]) -> Vec<Finding> {
    file_mounts
        .iter()
        .filter(|m| is_suspicious_file_mount(&m.target))
        .map(|m| Finding {
            rule_id: "rootkit.file_shadowed_by_mount",
            title: "System file shadowed by a mount",
            confirmation: Confirmation::Corroborate,
            severity: Severity::High,
            confidence: 70,
            mitre_tactic: "TA0005 Defense Evasion",
            mitre_technique: "T1564",
            subject: format!("path:{}", m.target),
            detail: format!(
                "{} is a mount point for {} ({}), so reads of that path do not reach the file \
                 on disk. The original is untouched and still passes every integrity check, \
                 while everything that opens the path gets the mounted content instead.",
                m.target, m.source, m.fstype,
            ),
            evidence: json!({
                "target": m.target,
                "source": m.source,
                "fstype": m.fstype,
            }),
        })
        .collect()
}

fn is_suspicious_file_mount(target: &str) -> bool {
    if EXPECTED_FILE_MOUNTS.contains(&target) {
        return false;
    }
    if UNREMARKABLE_MOUNT_PREFIXES
        .iter()
        .any(|p| target.starts_with(p))
    {
        return false;
    }
    // Kubernetes projects secrets and downward-API files into containers.
    !target.contains("/secrets/") && !target.contains("/kubernetes.io~")
}

// ── Parsing ─────────────────────────────────────────────────────────────────

/// Decode the octal escapes the kernel uses for whitespace and backslashes in
/// mount paths. Comparing an escaped path against an unescaped one would report
/// any mount point containing a space as hidden from whichever view escaped it.
pub fn unescape_mount_path(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = String::with_capacity(raw.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 3 < bytes.len() {
            if let Some(byte) = std::str::from_utf8(&bytes[i + 1..i + 4])
                .ok()
                .and_then(|oct| u8::from_str_radix(oct, 8).ok())
            {
                out.push(byte as char);
                i += 4;
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

/// `/proc/mounts`: `source target fstype options freq passno`.
pub fn parse_mounts(body: &str) -> BTreeMap<String, MountEntry> {
    body.lines()
        .filter_map(|line| {
            let mut f = line.split_whitespace();
            let source = f.next()?;
            let target = unescape_mount_path(f.next()?);
            let fstype = f.next()?;
            Some((
                target.clone(),
                MountEntry {
                    source: unescape_mount_path(source),
                    target,
                    fstype: fstype.to_string(),
                },
            ))
        })
        .collect()
}

/// `/proc/self/mountinfo`: the mount point is field 4, and the filesystem type
/// and source follow a lone `-` separator whose position varies with the number
/// of optional propagation fields.
pub fn parse_mountinfo(body: &str) -> BTreeMap<String, MountEntry> {
    body.lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            let target = unescape_mount_path(fields.get(4)?);
            let sep = fields.iter().position(|f| *f == "-")?;
            Some((
                target.clone(),
                MountEntry {
                    source: fields
                        .get(sep + 2)
                        .map(|s| unescape_mount_path(s))
                        .unwrap_or_default(),
                    target,
                    fstype: fields.get(sep + 1).unwrap_or(&"").to_string(),
                },
            ))
        })
        .collect()
}

/// `/proc/self/mountstats`: `device <src> mounted on <target> with fstype <fs>`.
pub fn parse_mountstats(body: &str) -> BTreeSet<String> {
    body.lines()
        .filter_map(|line| {
            let rest = line.strip_prefix("device ")?;
            let (_, after) = rest.split_once(" mounted on ")?;
            let target = after.split_once(" with fstype ").map(|(t, _)| t)?;
            Some(unescape_mount_path(target))
        })
        .collect()
}

// ── Host collection ─────────────────────────────────────────────────────────

pub fn gather() -> MountViews {
    let mounts = std::fs::read_to_string("/proc/mounts")
        .map(|b| parse_mounts(&b))
        .unwrap_or_default();
    let mountinfo = std::fs::read_to_string("/proc/self/mountinfo")
        .map(|b| parse_mountinfo(&b))
        .unwrap_or_default();
    let stats_body = std::fs::read_to_string("/proc/self/mountstats").ok();

    let file_mounts = mountinfo
        .values()
        .filter(|m| std::fs::symlink_metadata(Path::new(&m.target)).is_ok_and(|md| md.is_file()))
        .cloned()
        .collect();

    MountViews {
        mounts,
        mountinfo,
        mountstats: stats_body
            .as_deref()
            .map(parse_mountstats)
            .unwrap_or_default(),
        mountstats_readable: stats_body.is_some(),
        file_mounts,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MOUNTS: &str = "\
/dev/sda1 / ext4 rw,relatime 0 0
sysfs /sys sysfs rw,nosuid 0 0
tmpfs /dev/shm tmpfs rw,nosuid 0 0
";

    const MOUNTINFO: &str = "\
23 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw
24 23 0:19 / /sys rw,nosuid shared:2 - sysfs sysfs rw
25 23 0:20 / /dev/shm rw,nosuid shared:3 - tmpfs tmpfs rw
";

    const MOUNTSTATS: &str = "\
device /dev/sda1 mounted on / with fstype ext4
device sysfs mounted on /sys with fstype sysfs
device tmpfs mounted on /dev/shm with fstype tmpfs
";

    fn views(mounts: &str, mountinfo: &str, mountstats: Option<&str>) -> MountViews {
        MountViews {
            mounts: parse_mounts(mounts),
            mountinfo: parse_mountinfo(mountinfo),
            mountstats: mountstats.map(parse_mountstats).unwrap_or_default(),
            mountstats_readable: mountstats.is_some(),
            file_mounts: Vec::new(),
        }
    }

    #[test]
    fn agreeing_interfaces_produce_nothing() {
        assert!(analyze(&views(MOUNTS, MOUNTINFO, Some(MOUNTSTATS))).is_empty());
    }

    #[test]
    fn a_mount_scrubbed_from_proc_mounts_is_reported() {
        let filtered = "/dev/sda1 / ext4 rw,relatime 0 0\nsysfs /sys sysfs rw,nosuid 0 0\n";
        let found = analyze(&views(filtered, MOUNTINFO, Some(MOUNTSTATS)));
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].rule_id, "rootkit.mount_hidden_from_interface");
        assert_eq!(found[0].subject, "mount:/dev/shm");
        assert_eq!(found[0].evidence["views"]["proc_mounts"], false);
        assert_eq!(found[0].evidence["views"]["proc_self_mountinfo"], true);
    }

    #[test]
    fn a_mount_scrubbed_from_mountinfo_is_reported() {
        let filtered = "23 1 8:1 / / rw shared:1 - ext4 /dev/sda1 rw\n\
                        24 23 0:19 / /sys rw shared:2 - sysfs sysfs rw\n";
        let found = analyze(&views(MOUNTS, filtered, Some(MOUNTSTATS)));
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].subject, "mount:/dev/shm");
    }

    #[test]
    fn a_mount_only_mountstats_still_names_is_reported() {
        let m = "/dev/sda1 / ext4 rw 0 0\nsysfs /sys sysfs rw 0 0\n";
        let mi = "23 1 8:1 / / rw shared:1 - ext4 /dev/sda1 rw\n\
                  24 23 0:19 / /sys rw shared:2 - sysfs sysfs rw\n";
        let found = analyze(&views(m, mi, Some(MOUNTSTATS)));
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].subject, "mount:/dev/shm");
    }

    #[test]
    fn a_kernel_without_mountstats_is_not_a_finding() {
        // Its absence must not be read as an interface hiding every mount.
        assert!(analyze(&views(MOUNTS, MOUNTINFO, None)).is_empty());
    }

    #[test]
    fn an_unreadable_view_disables_the_comparison() {
        // One readable view cannot disagree with itself; reporting would just
        // be reporting that the other read failed.
        assert!(analyze(&views("", MOUNTINFO, Some(MOUNTSTATS))).is_empty());
        assert!(analyze(&views(MOUNTS, "", Some(MOUNTSTATS))).is_empty());
    }

    #[test]
    fn escaped_mount_paths_compare_equal_across_views() {
        let m = "/dev/sdb1 /mnt/my\\040disk ext4 rw 0 0\n/dev/sda1 / ext4 rw 0 0\n";
        let mi = "23 1 8:1 / / rw shared:1 - ext4 /dev/sda1 rw\n\
                  26 23 8:17 / /mnt/my\\040disk rw shared:4 - ext4 /dev/sdb1 rw\n";
        assert!(
            analyze(&views(m, mi, None)).is_empty(),
            "a mount point with a space must not look hidden"
        );
    }

    #[test]
    fn mount_paths_are_unescaped() {
        assert_eq!(unescape_mount_path("/mnt/my\\040disk"), "/mnt/my disk");
        assert_eq!(unescape_mount_path("/mnt/a\\134b"), "/mnt/a\\b");
        assert_eq!(unescape_mount_path("/plain/path"), "/plain/path");
        // A trailing lone backslash must not run off the end.
        assert_eq!(unescape_mount_path("/mnt/x\\"), "/mnt/x\\");
    }

    #[test]
    fn mountinfo_finds_the_fstype_after_the_separator() {
        let parsed = parse_mountinfo(
            "36 35 98:0 /src /mnt rw,noatime master:1 propagate_from:2 - ext3 /dev/root rw\n",
        );
        let entry = parsed.get("/mnt").expect("mount point");
        assert_eq!(entry.fstype, "ext3");
        assert_eq!(entry.source, "/dev/root");
    }

    #[test]
    fn a_bind_mount_over_a_system_binary_is_reported() {
        let found = file_mount_findings(&[MountEntry {
            source: "/dev/sda1".into(),
            target: "/bin/ps".into(),
            fstype: "ext4".into(),
        }]);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].rule_id, "rootkit.file_shadowed_by_mount");
        assert_eq!(found[0].subject, "path:/bin/ps");
    }

    #[test]
    fn container_file_mounts_are_not_reported() {
        let mounts: Vec<MountEntry> = [
            "/etc/hosts",
            "/etc/hostname",
            "/etc/resolv.conf",
            "/dev/termination-log",
            "/run/secrets/kubernetes.io/serviceaccount/token",
            "/var/run/secrets/token",
        ]
        .iter()
        .map(|t| MountEntry {
            source: "tmpfs".into(),
            target: (*t).to_string(),
            fstype: "tmpfs".into(),
        })
        .collect();
        assert!(
            file_mount_findings(&mounts).is_empty(),
            "every container runtime creates these"
        );
    }

    #[test]
    #[ignore = "reads the live mount table"]
    fn the_live_interfaces_agree_with_each_other() {
        let views = gather();
        assert!(!views.mounts.is_empty(), "/proc/mounts must be readable");
        assert!(
            disagreement_findings(&views).is_empty(),
            "an uncompromised host must describe its mounts consistently"
        );
    }
}
