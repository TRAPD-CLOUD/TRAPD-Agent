//! File-event rules: writes (and renames onto) persistence and privilege
//! locations, observed by the eBPF file-open / rename probes.
//!
//! These are the precise counterpart of the command-line heuristics in
//! [`super::behavior`]: the event names the real path and the real writer, so
//! when file telemetry is flowing the engine prefers these and drops the
//! command-line guesses for the same rules.

use trapd_schema::{CorrelationKeys, DetectionData, Severity};

use super::behavior::persistence_rule_for_path;

/// Rules this module covers (the engine suppresses the command-line variants
/// of these once file telemetry is seen).
pub const FILE_COVERED_RULES: &[&str] = &[
    "persistence.ssh_authorized_keys",
    "persistence.cron_write",
    "persistence.systemd_unit",
    "persistence.autostart_write",
    "persistence.rc_edit",
    "persistence.ld_preload",
    "privesc.sudoers_modify",
];

/// Package managers write system locations by definition; their own writes
/// are not persistence. (Their *children* are only downgraded, by policy.)
const PKG_WRITERS: &[&str] = &[
    "dpkg",
    "apt",
    "apt-get",
    "rpm",
    "dnf",
    "yum",
    "zypper",
    "pacman",
    "snapd",
    "apk",
    "unattended-upgr",
    "packagekitd",
    "systemd",
    "systemctl",
    "systemd-sysv-ge",
];
/// Writers sanctioned for a specific location.
const SANCTIONED: &[(&str, &[&str])] = &[
    ("privesc.sudoers_modify", &["visudo"]),
    (
        "persistence.ssh_authorized_keys",
        &["sshd", "ssh-copy-id", "google_guest_ag", "cloud-init"],
    ),
];

/// `open(2)` flags that imply a write.
const O_WRONLY: u64 = 0o1;
const O_RDWR: u64 = 0o2;
const O_CREAT: u64 = 0o100;
const O_TRUNC: u64 = 0o1000;
const O_APPEND: u64 = 0o2000;

pub fn is_write_open(flags: u64) -> bool {
    flags & (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC | O_APPEND) != 0
}

/// A write to `path` by `comm`. `None` when the path is not a persistence /
/// privilege location or the writer is sanctioned for it.
pub fn inspect_write(path: &str, comm: &str) -> Option<DetectionData> {
    let (rule_id, technique, title) = persistence_rule_for_path(path)?;
    let base = comm.rsplit('/').next().unwrap_or(comm);
    if PKG_WRITERS.contains(&base) {
        return None;
    }
    if SANCTIONED
        .iter()
        .any(|(rule, writers)| *rule == rule_id && writers.contains(&base))
    {
        return None;
    }
    // Editors are how admins change these files; the swap / backup files they
    // write next to the target are not the target.
    if path.ends_with(".swp") || path.ends_with(".swx") || path.ends_with('~') {
        return None;
    }
    let editor = matches!(
        base,
        "vim" | "vi" | "nvim" | "nano" | "emacs" | "code" | "gedit"
    );
    let base_severity = match rule_id {
        "persistence.cron_write" if base == "crontab" || editor => Some(Severity::Medium),
        "persistence.cron_write" => Some(Severity::High),
        "persistence.ssh_authorized_keys" | "privesc.sudoers_modify" if editor => {
            Some(Severity::Medium)
        }
        _ => None,
    };
    let tactic = if rule_id.starts_with("privesc.") {
        "TA0004 Privilege Escalation"
    } else {
        "TA0003 Persistence"
    };
    Some(DetectionData {
        rule_id: rule_id.into(),
        title: title.into(),
        category: if rule_id.starts_with("privesc.") {
            "privilege_escalation".into()
        } else {
            "persistence".into()
        },
        mitre_tactic: Some(tactic.into()),
        mitre_technique: Some(technique.into()),
        confidence: 75,
        subject: path.to_string(),
        detail: format!("{base} wrote {path}"),
        evidence: serde_json::json!({ "path": path, "comm": comm, "source": "file_event" }),
        base_severity,
        correlation: Some(CorrelationKeys {
            file_path: Some(path.to_string()),
            ..Default::default()
        }),
        ..Default::default()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authorized_keys_write_by_shell() {
        let d = inspect_write("/root/.ssh/authorized_keys", "bash").unwrap();
        assert_eq!(d.rule_id, "persistence.ssh_authorized_keys");
        assert_eq!(
            d.correlation.unwrap().file_path.as_deref(),
            Some("/root/.ssh/authorized_keys")
        );
    }

    #[test]
    fn cron_writer_decides_base_severity() {
        assert_eq!(
            inspect_write("/var/spool/cron/crontabs/root", "crontab")
                .unwrap()
                .base_severity,
            Some(Severity::Medium)
        );
        assert_eq!(
            inspect_write("/etc/cron.d/backdoor", "python3")
                .unwrap()
                .base_severity,
            Some(Severity::High)
        );
    }

    #[test]
    fn systemd_units_only() {
        assert_eq!(
            inspect_write("/etc/systemd/system/evil.service", "cp")
                .unwrap()
                .rule_id,
            "persistence.systemd_unit"
        );
        assert!(inspect_write("/etc/systemd/system/multi-user.target.wants", "cp").is_none());
        assert!(inspect_write("/home/u/.config/systemd/user/x.service", "tee").is_some());
    }

    #[test]
    fn sanctioned_and_package_writers_are_quiet() {
        assert!(inspect_write("/etc/sudoers.d/x", "visudo").is_none());
        assert!(inspect_write("/etc/cron.d/logrotate", "dpkg").is_none());
        assert!(inspect_write("/lib/systemd/system/nginx.service", "dpkg").is_none());
        assert!(inspect_write("/etc/sudoers.d/.x.swp", "vim").is_none());
    }

    #[test]
    fn sudoers_by_unexpected_writer() {
        let d = inspect_write("/etc/sudoers.d/99-backdoor", "tee").unwrap();
        assert_eq!(d.rule_id, "privesc.sudoers_modify");
        assert_eq!(d.base_severity, None);
    }

    #[test]
    fn unrelated_paths_are_ignored() {
        assert!(inspect_write("/home/u/notes.txt", "vim").is_none());
        assert!(inspect_write("/home/u/.ssh/known_hosts", "ssh").is_none());
    }

    #[test]
    fn write_flags() {
        assert!(is_write_open(0o1));
        assert!(is_write_open(0o101));
        assert!(!is_write_open(0));
    }
}
