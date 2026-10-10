use trapd_schema::DetectionData;

/// Credential / secret stores.  A file-open of any of these by an unexpected
/// process is treated as credential theft (MITRE T1555).  SSH private keys are
/// matched separately ([`is_ssh_private_key`]): the rest of `~/.ssh/`
/// (`known_hosts`, `config`, public keys) is written by `ssh` all day long.
const SENSITIVE_PATHS: &[&str] = &[
    "/etc/shadow",
    "/etc/gshadow",
    ".aws/credentials",
    ".kube/config",
];

/// Processes legitimately expected to open the sensitive paths above:
/// authentication, account management, and the owning CLIs.
const ALLOWED_PROCS: &[&str] = &[
    "sshd",
    "sudo",
    "su",
    "login",
    "passwd",
    "chpasswd",
    "chage",
    "usermod",
    "useradd",
    "userdel",
    "groupadd",
    "groupmod",
    "groupdel",
    "gpasswd",
    "vipw",
    "unix_chkpwd",
    "pwck",
    "grpck",
    "shadowconfig",
    "ssh",
    "ssh-agent",
    "ssh-add",
    "ssh-keygen",
    "scp",
    "sftp-server",
    "git",
    "gpg-agent",
    "aws",
    "kubectl",
    "helm",
    "k9s",
    "kubelet",
];

/// `~/.ssh/id_*` without `.pub`, `*.pem`, `*_key` under `.ssh/`.
fn is_ssh_private_key(path: &str) -> bool {
    let Some((_, rest)) = path.split_once(".ssh/") else {
        return false;
    };
    let file = rest.rsplit('/').next().unwrap_or(rest);
    (file.starts_with("id_") && !file.ends_with(".pub"))
        || file.ends_with(".pem")
        || (file.ends_with("_key") && !file.starts_with("authorized"))
}

// ── Sensitive file-access detection ───────────────────────────────────────────

/// Inspect a file-open against the sensitive credential-store list.
///
/// Returns a [`DetectionData`] when `path` is an SSH private key or one of
/// [`SENSITIVE_PATHS`] and the accessing process `comm` is **not** in
/// [`ALLOWED_PROCS`].  Pure and unit-testable, mirroring the heuristics in
/// `detection::behavior`; severity comes from the rule catalog.
pub fn inspect_sensitive_access(path: &str, comm: &str) -> Option<DetectionData> {
    let base = comm.rsplit('/').next().unwrap_or(comm);
    if ALLOWED_PROCS.contains(&base) {
        return None;
    }
    if is_ssh_private_key(path) {
        return Some(DetectionData {
            rule_id: "creds.private_key_read".into(),
            title: "SSH private key opened by an unexpected process".into(),
            category: "credential_access".into(),
            mitre_tactic: Some("TA0006 Credential Access".into()),
            mitre_technique: Some("T1552.004".into()),
            confidence: 80,
            subject: path.to_string(),
            detail: format!("Process {base} opened SSH private key {path}"),
            evidence: serde_json::json!({ "path": path, "comm": comm }),
            ..Default::default()
        });
    }
    let matched = SENSITIVE_PATHS.iter().find(|&&p| path.contains(p))?;
    Some(DetectionData {
        rule_id: "creds.sensitive_file_access".into(),
        title: "Sensitive credential store accessed by an unexpected process".into(),
        category: "credential_access".into(),
        mitre_tactic: Some("TA0006 Credential Access".into()),
        mitre_technique: Some("T1555".into()),
        confidence: 85,
        subject: path.to_string(),
        detail: format!("Process {base} opened sensitive path {path} (not an expected accessor)"),
        evidence: serde_json::json!({
            "path": path,
            "comm": comm,
            "matched": matched,
            "techniques": ["T1555"],
        }),
        ..Default::default()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn flags_shadow_read_by_unexpected_proc() {
        let d = inspect_sensitive_access("/etc/shadow", "cat").unwrap();
        assert_eq!(d.category, "credential_access");
        assert_eq!(d.mitre_technique.as_deref(), Some("T1555"));
        assert_eq!(d.rule_id, "creds.sensitive_file_access");
    }

    #[test]
    fn allows_expected_procs() {
        assert!(inspect_sensitive_access("/etc/shadow", "sshd").is_none());
        assert!(inspect_sensitive_access("/home/u/.ssh/id_rsa", "sudo").is_none());
        assert!(inspect_sensitive_access("/etc/shadow", "/usr/bin/passwd").is_none());
    }

    #[test]
    fn flags_ssh_and_cloud_credentials() {
        assert_eq!(
            inspect_sensitive_access("/home/u/.ssh/id_ed25519", "python3")
                .unwrap()
                .rule_id,
            "creds.private_key_read"
        );
        assert!(inspect_sensitive_access("/home/u/.ssh/id_ed25519", "scp").is_none());
        assert!(inspect_sensitive_access("/home/u/.aws/credentials", "curl").is_some());
        assert!(inspect_sensitive_access("/root/.kube/config", "python3").is_some());
        assert!(inspect_sensitive_access("/etc/gshadow", "tail").is_some());
    }

    #[test]
    fn ignores_non_sensitive_paths() {
        assert!(inspect_sensitive_access("/etc/hostname", "cat").is_none());
        // ssh maintains these constantly; they are not secrets.
        assert!(inspect_sensitive_access("/home/u/.ssh/known_hosts", "python3").is_none());
        assert!(inspect_sensitive_access("/home/u/.ssh/id_rsa.pub", "python3").is_none());
        assert!(inspect_sensitive_access("/home/u/.ssh/config", "python3").is_none());
        assert!(inspect_sensitive_access("/home/u/.ssh/authorized_keys", "python3").is_none());
        assert!(inspect_sensitive_access("/home/u/notes.txt", "vim").is_none());
    }
}
