//! Local customer approvals, deliberately outside signed AgentConfig/commands.
//!
//! The service environment is an administrative trust boundary. An approval
//! names one file and exact bytes; neither directories nor future remote bait
//! are implicitly authorized. Missing/malformed policy denies placement.
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use super::{Breadcrumb, DeployRequest};

const POLICY_ENV: &str = "TRAPD_DECEPTION_PLACEMENTS";

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PlacementPolicy {
    approvals: Vec<Approval>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Approval {
    path: String,
    kind: String,
    sha256: String,
    mode: u32,
}

impl PlacementPolicy {
    pub(super) fn local() -> Result<Self> {
        match std::env::var(POLICY_ENV) {
            Ok(json) => Self::parse(&json),
            Err(std::env::VarError::NotPresent) => Ok(Self::default()),
            Err(_) => bail!("local deception placement policy is not UTF-8"),
        }
    }

    pub(super) fn parse(json: &str) -> Result<Self> {
        if json.len() > 65_536 {
            bail!("local deception placement policy exceeds 64 KiB");
        }
        let policy: Self =
            serde_json::from_str(json).context("invalid local deception placement policy")?;
        if policy.approvals.len() > 256 {
            bail!("too many local deception approvals");
        }
        for item in &policy.approvals {
            validate_destination(&item.path)?;
            if item.mode == 0 {
                bail!("local approval mode must be explicit");
            }
            safe_mode(item.mode)?;
            if item.sha256.len() != 64
                || !item
                    .sha256
                    .bytes()
                    .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
            {
                bail!("local deception approval requires a lowercase SHA-256 digest");
            }
            if !known_kind(&item.kind) && item.kind != "breadcrumb" {
                bail!("local deception approval has an unsupported bait kind");
            }
        }
        Ok(policy)
    }

    pub(super) fn authorize(&self, req: &DeployRequest) -> Result<()> {
        if !known_kind(req.kind.as_deref().unwrap_or("unknown")) {
            bail!("signed placement requires a supported bait kind");
        }
        self.file(
            &req.path,
            req.kind.as_deref().unwrap_or("unknown"),
            &req.content,
            req.mode,
        )?;
        for crumb in &req.breadcrumbs {
            self.breadcrumb(crumb)?;
        }
        Ok(())
    }

    pub(super) fn breadcrumb(&self, crumb: &Breadcrumb) -> Result<()> {
        if crumb.append {
            bail!("general breadcrumb append is disabled; use an approved standalone note");
        }
        let path = Path::new(&crumb.path);
        if !matches!(
            path.extension().and_then(|s| s.to_str()),
            Some("txt" | "md")
        ) || std::str::from_utf8(&crumb.content).is_err()
            || crumb.content.iter().any(|&b| b == 0 || b == 27)
        {
            bail!("breadcrumb must be a UTF-8 .txt or .md note");
        }
        self.file(&crumb.path, "breadcrumb", &crumb.content, crumb.mode)
    }

    fn file(&self, path: &str, kind: &str, content: &[u8], mode: u32) -> Result<()> {
        validate_destination(path)?;
        let mode = safe_mode(mode)?;
        if content.is_empty() || content.len() > 1024 * 1024 {
            bail!("deception content must contain 1 byte to 1 MiB");
        }
        if content.starts_with(b"#!")
            || content.starts_with(b"\x7fELF")
            || content.starts_with(b"MZ")
        {
            bail!("executable content is forbidden for deception");
        }
        let digest = hex::encode(Sha256::digest(content));
        if !self.approvals.iter().any(|entry| {
            entry.path == path && entry.kind == kind && entry.sha256 == digest && entry.mode == mode
        }) {
            bail!("no exact local deception placement approval");
        }
        Ok(())
    }
}

pub(super) fn safe_mode(mode: u32) -> Result<u32> {
    match mode {
        0 => Ok(0o600),
        0o600 | 0o640 | 0o644 => Ok(mode),
        _ => bail!("deception mode must be 0600, 0640 or 0644; execution/special/write sharing bits are forbidden"),
    }
}

fn known_kind(kind: &str) -> bool {
    matches!(
        kind,
        "aws_credentials"
            | "jwt"
            | "jwt_token"
            | "kube_config"
            | "pgpass"
            | "my_cnf"
            | "ssh_private_key"
            | "docker_config"
            | "webroot_env"
            | "git_credentials"
            | "shadow_backup"
            | "browser_logins"
            | "root_backup_keys"
            | "office_doc"
            | "pdf_doc"
            | "passwords_kdbx"
    )
}

fn validate_destination(path: &str) -> Result<PathBuf> {
    let target = super::validate_target(path)?;
    let portable = path.replace('\\', "/").to_ascii_lowercase();
    let components: Vec<&str> = portable.split('/').filter(|s| !s.is_empty()).collect();
    // Reject ambiguous spellings even on Unix (where backslashes are literal).
    if path.ends_with(['/', '\\'])
        || path.chars().any(|c| c.is_control())
        || components
            .iter()
            .any(|s| *s == "." || *s == ".." || s.ends_with(['.', ' ']) || s.contains('~'))
    {
        bail!("ambiguous deception destination");
    }
    #[cfg(not(windows))]
    if path.contains('\\') || path.contains(':') || path.contains("//") {
        bail!("ambiguous deception destination");
    }
    #[cfg(windows)]
    {
        if path.len() < 4
            || !path.as_bytes()[0].is_ascii_alphabetic()
            || path.as_bytes()[1] != b':'
            || path.as_bytes()[2] != b'\\'
            || path[3..].contains(':')
            || path.contains('/')
            || path.contains("\\\\")
        {
            bail!("deception requires an unambiguous local drive path");
        }
    }
    for protected in [
        crate::paths::state_dir(),
        crate::paths::config_dir(),
        crate::paths::log_dir(),
    ] {
        let protected = protected
            .to_string_lossy()
            .replace('\\', "/")
            .to_ascii_lowercase();
        if portable == protected
            || portable.starts_with(&(protected.trim_end_matches('/').to_string() + "/"))
        {
            bail!("agent state/config/log destinations are forbidden");
        }
    }
    if components.iter().any(|s| {
        matches!(
            *s,
            "etc"
                | "proc"
                | "sys"
                | "dev"
                | "run"
                | "boot"
                | "bin"
                | "sbin"
                | "lib"
                | "lib64"
                | "usr"
                | "windows"
                | "program files"
                | "program files (x86)"
                | "programdata"
                | "startup"
                | "start menu"
                | "system32"
                | "trapd"
                | ".trapd"
        )
    }) || ["/var/lib/", "/var/log/", "/var/spool/", "/var/run/"]
        .iter()
        .any(|p| portable.starts_with(p))
    {
        bail!("system/control destinations are forbidden for deception");
    }
    let name = components
        .last()
        .context("deception destination has no filename")?;
    let device = name.split('.').next().unwrap_or("");
    if matches!(
        device,
        "con" | "prn" | "aux" | "nul" | "clock$" | "conin$" | "conout$"
    ) || device
        .strip_prefix("com")
        .or_else(|| device.strip_prefix("lpt"))
        .is_some_and(|n| {
            matches!(
                n,
                "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
            )
        })
    {
        bail!("device aliases are forbidden for deception");
    }

    if matches!(
        *name,
        "authorized_keys"
            | "authorized_keys2"
            | "authorized_principals"
            | "sshrc"
            | "rc"
            | "environment"
            | ".profile"
            | ".bashrc"
            | ".bash_profile"
            | ".bash_login"
            | ".bash_logout"
            | ".zshrc"
            | ".zshenv"
            | ".zprofile"
            | ".zlogin"
            | ".zlogout"
            | ".bash_history"
            | ".zsh_history"
            | "config.fish"
            | "known_hosts"
            | "config"
            | ".gitconfig"
            | ".gitmodules"
            | ".npmrc"
            | ".yarnrc"
            | ".pythonrc"
            | ".vimrc"
            | ".exrc"
            | ".inputrc"
            | ".wgetrc"
            | ".curlrc"
            | ".htaccess"
            | ".user.ini"
            | "rtr-enabled"
            | "agent.env"
            | "command_signing.pub"
            | "credentials.json"
            | "honeytokens.json"
            | "trapd-agent"
    ) || components
        .iter()
        .any(|s| matches!(*s, ".config" | ".local" | ".git" | "powershell"))
        || [
            ".sh", ".bash", ".zsh", ".fish", ".py", ".pyc", ".pl", ".rb", ".js", ".mjs", ".cjs",
            ".ts", ".php", ".phtml", ".cgi", ".exe", ".com", ".dll", ".bat", ".cmd", ".ps1",
            ".psm1", ".vbs", ".wsf", ".hta", ".lnk", ".url", ".desktop", ".service", ".timer",
            ".socket", ".conf", ".ini", ".scr", ".pif", ".cpl", ".msc", ".msi", ".msp", ".sys",
            ".jse", ".vbe", ".wsh", ".sct", ".reg", ".inf", ".jar", ".docm", ".xlsm", ".xlam",
        ]
        .iter()
        .any(|suffix| name.ends_with(suffix))
    {
        bail!("executable/startup/authorization destinations are forbidden");
    }
    Ok(target)
}

/// Keep Windows ancestor handles open throughout publication. No write/delete
/// sharing means a junction cannot be installed or an ancestor renamed after
/// validation. Local admins must pre-create all approved parent directories.
#[cfg(windows)]
pub(super) fn lock_parents(target: &Path) -> Result<Vec<std::fs::File>> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    let mut locks = Vec::new();
    let mut current = PathBuf::new();
    for component in target.parent().context("missing parent")?.components() {
        current.push(component);
        if !current.is_absolute() {
            continue;
        }
        let file = std::fs::OpenOptions::new()
            .access_mode(0x80)
            .share_mode(1)
            .custom_flags(0x0200_0000 | 0x0020_0000)
            .open(&current)
            .context("lock deception ancestor without following reparse points")?;
        let meta = file.metadata()?;
        if !meta.is_dir() || meta.file_attributes() & 0x400 != 0 {
            bail!("deception ancestor is not a plain directory");
        }
        locks.push(file);
    }
    Ok(locks)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn approved(path: &str, kind: &str, content: &[u8], mode: u32) -> Result<PlacementPolicy> {
        PlacementPolicy::parse(&serde_json::json!({"approvals": [{
            "path": path, "kind": kind, "sha256": hex::encode(Sha256::digest(content)), "mode": mode
        }]}).to_string())
    }

    #[test]
    fn exact_approval_binds_path_kind_bytes_and_mode() {
        let path = std::env::temp_dir().join("approved-credentials.txt");
        let path = path.to_str().unwrap();
        let policy = approved(path, "webroot_env", b"DB_PASSWORD=local", 0o600).unwrap();
        assert!(policy
            .file(path, "webroot_env", b"DB_PASSWORD=local", 0o600)
            .is_ok());
        assert!(policy
            .file(path, "webroot_env", b"DB_PASSWORD=remote", 0o600)
            .is_err());
        assert!(policy
            .file(path, "jwt", b"DB_PASSWORD=local", 0o600)
            .is_err());
        assert!(policy
            .file(path, "webroot_env", b"DB_PASSWORD=local", 0o644)
            .is_err());
        assert!(policy
            .file(
                &format!("{path}.other"),
                "webroot_env",
                b"DB_PASSWORD=local",
                0o600
            )
            .is_err());
        assert!(PlacementPolicy::default()
            .file(path, "webroot_env", b"DB_PASSWORD=local", 0o600)
            .is_err());
    }

    #[test]
    fn broad_roots_unknown_types_and_malformed_policy_are_rejected() {
        for json in [
            "{}",
            "{\"approvals\":[],\"roots\":[\"/\"]}",
            "{\"approvals\":[{}]}",
        ] {
            assert!(PlacementPolicy::parse(json).is_err());
        }
        assert!(approved("/tmp/note.txt", "unknown", b"data", 0o600).is_err());
        assert!(PlacementPolicy::parse(&" ".repeat(65_537)).is_err());
        assert!(PlacementPolicy::parse("{\"approvals\":[]}").is_ok());
    }

    #[test]
    fn explicit_approvals_cannot_authorize_system_startup_or_agent_paths() {
        #[cfg(not(windows))]
        let protected = [
            "/etc/cron.d/task",
            "/root/.ssh/authorized_keys",
            "/home/alice/.bashrc",
            "/home/alice/.profile",
            "/home/alice/.config/autostart/task.desktop",
            "/home/alice/payload.sh",
            "/srv/web/index.php",
            "/opt/task.service",
            "/tmp/../etc/task",
            "/tmp/./note.txt",
            "/tmp//note.txt",
            "/tmp/note.txt.",
            "/tmp/note.txt ",
            "/tmp/alias~1/note.txt",
            "/tmp/rtr-enabled",
        ];
        #[cfg(not(windows))]
        for path in protected {
            assert!(
                approved(path, "webroot_env", b"DB_PASSWORD=x", 0o600).is_err(),
                "approved unsafe path: {path}"
            );
        }
        for root in [
            crate::paths::state_dir(),
            crate::paths::config_dir(),
            crate::paths::log_dir(),
        ] {
            let target = root.join("approved-note.txt");
            assert!(approved(
                target.to_str().unwrap(),
                "webroot_env",
                b"DB_PASSWORD=x",
                0o600
            )
            .is_err());
        }
    }

    #[test]
    fn matching_hash_does_not_authorize_executable_payloads() {
        let path = std::env::temp_dir().join("credential-backup.txt");
        let path = path.to_str().unwrap();
        for content in [
            b"#!/bin/sh\necho payload".as_slice(),
            b"\x7fELFpayload",
            b"MZpayload",
        ] {
            let policy = approved(path, "root_backup_keys", content, 0o600).unwrap();
            assert!(policy
                .file(path, "root_backup_keys", content, 0o600)
                .is_err());
        }
    }

    #[test]
    fn breadcrumbs_only_create_approved_text_notes() {
        let path = std::env::temp_dir().join("approved-note.txt");
        let path = path.to_string_lossy().into_owned();
        let content = b"see credential backup\n".to_vec();
        let policy = approved(&path, "breadcrumb", &content, 0o600).unwrap();
        let mut crumb = Breadcrumb {
            path,
            content,
            mode: 0o600,
            append: false,
        };
        assert!(policy.breadcrumb(&crumb).is_ok());
        crumb.append = true;
        assert!(policy.breadcrumb(&crumb).is_err());
        crumb.append = false;
        crumb.content = b"remote command".to_vec();
        assert!(policy.breadcrumb(&crumb).is_err());
    }
}

#[cfg(all(test, windows))]
mod windows_tests {
    use super::*;
    #[test]
    fn windows_rejects_unc_ads_shortnames_devices_and_startup_aliases() {
        for path in [
            r"\\server\share\note.txt",
            r"\\?\C:\notes\note.txt",
            r"C:\notes\note.txt:stream",
            r"C:\PROGRA~1\note.txt",
            r"C:\notes\NUL.txt",
            r"C:\notes\COM1",
            r"C:\notes\note.txt.",
            r"C:\Users\Public\Startup\note.txt",
            r"C:\Windows\Temp\note.txt",
        ] {
            assert!(
                validate_destination(path).is_err(),
                "unsafe Windows destination: {path}"
            );
        }
        assert!(validate_destination(r"C:\Decoys\credentials.txt").is_ok());
    }
}

#[cfg(all(test, windows))]
mod windows_handle_tests {
    use super::*;

    #[test]
    fn retained_parent_handles_prevent_rename_until_publication_finishes() {
        let dir = std::env::temp_dir().join(format!("deception-lock-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&dir).unwrap();
        let moved = dir.with_extension("moved");
        let locks = lock_parents(&dir.join("note.txt")).unwrap();
        assert!(std::fs::rename(&dir, &moved).is_err());
        drop(locks);
        std::fs::rename(&dir, &moved).unwrap();
        std::fs::remove_dir(&moved).unwrap();
    }

    #[test]
    fn exclusive_windows_bait_handle_can_be_verified_and_revoked() {
        let dir = std::env::temp_dir().join(format!("deception-handle-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&dir).unwrap();
        let target = dir.join("note.txt");
        let content = b"locally approved data\n";
        super::super::write_camouflaged(&target, content, 0o600, None, None).unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), content);
        let digest = hex::encode(Sha256::digest(content));
        super::super::remove_verified_file(&target, &digest, 1024).unwrap();
        assert!(!target.exists());
        std::fs::remove_dir(&dir).unwrap();
    }
}
