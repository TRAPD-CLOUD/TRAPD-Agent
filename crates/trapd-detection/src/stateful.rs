//! Stateful single-host rules: patterns that only exist across several events
//! of one session or source — a burst of discovery commands, a brute force
//! that ends in a successful login, a dropped file made executable and run.
//!
//! Time is injected (`now` in seconds on a monotonic scale) so every rule is
//! unit-tested deterministically; all state is bounded.

use std::collections::{HashMap, HashSet, VecDeque};

use trapd_schema::{CorrelationKeys, DetectionData, Severity};

/// Distinct discovery commands within [`RECON_WINDOW`] that make a burst.
const RECON_THRESHOLD: usize = 4;
const RECON_WINDOW: f64 = 60.0;
/// Failed logins from one source within [`BRUTE_WINDOW`] before a success
/// makes it a successful brute force.
const BRUTE_THRESHOLD: usize = 5;
const BRUTE_WINDOW: f64 = 300.0;
/// A temp-dir binary executed within this long after `chmod +x`.
const CHMOD_EXEC_WINDOW: f64 = 120.0;
/// `systemctl enable` within this long after a unit was written.
const UNIT_ENABLE_WINDOW: f64 = 600.0;
/// Bound on tracked sessions / sources / files per tracker.
const MAX_KEYS: usize = 4_096;

#[derive(Default)]
pub struct StatefulRules {
    recon: HashMap<String, VecDeque<(f64, String)>>,
    failures: HashMap<String, VecDeque<f64>>,
    chmods: HashMap<String, f64>,
    units: HashMap<String, (f64, String)>,
    windows_logons: super::windows_logon::WindowsLogonTracker,
}

/// Normalised discovery command, or `None` when the exec is not discovery.
fn recon_command(base: &str, cmdline: &str) -> Option<String> {
    let lower = cmdline.to_ascii_lowercase();
    let arg1 = lower.split_whitespace().nth(1).unwrap_or("");
    // Windows image names carry an extension and arbitrary case (`WHOAMI.EXE`).
    let base = base.to_ascii_lowercase();
    let base = base.strip_suffix(".exe").unwrap_or(&base);
    let name = match base {
        "whoami" | "id" | "uname" | "hostname" | "hostnamectl" | "ifconfig" | "ss" | "netstat"
        | "w" | "who" | "last" | "lastlog" | "lsb_release" | "arp" | "route" | "groups"
        | "getent" | "lscpu" | "lsblk" | "env" | "printenv" | "uptime"
        // Windows discovery tools.
        | "ipconfig" | "systeminfo" | "tasklist" | "nltest" | "quser" | "qwinsta" => {
            base.to_string()
        }
        "net" | "net1" if matches!(arg1, "user" | "group" | "localgroup" | "view" | "accounts") => {
            format!("net {arg1}")
        }
        "ip" if matches!(arg1, "a" | "addr" | "address" | "r" | "route" | "link" | "neigh") => {
            format!("ip {arg1}")
        }
        "ps" if lower.contains("aux") || lower.contains("-ef") || lower.contains("-e") => {
            "ps".into()
        }
        "sudo" if arg1 == "-l" => "sudo -l".into(),
        "cat" | "head" | "less" => {
            const FILES: &[&str] = &[
                "/etc/passwd",
                "/etc/group",
                "/etc/os-release",
                "/etc/issue",
                "/etc/hosts",
                "/etc/resolv.conf",
                "/proc/version",
            ];
            let f = FILES.iter().find(|f| lower.contains(*f))?;
            format!("{base} {f}")
        }
        "find" if lower.contains("-perm") && (lower.contains("4000") || lower.contains("u=s")) => {
            "find suid".into()
        }
        _ => return None,
    };
    Some(name)
}

impl StatefulRules {
    pub fn new() -> Self {
        Self::default()
    }

    /// Discovery burst: `session` is the session root (or parent) key the
    /// commands share. Fires every time the burst threshold is reached; the
    /// finding gate folds repeated bursts of one session into one finding.
    pub fn observe_exec_recon(
        &mut self,
        session: &str,
        base: &str,
        cmdline: &str,
        now: f64,
    ) -> Option<DetectionData> {
        let cmd = recon_command(base, cmdline)?;
        bound(&mut self.recon);
        let q = self.recon.entry(session.to_string()).or_default();
        q.retain(|(t, _)| now - t <= RECON_WINDOW);
        q.push_back((now, cmd));
        let distinct: HashSet<&str> = q.iter().map(|(_, c)| c.as_str()).collect();
        if distinct.len() < RECON_THRESHOLD {
            return None;
        }
        let mut commands: Vec<String> = distinct.into_iter().map(String::from).collect();
        commands.sort();
        q.clear();
        Some(DetectionData {
            rule_id: "discovery.recon_burst".into(),
            title: "Burst of system discovery commands".into(),
            category: "discovery".into(),
            mitre_tactic: Some("TA0007 Discovery".into()),
            mitre_technique: Some("T1082".into()),
            confidence: 60,
            subject: session.to_string(),
            detail: format!(
                "{} distinct discovery commands within {RECON_WINDOW:.0}s: {}",
                commands.len(),
                commands.join(", ")
            ),
            evidence: serde_json::json!({ "commands": commands, "session": session }),
            ..Default::default()
        })
    }

    /// Logon outcome from `src`. A success after ≥ [`BRUTE_THRESHOLD`]
    /// failures from the same source inside the window is a brute force that
    /// worked.
    pub fn observe_logon(
        &mut self,
        user: &str,
        src: &str,
        success: bool,
        now: f64,
    ) -> Option<DetectionData> {
        if src.is_empty() {
            return None;
        }
        bound(&mut self.failures);
        let q = self.failures.entry(src.to_string()).or_default();
        q.retain(|t| now - t <= BRUTE_WINDOW);
        if !success {
            q.push_back(now);
            return None;
        }
        let failures = q.len();
        self.failures.remove(src);
        if failures < BRUTE_THRESHOLD {
            return None;
        }
        Some(DetectionData {
            rule_id: "auth.ssh_bruteforce_success".into(),
            title: "Successful login after brute force".into(),
            category: "credential_access".into(),
            mitre_tactic: Some("TA0001 Initial Access".into()),
            mitre_technique: Some("T1110.001".into()),
            confidence: 85,
            subject: format!("{user}@{src}"),
            detail: format!("{user} logged in from {src} after {failures} failed attempts"),
            evidence: serde_json::json!({ "user": user, "src_addr": src, "failures": failures }),
            correlation: Some(CorrelationKeys {
                user: Some(user.to_string()),
                remote_ip: Some(src.to_string()),
                ..Default::default()
            }),
            ..Default::default()
        })
    }

    /// Windows logon outcome (brute force, spray, success after failures).
    pub fn observe_windows_logon(
        &mut self,
        l: &trapd_schema::UserLogonData,
        now: f64,
    ) -> Vec<DetectionData> {
        self.windows_logons.observe(l, now)
    }

    /// `chmod` that set an execute bit on `path`.
    pub fn observe_chmod_exec(&mut self, path: &str, now: f64) {
        bound(&mut self.chmods);
        self.chmods.retain(|_, t| now - *t <= CHMOD_EXEC_WINDOW);
        self.chmods.insert(path.to_string(), now);
    }

    /// Exec of `exe` from a temp directory shortly after it was made
    /// executable: a dropped payload being run.
    pub fn observe_temp_exec(&mut self, exe: &str, now: f64) -> Option<DetectionData> {
        let t = self.chmods.remove(exe)?;
        if now - t > CHMOD_EXEC_WINDOW {
            return None;
        }
        Some(DetectionData {
            rule_id: "defense.tmp_exec_chmod".into(),
            title: "Dropped file made executable and run".into(),
            category: "execution".into(),
            mitre_tactic: Some("TA0002 Execution".into()),
            mitre_technique: Some("T1204.002".into()),
            confidence: 75,
            subject: exe.to_string(),
            detail: format!("{exe} was chmod +x'd and executed within {:.0}s", now - t),
            evidence: serde_json::json!({ "path": exe, "seconds_after_chmod": now - t }),
            correlation: Some(CorrelationKeys {
                file_path: Some(exe.to_string()),
                ..Default::default()
            }),
            ..Default::default()
        })
    }

    /// A systemd unit was written in `session`.
    pub fn observe_unit_write(&mut self, session: &str, path: &str, now: f64) {
        bound(&mut self.units);
        self.units
            .insert(session.to_string(), (now, path.to_string()));
    }

    /// `systemctl enable|start` in a session that just wrote a unit: the unit
    /// is being activated — escalate the persistence finding to High.
    pub fn observe_systemctl(
        &mut self,
        session: &str,
        cmdline: &str,
        now: f64,
    ) -> Option<DetectionData> {
        let lower = cmdline.to_ascii_lowercase();
        if !(lower.contains(" enable")
            || lower.contains(" start")
            || lower.contains(" daemon-reload"))
        {
            return None;
        }
        let (t, path) = self.units.get(session).cloned()?;
        if now - t > UNIT_ENABLE_WINDOW || lower.contains("daemon-reload") {
            return None;
        }
        self.units.remove(session);
        Some(DetectionData {
            rule_id: "persistence.systemd_unit".into(),
            title: "systemd unit written and activated".into(),
            category: "persistence".into(),
            mitre_tactic: Some("TA0003 Persistence".into()),
            mitre_technique: Some("T1543.002".into()),
            confidence: 85,
            subject: path.clone(),
            detail: format!("{path} written and activated via `{cmdline}`"),
            evidence: serde_json::json!({ "path": path, "cmdline": cmdline }),
            base_severity: Some(Severity::High),
            correlation: Some(CorrelationKeys {
                file_path: Some(path),
                ..Default::default()
            }),
            ..Default::default()
        })
    }
}

/// Keep a tracker bounded: past the cap, drop an arbitrary half. Bursts and
/// brute forces are short-lived, so losing cold state is harmless.
fn bound<V>(map: &mut HashMap<String, V>) {
    if map.len() >= MAX_KEYS {
        let drop: Vec<String> = map.keys().take(MAX_KEYS / 2).cloned().collect();
        for k in drop {
            map.remove(&k);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recon_burst_needs_distinct_commands() {
        let mut s = StatefulRules::new();
        assert!(s.observe_exec_recon("r", "id", "id", 0.0).is_none());
        assert!(s.observe_exec_recon("r", "id", "id", 1.0).is_none());
        assert!(s.observe_exec_recon("r", "whoami", "whoami", 2.0).is_none());
        assert!(s
            .observe_exec_recon("r", "uname", "uname -a", 3.0)
            .is_none());
        let d = s.observe_exec_recon("r", "ss", "ss -tan", 4.0).unwrap();
        assert_eq!(d.rule_id, "discovery.recon_burst");
        assert_eq!(d.subject, "r");
    }

    #[test]
    fn recon_burst_matches_windows_image_names() {
        let mut s = StatefulRules::new();
        assert!(s
            .observe_exec_recon("r", "whoami.exe", "whoami", 0.0)
            .is_none());
        assert!(s
            .observe_exec_recon("r", "HOSTNAME.EXE", "hostname", 1.0)
            .is_none());
        assert!(s
            .observe_exec_recon("r", "netstat.exe", "netstat -an", 2.0)
            .is_none());
        let d = s.observe_exec_recon("r", "arp.exe", "arp -a", 3.0).unwrap();
        assert_eq!(d.rule_id, "discovery.recon_burst");
    }

    #[test]
    fn recon_ignores_net_subcommands_that_are_not_discovery() {
        assert_eq!(
            recon_command("net.exe", "net user"),
            Some("net user".into())
        );
        assert_eq!(recon_command("net.exe", "net use z: \\\\srv\\share"), None);
    }

    #[test]
    fn recon_burst_respects_window_and_session() {
        let mut s = StatefulRules::new();
        s.observe_exec_recon("r", "id", "id", 0.0);
        s.observe_exec_recon("r", "whoami", "whoami", 1.0);
        s.observe_exec_recon("other", "uname", "uname", 2.0);
        assert!(s.observe_exec_recon("r", "ss", "ss", 100.0).is_none());
        assert!(s.observe_exec_recon("r", "ls", "ls -la", 101.0).is_none());
    }

    #[test]
    fn recon_rearms_after_firing() {
        let mut s = StatefulRules::new();
        let cmds = [
            ("id", "id"),
            ("whoami", "whoami"),
            ("uname", "uname"),
            ("ss", "ss"),
        ];
        let fire = |s: &mut StatefulRules, t: f64| {
            cmds.iter()
                .enumerate()
                .filter_map(|(i, (b, c))| s.observe_exec_recon("r", b, c, t + i as f64))
                .count()
        };
        assert_eq!(fire(&mut s, 0.0), 1);
        assert_eq!(
            fire(&mut s, 10.0),
            1,
            "a second burst fires again (the gate folds it)"
        );
    }

    #[test]
    fn cat_passwd_counts_but_cat_readme_does_not() {
        assert!(recon_command("cat", "cat /etc/passwd").is_some());
        assert!(recon_command("cat", "cat README.md").is_none());
        assert!(recon_command("ip", "ip a").is_some());
        assert!(recon_command("ip", "ip netns exec x").is_none());
    }

    #[test]
    fn brute_force_then_success() {
        let mut s = StatefulRules::new();
        for i in 0..5 {
            assert!(s
                .observe_logon("root", "198.51.100.7", false, i as f64)
                .is_none());
        }
        let d = s.observe_logon("root", "198.51.100.7", true, 10.0).unwrap();
        assert_eq!(d.rule_id, "auth.ssh_bruteforce_success");
        let c = d.correlation.unwrap();
        assert_eq!(c.remote_ip.as_deref(), Some("198.51.100.7"));
        assert_eq!(c.user.as_deref(), Some("root"));
    }

    #[test]
    fn few_failures_or_stale_failures_are_benign() {
        let mut s = StatefulRules::new();
        for i in 0..3 {
            s.observe_logon("u", "203.0.113.1", false, i as f64);
        }
        assert!(s.observe_logon("u", "203.0.113.1", true, 5.0).is_none());
        for i in 0..6 {
            s.observe_logon("u", "203.0.113.2", false, i as f64);
        }
        assert!(s.observe_logon("u", "203.0.113.2", true, 1000.0).is_none());
    }

    #[test]
    fn chmod_then_exec() {
        let mut s = StatefulRules::new();
        s.observe_chmod_exec("/tmp/x", 0.0);
        assert!(s.observe_temp_exec("/tmp/y", 1.0).is_none());
        assert_eq!(
            s.observe_temp_exec("/tmp/x", 5.0).unwrap().rule_id,
            "defense.tmp_exec_chmod"
        );
        s.observe_chmod_exec("/tmp/z", 0.0);
        assert!(s.observe_temp_exec("/tmp/z", 500.0).is_none());
    }

    #[test]
    fn unit_write_then_enable() {
        let mut s = StatefulRules::new();
        s.observe_unit_write("r", "/etc/systemd/system/evil.service", 0.0);
        assert!(s
            .observe_systemctl("other", "systemctl enable evil", 1.0)
            .is_none());
        let d = s
            .observe_systemctl("r", "systemctl enable --now evil", 2.0)
            .unwrap();
        assert_eq!(d.base_severity, Some(Severity::High));
    }
}
