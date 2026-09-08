//! Interactive logins that are running but not recorded.
//!
//! `who`, `w` and `last` all read one file: `/var/run/utmp`. It is an ordinary,
//! writable record file, not a kernel interface, so editing an attacker's own
//! session out of it is trivial and is one of the first things a rootkit's
//! userland component does. Nothing about the session itself changes — the
//! shell keeps running on its pseudo-terminal, owned by a login process.
//!
//! So the session is reconstructed from `/proc` instead, which utmp tampering
//! cannot touch: a session leader with a controlling terminal, whose parent
//! chain runs back to `sshd`, `login` or a `getty`, is an interactive login by
//! definition. If utmp has no entry for that terminal, the record was removed.
//!
//! ## Why the login-parent requirement is not optional
//!
//! Plenty of processes own a pseudo-terminal without being a login: every
//! `tmux` and `screen` pane, every `docker exec -it`, every terminal emulator
//! on a desktop. None of them are recorded in utmp and none of them should be.
//! Requiring the session to descend from a login program is what separates "no
//! utmp entry because it is not a login" from "no utmp entry because someone
//! deleted it".
//!
//! The check is also skipped entirely when utmp holds no live sessions at all,
//! which is the normal state inside a container and on hosts whose PAM stack
//! does not maintain it. An empty utmp is not evidence of anything.

use std::collections::BTreeSet;

use serde_json::json;

use super::{Confirmation, Finding};
use crate::schema::Severity;

/// Size of `struct utmp` on the glibc platforms this agent targets.
const UTMP_RECORD: usize = 384;

const UT_TYPE_MAX: i16 = 9;
/// `USER_PROCESS`: a logged-in user's session.
pub const USER_PROCESS: i16 = 7;

/// Programs whose descendants are interactive logins.
const LOGIN_PARENTS: &[&str] = &[
    "sshd",
    "login",
    "getty",
    "agetty",
    "mingetty",
    "in.telnetd",
    "in.rlogind",
    "dropbear",
];

/// How far up the parent chain a login program is looked for.
const ANCESTRY_DEPTH: usize = 12;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UtmpEntry {
    pub kind: i16,
    pub pid: i32,
    /// `ut_line`, e.g. `pts/3` or `tty1`.
    pub line: String,
    pub user: String,
    pub host: String,
}

/// A login session as `/proc` describes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveSession {
    pub pid: i32,
    pub tty: String,
    pub uid: u32,
    pub comm: String,
    /// The login program found in the parent chain.
    pub via: String,
    pub via_pid: i32,
}

#[derive(Debug, Default, Clone)]
pub struct LoginViews {
    /// `None` when utmp could not be read or its layout was not recognised.
    pub utmp: Option<Vec<UtmpEntry>>,
    pub live: Vec<LiveSession>,
}

pub fn analyze(views: &LoginViews) -> Vec<Finding> {
    let Some(utmp) = views.utmp.as_ref() else {
        return Vec::new();
    };
    let recorded: BTreeSet<&str> = utmp
        .iter()
        .filter(|e| e.kind == USER_PROCESS && !e.line.is_empty())
        .map(|e| e.line.as_str())
        .collect();

    // A host that records no sessions at all is not hiding one: utmp is simply
    // not in use here, which is the default in most containers.
    if recorded.is_empty() {
        return Vec::new();
    }

    views
        .live
        .iter()
        .filter(|s| !recorded.contains(s.tty.as_str()))
        .map(|s| Finding {
            rule_id: "rootkit.login_session_hidden_from_utmp",
            title: "Interactive login session with no utmp record",
            confirmation: Confirmation::Corroborate,
            severity: Severity::High,
            confidence: 75,
            mitre_tactic: "TA0005 Defense Evasion",
            mitre_technique: "T1070.002",
            subject: format!("tty:{}", s.tty),
            detail: format!(
                "PID {} ({}) leads a session on {} and descends from {} (PID {}), which makes \
                 it an interactive login, but utmp has no entry for {} while recording {} \
                 other session(s). who, w and last will not show this login.",
                s.pid,
                s.comm,
                s.tty,
                s.via,
                s.via_pid,
                s.tty,
                recorded.len(),
            ),
            evidence: json!({
                "tty": s.tty,
                "session_leader_pid": s.pid,
                "comm": s.comm,
                "uid": s.uid,
                "login_parent": s.via,
                "login_parent_pid": s.via_pid,
                "views": { "proc": true, "utmp": false },
                "utmp_recorded_ttys": recorded.iter().collect::<Vec<_>>(),
            }),
        })
        .collect()
}

// ── utmp parsing ────────────────────────────────────────────────────────────

/// Decode `/var/run/utmp`.
///
/// Returns `None` when the file's size is not a whole number of records, or a
/// record carries an out-of-range type — both mean the layout is not the one
/// assumed here (a different libc, a different architecture), and guessing
/// would invent sessions rather than find hidden ones.
pub fn parse_utmp(bytes: &[u8]) -> Option<Vec<UtmpEntry>> {
    if bytes.is_empty() || !bytes.len().is_multiple_of(UTMP_RECORD) {
        return None;
    }
    // struct utmp { short ut_type; pid_t ut_pid; char ut_line[32]; char ut_id[4];
    //               char ut_user[32]; char ut_host[256]; ... }
    const LINE: usize = 8;
    const USER: usize = 44;
    const HOST: usize = 76;

    let mut out = Vec::with_capacity(bytes.len() / UTMP_RECORD);
    for rec in bytes.as_chunks::<UTMP_RECORD>().0 {
        let kind = i16::from_ne_bytes([rec[0], rec[1]]);
        if !(0..=UT_TYPE_MAX).contains(&kind) {
            return None;
        }
        out.push(UtmpEntry {
            kind,
            pid: i32::from_ne_bytes([rec[4], rec[5], rec[6], rec[7]]),
            line: cstr(&rec[LINE..LINE + 32]),
            user: cstr(&rec[USER..USER + 32]),
            host: cstr(&rec[HOST..HOST + 256]),
        });
    }
    Some(out)
}

fn cstr(field: &[u8]) -> String {
    let end = field.iter().position(|b| *b == 0).unwrap_or(field.len());
    String::from_utf8_lossy(&field[..end]).into_owned()
}

// ── /proc reconstruction ────────────────────────────────────────────────────

/// Name the controlling terminal from the `tty_nr` field of `/proc/<pid>/stat`.
///
/// The value is a kernel `dev_t`, whose major and minor are interleaved rather
/// than simply packed.
pub fn tty_name(tty_nr: i32) -> Option<String> {
    if tty_nr == 0 {
        return None;
    }
    let dev = tty_nr as u32;
    let major = (dev >> 8) & 0x0fff;
    let minor = (dev & 0xff) | ((dev >> 12) & 0x000f_ff00);
    match major {
        // UNIX98 pty slaves: eight majors of 256 minors each.
        136..=143 => Some(format!("pts/{}", (major - 136) * 256 + minor)),
        4 if minor < 64 => Some(format!("tty{minor}")),
        4 => Some(format!("ttyS{}", minor - 64)),
        _ => None,
    }
}

/// The `session` and `tty_nr` fields of a `/proc/<pid>/stat` body.
///
/// The command name sits in parentheses and may itself contain spaces or
/// parentheses, so the fields are counted from the *last* `)` rather than by
/// splitting the whole line.
pub fn parse_stat_session(stat: &str) -> Option<(i32, i32)> {
    let rest = &stat[stat.rfind(')')? + 1..];
    let fields: Vec<&str> = rest.split_whitespace().collect();
    // After the comm field: state(0) ppid(1) pgrp(2) session(3) tty_nr(4)
    Some((fields.get(3)?.parse().ok()?, fields.get(4)?.parse().ok()?))
}

pub fn gather() -> LoginViews {
    LoginViews {
        utmp: read_utmp(),
        live: live_sessions(),
    }
}

fn read_utmp() -> Option<Vec<UtmpEntry>> {
    for path in ["/var/run/utmp", "/run/utmp"] {
        if let Ok(bytes) = std::fs::read(path) {
            return parse_utmp(&bytes);
        }
    }
    None
}

fn live_sessions() -> Vec<LiveSession> {
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return Vec::new();
    };

    let mut out = Vec::new();
    for pid in entries
        .flatten()
        .filter_map(|e| e.file_name().to_string_lossy().parse::<i32>().ok())
    {
        let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
            continue;
        };
        let Some((session, tty_nr)) = parse_stat_session(&stat) else {
            continue;
        };
        // Only the session leader represents the login; its children share the
        // terminal and would each report the same missing record.
        if session != pid {
            continue;
        }
        let Some(tty) = tty_name(tty_nr) else {
            continue;
        };
        let Some((via, via_pid)) = login_ancestor(pid) else {
            continue;
        };

        out.push(LiveSession {
            pid,
            tty,
            uid: process_uid(pid).unwrap_or(0),
            comm: read_comm(pid).unwrap_or_default(),
            via,
            via_pid,
        });
    }
    out
}

/// Walk the parent chain looking for a login program.
fn login_ancestor(pid: i32) -> Option<(String, i32)> {
    let mut current = pid;
    for _ in 0..ANCESTRY_DEPTH {
        let stat = std::fs::read_to_string(format!("/proc/{current}/stat")).ok()?;
        let ppid: i32 = {
            let rest = &stat[stat.rfind(')')? + 1..];
            rest.split_whitespace().nth(1)?.parse().ok()?
        };
        if ppid <= 0 {
            return None;
        }
        let comm = read_comm(ppid)?;
        if LOGIN_PARENTS.iter().any(|p| comm.starts_with(p)) {
            return Some((comm, ppid));
        }
        if ppid == 1 {
            return None;
        }
        current = ppid;
    }
    None
}

fn read_comm(pid: i32) -> Option<String> {
    std::fs::read_to_string(format!("/proc/{pid}/comm"))
        .ok()
        .map(|s| s.trim().to_string())
}

fn process_uid(pid: i32) -> Option<u32> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    status
        .lines()
        .find_map(|l| l.strip_prefix("Uid:"))
        .and_then(|v| v.split_whitespace().next()?.parse().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utmp_entry(kind: i16, line: &str, user: &str) -> UtmpEntry {
        UtmpEntry {
            kind,
            pid: 100,
            line: line.into(),
            user: user.into(),
            host: String::new(),
        }
    }

    fn session(tty: &str) -> LiveSession {
        LiveSession {
            pid: 4242,
            tty: tty.into(),
            uid: 0,
            comm: "bash".into(),
            via: "sshd".into(),
            via_pid: 4200,
        }
    }

    #[test]
    fn a_login_missing_from_utmp_is_reported() {
        let views = LoginViews {
            utmp: Some(vec![utmp_entry(USER_PROCESS, "pts/0", "alice")]),
            live: vec![session("pts/0"), session("pts/7")],
        };
        let found = analyze(&views);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].rule_id, "rootkit.login_session_hidden_from_utmp");
        assert_eq!(found[0].subject, "tty:pts/7");
        assert_eq!(found[0].mitre_technique, "T1070.002");
    }

    #[test]
    fn recorded_logins_produce_nothing() {
        let views = LoginViews {
            utmp: Some(vec![
                utmp_entry(USER_PROCESS, "pts/0", "alice"),
                utmp_entry(USER_PROCESS, "tty1", "root"),
            ]),
            live: vec![session("pts/0"), session("tty1")],
        };
        assert!(analyze(&views).is_empty());
    }

    #[test]
    fn a_host_that_records_no_sessions_is_skipped() {
        // Containers and hosts whose PAM stack does not maintain utmp. An
        // empty file is not evidence that a session was removed from it.
        let views = LoginViews {
            utmp: Some(vec![utmp_entry(2, "~", "reboot")]),
            live: vec![session("pts/3")],
        };
        assert!(analyze(&views).is_empty());
    }

    #[test]
    fn an_unreadable_or_unrecognised_utmp_disables_the_check() {
        let views = LoginViews {
            utmp: None,
            live: vec![session("pts/3")],
        };
        assert!(analyze(&views).is_empty());
    }

    #[test]
    fn dead_utmp_entries_do_not_cover_for_a_missing_one() {
        // A DEAD_PROCESS record on the same line is not a live session.
        let views = LoginViews {
            utmp: Some(vec![
                utmp_entry(USER_PROCESS, "pts/0", "alice"),
                utmp_entry(8, "pts/7", "bob"),
            ]),
            live: vec![session("pts/7")],
        };
        assert_eq!(analyze(&views).len(), 1);
    }

    // ── utmp decoding ───────────────────────────────────────────────────────

    fn record(kind: i16, pid: i32, line: &str, user: &str, host: &str) -> Vec<u8> {
        let mut rec = vec![0u8; UTMP_RECORD];
        rec[0..2].copy_from_slice(&kind.to_ne_bytes());
        rec[4..8].copy_from_slice(&pid.to_ne_bytes());
        rec[8..8 + line.len()].copy_from_slice(line.as_bytes());
        rec[44..44 + user.len()].copy_from_slice(user.as_bytes());
        rec[76..76 + host.len()].copy_from_slice(host.as_bytes());
        rec
    }

    #[test]
    fn utmp_records_are_decoded() {
        let mut bytes = record(USER_PROCESS, 1234, "pts/2", "alice", "10.0.0.5");
        bytes.extend(record(2, 0, "~", "reboot", ""));

        let parsed = parse_utmp(&bytes).expect("recognised layout");
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].kind, USER_PROCESS);
        assert_eq!(parsed[0].pid, 1234);
        assert_eq!(parsed[0].line, "pts/2");
        assert_eq!(parsed[0].user, "alice");
        assert_eq!(parsed[0].host, "10.0.0.5");
        assert_eq!(parsed[1].user, "reboot");
    }

    #[test]
    fn an_unexpected_record_size_is_refused() {
        assert!(parse_utmp(&[0u8; 100]).is_none());
        assert!(parse_utmp(&[]).is_none());
    }

    #[test]
    fn an_out_of_range_record_type_is_refused() {
        // A different libc or architecture: better to decline than to invent
        // sessions out of misaligned bytes.
        let mut bytes = record(USER_PROCESS, 1, "pts/0", "a", "");
        bytes[0] = 0x5a;
        assert!(parse_utmp(&bytes).is_none());
    }

    // ── /proc decoding ──────────────────────────────────────────────────────

    #[test]
    fn pty_and_console_devices_are_named() {
        // pts/3 is major 136, minor 3.
        assert_eq!(tty_name((136 << 8) | 3), Some("pts/3".into()));
        // The second pty major continues the numbering.
        assert_eq!(tty_name(137 << 8), Some("pts/256".into()));
        assert_eq!(tty_name((4 << 8) | 1), Some("tty1".into()));
        assert_eq!(tty_name((4 << 8) | 64), Some("ttyS0".into()));
    }

    #[test]
    fn a_process_without_a_terminal_has_no_tty() {
        assert_eq!(tty_name(0), None);
        // Majors that are not terminals must not be named as one.
        assert_eq!(tty_name(7 << 8), None);
    }

    #[test]
    fn stat_fields_survive_a_comm_containing_spaces_and_parens() {
        let stat = "4242 (my prog (odd)) S 4200 4242 4242 34819 4242 4194304 …";
        assert_eq!(parse_stat_session(stat), Some((4242, 34819)));
    }

    #[test]
    fn a_truncated_stat_line_is_declined() {
        assert_eq!(parse_stat_session("4242 (bash) S 1"), None);
        assert_eq!(parse_stat_session("no parens here"), None);
    }

    #[test]
    #[ignore = "reads the live host"]
    fn the_live_views_agree() {
        let views = gather();
        assert!(
            analyze(&views).is_empty(),
            "every interactive login on an uncompromised host is recorded in utmp"
        );
    }
}
