//! Session / execution context capture (issue #32, point 5).
//!
//! Turns a bare PID into the [`SessionContext`] that answers *who* touched the
//! bait and *from where*: the login session (`loginuid` / `sessionid`), the
//! controlling terminal, the working directory, and the container / namespace /
//! cgroup the process ran in. The remote source IP is correlated separately by
//! the engine (it owns the auth.log history), so capture here leaves it `None`.
//!
//! All decoding is done by pure functions that are unit-tested directly; the
//! `/proc` reads sit behind [`ProcReader`] so the assembly logic is testable
//! without a live `/proc`.

// The session-capture half is consumed by the Linux honeytoken detector only;
// off-Linux it compiles (pure /proc string reads) but has no caller yet.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use crate::schema::{NamespaceIds, SessionContext};

/// The namespaces we record, paired with the `/proc/<pid>/ns/<name>` link name.
const NAMESPACES: &[&str] = &["pid", "net", "mnt", "user", "cgroup", "ipc", "uts"];

/// Per-process `/proc` reads needed to assemble a [`SessionContext`].
pub trait ProcReader {
    /// `/proc/<pid>/loginuid` (raw contents).
    fn loginuid(&self, pid: i32) -> Option<String>;
    /// `/proc/<pid>/sessionid` (raw contents).
    fn sessionid(&self, pid: i32) -> Option<String>;
    /// `/proc/<pid>/stat` (raw line) — used for the controlling tty.
    fn stat(&self, pid: i32) -> Option<String>;
    /// `/proc/<pid>/cgroup` (raw contents).
    fn cgroup(&self, pid: i32) -> Option<String>;
    /// `readlink /proc/<pid>/cwd`.
    fn cwd(&self, pid: i32) -> Option<String>;
    /// `readlink /proc/<pid>/ns/<ns>` target (e.g. `net:[4026531992]`).
    fn ns_link(&self, pid: i32, ns: &str) -> Option<String>;
    /// Resolve a username from a uid (via `/etc/passwd`).
    fn username_for_uid(&self, uid: u32) -> Option<String>;
}

/// Assemble the session context for `pid` from `r`. Every field is best-effort:
/// a process that has already exited yields a mostly-empty context rather than
/// an error, so detection never fails on missing forensics.
pub fn capture(r: &dyn ProcReader, pid: i32) -> SessionContext {
    let loginuid = r.loginuid(pid).as_deref().and_then(parse_id_field);
    let login_user = loginuid.and_then(|u| r.username_for_uid(u));
    let audit_session_id = r.sessionid(pid).as_deref().and_then(parse_id_field);

    let tty = r
        .stat(pid)
        .as_deref()
        .and_then(parse_tty_nr_from_stat)
        .and_then(tty_from_nr);

    let cwd = r.cwd(pid).filter(|s| !s.is_empty());

    let cgroup_raw = r.cgroup(pid);
    let cgroup = cgroup_raw.as_deref().and_then(most_specific_cgroup);
    let (container_runtime, container_id) = cgroup
        .as_deref()
        .and_then(container_from_cgroup)
        .map(|(rt, id)| (Some(rt.to_string()), Some(id)))
        .unwrap_or((None, None));

    let mut namespaces = NamespaceIds::default();
    for ns in NAMESPACES {
        let inode = r.ns_link(pid, ns).as_deref().and_then(parse_ns_inode);
        match *ns {
            "pid" => namespaces.pid = inode,
            "net" => namespaces.net = inode,
            "mnt" => namespaces.mnt = inode,
            "user" => namespaces.user = inode,
            "cgroup" => namespaces.cgroup = inode,
            "ipc" => namespaces.ipc = inode,
            "uts" => namespaces.uts = inode,
            _ => {}
        }
    }

    SessionContext {
        loginuid,
        login_user,
        audit_session_id,
        tty,
        cwd,
        cgroup,
        container_id,
        container_runtime,
        namespaces,
        remote_addr: None,
        remote_port: None,
    }
}

// ── Pure parsers ────────────────────────────────────────────────────────────

/// Parse a `loginuid`/`sessionid` field. The kernel writes `4294967295`
/// (`u32::MAX`, also rendered `-1`) when unset — both map to `None`.
pub fn parse_id_field(raw: &str) -> Option<u32> {
    let t = raw.trim();
    if t == "-1" {
        return None;
    }
    let v: u32 = t.parse().ok()?;
    (v != u32::MAX).then_some(v)
}

/// Extract `tty_nr` (field 7) from a `/proc/<pid>/stat` line. The comm (field 2)
/// is parenthesised and may contain spaces/parens, so we split after the last
/// `)` then skip `state pgrp session` to reach `tty_nr`.
pub fn parse_tty_nr_from_stat(stat: &str) -> Option<i32> {
    let rest = stat.get(stat.rfind(')')? + 1..)?;
    let mut f = rest.split_whitespace();
    let _state = f.next()?; // 3
    let _ppid = f.next()?; // 4
    let _pgrp = f.next()?; // 5
    let _session = f.next()?; // 6
    f.next()?.parse::<i32>().ok() // 7: tty_nr
}

/// Decode a Linux `tty_nr` device number into a terminal name. Handles the two
/// cases that matter for interactive sessions: pseudo-terminals (major 136–143
/// → `pts/N`) and virtual consoles / legacy ttys (major 4 → `ttyN`). `0` (no
/// controlling terminal) and unrecognised majors yield `None`.
pub fn tty_from_nr(nr: i32) -> Option<String> {
    if nr == 0 {
        return None;
    }
    let dev = nr as u32;
    let major = (dev >> 8) & 0xfff;
    // Minor packs low 8 bits + high bits (from 20 up); for the small minors we
    // care about, the low byte is sufficient.
    let minor = (dev & 0xff) | ((dev >> 12) & 0xfff00);
    match major {
        136..=143 => Some(format!("pts/{}", (major - 136) * 256 + minor)),
        4 => Some(format!("tty{minor}")),
        _ => None,
    }
}

/// Parse a namespace symlink target (`net:[4026531992]`) into its inode id.
pub fn parse_ns_inode(link: &str) -> Option<u64> {
    let start = link.find('[')? + 1;
    let end = link.find(']')?;
    link.get(start..end)?.parse().ok()
}

/// Choose the most specific cgroup path from a `/proc/<pid>/cgroup` file. For
/// cgroup v2 there is a single `0::/path` line; for v1 there are several
/// `hier:controllers:/path` lines — we return the longest (deepest) path, which
/// is the one that carries a container scope when present.
pub fn most_specific_cgroup(content: &str) -> Option<String> {
    content
        .lines()
        .filter_map(|l| l.rsplit(':').next())
        .map(|p| p.trim())
        .filter(|p| !p.is_empty() && *p != "/")
        .max_by_key(|p| p.len())
        .map(|p| p.to_string())
}

/// Identify the container runtime and id from a cgroup path, if it is one.
/// Recognises Docker, containerd/CRI-O, Podman/libpod and Kubernetes `kubepods`
/// scopes and extracts the 64-hex (or `runtime-<id>`) container id.
pub fn container_from_cgroup(path: &str) -> Option<(&'static str, String)> {
    // Look at each path segment; the container id is the segment that contains a
    // long hex run, optionally wrapped as `docker-<id>.scope` / `libpod-<id>`.
    for seg in path.split('/').rev() {
        let core = seg
            .trim_end_matches(".scope")
            .rsplit(['-', ':'])
            .next()
            .unwrap_or(seg);
        if is_hex_id(core) {
            let runtime = if path.contains("kubepods") {
                "kubepods"
            } else if seg.contains("docker") {
                "docker"
            } else if seg.contains("libpod") || path.contains("libpod") {
                "podman"
            } else if seg.contains("crio") || path.contains("crio") {
                "cri-o"
            } else {
                "containerd"
            };
            return Some((runtime, core.to_string()));
        }
    }
    None
}

/// A container-id-shaped token: a hex run of at least 12 chars (Docker short id)
/// up to the full 64-char digest.
fn is_hex_id(s: &str) -> bool {
    (12..=64).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_field_handles_unset_sentinels() {
        assert_eq!(parse_id_field("1000\n"), Some(1000));
        assert_eq!(parse_id_field("4294967295"), None);
        assert_eq!(parse_id_field("-1"), None);
        assert_eq!(parse_id_field("notanum"), None);
    }

    #[test]
    fn tty_nr_parsed_from_stat() {
        // ... ppid pgrp session tty_nr ...  comm has spaces+parens.
        let stat = "100 (weird )( name) S 7 100 7 34816 100 ...";
        // fields after ')': state=S ppid=7 pgrp=100 session=7 tty_nr=34816
        assert_eq!(parse_tty_nr_from_stat(stat), Some(34816));
    }

    #[test]
    fn tty_nr_decodes_pts_and_console() {
        // 34816 = 0x8800 → major 136, minor 0 → pts/0
        assert_eq!(tty_from_nr(34816).as_deref(), Some("pts/0"));
        // 34819 = 0x8803 → pts/3
        assert_eq!(tty_from_nr(34819).as_deref(), Some("pts/3"));
        // 1025 = 0x401 → major 4, minor 1 → tty1
        assert_eq!(tty_from_nr(1025).as_deref(), Some("tty1"));
        // No controlling terminal.
        assert_eq!(tty_from_nr(0), None);
    }

    #[test]
    fn ns_inode_parsed() {
        assert_eq!(parse_ns_inode("net:[4026531992]"), Some(4026531992));
        assert_eq!(parse_ns_inode("mnt:[abc]"), None);
        assert_eq!(parse_ns_inode("garbage"), None);
    }

    #[test]
    fn cgroup_picks_deepest_path() {
        // cgroup v2 single line.
        let v2 = "0::/system.slice/docker-abc.scope\n";
        assert_eq!(
            most_specific_cgroup(v2).as_deref(),
            Some("/system.slice/docker-abc.scope")
        );
        // cgroup v1 multi-line: deepest path wins over a bare "/".
        let v1 = "12:pids:/\n3:memory:/docker/deadbeef\n2:cpu:/\n";
        assert_eq!(
            most_specific_cgroup(v1).as_deref(),
            Some("/docker/deadbeef")
        );
    }

    #[test]
    fn container_id_extracted_per_runtime() {
        let full = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let docker = format!("/system.slice/docker-{full}.scope");
        assert_eq!(
            container_from_cgroup(&docker),
            Some(("docker", full.to_string()))
        );

        let k8s = format!("/kubepods/besteffort/pod123/{full}");
        assert_eq!(
            container_from_cgroup(&k8s),
            Some(("kubepods", full.to_string()))
        );

        let podman = format!("/machine.slice/libpod-{full}.scope");
        assert_eq!(
            container_from_cgroup(&podman),
            Some(("podman", full.to_string()))
        );

        // A host process (no container scope) yields nothing.
        assert_eq!(container_from_cgroup("/system.slice/sshd.service"), None);
        assert_eq!(container_from_cgroup("/user.slice/user-1000.slice"), None);
    }

    /// Fake `/proc` exercising the full assembly.
    struct FakeProc;
    impl ProcReader for FakeProc {
        fn loginuid(&self, _: i32) -> Option<String> {
            Some("1000\n".into())
        }
        fn sessionid(&self, _: i32) -> Option<String> {
            Some("42\n".into())
        }
        fn stat(&self, _: i32) -> Option<String> {
            Some("100 (bash) S 7 100 7 34819 100".into())
        }
        fn cgroup(&self, _: i32) -> Option<String> {
            Some("0::/system.slice/sshd.service\n".into())
        }
        fn cwd(&self, _: i32) -> Option<String> {
            Some("/home/alice".into())
        }
        fn ns_link(&self, _: i32, ns: &str) -> Option<String> {
            (ns == "net").then(|| "net:[4026531992]".to_string())
        }
        fn username_for_uid(&self, uid: u32) -> Option<String> {
            (uid == 1000).then(|| "alice".to_string())
        }
    }

    #[test]
    fn capture_assembles_full_context() {
        let s = capture(&FakeProc, 100);
        assert_eq!(s.loginuid, Some(1000));
        assert_eq!(s.login_user.as_deref(), Some("alice"));
        assert_eq!(s.audit_session_id, Some(42));
        assert_eq!(s.tty.as_deref(), Some("pts/3"));
        assert_eq!(s.cwd.as_deref(), Some("/home/alice"));
        assert_eq!(s.cgroup.as_deref(), Some("/system.slice/sshd.service"));
        assert_eq!(s.container_id, None, "a host service is not a container");
        assert_eq!(s.namespaces.net, Some(4026531992));
        assert!(
            s.remote_addr.is_none(),
            "remote IP is correlated by the engine"
        );
    }
}
