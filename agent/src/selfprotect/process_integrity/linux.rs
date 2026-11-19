//! Linux process-integrity checks: tracer, mappings, preload, dumpability.
//!
//! The parsers are pure functions over `/proc` text and are unit-tested with
//! fixtures; the live checks are exercised against the test process itself.
//!
//! What counts as suspicious in `/proc/self/maps` (executable mappings only):
//! * anonymous executable memory (shellcode, injected stubs; the agent has no
//!   JIT) and any writable+executable mapping,
//! * executable `[heap]`/`[stack]`,
//! * a deleted file that is memfd/`/dev/shm`/temp-backed or outside the system
//!   library directories (a library replaced by the package manager while the
//!   agent runs, or the agent's own updated binary, is *not* flagged),
//! * a file-backed library outside the trusted directories and the allowlist.

use std::collections::HashSet;

use serde_json::json;
use tracing::{info, warn};

use super::{Config, Finding, Kind};
use crate::schema::Severity;

/// Directories whose libraries the agent may legitimately map.
const TRUSTED_PREFIXES: &[&str] = &[
    "/usr/",
    "/lib/",
    "/lib32/",
    "/lib64/",
    "/libx32/",
    "/opt/",
    "/snap/",
    "/nix/store/",
    "/gnu/store/",
];
/// Where an attacker (or a fileless loader) stages code.
const STAGING_PREFIXES: &[&str] = &["/memfd:", "/dev/shm/", "/tmp/", "/var/tmp/", "/run/user/"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mapping {
    pub start: u64,
    pub end: u64,
    pub perms: String,
    pub path: String,
}

pub fn parse_maps(text: &str) -> Vec<Mapping> {
    text.lines()
        .filter_map(|line| {
            // range perms offset dev inode [path, may contain spaces]
            let mut rest = line;
            let mut fields = [""; 5];
            for f in &mut fields {
                rest = rest.trim_start();
                let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
                (*f, rest) = rest.split_at(end);
            }
            let (s, e) = fields[0].split_once('-')?;
            Some(Mapping {
                start: u64::from_str_radix(s, 16).ok()?,
                end: u64::from_str_radix(e, 16).ok()?,
                perms: fields[1].to_string(),
                path: rest.trim().to_string(),
            })
        })
        .collect()
}

pub struct MapContext<'a> {
    pub own_exe: &'a str,
    pub allow: &'a [String],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MapAnomaly {
    pub kind: &'static str,
    pub path: String,
    pub perms: String,
    pub ranges: Vec<(u64, u64)>,
}

fn starts_with_any(path: &str, prefixes: &[&str]) -> bool {
    prefixes.iter().any(|p| path.starts_with(p))
}

/// Classify executable mappings; anonymous ones are grouped (their addresses
/// change between scans, the fact does not).
pub fn classify_maps(maps: &[Mapping], ctx: &MapContext<'_>) -> Vec<MapAnomaly> {
    let mut out: Vec<MapAnomaly> = Vec::new();
    let mut add = |kind: &'static str, m: &Mapping, path: &str| match out
        .iter_mut()
        .find(|a| a.kind == kind && a.path == path)
    {
        Some(a) => {
            if a.ranges.len() < 4 {
                a.ranges.push((m.start, m.end));
            }
        }
        None => out.push(MapAnomaly {
            kind,
            path: path.to_string(),
            perms: m.perms.clone(),
            ranges: vec![(m.start, m.end)],
        }),
    };
    for m in maps {
        let exec = m.perms.as_bytes().get(2) == Some(&b'x');
        let write = m.perms.as_bytes().get(1) == Some(&b'w');
        if !exec {
            continue;
        }
        let path = m.path.as_str();
        if matches!(path, "[vdso]" | "[vsyscall]") {
            continue;
        }
        if path.is_empty() {
            add(
                if write {
                    "anonymous_rwx"
                } else {
                    "anonymous_exec"
                },
                m,
                "",
            );
        } else if path == "[heap]" || path == "[stack]" || path.starts_with("[stack:") {
            add("exec_heap_or_stack", m, path);
        } else if let Some(real) = path.strip_suffix(" (deleted)") {
            // The updated agent binary, or a library the package manager
            // replaced while the agent runs, is expected; staged code is not.
            if real != ctx.own_exe
                && (starts_with_any(real, STAGING_PREFIXES)
                    || !starts_with_any(real, TRUSTED_PREFIXES))
            {
                add("deleted_exec", m, real);
            }
        } else if starts_with_any(path, STAGING_PREFIXES) {
            add("staged_library_exec", m, path);
        } else if write {
            add("rwx_file_mapping", m, path);
        } else if path == ctx.own_exe
            || starts_with_any(path, TRUSTED_PREFIXES)
            || ctx
                .allow
                .iter()
                .any(|a| path.to_ascii_lowercase().starts_with(a))
            || path.starts_with("/proc/self/")
        {
            continue;
        } else if path.starts_with('/') {
            add("untrusted_library_exec", m, path);
        }
    }
    out
}

/// Entries of `/etc/ld.so.preload` (comments and blanks removed; entries may
/// be separated by whitespace or colons).
pub fn parse_preload_file(text: &str) -> Vec<String> {
    text.lines()
        .map(|l| l.split('#').next().unwrap_or("").trim())
        .flat_map(|l| l.split(|c: char| c.is_whitespace() || c == ':'))
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

/// `LD_PRELOAD` entries from the NUL-separated initial environment.
pub fn parse_environ_preload(environ: &[u8]) -> Vec<String> {
    environ
        .split(|&b| b == 0)
        .filter_map(|kv| kv.strip_prefix(b"LD_PRELOAD="))
        .flat_map(|v| {
            String::from_utf8_lossy(v)
                .split(|c: char| c.is_whitespace() || c == ':')
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .collect()
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Status {
    pub name: String,
    pub ppid: u32,
    pub tracer_pid: u32,
}

pub fn parse_status(text: &str) -> Status {
    let mut s = Status::default();
    for line in text.lines() {
        let Some((k, v)) = line.split_once(':') else {
            continue;
        };
        let v = v.trim();
        match k {
            "Name" => s.name = v.to_string(),
            "PPid" => s.ppid = v.parse().unwrap_or(0),
            "TracerPid" => s.tracer_pid = v.parse().unwrap_or(0),
            _ => {}
        }
    }
    s
}

/// `(tracee pid, tracee status)` pairs whose tracer is somebody: restricted to
/// the agent and its direct children (the watchdog subprocess).
pub fn traced_agent_processes(statuses: &[(u32, Status)], own_pid: u32) -> Vec<(u32, Status)> {
    statuses
        .iter()
        .filter(|(pid, s)| s.tracer_pid != 0 && (*pid == own_pid || s.ppid == own_pid))
        .cloned()
        .collect()
}

fn read(path: &str) -> Option<String> {
    std::fs::read_to_string(path).ok()
}

fn proc_statuses() -> Vec<(u32, Status)> {
    let Ok(dir) = std::fs::read_dir("/proc") else {
        return Vec::new();
    };
    dir.flatten()
        .filter_map(|e| {
            let pid: u32 = e.file_name().to_str()?.parse().ok()?;
            Some((pid, parse_status(&read(&format!("/proc/{pid}/status"))?)))
        })
        .collect()
}

/// Mark the process non-dumpable: no core dumps with agent memory, and a
/// same-uid process can no longer `ptrace`/read `/proc/<pid>/mem` of it.
/// Root (and `CAP_SYS_PTRACE`) is unaffected, so this is a hardening step
/// against unprivileged tooling, not a security boundary. Costs: no core dump
/// for crash analysis (`TRAPD_SELFPROTECT_DUMPABLE=on` keeps the default).
pub fn harden() {
    if super::parse_switch(
        std::env::var("TRAPD_SELFPROTECT_DUMPABLE").ok().as_deref(),
        false,
    ) {
        info!("PR_SET_DUMPABLE left unchanged by configuration");
        return;
    }
    // SAFETY: prctl with PR_SET_DUMPABLE takes plain integers.
    let rc = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
    if rc == 0 {
        info!("process set non-dumpable (PR_SET_DUMPABLE=0)");
    } else {
        warn!(error = %std::io::Error::last_os_error(), "PR_SET_DUMPABLE not applied");
    }
}

pub struct Checker {
    cfg: Config,
    exe: String,
}

impl Checker {
    pub fn new(cfg: &Config) -> Self {
        let exe = std::env::current_exe()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default();
        Self {
            cfg: cfg.clone(),
            exe,
        }
    }

    /// Cheap checks, every tick.
    pub fn self_check(&mut self) -> Vec<Finding> {
        let mut out = Vec::new();
        if self.cfg.modules {
            out.extend(self.module_findings());
        }
        if self.cfg.debugger {
            out.extend(self.tracer_findings());
        }
        out
    }

    /// A `/proc` scan, every other tick (children of the agent being traced).
    pub fn watch(&mut self) -> Vec<Finding> {
        Vec::new()
    }

    fn module_findings(&self) -> Vec<Finding> {
        let mut out = Vec::new();
        if let Some(text) = read("/proc/self/maps") {
            let ctx = MapContext {
                own_exe: &self.exe,
                allow: &self.cfg.module_allow,
            };
            for a in classify_maps(&parse_maps(&text), &ctx) {
                let sev = match a.kind {
                    "anonymous_exec" | "anonymous_rwx" | "exec_heap_or_stack" | "deleted_exec" => {
                        Severity::High
                    }
                    _ => Severity::Medium,
                };
                out.push(Finding {
                    kind: Kind::ModuleInjected,
                    severity: sev,
                    subject: if a.path.is_empty() {
                        format!("{} mapping", a.kind)
                    } else {
                        a.path.clone()
                    },
                    detail: format!(
                        "Executable memory mapping of kind '{}' in the agent process",
                        a.kind
                    ),
                    evidence: json!({
                        "reason": a.kind,
                        "path": a.path,
                        "perms": a.perms,
                        "ranges": a.ranges.iter()
                            .map(|(s, e)| format!("{s:x}-{e:x}")).collect::<Vec<_>>(),
                    }),
                    dedup_key: format!("module:{}:{}", a.kind, a.path),
                });
            }
        }
        let mut preload: Vec<(&'static str, String)> = Vec::new();
        if let Ok(env) = std::fs::read("/proc/self/environ") {
            preload.extend(
                parse_environ_preload(&env)
                    .into_iter()
                    .map(|l| ("ld_preload_env", l)),
            );
        }
        if let Some(t) = read("/etc/ld.so.preload") {
            preload.extend(
                parse_preload_file(&t)
                    .into_iter()
                    .map(|l| ("ld_so_preload", l)),
            );
        }
        for (reason, lib) in preload {
            if self
                .cfg
                .module_allow
                .iter()
                .any(|a| lib.to_ascii_lowercase().starts_with(a))
            {
                continue;
            }
            out.push(Finding {
                kind: Kind::ModuleInjected,
                severity: Severity::High,
                subject: lib.clone(),
                detail: format!("Library forced into the agent via {reason}"),
                evidence: json!({ "reason": reason, "path": lib }),
                dedup_key: format!("module:{reason}:{lib}"),
            });
        }
        out
    }

    fn tracer_findings(&self) -> Vec<Finding> {
        let own = std::process::id();
        let mut watched: Vec<(u32, Status)> = Vec::new();
        if let Some(t) = read("/proc/self/status") {
            watched.push((own, parse_status(&t)));
        }
        // Children (watchdog subprocess) need a /proc scan; skip it when no
        // child exists, which is the common case for the agent process itself.
        if self.cfg.debugger && has_children(own) {
            watched.extend(proc_statuses());
        }
        let mut seen = HashSet::new();
        traced_agent_processes(&watched, own)
            .into_iter()
            .filter(|(pid, _)| seen.insert(*pid))
            .map(|(pid, st)| {
                let tracer = st.tracer_pid;
                let comm = read(&format!("/proc/{tracer}/comm"))
                    .unwrap_or_default()
                    .trim()
                    .to_string();
                let exe = std::fs::read_link(format!("/proc/{tracer}/exe"))
                    .map(|p| p.to_string_lossy().into_owned())
                    .unwrap_or_default();
                Finding {
                    kind: Kind::DebuggerAttached,
                    severity: Severity::High,
                    subject: format!("pid {pid} traced by pid {tracer} ({comm})"),
                    detail: "A process is attached to the agent via ptrace".into(),
                    evidence: json!({
                        "tracee_pid": pid,
                        "tracee_name": st.name,
                        "tracer_pid": tracer,
                        "tracer_comm": comm,
                        "tracer_exe": exe,
                    }),
                    dedup_key: format!("debugger:{tracer}:{pid}"),
                }
            })
            .collect()
    }
}

fn has_children(pid: u32) -> bool {
    // `children` needs CONFIG_PROC_CHILDREN; when absent assume yes and scan.
    match std::fs::read_to_string(format!("/proc/{pid}/task/{pid}/children")) {
        Ok(s) => !s.trim().is_empty(),
        Err(_) => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAPS: &str = "\
55d0c8a00000-55d0c8a50000 r--p 00000000 08:01 1310725 /usr/local/bin/trapd-agent
55d0c8a50000-55d0c9000000 r-xp 00050000 08:01 1310725 /usr/local/bin/trapd-agent
55d0c9a00000-55d0c9a21000 rw-p 00000000 00:00 0                          [heap]
7f1c00000000-7f1c00021000 rw-p 00000000 00:00 0
7f1c10000000-7f1c10200000 r-xp 00000000 08:01 2097 /usr/lib/x86_64-linux-gnu/libc.so.6
7f1c20000000-7f1c20010000 r-xp 00000000 08:01 3001 /usr/lib/x86_64-linux-gnu/libssl.so.3 (deleted)
7ffd5a1ff000-7ffd5a221000 rw-p 00000000 00:00 0                          [stack]
7ffd5a3f0000-7ffd5a3f4000 r--p 00000000 00:00 0                          [vvar]
7ffd5a3f4000-7ffd5a3f6000 r-xp 00000000 00:00 0                          [vdso]
";

    fn ctx<'a>(allow: &'a [String]) -> MapContext<'a> {
        MapContext {
            own_exe: "/usr/local/bin/trapd-agent",
            allow,
        }
    }

    #[test]
    fn a_normal_process_has_no_anomalies() {
        let maps = parse_maps(MAPS);
        assert_eq!(maps.len(), 9);
        assert_eq!(maps[3].path, "");
        assert_eq!(
            maps[5].path,
            "/usr/lib/x86_64-linux-gnu/libssl.so.3 (deleted)"
        );
        assert!(classify_maps(&maps, &ctx(&[])).is_empty());
    }

    #[test]
    fn injected_mappings_are_classified() {
        let text = format!(
            "{MAPS}\
7f2000000000-7f2000001000 r-xp 00000000 00:00 0
7f2000002000-7f2000003000 rwxp 00000000 00:00 0
7f2000004000-7f2000005000 r-xp 00000000 00:01 77 /memfd:payload (deleted)
7f2000006000-7f2000007000 r-xp 00000000 08:01 5 /tmp/evil.so
7f2000008000-7f2000009000 r-xp 00000000 08:01 6 /home/x/inject.so
7f200000a000-7f200000b000 r-xp 00000000 08:01 7 /tmp/gone.so (deleted)
"
        );
        let a = classify_maps(&parse_maps(&text), &ctx(&[]));
        let kinds: Vec<_> = a.iter().map(|x| (x.kind, x.path.as_str())).collect();
        assert!(kinds.contains(&("anonymous_exec", "")));
        assert!(kinds.contains(&("anonymous_rwx", "")));
        assert!(kinds.contains(&("deleted_exec", "/memfd:payload")));
        assert!(kinds.contains(&("staged_library_exec", "/tmp/evil.so")));
        assert!(kinds.contains(&("untrusted_library_exec", "/home/x/inject.so")));
        assert!(kinds.contains(&("deleted_exec", "/tmp/gone.so")));
        assert_eq!(a.len(), 6);
    }

    #[test]
    fn upgraded_binary_and_libraries_are_not_findings() {
        let text = "\
55d0c8a50000-55d0c9000000 r-xp 00050000 08:01 1 /usr/local/bin/trapd-agent (deleted)
7f1c20000000-7f1c20010000 r-xp 00000000 08:01 3 /usr/lib/x86_64-linux-gnu/libc.so.6 (deleted)
";
        assert!(classify_maps(&parse_maps(text), &ctx(&[])).is_empty());
    }

    #[test]
    fn the_allowlist_silences_a_vendor_library() {
        let text = "7f2000008000-7f2000009000 r-xp 00000000 08:01 6 /srv/vendor/av/hook.so\n";
        let maps = parse_maps(text);
        assert_eq!(classify_maps(&maps, &ctx(&[])).len(), 1);
        assert!(classify_maps(&maps, &ctx(&["/srv/vendor/".to_string()])).is_empty());
    }

    #[test]
    fn paths_with_spaces_and_garbage_lines_parse() {
        let text = "7f00-7f10 r-xp 00000000 08:01 9 /opt/my app/lib.so\nnot a maps line\n";
        let maps = parse_maps(text);
        assert_eq!(maps.len(), 1);
        assert_eq!(maps[0].path, "/opt/my app/lib.so");
    }

    #[test]
    fn preload_sources_are_parsed() {
        assert_eq!(
            parse_preload_file("# comment\n/lib/a.so /lib/b.so\n\n/lib/c.so # tail\n"),
            ["/lib/a.so", "/lib/b.so", "/lib/c.so"]
        );
        assert!(parse_preload_file("# only\n").is_empty());
        let env = b"PATH=/bin\0LD_PRELOAD=/tmp/x.so:/tmp/y.so\0HOME=/root\0";
        assert_eq!(parse_environ_preload(env), ["/tmp/x.so", "/tmp/y.so"]);
        assert!(parse_environ_preload(b"PATH=/bin\0").is_empty());
        assert!(parse_environ_preload(b"").is_empty());
    }

    #[test]
    fn status_parsing_and_tracee_selection() {
        let st = parse_status("Name:\ttrapd-agent\nPPid:\t1\nTracerPid:\t4242\nUid:\t0\n");
        assert_eq!(
            st,
            Status {
                name: "trapd-agent".into(),
                ppid: 1,
                tracer_pid: 4242
            }
        );
        let list = vec![
            (100, st.clone()),
            (
                101,
                Status {
                    name: "watchdog".into(),
                    ppid: 100,
                    tracer_pid: 9,
                },
            ),
            (
                102,
                Status {
                    name: "other".into(),
                    ppid: 1,
                    tracer_pid: 9,
                },
            ),
            (100 + 3, Status::default()),
        ];
        let pids: Vec<u32> = traced_agent_processes(&list, 100)
            .into_iter()
            .map(|(p, _)| p)
            .collect();
        assert_eq!(pids, [100, 101]);
    }

    // ---- live checks against the running test process -------------------

    fn cfg() -> Config {
        Config::default()
    }

    /// `self_check` reads the whole process's `/proc/self/maps`, and
    /// `live_anonymous_executable_memory_is_detected` maps an RWX page into the same process. The
    /// default parallel test runner could scan during that window and fail the clean-process test, so
    /// every live scan holds this lock.
    static LIVE_SCAN: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn live_a_plain_test_process_has_no_injection_findings() {
        let _scan = LIVE_SCAN.lock().unwrap_or_else(|e| e.into_inner());
        let mut c = Checker::new(&cfg());
        let findings: Vec<_> = c
            .self_check()
            .into_iter()
            .filter(|f| f.kind == Kind::ModuleInjected)
            .collect();
        // LD_PRELOAD in the CI environment (e.g. a sanitizer) would be a real
        // finding; everything else must be clean.
        let unexpected: Vec<_> = findings
            .iter()
            .filter(|f| !f.dedup_key.starts_with("module:ld_"))
            .collect();
        assert!(unexpected.is_empty(), "{unexpected:?}");
    }

    #[test]
    fn live_anonymous_executable_memory_is_detected() {
        let _scan = LIVE_SCAN.lock().unwrap_or_else(|e| e.into_inner());
        // SAFETY: anonymous private mapping, unmapped below.
        let p = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                4096,
                libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if p == libc::MAP_FAILED {
            return; // W^X-enforcing environment: nothing to detect
        }
        let mut c = Checker::new(&cfg());
        let found = c.self_check();
        // SAFETY: `p` came from the mmap above with the same length.
        unsafe { libc::munmap(p, 4096) };
        assert!(
            found
                .iter()
                .any(|f| f.kind == Kind::ModuleInjected && f.dedup_key.contains("anonymous_rwx")),
            "{found:?}"
        );
    }

    #[test]
    fn live_a_ptrace_attached_child_is_detected() {
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn sleep");
        let pid = child.id() as libc::pid_t;
        // SAFETY: PTRACE_SEIZE of our own child; detached before the kill.
        let rc = unsafe { libc::ptrace(libc::PTRACE_SEIZE, pid, 0, 0) };
        if rc != 0 {
            let _ = child.kill();
            let _ = child.wait();
            return; // ptrace forbidden (seccomp/yama): cannot test live here
        }
        let own = std::process::id();
        let statuses = proc_statuses();
        let traced = traced_agent_processes(&statuses, own);
        // SAFETY: matching detach of the seized child.
        unsafe { libc::ptrace(libc::PTRACE_DETACH, pid, 0, 0) };
        let _ = child.kill();
        let _ = child.wait();
        // The tracer is the *thread* that seized the child (a debugger process
        // has tid == pid); what matters is that the child is reported as traced.
        assert!(
            traced
                .iter()
                .any(|(p, s)| *p == pid as u32 && s.tracer_pid != 0 && s.ppid == own),
            "{traced:?}"
        );
    }

    /// `cargo test -- --ignored --nocapture measure_self_check_cost`
    #[test]
    #[ignore = "measurement, not an assertion"]
    fn measure_self_check_cost() {
        let mut c = Checker::new(&cfg());
        let n = 2000u32;
        let cpu = |f: &mut dyn FnMut()| {
            let mut ts = libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };
            // SAFETY: valid out-pointer for the thread CPU clock.
            unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut ts) };
            let t0 = ts.tv_sec as f64 + ts.tv_nsec as f64 / 1e9;
            for _ in 0..n {
                f();
            }
            unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut ts) };
            (ts.tv_sec as f64 + ts.tv_nsec as f64 / 1e9 - t0) / f64::from(n)
        };
        let per_check = cpu(&mut || {
            std::hint::black_box(c.self_check());
        });
        let per_scan = cpu(&mut || {
            std::hint::black_box(proc_statuses());
        });
        let procs = proc_statuses().len();
        println!(
            "self_check: {:.1} us per pass -> {:.5} % of one core at one pass / 30 s",
            per_check * 1e6,
            per_check / 30.0 * 100.0
        );
        println!(
            "full /proc status scan ({procs} processes): {:.1} us -> {:.5} % at one scan / 60 s \
             (only when the agent has child processes)",
            per_scan * 1e6,
            per_scan / 60.0 * 100.0
        );
    }

    #[test]
    fn live_set_dumpable_zero() {
        std::env::remove_var("TRAPD_SELFPROTECT_DUMPABLE");
        harden();
        // SAFETY: PR_GET_DUMPABLE takes no pointers.
        let now = unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) };
        // Restore so other tests (core dumps on failure) behave normally.
        unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 1, 0, 0, 0) };
        assert_eq!(now, 0);
    }
}
