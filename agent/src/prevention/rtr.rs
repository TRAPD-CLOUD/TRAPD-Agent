//! Real-Time Response (RTR) helpers — the pure, testable core of the live
//! remediation commands (signed script execution + artifact collection).
//!
//! RTR rides the **existing Ed25519-signed command channel**: every RTR command
//! is verified against the backend's signing key exactly like `KillPid` or
//! `QuarantineFile`, and is additionally gated behind `rtr_enabled` (off by
//! default). There is no new, unauthenticated remote-shell surface — so this
//! does not depend on mTLS. Results (script output, file/memory artifacts) are
//! returned through the normal audited event stream.
//!
//! This module holds only the side-effect-free pieces — output capping/encoding,
//! memory-region selection and interpreter resolution — so the parts that decide
//! *what bytes leave the host* and *what gets executed* are unit-tested. The
//! actual process spawn / `/proc` reads live on the prevention engine.

use base64::Engine as _;

#[cfg(target_os = "linux")]
use super::super::collectors::linux::memscan;

/// A size-capped, base64-encoded artifact plus provenance about truncation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Artifact {
    /// Base64 of the (possibly truncated) bytes.
    pub b64: String,
    /// Number of bytes actually encoded (≤ `total_len`).
    pub returned_len: usize,
    /// Original byte length before any truncation.
    pub total_len: usize,
    /// True when `returned_len < total_len`.
    pub truncated: bool,
}

/// Cap `data` to `max` bytes and base64-encode it. Never returns more than
/// `max` bytes of payload, so a single result event stays within the backend's
/// per-event size limit.
pub fn cap_and_encode(data: &[u8], max: usize) -> Artifact {
    let total_len = data.len();
    let returned_len = total_len.min(max);
    let slice = &data[..returned_len];
    Artifact {
        b64: base64::engine::general_purpose::STANDARD.encode(slice),
        returned_len,
        total_len,
        truncated: returned_len < total_len,
    }
}

/// An artifact for `captured` bytes that are a prefix of `total_len` bytes:
/// the reader already stopped at the cap, so only the count is known.
pub fn encode_prefix(captured: &[u8], total_len: usize) -> Artifact {
    Artifact {
        b64: base64::engine::general_purpose::STANDARD.encode(captured),
        returned_len: captured.len(),
        total_len: total_len.max(captured.len()),
        truncated: captured.len() < total_len,
    }
}

/// Read at most `cap` bytes of a regular file for `CollectFile`.
///
/// `std::fs::read` would load the whole file: a signed `collect /dev/zero`
/// or a multi-gigabyte log would exhaust the agent's memory, and a FIFO
/// would block the response engine forever. The file is opened without
/// blocking and refused unless it is a regular file; reading stops at the cap.
/// Procfs files report a length of zero, so the size is what was read when
/// the metadata does not know better.
pub fn collect_file(path: &str, cap: usize) -> std::io::Result<Artifact> {
    use std::io::Read;
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY);
    }
    let file = opts.open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "not a regular file (devices, FIFOs, sockets and directories are refused)",
        ));
    }
    let mut buf = Vec::with_capacity(cap.min(1 << 20));
    // One byte past the cap tells a file of exactly `cap` bytes from a longer one.
    file.take(cap as u64 + 1).read_to_end(&mut buf)?;
    let read = buf.len();
    buf.truncate(cap);
    let total = usize::try_from(meta.len()).unwrap_or(usize::MAX).max(read);
    Ok(encode_prefix(&buf, total))
}

/// Outcome of a bounded script run.
#[derive(Debug)]
pub struct ScriptRun {
    pub success: bool,
    pub code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stdout_total: usize,
    pub stderr: Vec<u8>,
    pub stderr_total: usize,
    pub note: String,
}

/// Keep the first `cap` bytes of a stream and count the rest. The stream is
/// drained to the end so the script never blocks on a full pipe, but what is
/// kept in memory never exceeds the cap.
async fn read_bounded<R: tokio::io::AsyncRead + Unpin>(
    stream: Option<R>,
    cap: usize,
) -> (Vec<u8>, usize) {
    use tokio::io::AsyncReadExt;
    let Some(mut stream) = stream else {
        return (Vec::new(), 0);
    };
    let mut kept = Vec::new();
    let mut total = 0usize;
    let mut chunk = vec![0u8; 16 * 1024];
    loop {
        match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                total = total.saturating_add(n);
                let room = cap.saturating_sub(kept.len());
                kept.extend_from_slice(&chunk[..n.min(room)]);
            }
        }
    }
    (kept, total)
}

/// Run a signed RTR script with bounded output and a hard deadline.
///
/// The script runs in its own process group. On timeout the whole group is
/// killed, not just the interpreter: a backgrounded child would otherwise
/// keep running unobserved and hold the output pipes open. Output beyond
/// `cap` bytes per stream is counted but not kept, so a script that prints
/// gigabytes cannot exhaust the agent's memory.
pub async fn run_script_bounded(
    program: &str,
    args: &[String],
    timeout: std::time::Duration,
    cap: usize,
) -> ScriptRun {
    use std::process::Stdio;
    let mut cmd = tokio::process::Command::new(program);
    cmd.args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    #[cfg(unix)]
    cmd.process_group(0);
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            return ScriptRun {
                success: false,
                code: None,
                stdout: Vec::new(),
                stdout_total: 0,
                stderr: Vec::new(),
                stderr_total: 0,
                note: format!("spawn failed: {e}"),
            }
        }
    };
    let pgid = child.id();
    let out = tokio::spawn(read_bounded(child.stdout.take(), cap));
    let err = tokio::spawn(read_bounded(child.stderr.take(), cap));
    let (status, note) = match tokio::time::timeout(timeout, child.wait()).await {
        Ok(Ok(status)) => (Some(status), String::new()),
        Ok(Err(e)) => (None, format!("wait failed: {e}")),
        Err(_) => (None, "timed out".to_string()),
    };
    // Whatever the outcome, nothing the script started outlives it.
    #[cfg(unix)]
    if let Some(pgid) = pgid.and_then(|p| i32::try_from(p).ok()).filter(|p| *p > 1) {
        // SAFETY: kill(2) with a negative pid signals the process group the
        // script was placed in above; it has no memory-safety preconditions.
        unsafe {
            libc::kill(-pgid, libc::SIGKILL);
        }
    }
    #[cfg(not(unix))]
    let _ = pgid;
    let _ = child.kill().await;
    // The pipes close once the group is gone; bound the wait regardless, in
    // case a descendant left the group and still holds them.
    let drain = std::time::Duration::from_secs(2);
    let (stdout, stdout_total) = tokio::time::timeout(drain, out)
        .await
        .ok()
        .and_then(Result::ok)
        .unwrap_or_default();
    let (stderr, stderr_total) = tokio::time::timeout(drain, err)
        .await
        .ok()
        .and_then(Result::ok)
        .unwrap_or_default();
    ScriptRun {
        success: status.is_some_and(|s| s.success()),
        code: status.and_then(|s| s.code()),
        stdout,
        stdout_total,
        stderr,
        stderr_total,
        note,
    }
}

/// Interpreter used when a `RunScript` names none: `/bin/sh` on Unix, the
/// built-in Windows PowerShell (absolute path, so `PATH` cannot redirect a
/// SYSTEM-level script run) on Windows.
fn default_interpreter() -> String {
    #[cfg(windows)]
    {
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string());
        format!("{root}\\System32\\WindowsPowerShell\\v1.0\\powershell.exe")
    }
    #[cfg(not(windows))]
    {
        "/bin/sh".to_string()
    }
}

/// The full argument list that runs `script` inline under `program`.
///
/// * PowerShell gets `-EncodedCommand` (base64 of the UTF-16LE text): the only
///   way to hand it an arbitrary script through a Windows command line without
///   its own quoting rules mangling embedded quotes. It also skips the profile
///   and never prompts — a remote script has no one to answer a prompt, and a
///   user profile must not be able to alter what a signed script does.
/// * `cmd.exe` gets `/D /C`.
/// * Everything else (POSIX shells, python, perl, ruby) takes `-c`.
pub fn script_args(program: &str, script: &str) -> Vec<String> {
    let stem = program
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(program)
        .to_ascii_lowercase();
    let stem = stem.strip_suffix(".exe").unwrap_or(&stem);
    match stem {
        "powershell" | "pwsh" => {
            let utf16: Vec<u8> = script
                .encode_utf16()
                .flat_map(|unit| unit.to_le_bytes())
                .collect();
            vec![
                "-NoProfile".into(),
                "-NonInteractive".into(),
                "-EncodedCommand".into(),
                base64::engine::general_purpose::STANDARD.encode(utf16),
            ]
        }
        "cmd" => vec!["/D".into(), "/C".into(), script.into()],
        _ => vec!["-c".into(), script.into()],
    }
}

/// Resolve the interpreter for a `RunScript`: the program to execute.
pub fn interpreter(interpreter: Option<&str>) -> String {
    interpreter
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .unwrap_or_else(default_interpreter)
}

/// One candidate region of a target process's address space.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemRegion {
    pub start: u64,
    pub end: u64,
    /// Private (not file-backed) and executable: the shape of injected code.
    pub anon_exec: bool,
}

/// Order readable regions for a memory dump — anonymous-executable first, then
/// the rest in their original order — and cut them to `max_total` bytes.
/// Returns `(start, end)` byte ranges, never exceeding the budget. Shared by the
/// Linux (`/proc/<pid>/maps`) and Windows (`VirtualQueryEx`) collectors, so the
/// "what leaves the host" policy is identical on both.
pub fn order_regions(mut regions: Vec<MemRegion>, max_total: u64) -> Vec<(u64, u64)> {
    regions.retain(|r| r.end > r.start);
    // Stable partition: anon-exec first, original order preserved within groups.
    regions.sort_by_key(|r| !r.anon_exec);

    let mut out = Vec::new();
    let mut budget = max_total;
    for r in regions {
        if budget == 0 {
            break;
        }
        let take = (r.end - r.start).min(budget);
        out.push((r.start, r.start + take));
        budget -= take;
    }
    out
}

/// Select which memory regions to dump for a `CollectProcessMemory`, given the
/// process's `/proc/<pid>/maps`. Only **readable** regions are eligible.
#[cfg(target_os = "linux")]
pub fn dumpable_regions(maps: &str, max_total: u64) -> Vec<(u64, u64)> {
    let regions = memscan::parse_maps(maps)
        .iter()
        .filter(|r| r.perms.contains('r'))
        .map(|r| MemRegion {
            start: r.start,
            end: r.end,
            anon_exec: r.perms.contains('x') && r.path.is_empty(),
        })
        .collect();
    order_regions(regions, max_total)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn collect_file_is_capped_and_refuses_devices_and_fifos() {
        let dir = std::env::temp_dir().join(format!("trapd-rtr-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("big");
        std::fs::write(&f, vec![b'x'; 10_000]).unwrap();
        let a = collect_file(f.to_str().unwrap(), 100).unwrap();
        assert_eq!(
            (a.returned_len, a.total_len, a.truncated),
            (100, 10_000, true)
        );
        let a = collect_file(f.to_str().unwrap(), 10_000).unwrap();
        assert_eq!((a.returned_len, a.truncated), (10_000, false));
        // /dev/zero never ends; it must be refused, not read.
        assert!(collect_file("/dev/zero", 100).is_err());
        assert!(collect_file(dir.to_str().unwrap(), 100).is_err());
        let fifo = dir.join("fifo");
        let c = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
        // SAFETY: mkfifo with a valid NUL-terminated path.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        assert!(
            collect_file(fifo.to_str().unwrap(), 100).is_err(),
            "a FIFO must not block"
        );
        // Procfs reports length 0; the read length is the size.
        let a = collect_file("/proc/self/status", 1 << 16).unwrap();
        assert!(a.returned_len > 0 && !a.truncated);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn script_output_is_bounded_and_the_run_is_reported() {
        let args = script_args("/bin/sh", "head -c 5000000 /dev/zero; echo err >&2; exit 3");
        let r =
            run_script_bounded("/bin/sh", &args, std::time::Duration::from_secs(20), 1000).await;
        assert_eq!(r.code, Some(3));
        assert!(!r.success);
        assert_eq!(r.stdout.len(), 1000);
        assert_eq!(r.stdout_total, 5_000_000);
        assert_eq!(r.stderr, b"err\n");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn timeout_kills_the_whole_process_group() {
        let dir = std::env::temp_dir().join(format!("trapd-rtr-pg-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let marker = dir.join("survived");
        // A backgrounded child holds the pipes open and would outlive the shell.
        let script = format!("(sleep 3; touch {}) & sleep 60", marker.display());
        let args = script_args("/bin/sh", &script);
        let started = std::time::Instant::now();
        let r =
            run_script_bounded("/bin/sh", &args, std::time::Duration::from_millis(300), 100).await;
        assert_eq!(r.note, "timed out");
        assert!(
            started.elapsed() < std::time::Duration::from_secs(3),
            "pipes held the run open"
        );
        tokio::time::sleep(std::time::Duration::from_secs(4)).await;
        assert!(!marker.exists(), "a background child survived the timeout");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn cap_and_encode_truncates_and_records_total() {
        let data = b"AAAABBBBCCCC"; // 12 bytes
        let a = cap_and_encode(data, 4);
        assert_eq!(a.total_len, 12);
        assert_eq!(a.returned_len, 4);
        assert!(a.truncated);
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(&a.b64)
            .unwrap();
        assert_eq!(decoded, b"AAAA");
    }

    #[test]
    fn cap_and_encode_passes_through_small_payloads() {
        let a = cap_and_encode(b"hi", 1024);
        assert!(!a.truncated);
        assert_eq!(a.returned_len, 2);
        assert_eq!(a.total_len, 2);
    }

    #[cfg(not(windows))]
    #[test]
    fn interpreter_defaults_to_sh_and_honours_an_explicit_one() {
        assert_eq!(interpreter(None), "/bin/sh");
        assert_eq!(interpreter(Some("  ")), "/bin/sh");
        assert_eq!(interpreter(Some("/usr/bin/python3")), "/usr/bin/python3");
    }

    #[test]
    fn posix_and_cmd_interpreters_take_the_script_inline() {
        assert_eq!(script_args("/bin/bash", "echo hi"), vec!["-c", "echo hi"]);
        assert_eq!(script_args("python3", "print(1)"), vec!["-c", "print(1)"]);
        assert_eq!(
            script_args("C:\\Windows\\System32\\cmd.exe", "dir"),
            vec!["/D", "/C", "dir"]
        );
    }

    #[test]
    fn powershell_receives_the_script_encoded_so_quotes_survive() {
        let script = "Write-Output \"a 'b' $x\"; 'é'";
        let args = script_args(
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\PowerShell.EXE",
            script,
        );
        assert_eq!(
            &args[..3],
            ["-NoProfile", "-NonInteractive", "-EncodedCommand"]
        );
        // Round-trips as UTF-16LE: exactly what PowerShell decodes.
        let raw = base64::engine::general_purpose::STANDARD
            .decode(&args[3])
            .unwrap();
        let units: Vec<u16> = raw
            .chunks(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        assert_eq!(String::from_utf16(&units).unwrap(), script);
        assert!(!args[3].contains(['"', ' ']), "nothing left to quote");
        assert_eq!(script_args("pwsh", "1")[2], "-EncodedCommand");
    }

    #[test]
    fn region_order_puts_injected_code_first_and_respects_the_budget() {
        let regions = vec![
            MemRegion {
                start: 0x1000,
                end: 0x3000,
                anon_exec: false,
            },
            MemRegion {
                start: 0x9000,
                end: 0xA000,
                anon_exec: true,
            },
            MemRegion {
                start: 0x5000,
                end: 0x5000,
                anon_exec: true,
            }, // empty
        ];
        let out = order_regions(regions.clone(), 0x1800);
        assert_eq!(out, vec![(0x9000, 0xA000), (0x1000, 0x1800)]);
        assert!(order_regions(regions, 0).is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn dumpable_regions_prioritises_anon_exec_and_respects_budget() {
        // A file-backed text segment (readable) and an anonymous RWX region.
        let maps = "\
55a000000000-55a000002000 r-xp 00000000 08:01 1 /usr/bin/bash
7f0000000000-7f0000001000 rwxp 00000000 00:00 0
7f0000002000-7f0000003000 ---p 00000000 00:00 0 ";
        // Budget smaller than the first (anon-exec) region: only it is taken,
        // truncated to the budget; the non-readable region is excluded.
        let regions = dumpable_regions(maps, 0x800);
        assert_eq!(regions.len(), 1);
        assert_eq!(regions[0], (0x7f0000000000, 0x7f0000000800));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn dumpable_regions_excludes_unreadable() {
        let maps = "7f0000002000-7f0000003000 ---p 00000000 00:00 0 ";
        assert!(dumpable_regions(maps, 0x10000).is_empty());
    }
}
