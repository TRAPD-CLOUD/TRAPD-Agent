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
//! This module owns bounded artifact reads and subprocess execution. Local
//! customer consent is required in addition to the signed remote enablement.

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

/// Interpreter used when a `RunScript` names none: `/bin/sh` on Unix, the
/// built-in Windows PowerShell (absolute path, so `PATH` cannot redirect a
/// SYSTEM-level script run) on Windows.
fn default_interpreter() -> String {
    #[cfg(windows)]
    {
        let root = windows_root().unwrap_or_else(|_| "C:\\Windows".to_string());
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

/// A hard ceiling independent of mutable remote configuration.
pub const MAX_CAPTURE_BYTES: usize = 1024 * 1024;

/// Read only an ordinary file, with a fixed allocation/read budget. Opening a
/// FIFO is nonblocking and symlinks/reparse points are refused before reading.
pub fn collect_file(path: &std::path::Path, max: usize) -> std::io::Result<Artifact> {
    use std::io::Read;
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
        // Refuse device namespaces before CreateFile can perform device I/O.
        let name = path.to_string_lossy().replace('/', "\\");
        let drive = name.as_bytes();
        if drive.len() < 3
            || !drive[0].is_ascii_alphabetic()
            || drive[1] != b':'
            || drive[2] != b'\\'
            || name[2..].contains(':')
        {
            return Err(std::io::Error::other(
                "device, UNC and alternate streams are not collectable",
            ));
        }
    }
    let file = options.open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file() {
        return Err(std::io::Error::other("only ordinary files are collectable"));
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;
        if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(std::io::Error::other("reparse points are not collectable"));
        }
    }
    let max = max.min(MAX_CAPTURE_BYTES);
    let mut bytes = Vec::with_capacity(max.min(8192));
    file.take(max.saturating_add(1) as u64)
        .read_to_end(&mut bytes)?;
    let mut artifact = cap_and_encode(&bytes, max);
    artifact.total_len = usize::try_from(meta.len())
        .unwrap_or(usize::MAX)
        .max(bytes.len());
    artifact.truncated = artifact.returned_len < artifact.total_len;
    Ok(artifact)
}

/// Local customer consent, independent of signed remotely delivered settings.
/// A remote command or policy must never create this marker. Windows requires
/// exact `TRAPD_RTR_ENABLED=1` in the locally administered service environment;
/// remotely delivered AgentConfig cannot modify either consent mechanism.
pub fn locally_enabled() -> bool {
    #[cfg(target_os = "linux")]
    {
        local_marker_enabled(&crate::paths::config_dir().join("rtr-enabled"))
    }
    #[cfg(windows)]
    {
        local_consent_value(std::env::var("TRAPD_RTR_ENABLED").ok().as_deref())
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        false
    }
}

#[cfg(any(windows, test))]
fn local_consent_value(value: Option<&str>) -> bool {
    value == Some("1")
}

#[cfg(target_os = "linux")]
fn local_marker_enabled(path: &std::path::Path) -> bool {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    // Every ancestor must be owned by root and protected against replacement.
    // Reject aliases instead of following a symlink into a weaker hierarchy.
    if !path.is_absolute() {
        return false;
    }
    for ancestor in path.ancestors().skip(1) {
        let Ok(meta) = std::fs::symlink_metadata(ancestor) else {
            return false;
        };
        if !meta.is_dir() || meta.uid() != 0 || meta.mode() & 0o022 != 0 {
            return false;
        }
    }
    let Ok(file) = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
    else {
        return false;
    };
    let Ok(meta) = file.metadata() else {
        return false;
    };
    if !meta.is_file() || meta.uid() != 0 || meta.mode() & 0o022 != 0 || meta.nlink() != 1 {
        return false;
    }
    use std::io::Read;
    let mut bytes = Vec::new();
    file.take(9).read_to_end(&mut bytes).is_ok() && bytes == b"enabled\n"
}

/// Captured output never exceeds the shared byte budget. Counts include bytes
/// drained after that budget was exhausted, so truncation is observable.
#[derive(Debug)]
pub struct ProcessOutput {
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub stdout_total: usize,
    pub stderr_total: usize,
}

impl ProcessOutput {
    pub fn success(&self) -> bool {
        !self.timed_out && self.exit_code == Some(0)
    }
}

async fn drain_capped(
    mut stream: impl tokio::io::AsyncRead + Unpin,
    remaining: &std::sync::atomic::AtomicUsize,
) -> std::io::Result<(Vec<u8>, usize)> {
    use std::sync::atomic::Ordering;
    use tokio::io::AsyncReadExt;
    let mut captured = Vec::new();
    let mut total = 0usize;
    let mut buf = [0u8; 8192];
    loop {
        let read = stream.read(&mut buf).await?;
        if read == 0 {
            return Ok((captured, total));
        }
        total = total.saturating_add(read);
        let available = remaining
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |left| {
                Some(left.saturating_sub(read))
            })
            .unwrap();
        captured.extend_from_slice(&buf[..read.min(available)]);
    }
}

#[cfg(target_os = "linux")]
struct ProcessTree(i32);

#[cfg(target_os = "linux")]
impl ProcessTree {
    fn attach(child: &tokio::process::Child) -> std::io::Result<Self> {
        let pid = child
            .id()
            .ok_or_else(|| std::io::Error::other("child has no process ID"))?;
        Ok(Self(pid as i32))
    }
    fn terminate(&mut self) -> std::io::Result<()> {
        if self.0 == 0 {
            return Ok(());
        }
        let result = unsafe { libc::kill(-self.0, libc::SIGKILL) };
        if result != 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::ESRCH) {
                return Err(error);
            }
        }
        self.0 = 0;
        Ok(())
    }
}

#[cfg(target_os = "linux")]
impl Drop for ProcessTree {
    fn drop(&mut self) {
        let _ = self.terminate();
    }
}

#[cfg(windows)]
fn windows_root() -> std::io::Result<String> {
    let mut root = [0u16; 32768];
    let len = unsafe {
        windows_sys::Win32::System::SystemInformation::GetWindowsDirectoryW(
            root.as_mut_ptr(),
            root.len() as u32,
        )
    };
    if len == 0 || len as usize >= root.len() {
        return Err(std::io::Error::last_os_error());
    }
    Ok(String::from_utf16_lossy(&root[..len as usize]))
}

#[cfg(windows)]
struct ProcessTree(windows_sys::Win32::Foundation::HANDLE);

// The Job handle is owned by this guard and accessed only by the executing task.
#[cfg(windows)]
unsafe impl Send for ProcessTree {}

#[cfg(windows)]
impl ProcessTree {
    fn attach(child: &tokio::process::Child) -> std::io::Result<Self> {
        use windows_sys::Win32::System::JobObjects::*;
        use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
        let process = child
            .raw_handle()
            .ok_or_else(|| std::io::Error::other("child has no process handle"))?;
        let job = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if job.is_null() {
            return Err(std::io::Error::last_os_error());
        }
        let guard = Self(job);
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        let set = unsafe {
            SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                &limits as *const _ as *const _,
                std::mem::size_of_val(&limits) as u32,
            )
        };
        if set == 0 || unsafe { AssignProcessToJobObject(job, process) } == 0 {
            return Err(std::io::Error::last_os_error());
        }
        // The child was created suspended, so it cannot spawn outside the Job
        // before assignment. Resume only after ownership is established.
        let name: Vec<u16> = "ntdll.dll".encode_utf16().chain(Some(0)).collect();
        let module = unsafe { GetModuleHandleW(name.as_ptr()) };
        let resume = unsafe { GetProcAddress(module, c"NtResumeProcess".as_ptr().cast()) }
            .ok_or_else(|| std::io::Error::other("NtResumeProcess unavailable"))?;
        let resume: unsafe extern "system" fn(windows_sys::Win32::Foundation::HANDLE) -> i32 =
            unsafe { std::mem::transmute(resume) };
        if unsafe { resume(process) } < 0 {
            return Err(std::io::Error::other("cannot resume bounded subprocess"));
        }
        Ok(guard)
    }
    fn terminate(&mut self) -> std::io::Result<()> {
        use windows_sys::Win32::System::JobObjects::TerminateJobObject;
        if unsafe { TerminateJobObject(self.0, 1) } == 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }
}

#[cfg(windows)]
impl Drop for ProcessTree {
    fn drop(&mut self) {
        unsafe {
            windows_sys::Win32::Foundation::CloseHandle(self.0);
        }
    }
}

/// Run an absolute executable without inherited loader/shell configuration.
/// Captures both pipes concurrently within one shared budget and bounds wall
/// time. Descendants are terminated on timeout, cancellation AND parent exit.
/// Linux owns a fresh process group; Windows owns a kill-on-close Job.
pub async fn run_bounded(
    program: &str,
    args: &[String],
    timeout: std::time::Duration,
    max_output: usize,
) -> std::io::Result<ProcessOutput> {
    use std::sync::atomic::AtomicUsize;
    if !std::path::Path::new(program).is_absolute() {
        return Err(std::io::Error::other(
            "subprocess executable must be absolute",
        ));
    }
    let mut command = tokio::process::Command::new(program);
    command
        .args(args)
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("LANG", "C.UTF-8")
        .env("DEBIAN_FRONTEND", "noninteractive")
        .env("APT_LISTCHANGES_FRONTEND", "none")
        .current_dir(std::path::MAIN_SEPARATOR.to_string())
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);
    #[cfg(target_os = "linux")]
    command.process_group(0);
    #[cfg(windows)]
    {
        use windows_sys::Win32::System::Threading::CREATE_SUSPENDED;
        command.creation_flags(CREATE_SUSPENDED);
        let root = windows_root()?;
        command
            .env("SystemRoot", &root)
            .env("WINDIR", &root)
            .env("PATH", format!("{root}\\System32;{root}"));
    }
    let mut child = command.spawn()?;
    let mut tree = ProcessTree::attach(&child)?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| std::io::Error::other("stdout pipe missing"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| std::io::Error::other("stderr pipe missing"))?;
    let remaining = AtomicUsize::new(max_output.min(MAX_CAPTURE_BYTES));
    let deadline = timeout.min(std::time::Duration::from_secs(300));
    let lifecycle = async {
        let outcome = tokio::time::timeout(deadline, child.wait()).await;
        tree.terminate()?;
        match outcome {
            Ok(status) => Ok::<_, std::io::Error>((status?.code(), false)),
            Err(_) => {
                child.wait().await?;
                Ok((None, true))
            }
        }
    };
    let work = async {
        let (status, stdout, stderr) = tokio::join!(
            lifecycle,
            drain_capped(stdout, &remaining),
            drain_capped(stderr, &remaining)
        );
        let (exit_code, timed_out) = status?;
        let (stdout, stdout_total) = stdout?;
        let (stderr, stderr_total) = stderr?;
        Ok(ProcessOutput {
            exit_code,
            timed_out,
            stdout,
            stderr,
            stdout_total,
            stderr_total,
        })
    };
    // A hostile descendant outside the owned group must not retain a pipe and
    // keep the agent task alive after tree cleanup; never wait indefinitely.
    tokio::time::timeout(deadline + std::time::Duration::from_secs(1), work)
        .await
        .map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "subprocess pipes did not close",
            )
        })?
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn collection_caps_sparse_files_and_refuses_special_files() {
        let path = std::env::temp_dir().join(format!("trapd-rtr-file-{}", uuid::Uuid::new_v4()));
        let file = std::fs::File::create(&path).unwrap();
        let length = if cfg!(target_os = "linux") {
            1024 * 1024 * 1024
        } else {
            1024 * 1024
        };
        file.set_len(length).unwrap();
        let art = collect_file(&path, 17).unwrap();
        assert_eq!(art.returned_len, 17);
        assert_eq!(art.total_len, length as usize);
        assert!(art.truncated);
        std::fs::remove_file(&path).unwrap();
        assert!(collect_file(&std::env::temp_dir(), 10).is_err());
        #[cfg(target_os = "linux")]
        {
            assert!(collect_file(std::path::Path::new("/dev/zero"), 10).is_err());
            use std::os::unix::ffi::OsStrExt;
            let name = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
            assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
            let now = std::time::Instant::now();
            assert!(collect_file(&path, 10).is_err());
            assert!(now.elapsed() < std::time::Duration::from_secs(1));
            std::fs::remove_file(path).unwrap();
        }
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn subprocess_caps_both_streams() {
        let result = run_bounded(
            "/bin/sh",
            &[
                "-c".into(),
                "head -c 100000 /dev/zero; head -c 100000 /dev/zero >&2; printf '%s' \"$PATH\""
                    .into(),
            ],
            std::time::Duration::from_secs(5),
            128,
        )
        .await
        .unwrap();
        assert!(result.success());
        assert!(result.stdout.len() + result.stderr.len() <= 128);
        assert!(result.stdout_total + result.stderr_total >= 200000);
        assert!(result.stdout_total > result.stdout.len());
        assert!(result.stderr_total > result.stderr.len());
    }

    #[cfg(target_os = "linux")]
    fn assert_process_dead(pid: i32) {
        // An adopted zombie has stopped executing even when init has not reaped it.
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"));
        assert!(
            stat.is_err()
                || stat
                    .unwrap()
                    .rsplit_once(')')
                    .unwrap()
                    .1
                    .trim_start()
                    .starts_with('Z'),
            "descendant {pid} is still running"
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn subprocess_timeout_and_success_clean_up_descendants() {
        for timeout in [true, false] {
            let path =
                std::env::temp_dir().join(format!("trapd-rtr-child-{}", uuid::Uuid::new_v4()));
            let script = format!(
                "sleep 60 & echo $! > {}; {}",
                path.display(),
                if timeout { "wait" } else { "exit 0" }
            );
            let now = std::time::Instant::now();
            let result = run_bounded(
                "/bin/sh",
                &["-c".into(), script],
                std::time::Duration::from_millis(200),
                64,
            )
            .await
            .unwrap();
            assert_eq!(result.timed_out, timeout);
            assert!(now.elapsed() < std::time::Duration::from_secs(2));
            let pid = std::fs::read_to_string(&path)
                .unwrap()
                .trim()
                .parse()
                .unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(30)).await;
            assert_process_dead(pid);
            std::fs::remove_file(path).unwrap();
        }
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn subprocess_cancellation_cleans_up_descendants() {
        let path = std::env::temp_dir().join(format!("trapd-rtr-cancel-{}", uuid::Uuid::new_v4()));
        let script = format!("sleep 60 & echo $! > {}; wait", path.display());
        let task = tokio::spawn(async move {
            run_bounded(
                "/bin/sh",
                &["-c".into(), script],
                std::time::Duration::from_secs(60),
                64,
            )
            .await
        });
        for _ in 0..100 {
            if std::fs::read_to_string(&path).is_ok_and(|value| value.trim().parse::<i32>().is_ok())
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        let pid = std::fs::read_to_string(&path)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        task.abort();
        let _ = task.await;
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        assert_process_dead(pid);
        std::fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn subprocess_refuses_relative_executables() {
        assert!(
            run_bounded("sh", &[], std::time::Duration::from_secs(1), 64)
                .await
                .is_err()
        );
    }

    #[test]
    fn local_service_consent_requires_exact_operator_value() {
        assert!(local_consent_value(Some("1")));
        for value in [
            None,
            Some(""),
            Some("true"),
            Some("0"),
            Some(" 1"),
            Some("1 "),
        ] {
            assert!(!local_consent_value(value));
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn untrusted_local_markers_cannot_enable_rtr() {
        let dir = std::env::temp_dir().join(format!("trapd-rtr-consent-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("rtr-enabled");
        std::fs::write(&path, b"enabled\n").unwrap();
        assert!(
            !local_marker_enabled(&path),
            "untrusted ownership/ancestors must fail closed"
        );
        std::fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink("/dev/zero", &path).unwrap();
        assert!(!local_marker_enabled(&path));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn subprocess_does_not_inherit_agent_secrets_or_loader_options() {
        if std::env::var_os("TRAPD_RTR_ENV_TEST_CHILD").is_some() {
            tokio::runtime::Runtime::new().unwrap().block_on(async {
                let result =
                    run_bounded("/usr/bin/env", &[], std::time::Duration::from_secs(2), 8192)
                        .await
                        .unwrap();
                assert!(result.success());
                let env = String::from_utf8(result.stdout).unwrap();
                assert!(!env.contains("TRAPD_RTR_ENV_TEST_CHILD"));
                assert!(!env.contains("private-agent-secret"));
                assert!(!env.contains("PYTHONPATH="));
                assert!(env.contains("PATH=/usr/sbin:/usr/bin:/sbin:/bin\n"));
            });
            return;
        }
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "prevention::rtr::tests::subprocess_does_not_inherit_agent_secrets_or_loader_options", "--nocapture"])
            .env("TRAPD_RTR_ENV_TEST_CHILD", "private-agent-secret")
            .env("PYTHONPATH", "/tmp/attacker-python")
            .output().unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[cfg(target_os = "linux")]
    fn memory_limited_test(name: &str) {
        use std::os::unix::process::CommandExt;
        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", name, "--test-threads=1", "--nocapture"])
            .env("TRAPD_RTR_MEMORY_TEST_CHILD", "1");
        // Exec a new test process: apply limits before it creates any threads.
        unsafe {
            command.pre_exec(|| {
                let memory = libc::rlimit {
                    rlim_cur: 256 * 1024 * 1024,
                    rlim_max: 256 * 1024 * 1024,
                };
                let core = libc::rlimit {
                    rlim_cur: 0,
                    rlim_max: 0,
                };
                if libc::setrlimit(libc::RLIMIT_AS, &memory) != 0
                    || libc::setrlimit(libc::RLIMIT_CORE, &core) != 0
                {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let output = command.output().unwrap();
        assert!(
            output.status.success(),
            "memory-limited child failed: {}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn collection_does_not_allocate_the_source_size() {
        memory_limited_test(
            "prevention::rtr::tests::collection_caps_sparse_files_and_refuses_special_files",
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn subprocess_caps_streams_before_they_exhaust_memory() {
        if std::env::var_os("TRAPD_RTR_MEMORY_TEST_CHILD").is_none() {
            memory_limited_test(
                "prevention::rtr::tests::subprocess_caps_streams_before_they_exhaust_memory",
            );
            return;
        }
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let result = run_bounded(
                    "/bin/sh",
                    &[
                        "-c".into(),
                        "head -c 200000000 /dev/zero; head -c 200000000 /dev/zero >&2".into(),
                    ],
                    std::time::Duration::from_secs(10),
                    128,
                )
                .await
                .unwrap();
                assert!(result.success());
                assert_eq!(result.stdout_total, 200000000);
                assert_eq!(result.stderr_total, 200000000);
                assert!(result.stdout.len() + result.stderr.len() <= 128);
            });
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn windows_job_caps_output_and_cleans_background_children() {
        use windows_sys::Win32::Foundation::{CloseHandle, ERROR_INVALID_PARAMETER, WAIT_OBJECT_0};
        use windows_sys::Win32::System::Threading::{
            OpenProcess, WaitForSingleObject, PROCESS_SYNCHRONIZE,
        };
        let program = interpreter(None);
        let args = script_args(
            &program,
            "[Console]::Out.Write(('x' * 65536)); [Console]::Error.Write(('y' * 65536))",
        );
        let result = run_bounded(&program, &args, std::time::Duration::from_secs(15), 128)
            .await
            .unwrap();
        assert!(result.success());
        assert_eq!(result.stdout_total, 65536);
        assert_eq!(result.stderr_total, 65536);
        assert!(result.stdout.len() + result.stderr.len() <= 128);
        let child_args = script_args(&program, "Start-Sleep -Seconds 60");
        for timeout in [false, true] {
            let path =
                std::env::temp_dir().join(format!("trapd-job-child-{}", uuid::Uuid::new_v4()));
            let quoted_path = path.to_string_lossy().replace("'", "''");
            let quoted_program = program.replace("'", "''");
            let script = format!("$p = Start-Process -FilePath '{quoted_program}' -ArgumentList @('-NoProfile','-NonInteractive','-EncodedCommand','{}') -NoNewWindow -PassThru; [IO.File]::WriteAllText('{quoted_path}', [string]$p.Id); {}", child_args[3], if timeout { "Start-Sleep -Seconds 60" } else { "exit 0" });
            let args = script_args(&program, &script);
            let result = run_bounded(&program, &args, std::time::Duration::from_secs(5), 128)
                .await
                .unwrap();
            assert_eq!(result.timed_out, timeout);
            let pid = std::fs::read_to_string(&path)
                .unwrap()
                .trim()
                .parse()
                .unwrap();
            let process = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, 0, pid) };
            if process.is_null() {
                assert_eq!(
                    std::io::Error::last_os_error().raw_os_error(),
                    Some(ERROR_INVALID_PARAMETER as i32)
                );
            } else {
                let status = unsafe { WaitForSingleObject(process, 1000) };
                unsafe {
                    CloseHandle(process);
                }
                assert_eq!(
                    status, WAIT_OBJECT_0,
                    "background child survived Job cleanup"
                );
            }
            std::fs::remove_file(path).unwrap();
        }
    }
}
