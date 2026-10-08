//! Windows process control: terminate, freeze, thaw — with the same safety
//! contract as the Linux `kill(2)` path.
//!
//! * A bare PID is not an identity on Windows either; PIDs are reused quickly.
//!   When the caller knows the creation time (the exec event carries it), the
//!   handle is opened, the creation FILETIME compared, and only then acted on —
//!   so a response aimed at a process that already exited can never hit the
//!   unrelated process that inherited its PID.
//! * Core system processes are refused ([`super::winguard`]). The decision is
//!   taken on the *opened handle's* image path, not on the PID or a name from an
//!   event, so it cannot be raced by the process swapping identity.
//! * If the image path cannot be established the action is refused (fail
//!   closed): an unattributable process is not terminated blind.

use anyhow::{anyhow, bail, Result};
use windows_sys::Win32::Foundation::{CloseHandle, FILETIME, HANDLE};
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
use windows_sys::Win32::System::Threading::{
    GetProcessTimes, OpenProcess, QueryFullProcessImageNameW, TerminateProcess,
    PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SUSPEND_RESUME, PROCESS_TERMINATE,
};

use super::winguard;

/// Owned process handle, closed on drop.
struct Process(HANDLE);

impl Drop for Process {
    fn drop(&mut self) {
        // SAFETY: the handle was returned by OpenProcess and is closed once.
        unsafe { CloseHandle(self.0) };
    }
}

fn system_root() -> String {
    std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string())
}

fn open(pid: i32, access: u32) -> Result<Process> {
    if winguard::is_reserved_pid(pid) {
        bail!("pid {pid} is reserved and can never be a response target");
    }
    // SAFETY: plain FFI call; a null result is handled.
    let handle = unsafe { OpenProcess(access | PROCESS_QUERY_LIMITED_INFORMATION, 0, pid as u32) };
    if handle.is_null() {
        return Err(anyhow!(
            "OpenProcess({pid}) failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(Process(handle))
}

fn creation_time(p: &Process) -> Option<u64> {
    let (mut created, mut exited, mut kernel, mut user) = (
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
    );
    // SAFETY: valid handle; four initialised out-parameters.
    let ok = unsafe { GetProcessTimes(p.0, &mut created, &mut exited, &mut kernel, &mut user) };
    (ok != 0).then_some(((created.dwHighDateTime as u64) << 32) | created.dwLowDateTime as u64)
}

fn image_path(p: &Process) -> Option<String> {
    let mut buf = vec![0u16; 1024];
    let mut len = buf.len() as u32;
    // SAFETY: `buf` holds `len` UTF-16 units; the call updates `len` to the
    // number written (excluding the terminator).
    let ok = unsafe { QueryFullProcessImageNameW(p.0, 0, buf.as_mut_ptr(), &mut len) };
    (ok != 0).then(|| String::from_utf16_lossy(&buf[..len as usize]))
}

/// Open `pid` for `access`, then enforce identity and the protected list.
fn open_target(pid: i32, access: u32, expected_start: Option<u64>) -> Result<Process> {
    let process = open(pid, access)?;
    if let Some(expected) = expected_start {
        match creation_time(&process) {
            Some(actual) if actual == expected => {}
            Some(_) => bail!("pid {pid} now belongs to a different process (PID reused); refusing"),
            None => bail!("cannot verify the identity of pid {pid}; refusing"),
        }
    }
    let Some(image) = image_path(&process) else {
        bail!(
            "cannot resolve the image of pid {pid}; refusing to act on an unattributable process"
        );
    };
    if winguard::is_protected_image(&image, &system_root()) {
        bail!("pid {pid} is a protected system process ({image}); refusing");
    }
    Ok(process)
}

/// Terminate `pid` (optionally only if its creation time still matches).
pub fn terminate(pid: i32, expected_start: Option<u64>) -> Result<()> {
    let p = open_target(pid, PROCESS_TERMINATE, expected_start)?;
    // SAFETY: valid handle with PROCESS_TERMINATE access.
    if unsafe { TerminateProcess(p.0, 1) } == 0 {
        bail!(
            "TerminateProcess({pid}) failed: {}",
            std::io::Error::last_os_error()
        );
    }
    Ok(())
}

type NtProcessFn = unsafe extern "system" fn(HANDLE) -> i32;

/// `NtSuspendProcess` / `NtResumeProcess` live in ntdll and are not in the
/// public SDK headers; they are the same calls Process Explorer and Task
/// Manager's "Suspend" use, and are stable across every supported release.
fn ntdll_fn(name: &[u8]) -> Result<NtProcessFn> {
    debug_assert!(name.ends_with(&[0]));
    let ntdll: Vec<u16> = "ntdll.dll".encode_utf16().chain(Some(0)).collect();
    // SAFETY: NUL-terminated name buffers; ntdll is always mapped.
    unsafe {
        let module = GetModuleHandleW(ntdll.as_ptr());
        if module.is_null() {
            bail!("ntdll.dll not loaded");
        }
        let addr =
            GetProcAddress(module, name.as_ptr()).ok_or_else(|| anyhow!("ntdll export missing"))?;
        Ok(std::mem::transmute::<
            unsafe extern "system" fn() -> isize,
            NtProcessFn,
        >(addr))
    }
}

fn nt_call(pid: i32, symbol: &[u8], expected_start: Option<u64>, verb: &str) -> Result<()> {
    let f = ntdll_fn(symbol)?;
    let p = open_target(pid, PROCESS_SUSPEND_RESUME, expected_start)?;
    // SAFETY: valid handle with PROCESS_SUSPEND_RESUME access.
    let status = unsafe { f(p.0) };
    if status < 0 {
        bail!("{verb} pid {pid} failed: NTSTATUS {status:#010x}");
    }
    Ok(())
}

/// Suspend every thread of `pid` — the "freeze" response.
pub fn suspend(pid: i32, expected_start: Option<u64>) -> Result<()> {
    nt_call(pid, b"NtSuspendProcess\0", expected_start, "suspend")
}

/// Resume a process frozen by [`suspend`].
pub fn resume(pid: i32, expected_start: Option<u64>) -> Result<()> {
    nt_call(pid, b"NtResumeProcess\0", expected_start, "resume")
}

/// File name of the image `pid` runs (the Windows analogue of Linux `comm`),
/// used to evaluate parent-process rules.
pub fn image_name(pid: i32) -> Option<String> {
    if winguard::is_reserved_pid(pid) {
        return None;
    }
    let p = open(pid, 0).ok()?;
    let path = image_path(&p)?;
    path.rsplit(['\\', '/']).next().map(str::to_string)
}

/// Result of a memory collection: the bytes plus how many regions were read.
pub struct MemoryDump {
    pub bytes: Vec<u8>,
    pub regions: usize,
}

/// One committed, accessible region from `VirtualQueryEx`.
struct Committed {
    base: usize,
    size: usize,
    kind: u32,
    protect: u32,
}

/// Walk the address space of `p` and return every committed region that is not
/// `PAGE_NOACCESS` / `PAGE_GUARD`. The walk is bounded: a pathological address
/// space must not spin the caller.
fn committed_regions(p: &Process) -> Vec<Committed> {
    use windows_sys::Win32::System::Memory::{
        VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, PAGE_GUARD, PAGE_NOACCESS,
    };
    let mut out = Vec::new();
    let mut address: usize = 0;
    for _ in 0..200_000 {
        // SAFETY: zeroed POD out-parameter; `p.0` is a valid handle.
        let mut info: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
        let got = unsafe {
            VirtualQueryEx(
                p.0,
                address as *const _,
                &mut info,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };
        if got == 0 {
            break;
        }
        let base = info.BaseAddress as usize;
        let size = info.RegionSize;
        if info.State == MEM_COMMIT
            && info.Protect & (PAGE_NOACCESS | PAGE_GUARD) == 0
            && info.Protect != 0
        {
            out.push(Committed {
                base,
                size,
                kind: info.Type,
                protect: info.Protect,
            });
        }
        match base.checked_add(size) {
            Some(next) if next > address => address = next,
            _ => break,
        }
    }
    out
}

/// Read up to `buf.len()` bytes at `address`; returns the number read.
fn read_at(p: &Process, address: usize, buf: &mut [u8]) -> usize {
    use windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory;
    let mut read = 0usize;
    // SAFETY: `buf` is writable for its length; a failed read leaves `read` 0
    // or short, and only that many bytes are used.
    let ok = unsafe {
        ReadProcessMemory(
            p.0,
            address as *const _,
            buf.as_mut_ptr().cast(),
            buf.len(),
            &mut read,
        )
    };
    if ok != 0 || read > 0 {
        read
    } else {
        0
    }
}

/// Dump readable committed memory of `pid`, private executable regions first,
/// up to `cap` bytes — the Windows counterpart of reading `/proc/<pid>/mem`.
///
/// Protected system processes (LSASS above all) are refused by the same guard
/// as terminate/suspend: a memory-collection command must not double as a
/// credential-dumping primitive.
pub fn dump_memory(pid: i32, cap: u64) -> Result<MemoryDump> {
    use windows_sys::Win32::System::Memory::MEM_PRIVATE;
    use windows_sys::Win32::System::Threading::{PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};

    let p = open_target(pid, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, None)?;
    let candidates = committed_regions(&p)
        .into_iter()
        .map(|r| {
            let region = super::super::collectors::win_mem_rules::WinRegion {
                base: r.base as u64,
                size: r.size as u64,
                kind: r.kind,
                protect: r.protect,
            };
            super::rtr::MemRegion {
                start: r.base as u64,
                end: (r.base + r.size) as u64,
                anon_exec: r.kind == MEM_PRIVATE && region.is_executable(),
            }
        })
        .collect();

    let regions = super::rtr::order_regions(candidates, cap);
    let mut bytes = Vec::new();
    let mut read_regions = 0;
    for (start, end) in &regions {
        let mut chunk = vec![0u8; (end - start) as usize];
        let read = read_at(&p, *start as usize, &mut chunk);
        if read > 0 {
            bytes.extend_from_slice(&chunk[..read]);
            read_regions += 1;
        }
    }
    Ok(MemoryDump {
        bytes,
        regions: read_regions,
    })
}

/// An executable, non-image region of a process plus whether it starts with a
/// PE image — everything the injection rules need.
pub struct InspectedRegion {
    pub region: super::super::collectors::win_mem_rules::WinRegion,
    pub header_is_pe: bool,
}

/// Executable memory of `pid` that is not backed by an image on disk, at most
/// `max_regions` of it. Only region *metadata* and the first 1 KiB of each
/// candidate are read, never other memory, so this is safe to run across the
/// whole process table; unlike [`dump_memory`] it is read-only inspection, so
/// it is not subject to the destructive-action guard.
pub fn inspect_unbacked_executable(pid: i32, max_regions: usize) -> Result<Vec<InspectedRegion>> {
    use super::super::collectors::win_mem_rules::{looks_like_pe, WinRegion};
    use windows_sys::Win32::System::Threading::{PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};

    let p = open(pid, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ)?;
    let mut out = Vec::new();
    for r in committed_regions(&p) {
        let region = WinRegion {
            base: r.base as u64,
            size: r.size as u64,
            kind: r.kind,
            protect: r.protect,
        };
        if !region.is_unbacked_executable() {
            continue;
        }
        let mut head = [0u8; 1024];
        let n = read_at(&p, r.base, &mut head);
        out.push(InspectedRegion {
            region,
            header_is_pe: looks_like_pe(&head[..n]),
        });
        if out.len() >= max_regions {
            break;
        }
    }
    Ok(out)
}

/// Win32 start address of every thread in the system, grouped by owning
/// process. One snapshot serves a whole sweep. A thread whose start address
/// cannot be read (it exited, or access is denied) is simply absent.
pub fn thread_start_addresses() -> std::collections::HashMap<i32, Vec<u64>> {
    use std::collections::HashMap;
    use windows_sys::Wdk::System::Threading::{
        NtQueryInformationThread, ThreadQuerySetWin32StartAddress,
    };
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
    };
    use windows_sys::Win32::System::Threading::{
        OpenThread, THREAD_QUERY_INFORMATION, THREAD_QUERY_LIMITED_INFORMATION,
    };

    let mut out: HashMap<i32, Vec<u64>> = HashMap::new();
    // SAFETY: the snapshot handle is closed on every path; `entry` is a
    // correctly sized, initialised THREADENTRY32.
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if snapshot.is_null() || snapshot == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
            return out;
        }
        let mut entry: THREADENTRY32 = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;
        let mut more = Thread32First(snapshot, &mut entry);
        while more != 0 {
            // Limited access is enough on current Windows; fall back for older.
            let mut handle = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, 0, entry.th32ThreadID);
            if handle.is_null() {
                handle = OpenThread(THREAD_QUERY_INFORMATION, 0, entry.th32ThreadID);
            }
            if !handle.is_null() {
                let mut start: usize = 0;
                let status = NtQueryInformationThread(
                    handle,
                    ThreadQuerySetWin32StartAddress,
                    (&mut start as *mut usize).cast(),
                    std::mem::size_of::<usize>() as u32,
                    std::ptr::null_mut(),
                );
                CloseHandle(handle);
                if status >= 0 && start != 0 {
                    out.entry(entry.th32OwnerProcessID as i32)
                        .or_default()
                        .push(start as u64);
                }
            }
            more = Thread32Next(snapshot, &mut entry);
        }
        CloseHandle(snapshot);
    }
    out
}

/// File names of the modules loaded in `pid` (lower-cased), 32- and 64-bit.
/// Used to recognise a code-generating engine (CLR, JVM, V8) in a process whose
/// own image name says nothing about it.
pub fn module_names(pid: i32) -> Vec<String> {
    use windows_sys::Win32::System::ProcessStatus::{
        EnumProcessModulesEx, GetModuleBaseNameW, LIST_MODULES_ALL,
    };
    use windows_sys::Win32::System::Threading::{PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};

    let Ok(p) = open(pid, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ) else {
        return Vec::new();
    };
    let mut modules = vec![std::ptr::null_mut(); 1024];
    let mut needed = 0u32;
    // SAFETY: `modules` holds `cb` bytes; the API writes at most that many.
    let ok = unsafe {
        EnumProcessModulesEx(
            p.0,
            modules.as_mut_ptr(),
            (modules.len() * std::mem::size_of::<*mut core::ffi::c_void>()) as u32,
            &mut needed,
            LIST_MODULES_ALL,
        )
    };
    if ok == 0 {
        return Vec::new();
    }
    let count =
        (needed as usize / std::mem::size_of::<*mut core::ffi::c_void>()).min(modules.len());
    let mut names = Vec::with_capacity(count);
    for &module in &modules[..count] {
        let mut name = [0u16; 260];
        // SAFETY: `name` is 260 writable UTF-16 units.
        let len = unsafe { GetModuleBaseNameW(p.0, module, name.as_mut_ptr(), name.len() as u32) };
        if len > 0 {
            names.push(String::from_utf16_lossy(&name[..len as usize]).to_ascii_lowercase());
        }
    }
    names
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Child, Command, Stdio};

    /// A harmless child that lives long enough to be acted on.
    fn sleeper() -> Child {
        Command::new("ping")
            .args(["-n", "60", "127.0.0.1"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn ping")
    }

    fn start_of(child: &Child) -> u64 {
        crate::telemetry::identity::process_start_time(child.id() as i32)
            .expect("creation time of a live child")
    }

    #[test]
    fn terminates_a_process_whose_identity_matches() {
        let mut child = sleeper();
        let start = start_of(&child);
        terminate(child.id() as i32, Some(start)).expect("terminate");
        let status = child.wait().expect("wait");
        assert_eq!(status.code(), Some(1), "TerminateProcess exit code");
    }

    #[test]
    fn refuses_a_pid_that_now_belongs_to_another_process() {
        let mut child = sleeper();
        let start = start_of(&child);
        // Same PID, different creation time: exactly what PID reuse looks like.
        let err = terminate(child.id() as i32, Some(start + 1)).unwrap_err();
        assert!(format!("{err:#}").contains("different process"), "{err:#}");
        assert!(
            child.try_wait().unwrap().is_none(),
            "the process must not have been touched"
        );
        let _ = child.kill();
        let _ = child.wait();
    }

    #[test]
    fn reserved_pids_are_never_opened() {
        for pid in [0, 4, -1] {
            assert!(terminate(pid, None).is_err(), "pid {pid}");
            assert!(suspend(pid, None).is_err(), "pid {pid}");
        }
    }

    #[test]
    fn a_missing_process_is_an_error_not_a_panic() {
        assert!(terminate(i32::MAX, None).is_err());
        assert!(image_name(i32::MAX).is_none());
    }

    #[test]
    fn suspend_and_resume_round_trip() {
        let mut child = sleeper();
        let start = start_of(&child);
        suspend(child.id() as i32, Some(start)).expect("suspend");
        resume(child.id() as i32, Some(start)).expect("resume");
        let _ = child.kill();
        let _ = child.wait();
    }

    #[test]
    fn image_name_is_the_file_name_of_the_running_image() {
        let name = image_name(std::process::id() as i32).expect("own image");
        assert!(name.to_ascii_lowercase().ends_with(".exe"), "{name}");
    }

    #[test]
    fn core_system_processes_are_refused_without_being_touched() {
        // `open_target` is the single guard terminate/suspend/dump share. It is
        // exercised here with no destructive access so a regression cannot take
        // the CI host down: the guard must refuse before any action.
        let mut sys = sysinfo::System::new();
        sys.refresh_processes();
        let lsass = sys
            .processes()
            .values()
            .find(|p| p.name().eq_ignore_ascii_case("lsass.exe"))
            .map(|p| p.pid().as_u32() as i32);
        let Some(pid) = lsass else {
            eprintln!("no lsass.exe visible; skipping");
            return;
        };
        match open_target(pid, 0, None) {
            Ok(_) => panic!("lsass.exe must never be an allowed target"),
            Err(e) => {
                let text = format!("{e:#}");
                assert!(
                    text.contains("protected system process") || text.contains("OpenProcess"),
                    "{text}"
                );
            }
        }
    }

    #[test]
    fn dumps_readable_memory_of_an_ordinary_process() {
        let dump = dump_memory(std::process::id() as i32, 256 * 1024).expect("dump own memory");
        assert!(!dump.bytes.is_empty());
        assert!(dump.bytes.len() <= 256 * 1024, "budget respected");
        assert!(dump.regions > 0);
    }
}
