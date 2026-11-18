//! Windows process-integrity checks (the OS-facing half; the parsing and
//! comparison logic lives in the portable, unit-tested `pe`, `policy` and
//! `handles` modules).
//!
//! Every Win32/NT call here is read-only. A call that fails makes the check
//! skip its pass (logged once at debug level) and never produces a finding:
//! "could not look" is not "found something".

use std::collections::{HashMap, HashSet};
use std::path::Path;

use serde_json::json;
use sha2::{Digest, Sha256};
use tracing::{debug, info, warn};
use windows_sys::Wdk::System::SystemInformation::NtQuerySystemInformation;
use windows_sys::Wdk::System::Threading::{
    NtQueryInformationProcess, NtQueryInformationThread, ProcessDebugObjectHandle,
    ProcessDebugPort, ThreadQuerySetWin32StartAddress,
};
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, HMODULE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Diagnostics::Debug::{IsDebuggerPresent, ReadProcessMemory};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
};
use windows_sys::Win32::System::LibraryLoader::{GetModuleFileNameW, GetModuleHandleW};
use windows_sys::Win32::System::Memory::{VirtualQuery, MEMORY_BASIC_INFORMATION};
use windows_sys::Win32::System::ProcessStatus::{
    EnumProcessModulesEx, GetModuleFileNameExW, GetModuleInformation, LIST_MODULES_ALL, MODULEINFO,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, OpenProcess, OpenThread, QueryFullProcessImageNameW,
    PROCESS_QUERY_LIMITED_INFORMATION, THREAD_QUERY_INFORMATION,
};

use super::handles::{self, Exclusions};
use super::pe::{self, PAGE};
use super::policy::{self, ModuleContext};
use super::{Config, Finding, Kind};
use crate::schema::Severity;

/// Files larger than this are not read for a comparison or a hash.
const MAX_IMAGE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_HANDLE_TABLE: usize = 256 * 1024 * 1024;
const SYSTEM_EXTENDED_HANDLE_INFORMATION: i32 = 0x40;
const STATUS_INFO_LENGTH_MISMATCH: i32 = 0xC000_0004u32 as i32;
const MEM_IMAGE: u32 = 0x0100_0000;
/// Bytes of a function prologue compared against the file.
const PROLOGUE: usize = 16;

/// Exported functions whose first bytes are checked on every pass: the ETW
/// write path attackers patch to blind the sensor.
const CRITICAL_EXPORTS: &[(&str, &[&str])] = &[("ntdll.dll", &["EtwEventWrite", "NtTraceEvent"])];

struct Critical {
    name: &'static str,
    rva: u32,
    expected: Vec<u8>,
}

/// The expected `.text` of one loaded image, kept as page digests.
struct CodeModule {
    name: String,
    path: String,
    base: u64,
    text_rva: u32,
    text_len: usize,
    expected: Vec<[u8; 32]>,
    ignore: Vec<(usize, usize)>,
    critical: Vec<Critical>,
    /// Page index -> digest of memory at the first scan. Differences present
    /// then are not reported as *changes* (see the note in `pe`).
    baseline: Option<HashMap<usize, [u8; 32]>>,
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

fn module_handle(name: Option<&str>) -> Option<HMODULE> {
    let h = match name {
        // SAFETY: NUL-terminated UTF-16 name; the module is not ref-counted.
        Some(n) => unsafe { GetModuleHandleW(wide(n).as_ptr()) },
        // SAFETY: a null name selects the process executable.
        None => unsafe { GetModuleHandleW(std::ptr::null()) },
    };
    (!h.is_null()).then_some(h)
}

fn module_path(h: HMODULE) -> Option<String> {
    let mut buf = vec![0u16; 1024];
    // SAFETY: `buf` is writable for `buf.len()` UTF-16 units.
    let n = unsafe { GetModuleFileNameW(h, buf.as_mut_ptr(), buf.len() as u32) } as usize;
    (n > 0 && n < buf.len()).then(|| String::from_utf16_lossy(&buf[..n]))
}

fn read_process_memory(addr: u64, buf: &mut [u8]) -> bool {
    let mut read = 0usize;
    // SAFETY: `buf` is writable for its length; the pseudo handle is valid.
    let ok = unsafe {
        ReadProcessMemory(
            GetCurrentProcess(),
            addr as *const _,
            buf.as_mut_ptr().cast(),
            buf.len(),
            &mut read,
        )
    };
    ok != 0 && read == buf.len()
}

fn read_file_capped(path: &Path) -> Option<Vec<u8>> {
    let meta = std::fs::metadata(path).ok()?;
    if meta.len() > MAX_IMAGE_BYTES {
        return None;
    }
    std::fs::read(path).ok()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

impl CodeModule {
    fn load(h: HMODULE, critical: &[&'static str]) -> Option<Self> {
        let path = module_path(h)?;
        let base = h as u64;
        let file = read_file_capped(Path::new(&path))?;
        let info = pe::parse(&file).ok()?;
        let section = info.text()?.clone();
        let image = pe::expected_text(&file, &info, &section, base)?;
        let critical = critical
            .iter()
            .filter_map(|&name| {
                let rva = pe::export_rva(&file, &info, name)?;
                let expected = pe::expected_at(&image, &section, rva, PROLOGUE)?;
                Some(Critical {
                    name,
                    rva,
                    expected,
                })
            })
            .collect();
        Some(Self {
            name: path.rsplit('\\').next().unwrap_or("").to_ascii_lowercase(),
            path,
            base,
            text_rva: section.virtual_address,
            text_len: image.bytes.len(),
            expected: pe::page_digests(&image),
            ignore: image.ignore.clone(),
            critical,
            baseline: None,
        })
    }

    /// Digest of every page of the in-memory `.text`; `None` when any page is
    /// unreadable (skip this pass rather than guess).
    fn memory_digests(&self) -> Option<Vec<[u8; 32]>> {
        let mut digests = Vec::with_capacity(self.expected.len());
        let mut page = vec![0u8; PAGE];
        let mut off = 0usize;
        while off < self.text_len {
            let len = (self.text_len - off).min(PAGE);
            let buf = &mut page[..len];
            if !read_process_memory(self.base + u64::from(self.text_rva) + off as u64, buf) {
                return None;
            }
            digests.push(pe::page_digest(buf, off, &self.ignore));
            off += len;
        }
        Some(digests)
    }

    fn check(&mut self) -> Vec<Finding> {
        let mut out = Vec::new();
        // 1. Prologues of critical functions, always compared with the file.
        for c in &self.critical {
            let mut now = vec![0u8; c.expected.len()];
            if read_process_memory(self.base + u64::from(c.rva), &mut now) && now != c.expected {
                out.push(Finding {
                    kind: Kind::CodePatched,
                    severity: Severity::High,
                    subject: format!("{}!{}", self.name, c.name),
                    detail: format!(
                        "The first bytes of {}!{} differ from the file on disk (hook or patch)",
                        self.name, c.name
                    ),
                    evidence: json!({
                        "module": self.path,
                        "function": c.name,
                        "rva": format!("{:#x}", c.rva),
                        "expected": hex(&c.expected),
                        "actual": hex(&now),
                    }),
                    dedup_key: format!("code:fn:{}:{}:{}", self.name, c.name, hex(&now)),
                });
            }
        }
        // 2. Whole `.text`, as a change since the first scan.
        let Some(digests) = self.memory_digests() else {
            debug!(module = %self.name, ".text unreadable; skipping this pass");
            return out;
        };
        let differing = pe::changed_pages(&self.expected, &digests);
        match &self.baseline {
            None => {
                if !differing.is_empty() {
                    info!(
                        module = %self.name,
                        pages = differing.len(),
                        "in-memory code differs from the file at start (recorded as baseline)"
                    );
                }
                self.baseline = Some(
                    differing
                        .iter()
                        .map(|&i| (i, digests[i]))
                        .collect::<HashMap<_, _>>(),
                );
            }
            Some(base) => {
                let new: Vec<usize> = differing
                    .into_iter()
                    .filter(|i| base.get(i) != digests.get(*i))
                    .collect();
                if !new.is_empty() {
                    let shown: Vec<String> = new
                        .iter()
                        .take(8)
                        .map(|i| format!("{:#x}", u64::from(self.text_rva) + (*i * PAGE) as u64))
                        .collect();
                    out.push(Finding {
                        kind: Kind::CodePatched,
                        severity: Severity::Medium,
                        subject: format!("{} .text", self.name),
                        detail: format!(
                            "{} page(s) of {} changed in memory since the agent started",
                            new.len(),
                            self.name
                        ),
                        evidence: json!({
                            "module": self.path,
                            "changed_pages": new.len(),
                            "page_rvas": shown,
                            "baseline_pages": base.len(),
                        }),
                        dedup_key: format!("code:text:{}:{:?}", self.name, new),
                    });
                }
            }
        }
        out
    }
}

struct ModuleInfo {
    path: String,
    base: u64,
    size: u64,
}

fn enum_modules() -> Option<Vec<ModuleInfo>> {
    let mut handles: Vec<HMODULE> = vec![std::ptr::null_mut(); 1024];
    let process = unsafe { GetCurrentProcess() };
    for _ in 0..3 {
        let mut needed = 0u32;
        // SAFETY: `handles` is writable for `cb` bytes.
        let ok = unsafe {
            EnumProcessModulesEx(
                process,
                handles.as_mut_ptr(),
                (handles.len() * std::mem::size_of::<HMODULE>()) as u32,
                &mut needed,
                LIST_MODULES_ALL,
            )
        };
        if ok == 0 {
            return None;
        }
        let count = needed as usize / std::mem::size_of::<HMODULE>();
        if count > handles.len() {
            handles.resize(count + 64, std::ptr::null_mut());
            continue;
        }
        let mut out = Vec::with_capacity(count);
        for &m in &handles[..count] {
            let mut name = [0u16; 1024];
            // SAFETY: writable buffers of the stated sizes.
            let n =
                unsafe { GetModuleFileNameExW(process, m, name.as_mut_ptr(), name.len() as u32) }
                    as usize;
            let mut mi: MODULEINFO = unsafe { std::mem::zeroed() };
            let ok = unsafe {
                GetModuleInformation(
                    process,
                    m,
                    &mut mi,
                    std::mem::size_of::<MODULEINFO>() as u32,
                )
            };
            if n > 0 && n < name.len() && ok != 0 {
                out.push(ModuleInfo {
                    path: String::from_utf16_lossy(&name[..n]),
                    base: mi.lpBaseOfDll as u64,
                    size: u64::from(mi.SizeOfImage),
                });
            }
        }
        return Some(out);
    }
    None
}

fn own_thread_start_addresses() -> Vec<(u32, u64)> {
    let mut out = Vec::new();
    // SAFETY: the snapshot handle is closed below; `entry` is correctly sized.
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if snap.is_null() || snap == INVALID_HANDLE_VALUE {
            return out;
        }
        let own = std::process::id();
        let mut entry: THREADENTRY32 = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;
        let mut more = Thread32First(snap, &mut entry);
        while more != 0 {
            if entry.th32OwnerProcessID == own {
                let t = OpenThread(THREAD_QUERY_INFORMATION, 0, entry.th32ThreadID);
                if !t.is_null() {
                    let mut start: usize = 0;
                    let status = NtQueryInformationThread(
                        t,
                        ThreadQuerySetWin32StartAddress,
                        (&mut start as *mut usize).cast(),
                        std::mem::size_of::<usize>() as u32,
                        std::ptr::null_mut(),
                    );
                    CloseHandle(t);
                    if status >= 0 && start != 0 {
                        out.push((entry.th32ThreadID, start as u64));
                    }
                }
            }
            more = Thread32Next(snap, &mut entry);
        }
        CloseHandle(snap);
    }
    out
}

fn region_info(addr: u64) -> Option<MEMORY_BASIC_INFORMATION> {
    // SAFETY: `mbi` is a correctly sized out-structure.
    unsafe {
        let mut mbi: MEMORY_BASIC_INFORMATION = std::mem::zeroed();
        let n = VirtualQuery(
            addr as *const _,
            &mut mbi,
            std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
        );
        (n != 0).then_some(mbi)
    }
}

fn file_sha256(path: &str) -> Option<String> {
    let bytes = read_file_capped(Path::new(path))?;
    Some(hex(&Sha256::digest(&bytes)))
}

fn process_image(pid: u32) -> Option<String> {
    // SAFETY: handle closed below; buffer writable for the stated length.
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if h.is_null() {
            return None;
        }
        let mut buf = vec![0u16; 1024];
        let mut len = buf.len() as u32;
        let ok = QueryFullProcessImageNameW(h, 0, buf.as_mut_ptr(), &mut len);
        CloseHandle(h);
        (ok != 0).then(|| String::from_utf16_lossy(&buf[..len as usize]))
    }
}

fn system_handle_table() -> Option<Vec<u8>> {
    let mut size = 4 * 1024 * 1024usize;
    for _ in 0..8 {
        let mut buf = vec![0u8; size];
        let mut needed = 0u32;
        // SAFETY: `buf` is writable for `size` bytes.
        let status = unsafe {
            NtQuerySystemInformation(
                SYSTEM_EXTENDED_HANDLE_INFORMATION,
                buf.as_mut_ptr().cast(),
                size as u32,
                &mut needed,
            )
        };
        if status >= 0 {
            buf.truncate(needed as usize);
            return Some(buf);
        }
        if status != STATUS_INFO_LENGTH_MISMATCH {
            return None;
        }
        // The table grows between calls: ask for more than reported.
        size = (needed as usize)
            .max(size)
            .saturating_mul(2)
            .min(MAX_HANDLE_TABLE + 1);
        if size > MAX_HANDLE_TABLE {
            return None;
        }
    }
    None
}

/// Opens a handle to `pid` (kept open so it appears in the table) and returns
/// `(handle, handle value)`.
fn open_self_handle(pid: u32) -> Option<HANDLE> {
    // SAFETY: plain FFI call; null handled.
    let h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    (!h.is_null()).then_some(h)
}

pub struct Checker {
    cfg: Config,
    own_pid: u32,
    exclusions: Exclusions,
    system_root: String,
    own_dir: String,
    code: Option<Vec<CodeModule>>,
    warned: HashSet<&'static str>,
}

impl Checker {
    pub fn new(cfg: &Config) -> Self {
        let exe = std::env::current_exe().unwrap_or_default();
        let own_dir = exe
            .parent()
            .map(|p| policy::normalize_path(&p.to_string_lossy()))
            .unwrap_or_default();
        let system_root = policy::normalize_path(
            &std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into()),
        );
        Self {
            cfg: cfg.clone(),
            own_pid: std::process::id(),
            exclusions: Exclusions {
                system_root: system_root.clone(),
                own_dir: own_dir.clone(),
                extra: cfg.handle_allow.clone(),
            },
            system_root,
            own_dir,
            code: None,
            warned: HashSet::new(),
        }
    }

    fn warn_once(&mut self, key: &'static str, msg: &str) {
        if self.warned.insert(key) {
            warn!("{msg}");
        }
    }

    fn load_code_modules(&mut self) -> Vec<CodeModule> {
        let mut out = Vec::new();
        let mut targets: Vec<(Option<&str>, &[&'static str])> = CRITICAL_EXPORTS
            .iter()
            .map(|(n, f)| (Some(*n), *f))
            .collect();
        targets.push((Some("kernelbase.dll"), &[]));
        targets.push((None, &[]));
        for (name, critical) in targets {
            match module_handle(name).and_then(|h| CodeModule::load(h, critical)) {
                Some(m) => out.push(m),
                None => debug!(module = ?name, "code comparison unavailable for this module"),
            }
        }
        out
    }

    fn code_findings(&mut self) -> Vec<Finding> {
        if self.code.is_none() {
            let loaded = self.load_code_modules();
            self.code = Some(loaded);
        }
        self.code
            .as_mut()
            .map(|mods| mods.iter_mut().flat_map(CodeModule::check).collect())
            .unwrap_or_default()
    }

    fn module_findings(&mut self) -> Vec<Finding> {
        let Some(mods) = enum_modules() else {
            self.warn_once("enum_modules", "module enumeration failed; check skipped");
            return Vec::new();
        };
        let ctx = ModuleContext {
            system_root: &self.system_root,
            own_dir: &self.own_dir,
            allow: &self.cfg.module_allow,
        };
        mods.iter()
            .filter(|m| !policy::is_expected_module(&m.path, &ctx))
            .map(|m| {
                let risky = policy::is_user_writable_location(&m.path);
                Finding {
                    kind: Kind::ModuleInjected,
                    severity: if risky {
                        Severity::High
                    } else {
                        Severity::Medium
                    },
                    subject: m.path.clone(),
                    detail: "A module outside the system directories and the agent installation \
                             is loaded in the agent process"
                        .into(),
                    evidence: json!({
                        "path": m.path,
                        "base": format!("{:#x}", m.base),
                        "size": m.size,
                        "sha256": file_sha256(&m.path),
                        "user_writable_location": risky,
                    }),
                    dedup_key: format!("module:{}", policy::normalize_path(&m.path)),
                }
            })
            .collect()
    }

    fn thread_findings(&mut self) -> Vec<Finding> {
        let Some(mods) = enum_modules() else {
            return Vec::new();
        };
        let ranges: Vec<(u64, u64)> = mods.iter().map(|m| (m.base, m.size)).collect();
        own_thread_start_addresses()
            .into_iter()
            .filter(|(_, addr)| !policy::in_ranges(*addr, &ranges))
            // A DLL loaded between the module list and the thread snapshot is
            // still image-backed memory.
            .filter_map(|(tid, addr)| {
                let region = region_info(addr)?;
                (region.Type != MEM_IMAGE).then_some((tid, addr, region))
            })
            .map(|(tid, addr, region)| Finding {
                kind: Kind::RemoteThread,
                severity: Severity::High,
                subject: format!("thread {tid} starts at {addr:#x}"),
                detail: "A thread of the agent process starts in memory that is not backed by \
                         any loaded module (injected code)"
                    .into(),
                evidence: json!({
                    "thread_id": tid,
                    "start_address": format!("{addr:#x}"),
                    "region_type": format!("{:#x}", region.Type),
                    "region_protect": format!("{:#x}", region.Protect),
                    "allocation_base": format!("{:#x}", region.AllocationBase as u64),
                }),
                dedup_key: format!("thread:{addr:x}"),
            })
            .collect()
    }

    fn debugger_findings(&mut self) -> Vec<Finding> {
        let mut reasons: Vec<&'static str> = Vec::new();
        let process = unsafe { GetCurrentProcess() };
        let mut port: usize = 0;
        // SAFETY: out-buffers are correctly sized for the queried classes.
        let s = unsafe {
            NtQueryInformationProcess(
                process,
                ProcessDebugPort,
                (&mut port as *mut usize).cast(),
                std::mem::size_of::<usize>() as u32,
                std::ptr::null_mut(),
            )
        };
        if s >= 0 && port != 0 {
            reasons.push("debug_port");
        }
        let mut object: usize = 0;
        let s = unsafe {
            NtQueryInformationProcess(
                process,
                ProcessDebugObjectHandle,
                (&mut object as *mut usize).cast(),
                std::mem::size_of::<usize>() as u32,
                std::ptr::null_mut(),
            )
        };
        // STATUS_PORT_NOT_SET (0xC0000353) means "no debug object".
        if s >= 0 && object != 0 {
            reasons.push("debug_object");
        }
        if unsafe { IsDebuggerPresent() } != 0 {
            reasons.push("peb_being_debugged");
        }
        reasons
            .into_iter()
            .map(|r| Finding {
                kind: Kind::DebuggerAttached,
                severity: Severity::High,
                subject: format!("debugger ({r})"),
                detail: "A debugger is attached to the agent process".into(),
                evidence: json!({ "indicator": r, "pid": self.own_pid }),
                dedup_key: format!("debugger:{r}"),
            })
            .collect()
    }

    pub fn self_check(&mut self) -> Vec<Finding> {
        let mut out = Vec::new();
        if self.cfg.code {
            out.extend(self.code_findings());
        }
        if self.cfg.modules {
            out.extend(self.module_findings());
        }
        if self.cfg.threads {
            out.extend(self.thread_findings());
        }
        if self.cfg.debugger {
            out.extend(self.debugger_findings());
        }
        out
    }

    /// Handle watch (every other tick).
    pub fn watch(&mut self) -> Vec<Finding> {
        if !self.cfg.handles {
            return Vec::new();
        }
        let guard_pid = crate::selfprotect::guard::agent_link::verified_guard_pid()
            .filter(|p| *p != self.own_pid);
        // Handles to ourselves/the guard stay open during the snapshot so they
        // appear in it; their object address identifies the processes.
        let mut targets: Vec<(u32, &'static str, HANDLE)> = Vec::new();
        if let Some(h) = open_self_handle(self.own_pid) {
            targets.push((self.own_pid, "agent", h));
        }
        if let Some(pid) = guard_pid {
            if let Some(h) = open_self_handle(pid) {
                targets.push((pid, "guard", h));
            }
        }
        let table = system_handle_table();
        let result = table
            .as_deref()
            .map(|t| self.handle_findings(t, &targets))
            .unwrap_or_default();
        for (_, _, h) in &targets {
            // SAFETY: opened above, closed once.
            unsafe { CloseHandle(*h) };
        }
        if table.is_none() {
            self.warn_once(
                "handle_table",
                "system handle table unavailable; watch skipped",
            );
        }
        result
    }

    fn handle_findings(
        &mut self,
        table: &[u8],
        targets: &[(u32, &'static str, HANDLE)],
    ) -> Vec<Finding> {
        let mut watched: Vec<(u64, &'static str)> = Vec::new();
        let mut exclude: Vec<u64> = Vec::new();
        for (pid, label, h) in targets {
            exclude.push(u64::from(*pid));
            let obj = handles::parse_table(table)
                .find(|e| e.pid == u64::from(*pid) && e.handle == *h as u64)
                .map(|e| e.object);
            match obj {
                Some(o) if o != 0 => watched.push((o, *label)),
                _ => debug!(
                    target = *label,
                    "own object address not visible in the handle table"
                ),
            }
        }
        let openers = handles::find_openers(handles::parse_table(table), &watched, &exclude);
        let mut images: HashMap<u64, Option<String>> = HashMap::new();
        let mut out = Vec::new();
        for o in openers {
            let image = images
                .entry(o.pid)
                .or_insert_with(|| process_image(o.pid as u32))
                .clone();
            if image
                .as_deref()
                .is_some_and(|i| handles::is_expected_opener(i, &self.exclusions))
            {
                continue;
            }
            let names = handles::access_names(o.access);
            let shown = image.clone().unwrap_or_else(|| "<unknown image>".into());
            out.push(Finding {
                kind: Kind::HandleAccess,
                severity: Severity::Medium,
                subject: format!("{shown} (pid {}) -> {}", o.pid, o.target),
                detail: format!(
                    "Another process holds a handle to the {} with {}",
                    o.target,
                    names.join(" | ")
                ),
                evidence: json!({
                    "opener_pid": o.pid,
                    "opener_image": image,
                    "target": o.target,
                    "access": format!("{:#06x}", o.access),
                    "rights": names,
                }),
                dedup_key: format!(
                    "handle:{}:{}:{:#x}",
                    policy::normalize_path(&shown),
                    o.target,
                    o.access
                ),
            });
        }
        out
    }
}
