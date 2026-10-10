//! Windows process-memory classification — the counterpart of the Linux
//! `/proc/<pid>/maps` rules, expressed over `VirtualQueryEx` facts.
//!
//! Pure: it decides *what a region means*, given its type, protection and (for
//! executable non-image regions) whether it starts with a PE image. The scanner
//! supplies those facts; the rules are unit-tested on every CI host.
//!
//! What counts as injection on Windows:
//!
//!   * **Executable memory that is not backed by a module on disk** — private
//!     (`MEM_PRIVATE`, `VirtualAlloc`) or section-mapped (`MEM_MAPPED`, not an
//!     image). Shellcode, process hollowing leftovers, reflective loaders
//!     (MITRE T1055). Writable + executable (RWX) is the strong single-region
//!     signal; plain executable private memory is also what every JIT leaves
//!     behind, so it is correlation context only.
//!   * **A thread that starts inside such memory** — `CreateRemoteThread` /
//!     shellcode loaders. This is the precise signal: security products leave
//!     RWX trampolines in many processes (API hooking), but nothing legitimate
//!     *starts a thread* in memory it allocated itself, so RWX on its own is
//!     context and an executing thread is the alert.
//!   * **A PE image in executable non-image memory** — reflective DLL / PE
//!     injection (T1055.001, T1055.002). Almost no legitimate software maps a
//!     PE into executable memory it allocated itself, so this is high
//!     confidence and is never excused by the JIT allow-list.

// Compiled everywhere so the rules are tested on every CI platform; only the
// Windows scanner calls them.
#![cfg_attr(not(windows), allow(dead_code))]

use super::mem_finding::MemFinding;
use crate::schema::Severity;

// Win32 memory constants, spelled out so the rules compile and are tested on
// every platform.
pub const MEM_PRIVATE: u32 = 0x0002_0000;
pub const MEM_MAPPED: u32 = 0x0004_0000;
pub const MEM_IMAGE: u32 = 0x0100_0000;

const PAGE_EXECUTE: u32 = 0x10;
const PAGE_EXECUTE_READ: u32 = 0x20;
const PAGE_EXECUTE_READWRITE: u32 = 0x40;
const PAGE_EXECUTE_WRITECOPY: u32 = 0x80;

/// One committed region of a target process, as `VirtualQueryEx` reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WinRegion {
    pub base: u64,
    pub size: u64,
    /// `MEM_PRIVATE`, `MEM_MAPPED` or `MEM_IMAGE`.
    pub kind: u32,
    /// `PAGE_*` protection flags.
    pub protect: u32,
}

impl WinRegion {
    pub fn is_executable(&self) -> bool {
        self.protect
            & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)
            != 0
    }

    /// Whether `address` lies inside this region.
    pub fn contains(&self, address: u64) -> bool {
        address >= self.base && address - self.base < self.size
    }

    pub fn is_writable_executable(&self) -> bool {
        self.protect & (PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY) != 0
    }

    /// Candidate for inspection: executable and not backed by an image on disk.
    pub fn is_unbacked_executable(&self) -> bool {
        self.is_executable() && self.kind != MEM_IMAGE
    }

    fn describe(&self) -> String {
        let prot = if self.is_writable_executable() {
            "rwx"
        } else if self.protect & PAGE_EXECUTE_READ != 0 {
            "r-x"
        } else {
            "--x"
        };
        let kind = match self.kind {
            MEM_PRIVATE => "private",
            MEM_MAPPED => "mapped",
            _ => "other",
        };
        format!(
            "{:#x}-{:#x} {prot} <{kind}>",
            self.base,
            self.base.saturating_add(self.size)
        )
    }
}

/// Whether the first bytes of a region form a PE image: `MZ`, and an `e_lfanew`
/// that points inside the buffer at `PE\0\0`. A bare `MZ` is not enough — it is
/// two arbitrary bytes.
pub fn looks_like_pe(head: &[u8]) -> bool {
    if head.len() < 0x40 || &head[..2] != b"MZ" {
        return false;
    }
    let e_lfanew = u32::from_le_bytes([head[0x3c], head[0x3d], head[0x3e], head[0x3f]]) as usize;
    e_lfanew >= 0x40
        && e_lfanew <= head.len().saturating_sub(4)
        && &head[e_lfanew..e_lfanew + 4] == b"PE\0\0"
}

/// Facts about one region beyond its protection flags.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RegionContext {
    /// The region starts with a PE image ([`looks_like_pe`]).
    pub header_is_pe: bool,
    /// A thread of the process was started at an address inside the region.
    pub thread_started_here: bool,
    /// The process legitimately generates code at run time.
    pub jit_runtime: bool,
    /// The process image lives in an admin-only location ([`is_protected_image_path`]).
    pub protected_image: bool,
}

/// Classify one unbacked-executable region.
pub fn classify(region: &WinRegion, ctx: RegionContext) -> Option<MemFinding> {
    if !region.is_unbacked_executable() {
        return None;
    }
    if ctx.header_is_pe {
        return Some(MemFinding {
            rule_id: "memory.injected_pe",
            title: "PE image in executable non-image memory (reflective injection)",
            technique: "T1055.001",
            confidence: 88,
            severity: Severity::High,
            region: region.describe(),
        });
    }
    if ctx.thread_started_here && ctx.protected_image && !region.is_writable_executable() {
        // Shell and vendor processes (explorer, RuntimeBroker, WARP, Copilot)
        // start threads in sealed (r-x) generated code or hook trampolines.
        // Shellcode injection allocates RWX, which stays an alert below, so
        // this is context only; a PE header is handled above.
        return Some(MemFinding {
            rule_id: "memory.anon_exec",
            title: "Thread started in sealed executable memory of a protected-location image",
            technique: "T1055",
            confidence: 45,
            severity: Severity::Low,
            region: region.describe(),
        });
    }
    if ctx.thread_started_here {
        // Not excused for JIT runtimes: their threads start in their own
        // modules; the generated code is *called* from there.
        return Some(MemFinding {
            rule_id: "memory.anon_exec",
            title: "Thread started in executable non-image memory (injected code running)",
            technique: "T1055",
            confidence: 94,
            severity: Severity::High,
            region: region.describe(),
        });
    }
    if ctx.jit_runtime {
        return None;
    }
    // Writable+executable or plain executable memory with nothing running from
    // it: correlation context only (confidence < 50 never alerts alone), because
    // hooking engines and JITs leave exactly this behind.
    match region.kind {
        MEM_PRIVATE => Some(MemFinding {
            rule_id: "memory.anon_exec",
            title: if region.is_writable_executable() {
                "Writable+executable private memory (RWX)"
            } else {
                "Executable private memory"
            },
            technique: "T1055",
            confidence: if region.is_writable_executable() {
                48
            } else {
                40
            },
            severity: Severity::Low,
            region: region.describe(),
        }),
        MEM_MAPPED if region.is_writable_executable() => Some(MemFinding {
            rule_id: "memory.anon_exec",
            title: "Writable+executable mapped (non-image) memory",
            technique: "T1055",
            confidence: 46,
            severity: Severity::Low,
            region: region.describe(),
        }),
        _ => None,
    }
}

/// Processes that generate machine code at run time and therefore legitimately
/// own writable+executable private memory (matched on the lower-cased image
/// name). Browsers and the Chromium/Electron family, language runtimes, and
/// virtualisation.
const JIT_PROCESSES: &[&str] = &[
    "chrome.exe",
    "msedge.exe",
    "msedgewebview2.exe",
    "firefox.exe",
    "brave.exe",
    "opera.exe",
    "vivaldi.exe",
    "iexplore.exe",
    "code.exe",
    "teams.exe",
    "ms-teams.exe",
    "slack.exe",
    "discord.exe",
    "spotify.exe",
    "whatsapp.exe",
    "signal.exe",
    "obsidian.exe",
    "notion.exe",
    "java.exe",
    "javaw.exe",
    "node.exe",
    "deno.exe",
    "bun.exe",
    "python.exe",
    "pythonw.exe",
    "pypy.exe",
    "ruby.exe",
    "php.exe",
    "php-cgi.exe",
    "julia.exe",
    "erl.exe",
    "beam.smp.exe",
    "dotnet.exe",
    "powershell.exe",
    "pwsh.exe",
    "powershell_ise.exe",
    "mono.exe",
    "qemu-system-x86_64.exe",
    "vmware-vmx.exe",
    "vmmem",
    "virtualbox.exe",
    "vboxheadless.exe",
];

/// Loaded modules that identify a code-generating engine inside an otherwise
/// ordinary process (every .NET application, every JVM, every V8/CEF host).
const JIT_MODULES: &[&str] = &[
    "clrjit.dll",
    "coreclr.dll",
    "clr.dll",
    "mscorjit.dll",
    "jvm.dll",
    "libcef.dll",
    "v8.dll",
    "node.dll",
    "mozjs.dll",
    "xul.dll",
    "chrome_elf.dll",
    "mono-2.0-bdwgc.dll",
    "luajit.dll",
];

/// Admin-only install roots of this host, normalised like an identity path:
/// lower-case, `/` separators, trailing `/`. Derived from `%SystemRoot%` and
/// the Program Files known folders, so hosts with Windows or applications on
/// another drive are classified like `C:` installs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallRoots {
    pub windows: Vec<String>,
    pub program_files: Vec<String>,
}

fn normalise_root(root: &str) -> Option<String> {
    let mut r = root.trim().replace('\\', "/").to_ascii_lowercase();
    // A relative or drive-less value is not an install root.
    if r.as_bytes().get(1) != Some(&b':') {
        return None;
    }
    if !r.ends_with('/') {
        r.push('/');
    }
    Some(r)
}

fn collect_roots(values: &[Option<&str>], fallback: &[&str]) -> Vec<String> {
    let mut roots: Vec<String> = values
        .iter()
        .flatten()
        .filter_map(|v| normalise_root(v))
        .collect();
    if roots.is_empty() {
        roots = fallback.iter().filter_map(|v| normalise_root(v)).collect();
    }
    roots.sort();
    roots.dedup();
    roots
}

pub fn install_roots_from(
    system_root: Option<&str>,
    program_files: &[Option<&str>],
) -> InstallRoots {
    InstallRoots {
        windows: collect_roots(&[system_root], &["C:\\Windows"]),
        program_files: collect_roots(
            program_files,
            &["C:\\Program Files", "C:\\Program Files (x86)"],
        ),
    }
}

/// The roots of the running host (computed once).
pub fn install_roots() -> &'static InstallRoots {
    static ROOTS: std::sync::OnceLock<InstallRoots> = std::sync::OnceLock::new();
    ROOTS.get_or_init(|| {
        let var = |k: &str| std::env::var(k).ok();
        let (sr, pf, pf86, pf64) = (
            var("SystemRoot"),
            var("ProgramFiles"),
            var("ProgramFiles(x86)"),
            var("ProgramW6432"),
        );
        install_roots_from(
            sr.as_deref(),
            &[pf.as_deref(), pf86.as_deref(), pf64.as_deref()],
        )
    })
}

/// `exe` is a normalised identity path (lower-case, `/`).
pub fn under_install_roots(
    exe: &str,
    roots: &InstallRoots,
    windows_subdirs: &[&str],
    include_program_files: bool,
) -> bool {
    roots.windows.iter().any(|w| {
        windows_subdirs
            .iter()
            .any(|d| exe.starts_with(&format!("{w}{d}")))
    }) || (include_program_files && roots.program_files.iter().any(|p| exe.starts_with(p)))
}

/// Whether a process image path is under an admin-only Windows install
/// location. Path based on purpose: writing there needs admin, so it is a
/// provenance hint, not a signature check (a hollowed image keeps its path,
/// which is why RWX thread starts and PE headers are never downgraded).
pub fn is_protected_image_path(path: &str) -> bool {
    is_protected_image_path_in(path, install_roots())
}

fn is_protected_image_path_in(path: &str, roots: &InstallRoots) -> bool {
    let p = path.replace('\\', "/").to_ascii_lowercase();
    under_install_roots(
        &p,
        roots,
        &["system32/", "syswow64/", "systemapps/", "explorer.exe"],
        true,
    )
}

pub fn is_jit_process(image_name: &str) -> bool {
    let name = image_name.to_ascii_lowercase();
    JIT_PROCESSES.iter().any(|j| name == *j)
}

pub fn is_jit_module(module_name: &str) -> bool {
    let name = module_name.to_ascii_lowercase();
    JIT_MODULES.iter().any(|j| name == *j)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn region(kind: u32, protect: u32) -> WinRegion {
        WinRegion {
            base: 0x1_0000_0000,
            size: 0x1000,
            kind,
            protect,
        }
    }

    fn pe_header() -> Vec<u8> {
        let mut h = vec![0u8; 0x200];
        h[0] = b'M';
        h[1] = b'Z';
        h[0x3c] = 0x80;
        h[0x80..0x84].copy_from_slice(b"PE\0\0");
        h
    }

    #[test]
    fn a_real_pe_header_is_recognised_and_lookalikes_are_not() {
        assert!(looks_like_pe(&pe_header()));
        // "MZ" alone.
        let mut bare = vec![0u8; 0x200];
        bare[..2].copy_from_slice(b"MZ");
        assert!(!looks_like_pe(&bare));
        // e_lfanew pointing outside the buffer or below the DOS header.
        let mut far = pe_header();
        far[0x3c..0x40].copy_from_slice(&0x0010_0000u32.to_le_bytes());
        assert!(!looks_like_pe(&far));
        let mut low = pe_header();
        low[0x3c..0x40].copy_from_slice(&0x10u32.to_le_bytes());
        assert!(!looks_like_pe(&low));
        assert!(!looks_like_pe(b"MZ"));
        assert!(!looks_like_pe(&[]));
    }

    fn ctx() -> RegionContext {
        RegionContext::default()
    }

    #[test]
    fn region_containment_is_exact_at_both_edges_and_overflow_safe() {
        let r = region(MEM_PRIVATE, PAGE_EXECUTE_READWRITE);
        assert!(r.contains(r.base));
        assert!(r.contains(r.base + r.size - 1));
        assert!(!r.contains(r.base + r.size));
        assert!(!r.contains(r.base - 1));
        let top = WinRegion {
            base: u64::MAX - 0xfff,
            size: 0x1000,
            ..r
        };
        assert!(top.contains(u64::MAX));
    }

    #[test]
    fn protected_image_path_is_admin_only_locations_only() {
        for p in [
            "C:\\Windows\\explorer.exe",
            "c:\\windows\\System32\\RuntimeBroker.exe",
            "C:\\Program Files\\Cloudflare\\Cloudflare WARP\\warp-svc.exe",
            "C:\\Windows\\SystemApps\\Microsoft.LockApp_x\\LockApp.exe",
        ] {
            assert!(is_protected_image_path(p), "{p}");
        }
        for p in [
            "C:\\Users\\bob\\AppData\\Local\\Temp\\evil.exe",
            "C:\\Windows\\Temp\\evil.exe",
            "C:\\ProgramData\\x.exe",
            "C:\\Program Files Evil\\x.exe",
            "",
        ] {
            assert!(!is_protected_image_path(p), "{p}");
        }
    }

    #[test]
    fn protected_roots_follow_the_host_instead_of_assuming_c() {
        let roots = install_roots_from(
            Some("D:\\WINDOWS"),
            &[
                Some("E:\\Program Files"),
                Some("E:\\Program Files (x86)"),
                None,
            ],
        );
        for p in [
            "D:\\Windows\\System32\\RuntimeBroker.exe",
            "d:\\windows\\explorer.exe",
            "E:\\Program Files\\Vendor\\a.exe",
            "E:\\Program Files (x86)\\Vendor\\a.exe",
        ] {
            assert!(is_protected_image_path_in(p, &roots), "{p}");
        }
        for p in [
            "C:\\Windows\\System32\\x.exe",
            "C:\\Program Files\\x.exe",
            "E:\\Program Files Evil\\x.exe",
            "E:\\Windows\\System32\\x.exe",
        ] {
            assert!(!is_protected_image_path_in(p, &roots), "{p}");
        }
    }

    #[test]
    fn unset_or_relative_roots_fall_back_to_the_c_defaults() {
        let roots = install_roots_from(Some("windows"), &[None]);
        assert_eq!(roots.windows, vec!["c:/windows/".to_string()]);
        assert_eq!(
            roots.program_files,
            vec![
                "c:/program files (x86)/".to_string(),
                "c:/program files/".to_string()
            ]
        );
    }

    #[test]
    fn thread_start_in_sealed_memory_of_a_protected_image_is_context() {
        let started = RegionContext {
            thread_started_here: true,
            protected_image: true,
            ..ctx()
        };
        let f = classify(&region(MEM_PRIVATE, PAGE_EXECUTE_READ), started).unwrap();
        assert_eq!(f.rule_id, "memory.anon_exec");
        assert!(f.confidence < 50);
    }

    #[test]
    fn thread_start_still_alerts_for_rwx_unprotected_images_and_pe() {
        // RWX shellcode thread inside a protected-location process (explorer).
        let in_protected = RegionContext {
            thread_started_here: true,
            protected_image: true,
            ..ctx()
        };
        let f = classify(&region(MEM_PRIVATE, PAGE_EXECUTE_READWRITE), in_protected).unwrap();
        assert!(f.confidence >= 90);
        // Sealed memory, but the image is in a user-writable location.
        let unprotected = RegionContext {
            thread_started_here: true,
            ..ctx()
        };
        let f = classify(&region(MEM_PRIVATE, PAGE_EXECUTE_READ), unprotected).unwrap();
        assert!(f.confidence >= 90);
        // Reflective PE is never downgraded.
        let pe = RegionContext {
            header_is_pe: true,
            protected_image: true,
            ..ctx()
        };
        let f = classify(&region(MEM_PRIVATE, PAGE_EXECUTE_READ), pe).unwrap();
        assert_eq!(f.rule_id, "memory.injected_pe");
    }

    #[test]
    fn rwx_alone_is_context_not_an_alert() {
        // Security products hook APIs with RWX trampolines in many processes.
        for kind in [MEM_PRIVATE, MEM_MAPPED] {
            let f = classify(&region(kind, PAGE_EXECUTE_READWRITE), ctx()).unwrap();
            assert_eq!(f.rule_id, "memory.anon_exec");
            assert!(f.confidence < 50, "must stay a non-alerting signal");
            assert_eq!(f.severity, Severity::Low);
        }
        let plain = classify(&region(MEM_PRIVATE, PAGE_EXECUTE_READ), ctx()).unwrap();
        assert!(plain.confidence < 50);
    }

    #[test]
    fn a_thread_started_in_unbacked_executable_memory_is_the_injection_alert() {
        let started = RegionContext {
            thread_started_here: true,
            ..ctx()
        };
        for protect in [PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_READ] {
            let f = classify(&region(MEM_PRIVATE, protect), started).unwrap();
            assert_eq!(f.rule_id, "memory.anon_exec");
            assert_eq!(f.severity, Severity::High);
            assert!(f.confidence >= 90);
            assert!(f.title.contains("Thread started"));
        }
        let f = classify(&region(MEM_MAPPED, PAGE_EXECUTE_READWRITE), started).unwrap();
        assert!(f.confidence >= 90);
    }

    #[test]
    fn image_backed_and_non_executable_memory_is_benign() {
        let started = RegionContext {
            thread_started_here: true,
            header_is_pe: true,
            jit_runtime: false,
            protected_image: false,
        };
        // Even a thread start or a PE header means nothing in a real module …
        assert!(classify(&region(MEM_IMAGE, PAGE_EXECUTE_READ), started).is_none());
        assert!(classify(&region(MEM_IMAGE, PAGE_EXECUTE_READWRITE), started).is_none());
        // … or in memory that is not executable.
        assert!(classify(&region(MEM_PRIVATE, 0x04 /* PAGE_READWRITE */), started).is_none());
        // Shared executable read-only sections are common (graphics stacks).
        assert!(classify(&region(MEM_MAPPED, PAGE_EXECUTE_READ), ctx()).is_none());
    }

    #[test]
    fn a_jit_runtime_is_excused_for_context_but_never_for_running_or_pe_code() {
        let jit = RegionContext {
            jit_runtime: true,
            ..ctx()
        };
        assert!(classify(&region(MEM_PRIVATE, PAGE_EXECUTE_READWRITE), jit).is_none());
        assert!(classify(&region(MEM_PRIVATE, PAGE_EXECUTE_READ), jit).is_none());
        let running = RegionContext {
            thread_started_here: true,
            ..jit
        };
        assert!(classify(&region(MEM_PRIVATE, PAGE_EXECUTE_READWRITE), running).is_some());
        let pe = RegionContext {
            header_is_pe: true,
            ..jit
        };
        let f = classify(&region(MEM_PRIVATE, PAGE_EXECUTE_READWRITE), pe).unwrap();
        assert_eq!(f.rule_id, "memory.injected_pe");
        assert_eq!(f.technique, "T1055.001");
    }

    #[test]
    fn a_pe_image_outranks_a_thread_start_in_the_same_region() {
        let both = RegionContext {
            header_is_pe: true,
            thread_started_here: true,
            jit_runtime: false,
            protected_image: false,
        };
        let f = classify(&region(MEM_PRIVATE, PAGE_EXECUTE_READWRITE), both).unwrap();
        assert_eq!(f.rule_id, "memory.injected_pe");
    }

    #[test]
    fn jit_allow_lists_match_case_insensitively_and_exactly() {
        assert!(is_jit_process("Chrome.EXE"));
        assert!(is_jit_process("pwsh.exe"));
        assert!(!is_jit_process("chrome.exe.bak"));
        assert!(!is_jit_process("notepad.exe"));
        assert!(
            !is_jit_process("svchost.exe"),
            "system hosts are not exempt"
        );
        assert!(is_jit_module("CLRJIT.dll"));
        assert!(!is_jit_module("kernel32.dll"));
    }
}
