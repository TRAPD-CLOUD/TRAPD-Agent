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
        assert_eq!(&args[..3], ["-NoProfile", "-NonInteractive", "-EncodedCommand"]);
        // Round-trips as UTF-16LE: exactly what PowerShell decodes.
        let raw = base64::engine::general_purpose::STANDARD.decode(&args[3]).unwrap();
        let units: Vec<u16> = raw.chunks(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
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
