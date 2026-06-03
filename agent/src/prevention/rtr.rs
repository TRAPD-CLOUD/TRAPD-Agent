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

use super::super::collectors::linux::memscan::{self, MapRegion};

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

/// Resolve the interpreter for a `RunScript`. Defaults to `/bin/sh`. Returns the
/// program plus the flag that precedes an inline script (`-c` for all common
/// POSIX shells and `python`/`perl`/`ruby`). The caller appends the script.
pub fn shell_invocation(interpreter: Option<&str>) -> (String, &'static str) {
    let prog = interpreter
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("/bin/sh");
    (prog.to_string(), "-c")
}

/// Select which memory regions to dump for a `CollectProcessMemory`, given the
/// process's `/proc/<pid>/maps`. Only **readable** regions are eligible;
/// **anonymous-executable** regions (the interesting, injected ones) are chosen
/// first, then the rest, accumulating until `max_total` bytes are budgeted.
/// Returns `(start, end)` byte ranges, never exceeding the budget.
pub fn dumpable_regions(maps: &str, max_total: u64) -> Vec<(u64, u64)> {
    let regions = memscan::parse_maps(maps);
    let readable = |r: &MapRegion| r.perms.contains('r') && r.end > r.start;
    let anon_exec = |r: &MapRegion| r.perms.contains('x') && r.path.is_empty();

    let mut ordered: Vec<&MapRegion> = regions.iter().filter(|r| readable(r)).collect();
    // Stable partition: anon-exec first, original order preserved within groups.
    ordered.sort_by_key(|r| !anon_exec(r));

    let mut out = Vec::new();
    let mut budget = max_total;
    for r in ordered {
        if budget == 0 {
            break;
        }
        let len = r.end - r.start;
        let take = len.min(budget);
        out.push((r.start, r.start + take));
        budget -= take;
    }
    out
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

    #[test]
    fn shell_invocation_defaults_to_sh() {
        assert_eq!(shell_invocation(None), ("/bin/sh".to_string(), "-c"));
        assert_eq!(shell_invocation(Some("  ")), ("/bin/sh".to_string(), "-c"));
        assert_eq!(
            shell_invocation(Some("/usr/bin/python3")),
            ("/usr/bin/python3".to_string(), "-c")
        );
    }

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

    #[test]
    fn dumpable_regions_excludes_unreadable() {
        let maps = "7f0000002000-7f0000003000 ---p 00000000 00:00 0 ";
        assert!(dumpable_regions(maps, 0x10000).is_empty());
    }
}
