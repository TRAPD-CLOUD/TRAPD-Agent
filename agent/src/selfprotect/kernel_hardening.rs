//! Kernel security-parameter audit.
//!
//! Called once at agent startup.  Reads a curated set of `/proc/sys/kernel/*`
//! and `/proc/sys/kernel/yama/*` parameters and logs a warning for every
//! value that deviates from the recommended security baseline.
//!
//! No agent functionality is blocked by a sub-optimal parameter — the checks
//! are advisory.  Operators should harden the kernel according to the
//! recommendations in the log output.

use tracing::{info, warn};

struct Param {
    path:        &'static str,
    recommended: &'static str,
    description: &'static str,
    /// If true, warn even when the value is "better" than recommended
    /// (e.g. modules_disabled=1 is only achievable on some distros, so a
    ///  missing file is acceptable).
    optional:    bool,
}

const PARAMS: &[Param] = &[
    Param {
        path:        "/proc/sys/kernel/dmesg_restrict",
        recommended: "1",
        description: "restrict dmesg access to root (prevents info-leak of kernel ring buffer)",
        optional:    false,
    },
    Param {
        path:        "/proc/sys/kernel/kptr_restrict",
        recommended: "2",
        description: "hide kernel symbol addresses from all users (prevents KASLR bypass)",
        optional:    false,
    },
    Param {
        path:        "/proc/sys/kernel/perf_event_paranoid",
        recommended: "3",
        description: "restrict perf_event_open(2) to root (prevents side-channel attacks)",
        optional:    false,
    },
    Param {
        path:        "/proc/sys/kernel/yama/ptrace_scope",
        recommended: "1",
        description: "Yama ptrace scope (1=parent-only, 2=admin-only, 3=disabled — prevents process injection)",
        optional:    false,
    },
    Param {
        path:        "/proc/sys/kernel/randomize_va_space",
        recommended: "2",
        description: "full ASLR (prevents ROP chain construction from known addresses)",
        optional:    false,
    },
    Param {
        path:        "/proc/sys/kernel/modules_disabled",
        recommended: "1",
        description: "prevent loading new kernel modules after boot (prevents LKM rootkits)",
        optional:    true,
    },
    Param {
        path:        "/proc/sys/fs/protected_symlinks",
        recommended: "1",
        description: "protect symlinks in sticky directories (prevents symlink-race attacks)",
        optional:    false,
    },
    Param {
        path:        "/proc/sys/fs/protected_hardlinks",
        recommended: "1",
        description: "restrict hard link creation (prevents privilege-escalation via hard links)",
        optional:    false,
    },
    Param {
        path:        "/proc/sys/net/ipv4/conf/all/rp_filter",
        recommended: "1",
        description: "strict reverse-path filtering (prevents IP spoofing)",
        optional:    false,
    },
];

/// Audit kernel security parameters and emit log warnings for deviations.
/// Returns the number of sub-optimal parameters found.
pub fn audit() -> usize {
    let mut warnings = 0usize;

    for p in PARAMS {
        match std::fs::read_to_string(p.path) {
            Ok(raw) => {
                let val = raw.trim();
                if val == p.recommended {
                    info!(
                        param = p.path,
                        value = val,
                        "Kernel hardening ✓  {}",
                        p.description,
                    );
                } else {
                    let sysctl_key = p.path
                        .trim_start_matches("/proc/sys/")
                        .replace('/', ".");
                    warn!(
                        param       = p.path,
                        current     = val,
                        recommended = p.recommended,
                        "Kernel hardening ⚠  {}  \
                         (current={val}, recommended={})  \
                         Fix: sysctl -w {sysctl_key}={}",
                        p.description,
                        p.recommended,
                        p.recommended,
                    );
                    warnings += 1;
                }
            }
            Err(_) if p.optional => {
                info!(param = p.path, "Kernel param not available on this kernel (optional)");
            }
            Err(_) => {
                warn!(
                    param = p.path,
                    "Kernel param not readable — kernel may lack support or permissions insufficient"
                );
            }
        }
    }

    if warnings == 0 {
        info!("Kernel hardening: all parameters are at recommended values ✓");
    } else {
        warn!(
            count = warnings,
            "Kernel hardening: {warnings} parameter(s) deviate from the security baseline. \
             Agent continues — see individual warnings above for remediation steps."
        );
    }

    warnings
}
