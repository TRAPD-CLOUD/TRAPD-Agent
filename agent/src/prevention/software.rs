//! Software (package) management actions, driven by signed backend commands.
//!
//! This turns the agent into a remote software-management endpoint: the backend
//! can install, remove or upgrade packages on the managed host.  Every request
//! arrives through the same Ed25519-signed [`super::commands`] channel as the
//! security-response commands, so nothing here runs without a verified, non-
//! replayable command from the operator.
//!
//! ## Safety
//!   * **No shell.**  Commands are executed via `Command::new(mgr).args(...)`
//!     with an argument vector — there is no shell interpolation, so a package
//!     name can never inject extra commands.
//!   * **Strict name validation.**  Package names are additionally validated
//!     against a conservative charset ([`is_valid_package_name`]) and rejected
//!     before the package manager is ever invoked.
//!   * **Non-interactive.**  apt is run with `DEBIAN_FRONTEND=noninteractive`
//!     and `-y`; dnf/yum with `-y`.  A hung prompt can never block the agent.
//!   * **Bounded output.**  Captured stdout/stderr is truncated so a noisy
//!     manager cannot blow up the audit event.
//!
//! Cross-platform note: the [`PackageManager`] abstraction is the seam the
//! future Windows agent re-implements (winget / MSI) behind the same command
//! payloads.

use std::time::Duration;

// Package managers mutate a shared host-wide database. Never run two at once.
static PACKAGE_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Result of a package operation, surfaced into the audit event.
pub struct OpResult {
    pub success: bool,
    pub summary: String,
    /// Truncated combined stdout+stderr for forensic context.
    pub output: String,
}

/// Supported Linux package managers, in detection-preference order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackageManager {
    Apt,
    Dnf,
    Yum,
    Zypper,
}

impl PackageManager {
    /// Detect only provisioned system binaries; never trust inherited PATH.
    pub fn detect() -> Option<Self> {
        for (mgr, bin) in [
            (PackageManager::Apt, "/usr/bin/apt-get"),
            (PackageManager::Dnf, "/usr/bin/dnf"),
            (PackageManager::Yum, "/usr/bin/yum"),
            (PackageManager::Zypper, "/usr/bin/zypper"),
        ] {
            if std::fs::metadata(bin).is_ok_and(|m| m.is_file()) {
                return Some(mgr);
            }
        }
        None
    }

    fn binary(self) -> &'static str {
        match self {
            PackageManager::Apt => "/usr/bin/apt-get",
            PackageManager::Dnf => "/usr/bin/dnf",
            PackageManager::Yum => "/usr/bin/yum",
            PackageManager::Zypper => "/usr/bin/zypper",
        }
    }

    fn install_args(self, pkg: &str) -> Vec<String> {
        match self {
            PackageManager::Apt => vec!["install".into(), "-y".into(), pkg.into()],
            PackageManager::Dnf | PackageManager::Yum => {
                vec!["install".into(), "-y".into(), pkg.into()]
            }
            PackageManager::Zypper => {
                vec!["--non-interactive".into(), "install".into(), pkg.into()]
            }
        }
    }

    fn remove_args(self, pkg: &str) -> Vec<String> {
        match self {
            PackageManager::Apt => vec!["remove".into(), "-y".into(), pkg.into()],
            PackageManager::Dnf | PackageManager::Yum => {
                vec!["remove".into(), "-y".into(), pkg.into()]
            }
            PackageManager::Zypper => vec!["--non-interactive".into(), "remove".into(), pkg.into()],
        }
    }

    /// Upgrade a single package (apt has no per-package upgrade verb, so we use
    /// `install --only-upgrade`).
    fn upgrade_one_args(self, pkg: &str) -> Vec<String> {
        match self {
            PackageManager::Apt => vec![
                "install".into(),
                "--only-upgrade".into(),
                "-y".into(),
                pkg.into(),
            ],
            PackageManager::Dnf | PackageManager::Yum => {
                vec!["upgrade".into(), "-y".into(), pkg.into()]
            }
            PackageManager::Zypper => vec!["--non-interactive".into(), "update".into(), pkg.into()],
        }
    }

    fn upgrade_all_args(self) -> Vec<String> {
        match self {
            PackageManager::Apt => vec!["upgrade".into(), "-y".into()],
            PackageManager::Dnf | PackageManager::Yum => vec!["upgrade".into(), "-y".into()],
            PackageManager::Zypper => vec!["--non-interactive".into(), "update".into()],
        }
    }

    /// `apt-get update` / `dnf makecache` — refresh metadata before installs so
    /// a fresh box can resolve packages.  Best-effort; failure is non-fatal.
    fn refresh_args(self) -> Option<Vec<String>> {
        match self {
            PackageManager::Apt => Some(vec!["update".into()]),
            PackageManager::Dnf | PackageManager::Yum => None, // resolves on demand
            PackageManager::Zypper => Some(vec!["--non-interactive".into(), "refresh".into()]),
        }
    }
}

/// The package operation requested by the backend.
pub enum Operation<'a> {
    Install(&'a str),
    Remove(&'a str),
    Upgrade(&'a str),
    UpgradeAll,
}

/// Execute a package operation, returning a structured [`OpResult`].
///
/// Never panics; any failure (no package manager, invalid name, non-zero exit)
/// becomes `success = false` with an explanatory summary.
pub async fn execute(op: Operation<'_>) -> OpResult {
    let _serial = PACKAGE_LOCK.lock().await;
    let mgr = match PackageManager::detect() {
        Some(m) => m,
        None => {
            return OpResult {
                success: false,
                summary: "no supported package manager found (apt/dnf/yum/zypper)".into(),
                output: String::new(),
            };
        }
    };

    // Validate the package name up front for the targeted operations.
    if let Some(pkg) = op.package() {
        if !is_valid_package_name(pkg) {
            return OpResult {
                success: false,
                summary: format!("rejected invalid package name: {pkg:?}"),
                output: String::new(),
            };
        }
    }

    // Refresh metadata before an install (best-effort, ignore failure).
    if matches!(op, Operation::Install(_)) {
        if let Some(args) = mgr.refresh_args() {
            let refresh = run(mgr, &args).await;
            if refresh.as_ref().is_ok_and(|out| out.timed_out) {
                return OpResult {
                    success: false,
                    summary: "package metadata refresh timed out".into(),
                    output: String::new(),
                };
            }
        }
    }

    let args = match &op {
        Operation::Install(p) => mgr.install_args(p),
        Operation::Remove(p) => mgr.remove_args(p),
        Operation::Upgrade(p) => mgr.upgrade_one_args(p),
        Operation::UpgradeAll => mgr.upgrade_all_args(),
    };

    match run(mgr, &args).await {
        Ok(result) => {
            let mut output = String::from_utf8_lossy(&result.stdout).into_owned();
            output.push_str(&String::from_utf8_lossy(&result.stderr));
            if result.stdout_total > result.stdout.len()
                || result.stderr_total > result.stderr.len()
            {
                output.push_str("\n…(truncated)");
            }
            OpResult {
                success: result.success(),
                summary: if result.timed_out {
                    format!("{} {} timed out", mgr.binary(), op.verb())
                } else {
                    format!(
                        "{} {} exited with code {}",
                        mgr.binary(),
                        op.verb(),
                        result.exit_code.unwrap_or(-1)
                    )
                },
                output: truncate(&output),
            }
        }
        Err(e) => OpResult {
            success: false,
            summary: format!("failed to run {}: {e}", mgr.binary()),
            output: String::new(),
        },
    }
}

impl Operation<'_> {
    fn package(&self) -> Option<&str> {
        match self {
            Operation::Install(p) | Operation::Remove(p) | Operation::Upgrade(p) => Some(p),
            Operation::UpgradeAll => None,
        }
    }
    fn verb(&self) -> &'static str {
        match self {
            Operation::Install(_) => "install",
            Operation::Remove(_) => "remove",
            Operation::Upgrade(_) => "upgrade",
            Operation::UpgradeAll => "upgrade-all",
        }
    }
}

/// Streaming capture and timeout are enforced while the package manager runs.
async fn run(mgr: PackageManager, args: &[String]) -> std::io::Result<super::rtr::ProcessOutput> {
    super::rtr::run_bounded(mgr.binary(), args, Duration::from_secs(300), MAX_OUTPUT).await
}

/// A conservative package-name allowlist.  Real Debian/RPM names use lower-case
/// letters, digits and `+ - . : _ ~`; we also allow an optional `=version` or
/// `-version` suffix.  Anything with whitespace, shell metacharacters, slashes
/// or path traversal is rejected.
pub fn is_valid_package_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 200 {
        return false;
    }
    // First char must be alphanumeric (no leading dash → no flag injection).
    let mut chars = name.chars();
    let first = chars.next().unwrap();
    if !first.is_ascii_alphanumeric() {
        return false;
    }
    name.chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.' | ':' | '_' | '~' | '='))
}

const MAX_OUTPUT: usize = 4000;
fn truncate(s: &str) -> String {
    if s.len() <= MAX_OUTPUT {
        s.to_string()
    } else {
        let mut end = MAX_OUTPUT;
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        let mut t = s[..end].to_string();
        t.push_str("\n…(truncated)");
        t
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_real_package_names() {
        for n in [
            "curl",
            "nginx",
            "python3",
            "lib32z1",
            "g++",
            "ca-certificates",
            "docker.io",
            "gcc-12",
            "nginx=1.24.0-1",
            "libssl3:amd64",
        ] {
            assert!(is_valid_package_name(n), "{n} should be valid");
        }
    }

    #[test]
    fn rejects_injection_and_flags() {
        for n in [
            "",
            "curl; rm -rf /",
            "a b",
            "$(reboot)",
            "`id`",
            "pkg|cat",
            "--option",
            "-rf",
            "../etc/passwd",
            "pkg\nrm",
            "a&&b",
            "pkg>file",
        ] {
            assert!(!is_valid_package_name(n), "{n:?} should be rejected");
        }
    }

    #[test]
    fn operation_metadata() {
        assert_eq!(Operation::Install("x").verb(), "install");
        assert_eq!(Operation::UpgradeAll.verb(), "upgrade-all");
        assert_eq!(Operation::Remove("x").package(), Some("x"));
        assert_eq!(Operation::UpgradeAll.package(), None);
    }

    #[test]
    fn apt_arg_construction_has_no_shell() {
        // Args are a vector — assert the package lands as its own argv entry.
        let args = PackageManager::Apt.install_args("nginx");
        assert_eq!(args, vec!["install", "-y", "nginx"]);
        let up = PackageManager::Apt.upgrade_one_args("nginx");
        assert_eq!(up, vec!["install", "--only-upgrade", "-y", "nginx"]);
    }

    #[test]
    fn executables_are_absolute_and_output_truncation_handles_unicode() {
        #[cfg(target_os = "linux")]
        for mgr in [
            PackageManager::Apt,
            PackageManager::Dnf,
            PackageManager::Yum,
            PackageManager::Zypper,
        ] {
            assert!(
                std::path::Path::new(mgr.binary()).is_absolute(),
                "package manager lookup must not trust PATH"
            );
        }
        let output = truncate(&format!("a{}", "é".repeat(3001)));
        assert!(output.len() <= MAX_OUTPUT + 32);
    }
}
