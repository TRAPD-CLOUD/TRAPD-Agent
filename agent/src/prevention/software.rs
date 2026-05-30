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

use std::process::Command;

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
    /// Detect the host package manager by probing for the binary on PATH.
    pub fn detect() -> Option<Self> {
        for (mgr, bin) in [
            (PackageManager::Apt, "apt-get"),
            (PackageManager::Dnf, "dnf"),
            (PackageManager::Yum, "yum"),
            (PackageManager::Zypper, "zypper"),
        ] {
            if which(bin) {
                return Some(mgr);
            }
        }
        None
    }

    fn binary(self) -> &'static str {
        match self {
            PackageManager::Apt => "apt-get",
            PackageManager::Dnf => "dnf",
            PackageManager::Yum => "yum",
            PackageManager::Zypper => "zypper",
        }
    }

    fn install_args(self, pkg: &str) -> Vec<String> {
        match self {
            PackageManager::Apt => vec!["install".into(), "-y".into(), pkg.into()],
            PackageManager::Dnf | PackageManager::Yum => vec!["install".into(), "-y".into(), pkg.into()],
            PackageManager::Zypper => vec!["--non-interactive".into(), "install".into(), pkg.into()],
        }
    }

    fn remove_args(self, pkg: &str) -> Vec<String> {
        match self {
            PackageManager::Apt => vec!["remove".into(), "-y".into(), pkg.into()],
            PackageManager::Dnf | PackageManager::Yum => vec!["remove".into(), "-y".into(), pkg.into()],
            PackageManager::Zypper => vec!["--non-interactive".into(), "remove".into(), pkg.into()],
        }
    }

    /// Upgrade a single package (apt has no per-package upgrade verb, so we use
    /// `install --only-upgrade`).
    fn upgrade_one_args(self, pkg: &str) -> Vec<String> {
        match self {
            PackageManager::Apt => vec!["install".into(), "--only-upgrade".into(), "-y".into(), pkg.into()],
            PackageManager::Dnf | PackageManager::Yum => vec!["upgrade".into(), "-y".into(), pkg.into()],
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
pub fn execute(op: Operation) -> OpResult {
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
            let _ = run(mgr, &args);
        }
    }

    let args = match &op {
        Operation::Install(p) => mgr.install_args(p),
        Operation::Remove(p) => mgr.remove_args(p),
        Operation::Upgrade(p) => mgr.upgrade_one_args(p),
        Operation::UpgradeAll => mgr.upgrade_all_args(),
    };

    match run(mgr, &args) {
        Ok((0, out)) => OpResult {
            success: true,
            summary: format!("{} {} succeeded", mgr.binary(), op.verb()),
            output: truncate(&out),
        },
        Ok((code, out)) => OpResult {
            success: false,
            summary: format!("{} {} exited with code {code}", mgr.binary(), op.verb()),
            output: truncate(&out),
        },
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

/// Run `mgr <args>` non-interactively, returning `(exit_code, combined_output)`.
fn run(mgr: PackageManager, args: &[String]) -> std::io::Result<(i32, String)> {
    let output = Command::new(mgr.binary())
        .args(args)
        .env("DEBIAN_FRONTEND", "noninteractive")
        .env("APT_LISTCHANGES_FRONTEND", "none")
        .output()?;
    let mut combined = String::from_utf8_lossy(&output.stdout).into_owned();
    combined.push_str(&String::from_utf8_lossy(&output.stderr));
    Ok((output.status.code().unwrap_or(-1), combined))
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
    name.chars().all(|c| {
        c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.' | ':' | '_' | '~' | '=')
    })
}

fn which(bin: &str) -> bool {
    if let Ok(path) = std::env::var("PATH") {
        for dir in path.split(':') {
            if std::path::Path::new(dir).join(bin).exists() {
                return true;
            }
        }
    }
    false
}

const MAX_OUTPUT: usize = 4000;
fn truncate(s: &str) -> String {
    if s.len() <= MAX_OUTPUT {
        s.to_string()
    } else {
        let mut t = s[..MAX_OUTPUT].to_string();
        t.push_str("\n…(truncated)");
        t
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_real_package_names() {
        for n in ["curl", "nginx", "python3", "lib32z1", "g++", "ca-certificates",
                  "docker.io", "gcc-12", "nginx=1.24.0-1", "libssl3:amd64"] {
            assert!(is_valid_package_name(n), "{n} should be valid");
        }
    }

    #[test]
    fn rejects_injection_and_flags() {
        for n in ["", "curl; rm -rf /", "a b", "$(reboot)", "`id`", "pkg|cat",
                  "--option", "-rf", "../etc/passwd", "pkg\nrm", "a&&b", "pkg>file"] {
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
}
