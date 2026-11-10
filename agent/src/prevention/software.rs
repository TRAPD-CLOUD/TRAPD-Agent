//! Software (package) management actions, driven by signed backend commands.
//!
//! The backend can install, remove or upgrade packages on a Linux host and
//! uninstall MSI products on a Windows host. Every request arrives through the
//! same Ed25519-signed [`super::commands`] channel as the security-response
//! commands, so nothing here runs without a verified, non-replayable command.
//!
//! ## Safety
//!   * **No shell.** The package manager is started with an argument vector, so
//!     a package name can never inject extra commands.
//!   * **Strict names.** Linux names must pass [`is_valid_package_name`]. A
//!     Windows target must be an MSI product code ([`msi_product_code`]) that
//!     the registry lists as a machine-wide Windows Installer product. An
//!     uninstall string from the registry is never executed.
//!   * **Fixed binaries.** The package manager is taken from the system
//!     directories, never from `PATH`.
//!   * **The agent stays.** Its own package cannot be installed, removed or
//!     changed this way; the agent has a signed update path of its own.
//!   * **No collateral removal.** A removal that would take other packages with
//!     it is refused, and an apt install may not remove packages either.
//!   * **Bounded.** Every run has a deadline and a cap on captured output, and
//!     never prompts.

use std::path::PathBuf;
use std::time::Duration;

use super::rtr::{run_bounded, ScriptRun};

/// Result of a package operation, surfaced into the audit event.
pub struct OpResult {
    pub success: bool,
    pub summary: String,
    /// Truncated combined stdout+stderr for forensic context.
    pub output: String,
}

impl OpResult {
    fn refused(summary: impl Into<String>) -> Self {
        Self {
            success: false,
            summary: summary.into(),
            output: String::new(),
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

/// Deadline for one package. Killing a package manager mid-transaction can
/// leave a package half configured, so this is generous: it exists to end a
/// hang, not to hurry a slow mirror.
const PACKAGE_TIMEOUT: Duration = Duration::from_secs(15 * 60);
#[cfg_attr(windows, allow(dead_code))]
const UPGRADE_ALL_TIMEOUT: Duration = Duration::from_secs(60 * 60);
/// Deadline for metadata refreshes and removal checks, which change nothing.
#[cfg_attr(windows, allow(dead_code))]
const CHECK_TIMEOUT: Duration = Duration::from_secs(5 * 60);
/// Bytes kept per output stream of one run.
const CAPTURE: usize = 64 * 1024;
/// Bytes of output that reach the audit event.
const MAX_OUTPUT: usize = 4000;

/// Package name of the agent on Linux (`deploy/deb`).
#[cfg_attr(windows, allow(dead_code))]
const OWN_PACKAGE: &str = "trapd-agent";
/// Product name of the agent MSI (`deploy/windows/Package.wxs`), lower case.
#[cfg_attr(not(windows), allow(dead_code))]
const OWN_PRODUCT: &str = "trapd agent";

/// Execute a package operation. Never panics; every failure becomes
/// `success = false` with an explanatory summary.
pub async fn execute(op: Operation<'_>) -> OpResult {
    #[cfg(windows)]
    {
        execute_windows(op).await
    }
    #[cfg(not(windows))]
    {
        execute_unix(op).await
    }
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
    if !name.starts_with(|c: char| c.is_ascii_alphanumeric()) {
        return false;
    }
    name.chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.' | ':' | '_' | '~' | '='))
}

/// The package a spec names, without an `=version` or `:arch` qualifier.
#[cfg_attr(windows, allow(dead_code))]
fn base_name(spec: &str) -> &str {
    spec.split(['=', ':']).next().unwrap_or(spec)
}

/// True for the agent's own package, including the RPM `name-version` form.
/// A differently named package that merely shares the prefix is refused too;
/// that errs on the side of keeping the agent installed.
#[cfg_attr(windows, allow(dead_code))]
fn is_own_package(spec: &str) -> bool {
    let name = base_name(spec).to_ascii_lowercase();
    name == OWN_PACKAGE
        || name
            .strip_prefix(OWN_PACKAGE)
            .is_some_and(|rest| rest.starts_with('-'))
}

/// Packages `apt-get -s remove` reports it would remove.
#[cfg_attr(windows, allow(dead_code))]
fn apt_removals(simulation: &str) -> Vec<String> {
    simulation
        .lines()
        .filter_map(|line| {
            line.strip_prefix("Remv ")
                .or_else(|| line.strip_prefix("Purg "))
        })
        .filter_map(|rest| rest.split_whitespace().next())
        .map(|name| base_name(name).to_string())
        .collect()
}

/// Allow a removal only when it removes the requested package and nothing else.
#[cfg_attr(windows, allow(dead_code))]
fn removal_verdict(requested: &str, removals: &[String]) -> Result<(), String> {
    let wanted = base_name(requested);
    if !removals.iter().any(|name| name == wanted) {
        return Err(format!("package {wanted} is not installed"));
    }
    let mut others: Vec<&str> = removals
        .iter()
        .map(String::as_str)
        .filter(|name| *name != wanted)
        .collect();
    if others.is_empty() {
        return Ok(());
    }
    others.sort_unstable();
    others.dedup();
    let shown = others
        .iter()
        .take(10)
        .copied()
        .collect::<Vec<_>>()
        .join(", ");
    Err(format!(
        "refused: removing {wanted} would also remove {} other package(s): {shown}",
        others.len()
    ))
}

/// Canonical form of an MSI product code: upper case, without braces. Accepts
/// the registry form `{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}` and the bare form
/// a command carries, which fits [`is_valid_package_name`].
#[cfg_attr(not(windows), allow(dead_code))]
pub fn msi_product_code(value: &str) -> Option<String> {
    let inner = value
        .strip_prefix('{')
        .and_then(|rest| rest.strip_suffix('}'))
        .unwrap_or(value);
    if inner.len() != 36 {
        return None;
    }
    let well_formed = inner.bytes().enumerate().all(|(index, byte)| {
        if matches!(index, 8 | 13 | 18 | 23) {
            byte == b'-'
        } else {
            byte.is_ascii_hexdigit()
        }
    });
    well_formed.then(|| inner.to_ascii_uppercase())
}

/// What an `msiexec /x` exit code means.
#[cfg_attr(not(windows), allow(dead_code))]
fn msi_outcome(code: Option<i32>) -> (bool, String) {
    match code {
        Some(0) => (true, "uninstalled".into()),
        Some(3010 | 1641) => (
            true,
            "uninstalled; a restart is required to complete it".into(),
        ),
        Some(1605) => (false, "the product is not installed".into()),
        Some(1618) => (false, "another installation is in progress".into()),
        Some(other) => (false, format!("msiexec exited with code {other}")),
        None => (false, "msiexec did not finish".into()),
    }
}

#[cfg_attr(not(windows), allow(dead_code))]
fn is_own_product(display_name: &str) -> bool {
    display_name
        .trim()
        .to_ascii_lowercase()
        .starts_with(OWN_PRODUCT)
}

/// Combined, size-limited output of a run for the audit event.
fn combined_output(run: &ScriptRun) -> String {
    let mut text = String::from_utf8_lossy(&run.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&run.stderr));
    truncate(&text)
}

fn truncate(s: &str) -> String {
    if s.len() <= MAX_OUTPUT {
        return s.to_string();
    }
    let mut end = MAX_OUTPUT;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}\n…(truncated)", &s[..end])
}

// ── Linux ───────────────────────────────────────────────────────────────────

/// Supported Linux package managers, in detection-preference order.
#[cfg(not(windows))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackageManager {
    Apt,
    Dnf,
    Yum,
    Zypper,
}

/// Directories a system binary is taken from. `PATH` is not consulted.
#[cfg(not(windows))]
const SYSTEM_DIRS: [&str; 4] = ["/usr/bin", "/usr/sbin", "/bin", "/sbin"];

#[cfg(not(windows))]
fn system_binary(name: &str) -> Option<PathBuf> {
    SYSTEM_DIRS
        .iter()
        .map(|dir| PathBuf::from(dir).join(name))
        .find(|path| path.is_file())
}

#[cfg(not(windows))]
fn strings(args: &[&str]) -> Vec<String> {
    args.iter().map(|arg| (*arg).to_string()).collect()
}

#[cfg(not(windows))]
impl PackageManager {
    /// Detect the host package manager and where its binary lives.
    fn detect() -> Option<(Self, PathBuf)> {
        [
            PackageManager::Apt,
            PackageManager::Dnf,
            PackageManager::Yum,
            PackageManager::Zypper,
        ]
        .into_iter()
        .find_map(|mgr| system_binary(mgr.binary()).map(|path| (mgr, path)))
    }

    fn binary(self) -> &'static str {
        match self {
            PackageManager::Apt => "apt-get",
            PackageManager::Dnf => "dnf",
            PackageManager::Yum => "yum",
            PackageManager::Zypper => "zypper",
        }
    }

    /// apt aborts with `--no-remove` when an install would remove a
    /// conflicting package. dnf and yum need `--allowerasing` for that.
    fn install_args(self, pkg: &str) -> Vec<String> {
        match self {
            PackageManager::Apt => strings(&["install", "-y", "--no-remove", pkg]),
            PackageManager::Dnf | PackageManager::Yum => strings(&["install", "-y", pkg]),
            PackageManager::Zypper => strings(&["--non-interactive", "install", pkg]),
        }
    }

    /// dnf and yum would otherwise also remove dependencies nothing else needs.
    fn remove_args(self, pkg: &str) -> Vec<String> {
        match self {
            PackageManager::Apt => strings(&["remove", "-y", pkg]),
            PackageManager::Dnf | PackageManager::Yum => strings(&[
                "remove",
                "-y",
                "--setopt=clean_requirements_on_remove=False",
                pkg,
            ]),
            PackageManager::Zypper => strings(&["--non-interactive", "remove", pkg]),
        }
    }

    /// Upgrade a single package (apt has no per-package upgrade verb, so we use
    /// `install --only-upgrade`).
    fn upgrade_one_args(self, pkg: &str) -> Vec<String> {
        match self {
            PackageManager::Apt => {
                strings(&["install", "--only-upgrade", "-y", "--no-remove", pkg])
            }
            PackageManager::Dnf | PackageManager::Yum => strings(&["upgrade", "-y", pkg]),
            PackageManager::Zypper => strings(&["--non-interactive", "update", pkg]),
        }
    }

    fn upgrade_all_args(self) -> Vec<String> {
        match self {
            PackageManager::Apt => strings(&["upgrade", "-y"]),
            PackageManager::Dnf | PackageManager::Yum => strings(&["upgrade", "-y"]),
            PackageManager::Zypper => strings(&["--non-interactive", "update"]),
        }
    }

    /// `apt-get update` / `zypper refresh` — refresh metadata before installs
    /// so a fresh box can resolve packages.  Best-effort; failure is non-fatal.
    fn refresh_args(self) -> Option<Vec<String>> {
        match self {
            PackageManager::Apt => Some(strings(&["update"])),
            PackageManager::Dnf | PackageManager::Yum => None, // resolves on demand
            PackageManager::Zypper => Some(strings(&["--non-interactive", "refresh"])),
        }
    }

    /// Confirm that removing `pkg` removes that package and nothing else.
    /// Anything that cannot be confirmed is refused.
    async fn check_removal(self, program: &std::path::Path, pkg: &str) -> Result<(), String> {
        match self {
            PackageManager::Apt => {
                let simulation =
                    run(program, &strings(&["-s", "remove", pkg]), CHECK_TIMEOUT).await;
                if !simulation.success {
                    return Err(format!(
                        "refused: the removal could not be simulated{}",
                        failure_detail(&simulation)
                    ));
                }
                if simulation.stdout_total > simulation.stdout.len() {
                    return Err(
                        "refused: the removal would affect too many packages to verify".into(),
                    );
                }
                removal_verdict(
                    pkg,
                    &apt_removals(&String::from_utf8_lossy(&simulation.stdout)),
                )
            }
            PackageManager::Dnf | PackageManager::Yum | PackageManager::Zypper => {
                let Some(rpm) = system_binary("rpm") else {
                    return Err("refused: rpm was not found to verify the removal".into());
                };
                // Fails when the package is absent or anything depends on it.
                let test = run(&rpm, &strings(&["-e", "--test", pkg]), CHECK_TIMEOUT).await;
                if test.success {
                    Ok(())
                } else {
                    Err(format!(
                        "refused: {pkg} cannot be removed on its own{}",
                        failure_detail(&test)
                    ))
                }
            }
        }
    }
}

/// Run a system binary non-interactively with a deadline. `LC_ALL=C` keeps
/// the output this module parses in one language.
#[cfg(not(windows))]
async fn run(program: &std::path::Path, args: &[String], timeout: Duration) -> ScriptRun {
    let mut cmd = tokio::process::Command::new(program);
    cmd.args(args)
        .env("LC_ALL", "C")
        .env("DEBIAN_FRONTEND", "noninteractive")
        .env("APT_LISTCHANGES_FRONTEND", "none");
    run_bounded(cmd, timeout, CAPTURE).await
}

/// A short reason for a failed helper run, for a refusal summary.
#[cfg(not(windows))]
fn failure_detail(run: &ScriptRun) -> String {
    if !run.note.is_empty() {
        return format!(": {}", run.note);
    }
    let text = String::from_utf8_lossy(&run.stderr);
    match text.lines().find(|line| !line.trim().is_empty()) {
        Some(line) => format!(": {}", line.trim().chars().take(200).collect::<String>()),
        None => String::new(),
    }
}

#[cfg(not(windows))]
async fn execute_unix(op: Operation<'_>) -> OpResult {
    if let Some(pkg) = op.package() {
        if !is_valid_package_name(pkg) {
            return OpResult::refused(format!("rejected invalid package name: {pkg:?}"));
        }
        if is_own_package(pkg) {
            return OpResult::refused(
                "refused: the TRAPD agent package cannot be changed by a package command",
            );
        }
    }

    let Some((mgr, program)) = PackageManager::detect() else {
        return OpResult::refused("no supported package manager found (apt/dnf/yum/zypper)");
    };

    if let Operation::Remove(pkg) = &op {
        if let Err(reason) = mgr.check_removal(&program, pkg).await {
            return OpResult::refused(reason);
        }
    }

    // Refresh metadata before an install (best-effort, ignore failure).
    if matches!(op, Operation::Install(_)) {
        if let Some(args) = mgr.refresh_args() {
            let _ = run(&program, &args, CHECK_TIMEOUT).await;
        }
    }

    let (args, timeout) = match &op {
        Operation::Install(p) => (mgr.install_args(p), PACKAGE_TIMEOUT),
        Operation::Remove(p) => (mgr.remove_args(p), PACKAGE_TIMEOUT),
        Operation::Upgrade(p) => (mgr.upgrade_one_args(p), PACKAGE_TIMEOUT),
        Operation::UpgradeAll => (mgr.upgrade_all_args(), UPGRADE_ALL_TIMEOUT),
    };

    let result = run(&program, &args, timeout).await;
    let summary = if result.success {
        format!("{} {} succeeded", mgr.binary(), op.verb())
    } else if !result.note.is_empty() {
        format!("{} {} failed: {}", mgr.binary(), op.verb(), result.note)
    } else {
        match result.code {
            Some(code) => format!("{} {} exited with code {code}", mgr.binary(), op.verb()),
            None => format!("{} {} was terminated", mgr.binary(), op.verb()),
        }
    };
    OpResult {
        success: result.success,
        summary,
        output: combined_output(&result),
    }
}

// ── Windows ─────────────────────────────────────────────────────────────────

/// Display name of a machine-wide Windows Installer product, if `code` is one.
/// Per-user products and entries of other installers are not found here, so
/// they cannot be targeted.
#[cfg(windows)]
fn installed_msi_product(code: &str) -> Option<String> {
    use crate::collectors::windows::registry;
    use windows_sys::Win32::System::Registry::{
        KEY_WOW64_32KEY, KEY_WOW64_64KEY, RRF_SUBKEY_WOW6432KEY, RRF_SUBKEY_WOW6464KEY,
    };
    const UNINSTALL: &str = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall";
    for (key_view, value_view) in [
        (KEY_WOW64_64KEY, RRF_SUBKEY_WOW6464KEY),
        (KEY_WOW64_32KEY, RRF_SUBKEY_WOW6432KEY),
    ] {
        for key in registry::subkeys(UNINSTALL, key_view) {
            if msi_product_code(&key).as_deref() != Some(code) {
                continue;
            }
            let path = format!("{UNINSTALL}\\{key}");
            if registry::dword(&path, "WindowsInstaller", value_view) == Some(1) {
                return Some(
                    registry::string(&path, "DisplayName", value_view).unwrap_or_default(),
                );
            }
        }
    }
    None
}

#[cfg(windows)]
async fn execute_windows(op: Operation<'_>) -> OpResult {
    let Operation::Remove(name) = op else {
        return OpResult::refused(format!(
            "{} of {} is not supported on Windows; only MSI products can be removed",
            op.verb(),
            op.package().map_or("all packages", |_| "a package"),
        ));
    };
    let Some(code) = msi_product_code(name) else {
        return OpResult::refused("on Windows the package name must be an MSI product code");
    };
    let Some(product) = installed_msi_product(&code) else {
        return OpResult::refused(
            "no machine-wide MSI product with this product code is installed",
        );
    };
    if is_own_product(&product) {
        return OpResult::refused(
            "refused: the TRAPD agent cannot be uninstalled by a package command",
        );
    }

    // Absolute path, so `PATH` cannot redirect a SYSTEM-level run.
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string());
    let mut cmd =
        tokio::process::Command::new(PathBuf::from(root).join("System32").join("msiexec.exe"));
    // Silent, and never restarts the host on its own.
    cmd.args(["/x", &format!("{{{code}}}"), "/qn", "/norestart"]);
    let result = run_bounded(cmd, PACKAGE_TIMEOUT, CAPTURE).await;

    let label: String = product.chars().take(200).collect();
    let (success, outcome) = if result.note.is_empty() {
        msi_outcome(result.code)
    } else {
        (false, result.note.clone())
    };
    OpResult {
        success,
        summary: format!("msiexec uninstall of {label:?}: {outcome}"),
        output: combined_output(&result),
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
            "8E3F1B5C-0A1D-4C7E-9B2F-1234567890AB",
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
            "{8E3F1B5C-0A1D-4C7E-9B2F-1234567890AB}",
        ] {
            assert!(!is_valid_package_name(n), "{n:?} should be rejected");
        }
    }

    #[test]
    fn operation_metadata() {
        assert_eq!(Operation::Install("x").verb(), "install");
        assert_eq!(Operation::Upgrade("x").verb(), "upgrade");
        assert_eq!(Operation::UpgradeAll.verb(), "upgrade-all");
        assert_eq!(Operation::Remove("x").package(), Some("x"));
        assert_eq!(Operation::UpgradeAll.package(), None);
    }

    #[test]
    fn the_agent_package_is_recognised_in_every_spelling() {
        for spec in [
            "trapd-agent",
            "TRAPD-Agent",
            "trapd-agent=0.7.4",
            "trapd-agent:amd64",
            "trapd-agent-0.7.4-1.x86_64",
        ] {
            assert!(is_own_package(spec), "{spec} names the agent");
        }
        for spec in ["trapd", "trapd-agentx", "nginx", "libtrapd-agent"] {
            assert!(!is_own_package(spec), "{spec} is another package");
        }
    }

    #[cfg(not(windows))]
    #[tokio::test]
    async fn a_command_naming_the_agent_package_is_refused_before_anything_runs() {
        for op in [
            Operation::Remove("trapd-agent"),
            Operation::Install("trapd-agent=0.1.0"),
            Operation::Upgrade("trapd-agent"),
        ] {
            let result = execute(op).await;
            assert!(!result.success);
            assert!(result.summary.starts_with("refused"), "{}", result.summary);
        }
    }

    #[cfg(not(windows))]
    #[tokio::test]
    async fn an_invalid_name_is_refused_before_anything_runs() {
        let result = execute(Operation::Remove("--purge")).await;
        assert!(!result.success);
        assert!(result.summary.contains("invalid package name"));
    }

    const APT_SINGLE: &str = "Reading package lists...\nBuilding dependency tree...\n\
        The following packages will be REMOVED:\n  nginx\n\
        0 upgraded, 0 newly installed, 1 to remove and 3 not upgraded.\n\
        Remv nginx [1.24.0-2ubuntu7]\n";

    const APT_CASCADE: &str = "The following packages will be REMOVED:\n  python3 ubuntu-minimal\n\
        Remv ubuntu-minimal [1.539]\nRemv python3-apt:amd64 [2.7.7]\nRemv python3 [3.12.3-0ubuntu2]\n";

    #[test]
    fn apt_simulation_lists_every_removed_package() {
        assert_eq!(apt_removals(APT_SINGLE), vec!["nginx"]);
        assert_eq!(
            apt_removals(APT_CASCADE),
            vec!["ubuntu-minimal", "python3-apt", "python3"]
        );
        assert_eq!(apt_removals("Purg nginx [1.24]\n"), vec!["nginx"]);
    }

    #[test]
    fn a_removal_of_only_the_named_package_is_allowed() {
        assert!(removal_verdict("nginx", &apt_removals(APT_SINGLE)).is_ok());
        assert!(removal_verdict("nginx=1.24.0-2ubuntu7", &apt_removals(APT_SINGLE)).is_ok());
        assert!(removal_verdict("nginx:amd64", &apt_removals(APT_SINGLE)).is_ok());
    }

    #[test]
    fn a_removal_that_takes_other_packages_along_is_refused() {
        let reason = removal_verdict("python3", &apt_removals(APT_CASCADE)).unwrap_err();
        assert!(reason.contains("2 other package(s)"), "{reason}");
        assert!(reason.contains("python3-apt") && reason.contains("ubuntu-minimal"));
    }

    #[test]
    fn a_removal_of_an_absent_package_is_refused() {
        let reason = removal_verdict("nginx", &[]).unwrap_err();
        assert!(reason.contains("not installed"));
        // Removing something else instead of the named package is not a match.
        assert!(removal_verdict("nginx", &["apache2".to_string()]).is_err());
    }

    #[cfg(not(windows))]
    #[test]
    fn package_arguments_stay_separate_and_guard_against_collateral_removal() {
        let install = PackageManager::Apt.install_args("nginx");
        assert_eq!(install, vec!["install", "-y", "--no-remove", "nginx"]);
        let upgrade = PackageManager::Apt.upgrade_one_args("nginx");
        assert_eq!(
            upgrade,
            vec!["install", "--only-upgrade", "-y", "--no-remove", "nginx"]
        );
        let remove = PackageManager::Dnf.remove_args("nginx");
        assert!(remove.contains(&"--setopt=clean_requirements_on_remove=False".to_string()));
        assert_eq!(remove.last().map(String::as_str), Some("nginx"));
    }

    #[cfg(not(windows))]
    #[test]
    fn binaries_come_from_the_system_directories_only() {
        let shell = system_binary("sh").expect("a system shell");
        assert!(SYSTEM_DIRS.iter().any(|dir| shell.starts_with(dir)));
        assert!(system_binary("trapd-no-such-binary").is_none());
    }

    #[test]
    fn msi_product_codes_are_canonicalised() {
        let code = "8E3F1B5C-0A1D-4C7E-9B2F-1234567890AB";
        assert_eq!(msi_product_code(code).as_deref(), Some(code));
        assert_eq!(
            msi_product_code("{8e3f1b5c-0a1d-4c7e-9b2f-1234567890ab}").as_deref(),
            Some(code)
        );
    }

    #[test]
    fn anything_but_a_product_code_is_rejected() {
        for value in [
            "",
            "Google Chrome",
            "{8E3F1B5C-0A1D-4C7E-9B2F-1234567890AB",
            "8E3F1B5C-0A1D-4C7E-9B2F-1234567890AB}",
            "8E3F1B5C-0A1D-4C7E-9B2F-1234567890AB_is1",
            "8E3F1B5C00A1D-4C7E-9B2F-1234567890AB",
            "8E3F1B5C-0A1D-4C7E-9B2F-1234567890AG",
            "8E3F1B5C-0A1D-4C7E-9B2F-1234567890AB /i evil.msi",
            "ÄE3F1B5C-0A1D-4C7E-9B2F-1234567890A",
        ] {
            assert_eq!(msi_product_code(value), None, "{value:?}");
        }
    }

    #[test]
    fn msiexec_exit_codes_are_reported_truthfully() {
        assert!(msi_outcome(Some(0)).0);
        let (success, text) = msi_outcome(Some(3010));
        assert!(success && text.contains("restart"));
        assert!(!msi_outcome(Some(1605)).0);
        assert!(!msi_outcome(Some(1618)).0);
        assert!(!msi_outcome(Some(1603)).0);
        assert!(!msi_outcome(None).0);
    }

    #[test]
    fn the_agent_product_is_recognised() {
        assert!(is_own_product("TRAPD Agent"));
        assert!(is_own_product(" trapd agent 0.7.4"));
        assert!(!is_own_product("Mozilla Firefox"));
        assert!(!is_own_product(""));
    }

    #[test]
    fn long_output_is_cut_on_a_character_boundary() {
        let text = "ä".repeat(MAX_OUTPUT);
        let cut = truncate(&text);
        assert!(cut.ends_with("…(truncated)"));
        assert!(cut.len() <= MAX_OUTPUT + 20);
        assert_eq!(truncate("short"), "short");
    }
}
