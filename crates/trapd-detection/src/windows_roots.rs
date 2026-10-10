//! Admin-only Windows install roots of this host.
//!
//! Derived from `%SystemRoot%` and the Program Files known folders instead of
//! assuming `C:`, so hosts with Windows or applications on another drive are
//! classified like `C:` installs. Pure string logic; the host environment is
//! read only by [`install_roots`].

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

#[cfg(test)]
mod tests {
    use super::*;

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
            assert!(
                under_install_roots(
                    &p.replace('\\', "/").to_ascii_lowercase(),
                    &roots,
                    &["system32/", "syswow64/", "systemapps/", "explorer.exe"],
                    true,
                ),
                "{p}"
            );
        }
        for p in [
            "C:\\Windows\\System32\\x.exe",
            "C:\\Program Files\\x.exe",
            "E:\\Program Files Evil\\x.exe",
            "E:\\Windows\\System32\\x.exe",
        ] {
            assert!(
                !under_install_roots(
                    &p.replace('\\', "/").to_ascii_lowercase(),
                    &roots,
                    &["system32/", "syswow64/", "systemapps/", "explorer.exe"],
                    true,
                ),
                "{p}"
            );
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
}
