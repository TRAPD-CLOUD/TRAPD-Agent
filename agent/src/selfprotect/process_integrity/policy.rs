//! Allowlist logic for loaded modules (portable, unit-tested).

/// Lower-case, `/`-to-`\`, without the `\\?\` / `\??\` NT prefixes.
pub fn normalize_path(path: &str) -> String {
    let p = path.to_ascii_lowercase().replace('/', "\\");
    for prefix in [r"\\?\", r"\??\"] {
        if let Some(rest) = p.strip_prefix(prefix) {
            return rest.to_string();
        }
    }
    p
}

pub struct ModuleContext<'a> {
    /// e.g. `c:\windows` (lower case, no trailing backslash).
    pub system_root: &'a str,
    /// Directory of the agent executable (lower case, no trailing backslash).
    pub own_dir: &'a str,
    /// Operator allowlist: lower-case path prefixes.
    pub allow: &'a [String],
}

/// A module is expected when it comes from the Windows system directories, the
/// agent's own installation directory or an operator allowlisted prefix. This
/// is a *location* rule (cheap, runs every scan); a file planted in System32
/// needs administrator rights and is outside what this check claims to catch.
pub fn is_expected_module(path: &str, ctx: &ModuleContext<'_>) -> bool {
    let p = normalize_path(path);
    let under = |dir: &str| !dir.is_empty() && p.starts_with(&format!("{dir}\\"));
    let sys = ctx.system_root;
    under(&format!("{sys}\\system32"))
        || under(&format!("{sys}\\syswow64"))
        || under(&format!("{sys}\\winsxs"))
        || under(ctx.own_dir)
        || ctx.allow.iter().any(|a| p.starts_with(a.as_str()))
}

/// Whether the path is in a directory ordinary users (and malware running as
/// them) can write, which raises the severity of an unexpected module.
pub fn is_user_writable_location(path: &str) -> bool {
    let p = normalize_path(path);
    [
        "\\users\\",
        "\\temp\\",
        "\\programdata\\",
        "\\appdata\\",
        "\\downloads\\",
        "\\public\\",
    ]
    .iter()
    .any(|d| p.contains(d))
}

/// Whether `addr` falls inside any `(base, size)` range.
pub fn in_ranges(addr: u64, ranges: &[(u64, u64)]) -> bool {
    ranges
        .iter()
        .any(|&(base, size)| addr >= base && addr - base < size)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx<'a>(allow: &'a [String]) -> ModuleContext<'a> {
        ModuleContext {
            system_root: r"c:\windows",
            own_dir: r"c:\program files\trapd agent",
            allow,
        }
    }

    #[test]
    fn system_and_install_directories_are_expected() {
        let c = ctx(&[]);
        assert!(is_expected_module(r"C:\Windows\System32\ntdll.dll", &c));
        assert!(is_expected_module(
            r"\\?\C:\Windows\System32\kernelbase.dll",
            &c
        ));
        assert!(is_expected_module(
            r"C:\Windows\WinSxS\amd64_microsoft.windows.common-controls\comctl32.dll",
            &c
        ));
        assert!(is_expected_module(
            r"C:\Program Files\TRAPD Agent\trapd-agent.exe",
            &c
        ));
    }

    #[test]
    fn everything_else_is_unexpected_and_prefixes_cannot_be_spoofed() {
        let c = ctx(&[]);
        assert!(!is_expected_module(
            r"C:\Users\x\AppData\Local\Temp\a.dll",
            &c
        ));
        assert!(!is_expected_module(r"C:\Windows\Temp\a.dll", &c));
        assert!(!is_expected_module(r"C:\Windows\System32x\a.dll", &c));
        assert!(!is_expected_module(
            r"C:\Program Files\TRAPD Agent2\a.dll",
            &c
        ));
        assert!(!is_expected_module(r"D:\Windows\System32\a.dll", &c));
    }

    #[test]
    fn the_allowlist_extends_the_expected_set() {
        let allow = vec![r"c:\vendor\av\".to_string()];
        assert!(is_expected_module(r"C:\Vendor\AV\hook.dll", &ctx(&allow)));
        assert!(!is_expected_module(
            r"C:\Vendor\Other\hook.dll",
            &ctx(&allow)
        ));
    }

    #[test]
    fn user_writable_locations_and_ranges() {
        assert!(is_user_writable_location(r"C:\Users\a\x.dll"));
        assert!(is_user_writable_location(r"C:\Windows\Temp\x.dll"));
        assert!(!is_user_writable_location(r"C:\Windows\System32\x.dll"));
        let r = [(0x1000u64, 0x100u64), (0x5000, 0x10)];
        assert!(in_ranges(0x1000, &r) && in_ranges(0x10ff, &r) && in_ranges(0x500f, &r));
        assert!(!in_ranges(0x1100, &r) && !in_ranges(0xfff, &r) && !in_ranges(0x5010, &r));
        assert!(!in_ranges(1, &[]));
    }
}
