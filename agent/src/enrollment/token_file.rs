//! Reading a one-time enrollment token from a file the MSI hands to the agent.
//!
//! `install.ps1 -EnrollTokenFile` passes only the *path* to `msiexec`
//! (`ENROLLTOKENFILE`, never the token, so no command line, MSI log or process
//! telemetry carries it). A deferred SYSTEM custom action runs
//! `trapd-agent enroll-token-import <path>`, which reads the file here and
//! stages the token in the protected `HKLM\SOFTWARE\TRAPD\Agent` key.
#![cfg_attr(not(windows), allow(dead_code))]

use std::path::Path;

use anyhow::{bail, Context, Result};

use crate::paths;

/// Enrollment tokens are short; anything larger is not one.
const MAX_TOKEN_FILE_BYTES: u64 = 512;

/// Read the token: bounded regular file (no links, reparse points or devices),
/// first line only, printable ASCII without whitespace or quotes.
pub(crate) fn read(path: &Path) -> Result<String> {
    use std::io::Read;
    let file = paths::open_bounded_regular(path, MAX_TOKEN_FILE_BYTES)
        .with_context(|| format!("cannot read enrollment token file {}", path.display()))?;
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::MetadataExt;
        let meta = file.metadata()?;
        anyhow::ensure!(
            meta.uid() == nix::unistd::Uid::effective().as_raw()
                && meta.mode() & 0o077 == 0
                && meta.nlink() == 1,
            "enrollment token file needs private ownership and permissions"
        );
    }
    let mut bytes = Vec::new();
    file.take(MAX_TOKEN_FILE_BYTES + 1)
        .read_to_end(&mut bytes)?;
    anyhow::ensure!(
        bytes.len() <= MAX_TOKEN_FILE_BYTES as usize,
        "oversized enrollment token"
    );
    parse(&bytes)
}

pub(super) fn parse(bytes: &[u8]) -> Result<String> {
    let text = std::str::from_utf8(bytes).context("enrollment token file is not text")?;
    let token = text.lines().next().unwrap_or("").trim();
    if token.is_empty() || !token.bytes().all(|b| b.is_ascii_graphic() && b != b'"') {
        bail!("enrollment token file does not start with a single token");
    }
    Ok(token.to_owned())
}

#[cfg(test)]
mod tests {
    /// A deferred EXE custom action has its `ExeCommand` formatted when it is
    /// scheduled; `[CustomActionData]` is empty there, so the install would run
    /// `enroll-token-import ""` and roll back (seen in CI). Pin the working form.
    #[test]
    fn msi_exe_actions_never_format_custom_action_data() {
        let wxs = include_str!("../../../deploy/windows/Package.wxs");
        let mut checked = 0;
        for line in wxs.lines().filter(|l| l.contains("<CustomAction ")) {
            if line.contains("FileRef=") {
                checked += 1;
                assert!(
                    !line.contains("CustomActionData"),
                    "EXE custom action formats CustomActionData: {line}"
                );
            }
        }
        assert!(checked >= 5, "expected the EXE custom actions to be found");
        assert!(wxs.contains("ExeCommand=\"enroll-token-import &quot;[ENROLLTOKENFILE]&quot;\""));
        assert!(!wxs.contains("SetImportEnrollTokenData"));
        // Each property goes straight into ExeCommand (extra flags may follow).
        let gate = wxs
            .lines()
            .find(|l| l.contains("Id=\"RequireUninstallToken\""))
            .expect("RequireUninstallToken action present");
        assert!(gate.contains(
            "ExeCommand=\"uninstall-gate --token-file &quot;[MAINTENANCE_TOKEN_FILE]&quot;"
        ));
        assert!(gate.contains("&quot;[UPGRADINGPRODUCTCODE]&quot;"));
        assert!(!gate.contains("CustomActionData"));
        assert!(!wxs.contains("SetRequireUninstallTokenData"));
    }

    use super::*;
    use std::path::PathBuf;

    struct TempDir(PathBuf);
    impl TempDir {
        fn new() -> Self {
            let p = std::env::temp_dir().join(format!("trapd-tokfile-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir_all(&p).unwrap();
            Self(p)
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn takes_first_line_and_trims() {
        assert_eq!(parse(b"abc123\r\nignored\n").unwrap(), "abc123");
        assert_eq!(parse(b"  abc123  ").unwrap(), "abc123");
    }

    #[test]
    fn rejects_empty_whitespace_quotes_and_non_ascii() {
        for bad in [
            &b""[..],
            b"\n",
            b"a b",
            b"a\"b",
            "t\u{f6}ken".as_bytes(),
            b"\xff\xfe",
        ] {
            assert!(parse(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn refuses_oversized_missing_and_directory_paths() {
        let dir = TempDir::new();
        let big = dir.0.join("big");
        std::fs::write(&big, vec![b'a'; 600]).unwrap();
        assert!(read(&big).is_err());
        assert!(read(&dir.0.join("missing")).is_err());
        assert!(read(&dir.0).is_err());
        let ok = dir.0.join("ok");
        std::fs::write(&ok, "tok-1\n").unwrap();
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&ok, std::fs::Permissions::from_mode(0o644)).unwrap();
            assert!(read(&ok).is_err());
            std::fs::set_permissions(&ok, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert_eq!(read(&ok).unwrap(), "tok-1");
    }

    #[cfg(unix)]
    #[test]
    fn refuses_symlinks() {
        let dir = TempDir::new();
        let target = dir.0.join("t");
        std::fs::write(&target, "tok").unwrap();
        let link = dir.0.join("l");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(read(&link).is_err());
    }
}
