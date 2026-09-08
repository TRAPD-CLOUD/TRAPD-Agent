//! Auto-discovery of well-known Linux security log sources.
//!
//! A candidate is only armed when the path currently exists (or the glob
//! matches at least one file). Rechecked periodically so installing nginx
//! after the agent starts still lights the source up. Custom config sources
//! of the same `name` always win.

use std::path::Path;

use crate::config::{LogSourceConfig, MultilineConfig};

struct Preset {
    name: &'static str,
    paths: &'static [&'static str],
    parser: &'static str,
    multiline: Option<&'static str>,
}

const PRESETS: &[Preset] = &[
    Preset {
        name: "nginx_access",
        paths: &["/var/log/nginx/access.log"],
        parser: "nginx_access",
        multiline: None,
    },
    Preset {
        name: "nginx_error",
        paths: &["/var/log/nginx/error.log"],
        parser: "nginx_error",
        multiline: None,
    },
    Preset {
        name: "apache_access",
        paths: &[
            "/var/log/apache2/access.log",
            "/var/log/httpd/access_log",
            "/var/log/httpd/access.log",
        ],
        parser: "apache_access",
        multiline: None,
    },
    Preset {
        name: "apache_error",
        paths: &[
            "/var/log/apache2/error.log",
            "/var/log/httpd/error_log",
            "/var/log/httpd/error.log",
        ],
        parser: "apache_error",
        multiline: None,
    },
    Preset {
        name: "postgresql",
        paths: &["/var/log/postgresql/*.log"],
        parser: "postgresql",
        multiline: Some(r"^\d{4}-\d{2}-\d{2}"),
    },
    Preset {
        name: "mysql",
        paths: &[
            "/var/log/mysql/error.log",
            "/var/log/mysqld.log",
            "/var/log/mysql/*.err",
        ],
        parser: "mysql",
        multiline: None,
    },
    Preset {
        name: "auditd",
        paths: &["/var/log/audit/audit.log"],
        parser: "auditd",
        multiline: None,
    },
];

/// Merge operator-configured sources with auto-discovered presets.
/// Configured names override presets. Empty-path / missing files are skipped
/// for presets; configured sources are always kept (the reader retries).
pub fn resolve_sources(
    configured: &[LogSourceConfig],
    auto_discover: bool,
) -> Vec<LogSourceConfig> {
    let mut out = configured.to_vec();
    if !auto_discover {
        return out;
    }
    let named: std::collections::HashSet<String> = out.iter().map(|s| s.name.clone()).collect();
    for preset in PRESETS {
        if named.contains(preset.name) {
            continue;
        }
        if let Some(src) = materialise(preset) {
            out.push(src);
        }
    }
    out
}

fn materialise(preset: &Preset) -> Option<LogSourceConfig> {
    let path = preset
        .paths
        .iter()
        .find(|p| path_or_glob_exists(p))
        .copied()?;
    Some(LogSourceConfig {
        name: preset.name.to_string(),
        source_type: "file".into(),
        path: path.to_string(),
        parser: preset.parser.to_string(),
        unit: String::new(),
        identifier: String::new(),
        multiline: preset.multiline.map(|pat| MultilineConfig {
            pattern: pat.to_string(),
            negate: false,
            timeout_ms: 1_000,
        }),
        start_at: String::new(),
        exclude: vec![],
        rate_limit: None,
    })
}

fn path_or_glob_exists(pattern: &str) -> bool {
    if !is_glob(pattern) {
        return Path::new(pattern).is_file();
    }
    !expand_glob(pattern).is_empty()
}

pub fn is_glob(pattern: &str) -> bool {
    pattern.contains('*') || pattern.contains('?') || pattern.contains('[')
}

/// Expand a glob (including a single literal path) into existing files.
/// `*.gz` / `*.xz` compressed rotations are skipped — we follow the live
/// inode, not the packed history.
pub fn expand_glob(pattern: &str) -> Vec<std::path::PathBuf> {
    if !is_glob(pattern) {
        let p = std::path::PathBuf::from(pattern);
        return if p.is_file() { vec![p] } else { Vec::new() };
    }
    let Ok(glob) = globset::Glob::new(pattern) else {
        return Vec::new();
    };
    let matcher = glob.compile_matcher();
    let root = glob_root(pattern);
    let mut out = Vec::new();
    let walker = walkdir::WalkDir::new(&root)
        .follow_links(false)
        .max_depth(glob_depth(pattern));
    for entry in walker.into_iter().filter_map(|e| e.ok()) {
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        if let Some(name) = path.file_name().and_then(|s| s.to_str()) {
            if name.ends_with(".gz")
                || name.ends_with(".xz")
                || name.ends_with(".bz2")
                || name.ends_with(".zst")
            {
                continue;
            }
        }
        if matcher.is_match(path) {
            out.push(path.to_path_buf());
        }
    }
    out.sort();
    out
}

fn glob_root(pattern: &str) -> std::path::PathBuf {
    let mut root = std::path::PathBuf::new();
    for comp in Path::new(pattern).components() {
        let s = comp.as_os_str().to_string_lossy();
        if s.contains('*') || s.contains('?') || s.contains('[') {
            break;
        }
        root.push(comp);
    }
    if root.as_os_str().is_empty() {
        std::path::PathBuf::from(".")
    } else {
        root
    }
}

fn glob_depth(pattern: &str) -> usize {
    if pattern.contains("**") {
        8
    } else {
        Path::new(pattern).components().count().saturating_add(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn scratch(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "trapd_log_disc_{}_{}_{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            tag
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn expand_literal_and_star() {
        let dir = scratch("glob");
        fs::write(dir.join("a.log"), b"x").unwrap();
        fs::write(dir.join("b.log"), b"x").unwrap();
        fs::write(dir.join("a.log.gz"), b"x").unwrap();
        let pat = dir.join("*.log").to_string_lossy().into_owned();
        let files = expand_glob(&pat);
        assert_eq!(files.len(), 2, "compressed rotation must be skipped");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn configured_name_wins_over_preset() {
        let configured = vec![LogSourceConfig {
            name: "nginx_access".into(),
            source_type: "file".into(),
            path: "/custom/access.log".into(),
            parser: "nginx_access".into(),
            unit: String::new(),
            identifier: String::new(),
            multiline: None,
            start_at: String::new(),
            exclude: vec![],
            rate_limit: None,
        }];
        let resolved = resolve_sources(&configured, true);
        let nginx: Vec<_> = resolved
            .iter()
            .filter(|s| s.name == "nginx_access")
            .collect();
        assert_eq!(nginx.len(), 1);
        assert_eq!(nginx[0].path, "/custom/access.log");
    }

    #[test]
    fn disabled_autodiscover_returns_configured_only() {
        let configured = vec![LogSourceConfig {
            name: "app".into(),
            source_type: "file".into(),
            path: "/var/log/myapp/*.log".into(),
            parser: "json".into(),
            unit: String::new(),
            identifier: String::new(),
            multiline: None,
            start_at: String::new(),
            exclude: vec![],
            rate_limit: None,
        }];
        let resolved = resolve_sources(&configured, false);
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].name, "app");
    }
}
