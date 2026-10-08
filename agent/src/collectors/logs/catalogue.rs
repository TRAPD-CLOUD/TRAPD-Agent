//! Built-in security log catalogue (Linux and Windows).
//!
//! Only sources whose paths exist (or whose journal units can be requested)
//! are armed. A host without nginx simply does not grow an nginx tail — no
//! error, no empty-file spam. Operators override the whole set by supplying
//! an explicit `logs:` list.
//!
//! The Linux catalogue covers the distro logs, auditd, web servers, databases
//! and the journal; the Windows catalogue covers IIS / http.sys and the web
//! servers and databases that run on Windows. Windows security telemetry itself
//! (the Security, System and Application event logs) has its own collector.

#[cfg(not(windows))]
use std::path::Path;

use crate::config::{LogSourceConfig, MultilineConfig};

/// Discover sources that look live on this host.
pub fn discover() -> Vec<LogSourceConfig> {
    #[cfg(windows)]
    {
        discover_windows()
    }
    #[cfg(not(windows))]
    {
        discover_unix()
    }
}

/// One built-in Windows source, before it is checked against the filesystem.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) struct WindowsCandidate {
    pub name: &'static str,
    pub path: String,
    pub parser: &'static str,
    pub postgres_multiline: bool,
}

/// The Windows sources worth tailing, as paths on this host. Pure so the
/// strings are tested everywhere; [`discover_windows`] keeps only those that
/// exist. Globs cover versioned install directories (`Apache24`,
/// `PostgreSQL\16`, `MySQL Server 8.0`) without hard-coding a version.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn windows_candidates(
    system_drive: &str,
    program_files: &str,
    program_data: &str,
) -> Vec<WindowsCandidate> {
    let c = |name, path: String, parser| WindowsCandidate {
        name,
        path,
        parser,
        postgres_multiline: false,
    };
    vec![
        // IIS: one directory per site, one file per day. Several sites share a
        // glob, so a new site is picked up without a restart.
        c(
            "iis",
            format!("{system_drive}\\inetpub\\logs\\LogFiles\\W3SVC*\\u_ex*.log"),
            "iis",
        ),
        // http.sys rejects malformed or abusive requests before IIS sees them.
        c(
            "iis_httperr",
            format!("{system_drive}\\Windows\\System32\\LogFiles\\HTTPERR\\httperr*.log"),
            "iis",
        ),
        c(
            "nginx_access",
            format!("{system_drive}\\nginx*\\logs\\access.log"),
            "nginx_access",
        ),
        c(
            "nginx_error",
            format!("{system_drive}\\nginx*\\logs\\error.log"),
            "nginx_error",
        ),
        c(
            "apache_access",
            format!("{system_drive}\\Apache*\\logs\\access.log"),
            "apache_access",
        ),
        c(
            "apache_error",
            format!("{system_drive}\\Apache*\\logs\\error.log"),
            "apache_error",
        ),
        c(
            "xampp_apache_access",
            format!("{system_drive}\\xampp\\apache\\logs\\access.log"),
            "apache_access",
        ),
        c(
            "xampp_apache_error",
            format!("{system_drive}\\xampp\\apache\\logs\\error.log"),
            "apache_error",
        ),
        WindowsCandidate {
            postgres_multiline: true,
            ..c(
                "postgresql",
                format!("{program_files}\\PostgreSQL\\*\\data\\log\\*.log"),
                "postgresql",
            )
        },
        c(
            "mysql",
            format!("{program_data}\\MySQL\\MySQL Server *\\Data\\*.err"),
            "mysql",
        ),
    ]
}

#[cfg(windows)]
fn discover_windows() -> Vec<LogSourceConfig> {
    let env = |key: &str, default: &str| std::env::var(key).unwrap_or_else(|_| default.to_string());
    windows_candidates(
        &env("SystemDrive", "C:"),
        &env("ProgramFiles", "C:\\Program Files"),
        &env("ProgramData", "C:\\ProgramData"),
    )
    .into_iter()
    .filter(|cand| glob_exists(&cand.path))
    .map(|cand| {
        let src = LogSourceConfig::file(cand.name, &cand.path, cand.parser);
        if cand.postgres_multiline {
            src.with_multiline(MultilineConfig::postgres())
        } else {
            src
        }
    })
    .collect()
}

#[cfg(not(windows))]
fn discover_unix() -> Vec<LogSourceConfig> {
    let mut out = Vec::new();

    // Authentication — files first (sshd/sudo land here on Debian/RHEL).
    // The dedicated AuthLogCollector still emits structured User events from
    // the same files; these records are class=log for SIEM / Sigma.
    push_first_file(
        &mut out,
        "auth",
        &["/var/log/auth.log", "/var/log/secure"],
        "syslog",
        None,
    );

    push_file(
        &mut out,
        "auditd",
        "/var/log/audit/audit.log",
        "auditd",
        None,
    );

    push_file(
        &mut out,
        "nginx_access",
        "/var/log/nginx/access.log",
        "nginx_access",
        None,
    );
    push_file(
        &mut out,
        "nginx_error",
        "/var/log/nginx/error.log",
        "nginx_error",
        None,
    );

    push_first_file(
        &mut out,
        "apache_access",
        &[
            "/var/log/apache2/access.log",
            "/var/log/httpd/access_log",
            "/var/log/httpd/access.log",
        ],
        "apache_access",
        None,
    );
    push_first_file(
        &mut out,
        "apache_error",
        &[
            "/var/log/apache2/error.log",
            "/var/log/httpd/error_log",
            "/var/log/httpd/error.log",
        ],
        "apache_error",
        None,
    );

    // Postgres writes timestamp-prefixed dumps that wrap SQL across lines.
    let pg_glob = "/var/log/postgresql/*.log";
    if glob_exists(pg_glob) {
        out.push(
            LogSourceConfig::file("postgresql", pg_glob, "postgresql")
                .with_multiline(MultilineConfig::postgres()),
        );
    }

    push_first_file(
        &mut out,
        "mysql",
        &[
            "/var/log/mysql/error.log",
            "/var/log/mysqld.log",
            "/var/log/mysql.log",
            "/var/log/mariadb/mariadb.log",
        ],
        "mysql",
        None,
    );

    // Journal units — armed whenever journalctl exists. Unit filters keep
    // the firehose off; operators who want everything add an explicit
    // `type: journal` source with empty `units`.
    if journalctl_present() {
        out.push(LogSourceConfig::journal(
            "journal_ssh",
            &["ssh.service", "sshd.service"],
            "sshd",
        ));
        out.push(LogSourceConfig::journal(
            "journal_sudo",
            &["sudo.service"],
            "sudo",
        ));
        out.push(LogSourceConfig::journal(
            "journal_docker",
            &["docker.service", "containerd.service"],
            "json",
        ));
        out.push(LogSourceConfig::journal(
            "journal_cron",
            &["cron.service", "crond.service"],
            "syslog",
        ));
    }

    out
}

#[cfg(not(windows))]
fn push_file(
    out: &mut Vec<LogSourceConfig>,
    name: &str,
    path: &str,
    parser: &str,
    ml: Option<MultilineConfig>,
) {
    if Path::new(path).is_file() {
        let mut src = LogSourceConfig::file(name, path, parser);
        if let Some(ml) = ml {
            src = src.with_multiline(ml);
        }
        out.push(src);
    }
}

#[cfg(not(windows))]
fn push_first_file(
    out: &mut Vec<LogSourceConfig>,
    name: &str,
    candidates: &[&str],
    parser: &str,
    ml: Option<MultilineConfig>,
) {
    for path in candidates {
        if Path::new(path).is_file() {
            let mut src = LogSourceConfig::file(name, path, parser);
            if let Some(ml) = ml {
                src = src.with_multiline(ml);
            }
            out.push(src);
            return;
        }
    }
}

fn glob_exists(pattern: &str) -> bool {
    super::reader::expand_paths(pattern, &[])
        .iter()
        .any(|p| p.is_file())
}

#[cfg(not(windows))]
fn journalctl_present() -> bool {
    std::process::Command::new("journalctl")
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Merge explicit config with (optional) builtins. Explicit names win when
/// they collide with a builtin of the same `name`.
pub fn resolve(cfg: &crate::config::AgentConfig) -> Vec<LogSourceConfig> {
    if !cfg.logs_enabled {
        return Vec::new();
    }
    let mut out = Vec::new();
    if cfg.logs.is_empty() || cfg.logs_include_builtins {
        out.extend(discover());
    }
    for src in &cfg.logs {
        out.retain(|s| s.name != src.name);
        out.push(src.clone());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AgentConfig;

    #[test]
    fn disabled_yields_nothing() {
        let cfg = AgentConfig {
            logs_enabled: false,
            ..Default::default()
        };
        assert!(resolve(&cfg).is_empty());
    }

    #[test]
    fn explicit_list_replaces_builtins_by_default() {
        let cfg = AgentConfig {
            logs: vec![LogSourceConfig::file("app", "/tmp/app.log", "json")],
            ..Default::default()
        };
        let got = resolve(&cfg);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].name, "app");
    }

    #[test]
    fn include_builtins_keeps_custom() {
        let cfg = AgentConfig {
            logs_include_builtins: true,
            logs: vec![LogSourceConfig::file("app", "/tmp/app.log", "json")],
            ..Default::default()
        };
        let got = resolve(&cfg);
        assert!(got.iter().any(|s| s.name == "app"));
    }

    #[test]
    fn windows_catalogue_paths_follow_the_host_layout_and_use_globs_for_versions() {
        let c = windows_candidates("D:", "D:\\Program Files", "D:\\ProgramData");
        let by = |name: &str| c.iter().find(|x| x.name == name).unwrap();
        assert_eq!(
            by("iis").path,
            "D:\\inetpub\\logs\\LogFiles\\W3SVC*\\u_ex*.log"
        );
        assert_eq!(by("iis").parser, "iis");
        assert_eq!(by("iis_httperr").parser, "iis");
        assert!(by("postgresql")
            .path
            .starts_with("D:\\Program Files\\PostgreSQL\\*"));
        assert!(by("postgresql").postgres_multiline);
        assert!(by("mysql")
            .path
            .starts_with("D:\\ProgramData\\MySQL\\MySQL Server *"));
        // Names are unique (an explicit source replaces a built-in by name).
        let names: std::collections::HashSet<_> = c.iter().map(|x| x.name).collect();
        assert_eq!(names.len(), c.len());
        // Every parser the catalogue names is one the parser module knows.
        for cand in &c {
            assert!(
                !super::super::parser::parse(cand.parser, "x")
                    .message
                    .is_empty(),
                "{}",
                cand.name
            );
        }
    }
}
