//! Built-in Linux security log catalogue.
//!
//! Only sources whose paths exist (or whose journal units can be requested)
//! are armed. A host without nginx simply does not grow an nginx tail — no
//! error, no empty-file spam. Operators override the whole set by supplying
//! an explicit `logs:` list.

use std::path::Path;

use crate::config::{LogSourceConfig, MultilineConfig};

/// Discover sources that look live on this host.
pub fn discover() -> Vec<LogSourceConfig> {
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
    !super::reader::expand_paths(pattern, &[]).is_empty()
}

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
}
