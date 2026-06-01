//! Deterministic host profiler — turns the existing inventory output into a
//! **recon profile**: the set of honeytoken *candidates* a real attacker would
//! expect to find on *this specific host*.
//!
//! The guiding rule, straight from the adversary playbook
//! (MITRE **T1552** Unsecured Credentials / **T1083** File & Directory
//! Discovery), is fidelity over volume:
//!
//! > Never propose a token where its genuine counterpart would not plausibly
//! > exist. No `~/.aws/credentials` on a host with no AWS footprint — that
//! > *is* the tell that gives the trap away. The observed context therefore
//! > drives the selection.
//!
//! So every candidate is gated on real evidence: an installed package, an
//! existing directory, a human user with a login shell. The module is pure
//! heuristics — it runs on-agent, touches only the local filesystem to confirm
//! plausibility, and never generates content (that is the backend's LLM job)
//! or places anything (that happens later, on a signed `deploy_honeytoken`).
//!
//! Output: a [`ReconProfile`] embedded in the inventory snapshot. The
//! `score` on each candidate is the *starting* deterministic ranking
//! (context strength × attacker attractiveness); the backend may re-rank, and
//! step 2 will replace it with a trained model once hit/miss telemetry exists.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::inventory::{SoftwareInventory, UserAccount};

/// Schema version of the recon profile, independent of the inventory schema so
/// the candidate contract can evolve on its own.
pub const RECON_PROFILE_SCHEMA: u32 = 1;

/// The condensed recon view derived from inventory, sent to the backend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconProfile {
    pub schema_version: u32,
    /// Token candidates, sorted by descending [`TokenCandidate::score`].
    pub candidates: Vec<TokenCandidate>,
}

/// One plausible honeytoken placement derived from observed host context.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenCandidate {
    /// Stable family discriminator: `ssh_private_key`, `aws_credentials`,
    /// `pgpass`, `my_cnf`, `docker_config`, `kube_config`, `webroot_env`,
    /// `root_backup_keys`, `passwords_kdbx`, `shell_history`.
    pub kind: String,
    /// Absolute path where the genuine artefact would live — i.e. where the
    /// attacker will look, and therefore where the token must go.
    pub path: String,
    /// MITRE ATT&CK technique this placement emulates.
    pub mitre_technique: String,
    /// Which observed evidence justified the candidate (human-readable).
    pub rationale: String,
    /// Concrete context tags that fired the candidate (package names, dirs, …).
    pub context: Vec<String>,
    /// Deterministic placement score, 0–100 (context strength × attractiveness).
    pub score: u8,
    /// Suggested file mode for the deployed token (octal, e.g. 0o600 = 384).
    pub mode: u32,
    /// Whether the agent should mimic neighbouring files when deploying.
    pub mimic_neighbor: bool,
}

// ── Public entry point ────────────────────────────────────────────────────────

/// Build the recon profile from the gathered users + software inventory.
///
/// Filesystem existence checks run against the live host (cheap `stat`s) so a
/// candidate is only proposed where its real counterpart is plausible.
pub fn build_profile(users: &[UserAccount], software: &SoftwareInventory) -> ReconProfile {
    build_profile_with(users, software, &RealFs)
}

/// Abstraction over filesystem probing so the heuristics are unit-testable
/// without mutating the host.
pub trait FsProbe {
    fn is_dir(&self, path: &str) -> bool;
    fn exists(&self, path: &str) -> bool;
}

struct RealFs;
impl FsProbe for RealFs {
    fn is_dir(&self, path: &str) -> bool {
        Path::new(path).is_dir()
    }
    fn exists(&self, path: &str) -> bool {
        Path::new(path).exists()
    }
}

pub fn build_profile_with(
    users: &[UserAccount],
    software: &SoftwareInventory,
    fs: &dyn FsProbe,
) -> ReconProfile {
    let mut candidates: Vec<TokenCandidate> = Vec::new();

    // Software context, resolved once.
    let has_aws = pkg_present(software, &["awscli", "aws-cli", "awscli-plugin-endpoint"]);
    let has_pg = pkg_present(software, &["postgresql-client", "postgresql-client-common", "postgresql", "libpq5"]);
    let has_mysql = pkg_present(software, &["mysql-client", "default-mysql-client", "mariadb-client", "mysql-client-core"]);
    let has_docker = pkg_present(software, &["docker.io", "docker-ce", "docker-ce-cli", "containerd", "podman"]);
    let has_kube = pkg_present(software, &["kubectl", "kubernetes-cli", "kubeadm", "kubelet"]);
    let has_nginx = pkg_present(software, &["nginx", "nginx-core", "nginx-full", "nginx-light"]);
    let has_apache = pkg_present(software, &["apache2", "httpd", "apache2-bin"]);

    // ── Per-user, home-rooted candidates ────────────────────────────────────
    // Only humans with a real login shell get personal credential bait; service
    // accounts (nologin / uid<1000) would not plausibly hold these.
    for user in users.iter().filter(|u| u.is_human && !u.home.is_empty()) {
        let home = user.home.trim_end_matches('/');

        // ~/.ssh present → a "backup" private key is the classic T1552.004 find.
        let ssh_dir = format!("{home}/.ssh");
        if fs.is_dir(&ssh_dir) {
            candidates.push(TokenCandidate {
                kind: "ssh_private_key".into(),
                path: format!("{ssh_dir}/id_rsa_backup"),
                mitre_technique: "T1552.004".into(),
                rationale: format!("user '{}' has a populated ~/.ssh directory", user.username),
                context: vec![format!("user:{}", user.username), "dir:~/.ssh".into()],
                score: score(90, 1.0),
                mode: 0o600,
                mimic_neighbor: true,
            });
        }

        // awscli installed → ~/.aws/credentials. Gated on AWS context only;
        // the directory itself may not exist yet, which is still plausible.
        if has_aws {
            let aws_dir_exists = fs.is_dir(&format!("{home}/.aws"));
            candidates.push(TokenCandidate {
                kind: "aws_credentials".into(),
                path: format!("{home}/.aws/credentials"),
                mitre_technique: "T1552.001".into(),
                rationale: "awscli is installed — AWS access keys are a plausible artefact".into(),
                context: vec![format!("user:{}", user.username), "pkg:awscli".into()],
                score: score(95, if aws_dir_exists { 1.0 } else { 0.75 }),
                mode: 0o600,
                mimic_neighbor: aws_dir_exists,
            });
        }

        if has_pg {
            candidates.push(TokenCandidate {
                kind: "pgpass".into(),
                path: format!("{home}/.pgpass"),
                mitre_technique: "T1552.001".into(),
                rationale: "a PostgreSQL client is installed — ~/.pgpass holds connection secrets".into(),
                context: vec![format!("user:{}", user.username), "pkg:postgresql-client".into()],
                score: score(70, 1.0),
                mode: 0o600,
                mimic_neighbor: true,
            });
        }

        if has_mysql {
            candidates.push(TokenCandidate {
                kind: "my_cnf".into(),
                path: format!("{home}/.my.cnf"),
                mitre_technique: "T1552.001".into(),
                rationale: "a MySQL/MariaDB client is installed — ~/.my.cnf holds DB credentials".into(),
                context: vec![format!("user:{}", user.username), "pkg:mysql-client".into()],
                score: score(70, 1.0),
                mode: 0o600,
                mimic_neighbor: true,
            });
        }

        if has_docker {
            candidates.push(TokenCandidate {
                kind: "docker_config".into(),
                path: format!("{home}/.docker/config.json"),
                mitre_technique: "T1552.001".into(),
                rationale: "a container runtime is installed — registry auth lives in ~/.docker/config.json".into(),
                context: vec![format!("user:{}", user.username), "pkg:docker".into()],
                score: score(65, 1.0),
                mode: 0o600,
                mimic_neighbor: fs.is_dir(&format!("{home}/.docker")),
            });
        }

        if has_kube {
            candidates.push(TokenCandidate {
                kind: "kube_config".into(),
                path: format!("{home}/.kube/config"),
                mitre_technique: "T1552.001".into(),
                rationale: "kubectl is installed — cluster credentials live in ~/.kube/config".into(),
                context: vec![format!("user:{}", user.username), "pkg:kubectl".into()],
                score: score(80, 1.0),
                mode: 0o600,
                mimic_neighbor: fs.is_dir(&format!("{home}/.kube")),
            });
        }

        // Shell history present → a "forgotten" credential line is bait that
        // accompanies the primary tokens. Placement targets a sibling file so
        // the real history is never touched (the deploy path additionally
        // refuses to overwrite any existing file).
        let bash_hist = format!("{home}/.bash_history");
        let zsh_hist = format!("{home}/.zsh_history");
        if fs.exists(&bash_hist) || fs.exists(&zsh_hist) {
            candidates.push(TokenCandidate {
                kind: "shell_history".into(),
                path: format!("{home}/.bash_history.1"),
                mitre_technique: "T1552.003".into(),
                rationale: format!("user '{}' keeps shell history — a leaked credential in a rotated history file is believable", user.username),
                context: vec![format!("user:{}", user.username), "file:shell_history".into()],
                score: score(40, 1.0),
                mode: 0o600,
                mimic_neighbor: true,
            });
        }
    }

    // ── Webroot .env ─────────────────────────────────────────────────────────
    // Plausible when a web server is installed or a conventional webroot exists.
    if has_nginx || has_apache {
        if let Some(webroot) = webroot(fs) {
            let mut ctx = vec![format!("dir:{webroot}")];
            if has_nginx { ctx.push("pkg:nginx".into()); }
            if has_apache { ctx.push("pkg:apache2".into()); }
            candidates.push(TokenCandidate {
                kind: "webroot_env".into(),
                path: format!("{webroot}/.env"),
                mitre_technique: "T1552.001".into(),
                rationale: "a web server is installed with a real webroot — a stray .env with DB/API keys is the canonical leak".into(),
                context: ctx,
                score: score(85, 1.0),
                mode: 0o640,
                mimic_neighbor: true,
            });
        }
    }

    // ── Root home / backup directories ────────────────────────────────────────
    // High-value loot an attacker hunts for post-escalation (T1083 → T1552).
    if fs.is_dir("/root") {
        candidates.push(TokenCandidate {
            kind: "root_backup_keys".into(),
            path: "/root/backup_keys.txt".into(),
            mitre_technique: "T1552.001".into(),
            rationale: "/root exists — a plaintext key dump is loot an attacker expects post-escalation".into(),
            context: vec!["dir:/root".into()],
            score: score(88, 1.0),
            mode: 0o600,
            mimic_neighbor: true,
        });
    }
    for backup_dir in ["/opt/backups", "/var/backups"] {
        if fs.is_dir(backup_dir) {
            candidates.push(TokenCandidate {
                kind: "passwords_kdbx".into(),
                path: format!("{backup_dir}/passwords.kdbx"),
                mitre_technique: "T1083".into(),
                rationale: format!("{backup_dir} exists — a KeePass vault in a backup dir is prime loot"),
                context: vec![format!("dir:{backup_dir}")],
                score: score(92, 1.0),
                mode: 0o600,
                mimic_neighbor: true,
            });
            break; // one vault candidate is enough
        }
    }

    // Highest score first; stable tie-break on path for deterministic output.
    candidates.sort_by(|a, b| b.score.cmp(&a.score).then_with(|| a.path.cmp(&b.path)));

    ReconProfile { schema_version: RECON_PROFILE_SCHEMA, candidates }
}

// ── Helpers ─────────────────────────────────────────────────────────────────

/// Deterministic score = attacker attractiveness (0–100) × context confidence
/// (0.0–1.0), rounded and clamped to a `u8`.
fn score(attacker_weight: u32, context_confidence: f32) -> u8 {
    let v = (attacker_weight as f32 * context_confidence).round();
    v.clamp(0.0, 100.0) as u8
}

/// True when any installed package name matches one of `names` (exact, case-
/// insensitive). Exact matching avoids the false positives a substring scan
/// would hit (e.g. "docker-doc" or a package merely *mentioning* aws).
fn pkg_present(software: &SoftwareInventory, names: &[&str]) -> bool {
    software.packages.iter().any(|p| {
        names.iter().any(|n| p.name.eq_ignore_ascii_case(n))
    })
}

/// First conventional webroot that actually exists.
fn webroot(fs: &dyn FsProbe) -> Option<String> {
    for candidate in ["/var/www/html", "/var/www", "/srv/www", "/usr/share/nginx/html"] {
        if fs.is_dir(candidate) {
            return Some(candidate.to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inventory::{SoftwarePackage, UserAccount};
    use std::collections::HashSet;

    /// In-memory filesystem stub for plausibility gating.
    struct FakeFs {
        dirs: HashSet<String>,
        files: HashSet<String>,
    }
    impl FakeFs {
        fn new(dirs: &[&str], files: &[&str]) -> Self {
            Self {
                dirs: dirs.iter().map(|s| s.to_string()).collect(),
                files: files.iter().map(|s| s.to_string()).collect(),
            }
        }
    }
    impl FsProbe for FakeFs {
        fn is_dir(&self, path: &str) -> bool {
            self.dirs.contains(path)
        }
        fn exists(&self, path: &str) -> bool {
            self.dirs.contains(path) || self.files.contains(path)
        }
    }

    fn user(name: &str, home: &str) -> UserAccount {
        UserAccount {
            username: name.into(),
            uid: 1000,
            gid: 1000,
            home: home.into(),
            shell: "/bin/bash".into(),
            is_human: true,
        }
    }

    fn software(pkgs: &[&str]) -> SoftwareInventory {
        let packages = pkgs
            .iter()
            .map(|n| SoftwarePackage { name: n.to_string(), version: "1".into(), architecture: None })
            .collect::<Vec<_>>();
        SoftwareInventory { source: "dpkg".into(), package_count: packages.len(), packages }
    }

    #[test]
    fn aws_candidate_requires_aws_context() {
        // No AWS package -> the trap-revealing ~/.aws/credentials is NOT proposed.
        let users = vec![user("alice", "/home/alice")];
        let fs = FakeFs::new(&["/home/alice/.ssh"], &[]);
        let profile = build_profile_with(&users, &software(&["vim", "curl"]), &fs);
        assert!(
            !profile.candidates.iter().any(|c| c.kind == "aws_credentials"),
            "must not place AWS creds without AWS footprint"
        );

        // With awscli installed it appears, in correct format/path.
        let profile = build_profile_with(&users, &software(&["awscli"]), &fs);
        let aws = profile.candidates.iter().find(|c| c.kind == "aws_credentials").expect("aws candidate");
        assert_eq!(aws.path, "/home/alice/.aws/credentials");
        assert_eq!(aws.mode, 0o600);
        assert_eq!(aws.mitre_technique, "T1552.001");
    }

    #[test]
    fn ssh_candidate_only_when_ssh_dir_exists() {
        let users = vec![user("bob", "/home/bob")];
        let without = build_profile_with(&users, &software(&[]), &FakeFs::new(&[], &[]));
        assert!(!without.candidates.iter().any(|c| c.kind == "ssh_private_key"));

        let with = build_profile_with(&users, &software(&[]), &FakeFs::new(&["/home/bob/.ssh"], &[]));
        let ssh = with.candidates.iter().find(|c| c.kind == "ssh_private_key").expect("ssh candidate");
        assert_eq!(ssh.path, "/home/bob/.ssh/id_rsa_backup");
        assert_eq!(ssh.mitre_technique, "T1552.004");
    }

    #[test]
    fn service_accounts_get_no_personal_bait() {
        let mut svc = user("www-data", "/var/www");
        svc.is_human = false;
        let fs = FakeFs::new(&["/var/www/.ssh"], &[]);
        let profile = build_profile_with(&[svc], &software(&["awscli"]), &fs);
        assert!(
            profile.candidates.iter().all(|c| !c.context.contains(&"user:www-data".to_string())),
            "non-human accounts must not receive personal credential bait"
        );
    }

    #[test]
    fn candidates_are_sorted_by_score_desc() {
        let users = vec![user("alice", "/home/alice")];
        let fs = FakeFs::new(&["/home/alice/.ssh", "/root", "/var/www/html"], &[]);
        let profile = build_profile_with(&users, &software(&["awscli", "nginx", "postgresql-client"]), &fs);
        assert!(profile.candidates.len() >= 4);
        for w in profile.candidates.windows(2) {
            assert!(w[0].score >= w[1].score, "candidates must be ranked by descending score");
        }
    }

    #[test]
    fn webroot_env_requires_web_server_and_root() {
        let fs = FakeFs::new(&["/var/www/html"], &[]);
        // Web server pkg + existing webroot -> candidate.
        let p = build_profile_with(&[], &software(&["nginx"]), &fs);
        let env = p.candidates.iter().find(|c| c.kind == "webroot_env").expect("webroot candidate");
        assert_eq!(env.path, "/var/www/html/.env");
        assert_eq!(env.mode, 0o640);

        // Web server but no webroot on disk -> nothing (no implausible placement).
        let p2 = build_profile_with(&[], &software(&["nginx"]), &FakeFs::new(&[], &[]));
        assert!(!p2.candidates.iter().any(|c| c.kind == "webroot_env"));
    }
}
