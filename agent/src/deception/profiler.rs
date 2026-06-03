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

use crate::inventory::{NetInterface, SoftwareInventory, UserAccount};

/// Schema version of the recon profile, independent of the inventory schema so
/// the candidate contract can evolve on its own.
///
/// v2 adds the [`HostPersona`] so the backend can generate content that is
/// *consistent* across every token on a host (same internal hostname, domain,
/// subnet and usernames a real artefact would reference).
pub const RECON_PROFILE_SCHEMA: u32 = 2;

/// The condensed recon view derived from inventory, sent to the backend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconProfile {
    pub schema_version: u32,
    /// The host's identity facts, so generated bait references real internal
    /// names/addresses instead of giveaway invented ones (issue #32, point 3).
    pub persona: HostPersona,
    /// Token candidates, sorted by descending [`TokenCandidate::score`].
    pub candidates: Vec<TokenCandidate>,
}

/// Stable, host-wide facts the backend should weave into every token so the
/// whole set tells one coherent story. Derived deterministically from inventory;
/// contains only data already collected elsewhere in the snapshot.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HostPersona {
    /// The host's reported hostname (may be short or an FQDN).
    pub hostname: String,
    /// Domain part of an FQDN hostname, when present (e.g. `corp.example.com`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    /// Primary interactive user (lowest-uid human), if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub primary_user: Option<String>,
    /// All human/login usernames on the host.
    pub human_users: Vec<String>,
    /// Primary private IPv4 address, if one is configured.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub internal_ipv4: Option<String>,
    /// /24 CIDR derived from [`Self::internal_ipv4`] (e.g. `10.0.12.0/24`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subnet_cidr: Option<String>,
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

/// Build the recon profile *with* host identity, deriving the [`HostPersona`]
/// from the hostname and network interfaces so generated bait stays consistent.
pub fn build_profile_with_host(
    users: &[UserAccount],
    software: &SoftwareInventory,
    hostname: &str,
    interfaces: &[NetInterface],
) -> ReconProfile {
    build_profile_full(users, software, hostname, interfaces, &RealFs)
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

/// Test entry: build candidates against an injected [`FsProbe`] with no host
/// facts (empty persona).
#[cfg(test)]
pub fn build_profile_with(
    users: &[UserAccount],
    software: &SoftwareInventory,
    fs: &dyn FsProbe,
) -> ReconProfile {
    build_profile_full(users, software, "", &[], fs)
}

/// Full builder: candidates (via `fs`) plus the derived persona.
pub fn build_profile_full(
    users: &[UserAccount],
    software: &SoftwareInventory,
    hostname: &str,
    interfaces: &[NetInterface],
    fs: &dyn FsProbe,
) -> ReconProfile {
    let mut candidates: Vec<TokenCandidate> = Vec::new();

    // Software context, resolved once.
    let has_aws = pkg_present(software, &["awscli", "aws-cli", "awscli-plugin-endpoint"]);
    let has_pg = pkg_present(
        software,
        &[
            "postgresql-client",
            "postgresql-client-common",
            "postgresql",
            "libpq5",
        ],
    );
    let has_mysql = pkg_present(
        software,
        &[
            "mysql-client",
            "default-mysql-client",
            "mariadb-client",
            "mysql-client-core",
        ],
    );
    let has_docker = pkg_present(
        software,
        &[
            "docker.io",
            "docker-ce",
            "docker-ce-cli",
            "containerd",
            "podman",
        ],
    );
    let has_kube = pkg_present(
        software,
        &["kubectl", "kubernetes-cli", "kubeadm", "kubelet"],
    );
    let has_nginx = pkg_present(
        software,
        &["nginx", "nginx-core", "nginx-full", "nginx-light"],
    );
    let has_apache = pkg_present(software, &["apache2", "httpd", "apache2-bin"]);
    let has_git = pkg_present(software, &["git", "git-core"]);

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
                rationale: "a PostgreSQL client is installed — ~/.pgpass holds connection secrets"
                    .into(),
                context: vec![
                    format!("user:{}", user.username),
                    "pkg:postgresql-client".into(),
                ],
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
                rationale: "a MySQL/MariaDB client is installed — ~/.my.cnf holds DB credentials"
                    .into(),
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
                rationale: "kubectl is installed — cluster credentials live in ~/.kube/config"
                    .into(),
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

        // git is installed or the user has a ~/.gitconfig → a ~/.git-credentials
        // store with a plaintext HTTPS token is a classic, high-value leak.
        if has_git || fs.exists(&format!("{home}/.gitconfig")) {
            candidates.push(TokenCandidate {
                kind: "git_credentials".into(),
                path: format!("{home}/.git-credentials"),
                mitre_technique: "T1552.001".into(),
                rationale: "git is present — ~/.git-credentials stores plaintext HTTPS tokens"
                    .into(),
                context: vec![format!("user:{}", user.username), "pkg:git".into()],
                score: score(78, 1.0),
                mode: 0o600,
                mimic_neighbor: fs.exists(&format!("{home}/.gitconfig")),
            });
        }

        // Browser credential stores — only proposed where the browser's own
        // profile directory already exists, so the placement is never a tell.
        let firefox_dir = format!("{home}/.mozilla/firefox");
        if fs.is_dir(&firefox_dir) {
            candidates.push(TokenCandidate {
                kind: "browser_logins".into(),
                path: format!("{firefox_dir}/logins.json"),
                mitre_technique: "T1555.003".into(),
                rationale: "a Firefox profile exists — logins.json holds saved site credentials"
                    .into(),
                context: vec![
                    format!("user:{}", user.username),
                    "dir:~/.mozilla/firefox".into(),
                ],
                score: score(72, 1.0),
                mode: 0o600,
                mimic_neighbor: true,
            });
        }
        let chrome_dir = format!("{home}/.config/google-chrome/Default");
        if fs.is_dir(&chrome_dir) {
            candidates.push(TokenCandidate {
                kind: "browser_logins".into(),
                path: format!("{chrome_dir}/Login Data"),
                mitre_technique: "T1555.003".into(),
                rationale: "a Chrome profile exists — 'Login Data' holds saved site credentials"
                    .into(),
                context: vec![
                    format!("user:{}", user.username),
                    "dir:~/.config/google-chrome".into(),
                ],
                score: score(72, 1.0),
                mode: 0o600,
                mimic_neighbor: true,
            });
        }

        // A password-bearing Office document is bait that doubles as an
        // out-of-band canary: opening it fetches a remote tracking pixel.
        let documents = format!("{home}/Documents");
        if fs.is_dir(&documents) {
            candidates.push(TokenCandidate {
                kind: "office_doc".into(),
                path: format!("{documents}/Passwords.docx"),
                mitre_technique: "T1552.001".into(),
                rationale: "user keeps a ~/Documents folder — a 'Passwords.docx' is irresistible loot and can carry a tracking pixel".into(),
                context: vec![format!("user:{}", user.username), "dir:~/Documents".into()],
                score: score(60, 1.0),
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
            if has_nginx {
                ctx.push("pkg:nginx".into());
            }
            if has_apache {
                ctx.push("pkg:apache2".into());
            }
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
            rationale:
                "/root exists — a plaintext key dump is loot an attacker expects post-escalation"
                    .into(),
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
                rationale: format!(
                    "{backup_dir} exists — a KeePass vault in a backup dir is prime loot"
                ),
                context: vec![format!("dir:{backup_dir}")],
                score: score(92, 1.0),
                mode: 0o600,
                mimic_neighbor: true,
            });
            break; // one vault candidate is enough
        }
    }

    // A "backup" of /etc/shadow is loot an attacker hunts after escalation. We
    // never touch the real /etc/shadow — the bait is a copy in a backup dir.
    for shadow_dir in ["/var/backups", "/opt/backups", "/root"] {
        if fs.is_dir(shadow_dir) {
            candidates.push(TokenCandidate {
                kind: "shadow_backup".into(),
                path: format!("{shadow_dir}/shadow.bak"),
                mitre_technique: "T1003.008".into(),
                rationale: format!("{shadow_dir} exists — a copied /etc/shadow with crackable hashes is prime post-escalation loot"),
                context: vec![format!("dir:{shadow_dir}")],
                score: score(86, 1.0),
                mode: 0o600,
                mimic_neighbor: true,
            });
            break; // one shadow backup is enough
        }
    }

    // Highest score first; stable tie-break on path for deterministic output.
    candidates.sort_by(|a, b| b.score.cmp(&a.score).then_with(|| a.path.cmp(&b.path)));

    ReconProfile {
        schema_version: RECON_PROFILE_SCHEMA,
        persona: derive_persona(users, hostname, interfaces),
        candidates,
    }
}

/// Derive the host persona from already-collected inventory facts.
fn derive_persona(
    users: &[UserAccount],
    hostname: &str,
    interfaces: &[NetInterface],
) -> HostPersona {
    let human_users: Vec<String> = users
        .iter()
        .filter(|u| u.is_human)
        .map(|u| u.username.clone())
        .collect();

    // Primary interactive user = lowest-uid human (root is uid 0 but is rarely
    // "the" desktop user; prefer the lowest uid >= 1000, else any human).
    let primary_user = users
        .iter()
        .filter(|u| u.is_human && u.uid >= 1000)
        .min_by_key(|u| u.uid)
        .or_else(|| users.iter().find(|u| u.is_human))
        .map(|u| u.username.clone());

    let domain = hostname
        .split_once('.')
        .map(|(_, d)| d.to_string())
        .filter(|d| !d.is_empty());

    let internal_ipv4 = first_private_ipv4(interfaces);
    let subnet_cidr = internal_ipv4.as_deref().and_then(slash24_cidr);

    HostPersona {
        hostname: hostname.to_string(),
        domain,
        primary_user,
        human_users,
        internal_ipv4,
        subnet_cidr,
    }
}

/// First non-loopback RFC-1918 IPv4 across the up interfaces.
fn first_private_ipv4(interfaces: &[NetInterface]) -> Option<String> {
    interfaces
        .iter()
        .flat_map(|i| i.ipv4.iter())
        .find(|ip| is_private_ipv4(ip))
        .cloned()
}

fn is_private_ipv4(ip: &str) -> bool {
    let o: Vec<u8> = ip.split('.').filter_map(|p| p.parse().ok()).collect();
    if o.len() != 4 {
        return false;
    }
    match (o[0], o[1]) {
        (10, _) => true,
        (172, b) if (16..=31).contains(&b) => true,
        (192, 168) => true,
        _ => false,
    }
}

/// `a.b.c.d` → `a.b.c.0/24`.
fn slash24_cidr(ip: &str) -> Option<String> {
    let o: Vec<&str> = ip.split('.').collect();
    (o.len() == 4).then(|| format!("{}.{}.{}.0/24", o[0], o[1], o[2]))
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
    software
        .packages
        .iter()
        .any(|p| names.iter().any(|n| p.name.eq_ignore_ascii_case(n)))
}

/// First conventional webroot that actually exists.
fn webroot(fs: &dyn FsProbe) -> Option<String> {
    for candidate in [
        "/var/www/html",
        "/var/www",
        "/srv/www",
        "/usr/share/nginx/html",
    ] {
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
            .map(|n| SoftwarePackage {
                name: n.to_string(),
                version: "1".into(),
                architecture: None,
            })
            .collect::<Vec<_>>();
        SoftwareInventory {
            source: "dpkg".into(),
            package_count: packages.len(),
            packages,
        }
    }

    #[test]
    fn aws_candidate_requires_aws_context() {
        // No AWS package -> the trap-revealing ~/.aws/credentials is NOT proposed.
        let users = vec![user("alice", "/home/alice")];
        let fs = FakeFs::new(&["/home/alice/.ssh"], &[]);
        let profile = build_profile_with(&users, &software(&["vim", "curl"]), &fs);
        assert!(
            !profile
                .candidates
                .iter()
                .any(|c| c.kind == "aws_credentials"),
            "must not place AWS creds without AWS footprint"
        );

        // With awscli installed it appears, in correct format/path.
        let profile = build_profile_with(&users, &software(&["awscli"]), &fs);
        let aws = profile
            .candidates
            .iter()
            .find(|c| c.kind == "aws_credentials")
            .expect("aws candidate");
        assert_eq!(aws.path, "/home/alice/.aws/credentials");
        assert_eq!(aws.mode, 0o600);
        assert_eq!(aws.mitre_technique, "T1552.001");
    }

    #[test]
    fn ssh_candidate_only_when_ssh_dir_exists() {
        let users = vec![user("bob", "/home/bob")];
        let without = build_profile_with(&users, &software(&[]), &FakeFs::new(&[], &[]));
        assert!(!without
            .candidates
            .iter()
            .any(|c| c.kind == "ssh_private_key"));

        let with = build_profile_with(
            &users,
            &software(&[]),
            &FakeFs::new(&["/home/bob/.ssh"], &[]),
        );
        let ssh = with
            .candidates
            .iter()
            .find(|c| c.kind == "ssh_private_key")
            .expect("ssh candidate");
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
            profile
                .candidates
                .iter()
                .all(|c| !c.context.contains(&"user:www-data".to_string())),
            "non-human accounts must not receive personal credential bait"
        );
    }

    #[test]
    fn candidates_are_sorted_by_score_desc() {
        let users = vec![user("alice", "/home/alice")];
        let fs = FakeFs::new(&["/home/alice/.ssh", "/root", "/var/www/html"], &[]);
        let profile = build_profile_with(
            &users,
            &software(&["awscli", "nginx", "postgresql-client"]),
            &fs,
        );
        assert!(profile.candidates.len() >= 4);
        for w in profile.candidates.windows(2) {
            assert!(
                w[0].score >= w[1].score,
                "candidates must be ranked by descending score"
            );
        }
    }

    #[test]
    fn webroot_env_requires_web_server_and_root() {
        let fs = FakeFs::new(&["/var/www/html"], &[]);
        // Web server pkg + existing webroot -> candidate.
        let p = build_profile_with(&[], &software(&["nginx"]), &fs);
        let env = p
            .candidates
            .iter()
            .find(|c| c.kind == "webroot_env")
            .expect("webroot candidate");
        assert_eq!(env.path, "/var/www/html/.env");
        assert_eq!(env.mode, 0o640);

        // Web server but no webroot on disk -> nothing (no implausible placement).
        let p2 = build_profile_with(&[], &software(&["nginx"]), &FakeFs::new(&[], &[]));
        assert!(!p2.candidates.iter().any(|c| c.kind == "webroot_env"));
    }

    #[test]
    fn git_credentials_gated_on_git_presence() {
        let users = vec![user("alice", "/home/alice")];
        // No git, no ~/.gitconfig -> not proposed.
        let none = build_profile_with(&users, &software(&[]), &FakeFs::new(&[], &[]));
        assert!(!none.candidates.iter().any(|c| c.kind == "git_credentials"));
        // git installed -> proposed at ~/.git-credentials.
        let with = build_profile_with(&users, &software(&["git"]), &FakeFs::new(&[], &[]));
        let gc = with
            .candidates
            .iter()
            .find(|c| c.kind == "git_credentials")
            .expect("git candidate");
        assert_eq!(gc.path, "/home/alice/.git-credentials");
        assert_eq!(gc.mitre_technique, "T1552.001");
    }

    #[test]
    fn browser_and_office_and_shadow_archetypes() {
        let users = vec![user("alice", "/home/alice")];
        let fs = FakeFs::new(
            &[
                "/home/alice/.mozilla/firefox",
                "/home/alice/.config/google-chrome/Default",
                "/home/alice/Documents",
                "/var/backups",
            ],
            &[],
        );
        let p = build_profile_with(&users, &software(&[]), &fs);
        let kinds: HashSet<&str> = p.candidates.iter().map(|c| c.kind.as_str()).collect();
        assert!(
            kinds.contains("browser_logins"),
            "firefox/chrome stores proposed"
        );
        assert!(kinds.contains("office_doc"), "office tracking doc proposed");
        assert!(kinds.contains("shadow_backup"), "shadow backup proposed");
        // Two browser_logins candidates (firefox + chrome).
        assert_eq!(
            p.candidates
                .iter()
                .filter(|c| c.kind == "browser_logins")
                .count(),
            2
        );
        let shadow = p
            .candidates
            .iter()
            .find(|c| c.kind == "shadow_backup")
            .unwrap();
        assert_eq!(shadow.path, "/var/backups/shadow.bak");
        assert_eq!(shadow.mitre_technique, "T1003.008");
    }

    #[test]
    fn persona_is_derived_from_host_facts() {
        let mut admin = user("root", "/root");
        admin.uid = 0;
        let alice = UserAccount {
            uid: 1000,
            ..user("alice", "/home/alice")
        };
        let bob = UserAccount {
            uid: 1001,
            ..user("bob", "/home/bob")
        };
        let ifaces = vec![
            NetInterface {
                name: "lo".into(),
                mac: None,
                ipv4: vec!["127.0.0.1".into()],
                ipv6: vec![],
                up: true,
            },
            NetInterface {
                name: "eth0".into(),
                mac: None,
                ipv4: vec!["10.0.12.34".into()],
                ipv6: vec![],
                up: true,
            },
        ];
        let p = build_profile_full(
            &[admin, alice, bob],
            &software(&[]),
            "web01.corp.example.com",
            &ifaces,
            &FakeFs::new(&[], &[]),
        );
        let persona = &p.persona;
        assert_eq!(persona.hostname, "web01.corp.example.com");
        assert_eq!(persona.domain.as_deref(), Some("corp.example.com"));
        // Lowest-uid human >= 1000 is the primary user (not root).
        assert_eq!(persona.primary_user.as_deref(), Some("alice"));
        assert!(persona.human_users.contains(&"bob".to_string()));
        // Loopback skipped; first private IPv4 wins, /24 derived.
        assert_eq!(persona.internal_ipv4.as_deref(), Some("10.0.12.34"));
        assert_eq!(persona.subnet_cidr.as_deref(), Some("10.0.12.0/24"));
    }

    #[test]
    fn persona_handles_short_hostname_and_no_private_ip() {
        let p = build_profile_full(
            &[user("alice", "/home/alice")],
            &software(&[]),
            "laptop",
            &[NetInterface {
                name: "eth0".into(),
                mac: None,
                ipv4: vec!["8.8.8.8".into()],
                ipv6: vec![],
                up: true,
            }],
            &FakeFs::new(&[], &[]),
        );
        assert_eq!(p.persona.hostname, "laptop");
        assert_eq!(p.persona.domain, None, "short hostname has no domain");
        assert_eq!(
            p.persona.internal_ipv4, None,
            "public IP is not an internal address"
        );
        assert_eq!(p.persona.subnet_cidr, None);
    }
}
