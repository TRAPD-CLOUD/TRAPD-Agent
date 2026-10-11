use super::*;
use crate::deception::activity::UserActivitySummary;

const DAY: i64 = 86_400;
const NOW: i64 = 1_790_000_000;

/// In-memory tree: path → entries.
#[derive(Default)]
struct MemFs {
    dirs: BTreeMap<PathBuf, Vec<EntryInfo>>,
    files: BTreeSet<PathBuf>,
}

impl MemFs {
    fn dir(&mut self, path: &str) -> &mut Self {
        let p = PathBuf::from(path);
        let mut cur = PathBuf::new();
        for c in p.components() {
            let parent = cur.clone();
            cur.push(c);
            if parent.as_os_str().is_empty() {
                continue;
            }
            let name = c.as_os_str().to_string_lossy().to_string();
            let list = self.dirs.entry(parent).or_default();
            if !list.iter().any(|e| e.name == name) {
                list.push(EntryInfo {
                    name,
                    is_dir: true,
                    modified_unix: NOW - 400 * DAY,
                });
            }
        }
        self.dirs.entry(p).or_default();
        self
    }
    fn file(&mut self, dir: &str, name: &str, age_days: i64) -> &mut Self {
        self.dir(dir);
        self.dirs
            .get_mut(&PathBuf::from(dir))
            .unwrap()
            .push(EntryInfo {
                name: name.into(),
                is_dir: false,
                modified_unix: NOW - age_days * DAY,
            });
        self.files.insert(PathBuf::from(dir).join(name));
        self
    }
}

impl DirProbe for MemFs {
    fn exists(&self, path: &Path) -> bool {
        self.dirs.contains_key(path) || self.files.contains(path)
    }
    fn entries(&self, dir: &Path) -> Vec<EntryInfo> {
        self.dirs.get(dir).cloned().unwrap_or_default()
    }
}

fn user(name: &str) -> WindowsUserProfile {
    WindowsUserProfile {
        name: name.into(),
        sid: format!("S-1-5-21-1-2-3-{}", 1000 + name.len()),
        profile_dir: format!("/Users/{name}"),
        last_use_unix: Some(NOW - DAY),
        ..Default::default()
    }
}

#[test]
fn only_recent_real_accounts_are_human() {
    assert!(is_human_profile(&user("anna"), NOW));
    let mut svc = user("svc");
    svc.sid = "S-1-5-80-123".into();
    assert!(!is_human_profile(&svc, NOW));
    let mut sys = user("system");
    sys.sid = "S-1-5-18".into();
    assert!(!is_human_profile(&sys, NOW));
    assert!(!is_human_profile(&user("defaultuser0"), NOW));
    assert!(!is_human_profile(&user("WDAGUtilityAccount"), NOW));
    assert!(!is_human_profile(&user("HOST\\Guest"), NOW));
    assert!(!is_human_profile(&user("HOST\\DefaultAccount"), NOW));
    assert!(is_human_profile(&user("HOST\\anna"), NOW));
    let mut stale = user("old");
    stale.last_use_unix = Some(NOW - 200 * DAY);
    assert!(!is_human_profile(&stale, NOW));
    let mut unc = user("roam");
    unc.profile_dir = "\\\\fs01\\profiles\\roam".into();
    assert!(!is_human_profile(&unc, NOW));
}

#[test]
fn profile_helpers() {
    assert_eq!(
        expand_user_path("%USERPROFILE%\\Documents", "C:\\Users\\anna").as_deref(),
        Some("C:\\Users\\anna\\Documents")
    );
    assert_eq!(
        expand_user_path("%OneDrive%\\Documents", "C:\\Users\\anna"),
        None
    );
    let roots = synced_roots_from_children(
        "/Users/anna",
        &[
            "OneDrive - Contoso GmbH".into(),
            "Dropbox".into(),
            "Documents".into(),
            "OneDriveX".into(),
            "Boxes".into(),
        ],
    );
    // `synced_roots_from_children` joins with the platform separator, so
    // build the expectation the same way rather than hard-coding `/`.
    let join = |child: &str| {
        Path::new("/Users/anna")
            .join(child)
            .to_string_lossy()
            .into_owned()
    };
    assert_eq!(
        roots,
        vec![join("OneDrive - Contoso GmbH"), join("Dropbox")]
    );
    // 2020-01-01T00:00:00Z = 132223104000000000 ticks.
    let t: u64 = 132_223_104_000_000_000;
    assert_eq!(
        filetime_to_unix((t >> 32) as u32, t as u32),
        Some(1_577_836_800)
    );
    assert_eq!(filetime_to_unix(0, 0), None);
}

#[test]
fn git_does_not_match_digital() {
    assert!(contains_word("git version 2.44", "git"));
    assert!(contains_word("git", "git"));
    assert!(!contains_word("digital editions", "git"));
    assert!(!contains_word("gitkraken", "git"));
}

#[test]
fn cold_dirs_skip_hot_synced_desktop_and_sparse_folders() {
    let mut fs = MemFs::default();
    fs.file("/Users/anna/Documents/IT Doku", "Netzplan.vsdx", 120)
        .file("/Users/anna/Documents/IT Doku", "Server-Liste.xlsx", 90)
        .file("/Users/anna/Documents/Aktuell", "Angebot.docx", 2)
        .file("/Users/anna/Documents/Aktuell", "Notizen.txt", 1)
        .file("/Users/anna/Documents/Leer", "eine.txt", 300)
        .file("/Users/anna/Documents/OneDrive/Alt", "a.txt", 300)
        .file("/Users/anna/Documents/OneDrive/Alt", "b.txt", 300)
        .file("/Users/anna/Documents/Kunden", "k1.txt", 60)
        .file("/Users/anna/Documents/Kunden", "k2.txt", 50);
    let docs = PathBuf::from("/Users/anna/Documents");
    let dirs = cold_dirs(&docs, &[], &BTreeSet::new(), NOW, &fs);
    let names: Vec<String> = dirs
        .iter()
        .map(|d| d.path.file_name().unwrap().to_string_lossy().into())
        .collect();
    assert_eq!(
        names,
        vec!["IT Doku", "Kunden"],
        "topical cold dirs only, IT first: {names:?}"
    );

    // Activity marks a dir hot even when its files look old.
    let hot: BTreeSet<String> = ["/users/anna/documents/it doku".to_string()].into();
    let dirs = cold_dirs(&docs, &[], &hot, NOW, &fs);
    assert!(dirs.iter().all(|d| !d.path.ends_with("IT Doku")));

    // A synced root excludes everything below it.
    let dirs = cold_dirs(&docs, &[docs.join("Kunden")], &BTreeSet::new(), NOW, &fs);
    assert!(dirs.iter().all(|d| !d.path.ends_with("Kunden")));
}

#[test]
fn candidates_require_role_evidence_and_a_cold_place() {
    let mut fs = MemFs::default();
    fs.file("/Users/anna/Documents/IT", "router.txt", 100)
        .file("/Users/anna/Documents/IT", "switch.txt", 80)
        .dir("/Users/anna/AppData/Roaming/FileZilla");
    let users = [user("anna")];
    let activity = BTreeMap::new();
    let input = ProfilerInput {
        users: &users,
        software: &[],
        activity: &activity,
        now_unix: NOW,
    };
    let (cands, signals) = build_candidates(&input, &fs);
    let kinds: BTreeSet<&str> = cands.iter().map(|c| c.kind.as_str()).collect();
    assert!(kinds.contains("filezilla_sitemanager"), "{kinds:?}");
    assert!(kinds.contains("password_note"));
    // No developer, cloud or db evidence → no such bait.
    assert!(!kinds.contains("appsettings_json"));
    assert!(!kinds.contains("aws_credentials_backup"));
    assert!(!kinds.contains("db_connection_notes"));
    assert!(signals[0].roles.contains(&"admin_tooling".to_string()));
    // Rationale never carries the user's own folder names.
    for c in &cands {
        assert!(
            c.rationale
                .iter()
                .all(|r| !r.contains("IT") && !r.contains("router")),
            "{:?}",
            c.rationale
        );
        assert_eq!(c.id, candidate_id(&users[0].sid, &c.kind));
    }
}

#[test]
fn host_software_alone_does_not_justify_role_specific_bait() {
    let mut fs = MemFs::default();
    fs.file("/Users/anna/Documents/Archiv", "a.txt", 100).file(
        "/Users/anna/Documents/Archiv",
        "b.txt",
        100,
    );
    let users = [user("anna")];
    let activity = BTreeMap::new();
    let software = vec!["WinSCP 6.3".to_string()];
    let input = ProfilerInput {
        users: &users,
        software: &software,
        activity: &activity,
        now_unix: NOW,
    };
    let (cands, _) = build_candidates(&input, &fs);
    assert!(cands.iter().all(|c| c.kind != "winscp_ini"));

    // Learned usage turns it into strong evidence.
    let mut activity = BTreeMap::new();
    let mut a = UserActivitySummary::default();
    a.tool_uses.insert("winscp.exe".into(), 7);
    activity.insert("anna".to_string(), a);
    let input = ProfilerInput {
        users: &users,
        software: &software,
        activity: &activity,
        now_unix: NOW,
    };
    let (cands, _) = build_candidates(&input, &fs);
    let winscp = cands
        .iter()
        .find(|c| c.kind == "winscp_ini")
        .expect("winscp candidate");
    assert!(winscp.rationale.iter().any(|r| r.contains("winscp.exe")));
}

#[test]
fn aws_backup_only_next_to_a_real_cli_config() {
    let mut fs = MemFs::default();
    fs.dir("/Users/anna/.aws");
    let spec = kind_spec("aws_credentials_backup").unwrap();
    assert!(resolve_placement(spec, &user("anna"), None, NOW, &fs).is_none());
    fs.file("/Users/anna/.aws", "credentials", 30);
    let p = resolve_placement(spec, &user("anna"), None, NOW, &fs).unwrap();
    assert_eq!(p.dir, PathBuf::from("/Users/anna/.aws"));
}

#[test]
fn project_bait_needs_a_cold_project_folder() {
    let mut fs = MemFs::default();
    fs.file("/Users/dev/source/repos/Billing", "Billing.sln", 90)
        .file("/Users/dev/source/repos/Billing", "README.md", 90)
        .file("/Users/dev/source/repos/Current", "Current.sln", 1)
        .file("/Users/dev/source/repos/Current", "README.md", 1);
    let spec = kind_spec("env_file").unwrap();
    let p = resolve_placement(spec, &user("dev"), None, NOW, &fs).unwrap();
    assert!(p.dir.ends_with("Billing"));
}

#[test]
fn redirected_or_synced_documents_are_refused() {
    let mut fs = MemFs::default();
    fs.file("/Users/anna/OneDrive/Documents/IT", "a.txt", 100)
        .file("/Users/anna/OneDrive/Documents/IT", "b.txt", 100);
    let mut u = user("anna");
    u.documents_dir = Some("/Users/anna/OneDrive/Documents".into());
    u.synced_roots = vec!["/Users/anna/OneDrive".into()];
    let spec = kind_spec("password_note").unwrap();
    assert!(resolve_placement(spec, &u, None, NOW, &fs).is_none());
    u.documents_dir = Some("\\\\fs01\\home\\anna".into());
    u.synced_roots.clear();
    assert!(resolve_placement(spec, &u, None, NOW, &fs).is_none());
}

#[test]
fn resolved_file_avoids_collisions_and_stays_in_the_neighbour_range() {
    let place = Placement {
        dir: PathBuf::from("/Users/anna/Documents/IT"),
        risk: 15,
        neighbors: vec!["WinSCP.ini".into()],
        newest_unix: NOW - 30 * DAY,
        oldest_unix: NOW - 300 * DAY,
    };
    let spec = kind_spec("winscp_ini").unwrap();
    let style = NamingStyle::default();
    let r = resolve_file(spec, &place, &style, 12345).unwrap();
    assert_ne!(
        r.path.file_name().unwrap().to_string_lossy().to_lowercase(),
        "winscp.ini"
    );
    assert!(r.mimic_unix >= place.oldest_unix && r.mimic_unix <= place.newest_unix);
}
