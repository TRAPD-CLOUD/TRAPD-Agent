use super::*;

/// The ownership register is process-global, and `reconcile_removed`
/// retires every owned decoy that is not listed: tests that plant and
/// reconcile must not interleave.
static REGISTER_LOCK: Mutex<()> = Mutex::new(());

fn serialize() -> std::sync::MutexGuard<'static, ()> {
    REGISTER_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

fn sample() -> (PathBuf, OwnedFile) {
    let path = std::env::temp_dir().join(format!("trapd-win-owned-{}", uuid::Uuid::new_v4()));
    std::fs::write(&path, b"bait").unwrap();
    let file = std::fs::File::open(&path).unwrap();
    let owned = OwnedFile {
        identity: file_identity(&file).unwrap(),
        sha256: sha256_hex(b"bait"),
    };
    (path, owned)
}

#[test]
fn cleanup_removes_owned_unchanged_file() {
    let (path, owned) = sample();
    remove_owned_file(&path, &owned).unwrap();
    assert!(!path.exists());
}

#[test]
fn cleanup_preserves_changed_contents() {
    let (path, owned) = sample();
    std::fs::write(&path, b"real user credentials").unwrap();
    assert!(remove_owned_file(&path, &owned).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), b"real user credentials");
    std::fs::remove_file(path).unwrap();
}

#[test]
fn cleanup_preserves_different_file_identity() {
    let (path, owned) = sample();
    let old = std::fs::File::open(&path).unwrap();
    std::fs::remove_file(&path).unwrap();
    std::fs::write(&path, b"bait").unwrap();
    assert!(remove_owned_file(&path, &owned).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), b"bait");
    drop(old);
    std::fs::remove_file(path).unwrap();
}

#[test]
fn preexisting_file_is_not_adopted_or_overwritten() {
    let path = std::env::temp_dir().join(format!("trapd-win-decoy-{}", uuid::Uuid::new_v4()));
    std::fs::write(&path, b"real credentials").unwrap();
    let state = FsState::default();
    assert!(plant_missing(std::slice::from_ref(&path), &state).is_empty());
    assert!(!state.sha.lock().unwrap().contains_key(&path));
    assert_eq!(std::fs::read(&path).unwrap(), b"real credentials");
    std::fs::remove_file(path).unwrap();
}
fn revoked_events(rx: &mut tokio::sync::mpsc::Receiver<AgentEvent>) -> Vec<(String, bool)> {
    let mut out = Vec::new();
    while let Ok(event) = rx.try_recv() {
        if let EventData::Prevention(p) = event.data {
            if matches!(event.action, EventAction::HoneytokenRevoked) {
                out.push((p.target, p.success));
            }
        }
    }
    out
}

#[test]
fn decoy_removed_from_config_is_retired_and_reported() {
    let _serial = serialize();
    let path = std::env::temp_dir().join(format!("trapd-win-retire-{}", uuid::Uuid::new_v4()));
    let state = FsState::default();
    assert_eq!(plant_missing(std::slice::from_ref(&path), &state).len(), 1);
    let config = Arc::new(RwLock::new(AgentConfig::default()));
    assert!(config.read().unwrap().honeytoken_paths.is_empty());
    let (tx, mut rx) = tokio::sync::mpsc::channel(8);
    reconcile_removed(&tx, "agent", "host", &config, &state);
    assert!(!path.exists());
    assert!(!owns_path(&path));
    assert_eq!(
        revoked_events(&mut rx),
        vec![(path.display().to_string(), true)]
    );
}

#[test]
fn listed_decoy_is_not_retired() {
    let _serial = serialize();
    let path = std::env::temp_dir().join(format!("trapd-win-keep-{}", uuid::Uuid::new_v4()));
    let state = FsState::default();
    plant_missing(std::slice::from_ref(&path), &state);
    let config = Arc::new(RwLock::new(AgentConfig::default()));
    config.write().unwrap().honeytoken_paths = vec![path.display().to_string()];
    let (tx, mut rx) = tokio::sync::mpsc::channel(8);
    reconcile_removed(&tx, "agent", "host", &config, &state);
    assert!(path.exists());
    assert!(revoked_events(&mut rx).is_empty());
    config.write().unwrap().honeytoken_paths.clear();
    reconcile_removed(&tx, "agent", "host", &config, &state);
    assert!(!path.exists());
}

#[test]
fn modified_decoy_is_preserved_when_retired() {
    let _serial = serialize();
    let path = std::env::temp_dir().join(format!("trapd-win-edited-{}", uuid::Uuid::new_v4()));
    let state = FsState::default();
    plant_missing(std::slice::from_ref(&path), &state);
    std::fs::write(&path, b"real user data").unwrap();
    let config = Arc::new(RwLock::new(AgentConfig::default()));
    let (tx, mut rx) = tokio::sync::mpsc::channel(8);
    reconcile_removed(&tx, "agent", "host", &config, &state);
    assert_eq!(std::fs::read(&path).unwrap(), b"real user data");
    assert!(!owns_path(&path));
    assert_eq!(
        revoked_events(&mut rx),
        vec![(path.display().to_string(), false)]
    );
    std::fs::remove_file(path).unwrap();
}

#[test]
fn unplantable_path_is_reported_once() {
    let path = std::env::temp_dir().join(format!("trapd-win-exists-{}", uuid::Uuid::new_v4()));
    std::fs::write(&path, b"real credentials").unwrap();
    let state = FsState::default();
    plant_missing(std::slice::from_ref(&path), &state);
    plant_missing(std::slice::from_ref(&path), &state);
    let failures = state.take_failures();
    assert_eq!(failures.len(), 1);
    assert_eq!(failures[0].0, path);
    assert!(state.take_failures().is_empty());
    std::fs::remove_file(path).unwrap();
}

#[test]
fn unlisted_unmanaged_file_is_left_in_place_and_reported() {
    let _serial = serialize();
    let path = std::env::temp_dir().join(format!("trapd-win-foreign-{}", uuid::Uuid::new_v4()));
    std::fs::write(&path, b"someone else's file").unwrap();
    let state = FsState::default();
    plant_missing(std::slice::from_ref(&path), &state);
    let config = Arc::new(RwLock::new(AgentConfig::default()));
    let (tx, mut rx) = tokio::sync::mpsc::channel(8);
    reconcile_removed(&tx, "agent", "host", &config, &state);
    assert_eq!(std::fs::read(&path).unwrap(), b"someone else's file");
    assert_eq!(
        revoked_events(&mut rx),
        vec![(path.display().to_string(), false)]
    );
    // Reported once only.
    reconcile_removed(&tx, "agent", "host", &config, &state);
    assert!(revoked_events(&mut rx).is_empty());
    std::fs::remove_file(path).unwrap();
}

#[test]
fn last_access_setting_maps_to_detection_mode() {
    assert_eq!(last_access_mode(None), "last_access");
    assert_eq!(last_access_mode(Some(0)), "last_access");
    assert_eq!(last_access_mode(Some(1)), "tamper_only");
    assert_eq!(last_access_mode(Some(0x8000_0000)), "last_access"); // user, enabled
    assert_eq!(last_access_mode(Some(0x8000_0001)), "tamper_only"); // user, disabled
    assert_eq!(last_access_mode(Some(0x8000_0002)), "last_access"); // system, enabled
    assert_eq!(last_access_mode(Some(0x8000_0003)), "tamper_only"); // system, disabled
    assert!(read_detection_mode() == "last_access" || read_detection_mode() == "tamper_only");
}

#[test]
fn registry_entries_are_not_treated_as_files() {
    let cfg = AgentConfig {
        honeytoken_paths: vec![
            "C:\\Data\\notes.txt".into(),
            "HKLM\\SOFTWARE\\TRAPD\\Honeytokens".into(),
        ],
        ..AgentConfig::default()
    };
    let config = Arc::new(RwLock::new(cfg));
    assert_eq!(
        desired_file_paths(&config),
        vec![PathBuf::from("C:\\Data\\notes.txt")]
    );
}
