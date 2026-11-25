use super::*;
use p256::ecdsa::{signature::Signer, SigningKey};
use p256::pkcs8::EncodePublicKey;

struct TestKey(SigningKey);

impl TestKey {
    fn new() -> Self {
        // Distinct key per instance (some tests need a foreign key); small
        // non-zero scalars are valid P-256 secret keys.
        static NEXT: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(1);
        let mut secret = [0u8; 32];
        secret[31] = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Self(SigningKey::from_slice(&secret).unwrap())
    }
}

impl IdentityKey for TestKey {
    fn public_key_spki_der(&self) -> Vec<u8> {
        p256::PublicKey::from(self.0.verifying_key())
            .to_public_key_der()
            .unwrap()
            .as_bytes()
            .to_vec()
    }
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        let sig: Signature = self.0.sign(msg);
        Ok(sig.to_der().as_bytes().to_vec())
    }
    fn protection(&self) -> crate::identity::Protection {
        crate::identity::Protection::Software
    }
}

struct Dir(PathBuf);
impl Dir {
    fn new(tag: &str) -> Self {
        let p = std::env::temp_dir().join(format!("trapd-journal-{tag}-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&p).unwrap();
        Self(p)
    }
}
impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn open(dir: &Dir, key: &Arc<TestKey>) -> Journal {
    Journal::open(&dir.0, key.clone(), Limits::default()).unwrap()
}

fn small(max: usize) -> Limits {
    Limits {
        max_unacked: max,
        max_bytes: 4 * 1024 * 1024,
    }
}

fn body(e: &WireEntry) -> EntryBody {
    serde_json::from_str(&e.entry).unwrap()
}

/// What the backend does: hash the bytes, verify the signature, check the chain.
fn verify_chain(entries: &[WireEntry], key: &TestKey, start_prev: &str, start_seq: u64) {
    let vk = *key.0.verifying_key();
    let mut prev = start_prev.to_string();
    for (seq, e) in (start_seq..).zip(entries) {
        let hash = sha256_hex(e.entry.as_bytes());
        let sig = Signature::from_der(&B64.decode(&e.signature).unwrap()).unwrap();
        vk.verify(&signed_message(&hash), &sig).expect("signature");
        let b = body(e);
        assert_eq!(b.seq, seq);
        assert_eq!(b.prev_hash, prev);
        prev = hash;
    }
}

#[test]
fn chain_is_contiguous_hashed_and_signed() {
    let dir = Dir::new("chain");
    let key = Arc::new(TestKey::new());
    let j = open(&dir, &key);
    for i in 0..5 {
        assert_eq!(
            j.append("selfprotect.test", json!({"i": i})).unwrap(),
            Some(i + 1)
        );
    }
    let pending = j.pending(100);
    assert_eq!(pending.len(), 5);
    verify_chain(&pending, &key, GENESIS_HASH, 1);
    assert_eq!(j.head().0, 5);
}

#[test]
fn entry_text_has_the_documented_shape() {
    let dir = Dir::new("shape");
    let key = Arc::new(TestKey::new());
    let j = open(&dir, &key);
    j.append("Selfprotect.Bad Kind!", json!({})).unwrap();
    let e = &j.pending(1)[0];
    let b = body(e);
    assert_eq!(b.kind, "selfprotect.bad_kind_");
    assert_eq!(b.v, 1);
    assert!(
        e.entry.starts_with("{\"payload\":"),
        "stable field order: {}",
        e.entry
    );
}

#[test]
fn restart_keeps_seq_and_chain() {
    let dir = Dir::new("restart");
    let key = Arc::new(TestKey::new());
    {
        let j = open(&dir, &key);
        j.append("a", json!({})).unwrap();
        j.append("b", json!({})).unwrap();
    }
    let j = open(&dir, &key);
    assert_eq!(j.head().0, 2);
    assert_eq!(j.append("c", json!({})).unwrap(), Some(3));
    verify_chain(&j.pending(100), &key, GENESIS_HASH, 1);
}

#[test]
fn recovery_counts_dense_blank_lines_without_indexing_each_line() {
    let dir = Dir::new("many-lines");
    let key = Arc::new(TestKey::new());
    std::fs::write(dir.0.join(FILE_NAME), vec![b'\n'; 100_000]).unwrap();
    let journal = open(&dir, &key);
    let pending = journal.pending(1);
    assert_eq!(body(&pending[0]).payload["discarded_lines"], 100_000);
}

#[test]
fn torn_last_line_is_dropped_without_a_corruption_entry() {
    let dir = Dir::new("torn");
    let key = Arc::new(TestKey::new());
    {
        let j = open(&dir, &key);
        j.append("a", json!({})).unwrap();
        j.append("b", json!({})).unwrap();
    }
    let path = dir.0.join(FILE_NAME);
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap();
    f.write_all(b"{\"e\":\"{\\\"payl").unwrap();
    drop(f);
    let j = open(&dir, &key);
    assert_eq!(j.head().0, 2);
    assert_eq!(kinds(&j).get("journal_corrupt"), None);
    assert_eq!(j.append("c", json!({})).unwrap(), Some(3));
    assert!(std::fs::read_to_string(&path).unwrap().ends_with('\n'));
}

#[test]
fn edited_entry_is_detected_quarantined_and_recorded() {
    let dir = Dir::new("edit");
    let key = Arc::new(TestKey::new());
    {
        let j = open(&dir, &key);
        for i in 0..4 {
            j.append("selfprotect.x", json!({"i": i})).unwrap();
        }
    }
    let path = dir.0.join(FILE_NAME);
    let text = std::fs::read_to_string(&path).unwrap();
    // rewrite history: change a payload inside entry 3 without re-signing
    let tampered = text.replacen("\\\"i\\\":2", "\\\"i\\\":9", 1);
    assert_ne!(text, tampered);
    std::fs::write(&path, tampered).unwrap();
    let j = open(&dir, &key);
    // valid prefix (2 entries) + journal_corrupt at seq 3
    assert_eq!(j.head().0, 3);
    let p = j.pending(100);
    assert_eq!(body(&p[2]).kind, "journal_corrupt");
    assert_eq!(body(&p[2]).payload["discarded_lines"], 2);
    verify_chain(&p, &key, GENESIS_HASH, 1);
    let quarantined = std::fs::read_dir(&dir.0)
        .unwrap()
        .filter_map(|e| e.ok())
        .any(|e| e.file_name().to_string_lossy().contains(".corrupt-"));
    assert!(quarantined, "original file must be kept as evidence");
}

#[test]
fn deleted_line_in_the_middle_breaks_the_chain() {
    let dir = Dir::new("delete");
    let key = Arc::new(TestKey::new());
    {
        let j = open(&dir, &key);
        for i in 0..4 {
            j.append("a", json!({ "i": i })).unwrap();
        }
    }
    let path = dir.0.join(FILE_NAME);
    let text = std::fs::read_to_string(&path).unwrap();
    let kept: Vec<&str> = text
        .lines()
        .enumerate()
        .filter(|(i, _)| *i != 1)
        .map(|(_, l)| l)
        .collect();
    std::fs::write(&path, kept.join("\n") + "\n").unwrap();
    let j = open(&dir, &key);
    assert_eq!(kinds(&j).get("journal_corrupt"), Some(&1));
    assert_eq!(j.head().0, 2); // entry 1 + journal_corrupt
}

#[test]
fn a_foreign_key_cannot_continue_the_journal() {
    let dir = Dir::new("foreign");
    let key = Arc::new(TestKey::new());
    {
        let j = open(&dir, &key);
        j.append("a", json!({})).unwrap();
    }
    let other = Arc::new(TestKey::new());
    let j = open(&dir, &other);
    // nothing verifies under the new key: new chain from seq 1, loudly marked
    let p = j.pending(10);
    assert_eq!(body(&p[0]).kind, "journal_corrupt");
    assert_eq!(body(&p[0]).seq, 1);
}

#[test]
fn deleted_journal_file_restarts_the_chain_at_genesis() {
    let dir = Dir::new("wiped");
    let key = Arc::new(TestKey::new());
    {
        let j = open(&dir, &key);
        for _ in 0..3 {
            j.append("a", json!({})).unwrap();
        }
    }
    std::fs::remove_file(dir.0.join(FILE_NAME)).unwrap();
    let j = open(&dir, &key);
    // The agent cannot know; the backend sees seq 1 again (regression/fork).
    assert_eq!(j.append("b", json!({})).unwrap(), Some(1));
}

#[test]
fn ack_tracks_the_backend_and_compacts_keeping_the_anchor() {
    let dir = Dir::new("ack");
    let key = Arc::new(TestKey::new());
    let j = open(&dir, &key);
    for _ in 0..50 {
        j.append("a", json!({})).unwrap();
    }
    let p = j.pending(100);
    let hash40 = sha256_hex(p[39].entry.as_bytes());
    assert_eq!(j.ack(40, &hash40), AckOutcome::Acked);
    let rest = j.pending(100);
    assert_eq!(rest.len(), 10);
    assert_eq!(body(&rest[0]).seq, 41);
    // file now starts at the anchor (seq 40) and chain verification still works
    let j2 = open(&dir, &key);
    assert_eq!(j2.head().0, 50);
    let all = j2.pending(100);
    assert_eq!(body(&all[0]).seq, 40);
    verify_chain(&all, &key, &body(&all[0]).prev_hash, 40);
}

#[test]
fn ack_with_a_foreign_hash_or_a_future_seq_is_divergence() {
    let dir = Dir::new("diverge");
    let key = Arc::new(TestKey::new());
    let j = open(&dir, &key);
    for _ in 0..3 {
        j.append("a", json!({})).unwrap();
    }
    assert!(matches!(j.ack(2, &"f".repeat(64)), AckOutcome::Diverged(_)));
    assert!(matches!(j.ack(9, &"f".repeat(64)), AckOutcome::Diverged(_)));
    assert_eq!(j.pending(10).len(), 3, "nothing is dropped on divergence");
}

#[test]
fn restoring_an_old_journal_file_is_visible_as_backend_ahead() {
    let dir = Dir::new("restore");
    let key = Arc::new(TestKey::new());
    let path = dir.0.join(FILE_NAME);
    let (old_copy, hash5) = {
        let j = open(&dir, &key);
        for _ in 0..3 {
            j.append("a", json!({})).unwrap();
        }
        let copy = std::fs::read(&path).unwrap();
        for _ in 0..2 {
            j.append("a", json!({})).unwrap();
        }
        (copy, j.head().1)
    };
    // attacker restores the old file; backend already has seq 5
    std::fs::write(&path, old_copy).unwrap();
    let j = open(&dir, &key);
    assert_eq!(j.head().0, 3);
    assert!(matches!(j.ack(5, &hash5), AckOutcome::Diverged(_)));
}

#[test]
fn full_journal_never_drops_entries_and_says_so() {
    let dir = Dir::new("full");
    let key = Arc::new(TestKey::new());
    let j = Journal::open(&dir.0, key.clone(), small(10)).unwrap();
    let mut accepted = 0;
    for i in 0..25 {
        if j.append("selfprotect.flood", json!({ "i": i }))
            .unwrap()
            .is_some()
        {
            accepted += 1;
        }
    }
    // 9 events fit; the 10th slot is the journal_full marker
    assert_eq!(accepted, 9);
    let p = j.pending(100);
    assert_eq!(p.len(), 10);
    assert_eq!(body(&p[9]).kind, "journal_truncated");
    assert_eq!(body(&p[9]).payload["reason"], "journal_full");
    verify_chain(&p, &key, GENESIS_HASH, 1);

    // backend acknowledges everything: space frees, next append writes the
    // closing marker with the exact count, then the event itself
    let (seq, hash) = j.head();
    assert_eq!(j.ack(seq, &hash), AckOutcome::Acked);
    assert!(j.append("selfprotect.after", json!({})).unwrap().is_some());
    let p = j.pending(100);
    let kinds: Vec<String> = p.iter().map(|e| body(e).kind).collect();
    assert_eq!(kinds, ["journal_truncated", "selfprotect.after"]);
    assert_eq!(body(&p[0]).payload["dropped_events"], 16);
    assert_eq!(body(&p[0]).payload["reason"], "overflow_dropped");
}

#[test]
fn oversized_payload_is_replaced_by_its_digest() {
    let dir = Dir::new("big");
    let key = Arc::new(TestKey::new());
    let j = open(&dir, &key);
    j.append("selfprotect.big", json!({ "blob": "x".repeat(20_000) }))
        .unwrap();
    let e = &j.pending(1)[0];
    assert!(e.entry.len() < MAX_ENTRY_BYTES);
    assert_eq!(body(e).payload["truncated"], true);
    assert_eq!(
        body(e).payload["payload_sha256"].as_str().unwrap().len(),
        64
    );
}

fn detection(rule: &str) -> AgentEvent {
    use crate::schema::{DetectionData, EventAction, EventClass, Severity};
    AgentEvent::new(
        "agent_t".into(),
        "host".into(),
        EventClass::Detection,
        EventAction::Detected,
        Severity::High,
        EventData::Detection(Box::new(DetectionData {
            rule_id: rule.into(),
            title: "t".into(),
            subject: "s".into(),
            ..Default::default()
        })),
    )
}

#[test]
fn only_selfprotect_findings_are_journalled() {
    let dir = Dir::new("observe");
    let key = Arc::new(TestKey::new());
    let j = open(&dir, &key);
    j.observe_event(&detection("selfprotect.etw_session_stopped"));
    j.observe_event(&detection("lolbin.shell_spawns_downloader"));
    j.observe_event(&detection("selfprotect.unclean_shutdown"));
    let p = j.pending(10);
    assert_eq!(p.len(), 2);
    assert_eq!(body(&p[0]).kind, "selfprotect.etw_session_stopped");
    assert!(body(&p[0]).payload["event_id"].is_string());
}

// ── upload state machine ────────────────────────────────────────────────────

fn ack_body(j: &Journal) -> Vec<u8> {
    let (seq, hash) = j.head();
    serde_json::to_vec(&json!({"status": "ok", "last_seq": seq, "last_hash": hash})).unwrap()
}

#[test]
fn upload_responses_drive_ack_and_waiting() {
    use upload::{handle_response, Next};
    let dir = Dir::new("upload");
    let key = Arc::new(TestKey::new());
    let j = open(&dir, &key);
    j.append("a", json!({})).unwrap();
    j.append("b", json!({})).unwrap();
    let mut fails = 3;

    assert_eq!(
        handle_response(&j, 200, &ack_body(&j), &mut fails),
        Next::Continue
    );
    assert_eq!(fails, 0);
    assert!(!j.has_pending());

    j.append("c", json!({})).unwrap();
    // rejected chain: entries stay, long wait
    for status in [409u16, 422] {
        assert!(
            matches!(handle_response(&j, status, b"{}", &mut fails), Next::Wait(d) if d.as_secs() >= 600)
        );
        assert!(j.has_pending());
    }
    assert_eq!(handle_response(&j, 401, b"{}", &mut fails), Next::Reauth);
    assert!(
        matches!(handle_response(&j, 403, br#"{"error":"identity_not_bound"}"#, &mut fails), Next::Wait(d) if d.as_secs() == 300)
    );
    assert!(
        matches!(handle_response(&j, 404, b"", &mut fails), Next::Wait(d) if d.as_secs() >= 3600)
    );
    assert!(matches!(
        handle_response(&j, 500, b"", &mut fails),
        Next::Wait(_)
    ));
    assert!(fails > 0);
    assert!(j.has_pending(), "no failure ever drops entries");
}

#[test]
fn a_backend_ack_that_does_not_match_is_not_applied() {
    use upload::{handle_response, Next};
    let dir = Dir::new("badack");
    let key = Arc::new(TestKey::new());
    let j = open(&dir, &key);
    j.append("a", json!({})).unwrap();
    let mut fails = 0;
    let body = serde_json::to_vec(&json!({"status":"ok","last_seq":1,"last_hash":"0".repeat(64)}))
        .unwrap();
    assert!(matches!(
        handle_response(&j, 200, &body, &mut fails),
        Next::Wait(_)
    ));
    assert!(j.has_pending());
    assert!(matches!(
        handle_response(&j, 200, b"not json", &mut fails),
        Next::Wait(_)
    ));
}

#[test]
fn an_acknowledgement_without_fields_or_progress_backs_off_instead_of_looping() {
    use upload::{handle_response, Next};
    let dir = Dir::new("ackprogress");
    let key = Arc::new(TestKey::new());
    let j = open(&dir, &key);
    j.append("a", json!({})).unwrap();
    let mut fails = 0;

    // `{}` is not "sequence 0": it is no acknowledgement at all.
    for body in [&b"{}"[..], br#"{"last_seq":1}"#, br#"{"last_hash":"00"}"#] {
        assert!(matches!(
            handle_response(&j, 200, body, &mut fails),
            Next::Wait(_)
        ));
    }
    assert_eq!(fails, 3);

    // A well-formed acknowledgement that removes nothing must not be retried immediately either.
    let zero = format!(r#"{{"last_seq":0,"last_hash":"{GENESIS_HASH}"}}"#);
    assert!(matches!(
        handle_response(&j, 200, zero.as_bytes(), &mut fails),
        Next::Wait(_)
    ));
    assert!(j.has_pending());
}

#[test]
fn a_failed_append_restores_the_file_boundary() {
    let dir = Dir::new("rollback");
    let path = dir.0.join("record");
    std::fs::write(&path, b"complete line\n").unwrap();
    // Opened like `append_to_file` (write + seek, not append mode: Windows
    // cannot truncate through an append-only handle).
    let mut f = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
    let start = {
        use std::io::Seek as _;
        f.seek(std::io::SeekFrom::End(0)).unwrap()
    };
    {
        use std::io::Write as _;
        (&f).write_all(b"partial reco").unwrap(); // the disk filled up mid-record
    }
    let err = std::io::Error::other("no space left on device");
    assert!(rollback_on_error(&f, start, Err(err)).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), b"complete line\n");
    assert!(rollback_on_error(&f, start, Ok(())).is_ok());
}

#[test]
fn overflow_state_survives_a_restart() {
    let dir = Dir::new("overflowrestart");
    let key = Arc::new(TestKey::new());
    {
        let j = Journal::open(&dir.0, key.clone(), small(10)).unwrap();
        for i in 0..25 {
            let _ = j.append("selfprotect.flood", json!({ "i": i }));
        }
        assert_eq!(kinds(&j)["journal_truncated"], 1);
    }
    // Restart while still full: no second full marker beyond the cap, and the later closing marker
    // says its count is incomplete instead of silently reporting zero.
    let j = Journal::open(&dir.0, key.clone(), small(10)).unwrap();
    assert!(j.append("selfprotect.more", json!({})).unwrap().is_none());
    assert_eq!(kinds(&j)["journal_truncated"], 1);
    let (seq, hash) = j.head();
    assert_eq!(j.ack(seq, &hash), AckOutcome::Acked);
    assert!(j.append("selfprotect.after", json!({})).unwrap().is_some());
    let p = j.pending(100);
    let closing = body(&p[0]);
    assert_eq!(closing.payload["reason"], "overflow_dropped");
    assert_eq!(closing.payload["dropped_events_incomplete"], true);
    assert_eq!(closing.payload["dropped_events"], 1);
}
