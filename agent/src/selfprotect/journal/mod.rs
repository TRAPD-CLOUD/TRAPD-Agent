//! Hash-chained, signed tamper journal (Phase 09, L5).
//!
//! Every security-relevant local event (all `selfprotect.*` findings, service
//! start/stop, planned-stop markers, config and policy changes) is appended to
//! an append-only file in the state directory. Each entry carries a sequence
//! number and the hash of its predecessor, and is signed with the identity key:
//!
//! ```text
//! entry      = JSON {"payload":..,"prev_hash":"<hex>","seq":N,"ts":"..","type":"..","v":1}
//! entry_hash = lowercase hex SHA-256 of the entry's UTF-8 bytes
//! signature  = identity.sign("trapd-journal-v1\n" + entry_hash)   (ECDSA P-256, DER)
//! file line  = {"e":"<entry text>","s":"<signature base64>"}
//! ```
//!
//! The backend verifies the signature with the key bound to the agent and keeps
//! the last accepted `(seq, hash)`. What this defends against (T13): an attacker
//! who deletes or rewrites journal entries before they are acknowledged, or
//! restores an older copy of the state, produces a chain the backend has already
//! seen differently: a missing sequence number, a fork, or a seq regression
//! raises `selfprotect.journal_gap`.
//!
//! Limits, stated plainly:
//! * An attacker who can *use the identity key* (SYSTEM on a software-key host)
//!   can sign a fresh, consistent chain. With a TPM-held key they can still ask
//!   the TPM to sign, but they cannot take the key elsewhere. The journal makes
//!   deletion detectable, it does not make a rooted host trustworthy.
//! * Entries that were never uploaded (backend unreachable, host killed) can
//!   still be deleted without a trace until the next upload. Their *absence* is
//!   detected as soon as any later entry arrives.
//!
//! Bounded size: at most [`Limits::max_unacked`] unacknowledged entries. Entries
//! are never dropped to make room. When full, the journal writes a
//! `journal_truncated` marker as its last slot and then counts what it has to
//! refuse; the next marker (written once space is free again) carries that
//! count, so nothing is lost silently and the chain stays contiguous.

use std::collections::VecDeque;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

use anyhow::{anyhow, bail, Context, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use chrono::{SecondsFormat, Utc};
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use p256::pkcs8::DecodePublicKey;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::sync::Notify;
use tracing::{error, warn};

use crate::identity::IdentityKey;
use crate::schema::{AgentEvent, EventData};

pub mod upload;

/// Prefix of the signed message (the hex entry hash follows).
pub const SIGNATURE_PREFIX: &str = "trapd-journal-v1\n";
/// `prev_hash` of the first entry.
pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";
pub const FILE_NAME: &str = "tamper_journal.ndjson";
/// Hard cap of one serialized entry; larger payloads are replaced by a digest.
/// Stays well below the backend's 8 KiB limit.
pub const MAX_ENTRY_BYTES: usize = 6000;
/// Retained acknowledged entries before the file is rewritten.
const COMPACT_AFTER: usize = 32;
const MAX_TEXT: usize = 256;

#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub max_unacked: usize,
    pub max_bytes: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_unacked: 2000,
            max_bytes: 4 * 1024 * 1024,
        }
    }
}

/// Serialized with a fixed field order (alphabetical), so the text the agent
/// signs is stable. The backend never re-serializes: it hashes these bytes.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EntryBody {
    payload: Value,
    prev_hash: String,
    seq: u64,
    ts: String,
    #[serde(rename = "type")]
    kind: String,
    v: u8,
}

#[derive(Serialize, Deserialize, Clone)]
struct Line {
    e: String,
    s: String,
}

#[derive(Clone)]
struct Stored {
    seq: u64,
    hash: String,
    line: Line,
}

/// One entry as it goes over the wire.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct WireEntry {
    pub entry: String,
    pub signature: String,
}

/// Outcome of applying the backend's acknowledgement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AckOutcome {
    Acked,
    /// The backend's view and ours disagree (state restored, journal replaced,
    /// chain forked). Nothing is dropped; the condition is reported loudly.
    Diverged(&'static str),
}

struct Inner {
    entries: VecDeque<Stored>,
    next_seq: u64,
    last_hash: String,
    acked: u64,
    bytes: u64,
    /// A `journal_full` marker is in the chain and events are being refused.
    overflowing: bool,
    dropped: u64,
    /// The journal was full when the process last stopped; the events refused since then
    /// were not persisted, so the closing marker cannot give an exact count.
    dropped_before_restart_unknown: bool,
}

pub struct Journal {
    path: PathBuf,
    key: Arc<dyn IdentityKey>,
    verifier: VerifyingKey,
    limits: Limits,
    inner: Mutex<Inner>,
    notify: Notify,
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn signed_message(hash: &str) -> Vec<u8> {
    format!("{SIGNATURE_PREFIX}{hash}").into_bytes()
}

fn cap(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

/// Entry types are `[a-z0-9_.]{1,64}` on the wire.
fn sanitize_kind(kind: &str) -> String {
    let s: String = kind
        .to_ascii_lowercase()
        .chars()
        .map(|c| {
            if c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .take(64)
        .collect();
    if s.is_empty() {
        "unknown".into()
    } else {
        s
    }
}

impl Journal {
    /// Open (or create) the journal in `dir`. Verifies every stored entry:
    /// signature, hash chain, sequence. A torn last line (crash mid-append) is
    /// dropped silently; any other damage keeps the valid prefix, quarantines
    /// the original file and records a `journal_corrupt` entry.
    pub fn open(dir: &Path, key: Arc<dyn IdentityKey>, limits: Limits) -> Result<Self> {
        let verifier = VerifyingKey::from_public_key_der(&key.public_key_spki_der())
            .map_err(|e| anyhow!("identity key is not a P-256 SPKI: {e}"))?;
        let path = dir.join(FILE_NAME);
        let mut journal = Self {
            path,
            key,
            verifier,
            limits,
            inner: Mutex::new(Inner {
                entries: VecDeque::new(),
                next_seq: 1,
                last_hash: GENESIS_HASH.to_string(),
                acked: 0,
                bytes: 0,
                overflowing: false,
                dropped: 0,
                dropped_before_restart_unknown: false,
            }),
            notify: Notify::new(),
        };
        journal.load()?;
        Ok(journal)
    }

    fn load(&mut self) -> Result<()> {
        // 2x: the file may legitimately hold acknowledged history until compaction.
        let raw = match crate::paths::bounded_regular_bytes(&self.path, self.limits.max_bytes * 2) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => {
                // Oversized, a link or unreadable: quarantine like corruption.
                warn!(error = %e, "tamper journal unreadable; starting a new chain");
                let q = self.quarantine().ok();
                return self.after_corruption(Vec::new(), 1, q);
            }
        };
        let torn_tail = !raw.is_empty() && !raw.ends_with(b"\n");
        let text = String::from_utf8_lossy(&raw).into_owned();
        let lines: Vec<&str> = text.lines().collect();
        let mut good: Vec<Stored> = Vec::new();
        let mut bad_from: Option<usize> = None;
        for (i, l) in lines.iter().enumerate() {
            match self.verify_line(l, good.last()) {
                Ok(s) => good.push(s),
                Err(e) => {
                    let is_torn_tail = torn_tail && i + 1 == lines.len();
                    if is_torn_tail {
                        warn!("tamper journal: dropping a torn last line");
                    } else {
                        warn!(line = i + 1, error = %e, "tamper journal: damaged entry");
                        bad_from = Some(i);
                    }
                    break;
                }
            }
        }
        match bad_from {
            None => {
                let rewrite = torn_tail;
                self.install(good);
                if rewrite {
                    self.rewrite_file()?;
                }
                Ok(())
            }
            Some(i) => {
                let lost = lines.len() - i;
                let q = self.quarantine().ok();
                self.after_corruption(good, lost, q)
            }
        }
    }

    fn after_corruption(
        &mut self,
        good: Vec<Stored>,
        lost_lines: usize,
        quarantined: Option<String>,
    ) -> Result<()> {
        let kept = good.len();
        self.install(good);
        self.rewrite_file()?;
        self.append_locked(
            "journal_corrupt",
            json!({
                "valid_entries": kept,
                "discarded_lines": lost_lines,
                "quarantined_as": quarantined,
            }),
            true,
        )?;
        Ok(())
    }

    fn quarantine(&self) -> Result<String> {
        let name = format!("{FILE_NAME}.corrupt-{}", Utc::now().timestamp());
        let target = self.path.with_file_name(&name);
        std::fs::rename(&self.path, &target)
            .with_context(|| format!("quarantine {}", self.path.display()))?;
        Ok(name)
    }

    fn install(&mut self, good: Vec<Stored>) {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.bytes = good.iter().map(|s| s.line.e.len() as u64 + 120).sum();
        if let Some(last) = good.last() {
            inner.next_seq = last.seq + 1;
            inner.last_hash = last.hash.clone();
        }
        // A `journal_full` marker without its closing `overflow_dropped` means the previous run
        // ended while events were being refused: stay in that state instead of forgetting it
        // (and of writing a second full marker beyond the entry cap).
        let mut overflowing = false;
        for s in &good {
            if let Ok(b) = serde_json::from_str::<EntryBody>(&s.line.e) {
                if b.kind == "journal_truncated" {
                    match b.payload.get("reason").and_then(Value::as_str) {
                        Some("journal_full") => overflowing = true,
                        Some("overflow_dropped") => overflowing = false,
                        _ => {}
                    }
                }
            }
        }
        inner.overflowing = overflowing;
        inner.dropped_before_restart_unknown = overflowing;
        inner.entries = good.into();
    }

    fn verify_line(&self, raw: &str, prev: Option<&Stored>) -> Result<Stored> {
        let line: Line = serde_json::from_str(raw).context("not a journal line")?;
        let body: EntryBody = serde_json::from_str(&line.e).context("not an entry")?;
        if body.v != 1 {
            bail!("unsupported entry version {}", body.v);
        }
        let hash = sha256_hex(line.e.as_bytes());
        let sig = Signature::from_der(&B64.decode(&line.s).context("signature base64")?)
            .map_err(|e| anyhow!("signature der: {e}"))?;
        self.verifier
            .verify(&signed_message(&hash), &sig)
            .map_err(|_| anyhow!("signature does not verify"))?;
        if let Some(p) = prev {
            if body.seq != p.seq + 1 || body.prev_hash != p.hash {
                bail!("chain broken at seq {}", body.seq);
            }
        } else if body.seq == 0 {
            bail!("seq 0");
        }
        Ok(Stored {
            seq: body.seq,
            hash,
            line,
        })
    }

    fn rewrite_file(&self) -> Result<()> {
        let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let mut out = String::new();
        for s in &inner.entries {
            out.push_str(&serde_json::to_string(&s.line)?);
            out.push('\n');
        }
        crate::paths::write_atomic(&self.path, out.as_bytes(), 0o600)
    }

    // ── append ──────────────────────────────────────────────────────────────

    /// Append an entry. Returns its sequence number, or `None` when the journal
    /// is full and the entry was refused (counted in the next `journal_truncated`
    /// marker). Errors leave the chain untouched.
    pub fn append(&self, kind: &str, payload: Value) -> Result<Option<u64>> {
        self.append_locked(kind, payload, false)
    }

    fn unacked(inner: &Inner) -> usize {
        inner.entries.iter().filter(|s| s.seq > inner.acked).count()
    }

    fn append_locked(&self, kind: &str, payload: Value, force: bool) -> Result<Option<u64>> {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if !force {
            let unacked = Self::unacked(&inner);
            let full =
                unacked + 1 >= self.limits.max_unacked || inner.bytes >= self.limits.max_bytes;
            if full {
                if !inner.overflowing {
                    inner.overflowing = true;
                    inner.dropped = 0;
                    inner.dropped_before_restart_unknown = false;
                    self.write_entry(
                        &mut inner,
                        "journal_truncated",
                        json!({"reason": "journal_full", "dropped_events": 0u64, "unacked": unacked}),
                    )?;
                }
                inner.dropped += 1;
                return Ok(None);
            }
            if inner.overflowing && unacked <= self.limits.max_unacked / 2 {
                let dropped = inner.dropped;
                let unknown = inner.dropped_before_restart_unknown;
                self.write_entry(
                    &mut inner,
                    "journal_truncated",
                    json!({
                        "reason": "overflow_dropped",
                        "dropped_events": dropped,
                        // True when a restart happened while full: the count is then a lower bound.
                        "dropped_events_incomplete": unknown,
                    }),
                )?;
                inner.overflowing = false;
                inner.dropped = 0;
                inner.dropped_before_restart_unknown = false;
            }
        }
        let seq = self.write_entry(&mut inner, kind, payload)?;
        drop(inner);
        self.notify.notify_one();
        Ok(Some(seq))
    }

    fn write_entry(&self, inner: &mut Inner, kind: &str, payload: Value) -> Result<u64> {
        let seq = inner.next_seq;
        let mut body = EntryBody {
            payload,
            prev_hash: inner.last_hash.clone(),
            seq,
            ts: Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
            kind: sanitize_kind(kind),
            v: 1,
        };
        let mut text = serde_json::to_string(&body)?;
        if text.len() > MAX_ENTRY_BYTES {
            let digest = sha256_hex(&serde_json::to_vec(&body.payload)?);
            body.payload = json!({"truncated": true, "payload_sha256": digest});
            text = serde_json::to_string(&body)?;
        }
        let hash = sha256_hex(text.as_bytes());
        let sig = self
            .key
            .sign(&signed_message(&hash))
            .context("sign journal entry")?;
        let line = Line {
            e: text,
            s: B64.encode(sig),
        };
        let mut encoded = serde_json::to_string(&line)?;
        encoded.push('\n');
        self.append_to_file(encoded.as_bytes())?;
        inner.bytes += encoded.len() as u64;
        inner.next_seq = seq + 1;
        inner.last_hash = hash.clone();
        inner.entries.push_back(Stored { seq, hash, line });
        Ok(seq)
    }

    fn append_to_file(&self, bytes: &[u8]) -> Result<()> {
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        // Write + explicit seek instead of append mode: on Windows an append-only
        // handle lacks FILE_WRITE_DATA, so `set_len` in `rollback_on_error` could
        // not cut off a partial record. Appends are serialized by the journal lock.
        let mut opts = std::fs::OpenOptions::new();
        opts.create(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            opts.mode(0o600);
        }
        let mut f = opts
            .open(&self.path)
            .with_context(|| format!("open {}", self.path.display()))?;
        let start = {
            use std::io::Seek as _;
            f.seek(std::io::SeekFrom::End(0))?
        };
        let result = f.write_all(bytes).and_then(|()| f.sync_data());
        rollback_on_error(&f, start, result)?;
        Ok(())
    }

    // ── upload side ─────────────────────────────────────────────────────────

    /// Entries the backend has not acknowledged, oldest first.
    pub fn pending(&self, max: usize) -> Vec<WireEntry> {
        let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner
            .entries
            .iter()
            .filter(|s| s.seq > inner.acked)
            .take(max)
            .map(|s| WireEntry {
                entry: s.line.e.clone(),
                signature: s.line.s.clone(),
            })
            .collect()
    }

    /// Sequence number of the oldest unacknowledged entry.
    pub fn first_pending_seq(&self) -> Option<u64> {
        let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner
            .entries
            .iter()
            .find(|s| s.seq > inner.acked)
            .map(|s| s.seq)
    }

    pub fn has_pending(&self) -> bool {
        let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.entries.back().is_some_and(|s| s.seq > inner.acked)
    }

    /// `(next_seq - 1, last_hash)`: the head of our chain.
    #[cfg(test)]
    pub fn head(&self) -> (u64, String) {
        let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        (inner.next_seq - 1, inner.last_hash.clone())
    }

    pub(crate) fn notified(&self) -> tokio::sync::futures::Notified<'_> {
        self.notify.notified()
    }

    /// Apply the backend's `(last_seq, last_hash)`.
    pub fn ack(&self, last_seq: u64, last_hash: &str) -> AckOutcome {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if last_seq == 0 {
            inner.acked = 0;
            return AckOutcome::Acked;
        }
        let head = inner.next_seq - 1;
        if last_seq > head {
            return AckOutcome::Diverged(
                "backend is ahead of this journal (state restored or replaced)",
            );
        }
        let Some(found) = inner.entries.iter().find(|s| s.seq == last_seq) else {
            return AckOutcome::Diverged("backend position is older than the retained history");
        };
        if found.hash != last_hash {
            return AckOutcome::Diverged("backend holds a different entry at that position (fork)");
        }
        inner.acked = last_seq;
        let acked = inner.acked;
        let old = inner.entries.iter().filter(|s| s.seq < acked).count();
        if old >= COMPACT_AFTER {
            // Keep the acknowledged entry itself as the chain anchor.
            while inner.entries.front().is_some_and(|s| s.seq < acked) {
                inner.entries.pop_front();
            }
            inner.bytes = inner
                .entries
                .iter()
                .map(|s| s.line.e.len() as u64 + 120)
                .sum();
            drop(inner);
            if let Err(e) = self.rewrite_file() {
                warn!(error = %e, "tamper journal: compaction failed");
            }
        }
        AckOutcome::Acked
    }

    // ── event adapters ──────────────────────────────────────────────────────

    /// Journal an agent event when it is a self-protection finding.
    pub fn observe_event(&self, event: &AgentEvent) {
        let Some((kind, payload)) = describe_event(event) else {
            return;
        };
        if let Err(e) = self.append(&kind, payload) {
            error!(error = %e, "tamper journal: could not append");
        }
    }
}

/// A failed append (disk full, failed sync) must not leave a partial record behind: the next
/// successful append would concatenate onto it, and `load` would discard everything after the
/// damaged line. Restore the file to its length before the append, so the in-memory chain
/// (which did not advance) and the file agree again.
fn rollback_on_error(f: &std::fs::File, start: u64, result: std::io::Result<()>) -> Result<()> {
    if let Err(e) = result {
        if let Err(trunc) = f.set_len(start) {
            error!(error = %trunc, "tamper journal: could not restore the file after a failed append");
        }
        return Err(anyhow!("append to the tamper journal failed: {e}"));
    }
    Ok(())
}

/// The journal entry for an event, `None` for events that are not
/// self-protection findings.
fn describe_event(event: &AgentEvent) -> Option<(String, Value)> {
    match &event.data {
        EventData::Detection(d) if d.rule_id.starts_with("selfprotect.") => Some((
            d.rule_id.clone(),
            json!({
                "event_id": event.event_id,
                "rule_id": cap(&d.rule_id, MAX_TEXT),
                "title": cap(&d.title, MAX_TEXT),
                "severity": event.severity,
                "subject": cap(&d.subject, MAX_TEXT),
                "event_ts": event.timestamp.to_rfc3339_opts(SecondsFormat::Millis, true),
            }),
        )),
        EventData::AgentTamper(t) => Some((
            "agent_tamper".into(),
            json!({
                "event_id": event.event_id,
                "path": cap(&t.path, MAX_TEXT),
                "action": cap(&t.action, 64),
                "severity": event.severity,
            }),
        )),
        _ => None,
    }
}

// ── process-wide handle ─────────────────────────────────────────────────────

static GLOBAL: OnceLock<Arc<Journal>> = OnceLock::new();

/// Install the process journal. Only the first call wins.
pub fn install(journal: Arc<Journal>) -> bool {
    GLOBAL.set(journal).is_ok()
}

/// The single choke point for events: called by `Spool::push`, which every
/// event (consumer path and direct stop/tamper alerts alike) passes through.
/// A no-op until the journal is installed (offline mode, early start-up).
pub fn observe(event: &AgentEvent) {
    if let Some(j) = GLOBAL.get() {
        j.observe_event(event);
    }
}

/// Journal a lifecycle or configuration fact (`service_start`, `service_stop`,
/// `config_changed`, `stop_marker`, ...). Never fails the caller.
pub fn record(kind: &str, payload: Value) {
    if let Some(j) = GLOBAL.get() {
        if let Err(e) = j.append(kind, payload) {
            error!(error = %e, kind, "tamper journal: could not append");
        }
    }
}

/// Count of entry kinds currently retained (diagnostics and tests).
#[cfg(test)]
fn kinds(journal: &Journal) -> std::collections::BTreeMap<String, usize> {
    let inner = journal.inner.lock().unwrap();
    let mut m = std::collections::BTreeMap::new();
    for s in &inner.entries {
        if let Ok(b) = serde_json::from_str::<EntryBody>(&s.line.e) {
            *m.entry(b.kind).or_insert(0) += 1;
        }
    }
    m
}

#[cfg(test)]
mod tests;
