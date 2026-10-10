//! Content check for the few files whose change is itself a security event.
//!
//! The Windows `hosts` file redirects name resolution, so one added line is
//! enough to send a bank or an update server somewhere else. A change
//! notification says only "modified"; this module remembers the last known
//! content of such a file, so the next notification can say *what* changed
//! (hash before/after, size delta, added and removed lines) and the collector
//! can raise it as an integrity violation instead of telemetry.
//!
//! Pure comparison logic plus one bounded read; the collector owns when to
//! call it. Only small text files are kept in memory (and only the hosts file
//! is, by [`is_diffable`]): the diff is limited to a few truncated lines, so a
//! changed hosts file never ships more than a handful of host entries.

// Driven by the Windows collector; compiled and tested everywhere.
#![cfg_attr(not(windows), allow(dead_code))]

use std::io::Read;
use std::path::Path;

use sha2::{Digest, Sha256};

/// Files larger than this are neither hashed nor diffed.
const MAX_BYTES: u64 = 256 * 1024;
const MAX_DIFF_LINES: usize = 8;
const MAX_LINE_CHARS: usize = 160;

/// `norm` is the comparison form from [`super::fs_plan::normalise`].
pub fn is_hosts_file(norm: &str) -> bool {
    norm.ends_with("\\system32\\drivers\\etc\\hosts")
}

/// Files whose content is diffed (and kept in memory).
pub fn is_diffable(norm: &str) -> bool {
    is_hosts_file(norm)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    /// `sha256:<hex>`
    pub sha256: String,
    pub size: u64,
    /// Content, kept only for [`is_diffable`] files.
    pub text: Option<String>,
}

pub fn snapshot_of(bytes: &[u8], keep_text: bool) -> Snapshot {
    Snapshot {
        sha256: format!("sha256:{}", hex::encode(Sha256::digest(bytes))),
        size: bytes.len() as u64,
        text: keep_text.then(|| String::from_utf8_lossy(bytes).into_owned()),
    }
}

/// Bounded read of `path`. `None` when it is missing, unreadable or too large
/// (the caller then reports the change without a content verdict).
pub fn read_snapshot(path: &Path, keep_text: bool) -> Option<Snapshot> {
    let meta = std::fs::metadata(path).ok()?;
    if !meta.is_file() || meta.len() > MAX_BYTES {
        return None;
    }
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .ok()?
        .take(MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    (bytes.len() as u64 <= MAX_BYTES).then(|| snapshot_of(&bytes, keep_text))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Content identical to the last known state (attribute or no-op write).
    Unchanged,
    /// No earlier state to compare with.
    NoBaseline,
    Changed {
        size_delta: i64,
        summary: Option<String>,
    },
}

pub fn compare(before: Option<&Snapshot>, after: &Snapshot) -> Verdict {
    let Some(before) = before else {
        return Verdict::NoBaseline;
    };
    if before.sha256 == after.sha256 {
        return Verdict::Unchanged;
    }
    Verdict::Changed {
        size_delta: after.size as i64 - before.size as i64,
        summary: match (&before.text, &after.text) {
            (Some(a), Some(b)) => Some(line_diff(a, b)),
            _ => None,
        },
    }
}

fn clip(line: &str) -> String {
    let t: String = line.trim().chars().take(MAX_LINE_CHARS).collect();
    if line.trim().chars().count() > MAX_LINE_CHARS {
        format!("{t}…")
    } else {
        t
    }
}

/// Added and removed lines (multiset semantics: order and duplicates are
/// ignored, blank lines skipped), e.g. `+2 -1 lines; + 127.0.0.1 bank.example`.
pub fn line_diff(old: &str, new: &str) -> String {
    use std::collections::HashMap;
    let count = |text: &str| {
        let mut m: HashMap<String, i32> = HashMap::new();
        for l in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
            *m.entry(l.to_string()).or_default() += 1;
        }
        m
    };
    let (o, n) = (count(old), count(new));
    let mut added: Vec<&String> = n
        .iter()
        .filter(|(l, c)| **c > o.get(*l).copied().unwrap_or(0))
        .map(|(l, _)| l)
        .collect();
    let mut removed: Vec<&String> = o
        .iter()
        .filter(|(l, c)| **c > n.get(*l).copied().unwrap_or(0))
        .map(|(l, _)| l)
        .collect();
    added.sort();
    removed.sort();
    if added.is_empty() && removed.is_empty() {
        return "whitespace or line-order change only".to_string();
    }
    let mut out = format!("+{} -{} lines", added.len(), removed.len());
    let shown = added
        .iter()
        .map(|l| ('+', *l))
        .chain(removed.iter().map(|l| ('-', *l)));
    for (i, (sign, line)) in shown.enumerate() {
        if i >= MAX_DIFF_LINES {
            out.push_str("; …");
            break;
        }
        out.push_str(&format!("; {sign} {}", clip(line)));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOSTS: &str = "# Copyright\n127.0.0.1 localhost\n::1 localhost\n";

    #[test]
    fn only_the_hosts_file_is_diffed() {
        assert!(is_diffable("c:\\windows\\system32\\drivers\\etc\\hosts"));
        assert!(!is_diffable(
            "c:\\windows\\system32\\drivers\\etc\\services"
        ));
        assert!(!is_hosts_file(
            "c:\\windows\\system32\\drivers\\etc\\hosts.bak"
        ));
    }

    #[test]
    fn an_appended_redirect_is_reported_as_a_changed_file_with_the_added_line() {
        let a = snapshot_of(HOSTS.as_bytes(), true);
        let b = snapshot_of(
            format!("{HOSTS}203.0.113.9 update.vendor.example\n").as_bytes(),
            true,
        );
        match compare(Some(&a), &b) {
            Verdict::Changed {
                size_delta,
                summary,
            } => {
                assert_eq!(
                    size_delta,
                    "203.0.113.9 update.vendor.example\n".len() as i64
                );
                let s = summary.unwrap();
                assert!(s.starts_with("+1 -0 lines"), "{s}");
                assert!(s.contains("+ 203.0.113.9 update.vendor.example"), "{s}");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn identical_content_and_a_missing_baseline_are_distinguished() {
        let a = snapshot_of(HOSTS.as_bytes(), true);
        assert_eq!(compare(Some(&a), &a.clone()), Verdict::Unchanged);
        assert_eq!(compare(None, &a), Verdict::NoBaseline);
    }

    #[test]
    fn removals_comments_and_reordering_are_handled() {
        let d = line_diff("a\nb\n", "b\nc\n");
        assert!(d.starts_with("+1 -1 lines"), "{d}");
        assert!(d.contains("+ c") && d.contains("- a"), "{d}");
        assert_eq!(
            line_diff("a\nb\n", "b\na\n"),
            "whitespace or line-order change only"
        );
    }

    #[test]
    fn the_diff_is_bounded_in_lines_and_width() {
        let many: String = (0..50).map(|i| format!("10.0.0.{i} h{i}\n")).collect();
        let d = line_diff("", &many);
        assert!(d.starts_with("+50 -0 lines"));
        assert!(d.ends_with("; …"));
        assert!(d.matches("; +").count() <= MAX_DIFF_LINES);
        let long = "x".repeat(10_000);
        assert!(line_diff("", &long).chars().count() < 300);
    }

    #[test]
    fn non_text_snapshots_compare_by_hash_without_a_summary() {
        let a = snapshot_of(b"one", false);
        let b = snapshot_of(b"two!", false);
        assert_eq!(
            compare(Some(&a), &b),
            Verdict::Changed {
                size_delta: 1,
                summary: None
            }
        );
    }

    #[test]
    fn oversized_and_missing_files_have_no_snapshot() {
        assert!(read_snapshot(Path::new("/definitely/not/here"), true).is_none());
        let dir = std::env::temp_dir().join(format!("trapd-critical-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let big = dir.join("big");
        std::fs::write(&big, vec![b'a'; (MAX_BYTES + 1) as usize]).unwrap();
        assert!(read_snapshot(&big, true).is_none());
        let small = dir.join("small");
        std::fs::write(&small, HOSTS).unwrap();
        assert_eq!(
            read_snapshot(&small, true).unwrap().size,
            HOSTS.len() as u64
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
