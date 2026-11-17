//! Parsing and filtering of the system handle table (portable, unit-tested).
//!
//! `NtQuerySystemInformation(SystemExtendedHandleInformation)` returns every
//! open handle of every process. A handle to *our* process is recognised by the
//! kernel object address (`Object`): the agent opens one handle to itself,
//! finds it in the table and then every entry with the same object address is
//! a handle to the agent, whoever owns it.

pub const PROCESS_TERMINATE: u32 = 0x0001;
pub const PROCESS_CREATE_THREAD: u32 = 0x0002;
pub const PROCESS_VM_WRITE: u32 = 0x0020;
pub const PROCESS_SUSPEND_RESUME: u32 = 0x0800;

/// Access bits that let the holder kill, silence or rewrite the process.
pub const DANGEROUS_ACCESS: u32 =
    PROCESS_TERMINATE | PROCESS_CREATE_THREAD | PROCESS_VM_WRITE | PROCESS_SUSPEND_RESUME;

/// One `SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX` (x64 layout, 40 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandleEntry {
    pub object: u64,
    pub pid: u64,
    pub handle: u64,
    pub access: u32,
    pub type_index: u16,
}

const HEADER: usize = 16;
const ENTRY: usize = 40;

/// Entries of a `SYSTEM_HANDLE_INFORMATION_EX` buffer. Truncated trailing
/// entries are ignored; the advertised count is never trusted beyond the
/// buffer length.
pub fn parse_table(buf: &[u8]) -> impl Iterator<Item = HandleEntry> + '_ {
    let advertised = buf
        .get(..8)
        .map(|b| u64::from_le_bytes(b.try_into().expect("8 bytes")))
        .unwrap_or(0) as usize;
    let fit = buf.len().saturating_sub(HEADER) / ENTRY;
    (0..advertised.min(fit)).map(move |i| {
        let e = &buf[HEADER + i * ENTRY..HEADER + (i + 1) * ENTRY];
        let u64_at = |o: usize| u64::from_le_bytes(e[o..o + 8].try_into().expect("8 bytes"));
        HandleEntry {
            object: u64_at(0),
            pid: u64_at(8),
            handle: u64_at(16),
            access: u32::from_le_bytes(e[24..28].try_into().expect("4 bytes")),
            type_index: u16::from_le_bytes(e[30..32].try_into().expect("2 bytes")),
        }
    })
}

/// Names of the dangerous rights present in `mask`.
pub fn access_names(mask: u32) -> Vec<&'static str> {
    [
        (PROCESS_TERMINATE, "TERMINATE"),
        (PROCESS_CREATE_THREAD, "CREATE_THREAD"),
        (PROCESS_VM_WRITE, "VM_WRITE"),
        (PROCESS_SUSPEND_RESUME, "SUSPEND_RESUME"),
    ]
    .into_iter()
    .filter(|(bit, _)| mask & bit != 0)
    .map(|(_, n)| n)
    .collect()
}

/// A foreign process holding a dangerous handle to a watched object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Opener {
    pub pid: u64,
    /// Which watched process (`agent`, `guard`).
    pub target: &'static str,
    /// Union of the dangerous bits over all the opener's handles to the target.
    pub access: u32,
}

/// Dangerous handles to the watched `(object address, label)` pairs, grouped
/// per `(opener pid, target)`. Handles owned by `exclude_pids` (the watched
/// processes themselves) and pid 0/4 (Idle, System: kernel handles) are skipped.
pub fn find_openers<I: Iterator<Item = HandleEntry>>(
    entries: I,
    watched: &[(u64, &'static str)],
    exclude_pids: &[u64],
) -> Vec<Opener> {
    let mut out: Vec<Opener> = Vec::new();
    for e in entries {
        let Some(&(_, target)) = watched.iter().find(|(o, _)| *o == e.object) else {
            continue;
        };
        let dangerous = e.access & DANGEROUS_ACCESS;
        if dangerous == 0 || e.pid <= 4 || exclude_pids.contains(&e.pid) {
            continue;
        }
        match out
            .iter_mut()
            .find(|o| o.pid == e.pid && o.target == target)
        {
            Some(o) => o.access |= dangerous,
            None => out.push(Opener {
                pid: e.pid,
                target,
                access: dangerous,
            }),
        }
    }
    out
}

/// Where an opener may legitimately live.
#[derive(Debug, Default, Clone)]
pub struct Exclusions {
    /// e.g. `c:\windows` (lower case, no trailing backslash).
    pub system_root: String,
    /// Directory of the agent executable (lower case, no trailing backslash).
    pub own_dir: String,
    /// Operator allowlist: lower-case image base names or full paths.
    pub extra: Vec<String>,
}

/// Processes Windows itself or the agent's installation hold handles with:
/// the SCM (`services.exe`) holds a full-access handle to every service
/// process, `csrss`/`lsass`/`wininit`/`smss` are the session/security core,
/// Defender's engine scans processes. Matching needs the *path*, so a
/// look-alike in a user directory is not excused.
pub fn is_expected_opener(image: &str, ex: &Exclusions) -> bool {
    let path = image.to_ascii_lowercase().replace('/', "\\");
    if ex
        .extra
        .iter()
        .any(|e| *e == path || path.rsplit('\\').next() == Some(e.as_str()))
    {
        return true;
    }
    if !ex.own_dir.is_empty() && path.starts_with(&format!("{}\\", ex.own_dir)) {
        return true;
    }
    let name = path.rsplit('\\').next().unwrap_or("");
    let in_dir = |dir: &str| {
        !ex.system_root.is_empty() && path == format!("{}\\{}\\{}", ex.system_root, dir, name)
    };
    if matches!(
        name,
        "csrss.exe" | "lsass.exe" | "services.exe" | "wininit.exe" | "smss.exe"
    ) && in_dir("system32")
    {
        return true;
    }
    if matches!(name, "msmpeng.exe" | "nissrv.exe") {
        let defender_roots = [
            r"\programdata\microsoft\windows defender\platform\",
            r"\program files\windows defender\",
            r"\program files\microsoft security client\",
        ];
        // `<drive>:` then an anchored root: a look-alike nested deeper is not excused.
        return path.as_bytes().get(1) == Some(&b':')
            && path
                .get(2..)
                .is_some_and(|rest| defender_roots.iter().any(|r| rest.starts_with(r)));
    }
    false
}

/// Parse a pid file (`guard.pid`): one decimal pid, nothing else.
pub fn parse_pid_file(text: &str) -> Option<u32> {
    let pid: u32 = text.trim().parse().ok()?;
    (pid > 4).then_some(pid)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table(entries: &[(u64, u64, u64, u32)]) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend((entries.len() as u64).to_le_bytes());
        b.extend(0u64.to_le_bytes());
        for (object, pid, handle, access) in entries {
            b.extend(object.to_le_bytes());
            b.extend(pid.to_le_bytes());
            b.extend(handle.to_le_bytes());
            b.extend(access.to_le_bytes());
            b.extend(0u16.to_le_bytes());
            b.extend(7u16.to_le_bytes());
            b.extend(0u32.to_le_bytes());
            b.extend(0u32.to_le_bytes());
        }
        b
    }

    #[test]
    fn parses_entries_and_ignores_a_lying_count() {
        let mut buf = table(&[(0xAA, 100, 8, 0x20), (0xBB, 200, 12, 0x1)]);
        let v: Vec<_> = parse_table(&buf).collect();
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].object, 0xAA);
        assert_eq!(v[1].pid, 200);
        assert_eq!(v[0].type_index, 7);
        // Header claims far more entries than the buffer holds.
        buf[..8].copy_from_slice(&1_000_000u64.to_le_bytes());
        assert_eq!(parse_table(&buf).count(), 2);
        // A truncated trailing entry is dropped; empty / tiny buffers are safe.
        assert_eq!(parse_table(&buf[..buf.len() - 1]).count(), 1);
        assert_eq!(parse_table(&[]).count(), 0);
        assert_eq!(parse_table(&[1, 2, 3]).count(), 0);
    }

    #[test]
    fn dangerous_handles_to_watched_objects_are_grouped_per_opener() {
        let buf = table(&[
            (0xAA, 100, 8, PROCESS_VM_WRITE),
            (0xAA, 100, 9, PROCESS_TERMINATE | 0x1000),
            (0xAA, 101, 4, 0x1000),            // query only
            (0xBB, 102, 4, PROCESS_TERMINATE), // other object
            (0xAA, 4, 4, PROCESS_TERMINATE),   // System
            (0xAA, 50, 4, PROCESS_TERMINATE),  // the watched process itself
            (0xCC, 103, 4, PROCESS_SUSPEND_RESUME),
        ]);
        let found = find_openers(
            parse_table(&buf),
            &[(0xAA, "agent"), (0xCC, "guard")],
            &[50],
        );
        assert_eq!(
            found,
            vec![
                Opener {
                    pid: 100,
                    target: "agent",
                    access: PROCESS_VM_WRITE | PROCESS_TERMINATE
                },
                Opener {
                    pid: 103,
                    target: "guard",
                    access: PROCESS_SUSPEND_RESUME
                },
            ]
        );
        assert_eq!(access_names(found[0].access), vec!["TERMINATE", "VM_WRITE"]);
    }

    fn ex() -> Exclusions {
        Exclusions {
            system_root: r"c:\windows".into(),
            own_dir: r"c:\program files\trapd agent".into(),
            extra: vec!["backup.exe".into(), r"d:\tools\scan.exe".into()],
        }
    }

    #[test]
    fn system_processes_are_excused_only_at_their_real_path() {
        let e = ex();
        assert!(is_expected_opener(r"C:\Windows\System32\services.exe", &e));
        assert!(is_expected_opener(r"C:\Windows\System32\csrss.exe", &e));
        assert!(is_expected_opener(r"C:\Windows\System32\lsass.exe", &e));
        // Look-alikes are not.
        assert!(!is_expected_opener(r"C:\Users\x\AppData\csrss.exe", &e));
        assert!(!is_expected_opener(r"C:\Windows\Temp\lsass.exe", &e));
        assert!(!is_expected_opener(r"C:\Windows\System32\cmd.exe", &e));
    }

    #[test]
    fn defender_the_install_dir_and_the_allowlist_are_excused() {
        let e = ex();
        assert!(is_expected_opener(
            r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.1\MsMpEng.exe",
            &e
        ));
        assert!(!is_expected_opener(r"C:\Temp\MsMpEng.exe", &e));
        assert!(is_expected_opener(
            r"C:\Program Files\TRAPD Agent\trapd-agent.exe",
            &e
        ));
        assert!(!is_expected_opener(
            r"C:\Program Files\TRAPD Agent2\x.exe",
            &e
        ));
        assert!(is_expected_opener(r"E:\anywhere\Backup.exe", &e));
        assert!(is_expected_opener(r"D:\Tools\Scan.exe", &e));
        assert!(!is_expected_opener(r"D:\Other\Scan.exe", &e));
    }

    #[test]
    fn pid_file_parsing_is_strict() {
        assert_eq!(parse_pid_file("1234\n"), Some(1234));
        assert_eq!(parse_pid_file("  77 "), Some(77));
        assert_eq!(parse_pid_file("4"), None);
        assert_eq!(parse_pid_file("12 34"), None);
        assert_eq!(parse_pid_file("-1"), None);
        assert_eq!(parse_pid_file(""), None);
    }
}
