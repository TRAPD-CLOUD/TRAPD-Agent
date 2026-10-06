//! Bait content for Windows decoy files.
//!
//! The Windows agent plants decoys itself from the signed config, so it also
//! has to produce their content. A decoy only works while it cannot be told
//! apart from the real artefact, and a constant shared by every decoy is worse
//! than none: an attacker who has seen one host could recognise (or grep for)
//! every other host of every tenant. So, per decoy:
//!
//!   * every secret, server name, account and date is drawn from the OS CSPRNG
//!     and shaped by the host's own identity (hostname prefix, DNS domain);
//!   * the layout varies (header, column set, ordering, entry count);
//!   * fixed text appears only where the genuine artefact has it too (the
//!     BitLocker recovery-key boilerplate is identical on every real host).
//!
//! Formats this module cannot produce faithfully (Office, KeePass, PDF, …) are
//! refused instead of filled with text a viewer would expose as fake.

use chrono::{Duration, NaiveDate, Utc};

/// Who the decoy should look like it belongs to.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostIdentity {
    /// The host's own name, e.g. `BER-WS-0142`.
    pub hostname: String,
    /// The host's DNS domain (`corp.example.eu`), when it is domain-joined.
    pub dns_domain: Option<String>,
}

/// Why no bait was produced for a path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsupportedDecoy(pub String);

impl std::fmt::Display for UnsupportedDecoy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Extensions whose genuine files are binary containers. Writing text into
/// them would be exposed the moment anyone opens the file.
const BINARY_EXTENSIONS: &[&str] = &[
    "xlsx", "xlsm", "xls", "docx", "docm", "doc", "pptx", "ppt", "pdf", "kdbx", "kdb", "zip", "7z",
    "rar", "pfx", "p12", "ppk", "vhd", "vhdx", "bak", "mdb", "accdb", "one", "sqlite", "db",
];

/// Produce bait for a decoy file named `file_name` on `host`.
pub fn generate(file_name: &str, host: &HostIdentity) -> Result<Vec<u8>, UnsupportedDecoy> {
    generate_recording(file_name, host, &mut Vec::new())
}

/// [`generate`], also returning every secret value it embedded (for tests).
fn generate_recording(
    file_name: &str,
    host: &HostIdentity,
    secrets: &mut Vec<String>,
) -> Result<Vec<u8>, UnsupportedDecoy> {
    let lower = file_name.to_ascii_lowercase();
    let ext = lower.rsplit_once('.').map(|(_, e)| e).unwrap_or("");
    if BINARY_EXTENSIONS.contains(&ext) {
        return Err(UnsupportedDecoy(format!(
            "'.{ext}' files are binary containers; a believable decoy cannot be generated for them, choose a text file (.txt, .csv, .ini, …)"
        )));
    }
    let mut rng = Rng;
    let persona = Persona::new(host, &mut rng);
    let theme = Theme::for_name(&lower);
    Ok(match theme {
        Theme::RecoveryKey => bitlocker_recovery(&mut rng, secrets),
        Theme::CredentialTable => credential_table(&persona, &mut rng, ext, secrets).into_bytes(),
        Theme::PasswordList => password_list(&persona, &mut rng, false, secrets).into_bytes(),
        Theme::BackupNotes => password_list(&persona, &mut rng, true, secrets).into_bytes(),
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Theme {
    RecoveryKey,
    CredentialTable,
    PasswordList,
    BackupNotes,
}

impl Theme {
    fn for_name(lower: &str) -> Self {
        let has = |needles: &[&str]| needles.iter().any(|n| lower.contains(n));
        if has(&["bitlocker", "recovery", "wiederherstellung"]) {
            Self::RecoveryKey
        } else if lower.ends_with(".csv") || has(&["credential", "account", "login", "zugang"]) {
            Self::CredentialTable
        } else if has(&["backup", "sicherung"]) {
            Self::BackupNotes
        } else {
            Self::PasswordList
        }
    }
}

// ── randomness ────────────────────────────────────────────────────────────────

/// Thin CSPRNG wrapper. Bait generation must never fall back to a predictable
/// source, so an unavailable OS RNG is a hard failure.
struct Rng;

impl Rng {
    fn u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        getrandom::fill(&mut b).expect("OS random number generator unavailable");
        u64::from_le_bytes(b)
    }
    /// Uniform in `0..n` (modulo bias is < 2^-50 for the small `n` used here).
    fn below(&mut self, n: usize) -> usize {
        (self.u64() % n.max(1) as u64) as usize
    }
    fn range(&mut self, lo: usize, hi: usize) -> usize {
        lo + self.below(hi - lo + 1)
    }
    fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.below(items.len())]
    }
    fn chance(&mut self, percent: usize) -> bool {
        self.below(100) < percent
    }
    fn chars(&mut self, alphabet: &[u8], n: usize) -> String {
        (0..n).map(|_| *self.pick(alphabet) as char).collect()
    }
}

const UPPER: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ";
const LOWER: &[u8] = b"abcdefghijkmnopqrstuvwxyz";
const DIGITS: &[u8] = b"0123456789";
const SYMBOLS: &[u8] = b"!#$%&*+-=?@_";

// ── persona ───────────────────────────────────────────────────────────────────

struct Persona {
    /// Site/location prefix taken from the host's own naming scheme (`BER-`).
    prefix: String,
    /// Uppercase server-name style matches the host (`SQL01` vs `sql01`).
    upper: bool,
    dns_domain: Option<String>,
    netbios: Option<String>,
}

impl Persona {
    fn new(host: &HostIdentity, rng: &mut Rng) -> Self {
        let hostname = sanitize(&host.hostname);
        let prefix = hostname
            .split_once('-')
            .map(|(p, _)| p)
            .filter(|p| (2..=6).contains(&p.len()) && p.chars().all(|c| c.is_ascii_alphabetic()))
            .map(|p| format!("{p}-"))
            .unwrap_or_default();
        let upper = if hostname.is_empty() {
            rng.chance(50)
        } else {
            !hostname.chars().any(|c| c.is_ascii_lowercase())
        };
        let dns_domain = host
            .dns_domain
            .as_deref()
            .map(sanitize)
            .filter(|d| d.contains('.') && !d.starts_with('.') && !d.ends_with('.'))
            .map(|d| d.to_ascii_lowercase());
        let netbios = dns_domain
            .as_deref()
            .and_then(|d| d.split('.').next())
            .map(|label| label.to_ascii_uppercase())
            .filter(|label| !label.is_empty() && label.len() <= 15);
        Self {
            prefix: if upper {
                prefix.to_ascii_uppercase()
            } else {
                prefix.to_ascii_lowercase()
            },
            upper,
            dns_domain,
            netbios,
        }
    }

    /// A server name in the host's naming scheme, sometimes fully qualified.
    fn server(&self, role: &str, rng: &mut Rng) -> String {
        let number = if rng.chance(70) {
            format!("{:02}", rng.range(1, 12))
        } else {
            format!("{}", rng.range(1, 4))
        };
        let short = format!("{}{role}{number}", self.prefix);
        let short = if self.upper {
            short.to_ascii_uppercase()
        } else {
            short.to_ascii_lowercase()
        };
        match &self.dns_domain {
            Some(domain) if rng.chance(55) => format!("{}.{domain}", short.to_ascii_lowercase()),
            _ => short,
        }
    }

    /// An account name, domain-qualified when the host is domain-joined.
    fn account(&self, base: &str, rng: &mut Rng) -> String {
        match &self.netbios {
            Some(nb) if rng.chance(60) => format!("{nb}\\{base}"),
            _ => base.to_string(),
        }
    }
}

/// Keep host-derived text to characters that are safe in any bait format.
fn sanitize(value: &str) -> String {
    value
        .trim()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.'))
        .take(63)
        .collect()
}

// ── secrets ───────────────────────────────────────────────────────────────────

const WORDS: &[&str] = &[
    "Sommer",
    "Winter",
    "Herbst",
    "Fruehling",
    "Falcon",
    "Orion",
    "Atlas",
    "Kiwi",
    "Matterhorn",
    "Bergblick",
    "Nordwind",
    "Pegasus",
    "Lighthouse",
    "Granite",
    "Cobalt",
    "Saturn",
    "Phoenix",
    "Meridian",
    "Tundra",
    "Riverside",
    "Hafen",
    "Linde",
    "Ostsee",
    "Alpen",
    "Quartz",
    "Harbor",
];

/// A password in one of the shapes people and password managers actually use,
/// and whether it is machine-generated (high entropy) rather than a human
/// pattern. Human patterns are low-entropy by nature, but varied enough
/// (≈10^5–10^6 shapes each) that no list of them identifies a decoy.
fn password(rng: &mut Rng) -> (String, bool) {
    let human = match rng.below(4) {
        // Human pattern: Word + year + optional digits + symbol, e.g. "Nordwind2023!".
        0 => {
            let year = Utc::now()
                .format("%Y")
                .to_string()
                .parse::<usize>()
                .unwrap_or(2026);
            let suffix = match rng.below(3) {
                0 => String::new(),
                1 => rng.chars(DIGITS, 1),
                _ => rng.chars(DIGITS, 2),
            };
            format!(
                "{}{}{suffix}{}",
                rng.pick(WORDS),
                rng.range(year - 4, year),
                *rng.pick(SYMBOLS) as char
            )
        }
        // Human pattern with leetspeak and a number.
        1 => {
            let word: String = rng
                .pick(WORDS)
                .chars()
                .map(|c| match c {
                    'a' => '@',
                    'o' => '0',
                    'e' => '3',
                    other => other,
                })
                .collect();
            format!(
                "{word}{}{}",
                *rng.pick(SYMBOLS) as char,
                rng.range(10, 9999)
            )
        }
        // Generated: mixed classes, 14–20 chars.
        _ => {
            let len = rng.range(14, 20);
            let mut alphabet = Vec::new();
            alphabet.extend_from_slice(UPPER);
            alphabet.extend_from_slice(LOWER);
            alphabet.extend_from_slice(DIGITS);
            alphabet.extend_from_slice(SYMBOLS);
            let mut s = rng.chars(&alphabet, len - 3);
            // Guarantee the classes a complexity policy demands.
            s.push(*rng.pick(UPPER) as char);
            s.push(*rng.pick(DIGITS) as char);
            s.push(*rng.pick(SYMBOLS) as char);
            return (s, true);
        }
    };
    (human, false)
}

/// A plausible past date (within roughly the last 14 months).
fn past_date(rng: &mut Rng) -> NaiveDate {
    let days = rng.range(3, 420) as i64;
    (Utc::now() - Duration::days(days)).date_naive()
}

// ── generators ────────────────────────────────────────────────────────────────

const SERVICES: &[(&str, &[&str])] = &[
    ("SQL", &["sa", "svc_sql", "sqladmin", "svc_mssql"]),
    ("DB", &["svc_db", "dbadmin", "postgres"]),
    ("VPN", &["svc_vpn", "vpnadmin"]),
    ("FS", &["administrator", "svc_files"]),
    ("APP", &["svc_app", "appadmin"]),
    ("WEB", &["svc_iis", "webadmin"]),
    ("ESX", &["root"]),
    ("VC", &["administrator@vsphere.local"]),
    ("NAS", &["admin", "svc_nas"]),
    ("PRN", &["svc_print"]),
    ("EXCH", &["svc_exchange"]),
    ("FW", &["admin", "netadmin"]),
];

const BACKUP_SERVICES: &[(&str, &[&str])] = &[
    ("BKP", &["svc_backup", "backupadmin", "veeam_svc"]),
    ("VEEAM", &["svc_veeam", "administrator"]),
    ("NAS", &["backup", "svc_nas"]),
    ("SQL", &["svc_sqlbackup", "sa"]),
    ("TAPE", &["svc_tape"]),
];

struct Entry {
    host: String,
    user: String,
    password: String,
    note: &'static str,
}

const NOTES: &[&str] = &[
    "",
    "",
    "",
    "prod",
    "test",
    "old - check",
    "new since migration",
    "do not change",
    "rotated",
    "temp",
    "vendor access",
    "emergency",
    "read only",
];

fn entries(
    persona: &Persona,
    rng: &mut Rng,
    backup: bool,
    secrets: &mut Vec<String>,
) -> Vec<Entry> {
    let pool = if backup { BACKUP_SERVICES } else { SERVICES };
    let count = rng.range(3, 7);
    let mut used = Vec::new();
    let mut out = Vec::new();
    while out.len() < count && used.len() < pool.len() {
        let idx = rng.below(pool.len());
        if used.contains(&idx) {
            continue;
        }
        used.push(idx);
        let (role, users) = pool[idx];
        let (password, generated) = password(rng);
        if generated {
            secrets.push(password.clone());
        }
        out.push(Entry {
            host: persona.server(role, rng),
            user: persona.account(rng.pick(users), rng),
            password,
            note: rng.pick(NOTES),
        });
    }
    out
}

const LIST_HEADERS: &[&str] = &[
    "",
    "Server / User / PW\r\n\r\n",
    "Zugangsdaten\r\n\r\n",
    "accounts\r\n-------\r\n",
    "IT logins (keep updated)\r\n\r\n",
    "Passwoerter Server\r\n==================\r\n",
];

/// Free-form notes file, the way admins keep them in Notepad.
fn password_list(
    persona: &Persona,
    rng: &mut Rng,
    backup: bool,
    secrets: &mut Vec<String>,
) -> String {
    let mut out = String::from(*rng.pick(LIST_HEADERS));
    let style = rng.below(3);
    for e in entries(persona, rng, backup, secrets) {
        let line = match style {
            0 => format!("{}\t{}\t{}", e.host, e.user, e.password),
            1 => format!("{} - {} / {}", e.host, e.user, e.password),
            _ => format!(
                "{}\r\n  user: {}\r\n  pw:   {}\r\n",
                e.host, e.user, e.password
            ),
        };
        out.push_str(&line);
        if !e.note.is_empty() && style != 2 {
            out.push_str(&format!("   ({})", e.note));
        }
        out.push_str("\r\n");
    }
    if rng.chance(40) {
        out.push_str(&format!(
            "\r\nlast change {}\r\n",
            past_date(rng).format(if rng.chance(50) {
                "%d.%m.%Y"
            } else {
                "%Y-%m-%d"
            })
        ));
    }
    out
}

/// A CSV export, in the column sets password managers and Excel produce.
fn credential_table(
    persona: &Persona,
    rng: &mut Rng,
    ext: &str,
    secrets: &mut Vec<String>,
) -> String {
    // German-locale Excel exports use ';'.
    let sep = if ext == "csv" && rng.chance(50) {
        ';'
    } else {
        ','
    };
    let columns = *rng.pick(CSV_HEADERS);
    let mut out = columns.join(&sep.to_string());
    out.push_str("\r\n");
    let backup = rng.chance(25);
    for e in entries(persona, rng, backup, secrets) {
        let row: Vec<String> = columns
            .iter()
            .map(|c| match c.to_ascii_lowercase().as_str() {
                "url" | "host" | "server" => {
                    if c.eq_ignore_ascii_case("url") {
                        format!("https://{}", e.host.to_ascii_lowercase())
                    } else {
                        e.host.clone()
                    }
                }
                "title" | "name" => e.host.split('.').next().unwrap_or("").to_string(),
                "username" | "user" | "benutzer" => e.user.clone(),
                "password" | "passwort" => e.password.clone(),
                "grouping" => "Servers".to_string(),
                _ => e.note.to_string(),
            })
            .map(|v| csv_field(&v, sep))
            .collect();
        out.push_str(&row.join(&sep.to_string()));
        out.push_str("\r\n");
    }
    out
}

/// Column sets of real exports (LastPass, KeePass, hand-made, German Excel).
const CSV_HEADERS: &[&[&str]] = &[
    &["url", "username", "password", "extra", "name", "grouping"],
    &["Title", "Username", "Password", "URL", "Notes"],
    &["host", "user", "password", "notes"],
    &["Server", "Benutzer", "Passwort", "Bemerkung"],
];

fn csv_field(value: &str, sep: char) -> String {
    if value.contains(sep) || value.contains('"') || value.contains('\n') {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

/// A BitLocker recovery-key text file exactly as Windows saves it (UTF-16LE
/// with BOM). The 48-digit key follows the real constraint: eight 6-digit
/// blocks, each divisible by 11 and below 720 896 (= 2^16 · 11).
fn bitlocker_recovery(rng: &mut Rng, secrets: &mut Vec<String>) -> Vec<u8> {
    let id = format!(
        "{}-{}-{}-{}-{}",
        rng.chars(b"0123456789ABCDEF", 8),
        rng.chars(b"0123456789ABCDEF", 4),
        rng.chars(b"0123456789ABCDEF", 4),
        rng.chars(b"0123456789ABCDEF", 4),
        rng.chars(b"0123456789ABCDEF", 12)
    );
    let key = recovery_key(rng);
    secrets.push(id.clone());
    secrets.push(key.clone());
    let text = format!(
        "BitLocker Drive Encryption recovery key\r\n\r\n\
         To verify that this is the correct recovery key, compare the start of the following identifier with the identifier value displayed on your PC.\r\n\r\n\
         Identifier:\r\n\r\n\t{id}\r\n\r\n\
         If the above identifier matches the one displayed by your PC, then use the following key to unlock your drive.\r\n\r\n\
         Recovery Key:\r\n\r\n\t{key}\r\n\r\n\
         If the above identifier doesn't match the one displayed by your PC, then this isn't the right key to unlock your drive.\r\n\
         Try another recovery key, or refer to https://go.microsoft.com/fwlink/?LinkID=260589 for additional assistance.\r\n"
    );
    let mut bytes = vec![0xFF, 0xFE];
    for unit in text.encode_utf16() {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    bytes
}

fn recovery_key(rng: &mut Rng) -> String {
    (0..8)
        .map(|_| format!("{:06}", rng.below(65_536) * 11))
        .collect::<Vec<_>>()
        .join("-")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deception::validate::reject_shared_watermark;

    fn host() -> HostIdentity {
        HostIdentity {
            hostname: "BER-WS-0142".into(),
            dns_domain: Some("corp.example.eu".into()),
        }
    }

    fn text(bytes: &[u8]) -> String {
        if bytes.starts_with(&[0xFF, 0xFE]) {
            let units: Vec<u16> = bytes[2..]
                .as_chunks::<2>()
                .0
                .iter()
                .map(|c| u16::from_le_bytes(*c))
                .collect();
            String::from_utf16(&units).unwrap()
        } else {
            String::from_utf8(bytes.to_vec()).unwrap()
        }
    }

    const NAMES: &[&str] = &[
        "passwords.txt",
        "credentials.csv",
        "logins.txt",
        "backup_keys.txt",
        "BitLocker Recovery Key 1A2B.txt",
        "notes.txt",
    ];

    #[test]
    fn legacy_constants_are_gone() {
        for name in NAMES {
            for _ in 0..20 {
                let bait = text(&generate(name, &host()).unwrap());
                for constant in [
                    "Pr0d-MSSQL-2024",
                    "B4ckup#Rot8-2024",
                    "V?n2024!Spr1ng",
                    "Wint3r2024!Adm",
                    "corp.local",
                    "BACKUP MASTER KEY",
                    "DO NOT SHARE",
                ] {
                    assert!(!bait.contains(constant), "{name}: {constant}\n{bait}");
                }
            }
        }
    }

    #[test]
    fn bait_never_carries_a_watermark() {
        for name in NAMES {
            for _ in 0..50 {
                let bait = text(&generate(name, &host()).unwrap());
                reject_shared_watermark("windows_decoy_file", &bait).unwrap();
            }
        }
    }

    /// The core anti-fingerprint property: two decoys of the same theme on the
    /// same host differ, and no secret of one appears in the other, so neither
    /// content, hash nor an embedded value identifies another decoy or tenant.
    #[test]
    fn two_generations_share_no_secret() {
        for name in NAMES {
            for _ in 0..20 {
                let (mut sa, mut sb) = (Vec::new(), Vec::new());
                let a = text(&generate_recording(name, &host(), &mut sa).unwrap());
                let b = text(&generate_recording(name, &host(), &mut sb).unwrap());
                assert_ne!(a, b);
                // Machine-generated secrets and keys never recur. Human
                // patterns may by chance, as in real files (see below).
                for secret in &sa {
                    assert!(a.contains(secret.as_str()), "{name}: secret not embedded");
                    assert!(
                        !b.contains(secret.as_str()),
                        "{name}: a generated secret was reused"
                    );
                }
            }
        }
    }

    #[test]
    fn human_pattern_passwords_are_not_enumerable() {
        let mut human = std::collections::HashSet::new();
        let mut total = 0;
        while total < 500 {
            let (pw, generated) = password(&mut Rng);
            if !generated {
                human.insert(pw);
                total += 1;
            }
        }
        // A small pattern space would repeat constantly at this sample size.
        assert!(human.len() >= 490, "only {} distinct of 500", human.len());
    }

    #[test]
    fn recovery_key_follows_the_bitlocker_checksum_rule() {
        for _ in 0..200 {
            let key = recovery_key(&mut Rng);
            let blocks: Vec<&str> = key.split('-').collect();
            assert_eq!(blocks.len(), 8);
            for block in blocks {
                assert_eq!(block.len(), 6);
                let n: u32 = block.parse().unwrap();
                assert_eq!(n % 11, 0);
                assert!(n < 720_896);
            }
        }
        let bait = generate("BitLocker Recovery Key.txt", &host()).unwrap();
        assert!(
            bait.starts_with(&[0xFF, 0xFE]),
            "Windows saves it as UTF-16LE"
        );
        assert!(text(&bait).starts_with("BitLocker Drive Encryption recovery key"));
    }

    #[test]
    fn persona_follows_the_host_naming_scheme() {
        let mut seen_fqdn = false;
        let mut seen_netbios = false;
        for _ in 0..40 {
            let bait = text(&generate("passwords.txt", &host()).unwrap());
            seen_fqdn |= bait.contains(".corp.example.eu");
            seen_netbios |= bait.contains("CORP\\");
            assert!(bait.contains("BER-") || bait.contains("ber-"), "{bait}");
        }
        assert!(seen_fqdn && seen_netbios);

        // A workgroup host gets no invented domain at all.
        let standalone = HostIdentity {
            hostname: "DESKTOP7".into(),
            dns_domain: None,
        };
        for _ in 0..20 {
            let bait = text(&generate("passwords.txt", &standalone).unwrap());
            assert!(!bait.contains('\\'), "{bait}");
        }
    }

    #[test]
    fn hostile_host_identity_is_sanitised() {
        let hostile = HostIdentity {
            hostname: "x\"; rm -rf /\r\n<script>".into(),
            dns_domain: Some("evil\r\ninjected.example".into()),
        };
        for _ in 0..20 {
            let bait = text(&generate("credentials.csv", &hostile).unwrap());
            assert!(!bait.contains('<') && !bait.contains('"') && !bait.contains("rm -rf"));
        }
    }

    #[test]
    fn binary_formats_are_refused_not_faked() {
        for name in [
            "credentials.xlsx",
            "Passwords.KDBX",
            "keys.docx",
            "vault.pdf",
        ] {
            assert!(generate(name, &host()).is_err(), "{name}");
        }
        assert!(
            generate("passwords", &host()).is_ok(),
            "no extension is text"
        );
    }
}
