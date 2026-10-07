//! The user's file-naming style, and decoy names written in it.
//!
//! A decoy called `passwords.txt` among `2024-03-12_Angebot_Mueller_v2.docx`
//! and `2024-05-02_Rechnung_Kunz.pdf` stands out to anyone listing the folder.
//! The style is inferred from the names next to the decoy (and, with local
//! learning, the names the user saved recently): language, separator, casing,
//! date format and position. Only these *features* are kept; the inference
//! never stores or reports the names themselves.

use chrono::{DateTime, Datelike, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Language {
    #[default]
    En,
    De,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Casing {
    /// `Server_Liste`
    #[default]
    Title,
    /// `server_liste`
    Lower,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DateFormat {
    /// `2024-03-12`
    Iso,
    /// `20240312`
    Compact,
    /// `12.03.2024`
    German,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DatePosition {
    Prefix,
    Suffix,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct NamingStyle {
    pub language: Language,
    pub separator: char,
    pub casing: Casing,
    pub date: Option<(DateFormat, DatePosition)>,
}

impl Default for NamingStyle {
    fn default() -> Self {
        Self {
            language: Language::En,
            separator: '_',
            casing: Casing::Title,
            date: None,
        }
    }
}

/// Common German words in office file names (ASCII-folded, lowercase).
const GERMAN_WORDS: &[&str] = &[
    "angebot",
    "rechnung",
    "vertrag",
    "protokoll",
    "liste",
    "kunden",
    "bericht",
    "notizen",
    "zugang",
    "zugangsdaten",
    "passwort",
    "passwoerter",
    "kennwort",
    "sicherung",
    "einrichtung",
    "anleitung",
    "uebersicht",
    "besprechung",
    "auftrag",
    "lieferschein",
    "entwurf",
    "neu",
    "alt",
    "final",
    "kopie",
    "aktuell",
    "stand",
    "netzplan",
    "doku",
    "dokumentation",
    "konzept",
    "mitarbeiter",
    "planung",
    "abrechnung",
    "bestellung",
    "projekt",
    "server",
    "und",
    "fuer",
];
const ENGLISH_WORDS: &[&str] = &[
    "invoice",
    "contract",
    "minutes",
    "report",
    "notes",
    "list",
    "customers",
    "offer",
    "draft",
    "copy",
    "final",
    "old",
    "new",
    "setup",
    "guide",
    "overview",
    "meeting",
    "order",
    "plan",
    "project",
    "accounts",
    "passwords",
    "backup",
    "access",
    "and",
    "for",
    "the",
    "summary",
];

impl NamingStyle {
    /// Infer the dominant style from file names (extensions ignored). Names
    /// without letters (`IMG_0001`) carry no style and are skipped.
    pub fn infer<S: AsRef<str>>(names: &[S]) -> Self {
        let mut de = 0i32;
        let mut en = 0i32;
        let (mut us, mut dash, mut space) = (0i32, 0i32, 0i32);
        let (mut title, mut lower) = (0i32, 0i32);
        let (mut iso, mut compact, mut german) = (0i32, 0i32, 0i32);
        let (mut prefix, mut suffix) = (0i32, 0i32);
        let mut considered = 0i32;
        for raw in names {
            let raw = raw.as_ref();
            let stem = raw.rsplit_once('.').map(|(s, _)| s).unwrap_or(raw);
            if !stem.chars().any(|c| c.is_alphabetic()) || stem.starts_with('.') {
                continue;
            }
            considered += 1;
            let folded = fold(stem);
            for w in folded
                .split(|c: char| !c.is_ascii_alphabetic())
                .filter(|w| w.len() > 1)
            {
                if GERMAN_WORDS.contains(&w) {
                    de += 1;
                }
                if ENGLISH_WORDS.contains(&w) {
                    en += 1;
                }
            }
            if stem
                .chars()
                .any(|c| matches!(c, 'ä' | 'ö' | 'ü' | 'ß' | 'Ä' | 'Ö' | 'Ü'))
            {
                de += 2;
            }
            us += stem.matches('_').count() as i32;
            dash += stem.matches('-').count() as i32;
            space += stem.matches(' ').count() as i32;
            let first_letter = stem.chars().find(|c| c.is_alphabetic());
            match first_letter {
                Some(c) if c.is_uppercase() => title += 1,
                Some(_) => lower += 1,
                None => {}
            }
            if let Some((fmt, at_start)) = find_date(stem) {
                match fmt {
                    DateFormat::Iso => iso += 1,
                    DateFormat::Compact => compact += 1,
                    DateFormat::German => german += 1,
                }
                if at_start {
                    prefix += 1;
                } else {
                    suffix += 1;
                }
            }
        }
        let mut style = Self::default();
        if considered == 0 {
            return style;
        }
        style.language = if de > en { Language::De } else { Language::En };
        // ISO dates contribute dashes that are not separators.
        let dash = (dash - 2 * iso).max(0);
        style.separator = if space > us && space > dash {
            ' '
        } else if dash > us {
            '-'
        } else {
            '_'
        };
        style.casing = if lower > title {
            Casing::Lower
        } else {
            Casing::Title
        };
        let dated = iso + compact + german;
        // Dates only when most names carry one: a single dated file is noise.
        if dated * 2 > considered {
            let fmt = if iso >= compact && iso >= german {
                DateFormat::Iso
            } else if german >= compact {
                DateFormat::German
            } else {
                DateFormat::Compact
            };
            let pos = if prefix >= suffix {
                DatePosition::Prefix
            } else {
                DatePosition::Suffix
            };
            style.date = Some((fmt, pos));
        }
        style
    }

    /// Compose a stem from words in this style, with the date if the style
    /// uses one.
    pub fn compose(&self, words: &[&str], date_unix: i64) -> String {
        let sep = self.separator.to_string();
        let words: Vec<String> = words
            .iter()
            .map(|w| match self.casing {
                Casing::Lower => w.to_lowercase(),
                Casing::Title => w.to_string(),
            })
            .collect();
        let body = words.join(&sep);
        match self.date {
            None => body,
            Some((fmt, pos)) => {
                let d = format_date(fmt, date_unix);
                match pos {
                    DatePosition::Prefix => format!("{d}{sep}{body}"),
                    DatePosition::Suffix => format!("{body}{sep}{d}"),
                }
            }
        }
    }
}

fn fold(s: &str) -> String {
    s.to_lowercase()
        .replace('ä', "ae")
        .replace('ö', "oe")
        .replace('ü', "ue")
        .replace('ß', "ss")
}

/// A date inside the stem and whether it starts the stem.
fn find_date(stem: &str) -> Option<(DateFormat, bool)> {
    let b = stem.as_bytes();
    let digit = |i: usize| b.get(i).is_some_and(|c| c.is_ascii_digit());
    for i in 0..b.len() {
        // Not inside a longer number.
        if i > 0 && digit(i - 1) {
            continue;
        }
        if (0..4).all(|k| digit(i + k))
            && b.get(i + 4) == Some(&b'-')
            && digit(i + 5)
            && digit(i + 6)
            && b.get(i + 7) == Some(&b'-')
            && digit(i + 8)
            && digit(i + 9)
        {
            return Some((DateFormat::Iso, i == 0));
        }
        if digit(i)
            && digit(i + 1)
            && b.get(i + 2) == Some(&b'.')
            && digit(i + 3)
            && digit(i + 4)
            && b.get(i + 5) == Some(&b'.')
            && (0..4).all(|k| digit(i + 6 + k))
        {
            return Some((DateFormat::German, i == 0));
        }
        if (0..8).all(|k| digit(i + k))
            && !digit(i + 8)
            && (stem[i..i + 2] == *"19" || stem[i..i + 2] == *"20")
        {
            let month: u32 = stem[i + 4..i + 6].parse().unwrap_or(0);
            let day: u32 = stem[i + 6..i + 8].parse().unwrap_or(0);
            if (1..=12).contains(&month) && (1..=31).contains(&day) {
                return Some((DateFormat::Compact, i == 0));
            }
        }
    }
    None
}

fn format_date(fmt: DateFormat, unix: i64) -> String {
    let d = DateTime::<Utc>::from_timestamp(unix, 0).unwrap_or_default();
    match fmt {
        DateFormat::Iso => format!("{:04}-{:02}-{:02}", d.year(), d.month(), d.day()),
        DateFormat::Compact => format!("{:04}{:02}{:02}", d.year(), d.month(), d.day()),
        DateFormat::German => format!("{:02}.{:02}.{:04}", d.day(), d.month(), d.year()),
    }
}

/// Topic words per kind and language, plus the extension. The first entries
/// are preferred; `pick` rotates through alternatives so two hosts with the
/// same style do not end up with the same name.
fn topics(kind: &str, lang: Language) -> (&'static [&'static [&'static str]], &'static str) {
    match (kind, lang) {
        ("password_note", Language::De) => (
            &[
                &["Zugangsdaten"],
                &["Passwoerter", "Server"],
                &["Kennwoerter"],
                &["Zugaenge", "IT"],
            ],
            "txt",
        ),
        ("password_note", Language::En) => (
            &[
                &["passwords"],
                &["server", "logins"],
                &["accounts"],
                &["IT", "access"],
            ],
            "txt",
        ),
        ("credential_csv", Language::De) => (
            &[
                &["Zugangsdaten", "Export"],
                &["Konten"],
                &["Benutzerkonten"],
            ],
            "csv",
        ),
        ("credential_csv", Language::En) => (
            &[
                &["accounts", "export"],
                &["credentials"],
                &["user", "accounts"],
            ],
            "csv",
        ),
        ("db_connection_notes", Language::De) => (
            &[
                &["DB", "Zugaenge"],
                &["SQL", "Zugangsdaten"],
                &["Datenbanken"],
            ],
            "txt",
        ),
        ("db_connection_notes", Language::En) => (
            &[&["DB", "logins"], &["SQL", "credentials"], &["databases"]],
            "txt",
        ),
        ("recovery_key", Language::De) => (
            &[
                &["BitLocker", "Wiederherstellungsschluessel"],
                &["Wiederherstellungsschluessel"],
            ],
            "txt",
        ),
        ("recovery_key", Language::En) => (
            &[&["BitLocker", "Recovery", "Key"], &["Recovery", "Key"]],
            "txt",
        ),
        ("rdp_connection", Language::De) => (
            &[
                &["Terminalserver"],
                &["Jumphost"],
                &["RDS"],
                &["Fernwartung"],
            ],
            "rdp",
        ),
        ("rdp_connection", Language::En) => (
            &[
                &["terminal", "server"],
                &["jumphost"],
                &["RDS"],
                &["remote", "admin"],
            ],
            "rdp",
        ),
        ("map_drives_script", Language::De) => (
            &[
                &["Laufwerke", "verbinden"],
                &["Netzlaufwerke"],
                &["map", "drives"],
            ],
            "bat",
        ),
        ("map_drives_script", Language::En) => (
            &[&["map", "drives"], &["network", "drives"], &["mapdrives"]],
            "bat",
        ),
        _ => (&[], ""),
    }
}

/// Candidate file names for a decoy kind, best first.
pub fn file_names_for(kind: &str, style: &NamingStyle, date_unix: i64, pick: u64) -> Vec<String> {
    // Names the generating software chooses itself: the user's style does not
    // apply, the software's does.
    let fixed: &[&str] = match kind {
        "winscp_ini" => &["WinSCP.ini", "WinSCP_export.ini", "WinSCP.ini.bak"],
        "filezilla_sitemanager" => &["sitemanager.xml", "FileZilla.xml", "sitemanager_backup.xml"],
        "unattend_xml" => &["unattend.xml", "Autounattend.xml", "unattend_backup.xml"],
        "appsettings_json" => &[
            "appsettings.Production.json",
            "appsettings.Staging.json",
            "appsettings.Release.json",
        ],
        "web_config" => &[
            "Web.Production.config",
            "Web.Release.config",
            "web.config.bak",
        ],
        "env_file" => &[".env.production", ".env.staging", ".env.backup"],
        "aws_credentials_backup" => &["credentials.bak", "credentials.old", "credentials.backup"],
        _ => &[],
    };
    if !fixed.is_empty() {
        return fixed.iter().map(|s| s.to_string()).collect();
    }
    let (alternatives, ext) = topics(kind, style.language);
    if alternatives.is_empty() {
        return Vec::new();
    }
    let start = (pick % alternatives.len() as u64) as usize;
    let mut out: Vec<String> = (0..alternatives.len())
        .map(|i| alternatives[(start + i) % alternatives.len()])
        .map(|words| {
            // .rdp/.bat names rarely carry dates.
            let s = if matches!(kind, "rdp_connection" | "map_drives_script") {
                NamingStyle {
                    date: None,
                    ..*style
                }
            } else {
                *style
            };
            format!("{}.{ext}", s.compose(words, date_unix))
        })
        .collect();
    // A numbered variant as last resort against collisions.
    if let Some(first) = out.first().cloned() {
        if let Some((stem, e)) = first.rsplit_once('.') {
            out.push(format!("{stem}{}2.{e}", style.separator));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn infers_german_iso_prefix_underscore() {
        let s = NamingStyle::infer(&[
            "2024-03-12_Angebot_Mueller_v2.docx",
            "2024-05-02_Rechnung_Kunz.pdf",
            "2023-11-30_Protokoll_Besprechung.docx",
            "Netzplan.vsdx",
        ]);
        assert_eq!(s.language, Language::De);
        assert_eq!(s.separator, '_');
        assert_eq!(s.casing, Casing::Title);
        assert_eq!(s.date, Some((DateFormat::Iso, DatePosition::Prefix)));
    }

    #[test]
    fn infers_english_lowercase_dash_without_dates() {
        let s = NamingStyle::infer(&[
            "meeting-notes.txt",
            "project-plan.md",
            "invoice-copy.pdf",
            "IMG_0001.jpg",
        ]);
        assert_eq!(s.language, Language::En);
        assert_eq!(s.separator, '-');
        assert_eq!(s.casing, Casing::Lower);
        assert_eq!(s.date, None);
    }

    #[test]
    fn infers_space_separator_and_german_suffix_dates() {
        let s = NamingStyle::infer(&[
            "Bericht Q1 12.03.2024.docx",
            "Liste Kunden 01.02.2024.xlsx",
            "Uebersicht neu 05.05.2024.docx",
        ]);
        assert_eq!(s.separator, ' ');
        assert_eq!(s.date, Some((DateFormat::German, DatePosition::Suffix)));
        assert_eq!(s.language, Language::De);
    }

    #[test]
    fn empty_or_styleless_input_gives_default() {
        assert_eq!(NamingStyle::infer::<&str>(&[]), NamingStyle::default());
        assert_eq!(
            NamingStyle::infer(&["IMG_0001.jpg", "123.txt", ".gitignore"]),
            NamingStyle::default()
        );
    }

    #[test]
    fn composes_names_in_style() {
        let s = NamingStyle {
            language: Language::De,
            separator: '_',
            casing: Casing::Title,
            date: Some((DateFormat::Iso, DatePosition::Prefix)),
        };
        // 2024-11-04
        let names = file_names_for("password_note", &s, 1_730_678_400, 0);
        assert_eq!(names[0], "2024-11-04_Zugangsdaten.txt");
        let lower = NamingStyle {
            casing: Casing::Lower,
            date: None,
            separator: '-',
            language: Language::En,
        };
        assert_eq!(
            file_names_for("password_note", &lower, 0, 1)[0],
            "server-logins.txt"
        );
        // rdp names never carry the date.
        assert!(!file_names_for("rdp_connection", &s, 1_730_678_400, 0)[0].contains("2024"));
        // Software-chosen names ignore the user's style.
        assert_eq!(file_names_for("winscp_ini", &s, 0, 0)[0], "WinSCP.ini");
        assert!(file_names_for("unknown_kind", &s, 0, 0).is_empty());
    }

    #[test]
    fn compact_dates_need_a_plausible_calendar_date() {
        assert_eq!(
            find_date("Scan_20240312"),
            Some((DateFormat::Compact, false))
        );
        assert_eq!(find_date("Order_12345678"), None);
        assert_eq!(find_date("x_202413991"), None);
    }
}
