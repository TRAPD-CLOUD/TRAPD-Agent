//! Rule catalog — the single place that decides how loud a rule may be.
//!
//! Rules describe *what* they saw (title, evidence, confidence); the catalog
//! decides *how much it matters*: a base severity, a ceiling the contextual
//! modifiers can never push past, whether the rule may alert on its own or is
//! only correlation context (`signal`), and how repeats are folded together by
//! the [`super::gate::FindingGate`].
//!
//! The backend keeps a copy (`rule-catalog.json`, kept in sync by a test) and
//! re-applies the same [`super::severity`] policy, so agent and backend agree
//! on severity without the backend re-deriving the rule's semantics.

use crate::schema::{DetectionMode, Severity};

/// How repeats of a rule are recognised as "the same finding".
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyStrategy {
    /// Same user running the same binary with the same (digit-normalised)
    /// command line — a cron job repeating `cat /etc/shadow` is one finding.
    Command,
    /// Same process instance (`process_key`), falling back to the subject.
    Process,
    /// Same process talking to the same remote IP / domain.
    ProcessRemote,
    /// Same process touching the same file path.
    Path,
    /// Same subject (the rule's own most identifying field).
    Subject,
}

/// Catalog entry for one rule (or rule family, for prefix entries).
#[derive(Debug, Clone, Copy, serde::Serialize)]
pub struct RuleMeta {
    pub id: &'static str,
    pub tactic: &'static str,
    pub technique: &'static str,
    /// Severity before contextual modifiers.
    pub base: Severity,
    /// Ceiling: modifiers never raise severity above this.
    pub max: Severity,
    pub mode: DetectionMode,
    pub dedup: KeyStrategy,
    /// Repeats inside this window are counted, not re-emitted.
    pub window_s: u64,
    /// Running as root makes this rule worse (a root reverse shell is worse
    /// than a user one; a root `cat /etc/shadow` is just administration).
    pub root_bump: bool,
    /// Running inside a container makes this rule worse (escape-adjacent).
    pub container_bump: bool,
    /// Prefix families (rootkit, sigma, yara) whose rules carry their own
    /// severity: the base is taken from the emitted event, capped at `max`.
    pub base_from_event: bool,
}

#[allow(clippy::too_many_arguments)]
const fn rule(
    id: &'static str,
    tactic: &'static str,
    technique: &'static str,
    base: Severity,
    max: Severity,
    mode: DetectionMode,
    dedup: KeyStrategy,
    window_s: u64,
) -> RuleMeta {
    RuleMeta {
        id,
        tactic,
        technique,
        base,
        max,
        mode,
        dedup,
        window_s,
        root_bump: false,
        container_bump: false,
        base_from_event: false,
    }
}

const fn root_bump(mut m: RuleMeta) -> RuleMeta {
    m.root_bump = true;
    m
}

const fn container_bump(mut m: RuleMeta) -> RuleMeta {
    m.container_bump = true;
    m
}

const fn from_event(mut m: RuleMeta) -> RuleMeta {
    m.base_from_event = true;
    m
}

use DetectionMode::{Alert, Signal};
use KeyStrategy::{Command, Path, Process, ProcessRemote, Subject};
use Severity::{Critical, High, Low, Medium};

const TEN_MIN: u64 = 600;
const FIFTEEN_MIN: u64 = 900;
const HOUR: u64 = 3600;

const EXEC: &str = "TA0002 Execution";
const PERSIST: &str = "TA0003 Persistence";
const PRIVESC: &str = "TA0004 Privilege Escalation";
const EVASION: &str = "TA0005 Defense Evasion";
const CREDS: &str = "TA0006 Credential Access";
const DISCOVERY: &str = "TA0007 Discovery";
const LATERAL: &str = "TA0008 Lateral Movement";
const COLLECTION: &str = "TA0009 Collection";
const C2: &str = "TA0011 Command and Control";
const EXFIL: &str = "TA0010 Exfiltration";
const IMPACT: &str = "TA0040 Impact";
const INITIAL: &str = "TA0001 Initial Access";

/// Every rule the agent can emit. Exact ids first; prefix families live in
/// [`PREFIXES`].
pub const RULES: &[RuleMeta] = &[
    // ── IOC matches ────────────────────────────────────────────────────────
    rule("ioc.process_hash", EXEC, "T1204", Critical, Critical, Alert, Process, HOUR),
    rule("ioc.network_ip", C2, "T1071", Critical, Critical, Alert, ProcessRemote, FIFTEEN_MIN),
    rule("ioc.dns_domain", C2, "T1071.004", High, Critical, Alert, ProcessRemote, FIFTEEN_MIN),
    // ── Network analytics ──────────────────────────────────────────────────
    rule("beaconing.regular_interval", C2, "T1071", High, High, Alert, Subject, HOUR),
    rule("dns_tunnel.anomalous_query_volume", C2, "T1071.004", High, High, Alert, Subject, HOUR),
    rule("recon.port_scan", DISCOVERY, "T1046", Medium, High, Alert, Subject, FIFTEEN_MIN),
    rule("lateral.admin_port_sweep", LATERAL, "T1021", High, High, Alert, Subject, FIFTEEN_MIN),
    // Cloud agents and SDKs read IMDS all the time; only meaningful in a chain.
    rule("cloud.imds_access", CREDS, "T1552.005", Low, Medium, Signal, ProcessRemote, FIFTEEN_MIN),
    // ── Process behaviour ──────────────────────────────────────────────────
    root_bump(rule("revshell.dev_tcp_redirect", C2, "T1059.004", Critical, Critical, Alert, Command, TEN_MIN)),
    root_bump(rule("revshell.interpreter_socket", C2, "T1059.006", High, Critical, Alert, Command, TEN_MIN)),
    // Plenty of installers are `curl | sh`; loud only with context.
    rule("lolbin.download_pipe_shell", EXEC, "T1059.004", Medium, High, Alert, Command, TEN_MIN),
    root_bump(rule("fileless.memfd_exec", EVASION, "T1620", High, Critical, Alert, Process, TEN_MIN)),
    rule("creds.shadow_read", CREDS, "T1003.008", Medium, High, Alert, Command, HOUR),
    rule("creds.secret_store_access", CREDS, "T1552.001", Medium, High, Alert, Command, HOUR),
    rule("creds.sensitive_file_access", CREDS, "T1555", High, Critical, Alert, Path, HOUR),
    rule("creds.private_key_read", CREDS, "T1552.004", High, Critical, Alert, Path, HOUR),
    rule("evasion.log_or_history_clear", EVASION, "T1070.002", Medium, High, Alert, Command, HOUR),
    rule("evasion.history_clear", EVASION, "T1070.003", Low, Medium, Signal, Command, HOUR),
    rule("persistence.autostart_write", PERSIST, "T1053", Medium, High, Alert, Command, HOUR),
    rule("persistence.rc_edit", PERSIST, "T1546.004", Low, Medium, Signal, Command, HOUR),
    rule("persistence.ld_preload", PERSIST, "T1574.006", High, Critical, Alert, Command, HOUR),
    rule("privesc.gtfobin", PRIVESC, "T1548", High, Critical, Alert, Command, TEN_MIN),
    rule("privesc.setuid_root", PRIVESC, "T1548.001", Medium, High, Alert, Process, TEN_MIN),
    rule("privesc.untracked_suid_exec", PRIVESC, "T1548.001", High, Critical, Alert, Process, HOUR),
    rule("injection.ld_preload", EVASION, "T1574.006", High, Critical, Alert, Command, HOUR),
    // ── Behavioural baseline (context only) ───────────────────────────────
    rule("anomaly.rare_binary_for_user", EXEC, "T1204", Low, Low, Signal, Command, HOUR),
    rule("anomaly.exec_rate_spike", EXEC, "T1059", Low, Low, Signal, Subject, HOUR),
    // ── IOA chains (already correlated across the process tree) ───────────
    rule("ioa.download_and_execute", EXEC, "T1105", High, Critical, Alert, Process, TEN_MIN),
    rule("ioa.privilege_escalation_activity", PRIVESC, "T1068", High, Critical, Alert, Process, TEN_MIN),
    rule("ioa.credential_access_exfil", EXFIL, "T1041", High, Critical, Alert, Process, TEN_MIN),
    // ── Memory scanning ────────────────────────────────────────────────────
    rule("memory.memfd_exec", EVASION, "T1620", Critical, Critical, Alert, Process, HOUR),
    root_bump(rule("memory.anon_exec", EVASION, "T1055", High, Critical, Alert, Process, HOUR)),
    // Long-lived daemons keep running deleted images after package upgrades.
    rule("memory.deleted_exec", EVASION, "T1620", Low, Medium, Signal, Process, HOUR),
    rule("injection.ld_preload_runtime", EVASION, "T1574.006", High, Critical, Alert, Process, HOUR),
    // ── Deception ──────────────────────────────────────────────────────────
    rule("deception.honeytoken_tamper", EVASION, "T1070", Critical, Critical, Alert, Path, HOUR),
    // ── Initial access / execution ─────────────────────────────────────────
    rule("exec.webserver_shell", INITIAL, "T1505.003", High, Critical, Alert, Command, TEN_MIN),
    rule("exec.b64_decode_exec", EXEC, "T1140", High, Critical, Alert, Command, TEN_MIN),
    rule("defense.tmp_exec", EXEC, "T1204.002", Low, Medium, Signal, Process, TEN_MIN),
    rule("defense.tmp_exec_chmod", EXEC, "T1204.002", Medium, High, Alert, Path, TEN_MIN),
    rule("auth.ssh_bruteforce_success", INITIAL, "T1110.001", High, Critical, Alert, Subject, HOUR),
    // ── Persistence ────────────────────────────────────────────────────────
    rule("persistence.ssh_authorized_keys", PERSIST, "T1098.004", High, Critical, Alert, Path, HOUR),
    rule("persistence.cron_write", PERSIST, "T1053.003", Medium, High, Alert, Path, HOUR),
    rule("persistence.systemd_unit", PERSIST, "T1543.002", Medium, High, Alert, Path, HOUR),
    rule("privesc.sudoers_modify", PRIVESC, "T1548.003", High, Critical, Alert, Path, HOUR),
    rule("defense.kmod_from_tmp", PERSIST, "T1547.006", Critical, Critical, Alert, Path, HOUR),
    // ── Discovery / collection / exfiltration / impact ─────────────────────
    rule("discovery.recon_burst", DISCOVERY, "T1082", Low, Low, Signal, Subject, TEN_MIN),
    rule("collection.archive_staging", COLLECTION, "T1560.001", Low, Medium, Signal, Command, TEN_MIN),
    root_bump(rule("exfil.http_upload", EXFIL, "T1048.003", Medium, High, Alert, ProcessRemote, TEN_MIN)),
    rule("impact.cryptominer", IMPACT, "T1496", High, High, Alert, Process, HOUR),
    rule("creds.proc_mem_access", CREDS, "T1003.007", High, Critical, Alert, Process, TEN_MIN),
    container_bump(rule("container.escape_indicators", PRIVESC, "T1611", High, Critical, Alert, Command, TEN_MIN)),
];

/// Rule families whose individual ids are open-ended.
pub const PREFIXES: &[RuleMeta] = &[
    from_event(rule("rootkit.", EVASION, "T1014", Medium, Critical, Alert, Subject, HOUR)),
    from_event(rule("yara.", EXEC, "T1204", High, Critical, Alert, Path, HOUR)),
    from_event(rule("sigma.", EXEC, "", Medium, Critical, Alert, Command, TEN_MIN)),
];

/// Fallback for a rule the catalog does not know: severity follows the
/// emitted event, never above High, so an uncatalogued rule cannot page.
const UNKNOWN: RuleMeta = from_event(rule("", "", "", Medium, High, Alert, Subject, TEN_MIN));

/// Look up a rule; unknown ids get a conservative fallback.
pub fn lookup(rule_id: &str) -> RuleMeta {
    if let Some(m) = RULES.iter().find(|m| m.id == rule_id) {
        return *m;
    }
    if let Some(m) = PREFIXES.iter().find(|m| rule_id.starts_with(m.id)) {
        return *m;
    }
    UNKNOWN
}

/// True when the catalog has an exact or prefix entry for the rule.
pub fn is_known(rule_id: &str) -> bool {
    RULES.iter().any(|m| m.id == rule_id) || PREFIXES.iter().any(|m| rule_id.starts_with(m.id))
}

/// The catalog as JSON — the artifact the backend seeds its
/// `detection_rule_catalog` table from.
pub fn to_json() -> serde_json::Value {
    serde_json::json!({
        "rules": RULES,
        "prefixes": PREFIXES,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_unique() {
        let mut seen = std::collections::HashSet::new();
        for m in RULES.iter().chain(PREFIXES) {
            assert!(seen.insert(m.id), "duplicate catalog id {}", m.id);
        }
    }

    #[test]
    fn base_never_exceeds_max() {
        for m in RULES.iter().chain(PREFIXES) {
            assert!(m.base <= m.max, "{}: base above max", m.id);
        }
    }

    #[test]
    fn signal_rules_are_quiet_by_construction() {
        for m in RULES.iter().filter(|m| m.mode == Signal) {
            assert!(m.base <= Low, "{}: a signal rule must have base <= low", m.id);
        }
    }

    #[test]
    fn prefixes_and_fallback() {
        assert_eq!(lookup("rootkit.hidden_module").id, "rootkit.");
        assert!(lookup("rootkit.hidden_module").base_from_event);
        assert_eq!(lookup("sigma.abc").id, "sigma.");
        let unknown = lookup("totally.new_rule");
        assert_eq!(unknown.max, High);
        assert!(!is_known("totally.new_rule"));
    }

    /// The JSON copy the backend vendors must match the compiled table.
    /// Regenerate with `TRAPD_UPDATE_CATALOG=1 cargo test catalog`.
    #[test]
    fn committed_json_matches_table() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("rule-catalog.json");
        let current = serde_json::to_string_pretty(&to_json()).unwrap() + "\n";
        if std::env::var("TRAPD_UPDATE_CATALOG").is_ok() {
            std::fs::write(&path, &current).unwrap();
        }
        let committed = std::fs::read_to_string(&path).unwrap_or_default();
        assert_eq!(
            committed, current,
            "rule-catalog.json is stale; run TRAPD_UPDATE_CATALOG=1 cargo test catalog"
        );
    }
}
