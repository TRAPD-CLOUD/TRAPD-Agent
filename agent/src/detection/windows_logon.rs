//! Windows logon telemetry: normalisation of Security events 4624/4625/4776
//! into structured fields, and the logon-pattern detections built on them
//! (brute force, password spray, success after failures).
//!
//! Platform-neutral on purpose (pure functions over the event's `Data` map),
//! so it is unit-tested on every build; only the event-log reader that feeds
//! it is Windows-only.

#![cfg_attr(not(any(windows, test)), allow(dead_code))]

use std::collections::{HashMap, HashSet, VecDeque};
use std::hash::Hash;

use crate::schema::{CorrelationKeys, DetectionData, UserLogonData};

type Fields = serde_json::Map<String, serde_json::Value>;

const WINDOW: f64 = 300.0;
/// Failures against one account (from anywhere) that make a brute force.
const USER_THRESHOLD: usize = 5;
/// Failures from one source (any accounts) that make a brute force.
const SOURCE_THRESHOLD: usize = 10;
/// Distinct accounts failing from one source that make a password spray.
const SPRAY_USERS: usize = 5;
const MAX_KEYS: usize = 4_096;
/// Keep a bounded recent sample during floods; capped counts are lower bounds.
const MAX_FAILURES_PER_KEY: usize = 128;

fn field<'a>(fields: &'a Fields, key: &str) -> &'a str {
    fields
        .get(key)
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
}

/// Name of a Windows logon type.
pub fn logon_type_name(t: u32) -> &'static str {
    match t {
        0 => "system",
        2 => "interactive",
        3 => "network",
        4 => "batch",
        5 => "service",
        7 => "unlock",
        8 => "network_cleartext",
        9 => "new_credentials",
        10 => "remote_interactive",
        11 => "cached_interactive",
        _ => "other",
    }
}

/// Meaning of an NTSTATUS seen in 4625/4776 (`Status` / `SubStatus`).
pub fn status_text(status: &str) -> Option<&'static str> {
    Some(match status.to_ascii_lowercase().as_str() {
        "0xc000006a" => "wrong password",
        "0xc000006d" => "logon failure (bad user name or password)",
        "0xc0000064" => "user name does not exist",
        "0xc000006e" => "account restriction",
        "0xc000006f" => "logon outside permitted hours",
        "0xc0000070" => "workstation restriction",
        "0xc0000071" => "password expired",
        "0xc0000072" => "account disabled",
        "0xc0000133" => "clock skew between client and domain controller",
        "0xc000015b" => "logon type not granted",
        "0xc0000193" => "account expired",
        "0xc0000224" => "password must change at next logon",
        "0xc0000234" => "account locked out",
        "0xc0000225" => "internal error (user not found)",
        _ => return None,
    })
}

/// The `%%NNNN` message ids Windows puts into `FailureReason`.
fn failure_reason_text(id: &str) -> Option<&'static str> {
    Some(match id {
        "%%2304" => "an error occurred during logon",
        "%%2305" => "account expired",
        "%%2306" => "NetLogon component not active",
        "%%2307" => "account locked out",
        "%%2308" => "logon type not granted at this machine",
        "%%2309" => "password expired",
        "%%2310" => "account disabled",
        "%%2311" => "logon time restriction violation",
        "%%2312" => "user not allowed to log on at this computer",
        "%%2313" => "unknown user name or bad password",
        _ => return None,
    })
}

/// Add readable companions (`logon_type_name`, `status_text`,
/// `sub_status_text`, `failure_reason_text`) to the raw log record's fields so
/// the unresolved `%%2313` / numeric codes are not the only evidence.
pub fn enrich_fields(event_id: u32, fields: &mut Fields) {
    if !matches!(event_id, 4624 | 4625 | 4776) {
        return;
    }
    let mut add = Vec::new();
    if let Ok(t) = field(fields, "LogonType").parse::<u32>() {
        add.push(("logon_type_name", logon_type_name(t)));
    }
    if let Some(t) = status_text(field(fields, "Status")) {
        add.push(("status_text", t));
    }
    if let Some(t) = status_text(field(fields, "SubStatus")) {
        add.push(("sub_status_text", t));
    }
    if let Some(t) = failure_reason_text(field(fields, "FailureReason")) {
        add.push(("failure_reason_text", t));
    }
    for (k, v) in add {
        fields.insert(k.into(), v.into());
    }
}

fn is_local_addr(a: &str) -> bool {
    matches!(a, "" | "-" | "::1" | "127.0.0.1" | "0.0.0.0" | "::")
}

/// Service, machine and session-manager identities: logons that are the
/// operating system talking to itself, not a person or an attacker.
fn is_system_identity(user: &str, domain: &str, sid: &str) -> bool {
    let u = user.to_ascii_lowercase();
    let d = domain.to_ascii_lowercase();
    matches!(sid, "S-1-5-18" | "S-1-5-19" | "S-1-5-20" | "S-1-5-7")
        || matches!(
            u.as_str(),
            "system" | "local service" | "network service" | "anonymous logon"
        )
        || u.ends_with('$')
        || u.starts_with("dwm-")
        || u.starts_with("umfd-")
        || d == "nt authority"
        || d == "window manager"
        || d == "font driver host"
}

/// Normalise a Security 4624 (success) or 4625 (failure) event. Returns
/// `None` for events that are not a user logon outcome, including the
/// operating system's own service/machine logons (SYSTEM, machine accounts,
/// DWM/UMFD, anonymous): those fire constantly and are not user activity.
pub fn normalize(event_id: u32, fields: &Fields) -> Option<UserLogonData> {
    let success = match event_id {
        4624 => true,
        4625 => false,
        _ => return None,
    };
    let username = field(fields, "TargetUserName");
    let domain = field(fields, "TargetDomainName");
    let sid = field(fields, "TargetUserSid");
    let logon_type = field(fields, "LogonType").parse::<u32>().ok();
    if success && is_system_identity(username, domain, sid) {
        return None;
    }
    // Service logons (type 5) are never user-driven, whoever the account is.
    if success && matches!(logon_type, Some(0 | 5)) {
        return None;
    }
    let opt = |k: &str| match field(fields, k) {
        "" | "-" => None,
        v => Some(v.to_string()),
    };
    let src_addr = opt("IpAddress").filter(|a| !is_local_addr(a));
    let status = opt("Status");
    let sub_status = opt("SubStatus");
    let failure_reason = (!success).then(|| {
        // The sub status is the precise cause; Status is usually the generic
        // 0xc000006d wrapper; FailureReason is the legacy message id.
        sub_status
            .as_deref()
            .and_then(status_text)
            .or_else(|| status.as_deref().and_then(status_text))
            .or_else(|| failure_reason_text(field(fields, "FailureReason")))
            .map(str::to_string)
    });
    Some(UserLogonData {
        username: username.to_string(),
        src_addr,
        src_port: field(fields, "IpPort").parse().ok().filter(|p| *p != 0),
        auth_method: opt("AuthenticationPackageName"),
        success,
        domain: opt("TargetDomainName"),
        logon_type,
        logon_type_name: logon_type.map(|t| logon_type_name(t).to_string()),
        status,
        sub_status,
        failure_reason: failure_reason.flatten(),
        workstation: opt("WorkstationName"),
        process_name: opt("ProcessName"),
    })
}

/// Failure bookkeeping for the Windows logon detections. Time is injected
/// (seconds on a monotonic scale); every map is bounded.
#[derive(Default)]
pub struct WindowsLogonTracker {
    by_user: HashMap<String, VecDeque<f64>>,
    by_source: HashMap<String, VecDeque<(f64, String)>>,
    /// Alert suppression is independent from evidence consumed on success.
    last_alert: HashMap<(&'static str, String), f64>,
}

fn bound<K: Clone + Ord + Hash, V>(m: &mut HashMap<K, V>, last_seen: impl Fn(&V) -> f64) {
    if m.len() >= MAX_KEYS {
        let oldest = m
            .iter()
            .min_by(|(left_key, left), (right_key, right)| {
                last_seen(left)
                    .total_cmp(&last_seen(right))
                    .then_with(|| left_key.cmp(right_key))
            })
            .map(|(key, _)| key.clone());
        if let Some(key) = oldest {
            m.remove(&key);
        }
    }
}

fn alert_due(
    alerts: &mut HashMap<(&'static str, String), f64>,
    scope: &'static str,
    subject: &str,
    now: f64,
) -> bool {
    let key = (scope, subject.to_owned());
    if alerts.get(&key).is_some_and(|last| now - last < WINDOW) {
        return false;
    }
    if !alerts.contains_key(&key) {
        bound(alerts, |last| *last);
    }
    alerts.insert(key, now);
    true
}

impl WindowsLogonTracker {
    /// Feed one normalised logon outcome. Returns the detections it completes.
    pub fn observe(&mut self, l: &UserLogonData, now: f64) -> Vec<DetectionData> {
        let user = l.username.to_ascii_lowercase();
        let source = l
            .src_addr
            .clone()
            .or_else(|| l.workstation.clone().filter(|w| !w.is_empty()))
            .map(|s| s.to_ascii_lowercase());
        let mut out = Vec::new();
        if user.is_empty() || user == "-" {
            return out;
        }
        if !l.success {
            if !self.by_user.contains_key(&user) {
                bound(&mut self.by_user, |q| {
                    q.back().copied().unwrap_or(f64::NEG_INFINITY)
                });
            }
            let q = self.by_user.entry(user.clone()).or_default();
            q.retain(|t| now - t <= WINDOW);
            q.push_back(now);
            if q.len() > MAX_FAILURES_PER_KEY {
                q.pop_front();
            }
            let n = q.len();
            if n >= USER_THRESHOLD && alert_due(&mut self.last_alert, "user", &user, now) {
                out.push(detection(
                    "auth.windows_bruteforce",
                    "Repeated failed logons against one account",
                    "T1110.001",
                    65,
                    &user,
                    format!("{n} failed logons for {} within {WINDOW:.0}s", l.username),
                    serde_json::json!({ "user": l.username, "failures": n,
                        "history_capped": n == MAX_FAILURES_PER_KEY,
                        "src_addr": l.src_addr, "last_reason": l.failure_reason }),
                    l,
                ));
            }
            if let Some(src) = &source {
                if !self.by_source.contains_key(src) {
                    bound(&mut self.by_source, |q| {
                        q.back().map(|(t, _)| *t).unwrap_or(f64::NEG_INFINITY)
                    });
                }
                let q = self.by_source.entry(src.clone()).or_default();
                q.retain(|(t, _)| now - t <= WINDOW);
                q.push_back((now, user.clone()));
                if q.len() > MAX_FAILURES_PER_KEY {
                    q.pop_front();
                }
                let users: HashSet<&str> = q.iter().map(|(_, u)| u.as_str()).collect();
                if users.len() >= SPRAY_USERS {
                    if !alert_due(&mut self.last_alert, "spray", src, now) {
                        return out;
                    }
                    let mut names: Vec<String> = users.into_iter().map(String::from).collect();
                    names.sort();
                    out.push(detection(
                        "auth.windows_password_spray",
                        "Failed logons across many accounts from one source",
                        "T1110.003",
                        75,
                        src,
                        format!(
                            "{} accounts failed to log on from {src} within {WINDOW:.0}s",
                            names.len()
                        ),
                        serde_json::json!({ "source": src, "users": names }),
                        l,
                    ));
                } else if q.len() >= SOURCE_THRESHOLD
                    && alert_due(&mut self.last_alert, "source", src, now)
                {
                    let n = q.len();
                    out.push(detection(
                        "auth.windows_bruteforce",
                        "Repeated failed logons from one source",
                        "T1110.001",
                        65,
                        src,
                        format!("{n} failed logons from {src} within {WINDOW:.0}s"),
                        serde_json::json!({ "source": src, "failures": n,
                        "history_capped": n == MAX_FAILURES_PER_KEY }),
                        l,
                    ));
                }
            }
            return out;
        }

        // Success: did the account (or the source) just fail repeatedly?
        let mut failures = 0;
        if let Some(q) = self.by_user.get_mut(&user) {
            q.retain(|t| now - t <= WINDOW);
            failures = q.len();
        }
        if let Some(src) = &source {
            if let Some(q) = self.by_source.get_mut(src) {
                q.retain(|(t, _)| now - t <= WINDOW);
                failures = failures.max(q.iter().filter(|(_, u)| *u == user).count());
            }
        }
        // Below the brute-force bar a few typos before success are normal.
        if failures >= 3 {
            self.by_user.remove(&user);
            if let Some(src) = &source {
                if let Some(q) = self.by_source.get_mut(src) {
                    q.retain(|(_, u)| *u != user);
                }
            }
            out.push(detection(
                "auth.windows_bruteforce_success",
                "Successful logon after repeated failures",
                "T1110.001",
                80,
                &user,
                format!("{} logged on after {failures} failed attempts", l.username),
                serde_json::json!({ "user": l.username, "failures": failures,
                    "history_capped": failures == MAX_FAILURES_PER_KEY,
                    "src_addr": l.src_addr, "logon_type": l.logon_type_name }),
                l,
            ));
        }
        out
    }
}

#[allow(clippy::too_many_arguments)]
fn detection(
    rule_id: &str,
    title: &str,
    technique: &str,
    confidence: u8,
    subject: &str,
    detail: String,
    evidence: serde_json::Value,
    l: &UserLogonData,
) -> DetectionData {
    DetectionData {
        rule_id: rule_id.into(),
        title: title.into(),
        category: "credential_access".into(),
        mitre_tactic: Some("TA0006 Credential Access".into()),
        mitre_technique: Some(technique.into()),
        confidence,
        subject: subject.to_string(),
        detail,
        evidence,
        correlation: Some(CorrelationKeys {
            user: Some(l.username.clone()),
            remote_ip: l.src_addr.clone(),
            ..Default::default()
        }),
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fields(pairs: &[(&str, &str)]) -> Fields {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), serde_json::Value::String(v.to_string())))
            .collect()
    }

    #[test]
    fn failed_logon_gets_type_reason_source_and_process() {
        let f = fields(&[
            ("TargetUserName", "nobody"),
            ("TargetDomainName", "CLT-MBL"),
            ("LogonType", "2"),
            ("Status", "0xc000006d"),
            ("SubStatus", "0xc0000064"),
            ("FailureReason", "%%2313"),
            ("WorkstationName", "CLT-MBL"),
            ("IpAddress", "-"),
            ("ProcessName", "C:\\Windows\\System32\\svchost.exe"),
            ("AuthenticationPackageName", "Negotiate"),
        ]);
        let l = normalize(4625, &f).unwrap();
        assert!(!l.success);
        assert_eq!(l.logon_type, Some(2));
        assert_eq!(l.logon_type_name.as_deref(), Some("interactive"));
        assert_eq!(
            l.failure_reason.as_deref(),
            Some("user name does not exist")
        );
        assert_eq!(l.src_addr, None);
        assert_eq!(l.workstation.as_deref(), Some("CLT-MBL"));
        assert_eq!(
            l.process_name.as_deref(),
            Some("C:\\Windows\\System32\\svchost.exe")
        );
        assert_eq!(l.sub_status.as_deref(), Some("0xc0000064"));
    }

    #[test]
    fn legacy_failure_reason_resolves_when_status_is_unknown() {
        let f = fields(&[("TargetUserName", "a"), ("FailureReason", "%%2313")]);
        assert_eq!(
            normalize(4625, &f).unwrap().failure_reason.as_deref(),
            Some("unknown user name or bad password")
        );
        let mut raw = fields(&[
            ("LogonType", "10"),
            ("Status", "0xc000006d"),
            ("FailureReason", "%%2313"),
        ]);
        enrich_fields(4625, &mut raw);
        assert_eq!(raw["logon_type_name"], "remote_interactive");
        assert_eq!(
            raw["failure_reason_text"],
            "unknown user name or bad password"
        );
        assert_eq!(
            raw["status_text"],
            "logon failure (bad user name or password)"
        );
        // Other event ids are left alone.
        let mut other = fields(&[("LogonType", "3")]);
        enrich_fields(4688, &mut other);
        assert!(!other.contains_key("logon_type_name"));
    }

    #[test]
    fn system_and_service_logons_are_dropped() {
        for (user, domain, sid, t) in [
            ("SYSTEM", "NT AUTHORITY", "S-1-5-18", "5"),
            ("SYSTEM", "NT AUTHORITY", "S-1-5-18", "0"),
            ("LOCAL SERVICE", "NT AUTHORITY", "S-1-5-19", "5"),
            ("CLT-MBL$", "WORKGROUP", "S-1-5-18", "3"),
            ("DWM-2", "Window Manager", "S-1-5-90-0-2", "2"),
            ("UMFD-0", "Font Driver Host", "S-1-5-96-0-0", "2"),
            ("ANONYMOUS LOGON", "NT AUTHORITY", "S-1-5-7", "3"),
            ("svc-backup", "CORP", "S-1-5-21-1", "5"),
        ] {
            let f = fields(&[
                ("TargetUserName", user),
                ("TargetDomainName", domain),
                ("TargetUserSid", sid),
                ("LogonType", t),
            ]);
            assert!(
                normalize(4624, &f).is_none(),
                "{user} type {t} should be dropped"
            );
        }
    }

    #[test]
    fn real_user_logons_are_kept() {
        let f = fields(&[
            ("TargetUserName", "alice"),
            ("TargetDomainName", "CORP"),
            ("TargetUserSid", "S-1-5-21-1-2-3-1001"),
            ("LogonType", "10"),
            ("IpAddress", "198.51.100.4"),
            ("IpPort", "51234"),
            ("AuthenticationPackageName", "Negotiate"),
        ]);
        let l = normalize(4624, &f).unwrap();
        assert!(l.success);
        assert_eq!(l.logon_type_name.as_deref(), Some("remote_interactive"));
        assert_eq!(l.src_addr.as_deref(), Some("198.51.100.4"));
        assert_eq!(l.src_port, Some(51234));
        // A failed logon for SYSTEM-like names is still reported.
        let f = fields(&[("TargetUserName", "SYSTEM"), ("LogonType", "3")]);
        assert!(normalize(4625, &f).is_some());
        assert!(normalize(4776, &f).is_none());
    }

    fn fail(user: &str, src: Option<&str>) -> UserLogonData {
        UserLogonData {
            username: user.into(),
            src_addr: src.map(String::from),
            success: false,
            ..Default::default()
        }
    }

    #[test]
    fn success_after_bruteforce_threshold_retains_failure_evidence() {
        for failures in [5, 10, 20] {
            let mut tracker = WindowsLogonTracker::default();
            for i in 0..failures {
                tracker.observe(&fail("alice", Some("203.0.113.5")), i as f64);
            }
            let mut success = fail("alice", Some("203.0.113.5"));
            success.success = true;
            let out = tracker.observe(&success, 30.0);
            let finding = out
                .iter()
                .find(|d| d.rule_id == "auth.windows_bruteforce_success")
                .expect("threshold alert must not erase evidence needed by success correlation");
            assert_eq!(finding.evidence["failures"], failures);
            assert!(
                tracker.observe(&success, 31.0).is_empty(),
                "success consumes its failure evidence"
            );
        }
    }

    #[test]
    fn spray_alert_does_not_erase_success_correlation() {
        let mut tracker = WindowsLogonTracker::default();
        for i in 0..5 {
            tracker.observe(&fail("alice", Some("203.0.113.5")), i as f64);
        }
        let mut spray = false;
        for (i, user) in ["bob", "carol", "dan", "erin"].iter().enumerate() {
            spray |= tracker
                .observe(&fail(user, Some("203.0.113.5")), 5.0 + i as f64)
                .iter()
                .any(|d| d.rule_id == "auth.windows_password_spray");
        }
        assert!(spray);
        let mut success = fail("alice", Some("203.0.113.5"));
        success.success = true;
        assert!(tracker
            .observe(&success, 10.0)
            .iter()
            .any(|d| d.rule_id == "auth.windows_bruteforce_success"));
    }

    #[test]
    fn repeated_alerts_have_a_separate_window_cooldown() {
        let mut tracker = WindowsLogonTracker::default();
        let mut account_hits = 0;
        let mut source_hits = 0;
        for i in 0..30 {
            for finding in tracker.observe(&fail("alice", Some("203.0.113.5")), i as f64) {
                if finding.rule_id == "auth.windows_bruteforce" {
                    if finding.evidence.get("source").is_some() {
                        source_hits += 1;
                    } else {
                        account_hits += 1;
                    }
                }
            }
        }
        assert_eq!(account_hits, 1);
        assert_eq!(source_hits, 1);
        let mut after_expiry = 0;
        for i in 0..5 {
            after_expiry += tracker
                .observe(&fail("alice", Some("203.0.113.5")), 305.0 + i as f64)
                .iter()
                .filter(|d| d.rule_id == "auth.windows_bruteforce")
                .count();
        }
        assert_eq!(
            after_expiry, 2,
            "account and source cooldowns expire independently of retained failures"
        );
    }

    #[test]
    fn retained_failure_history_stays_bounded_under_a_flood() {
        let mut tracker = WindowsLogonTracker::default();
        for i in 0..1000 {
            tracker.observe(&fail("alice", Some("203.0.113.5")), i as f64 / 100.0);
        }
        assert!(tracker.by_user.values().all(|q| q.len() <= 128));
        assert!(tracker.by_source.values().all(|q| q.len() <= 128));
        let mut success = fail("alice", Some("203.0.113.5"));
        success.success = true;
        assert!(tracker
            .observe(&success, 11.0)
            .iter()
            .any(|d| d.rule_id == "auth.windows_bruteforce_success"));
    }

    #[test]
    fn success_at_capacity_preserves_a_tracked_accounts_failures() {
        let mut tracker = WindowsLogonTracker::default();
        for i in 0..3 {
            tracker.observe(&fail("victim", Some("source-victim")), i as f64);
        }
        for i in 0..4095 {
            tracker.observe(
                &fail(&format!("user-{i}"), Some(&format!("source-{i}"))),
                3.0,
            );
        }
        assert_eq!(tracker.by_user.len(), 4096);
        assert_eq!(tracker.by_source.len(), 4096);
        let mut success = fail("victim", Some("source-victim"));
        success.success = true;
        assert!(tracker
            .observe(&success, 4.0)
            .iter()
            .any(|d| d.rule_id == "auth.windows_bruteforce_success"));
        assert_eq!(
            tracker.by_user.len(),
            4095,
            "success drains only its account"
        );
        assert_eq!(
            tracker.by_source.len(),
            4096,
            "success must not reset unrelated sources"
        );
        tracker.observe(&fail("new-user", Some("new-source")), 5.0);
        assert_eq!(tracker.by_user.len(), 4096);
        assert_eq!(tracker.by_source.len(), 4096);
        assert!(
            tracker.by_user.contains_key("user-4094"),
            "one new key must not discard all other history"
        );
        assert!(tracker.by_source.contains_key("source-4094"));
        // Updating a tracked key at capacity keeps its history. A later new
        // key evicts the oldest account/source, preserving the active one.
        for now in [6.0, 7.0] {
            tracker.observe(&fail("user-4094", Some("source-4094")), now);
        }
        tracker.observe(&fail("overflow", Some("overflow-source")), 8.0);
        assert!(!tracker.by_user.contains_key("user-0"));
        assert!(!tracker.by_source.contains_key("source-0"));
        let mut success = fail("user-4094", Some("source-4094"));
        success.success = true;
        assert!(tracker
            .observe(&success, 9.0)
            .iter()
            .any(|d| d.rule_id == "auth.windows_bruteforce_success"));
    }

    #[test]
    fn spray_cooldown_is_independent_from_source_bruteforce() {
        let mut tracker = WindowsLogonTracker::default();
        for i in 0..10 {
            tracker.observe(&fail("alice", Some("203.0.113.5")), i as f64);
        }
        let mut hits = 0;
        for i in 0..20 {
            hits += tracker
                .observe(
                    &fail(&format!("user-{i}"), Some("203.0.113.5")),
                    10.0 + i as f64,
                )
                .iter()
                .filter(|d| d.rule_id == "auth.windows_password_spray")
                .count();
        }
        assert_eq!(
            hits, 1,
            "source alert must not suppress spray or cause repeated spray alerts"
        );
        let mut next_window = 0;
        for i in 0..5 {
            next_window += tracker
                .observe(
                    &fail(&format!("next-{i}"), Some("203.0.113.5")),
                    315.0 + i as f64,
                )
                .iter()
                .filter(|d| d.rule_id == "auth.windows_password_spray")
                .count();
        }
        assert_eq!(next_window, 1);
    }

    #[test]
    fn success_consumes_only_its_account_and_expired_failures_do_not_match() {
        let mut tracker = WindowsLogonTracker::default();
        for i in 0..3 {
            tracker.observe(&fail("alice", Some("203.0.113.5")), i as f64);
            tracker.observe(&fail("bob", Some("203.0.113.5")), i as f64);
        }
        for user in ["alice", "bob"] {
            let mut success = fail(user, Some("203.0.113.5"));
            success.success = true;
            assert!(tracker
                .observe(&success, 4.0)
                .iter()
                .any(|d| d.rule_id == "auth.windows_bruteforce_success"));
            assert!(tracker.observe(&success, 5.0).is_empty());
        }
        for i in 0..5 {
            tracker.observe(&fail("carol", Some("203.0.113.5")), i as f64);
        }
        let mut success = fail("carol", Some("203.0.113.5"));
        success.success = true;
        assert!(
            tracker.observe(&success, 305.0).is_empty(),
            "expired failure evidence must not correlate"
        );
    }

    #[test]
    fn brute_force_per_account_fires_once_per_burst() {
        let mut t = WindowsLogonTracker::default();
        let mut hits = 0;
        for i in 0..5 {
            hits += t
                .observe(&fail("alice", Some("203.0.113.5")), i as f64)
                .iter()
                .filter(|d| d.rule_id == "auth.windows_bruteforce")
                .count();
        }
        assert_eq!(hits, 1);
        // Failures spread out beyond the window never accumulate.
        let mut t = WindowsLogonTracker::default();
        for i in 0..20 {
            assert!(t.observe(&fail("bob", None), i as f64 * 120.0).is_empty());
        }
    }

    #[test]
    fn password_spray_needs_many_accounts_from_one_source() {
        let mut t = WindowsLogonTracker::default();
        let mut spray = None;
        for (i, u) in ["a", "b", "c", "d", "e"].iter().enumerate() {
            for d in t.observe(&fail(u, Some("203.0.113.9")), i as f64) {
                if d.rule_id == "auth.windows_password_spray" {
                    spray = Some(d);
                }
            }
        }
        let d = spray.expect("spray detected");
        assert_eq!(d.mitre_technique.as_deref(), Some("T1110.003"));
        // The same five accounts from five different sources do not.
        let mut t = WindowsLogonTracker::default();
        for (i, u) in ["a", "b", "c", "d", "e"].iter().enumerate() {
            let src = format!("203.0.113.{i}");
            assert!(t.observe(&fail(u, Some(&src)), i as f64).is_empty());
        }
    }

    #[test]
    fn success_after_failures_fires_but_typos_do_not() {
        let ok = |u: &str| UserLogonData {
            username: u.into(),
            src_addr: Some("203.0.113.5".into()),
            success: true,
            ..Default::default()
        };
        let mut t = WindowsLogonTracker::default();
        for i in 0..4 {
            t.observe(&fail("alice", Some("203.0.113.5")), i as f64);
        }
        let out = t.observe(&ok("alice"), 10.0);
        assert!(out
            .iter()
            .any(|d| d.rule_id == "auth.windows_bruteforce_success"));
        // State is consumed: a second success is quiet.
        assert!(t.observe(&ok("alice"), 11.0).is_empty());
        // One mistyped password then success is normal.
        let mut t = WindowsLogonTracker::default();
        t.observe(&fail("bob", None), 0.0);
        assert!(t.observe(&ok("bob"), 5.0).is_empty());
    }

    #[test]
    fn source_flood_on_one_account_is_a_single_brute_force_family() {
        let mut t = WindowsLogonTracker::default();
        let mut n = 0;
        for i in 0..10 {
            n += t
                .observe(&fail("root", Some("198.51.100.1")), i as f64)
                .iter()
                .filter(|d| d.rule_id == "auth.windows_bruteforce")
                .count();
        }
        // Per-account (at 5) and per-source (at 10) thresholds both apply.
        assert!(n >= 1);
    }
}
