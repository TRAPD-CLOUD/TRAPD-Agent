//! OCSF 1.9.0 contract for agent telemetry.
//!
//! Standard fields are authoritative. `unmapped.trapd` preserves source
//! evidence not represented by OCSF and permits lossless legacy processing.
use chrono::{DateTime, SecondsFormat, Utc};
use serde_json::{json, Value};

pub const OCSF_VERSION: &str = "1.9.0";
pub const CAPABILITY_HEADER: &str = "x-trapd-event-formats";
pub const CAPABILITY_VALUE: &str = "legacy,ocsf-1.9.0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContractError(pub &'static str);
impl std::fmt::Display for ContractError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for ContractError {}

pub fn is_ocsf(v: &Value) -> bool {
    v.get("class_uid").is_some()
        || v.get("metadata")
            .is_some_and(|m| m.get("version").is_some())
}
fn string<'a>(v: &'a Value, key: &str) -> Result<&'a str, ContractError> {
    v.get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or(ContractError("missing or invalid string"))
}
fn severity(s: &str) -> Result<u64, ContractError> {
    match s {
        "info" => Ok(1),
        "low" => Ok(2),
        "medium" => Ok(3),
        "high" => Ok(4),
        "critical" => Ok(5),
        _ => Err(ContractError("invalid severity")),
    }
}
fn severity_name(n: u64) -> &'static str {
    match n {
        2 => "low",
        3 => "medium",
        4 => "high",
        5 | 6 => "critical",
        _ => "info",
    }
}
fn classification(class: &str, action: &str, data: &Value) -> (u64, u64) {
    match (class, action) {
        ("process", "create" | "exec" | "fork") => (1007, 1),
        ("process", "terminate") => (1007, 2),
        ("process", "ptrace") => (1007, 3),
        ("process", "setuid") => (1007, 5),
        ("filesystem", "create") => (1001, 1),
        ("filesystem", "modify" | "integrity_violation") => (1001, 3),
        ("filesystem", "delete" | "unlink") => (1001, 4),
        ("filesystem", "rename") => (1001, 5),
        ("filesystem", "chmod") => (1001, 7),
        ("filesystem", "chown") => (1001, 6),
        ("filesystem", "open") => (1001, 14),
        ("network", "dns_query" | "dns_response")
            if data.get("qname").and_then(Value::as_str).is_some() =>
        {
            (4003, if action == "dns_response" { 2 } else { 1 })
        }
        ("network", "connection") => (
            4001,
            if data.get("state").and_then(Value::as_str) == Some("closed") {
                2
            } else {
                1
            },
        ),
        ("network", "bind") => (4001, 7),
        ("network", "accept") => (4001, 1),
        ("network", "tls_handshake") => (4001, 99),
        ("user", "logon" | "logon_failed" | "session_open") => (3002, 1),
        ("user", "session_close") => (3002, 2),
        ("detection", "detected" | "honeytoken_access") => (2004, 1),
        ("prevention", _)
            if data
                .get("command_id")
                .and_then(Value::as_str)
                .is_some_and(|s| !s.is_empty()) =>
        {
            (
                7001,
                match action {
                    "network_isolated" | "ip_blocked" | "file_quarantined" | "process_frozen" => 1,
                    "process_blocked" => 2,
                    "network_deisolated" | "ip_unblocked" | "file_restored" | "process_thawed" => 3,
                    "honeytoken_deployed" | "deception_escalation" => 6,
                    _ => 99,
                },
            )
        }
        ("system", "snapshot") => (5001, 2),
        _ => (0, 99),
    }
}
fn copy(out: &mut Value, dest: &str, src: &Value, keys: &[&str]) {
    if let Some(v) = keys.iter().find_map(|k| {
        src.get(*k)
            .filter(|v| !v.is_null() && v.as_str() != Some(""))
    }) {
        // Collectors may retain non-IP source tokens from text logs. Keep that
        // evidence in the extension, never emit an invalid standard IP.
        if dest != "ip"
            || v.as_str()
                .is_some_and(|s| s.parse::<std::net::IpAddr>().is_ok())
        {
            out[dest] = v.clone();
        }
    }
}
fn file(path: &str) -> Value {
    json!({"path":path,"name":path.rsplit(['/', '\\']).next().filter(|s|!s.is_empty()).unwrap_or(path),"type_id":0})
}
fn process(data: &Value, target: bool) -> Value {
    let mut p = json!({});
    copy(
        &mut p,
        "pid",
        data,
        if target {
            &["target_pid", "child_pid", "pid"]
        } else {
            &["parent_pid", "ppid"]
        },
    );
    copy(
        &mut p,
        "name",
        data,
        if target {
            &["child_comm", "comm", "name", "process"]
        } else {
            &["parent_comm", "parent_name"]
        },
    );
    if target {
        copy(&mut p, "cmd_line", data, &["cmdline", "cmd"]);
        if let Some(path) = data
            .get("exe")
            .or_else(|| data.get("image"))
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
        {
            p["file"] = file(path);
            if let Some(hash) = data
                .get("exe_sha256")
                .and_then(Value::as_str)
                .filter(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()))
            {
                p["file"]["hashes"] = json!([{"algorithm_id":3,"value":hash}]);
            }
        }
    }
    p
}
fn actor(data: &Value, parent: bool) -> Value {
    let mut a = json!({});
    let p = if parent {
        process(data, false)
    } else {
        process(data, true)
    };
    if ["pid", "uid", "cpid"]
        .iter()
        .any(|k| p.get(*k).is_some_and(|v| !v.is_null()))
    {
        a["process"] = p;
    }
    if let Some(name) = data
        .get(if parent {
            "parent_username"
        } else {
            "username"
        })
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
    {
        a["user"] = json!({"name":name});
    }
    a
}

/// Map a legacy source event at the delivery boundary, never minting identity.
pub fn to_ocsf(v: &Value) -> Result<Value, ContractError> {
    let uid = string(v, "event_id")?;
    uuid::Uuid::parse_str(uid).map_err(|_| ContractError("invalid event_id"))?;
    let agent = string(v, "agent_id")?;
    let hostname = string(v, "hostname")?;
    let timestamp = string(v, "timestamp")?;
    let time = DateTime::parse_from_rfc3339(timestamp)
        .map_err(|_| ContractError("invalid timestamp"))?
        .timestamp_millis();
    let class = string(v, "class")?;
    let action = string(v, "action")?;
    let sev = string(v, "severity")?;
    let data = v
        .get("data")
        .filter(|d| d.is_object())
        .ok_or(ContractError("invalid event data"))?;
    for key in [
        "pid",
        "ppid",
        "parent_pid",
        "child_pid",
        "target_pid",
        "sender_pid",
        "uid",
        "gid",
    ] {
        if let Some(pid) = data.get(key).filter(|v| !v.is_null()) {
            if !pid.as_u64().is_some_and(|n| n <= u32::MAX as u64) {
                return Err(ContractError("invalid source process pid"));
            }
        }
    }
    for key in ["src_port", "dst_port", "port"] {
        if let Some(port) = data.get(key).filter(|v| !v.is_null()) {
            if !port.as_u64().is_some_and(|n| n <= u16::MAX as u64) {
                return Err(ContractError("invalid source endpoint port"));
            }
        }
    }
    for (path, max) in [
        ("/correlation/pid", u32::MAX as u64),
        ("/evidence/pid", u32::MAX as u64),
        ("/correlation/remote_port", u16::MAX as u64),
    ] {
        if let Some(n) = data.pointer(path).filter(|v| !v.is_null()) {
            if !n.as_u64().is_some_and(|n| n <= max) {
                return Err(ContractError("invalid detection correlation identifier"));
            }
        }
    }
    let (mut cid, mut aid) = classification(class, action, data);
    if cid == 1001
        && !data
            .get("path")
            .or_else(|| data.get("old_path"))
            .and_then(Value::as_str)
            .is_some_and(|p| !p.is_empty())
    {
        // Incomplete collector evidence remains deliverable without inventing a file.
        cid = 0;
        aid = 99;
    }
    let mut ext = json!({"schema_version":1,"class":class,"action":action,"severity":sev,"data":data,"timestamp":timestamp});
    if let Some(origin) = v.get("origin") {
        ext["origin"] = origin.clone();
    }
    let mut out = json!({"metadata":{"version":OCSF_VERSION,"uid":uid,"profiles":["host"],"product":{"name":"TRAPD Agent","vendor_name":"TRAPD"}},"time":time,"category_uid":cid/1000,"class_uid":cid,"activity_id":aid,"type_uid":cid*100+aid,"severity_id":severity(sev)?,"device":{"uid":agent,"hostname":hostname,"type_id":0},"unmapped":{"trapd":ext}});
    if aid == 99 {
        out["activity_name"] = json!(action);
        let caption = match cid {
            0 => "Base Event",
            1001 => "File System Activity",
            1007 => "Process Activity",
            2004 => "Detection Finding",
            3002 => "Authentication",
            4001 => "Network Activity",
            4003 => "DNS Activity",
            5001 => "Device Inventory Info",
            7001 => "Remediation Activity",
            _ => unreachable!(),
        };
        out["type_name"] = json!(format!("{caption}: {action}"));
    }
    match cid {
        1007 => {
            out["actor"] = actor(data, matches!(action, "create" | "exec" | "fork"));
            out["process"] = process(data, true);
            if action == "ptrace" {
                out["actor"] = json!({"process": {}});
                copy(&mut out["actor"]["process"], "pid", data, &["pid"]);
                copy(&mut out["actor"]["process"], "name", data, &["comm"]);
                out["process"] = json!({});
                copy(&mut out["process"], "pid", data, &["target_pid"]);
                copy(
                    &mut out["process"],
                    "name",
                    data,
                    &["target_comm", "target_name"],
                );
            }
            copy(&mut out, "exit_code", data, &["exit_code"]);
        }
        1001 => {
            out["actor"] = actor(data, false);
            let path = data
                .get("path")
                .or_else(|| data.get("old_path"))
                .and_then(Value::as_str)
                .filter(|p| !p.is_empty())
                .ok_or(ContractError("file activity requires path"))?;
            out["file"] = file(path);
        }
        4001 => {
            let mut src = json!({});
            copy(&mut src, "ip", data, &["src_addr"]);
            copy(&mut src, "port", data, &["src_port"]);
            let mut dst = json!({});
            copy(&mut dst, "ip", data, &["dst_addr", "addr"]);
            copy(&mut dst, "port", data, &["dst_port", "port"]);
            if action == "bind" {
                src = dst;
                dst = json!({});
            }
            if src.as_object().is_some_and(|o| !o.is_empty()) {
                out["src_endpoint"] = src;
            }
            if dst.as_object().is_some_and(|o| !o.is_empty()) {
                out["dst_endpoint"] = dst;
            }
            if let Some(proto) = data.get("protocol").and_then(Value::as_str) {
                out["connection_info"] = json!({"protocol_name":proto,"direction_id":0});
            }
            if let Some(pid) = data.get("pid").filter(|p| !p.is_null()) {
                out["actor"] = json!({"process":{"pid":pid}});
            }
        }
        4003 => {
            out["query"] = json!({"hostname":data["qname"]});
            if let Some(qtype) = data.get("qtype") {
                out["query"]["type"] = qtype.clone();
            }
            if let Some(ips) = data.get("resolved_ips").and_then(Value::as_array) {
                out["answers"] =
                    json!(ips.iter().map(|ip| json!({"rdata":ip})).collect::<Vec<_>>());
            }
            if let Some(ip) = data.get("server_addr").filter(|v| {
                v.as_str()
                    .is_some_and(|s| s.parse::<std::net::IpAddr>().is_ok())
            }) {
                out["dst_endpoint"] = json!({"ip":ip});
            }
            if let Some(ip) = data.get("client_addr").filter(|v| {
                v.as_str()
                    .is_some_and(|s| s.parse::<std::net::IpAddr>().is_ok())
            }) {
                out["src_endpoint"] = json!({"ip":ip});
            }
        }
        3002 => {
            out["user"] = json!({});
            copy(&mut out["user"], "name", data, &["username"]);
            out["dst_endpoint"] = json!({"hostname":hostname,"uid":agent});
            let mut src = json!({});
            copy(&mut src, "ip", data, &["src_addr"]);
            copy(&mut src, "port", data, &["src_port"]);
            if src.as_object().is_some_and(|o| !o.is_empty()) {
                out["src_endpoint"] = src;
            }
            if action == "logon_failed" {
                out["status_id"] = json!(2);
            } else if let Some(success) = data.get("success").and_then(Value::as_bool) {
                out["status_id"] = json!(if success { 1 } else { 2 });
            }
        }
        2004 => {
            out["finding_info"] = json!({"uid":uid});
            copy(
                &mut out["finding_info"],
                "title",
                data,
                &["title", "name", "rule_id"],
            );
            copy(
                &mut out["finding_info"],
                "desc",
                data,
                &["detail", "description", "details"],
            );
        }
        7001 => {
            out["command_uid"] = data["command_id"].clone();
            if let Some(success) = data.get("success").and_then(Value::as_bool) {
                out["status_id"] = json!(if success { 1 } else { 2 });
            }
        }
        _ => {}
    }
    for ep in ["src_endpoint", "dst_endpoint"] {
        if out.get(ep).is_some_and(|e| {
            e.get("ip").is_none() && e.get("hostname").is_none() && e.get("uid").is_none()
        }) {
            out.as_object_mut().unwrap().remove(ep);
        }
    }
    let identified_process = |p: &Value| {
        ["pid", "uid", "cpid"]
            .iter()
            .any(|k| p.get(*k).is_some_and(|v| !v.is_null()))
    };
    let identified_actor = |a: &Value| {
        a.get("process").is_some_and(identified_process)
            || a.get("user").is_some_and(|u| u.get("name").is_some())
    };
    if (cid == 1007 && (!identified_process(&out["process"]) || !identified_actor(&out["actor"])))
        || (cid == 1001 && !identified_actor(&out["actor"]))
        || (cid == 3002 && out["user"].get("name").is_none())
    {
        // Keep sparse collector evidence deliverable without fabricating identity.
        out["class_uid"] = json!(0);
        out["category_uid"] = json!(0);
        out["activity_id"] = json!(99);
        out["type_uid"] = json!(99);
        out["activity_name"] = json!(action);
        out["type_name"] = json!(format!("Base Event: {action}"));
        for field in [
            "process",
            "actor",
            "file",
            "user",
            "exit_code",
            "status_id",
            "dst_endpoint",
            "src_endpoint",
        ] {
            out.as_object_mut().unwrap().remove(field);
        }
    }
    if matches!(cid, 4001 | 4003)
        && out.get("src_endpoint").is_none()
        && out.get("dst_endpoint").is_none()
    {
        out["src_endpoint"] = json!({"hostname":hostname,"uid":agent});
    }
    validate_standard(&out)?;
    Ok(out)
}

/// Validate the supported OCSF classes without integer narrowing or fallback.
fn validate_standard(v: &Value) -> Result<(), ContractError> {
    let m = v.get("metadata").ok_or(ContractError("missing metadata"))?;
    if string(m, "version")? != OCSF_VERSION {
        return Err(ContractError("unsupported OCSF version"));
    }
    if !m.get("product").is_some_and(Value::is_object) {
        return Err(ContractError("invalid product"));
    }
    string(m, "uid")?;
    let time = v
        .get("time")
        .and_then(Value::as_i64)
        .ok_or(ContractError("invalid OCSF time"))?;
    if DateTime::<Utc>::from_timestamp_millis(time).is_none() {
        return Err(ContractError("out of range OCSF time"));
    }
    let cid = v
        .get("class_uid")
        .and_then(Value::as_u64)
        .ok_or(ContractError("invalid class_uid"))?;
    let aid = v
        .get("activity_id")
        .and_then(Value::as_u64)
        .ok_or(ContractError("invalid activity_id"))?;
    let max = match cid {
        0 => 0,
        1007 => 5,
        1001 => 14,
        4001 => 7,
        4003 => 6,
        3002 => 7,
        2004 => 3,
        5001 => 2,
        7001 => 6,
        _ => return Err(ContractError("unsupported OCSF class")),
    };
    if !((aid == 0 || aid == 99 || (aid >= 1 && aid <= max))
        && (cid != 4003 || [0, 1, 2, 6, 99].contains(&aid)))
    {
        return Err(ContractError("invalid class activity"));
    }
    if aid == 99 {
        string(v, "activity_name")?;
    }
    if v.get("category_uid").and_then(Value::as_u64) != Some(cid / 1000)
        || v.get("type_uid").and_then(Value::as_u64) != Some(cid * 100 + aid)
    {
        return Err(ContractError("inconsistent classification"));
    }
    if !matches!(
        v.get("severity_id").and_then(Value::as_u64),
        Some(0..=6 | 99)
    ) {
        return Err(ContractError("invalid severity_id"));
    }
    for key in match cid {
        1007 => &["device", "actor", "process"][..],
        1001 => &["device", "actor", "file"][..],
        3002 => &["user"][..],
        2004 => &["finding_info"][..],
        5001 => &["device"][..],
        _ => &[][..],
    } {
        if !v.get(*key).is_some_and(Value::is_object) {
            return Err(ContractError("missing class object"));
        }
    }
    if let Some(d) = v.get("device") {
        if d.get("type_id").and_then(Value::as_u64).is_none() {
            return Err(ContractError("missing device type_id"));
        }
    }
    if cid == 1001 {
        let f = &v["file"];
        string(f, "name")?;
        if f.get("type_id").and_then(Value::as_u64).is_none() {
            return Err(ContractError("missing file type_id"));
        }
    }
    if cid == 2004 {
        string(&v["finding_info"], "uid")?;
    }
    if cid == 7001 {
        string(v, "command_uid")?;
    }
    if matches!(cid, 4001 | 4003)
        && v.get("src_endpoint").is_none()
        && v.get("dst_endpoint").is_none()
    {
        return Err(ContractError("missing network endpoint"));
    }
    if cid == 3002 && v.get("service").is_none() && v.get("dst_endpoint").is_none() {
        return Err(ContractError("missing authentication target"));
    }
    for path in [
        "/process",
        "/process/parent_process",
        "/actor/process",
        "/actor/process/parent_process",
    ] {
        if let Some(p) = v.pointer(path) {
            if !p.is_object()
                || !["pid", "uid", "cpid"]
                    .iter()
                    .any(|k| p.get(*k).is_some_and(|v| !v.is_null()))
            {
                return Err(ContractError("missing process identity"));
            }
        }
    }
    if let Some(a) = v.get("actor") {
        if !a.is_object()
            || ![
                "process",
                "user",
                "iam_role",
                "session",
                "app",
                "invoked_by",
                "idp",
            ]
            .iter()
            .any(|k| a.get(*k).is_some_and(|v| !v.is_null()))
        {
            return Err(ContractError("missing actor identity"));
        }
    }
    for path in ["/user", "/actor/user", "/process/user"] {
        if let Some(u) = v.pointer(path) {
            if !u.is_object()
                || !["account", "name", "uid"].iter().any(|k| {
                    u.get(*k)
                        .is_some_and(|v| !v.is_null() && v.as_str() != Some(""))
                })
            {
                return Err(ContractError("missing user identity"));
            }
        }
    }
    for ep in ["src_endpoint", "dst_endpoint"] {
        if let Some(e) = v.get(ep) {
            if !e.is_object()
                || ![
                    "ip",
                    "uid",
                    "name",
                    "hostname",
                    "mac",
                    "domain",
                    "interface_uid",
                    "instance_uid",
                ]
                .iter()
                .any(|k| {
                    e.get(*k)
                        .is_some_and(|v| !v.is_null() && v.as_str() != Some(""))
                })
            {
                return Err(ContractError("missing endpoint identity"));
            }
        }
        if let Some(ip) = v.pointer(&format!("/{ep}/ip")) {
            if !ip
                .as_str()
                .is_some_and(|s| s.parse::<std::net::IpAddr>().is_ok())
            {
                return Err(ContractError("invalid endpoint IP"));
            }
        }
        if let Some(port) = v.pointer(&format!("/{ep}/port")) {
            if !port.as_u64().is_some_and(|n| n <= 65535) {
                return Err(ContractError("invalid endpoint port"));
            }
        }
    }
    if let Some(query) = v.get("query") {
        string(query, "hostname")?;
    }
    for path in [
        "/process/pid",
        "/process/parent_process/pid",
        "/actor/process/pid",
        "/actor/process/parent_process/pid",
    ] {
        if let Some(pid) = v.pointer(path) {
            if !pid.as_u64().is_some_and(|n| n <= u32::MAX as u64) {
                return Err(ContractError("invalid process pid"));
            }
        }
    }
    Ok(())
}

pub fn validate(v: &Value) -> Result<(), ContractError> {
    validate_standard(v)?;
    if let Some(ext) = v.pointer("/unmapped/trapd") {
        if ext.get("schema_version").and_then(Value::as_u64) != Some(1) {
            return Err(ContractError("unsupported TRAPD extension"));
        }
        let legacy = legacy_from_extension(v, ext)?;
        let mapped = to_ocsf(&legacy)?;
        for key in [
            "class_uid",
            "activity_id",
            "severity_id",
            "time",
            "process",
            "actor",
            "file",
            "user",
            "finding_info",
            "command_uid",
            "status_id",
            "src_endpoint",
            "dst_endpoint",
            "connection_info",
            "query",
            "answers",
        ] {
            if v.get(key) != mapped.get(key) {
                return Err(ContractError("OCSF fields contradict source evidence"));
            }
        }
    }
    Ok(())
}
fn legacy_from_extension(v: &Value, ext: &Value) -> Result<Value, ContractError> {
    let device = v
        .get("device")
        .ok_or(ContractError("missing agent device"))?;
    let mut legacy = json!({"event_id":string(&v["metadata"],"uid")?,"agent_id":string(device,"uid")?,"hostname":string(device,"hostname")?,"timestamp":string(ext,"timestamp")?,"class":string(ext,"class")?,"action":string(ext,"action")?,"severity":string(ext,"severity")?,"data":ext.get("data").filter(|d|d.is_object()).ok_or(ContractError("invalid extension data"))?});
    if let Some(origin) = ext.get("origin") {
        legacy["origin"] = origin.clone();
    }
    Ok(legacy)
}

/// Legacy analytics projection. The original OCSF remains the stored payload.
pub fn from_ocsf(v: &Value) -> Result<Value, ContractError> {
    validate(v)?;
    let uid = string(&v["metadata"], "uid")?;
    uuid::Uuid::parse_str(uid)
        .map_err(|_| ContractError("agent contract requires UUID metadata.uid"))?;
    if let Some(ext) = v.pointer("/unmapped/trapd") {
        return legacy_from_extension(v, ext);
    }
    let device = v
        .get("device")
        .ok_or(ContractError("missing agent device"))?;
    let cid = v["class_uid"]
        .as_u64()
        .ok_or(ContractError("invalid class"))?;
    let aid = v["activity_id"]
        .as_u64()
        .ok_or(ContractError("invalid activity"))?;
    let (class, action) = match (cid, aid) {
        (1007, 1) => ("process", "create"),
        (1007, 2) => ("process", "terminate"),
        (1001, 1) => ("filesystem", "create"),
        (1001, 2 | 14) => ("filesystem", "open"),
        (1001, 3) => ("filesystem", "modify"),
        (1001, 4) => ("filesystem", "delete"),
        (4001, 1 | 2 | 6) => ("network", "connection"),
        (4003, 1) => ("network", "dns_query"),
        (4003, 2) => ("network", "dns_response"),
        (3002, 1) => (
            "user",
            if v.get("status_id").and_then(Value::as_u64) == Some(2) {
                "logon_failed"
            } else {
                "logon"
            },
        ),
        (3002, 2) => ("user", "session_close"),
        (2004, 1) => ("detection", "detected"),
        _ => ("ocsf", "other"),
    };
    let mut data = json!({});
    match cid {
        1007 => {
            let p = &v["process"];
            copy(&mut data, "pid", p, &["pid"]);
            copy(&mut data, "name", p, &["name"]);
            copy(&mut data, "cmdline", p, &["cmd_line"]);
            copy(&mut data, "exe", &p["file"], &["path"]);
            copy(&mut data, "ppid", &v["actor"]["process"], &["pid"]);
        }
        1001 => {
            copy(&mut data, "path", &v["file"], &["path", "name"]);
        }
        4001 => {
            copy(&mut data, "src_addr", &v["src_endpoint"], &["ip"]);
            copy(&mut data, "src_port", &v["src_endpoint"], &["port"]);
            copy(&mut data, "dst_addr", &v["dst_endpoint"], &["ip"]);
            copy(&mut data, "dst_port", &v["dst_endpoint"], &["port"]);
            copy(
                &mut data,
                "protocol",
                &v["connection_info"],
                &["protocol_name"],
            );
            data["state"] = json!(if aid == 2 { "closed" } else { "open" });
        }
        4003 => {
            copy(&mut data, "qname", &v["query"], &["hostname"]);
            copy(&mut data, "qtype", &v["query"], &["type"]);
        }
        3002 => {
            copy(&mut data, "username", &v["user"], &["name"]);
        }
        // Generic third-party findings are stored but do not impersonate a
        // catalogued agent rule or drive response automation.
        2004 => {
            copy(
                &mut data,
                "description",
                &v["finding_info"],
                &["desc", "title"],
            );
        }
        _ => {}
    }
    let time = v["time"].as_i64().ok_or(ContractError("invalid time"))?;
    let timestamp = DateTime::<Utc>::from_timestamp_millis(time)
        .ok_or(ContractError("out of range time"))?
        .to_rfc3339_opts(SecondsFormat::Millis, true);
    Ok(
        json!({"event_id":uid,"agent_id":string(device,"uid")?,"hostname":string(device,"hostname")?,"timestamp":timestamp,"class":class,"action":action,"severity":severity_name(v["severity_id"].as_u64().ok_or(ContractError("invalid severity"))?),"data":data}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn event(class: &str, action: &str, data: Value) -> Value {
        json!({"event_id":"a2522ab9-4f09-4c6f-93cb-61f91c716224","agent_id":"agent_test","hostname":"host","timestamp":"2026-10-09T12:00:00.123456Z","class":class,"action":action,"severity":"medium","data":data,"origin":{"boot_id":"boot","sequence_number":42,"monotonic_timestamp_ns":123456789}})
    }
    #[test]
    fn sparse_evidence_uses_lossless_base_other() {
        for (class, action, data) in [
            ("process", "exec", json!({"pid":42})),
            ("filesystem", "open", json!({"path":"/tmp/file"})),
            ("filesystem", "open", json!({"pid":42,"path":""})),
            ("user", "logon", json!({"success":false})),
        ] {
            let src = event(class, action, data);
            let mapped = to_ocsf(&src).unwrap();
            assert_eq!(mapped["class_uid"], 0);
            assert_eq!(from_ocsf(&mapped).unwrap(), src);
        }
    }
    #[test]
    fn rejects_invalid_nested_identity_and_addresses() {
        let valid = to_ocsf(&event("process", "exec", json!({"pid":42,"ppid":1}))).unwrap();
        for process in [json!({}), json!({"pid":4294967296u64})] {
            let mut bad = valid.clone();
            bad["actor"]["process"] = process;
            assert!(validate(&bad).is_err());
        }
        let valid = to_ocsf(&event(
            "network",
            "dns_response",
            json!({"qname":"example.org","server_addr":"192.0.2.1"}),
        ))
        .unwrap();
        for endpoint in [
            json!({}),
            json!({"ip":""}),
            json!({"ip":"invalid"}),
            json!({"ip":"192.0.2.1","port":65536}),
        ] {
            let mut bad = valid.clone();
            bad["dst_endpoint"] = endpoint;
            assert!(validate(&bad).is_err());
        }
    }
    #[test]
    fn collected_snapshots_and_unknown_network_direction_are_explicit() {
        let snapshot = to_ocsf(&event("system", "snapshot", json!({"os":"Linux"}))).unwrap();
        assert_eq!(snapshot["activity_id"], 2);
        let connection=to_ocsf(&event("network","connection",json!({"protocol":"tcp","src_addr":"127.0.0.1","dst_addr":"127.0.0.2","src_port":1000,"dst_port":443}))).unwrap();
        assert_eq!(connection["connection_info"]["direction_id"], 0);
    }
    #[test]
    fn process_identity_and_evidence_roundtrip() {
        let src = event(
            "process",
            "exec",
            json!({"pid":123,"ppid":1,"exe":"/bin/sh","cmdline":"sh -c id","uid":1000}),
        );
        let dst = to_ocsf(&src).unwrap();
        assert_eq!(dst["metadata"]["uid"], src["event_id"]);
        assert_eq!(dst["time"], 1791547200123i64);
        assert_eq!(dst["class_uid"], 1007);
        assert_eq!(dst["type_uid"], 100701);
        assert_eq!(dst["process"]["pid"], 123);
        assert_eq!(from_ocsf(&dst).unwrap(), src);
    }
    #[test]
    fn activities_are_class_specific() {
        let file = to_ocsf(&event(
            "filesystem",
            "delete",
            json!({"path":"/tmp/a","pid":42}),
        ))
        .unwrap();
        assert_eq!(file["class_uid"], 1001);
        assert_eq!(file["activity_id"], 4);
        let proc = to_ocsf(&event("process", "terminate", json!({"pid":42}))).unwrap();
        assert_eq!(proc["activity_id"], 2);
    }
    #[test]
    fn rejects_inconsistent_standard_and_extension() {
        let mut dst = to_ocsf(&event("process", "exec", json!({"pid":42}))).unwrap();
        dst["device"]["uid"] = json!("agent_other");
        assert_eq!(from_ocsf(&dst).unwrap()["agent_id"], "agent_other");
        dst["class_uid"] = json!(1001);
        assert!(validate(&dst).is_err());
    }
    #[test]
    fn rejects_bad_numbers_version_and_time() {
        let dst = to_ocsf(&event("process", "exec", json!({"pid":42}))).unwrap();
        for (key, value) in [
            ("class_uid", json!(655361007u64)),
            ("severity_id", json!(256)),
            ("activity_id", json!(256)),
            ("type_uid", json!(100702)),
            ("time", json!("bad")),
        ] {
            let mut bad = dst.clone();
            bad[key] = value;
            assert!(validate(&bad).is_err(), "{key}");
        }
        let mut bad = dst;
        bad["metadata"]["version"] = json!("0.1.0");
        assert!(validate(&bad).is_err());
    }
    #[test]
    fn unknown_trapd_action_uses_base_event_other() {
        let src = event("system", "ebpf_drops", json!({"lost":5}));
        let dst = to_ocsf(&src).unwrap();
        assert_eq!(dst["class_uid"], 0);
        assert_eq!(dst["activity_id"], 99);
        assert_eq!(from_ocsf(&dst).unwrap(), src);
    }
    #[test]
    fn required_objects_and_class_dependent_fields() {
        for (class, action, data, key) in [
            (
                "filesystem",
                "open",
                json!({"path":"/etc/passwd","pid":42}),
                "file",
            ),
            (
                "detection",
                "detected",
                json!({"rule_id":"rule","description":"test"}),
                "finding_info",
            ),
            ("user", "logon", json!({"username":"alice"}), "user"),
        ] {
            let mut dst = to_ocsf(&event(class, action, data)).unwrap();
            assert!(validate(&dst).is_ok());
            dst.as_object_mut().unwrap().remove(key);
            assert!(validate(&dst).is_err(), "{key}");
        }
    }
    #[test]
    fn preserves_extensions_without_inventing_outcomes() {
        let dst = to_ocsf(&event(
            "process",
            "exec",
            json!({"pid":42,"enrichment_errors":{"cmdline":"process_exited"}}),
        ))
        .unwrap();
        assert!(dst.get("status_id").is_none());
        assert_eq!(
            dst["unmapped"]["trapd"]["data"]["enrichment_errors"]["cmdline"],
            "process_exited"
        );
    }
}
