#![no_main]

use libfuzzer_sys::fuzz_target;
use trapd_schema as schema;

#[allow(dead_code)]
#[path = "../../agent/src/config/logs.rs"]
mod config;
#[allow(dead_code)]
#[path = "../../agent/src/collectors/logs/framing.rs"]
mod framing;

// The collector lives in the agent binary crate. Compile its actual dispatcher.
#[path = "../../agent/src/collectors/logs/parser.rs"]
mod parser;

fuzz_target!(|fields: [u8; 8]| {
    let pid = u16::from_le_bytes([fields[0], fields[1]]);
    let port = u16::from_le_bytes([fields[2], fields[3]]);
    let status = 100 + u16::from_le_bytes([fields[4], fields[5]]) % 500;
    let user = format!("user{}", fields[6]);
    let address = format!("192.0.2.{}", fields[7]);
    let stamp = "2024-01-15T12:00:00Z";

    let access = format!(
        r#"{address} - {user} [15/Jan/2024:13:00:00 +0100] "GET /index HTTP/1.1" {status} 123 "-" "client""#
    );
    let framed = format!("{access}\r\n");
    let mut rest = Vec::new();
    let mut lines = Vec::new();
    for chunk in framed.as_bytes().chunks(usize::from(fields[6]) + 1) {
        lines.extend(framing::frame_bytes(chunk, 2048, &mut rest));
    }
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0].as_str(), access);
    let iis = serde_json::json!({"date":"2024-01-15","time":"12:00:00","c-ip":address,"cs-method":"GET","cs-uri-stem":"/index","sc-status":status.to_string()}).to_string();
    for (format, line) in [
        ("apache_access", &access),
        ("nginx_access", &access),
        ("iis", &iis),
    ] {
        let record = parser::parse(format, line);
        assert_eq!(record.fields["status"].as_u64(), Some(u64::from(status)));
        assert_eq!(record.fields["remote_addr"], address);
        assert_eq!(record.timestamp.map(|t| t.timestamp()), Some(1_705_320_000));
    }

    let msg = format!("Accepted publickey for {user} from {address} port {port} ssh2");
    let ssh = parser::parse("sshd", &msg);
    assert_eq!(ssh.username.as_deref(), Some(user.as_str()));
    assert_eq!(ssh.fields["src_port"].as_u64(), Some(u64::from(port)));
    let syslog = parser::parse(
        "syslog",
        &format!("<165>1 {stamp} host app {pid} ID47 - hello world"),
    );
    let postgres = parser::parse(
        "postgresql",
        &format!("2024-01-15 12:00:00.123 UTC [{pid}] {user}@app LOG:  connection authorized"),
    );
    let audit = parser::parse(
        "auditd",
        &format!(
            "type=SYSCALL msg=audit(1712345678.123:9): syscall=59 pid={pid} uid=0 comm=\"sh\""
        ),
    );
    for record in [syslog, postgres, audit] {
        assert_eq!(record.pid, Some(i32::from(pid)));
    }

    let json = parser::parse(
        "json",
        &serde_json::json!({"message":msg,"ts":stamp}).to_string(),
    );
    let docker = parser::parse(
        "docker",
        &serde_json::json!({"log":format!("{msg}\n"),"time":stamp}).to_string(),
    );
    assert_eq!(json.message, msg);
    assert_eq!(docker.message, msg);
    let sudo = parser::parse(
        "sudo",
        &format!("{user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND=/usr/bin/id"),
    );
    assert_eq!(sudo.username.as_deref(), Some(user.as_str()));
    let mysql = parser::parse(
        "mysql",
        &format!("{stamp} {pid} [Note] [MY-010000] Access denied for user '{user}'@'{address}'"),
    );
    assert_eq!(mysql.category, "authentication");
    assert_eq!(mysql.timestamp, json.timestamp);
});
