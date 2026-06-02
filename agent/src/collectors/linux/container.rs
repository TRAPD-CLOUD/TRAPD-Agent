//! Container image / label enrichment from the on-host runtime state.
//!
//! The cgroup path yields only the container *id*. A Falcon-class sensor also
//! carries the **image name + digest** and the orchestration **labels** (pod /
//! namespace for Kubernetes). Those live in the runtime's own metadata, not in
//! `/proc`, so this module reads them best-effort from the runtime state files
//! the daemons write to disk — no CRI/daemon socket round-trip required:
//!
//!   * **Docker / dockershim** — `/var/lib/docker/containers/<id>/config.v2.json`
//!     carries `Image` (the `sha256:` digest), `Config.Image` (the name:tag) and
//!     `Config.Labels` (which, under Kubernetes, include `io.kubernetes.pod.*`).
//!   * **containerd (CRI)** — the same `io.kubernetes.*` labels surface in the
//!     container's OCI `config.json` under the CRI state root.
//!
//! Everything is best-effort: an unreadable file (non-root, or a runtime not
//! present) degrades to `None`/empty rather than failing the event.

use std::collections::BTreeMap;

/// Resolved image / label metadata for a container.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ContainerImage {
    /// Image reference, e.g. `nginx:1.25` (from `Config.Image`).
    pub image: Option<String>,
    /// Image content digest, e.g. `sha256:…` (from `Image`).
    pub image_digest: Option<String>,
    /// Runtime/orchestration labels (`io.kubernetes.pod.name`, …).
    pub labels: BTreeMap<String, String>,
}

impl ContainerImage {
    pub fn is_empty(&self) -> bool {
        self.image.is_none() && self.image_digest.is_none() && self.labels.is_empty()
    }
}

/// Candidate runtime state roots, tried in order. Each `{}` is replaced with the
/// full container id.
const DOCKER_STATE: &str = "/var/lib/docker/containers";
const CONTAINERD_CRI_STATE: &[&str] = &[
    "/run/containerd/io.containerd.runtime.v2.task/k8s.io",
    "/run/containerd/io.containerd.runtime.v1.linux/k8s.io",
];

/// Resolve image + labels for a container id (full 64-char id from the cgroup).
pub fn resolve(container_id: &str) -> ContainerImage {
    // Only accept a plausible id so we never stat() attacker-influenced paths.
    if !(12..=64).contains(&container_id.len())
        || !container_id.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return ContainerImage::default();
    }

    if let Some(info) = read_docker(container_id) {
        if !info.is_empty() {
            return info;
        }
    }
    read_containerd(container_id).unwrap_or_default()
}

fn read_docker(id: &str) -> Option<ContainerImage> {
    let path = format!("{DOCKER_STATE}/{id}/config.v2.json");
    let json = std::fs::read_to_string(path).ok()?;
    Some(parse_docker_config(&json))
}

fn read_containerd(id: &str) -> Option<ContainerImage> {
    for root in CONTAINERD_CRI_STATE {
        let path = format!("{root}/{id}/config.json");
        if let Ok(json) = std::fs::read_to_string(&path) {
            return Some(parse_oci_config(&json));
        }
    }
    None
}

/// Parse the relevant fields out of a Docker `config.v2.json`. Pure + tested.
pub fn parse_docker_config(json: &str) -> ContainerImage {
    let v: serde_json::Value = match serde_json::from_str(json) {
        Ok(v) => v,
        Err(_) => return ContainerImage::default(),
    };

    let image_digest = v
        .get("Image")
        .and_then(|x| x.as_str())
        .filter(|s| s.starts_with("sha256:"))
        .map(str::to_string);

    let config = v.get("Config");
    let image = config
        .and_then(|c| c.get("Image"))
        .and_then(|x| x.as_str())
        .map(str::to_string);

    let labels = config
        .and_then(|c| c.get("Labels"))
        .and_then(|l| l.as_object())
        .map(|obj| {
            obj.iter()
                .filter_map(|(k, val)| val.as_str().map(|s| (k.clone(), s.to_string())))
                .collect()
        })
        .unwrap_or_default();

    ContainerImage { image, image_digest, labels }
}

/// Parse the relevant fields out of an OCI runtime `config.json` (containerd /
/// CRI). The image name + k8s labels live in `annotations`.
pub fn parse_oci_config(json: &str) -> ContainerImage {
    let v: serde_json::Value = match serde_json::from_str(json) {
        Ok(v) => v,
        Err(_) => return ContainerImage::default(),
    };

    let labels: BTreeMap<String, String> = v
        .get("annotations")
        .and_then(|a| a.as_object())
        .map(|obj| {
            obj.iter()
                .filter_map(|(k, val)| val.as_str().map(|s| (k.clone(), s.to_string())))
                .collect()
        })
        .unwrap_or_default();

    // CRI records the image reference under these annotation keys.
    let image = labels
        .get("io.kubernetes.cri.image-name")
        .or_else(|| labels.get("io.kubernetes.image.name"))
        .cloned();

    ContainerImage { image, image_digest: None, labels }
}

/// Extract the Kubernetes pod name / namespace / uid from container labels, if
/// the workload is orchestrated by Kubernetes (labels are set by the kubelet).
pub fn k8s_labels(
    labels: &BTreeMap<String, String>,
) -> (Option<String>, Option<String>, Option<String>) {
    let name = labels.get("io.kubernetes.pod.name").cloned();
    let namespace = labels.get("io.kubernetes.pod.namespace").cloned();
    let uid = labels.get("io.kubernetes.pod.uid").cloned();
    (name, namespace, uid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_docker_config_with_k8s_labels() {
        let json = r#"{
            "Image": "sha256:abc123def4567890",
            "Config": {
                "Image": "registry.io/nginx:1.25",
                "Labels": {
                    "io.kubernetes.pod.name": "web-7d9",
                    "io.kubernetes.pod.namespace": "prod",
                    "io.kubernetes.pod.uid": "1234-5678",
                    "maintainer": "team"
                }
            }
        }"#;
        let info = parse_docker_config(json);
        assert_eq!(info.image.as_deref(), Some("registry.io/nginx:1.25"));
        assert_eq!(info.image_digest.as_deref(), Some("sha256:abc123def4567890"));
        let (name, ns, uid) = k8s_labels(&info.labels);
        assert_eq!(name.as_deref(), Some("web-7d9"));
        assert_eq!(ns.as_deref(), Some("prod"));
        assert_eq!(uid.as_deref(), Some("1234-5678"));
        assert_eq!(info.labels.get("maintainer").map(String::as_str), Some("team"));
    }

    #[test]
    fn ignores_non_digest_image_field() {
        let json = r#"{"Image":"nginx","Config":{"Image":"nginx:latest"}}"#;
        let info = parse_docker_config(json);
        assert!(info.image_digest.is_none());
        assert_eq!(info.image.as_deref(), Some("nginx:latest"));
    }

    #[test]
    fn parses_oci_annotations() {
        let json = r#"{
            "annotations": {
                "io.kubernetes.cri.image-name": "docker.io/library/redis:7",
                "io.kubernetes.pod.namespace": "cache"
            }
        }"#;
        let info = parse_oci_config(json);
        assert_eq!(info.image.as_deref(), Some("docker.io/library/redis:7"));
        let (_, ns, _) = k8s_labels(&info.labels);
        assert_eq!(ns.as_deref(), Some("cache"));
    }

    #[test]
    fn malformed_json_is_empty() {
        assert!(parse_docker_config("not json").is_empty());
        assert!(parse_oci_config("{").is_empty());
    }

    #[test]
    fn resolve_rejects_implausible_ids() {
        assert!(resolve("../../etc/passwd").is_empty());
        assert!(resolve("short").is_empty());
        assert!(resolve("nothexZZZZZZ").is_empty());
    }
}
