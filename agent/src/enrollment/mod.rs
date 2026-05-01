use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tracing::info;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credentials {
    pub agent_id: String,
    pub agent_secret: String,
    pub project_id: String,
}

#[derive(Serialize)]
struct EnrollRequest {
    enrollment_token: String,
    device_id: String,
    hostname: String,
    os_version: String,
    arch: String,
    agent_version: String,
}

#[derive(Deserialize)]
struct EnrollResponse {
    agent_id: String,
    agent_secret: String,
    project_id: String,
}

/// Load persisted credentials or enroll for the first time via TRAPD_ENROLL_TOKEN.
///
/// Credential storage: `~/.trapd/credentials.json`
/// First-run: set `TRAPD_ENROLL_TOKEN=<token>` + `TRAPD_BACKEND_URL=<url>` before starting.
pub async fn load_or_enroll(
    backend_url: &str,
    device_id: &str,
    hostname: &str,
) -> Result<Credentials> {
    let creds_path = credentials_path()?;

    // 1. Return persisted credentials if they exist and are valid
    if creds_path.exists() {
        let raw = tokio::fs::read_to_string(&creds_path)
            .await
            .context("Failed to read credentials file")?;
        match serde_json::from_str::<Credentials>(&raw) {
            Ok(creds) if !creds.agent_id.is_empty() && !creds.agent_secret.is_empty() => {
                info!("Loaded credentials for agent_id={}", creds.agent_id);
                return Ok(creds);
            }
            _ => {}
        }
    }

    // 2. First-run enrollment via TRAPD_ENROLL_TOKEN
    let enroll_token = std::env::var("TRAPD_ENROLL_TOKEN").context(
        "No credentials found at ~/.trapd/credentials.json and TRAPD_ENROLL_TOKEN is not set.\n\
         To enroll this agent: set TRAPD_ENROLL_TOKEN=<token from dashboard> and restart.",
    )?;

    info!("Enrolling agent with backend at {backend_url}");

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{backend_url}/api/v1/agents/enroll"))
        .json(&EnrollRequest {
            enrollment_token: enroll_token,
            device_id: device_id.to_string(),
            hostname: hostname.to_string(),
            os_version: read_os_version(),
            arch: std::env::consts::ARCH.to_string(),
            agent_version: env!("CARGO_PKG_VERSION").to_string(),
        })
        .send()
        .await
        .context("Enrollment request failed")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("Enrollment failed: HTTP {status} — {body}");
    }

    let body: EnrollResponse = resp
        .json()
        .await
        .context("Failed to parse enrollment response")?;

    let creds = Credentials {
        agent_id: body.agent_id,
        agent_secret: body.agent_secret,
        project_id: body.project_id,
    };

    persist_credentials(&creds_path, &creds).await?;
    info!(
        agent_id = %creds.agent_id,
        project_id = %creds.project_id,
        "Agent enrolled successfully — credentials persisted to {}",
        creds_path.display()
    );

    Ok(creds)
}

fn read_os_version() -> String {
    std::fs::read_to_string("/etc/os-release")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("PRETTY_NAME="))
                .map(|l| l["PRETTY_NAME=".len()..].trim_matches('"').to_string())
        })
        .unwrap_or_else(|| "Linux".to_string())
}

async fn persist_credentials(path: &Path, creds: &Credentials) -> Result<()> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .context("Failed to create ~/.trapd directory")?;
    }
    let content =
        serde_json::to_string_pretty(creds).context("Failed to serialize credentials")?;
    tokio::fs::write(path, content)
        .await
        .context("Failed to write credentials file")?;
    Ok(())
}

fn credentials_path() -> Result<PathBuf> {
    let home = std::env::var("HOME").context("HOME env var not set")?;
    Ok(PathBuf::from(home).join(".trapd").join("credentials.json"))
}
