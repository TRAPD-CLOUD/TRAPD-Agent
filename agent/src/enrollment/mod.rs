use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tracing::info;
use uuid::Uuid;

#[derive(Serialize)]
struct EnrollRequest {
    agent_id: Uuid,
    hostname: String,
}

#[derive(Deserialize)]
struct EnrollResponse {
    token: String,
}

/// Resolves the agent token using this priority order:
/// 1. Persisted token at `~/.trapd/token`
/// 2. `TRAPD_TOKEN` env var (persisted for future runs)
/// 3. POST `{backend_url}/api/v1/enroll` → save received token
pub async fn load_or_enroll_token(
    backend_url: &str,
    agent_id:    Uuid,
    hostname:    &str,
) -> Result<String> {
    let token_path = token_path()?;

    // 1. Persisted token
    if token_path.exists() {
        let raw = tokio::fs::read_to_string(&token_path)
            .await
            .context("Failed to read token file")?;
        let token = raw.trim().to_string();
        if !token.is_empty() {
            return Ok(token);
        }
    }

    // 2. Environment variable
    if let Ok(token) = std::env::var("TRAPD_TOKEN") {
        if !token.is_empty() {
            persist_token(&token_path, &token).await?;
            return Ok(token);
        }
    }

    // 3. Enroll with backend
    info!("No token found — enrolling with backend at {backend_url}");
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{backend_url}/api/v1/enroll"))
        .json(&EnrollRequest {
            agent_id,
            hostname: hostname.to_string(),
        })
        .send()
        .await
        .context("Enrollment request failed")?;

    if !resp.status().is_success() {
        anyhow::bail!("Enrollment failed: HTTP {}", resp.status());
    }

    let body: EnrollResponse = resp
        .json()
        .await
        .context("Failed to parse enrollment response")?;

    persist_token(&token_path, &body.token).await?;
    info!("Enrollment successful — token persisted to {}", token_path.display());
    Ok(body.token)
}

async fn persist_token(path: &Path, token: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .context("Failed to create ~/.trapd directory")?;
    }
    tokio::fs::write(path, token)
        .await
        .context("Failed to write token file")?;
    Ok(())
}

fn token_path() -> Result<PathBuf> {
    let home = std::env::var("HOME").context("HOME env var not set")?;
    Ok(PathBuf::from(home).join(".trapd").join("token"))
}
