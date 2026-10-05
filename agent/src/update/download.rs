//! Streaming download of an update artifact into the staging directory.
//!
//! The artifact is untrusted until its SHA-256 matches the digest from the
//! signed release statement, so the bytes are hashed while streaming and the
//! file is only handed back (and renamed into place) after the comparison. The
//! transfer is capped at the signed size: a server cannot make the agent buffer
//! more than it was told to expect.

use std::path::Path;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;

use super::manifest::{sha256_matches, VerifiedArtifact};

/// Hosts a GitHub release download may redirect through.
const ALLOWED_REDIRECT_HOSTS: &[&str] = &[
    "github.com",
    "objects.githubusercontent.com",
    "release-assets.githubusercontent.com",
];
const MAX_REDIRECTS: usize = 5;

/// Client for artifact downloads.
///
/// Deliberately *not* [`crate::http::build_client`]: that client trusts only the
/// backend's pinned CA, which cannot validate github.com. Transport trust is not
/// what protects the update — the signed SHA-256 is — so the public web PKI is
/// acceptable here. Redirects are restricted to https and GitHub's hosts.
pub fn download_client() -> Result<reqwest::Client> {
    let policy = reqwest::redirect::Policy::custom(|attempt| {
        let url = attempt.url();
        let host_ok = url
            .host_str()
            .map(|h| ALLOWED_REDIRECT_HOSTS.contains(&h))
            .unwrap_or(false);
        if attempt.previous().len() >= MAX_REDIRECTS {
            attempt.error("too many redirects")
        } else if url.scheme() != "https" || !host_ok {
            attempt.error("redirect to a disallowed host")
        } else {
            attempt.follow()
        }
    });
    reqwest::ClientBuilder::new()
        .use_rustls_tls()
        .redirect(policy)
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(600))
        .build()
        .context("update: failed to build download client")
}

/// Download `update.url` to `dest` and verify size and SHA-256.
///
/// On any failure `dest` is removed, so a partial or mismatching file is never
/// left behind for the apply step to find.
pub async fn download_verified(
    client: &reqwest::Client,
    artifact: &VerifiedArtifact,
    dest: &Path,
) -> Result<()> {
    let result = download_inner(client, artifact, dest).await;
    if result.is_err() {
        let _ = tokio::fs::remove_file(dest).await;
    }
    result
}

async fn download_inner(
    client: &reqwest::Client,
    update: &VerifiedArtifact,
    dest: &Path,
) -> Result<()> {
    let mut resp = client
        .get(&update.url)
        .send()
        .await
        .context("update: download request failed")?;
    if !resp.status().is_success() {
        bail!("update: download returned HTTP {}", resp.status());
    }
    if let Some(len) = resp.content_length() {
        if len != update.size {
            bail!(
                "update: content-length {len} differs from signed size {}",
                update.size
            );
        }
    }

    let mut file = tokio::fs::File::create(dest)
        .await
        .with_context(|| format!("update: create {}", dest.display()))?;
    let mut hasher = Sha256::new();
    let mut received: u64 = 0;

    while let Some(chunk) = resp.chunk().await.context("update: download interrupted")? {
        received += chunk.len() as u64;
        if received > update.size {
            bail!("update: artifact larger than signed size {}", update.size);
        }
        hasher.update(&chunk);
        file.write_all(&chunk)
            .await
            .context("update: write staged artifact")?;
    }
    file.flush().await?;
    file.sync_all().await?;

    if received != update.size {
        bail!(
            "update: artifact truncated ({received} of {} bytes)",
            update.size
        );
    }
    if !sha256_matches(hasher, &update.sha256) {
        bail!("update: SHA-256 mismatch, artifact rejected");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// One-shot HTTP/1.1 server answering a single request with `body`.
    async fn serve(body: Vec<u8>) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            let _ = s.read(&mut buf).await;
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = s.write_all(head.as_bytes()).await;
            let _ = s.write_all(&body).await;
        });
        format!("http://{addr}/artifact")
    }

    fn update_for(url: &str, body: &[u8]) -> VerifiedArtifact {
        VerifiedArtifact {
            url: url.to_string(),
            sha256: Sha256::digest(body).into(),
            size: body.len() as u64,
        }
    }

    #[tokio::test]
    async fn accepts_matching_artifact() {
        let body = b"genuine agent binary".to_vec();
        let url = serve(body.clone()).await;
        let dir = tempfile_dir();
        let dest = dir.join("staged.bin");
        download_verified(&reqwest::Client::new(), &update_for(&url, &body), &dest)
            .await
            .unwrap();
        assert_eq!(std::fs::read(&dest).unwrap(), body);
    }

    #[tokio::test]
    async fn rejects_and_removes_tampered_artifact() {
        let signed = b"genuine agent binary".to_vec();
        // Same length as the signed artifact, so only the digest can catch it.
        let url = serve(vec![b'x'; signed.len()]).await;
        let dir = tempfile_dir();
        let dest = dir.join("staged.bin");
        let err = download_verified(&reqwest::Client::new(), &update_for(&url, &signed), &dest)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("SHA-256 mismatch"), "{err}");
        assert!(
            !dest.exists(),
            "mismatching artifact must not remain on disk"
        );
    }

    #[tokio::test]
    async fn rejects_size_mismatch() {
        let signed = b"short".to_vec();
        let url = serve(b"much longer body than signed".to_vec()).await;
        let dir = tempfile_dir();
        let dest = dir.join("staged.bin");
        let err = download_verified(&reqwest::Client::new(), &update_for(&url, &signed), &dest)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("signed size"), "{err}");
        assert!(!dest.exists());
    }

    fn tempfile_dir() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("trapd-update-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }
}
