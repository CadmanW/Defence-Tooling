//! S3/MinIO forwarder for TTY session blobs.

use super::object_storage::S3Client;
use super::spool;
use crate::misc::get_hostname;

use log::{debug, error};
use std::path::{Path, PathBuf};
use tokio::time::{Duration, interval};

/// Run the S3 forwarding loop. This function never returns under normal operation.
pub async fn run(s3: S3Client, spool_dir: PathBuf, interval_secs: u64) {
    debug!("TTY S3 forwarder started (interval={}s)", interval_secs);

    let mut tick = interval(Duration::from_secs(interval_secs));

    loop {
        tokio::select! {
            _ = tick.tick() => {
                if let Err(e) = forward_once(&s3, &spool_dir).await {
                    error!("TTY S3 forward tick failed: {e:#}");
                }
            }
        }
    }
}

/// One forward pass: upload every sealed chunk file and delete it on success.
async fn forward_once(s3: &S3Client, spool_dir: &Path) -> anyhow::Result<()> {
    let hostname = get_hostname().unwrap_or_else(|| "unknown".to_string());
    let chunks = spool::collect_ready_chunks(spool_dir, &hostname).await?;

    if chunks.is_empty() {
        return Ok(());
    }

    for chunk in chunks {
        match s3
            .put_object_multipart_file(&chunk.s3_key, &chunk.path)
            .await
        {
            Ok(()) => {
                if let Err(e) = tokio::fs::remove_file(&chunk.path).await {
                    error!(
                        "Uploaded chunk {} but failed to delete local file {}: {e}",
                        chunk.s3_key,
                        chunk.path.display(),
                    );
                } else {
                    if let Some(parent) = chunk.path.parent() {
                        let _ = tokio::fs::remove_dir(parent).await;
                    }
                    debug!(
                        "Forwarded tty chunk {} -> s3://{}",
                        chunk.path.display(),
                        chunk.s3_key
                    );
                }
            }
            Err(e) => {
                error!(
                    "S3 upload failed for tty chunk {} (key={}): {e:#}; will retry next tick",
                    chunk.path.display(),
                    chunk.s3_key,
                );
            }
        }
    }

    Ok(())
}
