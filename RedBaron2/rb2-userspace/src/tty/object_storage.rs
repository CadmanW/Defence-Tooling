//! Shared S3-compatible object storage client using `rusty_s3` for signing
//! and `reqwest` for async HTTP transport.

use crate::config::yaml::ObjectStorageConfig;
use anyhow::{Context, anyhow};
use log::{debug, warn};
use reqwest::header::{CONTENT_TYPE, ETAG};
use rusty_s3::actions::{CreateMultipartUpload, ListObjectsV2};
use rusty_s3::{Bucket, Credentials, S3Action, UrlStyle};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;

/// Pre-sign duration for PutObject URLs.
const PRESIGN_DURATION: Duration = Duration::from_secs(3600);

const MULTIPART_CHUNK_SIZE: usize = 8 * 1024 * 1024; // 8 MiB.
const RETRY_INITIAL_BACKOFF: Duration = Duration::from_secs(2);
const MAX_RETRIES: u32 = 3;
const HTTP_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const HTTP_TCP_KEEPALIVE: Duration = Duration::from_secs(30);
const HTTP_CONTROL_TIMEOUT: Duration = Duration::from_secs(60);
const HTTP_PUT_TIMEOUT: Duration = Duration::from_secs(120);
const HTTP_UPLOAD_PART_TIMEOUT: Duration = Duration::from_secs(300);
const HTTP_GET_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Clone)]
pub struct S3Client {
    inner: Arc<S3Inner>,
}

struct S3Inner {
    bucket: Bucket,
    credentials: Credentials,
    http: reqwest::Client,
    endpoint_str: String,
    url_style: UrlStyle,
}

impl S3Client {
    pub fn new(cfg: &ObjectStorageConfig) -> anyhow::Result<Self> {
        let endpoint = cfg
            .endpoint
            .parse()
            .map_err(|e| anyhow!("invalid object_storage.endpoint URL: {e}"))?;

        let url_style = if cfg.path_style {
            UrlStyle::Path
        } else {
            UrlStyle::VirtualHost
        };

        let bucket = Bucket::new(
            endpoint,
            url_style,
            cfg.bucket_tty.clone(),
            cfg.region.clone(),
        )
        .map_err(|e| anyhow!("invalid bucket config: {e}"))?;

        let credentials = Credentials::new(cfg.access_key.clone(), cfg.secret_key.clone());

        // Reqwest will read proxy env vars by default; set timeouts as desired.
        let http = reqwest::Client::builder()
            .user_agent("s3-client/1.0")
            .connect_timeout(HTTP_CONNECT_TIMEOUT)
            .tcp_keepalive(HTTP_TCP_KEEPALIVE)
            .build()
            .context("building reqwest client")?;

        Ok(Self {
            inner: Arc::new(S3Inner {
                bucket,
                credentials,
                http,
                endpoint_str: cfg.endpoint.clone(),
                url_style,
            }),
        })
    }

    pub fn with_bucket(&self, bucket_name: &str) -> anyhow::Result<Self> {
        let endpoint = self
            .inner
            .endpoint_str
            .parse()
            .map_err(|e| anyhow!("invalid endpoint URL on re-parse: {e}"))?;

        let bucket = Bucket::new(
            endpoint,
            self.inner.url_style,
            bucket_name.to_string(),
            self.inner.bucket.region().to_string(),
        )
        .map_err(|e| anyhow!("invalid bucket config for '{}': {e}", bucket_name))?;

        Ok(Self {
            inner: Arc::new(S3Inner {
                bucket,
                credentials: self.inner.credentials.clone(),
                http: self.inner.http.clone(),
                endpoint_str: self.inner.endpoint_str.clone(),
                url_style: self.inner.url_style,
            }),
        })
    }

    pub async fn put_object(&self, key: &str, body: &[u8]) -> anyhow::Result<()> {
        self.with_retry(key, || async move { self.put_object_once(key, body).await })
            .await
    }

    pub async fn put_object_multipart(&self, key: &str, data: &[u8]) -> anyhow::Result<()> {
        self.with_retry(key, || async move {
            self.put_object_multipart_once(key, data).await
        })
        .await
    }

    async fn with_retry<F, Fut>(&self, key: &str, mut op: F) -> anyhow::Result<()>
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = anyhow::Result<()>>,
    {
        let mut last_err: Option<anyhow::Error> = None;

        for attempt in 0..MAX_RETRIES {
            match op().await {
                Ok(()) => return Ok(()),
                Err(e) => {
                    let delay = RETRY_INITIAL_BACKOFF * 2u32.saturating_pow(attempt);
                    last_err = Some(e);

                    if attempt + 1 < MAX_RETRIES {
                        warn!(
                            "S3 upload attempt {}/{} failed for key {}: {:#}; retrying in {:?}",
                            attempt + 1,
                            MAX_RETRIES,
                            key,
                            last_err.as_ref().unwrap(),
                            delay
                        );
                        sleep(delay).await;
                    }
                }
            }
        }

        Err(last_err.unwrap_or_else(|| anyhow!("S3 upload failed for key {key}")))
    }

    async fn put_object_once(&self, key: &str, body: &[u8]) -> anyhow::Result<()> {
        let action = self
            .inner
            .bucket
            .put_object(Some(&self.inner.credentials), key);
        let url = action.sign(PRESIGN_DURATION);

        debug!("S3 PutObject {} ({} bytes)", key, body.len());

        let resp = self
            .inner
            .http
            .put(url.as_str())
            .header(CONTENT_TYPE, "application/octet-stream")
            .timeout(HTTP_PUT_TIMEOUT)
            .body(body.to_vec())
            .send()
            .await
            .with_context(|| format!("S3 PutObject HTTP request failed for key {key}"))?;

        let status = resp.status();
        if !status.is_success() {
            let body_text = resp.text().await.unwrap_or_default();
            return Err(anyhow!(
                "S3 PutObject returned status {status} for key {key}: {body_text}"
            ));
        }

        debug!("S3 PutObject {} succeeded (status {})", key, status);
        Ok(())
    }

    async fn put_object_multipart_once(&self, key: &str, data: &[u8]) -> anyhow::Result<()> {
        if data.len() <= MULTIPART_CHUNK_SIZE {
            return self.put_object_once(key, data).await;
        }

        debug!(
            "S3 multipart upload {} ({} bytes, {} parts)",
            key,
            data.len(),
            data.len().div_ceil(MULTIPART_CHUNK_SIZE)
        );

        let upload_id = self.initiate_multipart(key).await?;

        match self.upload_parts(key, &upload_id, data).await {
            Ok(etags) => {
                self.complete_multipart(key, &upload_id, &etags).await?;
                debug!("S3 multipart upload {} completed successfully", key);
                Ok(())
            }
            Err(e) => {
                if let Err(abort_err) = self.abort_multipart(key, &upload_id).await {
                    debug!("S3 AbortMultipartUpload also failed: {abort_err:#}");
                }
                Err(e)
            }
        }
    }

    async fn initiate_multipart(&self, key: &str) -> anyhow::Result<String> {
        let action = self
            .inner
            .bucket
            .create_multipart_upload(Some(&self.inner.credentials), key);
        let url = action.sign(PRESIGN_DURATION);

        let resp = self
            .inner
            .http
            .post(url.as_str())
            .timeout(HTTP_CONTROL_TIMEOUT)
            .body(Vec::new())
            .send()
            .await
            .with_context(|| format!("S3 CreateMultipartUpload failed for key {key}"))?;

        let status = resp.status();
        let body = resp
            .text()
            .await
            .context("reading CreateMultipartUpload response")?;

        if !status.is_success() {
            return Err(anyhow!(
                "S3 CreateMultipartUpload returned {status} for key {key}: {body}"
            ));
        }

        let parsed = CreateMultipartUpload::parse_response(&body)
            .map_err(|e| anyhow!("parsing CreateMultipartUpload XML: {e}"))?;

        let upload_id = parsed.upload_id().to_string();
        debug!(
            "S3 CreateMultipartUpload {} -> upload_id={}",
            key, upload_id
        );
        Ok(upload_id)
    }

    async fn upload_parts(
        &self,
        key: &str,
        upload_id: &str,
        data: &[u8],
    ) -> anyhow::Result<Vec<String>> {
        let mut etags = Vec::with_capacity(data.len().div_ceil(MULTIPART_CHUNK_SIZE));

        for (i, chunk) in data.chunks(MULTIPART_CHUNK_SIZE).enumerate() {
            let part_number = (i + 1) as u16;

            let action = self.inner.bucket.upload_part(
                Some(&self.inner.credentials),
                key,
                part_number,
                upload_id,
            );
            let url = action.sign(PRESIGN_DURATION);

            let resp = self
                .inner
                .http
                .put(url.as_str())
                .header(CONTENT_TYPE, "application/octet-stream")
                .timeout(HTTP_UPLOAD_PART_TIMEOUT)
                .body(chunk.to_vec())
                .send()
                .await
                .with_context(|| format!("S3 UploadPart {part_number} failed for key {key}"))?;

            let status = resp.status();
            if !status.is_success() {
                let body_text = resp.text().await.unwrap_or_default();
                return Err(anyhow!(
                    "S3 UploadPart {part_number} returned {status} for key {key}: {body_text}"
                ));
            }

            let etag = resp
                .headers()
                .get(ETAG)
                .ok_or_else(|| anyhow!("S3 UploadPart {part_number} missing ETag header"))?
                .to_str()
                .map_err(|e| anyhow!("S3 UploadPart {part_number} ETag not valid UTF-8: {e}"))?
                .to_string();

            debug!(
                "S3 UploadPart {} part {} ({} bytes) etag={}",
                key,
                part_number,
                chunk.len(),
                etag
            );

            etags.push(etag);
        }

        Ok(etags)
    }

    async fn complete_multipart(
        &self,
        key: &str,
        upload_id: &str,
        etags: &[String],
    ) -> anyhow::Result<()> {
        let action = self.inner.bucket.complete_multipart_upload(
            Some(&self.inner.credentials),
            key,
            upload_id,
            etags.iter().map(String::as_str),
        );
        let url = action.sign(PRESIGN_DURATION);
        let body = action.body();

        let resp = self
            .inner
            .http
            .post(url.as_str())
            .header(CONTENT_TYPE, "application/xml")
            .timeout(HTTP_CONTROL_TIMEOUT)
            .body(body.into_bytes())
            .send()
            .await
            .with_context(|| format!("S3 CompleteMultipartUpload failed for key {key}"))?;

        let status = resp.status();
        if !status.is_success() {
            let body_text = resp.text().await.unwrap_or_default();
            return Err(anyhow!(
                "S3 CompleteMultipartUpload returned {status} for key {key}: {body_text}"
            ));
        }

        Ok(())
    }

    async fn abort_multipart(&self, key: &str, upload_id: &str) -> anyhow::Result<()> {
        let action =
            self.inner
                .bucket
                .abort_multipart_upload(Some(&self.inner.credentials), key, upload_id);
        let url = action.sign(PRESIGN_DURATION);

        debug!("S3 AbortMultipartUpload {} upload_id={}", key, upload_id);

        let resp = self
            .inner
            .http
            .delete(url.as_str())
            .timeout(HTTP_CONTROL_TIMEOUT)
            .send()
            .await
            .with_context(|| format!("S3 AbortMultipartUpload failed for key {key}"))?;

        let status = resp.status();
        if !status.is_success() {
            let body_text = resp.text().await.unwrap_or_default();
            return Err(anyhow!(
                "S3 AbortMultipartUpload returned {status} for key {key}: {body_text}"
            ));
        }

        Ok(())
    }

    pub async fn get_object(&self, key: &str) -> anyhow::Result<Vec<u8>> {
        let action = self
            .inner
            .bucket
            .get_object(Some(&self.inner.credentials), key);
        let url = action.sign(PRESIGN_DURATION);

        debug!("S3 GetObject {}", key);

        let resp = self
            .inner
            .http
            .get(url.as_str())
            .timeout(HTTP_GET_TIMEOUT)
            .send()
            .await
            .with_context(|| format!("S3 GetObject HTTP request failed for key {key}"))?;

        let status = resp.status();
        if !status.is_success() {
            let body_text = resp.text().await.unwrap_or_default();
            return Err(anyhow!(
                "S3 GetObject returned status {status} for key {key}: {body_text}"
            ));
        }

        let body = resp
            .bytes()
            .await
            .with_context(|| format!("reading S3 GetObject response for key {key}"))?
            .to_vec();

        debug!("S3 GetObject {} succeeded ({} bytes)", key, body.len());
        Ok(body)
    }

    pub async fn list_objects(&self, prefix: Option<&str>) -> anyhow::Result<Vec<String>> {
        let mut all_keys = Vec::new();
        let mut continuation_token: Option<String> = None;

        loop {
            let mut action = self
                .inner
                .bucket
                .list_objects_v2(Some(&self.inner.credentials));

            if let Some(pfx) = prefix {
                action.with_prefix(pfx);
            }
            if let Some(token) = &continuation_token {
                action.with_continuation_token(token.as_str());
            }

            let url = action.sign(PRESIGN_DURATION);

            let resp = self
                .inner
                .http
                .get(url.as_str())
                .timeout(HTTP_CONTROL_TIMEOUT)
                .send()
                .await
                .context("S3 ListObjectsV2 HTTP request failed")?;

            let status = resp.status();
            let body = resp
                .text()
                .await
                .context("reading S3 ListObjectsV2 response body")?;

            if !status.is_success() {
                return Err(anyhow!("S3 ListObjectsV2 returned status {status}: {body}"));
            }

            let parsed = ListObjectsV2::parse_response(&body)
                .map_err(|e| anyhow!("parsing ListObjectsV2 XML: {e}"))?;

            all_keys.reserve(parsed.contents.len());
            for obj in &parsed.contents {
                all_keys.push(obj.key.clone());
            }

            match parsed.next_continuation_token {
                Some(token) => continuation_token = Some(token),
                None => break,
            }
        }

        Ok(all_keys)
    }

    /// Stream a local file to S3 using multipart upload (async)
    /// Keeps memory bounded to MULTIPART_CHUNK_SIZE
    pub async fn put_object_multipart_file(
        &self,
        key: &str,
        path: &std::path::Path,
    ) -> anyhow::Result<()> {
        self.with_retry(key, || async move {
            self.put_object_multipart_file_once(key, path).await
        })
        .await
    }

    async fn put_object_multipart_file_once(
        &self,
        key: &str,
        path: &std::path::Path,
    ) -> anyhow::Result<()> {
        use tokio::fs::File;
        use tokio::io::AsyncReadExt;

        let mut file = File::open(path)
            .await
            .with_context(|| format!("opening file for multipart upload: {}", path.display()))?;

        let upload_id = self.initiate_multipart(key).await?;

        let mut part_number: u16 = 1;
        let mut etags = Vec::new();
        let mut buf = vec![0u8; MULTIPART_CHUNK_SIZE];

        loop {
            let n = file.read(&mut buf).await?;
            if n == 0 {
                break;
            }

            let chunk = &buf[..n];

            let action = self.inner.bucket.upload_part(
                Some(&self.inner.credentials),
                key,
                part_number,
                &upload_id,
            );
            let url = action.sign(PRESIGN_DURATION);

            let resp = self
                .inner
                .http
                .put(url.as_str())
                .header(CONTENT_TYPE, "application/octet-stream")
                .timeout(HTTP_UPLOAD_PART_TIMEOUT)
                .body(chunk.to_vec())
                .send()
                .await
                .with_context(|| format!("S3 UploadPart {part_number} failed for key {key}"))?;

            let status = resp.status();
            if !status.is_success() {
                let body_text = resp.text().await.unwrap_or_default();
                self.abort_multipart(key, &upload_id).await.ok();
                return Err(anyhow!(
                    "S3 UploadPart {part_number} returned {status} for key {key}: {body_text}"
                ));
            }

            let etag = resp
                .headers()
                .get(ETAG)
                .ok_or_else(|| anyhow!("S3 UploadPart missing ETag header"))?
                .to_str()
                .map_err(|e| anyhow!("Invalid ETag UTF-8: {e}"))?
                .to_string();

            etags.push(etag);
            part_number = part_number
                .checked_add(1)
                .ok_or_else(|| anyhow!("part_number overflow"))?;
        }

        self.complete_multipart(key, &upload_id, &etags).await?;
        Ok(())
    }
}
