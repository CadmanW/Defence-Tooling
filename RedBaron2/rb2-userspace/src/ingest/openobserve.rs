use super::{Ingestor, LogRecord};
use crate::config::yaml::OpenObserveConfig;
use anyhow::Context;
use async_trait::async_trait;
use flate2::Compression;
use flate2::write::GzEncoder;
use log::{debug, error, warn};
use reqwest::Url;
use reqwest::header::{CONTENT_ENCODING, CONTENT_TYPE};
use serde_json::json;
use std::io::Write;
use std::sync::Arc;
use std::time::Duration;

const HTTP_TIMEOUT_SECS: u64 = 10;

pub struct OpenObserveIngestor {
    state: Arc<State>,
}

struct State {
    name: String,
    url: String,
    stream_prefix: String,
    username: String,
    password: String,
    http: reqwest::Client,
}

impl OpenObserveIngestor {
    pub fn new(name: String, cfg: OpenObserveConfig) -> anyhow::Result<Self> {
        let mut base = cfg.url.clone();
        if !base.ends_with('/') {
            base.push('/');
        }

        let base = Url::parse(&base).context("parsing cfg.url")?;
        let url = base
            .join(&format!("api/{}/_bulk", cfg.org)) // no leading '/'
            .context("building OpenObserve bulk ingest URL")?
            .to_string();

        let http = reqwest::Client::builder()
            .user_agent("openobserve-ingestor/1.0")
            .timeout(Duration::from_secs(HTTP_TIMEOUT_SECS))
            .build()
            .context("building reqwest client")?;

        Ok(Self {
            state: Arc::new(State {
                name,
                url,
                stream_prefix: cfg.stream_prefix.clone(),
                username: cfg.username.clone(),
                password: cfg.password,
                http,
            }),
        })
    }

    fn format_ndjson(&self, records: &[Arc<LogRecord>]) -> anyhow::Result<Vec<u8>> {
        let mut ndjson = Vec::with_capacity(records.len().saturating_mul(1024));

        for record in records {
            let stream = format!("{}-{}", self.state.stream_prefix, record.log_type);
            let action = json!({ "index": { "_index": stream } });

            let mut line = serde_json::to_vec(&action)?;
            ndjson.append(&mut line);
            ndjson.push(b'\n');

            let mut doc = serde_json::to_vec(&record.record)?;
            ndjson.append(&mut doc);
            ndjson.push(b'\n');
        }

        Ok(ndjson)
    }

    fn gzip_compress(data: &[u8]) -> anyhow::Result<Vec<u8>> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
        encoder
            .write_all(data)
            .context("Failed to write data to gzip encoder")?;
        encoder
            .finish()
            .context("Failed to finish gzip compression")
    }

    fn handle_success(&self, status: reqwest::StatusCode, body: &str) {
        debug!("OpenObserve bulk response (status {}): {}", status, body);

        let Ok(v) = serde_json::from_str::<serde_json::Value>(body) else {
            warn!("Failed to parse OpenObserve response as JSON: {}", body);
            return;
        };

        if v.get("errors").and_then(|e| e.as_bool()) == Some(true) {
            warn!("OpenObserve response indicates errors occurred");
        }

        if let Some(items) = v.get("status").and_then(|s| s.as_array()) {
            for (idx, item) in items.iter().enumerate() {
                let failed = item.get("failed").and_then(|f| f.as_u64()).unwrap_or(0);
                if failed == 0 {
                    continue;
                }

                warn!(
                    "OpenObserve reported {} failed records in batch {}",
                    failed, idx
                );

                if let Some(details) = item.get("error") {
                    error!(
                        "OpenObserve batch {} error details: {}",
                        idx,
                        json_string(details)
                    );
                }
            }
        }

        if let Some(top) = v.get("error") {
            error!(
                "OpenObserve returned error in response: {}",
                json_string(top)
            );
        }
    }

    fn handle_error(&self, status: reqwest::StatusCode, body: &str) {
        error!(
            "OpenObserve returned non-success status {}: {} (url: {}, stream_prefix: {})",
            status, body, self.state.url, self.state.stream_prefix
        );

        let Ok(v) = serde_json::from_str::<serde_json::Value>(body) else {
            return;
        };

        if let Some(err) = v.get("error") {
            error!("OpenObserve error details: {}", json_string(err));
        }
        if let Some(msg) = v.get("message") {
            error!("OpenObserve error message: {}", msg);
        }
    }
}

#[async_trait]
impl Ingestor for OpenObserveIngestor {
    async fn ingest(&self, records: &[Arc<LogRecord>]) -> anyhow::Result<()> {
        if records.is_empty() {
            return Ok(());
        }

        let ndjson = self
            .format_ndjson(records)
            .context("Failed to format records as NDJSON")?;

        debug!(
            "Sending {} records to OpenObserve (stream_prefix: {}, url: {}, payload: {} bytes)",
            records.len(),
            self.state.stream_prefix,
            self.state.url,
            ndjson.len()
        );

        let compressed = Self::gzip_compress(&ndjson).context("Failed to gzip compress payload")?;

        debug!(
            "Gzip compressed payload: {} -> {} bytes ({:.0}% reduction)",
            ndjson.len(),
            compressed.len(),
            (1.0 - compressed.len() as f64 / ndjson.len() as f64) * 100.0
        );

        let resp = self
            .state
            .http
            .post(&self.state.url)
            .basic_auth(&self.state.username, Some(&self.state.password))
            .header(CONTENT_TYPE, "application/x-ndjson")
            .header(CONTENT_ENCODING, "gzip")
            .body(compressed)
            .send()
            .await
            .with_context(|| {
                format!(
                    "OpenObserve request failed (url: {}, stream_prefix: {})",
                    self.state.url, self.state.stream_prefix
                )
            })?;

        let status = resp.status();
        let body = resp.text().await.with_context(|| {
            format!(
                "Failed to read OpenObserve response body (status: {}, url: {})",
                status, self.state.url
            )
        })?;

        if status.is_success() {
            self.handle_success(status, &body);
            return Ok(());
        }

        self.handle_error(status, &body);
        Err(anyhow::anyhow!(
            "OpenObserve returned status {}: {}",
            status,
            body
        ))
    }

    fn name(&self) -> &str {
        &self.state.name
    }

    fn forwarder_type(&self) -> &str {
        "openobserve"
    }
}

fn json_string(v: &serde_json::Value) -> String {
    serde_json::to_string(v).unwrap_or_else(|_| "Failed to serialize".to_string())
}
