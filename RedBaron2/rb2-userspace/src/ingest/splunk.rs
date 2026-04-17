use super::{Ingestor, LogRecord};
use crate::config::yaml::SplunkConfig;
use anyhow::Context;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use flate2::Compression;
use flate2::write::GzEncoder;
use log::{debug, error};
use reqwest::Url;
use reqwest::header::{AUTHORIZATION, CONTENT_ENCODING, CONTENT_TYPE};
use serde_json::{Map, Number, Value};
use std::io::Write;
use std::sync::Arc;
use std::time::Duration;

const HTTP_TIMEOUT_SECS: u64 = 10;

pub struct SplunkIngestor {
    state: Arc<State>,
}

struct State {
    name: String,
    url: String,
    token: String,
    index: Option<String>,
    source: String,
    sourcetype_prefix: String,
    gzip_enabled: bool,
    http: reqwest::Client,
}

impl SplunkIngestor {
    pub fn new(name: String, cfg: SplunkConfig) -> anyhow::Result<Self> {
        let mut base = cfg.url.clone();
        if !base.ends_with('/') {
            base.push('/');
        }

        let base = Url::parse(&base).context("parsing splunk cfg.url")?;
        let url = base
            .join("services/collector/event")
            .context("building Splunk HEC ingest URL")?
            .to_string();

        let mut client_builder = reqwest::Client::builder()
            .user_agent("splunk-ingestor/1.0")
            .timeout(Duration::from_secs(HTTP_TIMEOUT_SECS));
        if cfg.tls_skip_verify {
            client_builder = client_builder.danger_accept_invalid_certs(true);
        }
        let http = client_builder.build().context("building reqwest client")?;

        Ok(Self {
            state: Arc::new(State {
                name,
                url,
                token: cfg.token,
                index: cfg.index,
                source: cfg.source,
                sourcetype_prefix: cfg.sourcetype_prefix,
                gzip_enabled: cfg.gzip_enabled,
                http,
            }),
        })
    }

    fn build_payload(&self, records: &[Arc<LogRecord>]) -> anyhow::Result<Vec<u8>> {
        let mut payload = Vec::with_capacity(records.len().saturating_mul(512));

        for record in records {
            let event = self.hec_event(record);
            let mut line = serde_json::to_vec(&event)?;
            payload.append(&mut line);
            payload.push(b'\n');
        }

        Ok(payload)
    }

    fn hec_event(&self, record: &LogRecord) -> Value {
        let mut object = Map::new();

        if let Some(time) = extract_timestamp(&record.record) {
            object.insert("time".to_string(), Value::Number(time));
        }

        if let Some(host) = crate::misc::get_hostname() {
            object.insert("host".to_string(), Value::String(host));
        }

        object.insert(
            "source".to_string(),
            Value::String(self.state.source.clone()),
        );
        object.insert(
            "sourcetype".to_string(),
            Value::String(format!(
                "{}:{}",
                self.state.sourcetype_prefix, record.log_type
            )),
        );

        if let Some(index) = &self.state.index {
            object.insert("index".to_string(), Value::String(index.clone()));
        }

        object.insert("event".to_string(), record.record.clone());
        Value::Object(object)
    }

    fn maybe_compress(&self, payload: Vec<u8>) -> anyhow::Result<(Vec<u8>, bool)> {
        if !self.state.gzip_enabled {
            return Ok((payload, false));
        }

        let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
        encoder
            .write_all(&payload)
            .context("Failed to write data to gzip encoder")?;
        let compressed = encoder
            .finish()
            .context("Failed to finish gzip compression")?;

        Ok((compressed, true))
    }
}

#[async_trait]
impl Ingestor for SplunkIngestor {
    async fn ingest(&self, records: &[Arc<LogRecord>]) -> anyhow::Result<()> {
        if records.is_empty() {
            return Ok(());
        }

        let payload = self
            .build_payload(records)
            .context("Failed to format records for Splunk HEC")?;
        let (body, compressed) = self.maybe_compress(payload)?;

        debug!(
            "Sending {} records to Splunk (name: {}, url: {}, payload: {} bytes, gzip: {})",
            records.len(),
            self.state.name,
            self.state.url,
            body.len(),
            compressed
        );

        let mut request = self
            .state
            .http
            .post(&self.state.url)
            .header(AUTHORIZATION, format!("Splunk {}", self.state.token))
            .header(CONTENT_TYPE, "application/json");

        if compressed {
            request = request.header(CONTENT_ENCODING, "gzip");
        }

        let resp = request.body(body).send().await.with_context(|| {
            format!(
                "Splunk HEC request failed (name: {}, url: {})",
                self.state.name, self.state.url
            )
        })?;

        let status = resp.status();
        let body = resp.text().await.with_context(|| {
            format!(
                "Failed to read Splunk HEC response body (status: {}, url: {})",
                status, self.state.url
            )
        })?;

        if status.is_success() {
            debug!(
                "Splunk HEC response (name: {}, status {}): {}",
                self.state.name, status, body
            );
            return Ok(());
        }

        error!(
            "Splunk HEC returned non-success status {}: {} (name: {}, url: {})",
            status, body, self.state.name, self.state.url
        );
        Err(anyhow::anyhow!(
            "Splunk HEC returned status {}: {}",
            status,
            body
        ))
    }

    fn name(&self) -> &str {
        &self.state.name
    }

    fn forwarder_type(&self) -> &str {
        "splunk"
    }
}

fn extract_timestamp(record: &Value) -> Option<Number> {
    let ts = record.get("_timestamp")?.as_str()?;
    let parsed = DateTime::parse_from_rfc3339(ts).ok()?;
    Number::from_f64(parsed.with_timezone(&Utc).timestamp_millis() as f64 / 1000.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample_config() -> SplunkConfig {
        SplunkConfig {
            url: "https://splunk.example.com:8088".to_string(),
            token: "token".to_string(),
            index: Some("security".to_string()),
            source: "rb2".to_string(),
            sourcetype_prefix: "rb2".to_string(),
            gzip_enabled: true,
            tls_skip_verify: false,
        }
    }

    fn sample_record() -> Arc<LogRecord> {
        Arc::new(LogRecord {
            log_type: "process",
            record: json!({
                "_timestamp": "2026-03-25T12:34:56.789Z",
                "message": "hello"
            }),
        })
    }

    #[test]
    fn builds_hec_payload() {
        let ingestor = SplunkIngestor::new("splunk-primary".to_string(), sample_config())
            .expect("build ingestor");
        let payload = ingestor
            .build_payload(&[sample_record()])
            .expect("payload should build");
        let body = String::from_utf8(payload).expect("payload should be utf8");
        let parsed: Value = serde_json::from_str(body.trim()).expect("valid json line");

        assert_eq!(parsed["source"], "rb2");
        assert_eq!(parsed["sourcetype"], "rb2:process");
        assert_eq!(parsed["index"], "security");
        assert_eq!(parsed["event"]["message"], "hello");
        assert!(parsed.get("time").is_some());
    }

    #[test]
    fn plain_and_gzip_payload_modes_are_supported() {
        let mut cfg = sample_config();
        cfg.gzip_enabled = false;
        let ingestor = SplunkIngestor::new("splunk-plain".to_string(), cfg).expect("build plain");
        let plain = ingestor
            .maybe_compress(b"{\"event\":1}\n".to_vec())
            .expect("plain payload");
        assert!(!plain.1);

        let gzip = SplunkIngestor::new("splunk-gzip".to_string(), sample_config())
            .expect("build gzip")
            .maybe_compress(b"{\"event\":1}\n".to_vec())
            .expect("gzip payload");
        assert!(gzip.1);
        assert!(gzip.0.len() > 2);
        assert_eq!(&gzip.0[0..2], &[0x1f, 0x8b]);
    }

    #[test]
    fn accepts_http_hec_urls() {
        let mut cfg = sample_config();
        cfg.url = "http://splunk.example.com:8088".to_string();
        let ingestor =
            SplunkIngestor::new("splunk-http".to_string(), cfg).expect("http url should parse");
        assert_eq!(
            ingestor.state.url,
            "http://splunk.example.com:8088/services/collector/event"
        );
    }
}
