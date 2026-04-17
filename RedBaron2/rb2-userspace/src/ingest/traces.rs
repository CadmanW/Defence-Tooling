use crate::config::yaml::OpenObserveConfig;
use crate::misc::{get_hostname, get_machine_id};
use fastrace::collector::{Config, Reporter, SpanRecord};
use flate2::Compression;
use flate2::write::GzEncoder;
use log::{debug, error, info, warn};
use reqwest::header::CONTENT_TYPE;
use reqwest::{StatusCode, Url};
use serde_json::{Value, json};
use std::io::Write;
use std::sync::{
    Arc, OnceLock,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;
use tokio::sync::{Notify, mpsc};
use tokio::time::sleep;

static TRACE_REPORTER_CONTROL: OnceLock<ReporterControl> = OnceLock::new();

const TRACE_QUEUE_CAPACITY: usize = 1024;
const HTTP_CONNECT_TIMEOUT_SECS: u64 = 3;
const HTTP_REQUEST_TIMEOUT_SECS: u64 = 10;
const MAX_LOGGED_RESPONSE_BODY_BYTES: usize = 1024;
const MAX_SEND_ATTEMPTS: usize = 3;
const INITIAL_RETRY_BACKOFF_MILLIS: u64 = 250;

struct ReporterState {
    url: String,
    username: String,
    password: String,
    http: reqwest::Client,
    resource: Value,
}

struct ShutdownState {
    complete: AtomicBool,
    notify: Notify,
}

impl ShutdownState {
    fn new() -> Self {
        Self {
            complete: AtomicBool::new(false),
            notify: Notify::new(),
        }
    }

    fn mark_complete(&self) {
        self.complete.store(true, Ordering::Release);
        self.notify.notify_waiters();
    }

    async fn wait(&self) {
        loop {
            let notified = self.notify.notified();

            if self.complete.load(Ordering::Acquire) {
                return;
            }

            notified.await;
        }
    }
}

struct ReporterControl {
    shutting_down: Arc<AtomicBool>,
    shutdown_notify: Arc<Notify>,
    shutdown_state: Arc<ShutdownState>,
}

impl ReporterControl {
    async fn shutdown(&self) -> anyhow::Result<()> {
        if !self.shutting_down.swap(true, Ordering::SeqCst) {
            self.shutdown_notify.notify_waiters();
        }

        self.shutdown_state.wait().await;
        Ok(())
    }
}

pub struct OpenObserveTraceReporter {
    state: Arc<ReporterState>,
    tx: mpsc::Sender<Vec<SpanRecord>>,
    shutting_down: Arc<AtomicBool>,
}

impl OpenObserveTraceReporter {
    #[expect(
        clippy::type_complexity,
        reason = "constructor returns the full reporter wiring tuple"
    )]
    fn new(
        cfg: &OpenObserveConfig,
    ) -> anyhow::Result<(
        Self,
        ReporterControl,
        mpsc::Receiver<Vec<SpanRecord>>,
        Arc<Notify>,
        Arc<ShutdownState>,
    )> {
        let url = build_trace_url(cfg)?;
        let http = build_http_client()?;
        let resource = build_resource();

        let state = Arc::new(ReporterState {
            url,
            username: cfg.username.clone(),
            password: cfg.password.clone(),
            http,
            resource,
        });

        let (tx, rx) = mpsc::channel(TRACE_QUEUE_CAPACITY);
        let shutting_down = Arc::new(AtomicBool::new(false));
        let shutdown_notify = Arc::new(Notify::new());
        let shutdown_state = Arc::new(ShutdownState::new());

        let reporter = Self {
            state,
            tx,
            shutting_down: Arc::clone(&shutting_down),
        };

        let control = ReporterControl {
            shutting_down,
            shutdown_notify: Arc::clone(&shutdown_notify),
            shutdown_state: Arc::clone(&shutdown_state),
        };

        Ok((reporter, control, rx, shutdown_notify, shutdown_state))
    }
}

impl Reporter for OpenObserveTraceReporter {
    fn report(&mut self, spans: Vec<SpanRecord>) {
        if spans.is_empty() {
            return;
        }

        if self.shutting_down.load(Ordering::Relaxed) {
            debug!(
                "Dropping {} trace spans because shutdown has started",
                spans.len()
            );
            return;
        }

        match self.tx.try_send(spans) {
            Ok(()) => {}
            Err(tokio::sync::mpsc::error::TrySendError::Full(spans)) => {
                warn!(
                    "Dropping {} trace spans because the OpenObserve queue is full",
                    spans.len()
                );
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(spans)) => {
                error!(
                    "Dropping {} trace spans because the OpenObserve worker is not running",
                    spans.len()
                );
            }
        }
    }
}

async fn trace_worker(
    state: Arc<ReporterState>,
    mut rx: mpsc::Receiver<Vec<SpanRecord>>,
    shutting_down: Arc<AtomicBool>,
    shutdown_notify: Arc<Notify>,
    shutdown_state: Arc<ShutdownState>,
) {
    loop {
        if shutting_down.load(Ordering::Acquire) {
            rx.close();
        }

        let spans = tokio::select! {
            maybe_spans = rx.recv() => match maybe_spans {
                Some(spans) => spans,
                None => break,
            },
            _ = shutdown_notify.notified(), if !shutting_down.load(Ordering::Acquire) => {
                rx.close();
                continue;
            }
        };

        let batch = coalesce_span_batch(spans, &mut rx);

        if let Err(e) = send_spans(&state, &batch).await {
            error!("Failed to send traces to OpenObserve: {}", e);
        }
    }

    shutdown_state.mark_complete();
    debug!("OpenObserve trace worker exited");
}

fn coalesce_span_batch(
    mut batch: Vec<SpanRecord>,
    rx: &mut mpsc::Receiver<Vec<SpanRecord>>,
) -> Vec<SpanRecord> {
    while let Ok(mut more) = rx.try_recv() {
        batch.append(&mut more);
    }

    batch
}

async fn send_spans(state: &ReporterState, spans: &[SpanRecord]) -> anyhow::Result<()> {
    let compressed = build_compressed_payload(&state.resource, spans).await?;

    debug!(
        "Sending {} trace spans to OpenObserve ({} bytes gzipped, url: {})",
        spans.len(),
        compressed.len(),
        state.url
    );

    let mut backoff = Duration::from_millis(INITIAL_RETRY_BACKOFF_MILLIS);

    for attempt in 1..=MAX_SEND_ATTEMPTS {
        match send_compressed_payload(state, &compressed).await {
            Ok(()) => return Ok(()),
            Err(SendError::Fatal(e)) => return Err(e),
            Err(SendError::Retryable(e)) if attempt == MAX_SEND_ATTEMPTS => return Err(e),
            Err(SendError::Retryable(e)) => {
                warn!(
                    "OpenObserve trace send attempt {}/{} failed: {}. Retrying in {:?}",
                    attempt, MAX_SEND_ATTEMPTS, e, backoff
                );

                sleep(backoff).await;
                backoff = backoff
                    .checked_mul(2)
                    .unwrap_or(Duration::from_secs(HTTP_REQUEST_TIMEOUT_SECS));
            }
        }
    }

    unreachable!()
}

async fn build_compressed_payload(
    resource: &Value,
    spans: &[SpanRecord],
) -> anyhow::Result<Vec<u8>> {
    let payload = build_otlp_payload(resource, spans);

    let body = serde_json::to_vec(&payload)
        .map_err(|e| anyhow::anyhow!("serializing trace payload: {}", e))?;

    tokio::task::spawn_blocking(move || gzip_compress(&body))
        .await
        .map_err(|e| anyhow::anyhow!("gzip task join failure: {}", e))?
}

enum SendError {
    Retryable(anyhow::Error),
    Fatal(anyhow::Error),
}

async fn send_compressed_payload(
    state: &ReporterState,
    compressed: &[u8],
) -> Result<(), SendError> {
    let resp = state
        .http
        .post(&state.url)
        .basic_auth(&state.username, Some(&state.password))
        .header(CONTENT_TYPE, "application/json")
        .header("Content-Encoding", "gzip")
        .body(compressed.to_vec())
        .send()
        .await
        .map_err(|e| SendError::Retryable(anyhow::anyhow!("trace request failed: {}", e)))?;

    let status = resp.status();

    if status.is_success() {
        drain_response_body(resp).await;
        debug!("OpenObserve trace response status {}", status);
        return Ok(());
    }

    let body_preview = read_response_preview(resp, MAX_LOGGED_RESPONSE_BODY_BYTES).await;
    let err = anyhow::anyhow!(
        "OpenObserve trace returned status {}: {}",
        status,
        body_preview
    );

    if is_retryable_status(status) {
        Err(SendError::Retryable(err))
    } else {
        Err(SendError::Fatal(err))
    }
}

fn is_retryable_status(status: StatusCode) -> bool {
    status == StatusCode::TOO_MANY_REQUESTS || status.is_server_error()
}

async fn drain_response_body(mut resp: reqwest::Response) {
    while let Ok(Some(_)) = resp.chunk().await {}
}

async fn read_response_preview(mut resp: reqwest::Response, max_bytes: usize) -> String {
    let mut buf = Vec::with_capacity(max_bytes.min(256));
    let mut truncated = false;

    loop {
        match resp.chunk().await {
            Ok(Some(chunk)) => {
                let remaining = max_bytes.saturating_sub(buf.len());

                if remaining == 0 {
                    truncated = true;
                    continue;
                }

                let take = remaining.min(chunk.len());
                buf.extend_from_slice(&chunk[..take]);

                if take < chunk.len() {
                    truncated = true;
                }
            }
            Ok(None) => break,
            Err(_) => return "<unreadable>".to_string(),
        }
    }

    let mut out = String::from_utf8_lossy(&buf).into_owned();
    if truncated {
        out.push_str("...");
    }
    out
}

fn build_trace_url(cfg: &OpenObserveConfig) -> anyhow::Result<String> {
    let mut base = cfg.url.clone();
    if !base.ends_with('/') {
        base.push('/');
    }

    let mut base = Url::parse(&base).map_err(|e| anyhow::anyhow!("parsing trace url: {}", e))?;

    base.path_segments_mut()
        .map_err(|_| anyhow::anyhow!("trace base url cannot be used as a base"))?
        .extend(["api", &cfg.org, "v1", "traces"]);

    Ok(base.to_string())
}

fn build_http_client() -> anyhow::Result<reqwest::Client> {
    reqwest::Client::builder()
        .user_agent("rb2-tracer/1.0")
        .connect_timeout(Duration::from_secs(HTTP_CONNECT_TIMEOUT_SECS))
        .timeout(Duration::from_secs(HTTP_REQUEST_TIMEOUT_SECS))
        .build()
        .map_err(|e| anyhow::anyhow!("building http client: {}", e))
}

fn build_resource() -> Value {
    let hostname = get_hostname().unwrap_or_else(|| "unknown".to_string());
    let machine_id = get_machine_id().unwrap_or_else(|| "unknown".to_string());

    json!({
        "attributes": [
            {"key": "service.name", "value": {"stringValue": "rb2"}},
            {"key": "host.name", "value": {"stringValue": hostname}},
            {"key": "host.id", "value": {"stringValue": machine_id}},
        ]
    })
}

fn build_otlp_payload(resource: &Value, spans: &[SpanRecord]) -> Value {
    let otlp_spans: Vec<Value> = spans.iter().map(span_to_otlp).collect();

    json!({
        "resourceSpans": [{
            "resource": resource,
            "scopeSpans": [{
                "scope": {
                    "name": "rb2",
                    "version": env!("CARGO_PKG_VERSION"),
                },
                "spans": otlp_spans,
            }]
        }]
    })
}

fn span_to_otlp(span: &SpanRecord) -> Value {
    let trace_id = format!("{:032x}", span.trace_id.0);
    let span_id = format!("{:016x}", span.span_id.0);
    let parent_span_id = if span.parent_id.0 == 0 {
        String::new()
    } else {
        format!("{:016x}", span.parent_id.0)
    };

    let end_time_unix_nano = span.begin_time_unix_ns.saturating_add(span.duration_ns);

    let attributes: Vec<Value> = span
        .properties
        .iter()
        .map(|(k, v)| {
            json!({
                "key": k.as_ref(),
                "value": {"stringValue": v.as_ref()},
            })
        })
        .collect();

    json!({
        "traceId": trace_id,
        "spanId": span_id,
        "parentSpanId": parent_span_id,
        "name": span.name.as_ref(),
        "kind": 1,
        "startTimeUnixNano": span.begin_time_unix_ns.to_string(),
        "endTimeUnixNano": end_time_unix_nano.to_string(),
        "attributes": attributes,
        "status": {},
    })
}

fn gzip_compress(data: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
    encoder
        .write_all(data)
        .map_err(|e| anyhow::anyhow!("gzip write: {}", e))?;
    encoder
        .finish()
        .map_err(|e| anyhow::anyhow!("gzip finish: {}", e))
}

pub fn init_tracer(cfg: &OpenObserveConfig) -> anyhow::Result<()> {
    if TRACE_REPORTER_CONTROL.get().is_some() {
        anyhow::bail!("trace reporter already initialized");
    }

    let (reporter, control, rx, shutdown_notify, shutdown_state) =
        OpenObserveTraceReporter::new(cfg)?;

    TRACE_REPORTER_CONTROL
        .set(control)
        .map_err(|_| anyhow::anyhow!("trace reporter already initialized"))?;

    let handle = tokio::runtime::Handle::try_current()
        .map_err(|_| anyhow::anyhow!("init_tracer must be called inside a Tokio runtime"))?;

    info!("Initializing trace reporter -> {}", reporter.state.url);

    handle.spawn(trace_worker(
        Arc::clone(&reporter.state),
        rx,
        Arc::clone(&reporter.shutting_down),
        shutdown_notify,
        shutdown_state,
    ));

    fastrace::set_reporter(reporter, Config::default());
    Ok(())
}

pub async fn shutdown() {
    // Make fastrace hand over any buffered spans to the Reporter.
    fastrace::flush();

    let Some(control) = TRACE_REPORTER_CONTROL.get() else {
        return;
    };

    if let Err(e) = control.shutdown().await {
        warn!("Trace reporter shutdown was not clean: {}", e);
    }
}
