mod filter;
mod openobserve;
pub mod queue;
mod reader;
mod splunk;
pub mod traces;

use async_trait::async_trait;
use chrono::SecondsFormat;
use log::{debug, error, info, warn};
use serde_json::json;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::watch;
use tokio::task::JoinSet;

pub use filter::SelfObservationFilter;
pub use openobserve::OpenObserveIngestor;
use queue::{QueuedRecord, TakeBatchResult, global_queue};
pub use splunk::SplunkIngestor;

pub use reader::{LogRecord, parse_log_line, read_logs};

const MAX_BATCH_RECORDS: usize = 512;

#[async_trait]
pub trait Ingestor: Send + Sync {
    async fn ingest(&self, records: &[Arc<LogRecord>]) -> anyhow::Result<()>;
    fn name(&self) -> &str;
    fn forwarder_type(&self) -> &str;
}

#[derive(Clone)]
struct LogSource {
    log_type: &'static str,
    path: PathBuf,
}

#[derive(Default, Clone)]
struct ForwarderCounters {
    records_sent: u64,
    failed_batches: u64,
}

#[derive(Clone)]
struct RecoveryPoint {
    resume_seq: u64,
    live_start_seq: u64,
    file_limits: HashMap<&'static str, u64>,
}

struct RecoveryCursor {
    offsets: HashMap<&'static str, u64>,
    offset_files: HashMap<&'static str, PathBuf>,
    next_source_idx: usize,
}

struct FileBatch {
    records: Vec<Arc<LogRecord>>,
    new_offsets: HashMap<&'static str, u64>,
    complete: bool,
    next_source_idx: usize,
}

enum SendOutcome {
    Sent,
    Failed(anyhow::Error),
    Shutdown,
}

impl RecoveryCursor {
    async fn load(forwarder_name: &str, sources: &[LogSource]) -> anyhow::Result<Self> {
        let mut offsets = HashMap::new();
        let mut offset_files = HashMap::new();

        for source in sources {
            let offset_file = reader::offset_path(&source.path, Some(forwarder_name));
            let offset = reader::get_offset(&offset_file).await.unwrap_or(0);
            offsets.insert(source.log_type, offset);
            offset_files.insert(source.log_type, offset_file);
        }

        Ok(Self {
            offsets,
            offset_files,
            next_source_idx: 0,
        })
    }

    async fn persist_offsets(&self) -> anyhow::Result<()> {
        for (log_type, offset_file) in &self.offset_files {
            let offset = self.offsets.get(log_type).copied().unwrap_or(0);
            reader::save_offset(offset_file, offset).await?;
        }
        Ok(())
    }

    fn advance_with_memory_batch(&mut self, records: &[QueuedRecord]) {
        for record in records {
            let entry = self.offsets.entry(record.record.log_type).or_insert(0);
            *entry = entry.saturating_add(record.encoded_len);
        }
    }

    async fn capture_recovery_point(&self, sources: &[LogSource]) -> RecoveryPoint {
        let queue_snapshot = global_queue().snapshot();
        let mut file_limits = HashMap::new();

        for source in sources {
            let limit = tokio::fs::metadata(&source.path)
                .await
                .map(|meta| meta.len())
                .unwrap_or(0);
            file_limits.insert(source.log_type, limit);
        }

        RecoveryPoint {
            resume_seq: queue_snapshot.next_seq,
            live_start_seq: queue_snapshot.live_start_seq,
            file_limits,
        }
    }

    async fn read_file_batch(
        &self,
        sources: &[LogSource],
        recovery: &RecoveryPoint,
        max_records: usize,
    ) -> anyhow::Result<FileBatch> {
        let mut records = Vec::new();
        let mut new_offsets = self.offsets.clone();
        let mut complete = true;

        if sources.is_empty() {
            return Ok(FileBatch {
                records,
                new_offsets,
                complete,
                next_source_idx: self.next_source_idx,
            });
        }

        let source_count = sources.len();
        let start_idx = self.next_source_idx % source_count;
        let mut next_start_idx = start_idx;

        for offset_idx in 0..source_count {
            if records.len() >= max_records {
                complete = false;
                break;
            }

            let source_idx = (start_idx + offset_idx) % source_count;
            let source = &sources[source_idx];

            let offset = self.offsets.get(source.log_type).copied().unwrap_or(0);
            let limit = recovery
                .file_limits
                .get(source.log_type)
                .copied()
                .unwrap_or(0);

            if offset >= limit {
                continue;
            }

            let read_limit = max_records - records.len();
            let new_offset = reader::read_from_offset_into(
                &source.path,
                source.log_type,
                offset,
                Some(limit),
                Some(read_limit),
                &mut records,
            )
            .await?;
            new_offsets.insert(source.log_type, new_offset);
            next_start_idx = (source_idx + 1) % source_count;

            if new_offset < limit {
                complete = false;
                break;
            }
        }

        Ok(FileBatch {
            records,
            new_offsets,
            complete,
            next_source_idx: next_start_idx,
        })
    }
}

fn build_ingestors(
    cfg: &crate::config::yaml::IngestorConfig,
) -> anyhow::Result<Vec<Arc<dyn Ingestor>>> {
    let mut ingestors: Vec<Arc<dyn Ingestor>> = Vec::with_capacity(cfg.forwarders.len());

    for forwarder in &cfg.forwarders {
        match forwarder.forwarder_type.as_str() {
            "openobserve" => {
                let openobserve_cfg = forwarder
                    .openobserve
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("openobserve config missing"))?;
                ingestors.push(Arc::new(OpenObserveIngestor::new(
                    forwarder.name.clone(),
                    openobserve_cfg.clone(),
                )?));
            }
            "splunk" => {
                let splunk_cfg = forwarder
                    .splunk
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("splunk config missing"))?;
                ingestors.push(Arc::new(SplunkIngestor::new(
                    forwarder.name.clone(),
                    splunk_cfg.clone(),
                )?));
            }
            other => {
                return Err(anyhow::anyhow!(
                    "Unknown forwarder type {} for forwarder {}",
                    other,
                    forwarder.name,
                ));
            }
        }
    }

    if ingestors.is_empty() {
        return Err(anyhow::anyhow!("No ingestor forwarders configured"));
    }

    Ok(ingestors)
}

fn build_log_sources(cfg: &crate::config::yaml::AppConfig) -> Vec<LogSource> {
    let mut sources = Vec::with_capacity(8);

    if let Some(firewall_cfg) = &cfg.firewall {
        sources.push(LogSource {
            log_type: "firewall",
            path: firewall_cfg.log_file.clone(),
        });
    }
    if let Some(process_cfg) = &cfg.process {
        sources.push(LogSource {
            log_type: "process",
            path: process_cfg.log_file.clone(),
        });
        sources.push(LogSource {
            log_type: "alerts",
            path: process_cfg.alert_log_file.clone(),
        });
    }
    if let Some(auth_cfg) = &cfg.auth {
        sources.push(LogSource {
            log_type: "auth",
            path: auth_cfg.log_file.clone(),
        });
    }
    if let Some(audit_cfg) = &cfg.audit {
        sources.push(LogSource {
            log_type: "audit",
            path: audit_cfg.log_file.clone(),
        });
    }
    if let Some(yara_cfg) = &cfg.yara {
        sources.push(LogSource {
            log_type: "yara",
            path: yara_cfg.log_file.clone(),
        });
    }
    if let Some(scan_cfg) = &cfg.scan {
        sources.push(LogSource {
            log_type: "scan",
            path: scan_cfg.log_file.clone(),
        });
    }
    if let Some(network_cfg) = &cfg.networking {
        sources.push(LogSource {
            log_type: "network",
            path: network_cfg.log_file.clone(),
        });
    }
    if let Some(file_integrity_cfg) = &cfg.file_integrity {
        sources.push(LogSource {
            log_type: "fim",
            path: file_integrity_cfg.log_file.clone(),
        });
    }
    sources.push(LogSource {
        log_type: "health",
        path: cfg.health_log_file.clone(),
    });

    sources
}

fn queued_log_records(records: &[QueuedRecord]) -> Vec<Arc<LogRecord>> {
    records.iter().map(|record| record.record.clone()).collect()
}

const fn should_complete_recovery(
    batch_is_empty: bool,
    batch_complete: bool,
    replay_sent: bool,
) -> bool {
    batch_is_empty || (batch_complete && replay_sent)
}

async fn send_batch_with_shutdown(
    ingestor: &dyn Ingestor,
    records: &[Arc<LogRecord>],
    shutdown_rx: &mut watch::Receiver<bool>,
) -> SendOutcome {
    if *shutdown_rx.borrow() {
        return SendOutcome::Shutdown;
    }

    tokio::select! {
        result = ingestor.ingest(records) => {
            match result {
                Ok(()) => SendOutcome::Sent,
                Err(err) => SendOutcome::Failed(err),
            }
        }
        changed = shutdown_rx.changed() => {
            match changed {
                Ok(()) | Err(_) => SendOutcome::Shutdown,
            }
        }
    }
}

async fn run_forwarder(
    ingestor: Arc<dyn Ingestor>,
    cfg: crate::config::yaml::IngestorConfig,
    sources: Vec<LogSource>,
    mut shutdown_rx: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    use log::error;
    use tokio::time::{Duration, Instant};

    let queue = global_queue().clone();
    let mut counters = ForwarderCounters::default();
    let mut last_stats_log = Instant::now();
    let stats_interval = Duration::from_secs(cfg.stats_interval_secs.max(1));
    let flush_interval = Duration::from_secs(cfg.flush_interval_secs.max(1));
    let memory_trigger_bytes = cfg.memory_trigger_size_mb.saturating_mul(1024 * 1024);
    let mut flush_deadline = Instant::now() + flush_interval;

    let mut cursor = RecoveryCursor::load(ingestor.name(), &sources).await?;
    let mut recovery = Some(cursor.capture_recovery_point(&sources).await);
    let mut next_live_seq = recovery.as_ref().map(|r| r.resume_seq).unwrap_or(1);
    queue.register_forwarder(ingestor.name(), next_live_seq);

    loop {
        if *shutdown_rx.borrow() {
            queue.unregister_forwarder(ingestor.name());
            return Ok(());
        }

        let mut sent_any = false;

        if let Some(active_recovery) = recovery.clone() {
            let batch = match cursor
                .read_file_batch(&sources, &active_recovery, MAX_BATCH_RECORDS)
                .await
            {
                Ok(b) => b,
                Err(e) => {
                    warn!(
                        "Recovery read failed for {}, skipping to live: {:#}",
                        ingestor.name(),
                        e
                    );
                    next_live_seq = active_recovery
                        .resume_seq
                        .max(active_recovery.live_start_seq);
                    queue.ack_forwarder(ingestor.name(), next_live_seq);
                    recovery = None;
                    continue;
                }
            };
            let mut replay_sent = false;

            if !batch.records.is_empty() {
                match send_batch_with_shutdown(ingestor.as_ref(), &batch.records, &mut shutdown_rx)
                    .await
                {
                    SendOutcome::Sent => {
                        counters.records_sent += batch.records.len() as u64;
                        cursor.offsets = batch.new_offsets;
                        cursor.next_source_idx = batch.next_source_idx;
                        if let Err(e) = cursor.persist_offsets().await {
                            warn!("Failed to persist offsets for {}: {:#}", ingestor.name(), e);
                        }
                        flush_deadline = Instant::now() + flush_interval;
                        replay_sent = true;
                        sent_any = true;
                    }
                    SendOutcome::Failed(e) => {
                        counters.failed_batches += 1;
                        error!(
                            "Failed to ingest logs to forwarder {}: {}",
                            ingestor.name(),
                            e
                        );
                        flush_deadline = Instant::now() + flush_interval;
                    }
                    SendOutcome::Shutdown => {
                        queue.unregister_forwarder(ingestor.name());
                        return Ok(());
                    }
                }
            }

            let fully_caught_up =
                should_complete_recovery(batch.records.is_empty(), batch.complete, replay_sent);
            if fully_caught_up {
                next_live_seq = active_recovery
                    .resume_seq
                    .max(active_recovery.live_start_seq);
                queue.ack_forwarder(ingestor.name(), next_live_seq);
                recovery = None;
            }

            if sent_any {
                maybe_log_stats(
                    &cfg,
                    &mut counters,
                    &mut last_stats_log,
                    stats_interval,
                    ingestor.as_ref(),
                );
                continue;
            }
        }

        match queue.take_batch(ingestor.name(), next_live_seq, MAX_BATCH_RECORDS) {
            TakeBatchResult::Records {
                records,
                next_seq,
                memory_bytes,
            } => {
                let reached_interval = Instant::now() >= flush_deadline;
                let reached_memory_trigger =
                    memory_trigger_bytes > 0 && memory_bytes >= memory_trigger_bytes;

                if !reached_interval && !reached_memory_trigger {
                    tokio::select! {
                        _ = queue.wait_for_records() => {}
                        _ = tokio::time::sleep_until(flush_deadline) => {}
                        changed = shutdown_rx.changed() => {
                            if changed.is_err() {
                                queue.unregister_forwarder(ingestor.name());
                                return Ok(());
                            }
                        }
                    }
                    continue;
                }

                let payload = queued_log_records(&records);
                match send_batch_with_shutdown(ingestor.as_ref(), &payload, &mut shutdown_rx).await
                {
                    SendOutcome::Sent => {
                        counters.records_sent += payload.len() as u64;
                        cursor.advance_with_memory_batch(&records);
                        if let Err(e) = cursor.persist_offsets().await {
                            warn!("Failed to persist offsets for {}: {:#}", ingestor.name(), e);
                        }
                        next_live_seq = next_seq;
                        queue.ack_forwarder(ingestor.name(), next_live_seq);
                        flush_deadline = Instant::now() + flush_interval;
                    }
                    SendOutcome::Failed(e) => {
                        counters.failed_batches += 1;
                        error!(
                            "Failed to ingest logs to forwarder {}: {}",
                            ingestor.name(),
                            e
                        );
                        flush_deadline = Instant::now() + flush_interval;
                    }
                    SendOutcome::Shutdown => {
                        queue.unregister_forwarder(ingestor.name());
                        return Ok(());
                    }
                }
            }
            TakeBatchResult::Gap { live_start_seq: _ } => {
                recovery = Some(cursor.capture_recovery_point(&sources).await);
                next_live_seq = recovery
                    .as_ref()
                    .map(|r| r.resume_seq)
                    .unwrap_or(next_live_seq);
                queue.register_forwarder(ingestor.name(), next_live_seq);
            }
            TakeBatchResult::Empty {
                next_seq,
                memory_bytes,
            } => {
                next_live_seq = next_seq;
                queue.ack_forwarder(ingestor.name(), next_live_seq);

                if Instant::now() >= flush_deadline {
                    flush_deadline = Instant::now() + flush_interval;
                }

                let should_wait_for_pressure =
                    memory_trigger_bytes > 0 && memory_bytes >= memory_trigger_bytes;
                tokio::select! {
                    _ = queue.wait_for_records() => {}
                    _ = if should_wait_for_pressure {
                        tokio::time::sleep(Duration::from_millis(250))
                    } else {
                        tokio::time::sleep_until(flush_deadline)
                    } => {}
                    changed = shutdown_rx.changed() => {
                        if changed.is_err() {
                            queue.unregister_forwarder(ingestor.name());
                            return Ok(());
                        }
                    }
                }
            }
        }

        maybe_log_stats(
            &cfg,
            &mut counters,
            &mut last_stats_log,
            stats_interval,
            ingestor.as_ref(),
        );
    }
}

fn maybe_log_stats(
    cfg: &crate::config::yaml::IngestorConfig,
    counters: &mut ForwarderCounters,
    last_stats_log: &mut tokio::time::Instant,
    stats_interval: tokio::time::Duration,
    ingestor: &dyn Ingestor,
) {
    use log::info;

    if cfg.stats_interval_secs == 0 || last_stats_log.elapsed() < stats_interval {
        return;
    }
    if counters.records_sent == 0 && counters.failed_batches == 0 {
        *last_stats_log = tokio::time::Instant::now();
        return;
    }

    debug!(
        "Ingested {} records to {} ({}) in the last {}s",
        counters.records_sent,
        ingestor.name(),
        ingestor.forwarder_type(),
        cfg.stats_interval_secs
    );
    info!(
        target: "rb2_health",
        "{}",
        json!({
            "_timestamp": chrono::Local::now().to_rfc3339_opts(SecondsFormat::Millis, true),
            "event": "ingestor_stats",
            "host_name": crate::misc::get_hostname(),
            "host_id": crate::misc::get_machine_id(),
            "records_sent": counters.records_sent,
            "forwarder_name": ingestor.name(),
            "forwarder_type": ingestor.forwarder_type(),
            "failed_batches": counters.failed_batches,
            "interval_secs": cfg.stats_interval_secs,
        })
    );
    counters.records_sent = 0;
    counters.failed_batches = 0;
    *last_stats_log = tokio::time::Instant::now();
}

pub async fn run_ingestor(
    cfg: crate::config::yaml::IngestorConfig,
    shutdown_rx: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let ingestors = build_ingestors(&cfg)?;
    let forwarder_names: Vec<&str> = ingestors.iter().map(|ingestor| ingestor.name()).collect();
    info!(
        "Starting log ingestor with forwarders: {}",
        forwarder_names.join(", ")
    );

    let cfg_ref = crate::config::yaml::get_config()
        .map_err(|e| anyhow::anyhow!("Failed to get config: {}", e))?;
    let sources = build_log_sources(cfg_ref);
    global_queue().configure_max_bytes(cfg.memory_trigger_size_mb.saturating_mul(1024 * 1024));

    let mut tasks = JoinSet::new();
    for ingestor in ingestors {
        let ingestor_name = ingestor.name().to_string();
        let ingestor_cfg = cfg.clone();
        let ingestor_sources = sources.clone();
        let ingestor_shutdown = shutdown_rx.clone();
        tasks.spawn(async move {
            (
                ingestor_name,
                run_forwarder(ingestor, ingestor_cfg, ingestor_sources, ingestor_shutdown).await,
            )
        });
    }

    while let Some(result) = tasks.join_next().await {
        match result {
            Ok((ingestor_name, Ok(()))) => {
                debug!("Log forwarder '{}' exited", ingestor_name);
            }
            Ok((ingestor_name, Err(err))) => {
                error!(
                    "Log forwarder '{}' exited with error: {err:#}",
                    ingestor_name
                );
            }
            Err(err) => {
                error!("A log forwarder task failed to join: {err:#}");
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::anyhow;
    use std::sync::{Arc, Mutex};
    use std::time::{SystemTime, UNIX_EPOCH};
    use tokio::sync::Notify;

    struct SuccessIngestor;

    #[async_trait]
    impl Ingestor for SuccessIngestor {
        async fn ingest(&self, _records: &[Arc<LogRecord>]) -> anyhow::Result<()> {
            Ok(())
        }

        fn name(&self) -> &str {
            "success"
        }

        fn forwarder_type(&self) -> &str {
            "test"
        }
    }

    struct FailingIngestor;

    #[async_trait]
    impl Ingestor for FailingIngestor {
        async fn ingest(&self, _records: &[Arc<LogRecord>]) -> anyhow::Result<()> {
            Err(anyhow!("boom"))
        }

        fn name(&self) -> &str {
            "failure"
        }

        fn forwarder_type(&self) -> &str {
            "test"
        }
    }

    struct BlockingIngestor {
        started: Arc<Notify>,
        release: Arc<Notify>,
        seen: Arc<Mutex<Vec<usize>>>,
    }

    #[async_trait]
    impl Ingestor for BlockingIngestor {
        async fn ingest(&self, records: &[Arc<LogRecord>]) -> anyhow::Result<()> {
            self.seen
                .lock()
                .expect("seen lock poisoned")
                .push(records.len());
            self.started.notify_waiters();
            self.release.notified().await;
            Ok(())
        }

        fn name(&self) -> &str {
            "blocking"
        }

        fn forwarder_type(&self) -> &str {
            "test"
        }
    }

    fn sample_records() -> Vec<Arc<LogRecord>> {
        vec![Arc::new(LogRecord {
            log_type: "process",
            record: json!({"message": "hello"}),
        })]
    }

    fn unique_temp_path(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time before epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("rb2-{name}-{nanos}.log"))
    }

    #[test]
    fn health_target_maps_to_health_log_type() {
        assert_eq!(queue::log_type_for_target("rb2_health"), Some("health"));
        assert_eq!(queue::log_type_for_target("rb2_ace"), Some("alerts"));
    }

    #[test]
    fn build_log_sources_includes_auth_when_enabled() {
        let cfg = crate::config::yaml::AppConfig {
            yara: None,
            firewall: None,
            process: None,
            auth: Some(crate::config::yaml::AuthConfig {
                log_file: std::path::PathBuf::from("/tmp/rb2-auth-source-test/auth"),
                libpam_path: None,
            }),
            audit: None,
            scan: None,
            networking: None,
            tty: None,
            ingestor: None,
            object_storage: None,
            logging: crate::config::yaml::LoggingConfig {
                log_dir: std::path::PathBuf::from("/tmp/rb2-auth-source-test"),
                rollover_size_bytes: 1024,
                rollover_count: 1,
            },
            health_log_file: std::path::PathBuf::from("/tmp/rb2-auth-source-test/health"),
            file_integrity: None,
        };

        let sources = build_log_sources(&cfg);
        assert!(sources.iter().any(|source| {
            source.log_type == "auth" && *source.path == *"/tmp/rb2-auth-source-test/auth"
        }));
    }

    #[test]
    fn build_log_sources_includes_network_logs_when_enabled() {
        let cfg = crate::config::yaml::AppConfig {
            yara: None,
            firewall: None,
            process: None,
            auth: None,
            audit: None,
            scan: None,
            networking: Some(crate::config::yaml::NetworkingConfig {
                interfaces: vec!["eth0".to_string()],
                dns_enabled: true,
                http_enabled: true,
                https_enabled: true,
                http_capture_inbound: false,
                snaplen_bytes: 2048,
                log_file: std::path::PathBuf::from("/tmp/rb2-network-test/network"),
            }),
            tty: None,
            ingestor: None,
            object_storage: None,
            logging: crate::config::yaml::LoggingConfig {
                log_dir: std::path::PathBuf::from("/tmp/rb2-network-test"),
                rollover_size_bytes: 1024,
                rollover_count: 1,
            },
            health_log_file: std::path::PathBuf::from("/tmp/rb2-network-test/health"),
            file_integrity: None,
        };

        let sources = build_log_sources(&cfg);
        assert!(sources.iter().any(|source| {
            source.log_type == "network" && *source.path == *"/tmp/rb2-network-test/network"
        }));
    }

    #[test]
    fn build_log_sources_includes_audit_when_enabled() {
        let cfg = crate::config::yaml::AppConfig {
            yara: None,
            firewall: None,
            process: None,
            auth: None,
            audit: Some(crate::config::yaml::AuditConfig {
                log_file: std::path::PathBuf::from("/tmp/rb2-audit-test/audit"),
            }),
            scan: None,
            networking: None,
            tty: None,
            ingestor: None,
            object_storage: None,
            logging: crate::config::yaml::LoggingConfig {
                log_dir: std::path::PathBuf::from("/tmp/rb2-audit-test"),
                rollover_size_bytes: 1024,
                rollover_count: 1,
            },
            health_log_file: std::path::PathBuf::from("/tmp/rb2-audit-test/rb2_health"),
            file_integrity: None,
        };

        let sources = build_log_sources(&cfg);
        assert!(sources.iter().any(|source| {
            source.log_type == "audit" && *source.path == *"/tmp/rb2-audit-test/audit"
        }));
    }

    #[test]
    fn recovery_only_completes_after_success_or_empty_batch() {
        assert!(should_complete_recovery(true, false, false));
        assert!(should_complete_recovery(false, true, true));
        assert!(!should_complete_recovery(false, true, false));
        assert!(!should_complete_recovery(false, false, true));
    }

    #[tokio::test]
    async fn send_batch_with_shutdown_stops_immediately_if_shutdown_set() {
        let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
        let _ = shutdown_tx.send(true);

        let outcome =
            send_batch_with_shutdown(&SuccessIngestor, &sample_records(), &mut shutdown_rx).await;

        assert!(matches!(outcome, SendOutcome::Shutdown));
    }

    #[tokio::test]
    async fn send_batch_with_shutdown_returns_sent_when_ingest_finishes() {
        let (_shutdown_tx, mut shutdown_rx) = watch::channel(false);

        let outcome =
            send_batch_with_shutdown(&SuccessIngestor, &sample_records(), &mut shutdown_rx).await;

        assert!(matches!(outcome, SendOutcome::Sent));
    }

    #[tokio::test]
    async fn send_batch_with_shutdown_returns_failed_when_ingestor_errors() {
        let (_shutdown_tx, mut shutdown_rx) = watch::channel(false);

        let outcome =
            send_batch_with_shutdown(&FailingIngestor, &sample_records(), &mut shutdown_rx).await;

        match outcome {
            SendOutcome::Failed(err) => assert!(err.to_string().contains("boom")),
            _ => panic!("expected failed outcome"),
        }
    }

    #[tokio::test]
    async fn send_batch_with_shutdown_exits_when_shutdown_arrives_first() {
        let started = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let seen = Arc::new(Mutex::new(Vec::new()));
        let ingestor = BlockingIngestor {
            started: started.clone(),
            release: release.clone(),
            seen: seen.clone(),
        };
        let (shutdown_tx, mut shutdown_rx) = watch::channel(false);

        let join = tokio::spawn(async move {
            send_batch_with_shutdown(&ingestor, &sample_records(), &mut shutdown_rx).await
        });

        started.notified().await;
        let _ = shutdown_tx.send(true);

        let outcome = join.await.expect("task join ok");
        assert!(matches!(outcome, SendOutcome::Shutdown));
        assert_eq!(seen.lock().expect("seen lock poisoned").as_slice(), &[1]);

        release.notify_waiters();
    }

    #[tokio::test]
    async fn read_file_batch_rotates_sources_between_batches() {
        let first_path = unique_temp_path("recovery-first");
        let second_path = unique_temp_path("recovery-second");
        tokio::fs::write(&first_path, b"{\"message\":\"first\"}\n")
            .await
            .expect("write first log");
        tokio::fs::write(&second_path, b"{\"message\":\"second\"}\n")
            .await
            .expect("write second log");

        let sources = vec![
            LogSource {
                log_type: "process",
                path: first_path.clone(),
            },
            LogSource {
                log_type: "health",
                path: second_path.clone(),
            },
        ];
        let mut cursor = RecoveryCursor {
            offsets: HashMap::from([("process", 0), ("health", 0)]),
            offset_files: HashMap::new(),
            next_source_idx: 0,
        };
        let recovery = RecoveryPoint {
            resume_seq: 10,
            live_start_seq: 10,
            file_limits: HashMap::from([
                (
                    "process",
                    tokio::fs::metadata(&first_path)
                        .await
                        .expect("first metadata")
                        .len(),
                ),
                (
                    "health",
                    tokio::fs::metadata(&second_path)
                        .await
                        .expect("second metadata")
                        .len(),
                ),
            ]),
        };

        let first_batch = cursor
            .read_file_batch(&sources, &recovery, 1)
            .await
            .expect("first batch");
        cursor.offsets = first_batch.new_offsets;
        cursor.next_source_idx = first_batch.next_source_idx;
        let second_batch = cursor
            .read_file_batch(&sources, &recovery, 1)
            .await
            .expect("second batch");

        assert_eq!(first_batch.records.len(), 1);
        assert_eq!(second_batch.records.len(), 1);
        assert_eq!(first_batch.records[0].log_type, "process");
        assert_eq!(second_batch.records[0].log_type, "health");

        let _ = tokio::fs::remove_file(&first_path).await;
        let _ = tokio::fs::remove_file(&second_path).await;
    }
}
