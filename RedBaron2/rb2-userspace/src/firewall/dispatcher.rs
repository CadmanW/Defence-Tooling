use super::event::ebpf::EbpfEventProducer;
use super::event::nfq::NfqEventProducer;
use super::handler::kill::KillFirewall;
use super::handler::nfq::NfqFirewall;
use super::sockets;
use super::{EventProducer, EventProducerImpl, FirewallEvent, Handler, HandlerImpl};
use crate::config::yaml::{FirewallConfig, HandlerConfig, ProducerConfig};
use crate::ingest::SelfObservationFilter;
use crate::misc::{get_hostname, get_machine_id};
use chrono::SecondsFormat;
use fastrace::prelude::*;
use log::{debug, error, info, trace, warn};
use rb2_auditd::AuditEvent;
use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{RwLock, mpsc, watch};

pub enum ProducerInput {
    Config {
        btf_file_path: PathBuf,
        shutdown_rx: watch::Receiver<bool>,
    },
    Audit {
        receiver: tokio::sync::broadcast::Receiver<AuditEvent>,
        shutdown_rx: watch::Receiver<bool>,
    },
}

pub async fn run_firewall(
    cfg: FirewallConfig,
    producer_input: ProducerInput,
    filter: Arc<SelfObservationFilter>,
) -> anyhow::Result<()> {
    let (firewall, producer) = build_runtime(&cfg, producer_input)?;
    run_firewall_inner(cfg, firewall, producer, filter).await
}

async fn run_firewall_inner(
    cfg: FirewallConfig,
    firewall: HandlerImpl,
    producer: EventProducerImpl,
    filter: Arc<SelfObservationFilter>,
) -> anyhow::Result<()> {
    let firewall: Arc<dyn Handler> = Arc::new(firewall);

    let (tx, rx) = mpsc::channel::<FirewallEvent>(1024);

    clean_active_sockets(&cfg).await;
    info!(
        "Firewall with producer: {} consumer: {} started",
        producer_name(&cfg.producer),
        consumer_name(&cfg.handler)
    );

    let fw_clone = firewall.clone();
    let fw_fut = fw_clone.run();
    let producer_fut = producer.run(tx);
    let dispatch_fut = run_dispatcher(rx, firewall, &cfg, filter);

    tokio::try_join!(fw_fut, producer_fut, dispatch_fut)?;
    Ok(())
}

fn build_runtime(
    cfg: &FirewallConfig,
    producer_input: ProducerInput,
) -> anyhow::Result<(HandlerImpl, EventProducerImpl)> {
    if cfg.producer == ProducerConfig::Nfq && cfg.handler != HandlerConfig::Nfq {
        return Err(anyhow::anyhow!(
            "NFQ producer must be paired with NFQ handler, got {:?}",
            cfg.handler
        ));
    }
    if cfg.handler == HandlerConfig::Nfq && cfg.producer != ProducerConfig::Nfq {
        return Err(anyhow::anyhow!(
            "NFQ handler must be paired with NFQ producer, got {:?}",
            cfg.producer
        ));
    }

    match producer_input {
        ProducerInput::Config {
            btf_file_path,
            shutdown_rx,
        } => {
            if cfg.producer == ProducerConfig::Nfq && cfg.handler == HandlerConfig::Nfq {
                let nfq_producer = NfqEventProducer::new(btf_file_path, cfg.enforcing, shutdown_rx);
                let firewall = HandlerImpl::Nfq(NfqFirewall::new(nfq_producer.get_sender()?));
                let producer = EventProducerImpl::Nfq(nfq_producer);
                return Ok((firewall, producer));
            }

            match &cfg.producer {
                ProducerConfig::Ebpf => Ok((
                    build_standard_handler(cfg)?,
                    EventProducerImpl::Ebpf(EbpfEventProducer {
                        btf_file_path,
                        shutdown_rx,
                    }),
                )),
                prod => Err(anyhow::anyhow!("Unsupported producer: {:?}", prod)),
            }
        }
        ProducerInput::Audit {
            receiver,
            shutdown_rx,
        } => {
            if cfg.producer != ProducerConfig::Auditd {
                return Err(anyhow::anyhow!(
                    "Audit producer input requires auditd producer config, got {:?}",
                    cfg.producer
                ));
            }

            match &cfg.handler {
                HandlerConfig::Kill => Ok((
                    HandlerImpl::Kill(KillFirewall::default()),
                    EventProducerImpl::audit(receiver, shutdown_rx),
                )),
                hand => Err(anyhow::anyhow!("Unsupported handler: {:?}", hand)),
            }
        }
    }
}

fn producer_name(producer: &ProducerConfig) -> &'static str {
    match producer {
        ProducerConfig::Auditd => "auditd",
        ProducerConfig::Ebpf => "ebpf",
        ProducerConfig::Nfq => "nfq",
        ProducerConfig::Bsm => "bsm",
    }
}

fn consumer_name(handler: &HandlerConfig) -> &'static str {
    match handler {
        HandlerConfig::Kill => "kill",
        HandlerConfig::Nfq => "nfq",
    }
}

fn build_standard_handler(cfg: &FirewallConfig) -> anyhow::Result<HandlerImpl> {
    match &cfg.handler {
        HandlerConfig::Kill => Ok(HandlerImpl::Kill(KillFirewall::default())),
        hand => Err(anyhow::anyhow!("Unsupported handler: {:?}", hand)),
    }
}

async fn clean_active_sockets(cfg: &FirewallConfig) {
    let paths = &cfg.binary_whitelist;

    if let Err(e) = sockets::enumerate_udp_sockets(paths, cfg.enforcing).await {
        warn!("Failed to enumerate UDP sockets: {}", e);
    };
    if let Err(e) = sockets::enumerate_tcp_sockets(paths, cfg.enforcing).await {
        warn!("Failed to enumerate TCP sockets: {}", e);
    }

    debug!("Existing sockets parsed by firewall");
}

/// Will not take into account if the firewall should be enforcing or not here
pub fn make_decision(ev: &FirewallEvent, allow: &HashSet<PathBuf>) -> (bool, Option<PathBuf>) {
    let path = fs::read_link(format!("/proc/{}/exe", ev.pid)).ok();

    let decision = path.as_ref().map(|p| allow.contains(p)).unwrap_or_else(|| {
        // only make a debug message bc kill handler will be racy with new events
        debug!("Failed to resolve path for pid {}", ev.pid);
        false
    });

    debug!(
        "Firewall making a decision decision={} on pid={} path={:?}",
        decision, ev.pid, path,
    );

    (decision, path)
}

// dedup duplicate consecutive events in logfile
static EVENT_CACHE: RwLock<Option<(FirewallEvent, Option<PathBuf>)>> = RwLock::const_new(None);

async fn log_event(
    ev: &FirewallEvent,
    path: Option<PathBuf>,
    dec: bool,
    enforcing: bool,
    producer: &ProducerConfig,
    filter: &SelfObservationFilter,
) {
    // path we'll use for logging + caching.
    let mut saved_path = None;

    {
        let e = EVENT_CACHE.read().await;
        if let Some((cached_ev, cached_path)) = e.as_ref() {
            // dedup event check
            if cached_ev == ev && cached_path.as_ref() == path.as_ref() {
                return;
            }

            // partial match to backfill path when current is None
            if path.is_none() && cached_ev.pid == ev.pid && cached_ev.comm == ev.comm {
                saved_path = cached_path.clone();
            }
        }
    }

    let eff_path = if saved_path.is_some() {
        saved_path
    } else {
        path
    };

    if let Some(path) = eff_path.as_deref()
        && filter.should_ignore_firewall(path, ev.ip.as_deref(), ev.dport)
    {
        *EVENT_CACHE.write().await = Some((ev.clone(), eff_path.clone()));
        return;
    }

    *EVENT_CACHE.write().await = Some((ev.clone(), eff_path.clone()));

    let path_str = eff_path
        .as_ref()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "<unknown>".to_string());

    let ts = chrono::Local::now().to_rfc3339_opts(SecondsFormat::Millis, true);

    let json = serde_json::json!({
        "timestamp": ts,
        "decision": if dec { "ALLOW" } else { "DENY" },
        "enforcing": enforcing,
        "producer": format!("{:?}", producer).to_lowercase(),
        "pid": ev.pid,
        "path": path_str,
        "comm": ev.comm,
        "ip": ev.ip,
        "port": ev.dport,
        "op": ev.op,
        "host_name": get_hostname(),
        "host_id": get_machine_id(),
    });

    trace!(
        "firewall {} pid={} path={} ip={:?} port={:?}",
        if dec { "ALLOW" } else { "DENY" },
        ev.pid,
        path_str,
        ev.ip,
        ev.dport
    );

    info!(target: "rb2_firewall", "{}", json);
}

/// creates a span for the firewall if tracing is enabled
fn create_span(ev: &FirewallEvent, cfg: &FirewallConfig) -> Span {
    Span::root("firewall.decision", SpanContext::random()).with_properties(|| {
        let mut props = vec![
            ("pid", ev.pid.to_string()),
            ("enforcing", cfg.enforcing.to_string()),
        ];

        if let Some(ip) = &ev.ip {
            props.push(("ip", ip.clone()));
        }
        if let Some(port) = ev.dport {
            props.push(("port", port.to_string()));
        }
        if let Some(op) = &ev.op {
            props.push(("op", op.clone()));
        }

        props
    })
}

/// adds decision information to the span if it is Some
fn enrich_span(root: &Span, dec: bool) {
    root.add_property(|| {
        (
            "decision",
            if dec {
                "ALLOW".to_string()
            } else {
                "DENY".to_string()
            },
        )
    });
}

async fn run_dispatcher(
    mut src: mpsc::Receiver<FirewallEvent>,
    dst_firewall: Arc<dyn Handler>,
    cfg: &FirewallConfig,
    filter: Arc<SelfObservationFilter>,
) -> anyhow::Result<()> {
    while let Some(ev) = src.recv().await {
        let root = create_span(&ev, cfg);

        let (dec, path) = make_decision(&ev, &cfg.binary_whitelist);

        enrich_span(&root, dec);

        let (handle_res, ()) = tokio::join!(
            dst_firewall.handle_event(&ev, if cfg.enforcing { dec } else { true }),
            log_event(&ev, path, dec, cfg.enforcing, &cfg.producer, &filter),
        );

        if let Err(e) = handle_res {
            error!("Unable to handle firewall event: {e}");
        }
    }

    debug!("firewall event producer closed; dispatcher exiting");
    Ok(())
}
