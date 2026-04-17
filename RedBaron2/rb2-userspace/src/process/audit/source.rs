use super::normalize::engine_event_from_exec_event;
use crate::{config::yaml, process::pipeline};
use log::{debug, info, warn};
use rb2_auditd::{AuditDaemon, AuditDaemonConfig, AuditEvent, AuditEventFlags};
use sysinfo::System;
use tokio::sync::{broadcast, mpsc, watch};

/// Returns true if an auditd process (e.g. system auditd daemon) is already running.
/// When true, we should not start our own audit netlink listener to avoid conflict.
pub fn is_external_auditd_running() -> bool {
    let mut sys = System::new_all();
    sys.refresh_all();
    sys.processes().values().any(|p| p.name() == "auditd")
}

pub async fn run(
    cfg: yaml::ProcessConfig,
    shutdown_rx: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    if is_external_auditd_running() {
        let msg = "auditd process is already running; skipping rb2 auditd process monitor to avoid conflict";
        warn!("{}", msg);
        eprintln!("rb2: {}", msg);
        return Ok(());
    }

    let daemon = AuditDaemon::start_with_config(
        AuditDaemonConfig {
            event_flags: AuditEventFlags::EXEC,
        },
        shutdown_rx.clone(),
    )?;
    let audit_rx = daemon.subscribe_events();

    let result = run_with_stream(cfg, shutdown_rx, audit_rx).await;

    daemon.shutdown().await;
    info!("auditd process monitor stopped and audit rules cleaned up");

    result
}

pub async fn run_with_stream(
    cfg: yaml::ProcessConfig,
    shutdown_rx: watch::Receiver<bool>,
    mut audit_rx: broadcast::Receiver<AuditEvent>,
) -> anyhow::Result<()> {
    let engine = pipeline::init_rhai_engine(&cfg);
    let scorer = if cfg.ml_enabled {
        Some(rb2_ml::OnlineScorer::new(rb2_ml::Config::default()))
    } else {
        None
    };
    let (tx, rx) = mpsc::channel(128);
    let pipeline_handle = tokio::spawn(async move {
        pipeline::run_event_pipeline(engine, scorer, cfg.ml_debug, rx).await;
    });

    let mut shutdown = shutdown_rx;
    info!("Setup auditd process monitor, listening for process create events");

    loop {
        tokio::select! {
            recv = audit_rx.recv() => {
                match recv {
                    Ok(AuditEvent::Exec(event)) => {
                        if tx.send(engine_event_from_exec_event(event)).await.is_err() {
                            debug!("audit event channel closed; consumer exiting");
                            break;
                        }
                    }
                    Ok(AuditEvent::Network(_)) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        warn!(
                            "audit event broadcast: consumer lagged, missed {} messages",
                            n
                        );
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        debug!("audit event broadcast closed; consumer exiting");
                        break;
                    }
                }
            }
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    info!("auditd process monitor shutting down");
                    break;
                }
            }
        }
    }

    drop(tx);
    pipeline_handle.abort();
    let _ = pipeline_handle.await;

    Ok(())
}
