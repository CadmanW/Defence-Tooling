use crate::dedupe::NetworkDeduper;
use crate::{AuditDaemonConfig, AuditEvent, AuditEventFlags, netlink, parser, rules};
use log::{debug, info, warn};
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;
use tokio::sync::{Notify, broadcast, watch};

/// A raw audit message as received from the kernel: (msg_type, payload bytes).
pub type RawAuditMessage = (u16, Vec<u8>);

const BROADCAST_CAPACITY: usize = 512;

/// Owns the single audit netlink daemon: socket, PID registration, keepalive,
/// rule management, and a blocking reader loop that broadcasts raw messages.
pub struct AuditDaemon {
    raw_tx: broadcast::Sender<RawAuditMessage>,
    event_tx: broadcast::Sender<AuditEvent>,
    event_flags: AuditEventFlags,
    stop_flag: Arc<AtomicBool>,
    stop_notify: Arc<Notify>,
    cleanup_started: Arc<AtomicBool>,
}

impl AuditDaemon {
    pub fn start(shutdown_rx: watch::Receiver<bool>) -> anyhow::Result<Self> {
        Self::start_with_config(AuditDaemonConfig::default(), shutdown_rx)
    }

    pub fn start_with_config(
        config: AuditDaemonConfig,
        shutdown_rx: watch::Receiver<bool>,
    ) -> anyhow::Result<Self> {
        const AUDIT_RECV_BUF: i32 = 1024 * 1024;
        let event_flags = config.event_flags;

        let mut client = netlink::AuditNetlinkClient::new(AUDIT_RECV_BUF)?;
        client.register_pid()?;

        rules::load_audit_rules_on_socket(client.fd.as_raw_fd(), event_flags)?;

        let stop_flag = Arc::new(AtomicBool::new(false));
        let stop_notify = Arc::new(Notify::new());
        let cleanup_started = Arc::new(AtomicBool::new(false));
        let (raw_tx, _) = broadcast::channel(BROADCAST_CAPACITY);
        let (event_tx, _) = broadcast::channel(BROADCAST_CAPACITY);

        netlink::spawn_keepalive(client.fd.as_raw_fd(), stop_flag.clone());

        let reader_stop = stop_flag.clone();
        let reader_raw_tx = raw_tx.clone();
        let reader_event_tx = event_tx.clone();
        tokio::task::spawn_blocking(move || {
            let mut assembler = parser::AuditEventAssembler::new(event_flags);
            let mut network_deduper = NetworkDeduper::new();
            let mut evict_counter: u64 = 0;

            loop {
                if reader_stop.load(Ordering::Relaxed) {
                    debug!("audit reader: stop flag set, exiting");
                    return;
                }

                if let Some((msg_type, data)) = client.receive() {
                    if (1300..=1400).contains(&msg_type) {
                        debug!("audit recv msg_type={msg_type}");
                    }

                    if let Some(record) = parser::parse_audit_message(msg_type, &data) {
                        if let Some(event) = assembler.push(record)
                            && should_emit_event(&mut network_deduper, &event)
                        {
                            let _ = reader_event_tx.send(event);
                        }

                        evict_counter = evict_counter.wrapping_add(1);
                        if evict_counter.is_multiple_of(500) {
                            network_deduper.prune_expired(Instant::now());
                            for event in assembler.evict_stale(5) {
                                if should_emit_event(&mut network_deduper, &event) {
                                    let _ = reader_event_tx.send(event);
                                }
                            }
                        }
                    }

                    let _ = reader_raw_tx.send((msg_type, data));
                }
            }
        });

        let shutdown_stop = stop_flag.clone();
        let shutdown_notify = stop_notify.clone();
        let mut shutdown = shutdown_rx;
        let shutdown_cleanup_started = cleanup_started.clone();
        tokio::spawn(async move {
            loop {
                if *shutdown.borrow() {
                    break;
                }

                tokio::select! {
                    changed = shutdown.changed() => {
                        if changed.is_err() {
                            break;
                        }
                    }
                    _ = shutdown_notify.notified() => {
                        break;
                    }
                }
            }
            shutdown_stop.store(true, Ordering::Relaxed);
            remove_rules_once_async(shutdown_cleanup_started, event_flags).await;
        });

        Ok(Self {
            raw_tx,
            event_tx,
            event_flags,
            stop_flag,
            stop_notify,
            cleanup_started,
        })
    }

    pub async fn shutdown(self) {
        self.stop_flag.store(true, Ordering::Relaxed);
        self.stop_notify.notify_waiters();
        remove_rules_once_async(self.cleanup_started.clone(), self.event_flags).await;
    }

    pub fn subscribe(&self) -> broadcast::Receiver<RawAuditMessage> {
        self.raw_tx.subscribe()
    }

    pub fn subscribe_events(&self) -> broadcast::Receiver<AuditEvent> {
        self.event_tx.subscribe()
    }
}

impl Drop for AuditDaemon {
    fn drop(&mut self) {
        self.stop_flag.store(true, Ordering::Relaxed);
        self.stop_notify.notify_waiters();
        remove_rules_once_detached(self.cleanup_started.clone(), self.event_flags);
    }
}

fn try_start_cleanup(cleanup_started: &AtomicBool) -> bool {
    !cleanup_started.swap(true, Ordering::Relaxed)
}

async fn remove_rules_once_async(cleanup_started: Arc<AtomicBool>, event_flags: AuditEventFlags) {
    if event_flags.is_empty() || !try_start_cleanup(&cleanup_started) {
        return;
    }

    match tokio::task::spawn_blocking(move || rules::remove_audit_rules(event_flags)).await {
        Ok(()) => info!("audit daemon stopped, audit rules removed"),
        Err(err) => warn!("audit daemon cleanup task failed: {err}"),
    }
}

fn remove_rules_once_detached(cleanup_started: Arc<AtomicBool>, event_flags: AuditEventFlags) {
    if event_flags.is_empty() || !try_start_cleanup(&cleanup_started) {
        return;
    }

    if let Err(err) = std::thread::Builder::new()
        .name("rb2-audit-cleanup".to_string())
        .spawn(move || {
            rules::remove_audit_rules(event_flags);
            info!("audit daemon dropped, audit rules removed");
        })
    {
        warn!("failed to spawn audit daemon cleanup thread: {err}");
    }
}

fn should_emit_event(deduper: &mut NetworkDeduper, event: &AuditEvent) -> bool {
    match event {
        AuditEvent::Network(network_event) => deduper.should_emit(network_event, Instant::now()),
        AuditEvent::Exec(_) => true,
    }
}
