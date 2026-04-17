mod attach;
mod event;
mod http1;
mod http2;
mod ringbuf;

use log::{debug, error, info, warn};
use std::sync::Arc;
use tokio::sync::watch;

use crate::config::yaml::NetworkingConfig;
use crate::ingest::SelfObservationFilter;

use self::attach::load_and_attach_ebpf;
use self::event::{DEFAULT_CAPTURE_BYTES, TLS_CAPTURE_MAX_BYTES, network_event_from_tls_write};
use self::http1::Http1Tracker;
use self::http2::{HandleResult, Http2Tracker};
use self::ringbuf::{spawn_ringbuf_reader, take_ringbuf_asyncfd};

async fn shutdown_reader_task(reader_task: tokio::task::JoinHandle<()>) {
    if let Err(err) = reader_task.await {
        if err.is_cancelled() {
            debug!("https capture reader task cancelled");
        } else {
            warn!("https capture reader task failed: {err}");
        }
    }
}

pub async fn run(
    cfg: NetworkingConfig,
    filter: Arc<SelfObservationFilter>,
    mut shutdown_rx: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let max_capture_bytes = u32::try_from(cfg.snaplen_bytes.min(TLS_CAPTURE_MAX_BYTES as u64))
        .unwrap_or(DEFAULT_CAPTURE_BYTES)
        .max(1);

    let (ebpf, attached_libraries) = match load_and_attach_ebpf(max_capture_bytes) {
        Ok(Some(result)) => result,
        Ok(None) => return Ok(()),
        Err(err) => {
            error!("https capture disabled: failed to initialize TLS probes: {err:#}");
            return Ok(());
        }
    };

    let (afd, _ebpf) = match take_ringbuf_asyncfd(ebpf) {
        Ok(result) => result,
        Err(err) => {
            error!("https capture disabled: failed to initialize ring buffer: {err:#}");
            return Ok(());
        }
    };
    let (mut rx, reader_task) = spawn_ringbuf_reader(afd, shutdown_rx.clone());
    let mut reader_task = Some(reader_task);
    let mut http1_tracker = Http1Tracker::new();
    let mut http2_tracker = Http2Tracker::new();

    info!(
        "HTTPS TLS capture started libraries={} capture_bytes={} direction=outbound-only",
        attached_libraries.join(","),
        max_capture_bytes
    );

    loop {
        tokio::select! {
            changed = shutdown_rx.changed() => {
                if changed.is_err() || *shutdown_rx.borrow() {
                    debug!("https capture shutting down");
                    drop(rx);
                    if let Some(reader_task) = reader_task.take() {
                        shutdown_reader_task(reader_task).await;
                    }
                    return Ok(());
                }
            }
            maybe_event = rx.recv() => {
                let Some(event) = maybe_event else {
                    let shutting_down = *shutdown_rx.borrow();
                    if let Some(reader_task) = reader_task.take() {
                        shutdown_reader_task(reader_task).await;
                    }

                    if shutting_down || *shutdown_rx.borrow() {
                        debug!("https capture reader stopped during shutdown");
                    } else {
                        warn!("https capture disabled: TLS event reader stopped");
                    }

                    return Ok(());
                };
                let events = match http2_tracker.handle_tls_write(&event) {
                    HandleResult::Events(events) => events,
                    HandleResult::NeedMoreData => Vec::new(),
                    HandleResult::NotHttp2 => http1_tracker.handle_tls_write(&event),
                };

                if events.is_empty() {
                    if let Some(network_event) = network_event_from_tls_write(&event)
                        && !filter.should_ignore_network(&network_event) {
                            network_event.log();
                        }
                } else {
                    for network_event in events {
                        if !filter.should_ignore_network(&network_event) {
                            network_event.log();
                        }
                    }
                }
            }
        }
    }
}
