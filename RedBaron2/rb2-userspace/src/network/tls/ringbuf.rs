use std::io;

use anyhow::Context;
use aya::Ebpf;
use aya::maps::{MapData, RingBuf};
use log::{error, warn};
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc::{self, error::TrySendError};
use tokio::sync::watch;
use tokio::task::JoinHandle;

use super::event::{ParsedTlsWriteEvent, parse_tls_write_event};

const EVENT_CHAN_CAP: usize = 256;
const MAX_PER_WAKE: usize = 64;

pub(super) fn take_ringbuf_asyncfd(
    mut ebpf: Ebpf,
) -> anyhow::Result<(AsyncFd<RingBuf<MapData>>, Ebpf)> {
    let map = ebpf
        .take_map("events")
        .context("https ringbuf map not found (Ebpf::take_map)")?;
    let ring: RingBuf<MapData> =
        RingBuf::try_from(map).context("failed to convert https map to RingBuf")?;
    let afd = AsyncFd::new(ring).context("failed to wrap https RingBuf in AsyncFd")?;
    Ok((afd, ebpf))
}

pub(super) fn spawn_ringbuf_reader(
    mut afd: AsyncFd<RingBuf<MapData>>,
    mut shutdown_rx: watch::Receiver<bool>,
) -> (mpsc::Receiver<ParsedTlsWriteEvent>, JoinHandle<()>) {
    let (tx, rx) = mpsc::channel(EVENT_CHAN_CAP);

    let handle = tokio::spawn(async move {
        loop {
            if *shutdown_rx.borrow() {
                break;
            }

            let mut guard = tokio::select! {
                changed = shutdown_rx.changed() => {
                    if changed.is_err() || *shutdown_rx.borrow() {
                        break;
                    }
                    continue;
                }
                guard = afd.readable_mut() => {
                    match guard {
                        Ok(guard) => guard,
                        Err(err) => {
                            error!("https AsyncFd readable_mut failed: {err}");
                            continue;
                        }
                    }
                }
            };

            let mut receiver_closed = false;

            let drained = guard.try_io(|afd: &mut AsyncFd<RingBuf<MapData>>| {
                let ring = afd.get_mut();
                let mut count = 0usize;

                while count < MAX_PER_WAKE {
                    match ring.next() {
                        Some(item) => {
                            match parse_tls_write_event(&item) {
                                Ok(event) => {
                                    if let Err(err) = tx.try_send(event) {
                                        match err {
                                            TrySendError::Full(_) => {
                                                warn!(
                                                    "https reader could not keep up, events are being lost"
                                                );
                                            }
                                            TrySendError::Closed(_) => {
                                                receiver_closed = true;
                                                break;
                                            }
                                        }
                                    }
                                }
                                Err(err) => error!("https parse error: {err:#}"),
                            }
                            count += 1;
                        }
                        None => break,
                    }
                }

                if count == 0 {
                    Err(io::Error::from(io::ErrorKind::WouldBlock))
                } else {
                    Ok(count)
                }
            });

            if receiver_closed {
                break;
            }

            match drained {
                Ok(Ok(count)) if count >= MAX_PER_WAKE => tokio::task::yield_now().await,
                Ok(Ok(_)) | Ok(Err(_)) | Err(_) => {}
            }
        }
    });

    (rx, handle)
}
