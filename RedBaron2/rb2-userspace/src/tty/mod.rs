mod cast_writer;
mod ebpf;
mod encrypt;
pub mod object_storage;
pub mod s3_forward;
mod session;
pub mod spool;

use crate::config::yaml;
use crate::config::yaml::ObjectStorageConfig;
use anyhow::anyhow;
use aya::maps::{MapData, RingBuf};
use fastrace::prelude::*;
use log::{error, info, trace, warn};
use std::io;
use std::path::Path;
use std::time::Duration;
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc;

use ebpf::ParsedTtyWrite;
use session::{SessionTracker, StorageBackend};

const EVENT_CHAN_CAP: usize = 16_384;
const MAX_PER_WAKE: usize = 8192;

fn validate_cfg(cfg: &yaml::TTYConfig) -> anyhow::Result<()> {
    if cfg.session_recognition_idle_secs == 0 {
        return Err(anyhow!(
            "tty.session_recognition_idle_secs must be greater than 0, got {}",
            cfg.session_recognition_idle_secs
        ));
    }
    if cfg.flush_interval_secs == 0 {
        return Err(anyhow!(
            "tty.flush_interval_secs must be greater than 0, got {}",
            cfg.flush_interval_secs
        ));
    }
    if cfg.forward_to_s3 && cfg.s3_forward_interval_secs == 0 {
        return Err(anyhow!(
            "tty.s3_forward_interval_secs must be greater than 0 when forwarding to S3"
        ));
    }
    Ok(())
}

async fn setup_backend(cfg: &yaml::TTYConfig) -> anyhow::Result<StorageBackend> {
    ensure_output_dir(&cfg.spool_dir).await?;
    Ok(StorageBackend::Spool {
        spool_dir: cfg.spool_dir.clone(),
    })
}

fn spawn_s3_forwarder_if_enabled(
    cfg: &yaml::TTYConfig,
    backend: &StorageBackend,
    object_storage_cfg: &Option<ObjectStorageConfig>,
) -> anyhow::Result<()> {
    if !cfg.forward_to_s3 {
        return Ok(());
    }

    if let Some(os_cfg) = object_storage_cfg {
        let s3 = object_storage::S3Client::new(os_cfg)?;
        let StorageBackend::Spool { spool_dir } = backend;
        let spool_dir = spool_dir.clone();
        let interval_secs = cfg.s3_forward_interval_secs;

        tokio::spawn(async move {
            s3_forward::run(s3, spool_dir, interval_secs).await;
        });

        info!("TTY S3 forwarder spawned (interval={}s)", interval_secs);
        Ok(())
    } else {
        warn!(
            "tty.forward_to_s3 is true but object_storage config is missing - S3 forwarding disabled"
        );
        Ok(())
    }
}

fn spawn_ringbuf_reader(mut afd: AsyncFd<RingBuf<MapData>>) -> mpsc::Receiver<ParsedTtyWrite> {
    let (tx, rx) = mpsc::channel::<ParsedTtyWrite>(EVENT_CHAN_CAP);

    tokio::spawn(async move {
        loop {
            let mut guard = match afd.readable_mut().await {
                Ok(g) => g,
                Err(e) => {
                    error!("AsyncFd readable_mut failed: {e}");
                    continue;
                }
            };

            let drained = guard.try_io(|afd: &mut AsyncFd<RingBuf<MapData>>| {
                let rb: &mut RingBuf<MapData> = afd.get_mut();

                let mut n = 0usize;
                while n < MAX_PER_WAKE {
                    match rb.next() {
                        Some(item) => {
                            match ebpf::parse_tty_write_event(&item) {
                                Ok(ev) => {
                                    // don't block in reader task
                                    if let Err(e) = tx.try_send(ev) {
                                        warn!(
                                            "Tty reader could not keep up! Events are being lost: {}",
                                            e
                                        );
                                    }
                                }
                                Err(e) => error!("parse error: {e:#}"),
                            }

                            n += 1;
                        }
                        None => break,
                    }
                }

                if n == 0 {
                    Err(io::Error::from(io::ErrorKind::WouldBlock))
                } else {
                    Ok(n)
                }
            });

            match drained {
                Ok(Ok(n)) if n >= MAX_PER_WAKE => {
                    tokio::task::yield_now().await;
                }
                Ok(Ok(_)) => {}
                Ok(Err(_would_block)) => {}
                Err(_) => {}
            }
        }
    });

    rx
}

async fn handle_event(tracker: &mut SessionTracker, ev: ParsedTtyWrite) {
    let root = Span::root("tty.handle_event", SpanContext::random()).with_properties(|| {
        vec![
            ("tid", ev.tid.to_string()),
            ("comm", ev.comm.clone()),
            (
                "tty",
                format!(
                    "{}:{}->{}:{}",
                    ev.ctty_major, ev.ctty_minor, ev.tty_major, ev.tty_minor
                ),
            ),
        ]
    });

    if let Err(e) = tracker.handle_tty_write(&ev).await {
        root.add_property(|| ("tty.handle_error", format!("{e}")));
        error!("Failed to handle tty write: {e}");
        return;
    }

    trace!(
        "{} {} {}:{} -> {}:{} {}x{} trunc={} {:?}",
        ev.tid,
        ev.comm,
        ev.ctty_major,
        ev.ctty_minor,
        ev.tty_major,
        ev.tty_minor,
        ev.rows,
        ev.cols,
        ev.tty_out_truncated,
        String::from_utf8_lossy(ev.tty_out.as_slice()),
    );
}

async fn flush_sessions(tracker: &mut SessionTracker) {
    if let Err(e) = tracker.flush_all().await {
        error!("Failed to flush sessions: {e}");
    }
}

async fn main_loop<S>(
    mut tracker: SessionTracker,
    mut rx: mpsc::Receiver<ParsedTtyWrite>,
    flush_interval_secs: u64,
    shutdown: S,
) -> anyhow::Result<()>
where
    S: std::future::Future<Output = ()> + Send,
{
    let mut flush_interval = tokio::time::interval(Duration::from_secs(flush_interval_secs));
    flush_interval.tick().await;
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            _ = &mut shutdown => {
                // final flush + retention + close
                flush_sessions(&mut tracker).await;
                if let Err(e) = tracker.close_all().await {
                    error!("Failed to close tty sessions: {e}");
                }
                return Ok(());
            }

            maybe_ev = rx.recv() => {
                let Some(ev) = maybe_ev else {
                    flush_sessions(&mut tracker).await;
                    let _ = tracker.close_all().await;
                    return Err(anyhow!("ringbuf reader task exited"));
                };
                handle_event(&mut tracker, ev).await;
            }

            _ = flush_interval.tick() => {
                flush_sessions(&mut tracker).await;
            }
        }
    }
}

pub async fn run<P, S>(
    btf_file_path: P,
    cfg: yaml::TTYConfig,
    object_storage_cfg: Option<ObjectStorageConfig>,
    shutdown: S,
) -> anyhow::Result<()>
where
    P: AsRef<Path>,
    S: std::future::Future<Output = ()> + Send,
{
    validate_cfg(&cfg)?;

    let ebpf = ebpf::load_and_attach_ebpf(btf_file_path).await?;

    // Take the map so AsyncFd<RingBuf<...>> it can live in a spawned task.
    let (afd, _ebpf) = ebpf::take_ringbuf_asyncfd(ebpf)?;

    let backend = setup_backend(&cfg).await?;
    spawn_s3_forwarder_if_enabled(&cfg, &backend, &object_storage_cfg)?;

    let tracker = SessionTracker::new(
        backend,
        cfg.pubkey.clone(),
        cfg.session_recognition_idle_secs,
    )
    .map_err(|e| anyhow!("Failed to create session tracker: {e}"))?;

    let rx = spawn_ringbuf_reader(afd);

    info!("Tty tracking started");

    // NOTE: if you have a shutdown path, make sure you call tracker.close_all().await.
    // Here we run forever, so periodic flush covers durability.
    main_loop(tracker, rx, cfg.flush_interval_secs, shutdown).await
}

async fn ensure_output_dir(path: &Path) -> io::Result<()> {
    if !tokio::fs::try_exists(path).await? {
        tokio::fs::create_dir_all(path).await?;
    }
    Ok(())
}
