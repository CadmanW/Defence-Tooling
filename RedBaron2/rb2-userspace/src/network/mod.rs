pub(crate) mod model;
mod parser;
mod sniffer;
mod tls;

use log::{error, info, warn};
use std::sync::Arc;
use tokio::sync::watch;
use tokio::task::JoinSet;

use crate::config::yaml::NetworkingConfig;
use crate::ingest::SelfObservationFilter;

pub async fn run(
    cfg: NetworkingConfig,
    filter: Arc<SelfObservationFilter>,
    shutdown_rx: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let packet_capture_enabled = cfg.dns_enabled || cfg.http_enabled;
    let tls_capture_enabled = cfg.https_enabled;

    if !packet_capture_enabled && !tls_capture_enabled {
        warn!(
            "networking feature is enabled but dns_enabled, http_enabled, and https_enabled are all false"
        );
        return Ok(());
    }

    let (interfaces, packet_interfaces_available) = if packet_capture_enabled {
        match sniffer::select_interfaces(&cfg.interfaces) {
            Ok(interfaces) => (interfaces, true),
            Err(err) => {
                error!("packet networking capture disabled: {err}");
                (Vec::new(), false)
            }
        }
    } else {
        (Vec::new(), true)
    };

    if packet_capture_enabled && packet_interfaces_available && interfaces.is_empty() {
        warn!("packet networking capture requested but no matching interfaces were available");
    }

    info!(
        "networking capture packet_interfaces={} dns_enabled={} http_enabled={} https_enabled={} http_capture_inbound={} started",
        interfaces.len(),
        cfg.dns_enabled,
        cfg.http_enabled,
        tls_capture_enabled,
        cfg.http_capture_inbound
    );

    let mut tasks = JoinSet::new();
    if packet_capture_enabled {
        for interface in interfaces {
            let interface_name = interface.name.clone();
            let interface_cfg = cfg.clone();
            let interface_filter = filter.clone();
            let interface_shutdown = shutdown_rx.clone();
            tasks.spawn(async move {
                if let Err(err) = sniffer::run_interface(
                    interface,
                    interface_cfg,
                    interface_filter,
                    interface_shutdown,
                )
                .await
                {
                    error!("network capture failed on {}: {err:#}", interface_name);
                }
            });
        }
    }

    if tls_capture_enabled {
        let tls_cfg = cfg.clone();
        let tls_filter = filter.clone();
        let tls_shutdown = shutdown_rx.clone();
        tasks.spawn(async move {
            if let Err(err) = tls::run(tls_cfg, tls_filter, tls_shutdown).await {
                error!("https capture failed: {err:#}");
            }
        });
    }

    while let Some(result) = tasks.join_next().await {
        if let Err(err) = result {
            error!("network capture task join failed: {err}");
        }
    }

    Ok(())
}
