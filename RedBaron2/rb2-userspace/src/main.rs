#[cfg(not(target_os = "linux"))]
compile_error!("only linux is supported");

use log::{debug, error, info, warn};
use rb2_auditd::{AuditDaemon, AuditDaemonConfig};
use rb2_userspace::{
    auth,
    btf::fetch_btf,
    config::{
        self, dropper, systemd,
        yaml::{AppConfig, ProcessCollector, ProducerConfig},
    },
    file_integrity,
    firewall::dispatcher::{self, ProducerInput},
    ingest, integrity,
    misc::health,
    network,
    process::{audit, process_monitor},
    scan::scans,
    tty, yara,
};
use std::{env, io, sync::Arc, thread};
use tokio::{
    runtime::Runtime,
    signal::unix::{SignalKind, signal},
    sync::watch,
    task::JoinHandle,
};
use yara::yara_scan::full_scan_all;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    config::logger::init();
    let args = env::args().skip(1);
    for arg in args {
        match arg.as_str() {
            "-c" | "--config" => {
                let path = dropper::write_config_with_fallback("rb2.yaml")?;
                info!("Written config to {:?}", path);
                return Ok(());
            }
            "-s" | "--systemd" => {
                systemd::install_systemd_unit()?;
                info!("Systemd unit installed, exiting");
                return Ok(());
            }
            "-r" | "--rootkit" => {
                info!("Running a singular rootkit scan");
                let rt = Runtime::new().unwrap();
                return rt.block_on(scans::do_singular_scan()).map_err(|e| e.into());
            }
            "-y" | "--yara" => {
                info!("Running a singular full yara scan");
                return Ok(yara_scan()?);
            }
            "-p" | "--integrity" => {
                info!("Running a singular package integrity scan (without conffiles)");
                return Ok(package_integrity_scan(false)?);
            }
            "-a" | "--integrity_all" => {
                info!("Running a singular package integrity scan (including conffiles)");
                return Ok(package_integrity_scan(true)?);
            }
            "-d" | "--daemonize" => {
                info!("Daemonizing");
                orphan_self()?;
            }
            "-i" | "--diff" => {
                info!("Diffing config against defaults");
                if let Err(e) = dropper::diff_config("sample_rb2.yaml") {
                    error!("Diff config error: {e:#}");
                    return Err(e.into());
                } else {
                    return Ok(());
                }
            }
            s => {
                warn!("Unknown arg {s}");
            }
        }
    }

    tokio_main()
}

#[tokio::main]
async fn tokio_main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize config from RB2_CONFIG env var
    let cfg = match config::yaml::get_config() {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to initialize config: {:?}", e);
            std::process::exit(1);
        }
    };

    // now that config is loaded, wire up log4rs rolling-file appenders
    config::logger::add_file_appenders(&config::logger::FileAppenderPaths {
        firewall: cfg.firewall.as_ref().map(|c| c.log_file.as_path()),
        process: cfg.process.as_ref().map(|c| c.log_file.as_path()),
        ace: cfg.process.as_ref().map(|c| c.alert_log_file.as_path()),
        auth: cfg.auth.as_ref().map(|c| c.log_file.as_path()),
        audit: None,
        network: cfg.networking.as_ref().map(|c| c.log_file.as_path()),
        yara: cfg.yara.as_ref().map(|c| c.log_file.as_path()),
        scan: cfg.scan.as_ref().map(|c| c.log_file.as_path()),
        fim: cfg.file_integrity.as_ref().map(|c| c.log_file.as_path()),
        health: Some(cfg.health_log_file.as_path()),
        rollover_size_bytes: cfg.logging.rollover_size_bytes,
        rollover_count: cfg.logging.rollover_count,
        queue_ingest_enabled: cfg.ingestor.is_some(),
    });

    // Try to fetch/locate btf for ebpf
    let btf_file_path = match fetch_btf::get_btf_file().await {
        Ok(path) => {
            info!(
                "BTF file loading from: {}",
                path.to_str().unwrap_or("UNKNOWN")
            );
            Some(path)
        }
        Err(e) => {
            warn!(
                "BTF file could not be found/fetched: {}. Disabling all eBPF-dependent features.",
                e
            );
            None
        }
    };

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let self_observation_filter = match ingest::SelfObservationFilter::from_app_config(cfg).await {
        Ok(filter) => Arc::new(filter),
        Err(err) => {
            warn!("failed to build self-observation filter: {err:#}");
            Arc::new(ingest::SelfObservationFilter::default())
        }
    };
    let mut handles: Vec<JoinHandle<()>> = if let Some(btf_path) = &btf_file_path {
        spawn_ebpf_tasks(cfg, btf_path, shutdown_rx.clone())
    } else {
        Vec::new()
    };

    if let Some(network_cfg) = &cfg.networking {
        let network_cfg = network_cfg.clone();
        let network_filter = self_observation_filter.clone();
        let network_shutdown_rx = shutdown_rx.clone();
        handles.push(tokio::spawn(async move {
            if let Err(e) = network::run(network_cfg, network_filter, network_shutdown_rx).await {
                error!("networking capture failed: {:?}", e);
            }
        }));
    } else {
        info!("Networking feature disabled via config");
    }

    let audit_flags = audit::derive_audit_event_flags(cfg);
    let mut audit_daemon: Option<AuditDaemon> = None;
    let mut audit_unavailable_reason = None;
    if !audit_flags.is_empty() {
        if audit::is_external_auditd_running() {
            audit_unavailable_reason = Some("external auditd is already running");
        } else {
            match AuditDaemon::start_with_config(
                AuditDaemonConfig {
                    event_flags: audit_flags,
                },
                shutdown_rx.clone(),
            ) {
                Ok(daemon) => audit_daemon = Some(daemon),
                Err(err) => {
                    error!(
                        "Failed to start shared audit daemon: {err:#}. Continuing without audit-backed features."
                    );
                    audit_unavailable_reason = Some("shared audit daemon failed to start");
                }
            }
        }
    }
    audit::log_audit_feature_degradation(cfg, audit_daemon.is_some(), audit_unavailable_reason);

    if let Some(process_cfg) = &cfg.process
        && process_cfg.collector == ProcessCollector::Auditd
    {
        if let Some(daemon) = audit_daemon.as_ref() {
            let cloned_process_cfg = process_cfg.clone();
            let audit_rx = daemon.subscribe_events();
            let audit_shutdown_rx = shutdown_rx.clone();
            handles.push(tokio::spawn(async move {
                if let Err(e) =
                    audit::run_with_stream(cloned_process_cfg, audit_shutdown_rx, audit_rx).await
                {
                    error!("auditd process monitor failed {:?}", e);
                }
            }));
        } else {
            error!("Auditd process collector requested but shared audit daemon was not started");
        }
    }

    if let Some(firewall_cfg) = &cfg.firewall {
        match firewall_cfg.producer {
            ProducerConfig::Auditd => {
                if let Some(daemon) = audit_daemon.as_ref() {
                    let audit_rx = daemon.subscribe_events();
                    let audit_firewall_cfg = firewall_cfg.clone();
                    let firewall_filter = self_observation_filter.clone();
                    let audit_shutdown_rx = shutdown_rx.clone();
                    handles.push(tokio::spawn(async move {
                        if let Err(e) = dispatcher::run_firewall(
                            audit_firewall_cfg,
                            ProducerInput::Audit {
                                receiver: audit_rx,
                                shutdown_rx: audit_shutdown_rx,
                            },
                            firewall_filter,
                        )
                        .await
                        {
                            error!("auditd firewall failed {:?}", e);
                        }
                    }));
                } else {
                    error!(
                        "Auditd firewall producer requested but shared audit daemon was not started"
                    );
                }
            }
            _ => {
                if let Some(btf_path) = &btf_file_path {
                    let cloned_btf_path = btf_path.to_path_buf();
                    let cloned_firewall_cfg = firewall_cfg.clone();
                    let firewall_filter = self_observation_filter.clone();
                    let firewall_shutdown_rx = shutdown_rx.clone();
                    handles.push(tokio::spawn(async move {
                        if let Err(e) = dispatcher::run_firewall(
                            cloned_firewall_cfg,
                            ProducerInput::Config {
                                btf_file_path: cloned_btf_path,
                                shutdown_rx: firewall_shutdown_rx,
                            },
                            firewall_filter,
                        )
                        .await
                        {
                            error!("firewall failed {:?}", e);
                        }
                    }));
                } else {
                    warn!("Firewall requested but BTF path is unavailable");
                }
            }
        }
    }

    let mut yara_fanotify_handle = None;
    if let Some(yara_cfg) = &cfg.yara {
        if let Some(max_bytes) = yara_cfg.max_scan_bytes_per_rule {
            yara::yara_scan::set_max_scan_bytes_per_rule(max_bytes as usize);
        }

        match yara::yara_init_scan(yara_cfg, shutdown_rx.clone()) {
            Ok(handle) => yara_fanotify_handle = handle,
            Err(e) => error!("Yara scanning failed to start: {:?}", e),
        }
    } else {
        info!("YARA feature disabled via config");
    }

    if let Some(scan_cfg) = &cfg.scan {
        let cfg = scan_cfg.clone();
        tokio::spawn(async move {
            let Err(e) = scans::do_scans(cfg).await;
            error!("misc scans failed {:?}", e);
        });
    } else {
        info!("Misc scans disabled via config");
    }

    if let Some(ingestor_cfg) = &cfg.ingestor {
        let cfg = ingestor_cfg.clone();
        let ingestor_shutdown_rx = shutdown_rx.clone();
        handles.push(tokio::spawn(async move {
            if let Err(e) = ingest::run_ingestor(cfg, ingestor_shutdown_rx).await {
                error!("Log ingestor failed: {:?}", e);
            }
        }));

        #[cfg(feature = "tracing")]
        {
            let cfg = ingestor_cfg.clone();
            if let Some((forwarder_name, oo_cfg)) = cfg.first_openobserve_forwarder() {
                if let Err(e) = ingest::traces::init_tracer(oo_cfg) {
                    error!("Failed to initialize trace reporter: {:?}", e);
                } else {
                    if cfg.openobserve_forwarder_count() > 1 {
                        warn!(
                            "Multiple OpenObserve forwarders are configured; tracing will use '{}'",
                            forwarder_name
                        );
                    }
                    info!(
                        "Trace reporter initialized (OpenObserve OTLP via '{}')",
                        forwarder_name
                    );
                }
            } else {
                warn!("tracing feature is on but no OpenObserve forwarder is configured");
            }
        }
    } else {
        info!("Log ingestor disabled via config");
    }

    if let Some(file_integrity_cfg) = &cfg.file_integrity {
        let cfg = file_integrity_cfg.clone();
        thread::spawn(move || {
            if let Err(e) = file_integrity::init_fanotify_monitoring(&cfg) {
                error!("FIM monitoring failed: {}", e);
            }
        });
    } else {
        info!("FIM feature disabled via config");
    }

    if under_systemd() {
        sd_ready();
        spawn_systemd_watchdog();
    }

    tokio::spawn(async move {
        health::run_health_check().await;
    });

    info!("Waiting for Ctrl-C...");
    shutdown_signal().await;
    info!("Shutdown signal received, ending...");

    let _ = shutdown_tx.send(true);

    if let Some(handle) = yara_fanotify_handle
        && let Err(err) = handle.join()
    {
        error!("YARA fanotify thread join failed: {:?}", err);
    }

    // XXX: this will hang to flush if o2 is failing, but I don't care
    #[cfg(feature = "tracing")]
    ingest::traces::shutdown().await;

    for h in handles {
        if let Err(e) = h.await {
            error!("Task join failed: {:?}", e);
        }
    }

    Ok(())
}

async fn shutdown_signal() {
    let mut sigterm = signal(SignalKind::terminate()).expect("install SIGTERM handler");
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = sigterm.recv() => {}
    }
}

fn spawn_ebpf_tasks(
    cfg: &AppConfig,
    btf_file_path: &std::path::Path,
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> Vec<JoinHandle<()>> {
    let mut handles = Vec::new();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    use nix::sys::resource::{RLIM_INFINITY, Resource, setrlimit};
    let _ = setrlimit(Resource::RLIMIT_MEMLOCK, RLIM_INFINITY, RLIM_INFINITY);

    if cfg.firewall.is_none() {
        info!("Firewall feature disabled via config");
    } else {
        debug!("Firewall startup handled outside eBPF task setup");
    }

    if let Some(process_cfg) = &cfg.process {
        if process_cfg.collector == ProcessCollector::Ebpf {
            let cloned_btf_path = btf_file_path.to_path_buf();
            let cloned_process_cfg = process_cfg.clone();
            tokio::spawn(async move {
                let Err(e) = process_monitor::run(cloned_btf_path, cloned_process_cfg).await;
                error!("ebpf process monitor failed {:?}", e);
            });
        } else {
            info!("Process auditd collector will be started outside eBPF task setup");
        }
    } else {
        info!("Process monitor feature disabled via config");
    }

    if let Some(auth_cfg) = &cfg.auth {
        let cloned_btf_path = btf_file_path.to_path_buf();
        let cloned_auth_cfg = auth_cfg.clone();
        tokio::spawn(async move {
            if let Err(e) = auth::run(cloned_btf_path, cloned_auth_cfg).await {
                error!("ebpf auth collector failed {:?}", e);
            }
        });
    } else {
        info!("Auth monitor feature disabled via config");
    }

    if let Some(tty_cfg) = &cfg.tty {
        let cloned_btf_path = btf_file_path.to_path_buf();
        let cloned_tty_cfg = tty_cfg.clone();
        let cloned_os_cfg = cfg.object_storage.clone();
        let mut shutdown_rx = shutdown_rx;

        handles.push(tokio::spawn(async move {
            let shutdown = async move {
                while !*shutdown_rx.borrow() {
                    if shutdown_rx.changed().await.is_err() {
                        break;
                    }
                }
            };

            if let Err(e) = tty::run(cloned_btf_path, cloned_tty_cfg, cloned_os_cfg, shutdown).await
            {
                error!("ebpf tty session monitor failed {:?}", e);
            }
        }));
    } else {
        info!("Tty session monitor feature disabled via config");
    }

    handles
}

fn orphan_self() -> io::Result<()> {
    use std::os::fd::{AsFd, FromRawFd, OwnedFd};

    use nix::{
        errno::Errno,
        fcntl::{OFlag, open},
        sys::{
            signal::{self, SigHandler, Signal},
            stat::Mode,
            wait::waitpid,
        },
        unistd::{ForkResult, dup2, fork, setsid},
    };

    fn errno_to_io(errno: Errno) -> io::Error {
        io::Error::from_raw_os_error(errno as i32)
    }

    // Ignore some signals
    unsafe {
        signal::signal(Signal::SIGHUP, SigHandler::SigIgn).map_err(errno_to_io)?;
        signal::signal(Signal::SIGPIPE, SigHandler::SigIgn).map_err(errno_to_io)?;
    }

    // fork and exit as parent
    match unsafe { fork().map_err(errno_to_io)? } {
        ForkResult::Parent { child } => {
            let _ = waitpid(child, None);
            std::process::exit(0);
        }
        ForkResult::Child => {}
    }

    // Become session leader
    setsid().map_err(errno_to_io)?;

    // fork a grandchild and exit parent to avoid reacquiring a controlling terminal
    match unsafe { fork().map_err(errno_to_io)? } {
        ForkResult::Parent { .. } => {
            std::process::exit(0);
        }
        ForkResult::Child => {}
    }

    // Open /dev/null
    let devnull = open("/dev/null", OFlag::O_RDWR, Mode::empty()).map_err(errno_to_io)?;

    // Redirect stdin/out/err to /dev/null.
    for raw in [0, 1, 2] {
        let mut target = unsafe { OwnedFd::from_raw_fd(raw) };
        dup2(devnull.as_fd(), &mut target).map_err(errno_to_io)?;
        // Prevent closing 0/1/2 when `target` is dropped
        std::mem::forget(target);
    }

    Ok(())
}

fn yara_scan() -> anyhow::Result<()> {
    // Build a YaraConfig (either from config, or a sane default)
    let cfg = match config::yaml::get_config() {
        Ok(app) => {
            if let Some(y) = app.yara.as_ref() {
                y.clone()
            } else {
                warn!("yara not present/enabled in config, defaulting to built-in rules");
                crate::config::yaml::YaraConfig {
                    rules_dir: None,
                    log_file: std::path::PathBuf::from("/var/log/rb2/yara"),
                    max_scan_bytes_per_rule: None,
                    poll_interval_secs: None,
                    full_scan_interval_secs: None,
                    disabled_rules: std::collections::HashSet::new(),
                    disable_bundled_rules: false,
                    actions: crate::config::yaml::YaraActions {
                        alert: true,
                        kill: true,
                        move_sample: false,
                    },
                    samples_dir: std::path::PathBuf::from("/var/lib/rb2/samples"),
                    fanotify_enabled: false,
                }
            }
        }
        Err(e) => {
            warn!(
                "Failed to initialize config, defaulting to built-in rules: {:?}",
                e
            );
            crate::config::yaml::YaraConfig {
                rules_dir: None,
                log_file: std::path::PathBuf::from("/var/log/rb2/yara"),
                max_scan_bytes_per_rule: None,
                poll_interval_secs: None,
                full_scan_interval_secs: None,
                disabled_rules: std::collections::HashSet::new(),
                disable_bundled_rules: false,
                actions: crate::config::yaml::YaraActions {
                    alert: true,
                    kill: true,
                    move_sample: false,
                },
                samples_dir: std::path::PathBuf::from("/var/lib/rb2/samples"),
                fanotify_enabled: false,
            }
        }
    };

    let rules = yara::build_rules(cfg.disable_bundled_rules, &cfg.rules_dir)?;
    let mut scanner = yara_x::blocks::Scanner::new(&rules);
    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    full_scan_all(
        std::process::id() as i32,
        &mut scanner,
        &mut std::collections::HashMap::new(),
        &mut std::collections::HashSet::new(),
        &mut Vec::new(),
        &cfg,
        &shutdown_rx,
    );

    Ok(())
}

fn package_integrity_scan(scan_conffiles: bool) -> anyhow::Result<()> {
    use anyhow::Context;

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("building tokio runtime failed")?;

    rt.block_on(integrity::single_scan(scan_conffiles))
        .context("integrity single_scan failed")?;

    Ok(())
}

fn under_systemd() -> bool {
    std::env::var_os("NOTIFY_SOCKET").is_some()
}

fn spawn_systemd_watchdog() {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(15));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            interval.tick().await;
            let _ = sd_notify::notify(&[sd_notify::NotifyState::Watchdog]);
        }
    });
}

fn sd_ready() {
    let _ = sd_notify::notify(&[sd_notify::NotifyState::Ready]);
}
