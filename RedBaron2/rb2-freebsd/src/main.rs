#[cfg(not(target_os = "freebsd"))]
compile_error!("only freebsd is supported");

mod bsm;
mod firewall;
mod service;
mod sysctl;
mod yara_scan;

use log::{error, info, warn};
use rb2_userspace::yara;
use rb2_userspace::{config, ingest, misc::health};
use std::{env, io, sync::Arc, thread};
use tokio::{
    signal::unix::{SignalKind, signal},
    sync::{mpsc, watch},
    task::JoinHandle,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    config::logger::init();
    let args = env::args().skip(1).peekable();
    for arg in args {
        match arg.as_str() {
            "-c" | "--config" => {
                let path = config::dropper::write_config_with_fallback("rb2.yaml")?;
                info!("Written config to {:?}", path);
                return Ok(());
            }
            "-i" | "--diff" => {
                info!("Diffing config against defaults");
                if let Err(e) = config::dropper::diff_config("sample_rb2.yaml") {
                    error!("Diff config error: {e:#}");
                    return Err(e.into());
                } else {
                    return Ok(());
                }
            }
            "-s" | "--service" => {
                service::install_rc_service()?;
                info!("rc.d service installed, exiting");
                return Ok(());
            }
            "-y" | "--yara" => {
                info!("Running a singular full yara scan");
                return Ok(yara_scan()?);
            }
            "-d" | "--daemonize" => {
                info!("Daemonizing");
                orphan_self()?;
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
    let cfg = match config::yaml::get_config() {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to initialize config: {:?}", e);
            std::process::exit(1);
        }
    };

    config::logger::add_file_appenders(&config::logger::FileAppenderPaths {
        firewall: cfg.firewall.as_ref().map(|c| c.log_file.as_path()),
        process: cfg.process.as_ref().map(|c| c.log_file.as_path()),
        ace: cfg.process.as_ref().map(|c| c.alert_log_file.as_path()),
        auth: cfg.auth.as_ref().map(|c| c.log_file.as_path()),
        #[cfg(not(target_os = "linux"))]
        audit: cfg.audit.as_ref().map(|c| c.log_file.as_path()),
        #[cfg(target_os = "linux")]
        audit: None,
        yara: cfg.yara.as_ref().map(|c| c.log_file.as_path()),
        health: Some(cfg.health_log_file.as_path()),
        rollover_size_bytes: cfg.logging.rollover_size_bytes,
        rollover_count: cfg.logging.rollover_count,
        queue_ingest_enabled: cfg.ingestor.is_some(),
        ..Default::default()
    });

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let self_observation_filter = match ingest::SelfObservationFilter::from_app_config(cfg).await {
        Ok(filter) => Arc::new(filter),
        Err(err) => {
            warn!("failed to build self-observation filter: {err:#}");
            Arc::new(ingest::SelfObservationFilter::default())
        }
    };
    let mut handles: Vec<JoinHandle<()>> = Vec::new();

    if let Some(ref yara_cfg) = cfg.yara {
        if let Some(max_bytes) = yara_cfg.max_scan_bytes_per_rule {
            yara_scan::set_max_scan_bytes_per_rule(max_bytes as usize);
        }
        match yara::build_rules(yara_cfg.disable_bundled_rules, &yara_cfg.rules_dir) {
            Ok(rules) => {
                let cfg_clone = yara_cfg.clone();
                thread::spawn(move || {
                    const YARA_NICE_LEVEL: i32 = 10;
                    unsafe { libc::nice(YARA_NICE_LEVEL) };
                    if let Err(e) = yara_scan::yara_init_memory_scan(&cfg_clone, &rules) {
                        error!("YARA memory scanning failed: {}", e);
                    }
                });
            }
            Err(e) => {
                error!("Yara scanning failed to start {}", e);
            }
        }
        let _ = yara_cfg;
    } else {
        info!("YARA feature disabled via config");
    }

    let process_cfg = cfg.process.clone();
    let ace_engine = process_cfg
        .as_ref()
        .and_then(rb2_userspace::process::pipeline::init_rhai_engine);
    let scorer = process_cfg.as_ref().and_then(|process| {
        process
            .ml_enabled
            .then(|| rb2_ml::OnlineScorer::new(rb2_ml::Config::default()))
    });
    let ml_debug = process_cfg
        .as_ref()
        .map(|process| process.ml_debug)
        .unwrap_or(false);
    let (process_tx, process_rx) = mpsc::channel(128);
    let process_pipeline = tokio::spawn(async move {
        rb2_userspace::process::pipeline::run_event_pipeline(
            ace_engine, scorer, ml_debug, process_rx,
        )
        .await;
    });

    let fw_tx = cfg
        .firewall
        .as_ref()
        .filter(|fw| fw.producer == rb2_userspace::config::yaml::ProducerConfig::Bsm)
        .map(|fw_cfg| {
            let (tx, rx) = mpsc::channel(1024);
            let fw_cfg = fw_cfg.clone();
            let fw_filter = self_observation_filter.clone();
            tokio::spawn(async move {
                crate::firewall::run_bsm_firewall(fw_cfg, fw_filter, rx).await;
            });
            tx
        });

    let bsm_shutdown_rx = shutdown_rx.clone();
    handles.push(tokio::task::spawn_blocking(move || {
        crate::bsm::run_auditpipe(bsm_shutdown_rx, process_tx, fw_tx);
    }));

    if let Some(ref ingestor_cfg) = cfg.ingestor {
        let cfg = ingestor_cfg.clone();
        let ingestor_shutdown_rx = shutdown_rx.clone();
        handles.push(tokio::spawn(async move {
            if let Err(e) = ingest::run_ingestor(cfg, ingestor_shutdown_rx).await {
                error!("Log ingestor failed: {:?}", e);
            }
        }));
    } else {
        info!("Log ingestor disabled via config");
    }

    tokio::spawn(async move {
        health::run_health_check().await;
    });

    info!("Waiting for Ctrl-C...");
    shutdown_signal().await;
    info!("Shutdown signal received, ending...");

    let _ = shutdown_tx.send(true);

    for h in handles {
        if let Err(e) = h.await {
            error!("Task join failed: {:?}", e);
        }
    }

    process_pipeline.abort();
    let _ = process_pipeline.await;

    Ok(())
}

async fn shutdown_signal() {
    let mut sigterm = signal(SignalKind::terminate()).expect("install SIGTERM handler");
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = sigterm.recv() => {}
    }
}

fn yara_scan() -> anyhow::Result<()> {
    use rb2_userspace::config::yaml::{YaraActions, YaraConfig};

    let cfg = match config::yaml::get_config() {
        Ok(app) => {
            if let Some(y) = app.yara.as_ref() {
                y.clone()
            } else {
                warn!("yara not present/enabled in config, defaulting to built-in rules");
                YaraConfig {
                    rules_dir: None,
                    log_file: std::path::PathBuf::from("/var/log/rb2/yara"),
                    max_scan_bytes_per_rule: None,
                    poll_interval_secs: None,
                    full_scan_interval_secs: None,
                    disabled_rules: std::collections::HashSet::new(),
                    disable_bundled_rules: false,
                    actions: YaraActions {
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
            YaraConfig {
                rules_dir: None,
                log_file: std::path::PathBuf::from("/var/log/rb2/yara"),
                max_scan_bytes_per_rule: None,
                poll_interval_secs: None,
                full_scan_interval_secs: None,
                disabled_rules: std::collections::HashSet::new(),
                disable_bundled_rules: false,
                actions: YaraActions {
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

    crate::yara_scan::full_scan_all(
        std::process::id() as i32,
        &mut scanner,
        &mut std::collections::HashMap::new(),
        &mut std::collections::HashSet::new(),
        &mut Vec::new(),
        &cfg,
    );

    Ok(())
}

fn orphan_self() -> io::Result<()> {
    use nix::errno::Errno;
    use nix::fcntl::{OFlag, open};
    use nix::sys::signal::{self, SigHandler, Signal};
    use nix::sys::stat::Mode;
    use nix::sys::wait::waitpid;
    use nix::unistd::{ForkResult, dup2, fork, setsid};
    use std::os::fd::AsFd;
    use std::os::fd::FromRawFd;
    use std::os::fd::OwnedFd;

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
