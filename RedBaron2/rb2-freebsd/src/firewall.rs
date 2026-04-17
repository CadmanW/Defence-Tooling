use chrono::SecondsFormat;
use log::{debug, info, warn};
use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use rb2_userspace::config::yaml::FirewallConfig;
use rb2_userspace::ingest::SelfObservationFilter;
use rb2_userspace::misc::{get_hostname, get_machine_id};
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;
use tokio::sync::{RwLock, mpsc};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BsmFirewallEvent {
    pub pid: i32,
    pub comm: Option<String>,
    pub dport: Option<u16>,
    pub ip: Option<String>,
    pub op: Option<String>,
}

pub async fn run_bsm_firewall(
    cfg: FirewallConfig,
    filter: Arc<SelfObservationFilter>,
    mut rx: mpsc::Receiver<BsmFirewallEvent>,
) {
    info!("FreeBSD BSM firewall started (enforcing={})", cfg.enforcing);

    let startup_cfg = cfg.clone();
    let startup_filter = filter.clone();
    tokio::task::spawn_blocking(move || clean_active_sockets(&startup_cfg, &startup_filter))
        .await
        .unwrap_or_else(|e| warn!("BSM firewall: startup socket scan panicked: {}", e));

    while let Some(ev) = rx.recv().await {
        let path = crate::sysctl::get_exe_path(ev.pid).map(PathBuf::from);

        let allowed = path
            .as_ref()
            .map(|p| cfg.binary_whitelist.contains(p))
            .unwrap_or_else(|| {
                debug!("Failed to resolve path for pid {}", ev.pid);
                false
            });

        debug!(
            "BSM firewall decision={} pid={} path={:?}",
            allowed, ev.pid, path
        );

        log_event(&ev, path.as_ref(), allowed, cfg.enforcing, &filter).await;

        if !allowed {
            if cfg.enforcing {
                kill_pid(ev.pid);
            } else {
                warn!(
                    "Would have killed pid {} path {} if enforcing",
                    ev.pid,
                    path.as_ref()
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|| "<unknown>".to_string())
                );
            }
        }
    }

    debug!("BSM firewall event channel closed; dispatcher exiting");
}

/// On startup, enumerate all active (non-loopback) sockets via sockstat and
/// kill any whose exe is not in the whitelist, mirroring the Linux
/// clean_active_sockets / kill_disallowed_sockets behaviour.
fn clean_active_sockets(cfg: &FirewallConfig, filter: &SelfObservationFilter) {
    let output = match Command::new("sockstat").args(["-4", "-6", "-q"]).output() {
        Ok(o) => o,
        Err(e) => {
            warn!("BSM firewall: failed to run sockstat at startup: {}", e);
            return;
        }
    };

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        warn!(
            "BSM firewall: sockstat exited with {} at startup: {}",
            output.status,
            stderr.trim()
        );
        return;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);

    // sockstat -q columns: user command pid fd proto local_addr foreign_addr
    for line in stdout.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 7 {
            continue;
        }
        let pid: i32 = match parts[2].parse() {
            Ok(p) => p,
            Err(_) => continue,
        };

        let local = parts[5];
        let foreign = parts[6];

        // Mirror Linux: skip only when both endpoints are loopback.
        let local_is_loopback = local.starts_with("127.") || local.starts_with("::1");
        let foreign_is_loopback = foreign.starts_with("127.") || foreign.starts_with("::1");
        if local_is_loopback && foreign_is_loopback {
            continue;
        }

        let path = crate::sysctl::get_exe_path(pid).map(PathBuf::from);
        let allowed = path
            .as_ref()
            .map(|p| cfg.binary_whitelist.contains(p))
            .unwrap_or(false);

        let path_str = path
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "<unknown>".to_string());

        let (foreign_ip, foreign_port) = split_addr(foreign);
        let startup_event = BsmFirewallEvent {
            pid,
            comm: None,
            dport: foreign_port,
            ip: Some(foreign_ip.clone()),
            op: Some("existing_socket".to_string()),
        };

        if let Some(path) = path.as_deref()
            && filter.should_ignore_firewall(path, startup_event.ip.as_deref(), startup_event.dport)
        {
            continue;
        }

        let action = if allowed { "ALLOW" } else { "DENY" };
        let ts = chrono::Local::now().to_rfc3339_opts(SecondsFormat::Millis, true);

        let json = serde_json::json!({
            "timestamp": ts,
            "decision": action,
            "enforcing": cfg.enforcing,
            "producer": "bsm",
            "pid": pid,
            "path": path_str,
            "ip": foreign_ip,
            "port": foreign_port,
            "op": "existing_socket",
            "host_name": get_hostname(),
            "host_id": get_machine_id(),
        });
        info!(target: "rb2_firewall", "{}", json);

        if !allowed {
            if cfg.enforcing {
                kill_pid(pid);
            } else {
                warn!(
                    "BSM firewall: would kill pid {} path {} (existing socket, not enforcing)",
                    pid, path_str
                );
            }
        }
    }

    debug!("BSM firewall: existing sockets evaluated");
}

/// Split `ip:port` or `[ipv6]:port` into (ip_str, port).
fn split_addr(addr: &str) -> (String, Option<u16>) {
    let Some(colon) = addr.rfind(':') else {
        return (addr.to_string(), None);
    };
    let ip = addr[..colon].to_string();
    let port = addr[colon + 1..].parse().ok();
    (ip, port)
}

static EVENT_CACHE: RwLock<Option<(BsmFirewallEvent, Option<PathBuf>)>> = RwLock::const_new(None);

async fn log_event(
    ev: &BsmFirewallEvent,
    path: Option<&PathBuf>,
    dec: bool,
    enforcing: bool,
    filter: &SelfObservationFilter,
) {
    let mut saved_path: Option<PathBuf> = None;

    {
        let cache = EVENT_CACHE.read().await;
        if let Some((cached_ev, cached_path)) = cache.as_ref() {
            if cached_ev == ev && cached_path.as_ref() == path {
                return;
            }
            if path.is_none() && cached_ev.pid == ev.pid && cached_ev.comm == ev.comm {
                saved_path = cached_path.clone();
            }
        }
    }

    let eff_path = if saved_path.is_some() {
        saved_path
    } else {
        path.cloned()
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
        "producer": "bsm",
        "pid": ev.pid,
        "path": path_str,
        "comm": ev.comm,
        "ip": ev.ip,
        "port": ev.dport,
        "op": ev.op,
        "host_name": get_hostname(),
        "host_id": get_machine_id(),
    });

    info!(target: "rb2_firewall", "{}", json);
}

fn kill_pid(pid: i32) {
    if pid == nix::unistd::getpid().as_raw() {
        debug!("BSM firewall: refusing to kill self (pid {})", pid);
        return;
    }
    match kill(Pid::from_raw(pid), Signal::SIGKILL) {
        Ok(()) => debug!("BSM firewall killed pid {}", pid),
        Err(nix::errno::Errno::ESRCH) => debug!("BSM firewall: pid {} already gone", pid),
        Err(e) => debug!("BSM firewall: kill pid {} failed: {}", pid, e),
    }
}
