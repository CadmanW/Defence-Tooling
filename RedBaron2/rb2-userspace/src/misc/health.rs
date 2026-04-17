use chrono::SecondsFormat;
use log::info;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::fmt::Write as _;
use std::sync::OnceLock;
use std::time::Instant;
use sysinfo::{Networks, Pid, ProcessRefreshKind, ProcessesToUpdate, System};
use tokio::fs;
use tokio::time::{Duration, MissedTickBehavior};

use crate::config::yaml::get_config;
use crate::misc::{get_hostname, get_machine_id};

static PROCESS_START: OnceLock<Instant> = OnceLock::new();
static STATIC_INFO: OnceLock<Value> = OnceLock::new();
static HOSTNAME: OnceLock<String> = OnceLock::new();
static MACHINE_ID: OnceLock<String> = OnceLock::new();

struct HealthState {
    sys: System,
}

impl HealthState {
    fn new() -> Self {
        Self { sys: System::new() }
    }

    fn refresh_runtime(&mut self) {
        self.sys.refresh_memory();
        self.sys.refresh_processes_specifics(
            ProcessesToUpdate::All,
            true,
            ProcessRefreshKind::nothing().with_memory(),
        );
    }

    fn runtime_json(&self) -> Map<String, Value> {
        let mut out = Map::new();

        let total = self.sys.total_memory();
        let used = self.sys.used_memory();

        let free_pct = if total > 0 {
            ((total - used) as f64 / total as f64) * 100.0
        } else {
            0.0
        };

        out.insert("sysinfo_total_memory".into(), json!(total));
        out.insert("sysinfo_used_memory".into(), json!(used));
        out.insert("sysinfo_free_ram_percent".into(), json!(free_pct));
        out.insert(
            "sysinfo_process_count".into(),
            json!(self.sys.processes().len()),
        );

        // dynamic user count (NOT cached)
        let users = sysinfo::Users::new_with_refreshed_list();
        out.insert("sysinfo_user_count".into(), json!(users.list().len()));

        // rb2 process memory (current process)
        let pid = std::process::id();
        if let Some(proc) = self.sys.process(Pid::from_u32(pid)) {
            let bytes = proc.memory();
            out.insert("rb2_process_memory_bytes".into(), json!(bytes));
            out.insert(
                "rb2_process_memory_human".into(),
                json!(format_bytes_human(bytes)),
            );
        }

        out
    }
}

fn format_bytes_human(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{:.2}G", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2}M", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2}K", bytes as f64 / KB as f64)
    } else {
        format!("{}B", bytes)
    }
}

async fn init_static_health_info() {
    if STATIC_INFO.get().is_some() {
        return;
    }

    let cfg = match get_config() {
        Ok(c) => c,
        Err(_) => return,
    };

    HOSTNAME.get_or_init(|| get_hostname().unwrap_or_else(|| "unknown".to_string()));
    MACHINE_ID.get_or_init(|| get_machine_id().unwrap_or_else(|| "unknown".to_string()));

    let kernel = System::kernel_long_version();
    let os = System::long_os_version();
    let arch = System::cpu_arch();
    let boot = System::boot_time();
    let cpu_count = System::physical_core_count();

    let networks = Networks::new_with_refreshed_list();
    let binary_sha256 = compute_binary_sha256().await;

    let networks_json: Vec<Value> = networks
        .iter()
        .map(|(name, data)| {
            json!({
                "interface": name,
                "mac_address": format!("{}", data.mac_address()),
                "ip_networks": data.ip_networks()
                    .iter()
                    .map(|ip| ip.to_string())
                    .collect::<Vec<_>>()
            })
        })
        .collect();

    let static_blob = json!({
        "sysinfo_kernel_long_version": kernel,
        "sysinfo_long_os_version": os,
        "sysinfo_cpu_arch": arch,
        "sysinfo_boot_time": boot,
        "sysinfo_physical_core_count": cpu_count,
        "sysinfo_networks": networks_json,
        "binary_sha256": binary_sha256,
        "features": build_features_json(cfg),
        "logging": {
            "log_dir": cfg.logging.log_dir.to_string_lossy(),
            "rollover_size_bytes": cfg.logging.rollover_size_bytes,
            "rollover_count": cfg.logging.rollover_count
        }
    });

    STATIC_INFO.set(static_blob).ok();
}

pub async fn run_health_check() {
    PROCESS_START.get_or_init(Instant::now);

    init_static_health_info().await;

    let hostname = HOSTNAME
        .get_or_init(|| get_hostname().unwrap_or_else(|| "unknown".to_string()))
        .clone();
    let machine_id = MACHINE_ID
        .get_or_init(|| get_machine_id().unwrap_or_else(|| "unknown".to_string()))
        .clone();

    let static_info = STATIC_INFO.get_or_init(|| Value::Null).clone();

    let mut interval = tokio::time::interval(Duration::from_secs(30));
    interval.set_missed_tick_behavior(MissedTickBehavior::Delay);

    let mut state = HealthState::new();

    info!("Health checker started");

    loop {
        state.refresh_runtime();

        let mut payload = Map::new();

        payload.insert(
            "_timestamp".into(),
            json!(chrono::Local::now().to_rfc3339_opts(SecondsFormat::Millis, true)),
        );

        payload.insert("event".into(), json!("health_check"));
        payload.insert("host_name".into(), json!(hostname));
        payload.insert("host_id".into(), json!(machine_id));
        payload.insert("pid".into(), json!(std::process::id()));

        let uptime = PROCESS_START.get().unwrap().elapsed().as_secs();
        payload.insert("uptime_secs".into(), json!(uptime));

        payload.extend(state.runtime_json());

        if let Some(obj) = static_info.as_object() {
            for (k, v) in obj {
                payload.insert(k.clone(), v.clone());
            }
        }

        info!(target: "rb2_health", "{}", Value::Object(payload));

        interval.tick().await;
    }
}

fn build_features_json(cfg: &crate::config::yaml::AppConfig) -> serde_json::Value {
    let firewall = cfg
        .firewall
        .as_ref()
        .map(|f| {
            json!({
                "enabled": true,
                "enforcing": f.enforcing,
                "producer": format!("{:?}", f.producer).to_lowercase(),
                "handler": format!("{:?}", f.handler).to_lowercase(),
            })
        })
        .unwrap_or_else(|| json!({"enabled": false}));

    let process = cfg
        .process
        .as_ref()
        .map(|p| {
            json!({
                "enabled": true,
                "rhai_enabled": p.rhai_enabled,
            })
        })
        .unwrap_or_else(|| json!({"enabled": false}));

    let yara = cfg
        .yara
        .as_ref()
        .map(|y| {
            json!({
                "enabled": true,
                "fanotify_enabled": y.fanotify_enabled,
                "disable_bundled_rules": y.disable_bundled_rules,
                "actions": {
                    "alert": y.actions.alert,
                    "kill": y.actions.kill,
                    "move_sample": y.actions.move_sample,
                },
            })
        })
        .unwrap_or_else(|| json!({"enabled": false}));

    let scan = json!({
        "enabled": cfg.scan.is_some(),
    });

    let networking = cfg
        .networking
        .as_ref()
        .map(|network| {
            json!({
                "enabled": true,
                "interfaces": network.interfaces,
                "dns_enabled": network.dns_enabled,
                "http_enabled": network.http_enabled,
                "https_enabled": network.https_enabled,
                "http_capture_inbound": network.http_capture_inbound,
                "snaplen_bytes": network.snaplen_bytes,
            })
        })
        .unwrap_or_else(|| json!({"enabled": false}));

    let tty = cfg
        .tty
        .as_ref()
        .map(|t| {
            json!({
                "enabled": true,
                "encrypt": t.encrypt,
                "spool_dir": t.spool_dir.to_string_lossy().into_owned(),
                "flush_interval_secs": t.flush_interval_secs,
                "forward_to_s3": t.forward_to_s3,
                "pubkey": if t.pubkey.is_some() { json!("***") } else { json!(null) },
            })
        })
        .unwrap_or_else(|| json!({"enabled": false}));

    let file_integrity = cfg
        .file_integrity
        .as_ref()
        .map(|f| {
            json!({
                "enabled": true,
                "log_paths": f
                    .log_paths
                    .iter()
                    .map(|p| p.to_string_lossy().into_owned())
                    .collect::<Vec<_>>(),
            })
        })
        .unwrap_or_else(|| json!({"enabled": false}));

    let ingestor = cfg
        .ingestor
        .as_ref()
        .map(|i| {
            json!({
                "enabled": true,
                "flush_interval_secs": i.flush_interval_secs,
                "memory_trigger_size_mb": i.memory_trigger_size_mb,
                "stats_interval_secs": i.stats_interval_secs,
                "forwarders": i
                    .forwarders
                    .iter()
                    .map(|forwarder| {
                        let mut obj = json!({
                            "name": forwarder.name,
                            "type": forwarder.forwarder_type,
                        });

                        if let Some(oo) = &forwarder.openobserve {
                            let openobserve = json!({
                                "url": oo.url,
                                "org": oo.org,
                                "stream_prefix": oo.stream_prefix,
                                "username": "***",
                                "password": "***",
                            });
                            if let Some(m) = obj.as_object_mut() {
                                m.insert("openobserve".to_string(), openobserve);
                            }
                        }

                        if let Some(splunk) = &forwarder.splunk {
                            let splunk_json = json!({
                                "url": splunk.url,
                                "index": splunk.index,
                                "source": splunk.source,
                                "sourcetype_prefix": splunk.sourcetype_prefix,
                                "gzip_enabled": splunk.gzip_enabled,
                                "tls_skip_verify": splunk.tls_skip_verify,
                                "token": "***",
                            });
                            if let Some(m) = obj.as_object_mut() {
                                m.insert("splunk".to_string(), splunk_json);
                            }
                        }

                        obj
                    })
                    .collect::<Vec<_>>(),
            })
        })
        .unwrap_or_else(|| json!({"enabled": false}));

    json!({
        "firewall": firewall,
        "process": process,
        "yara": yara,
        "scan": scan,
        "networking": networking,
        "tty": tty,
        "file_integrity": file_integrity,
        "ingestor": ingestor,
    })
}

async fn compute_binary_sha256() -> String {
    // On Linux, read directly from /proc/self/exe - this is the kernel's view
    // of the running binary and cannot be swapped by replacing the file on disk.
    // On other platforms, fall back to current_exe().
    #[cfg(target_os = "linux")]
    let path = std::path::PathBuf::from("/proc/self/exe");
    #[cfg(not(target_os = "linux"))]
    let path = match std::env::current_exe() {
        Ok(p) => p,
        Err(_) => return "unknown".into(),
    };

    let bytes = match fs::read(&path).await {
        Ok(b) => b,
        Err(_) => return "unknown".into(),
    };

    let hash = Sha256::digest(&bytes);

    let mut out = String::with_capacity(hash.len() * 2);
    for byte in hash {
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}
