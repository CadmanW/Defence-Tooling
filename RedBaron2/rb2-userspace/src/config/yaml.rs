use anyhow::{Context, Result, bail};
use log::{debug, error, info, warn};
use std::{
    collections::HashSet,
    env, fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::OnceLock,
};
use yaml_rust2::{Yaml, YamlLoader};

#[derive(Debug, Clone)]
pub struct ScanConfig {
    pub log_file: PathBuf,
    pub poll_interval_secs: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkingConfig {
    pub interfaces: Vec<String>,
    pub dns_enabled: bool,
    pub http_enabled: bool,
    pub https_enabled: bool,
    pub http_capture_inbound: bool,
    pub snaplen_bytes: u64,
    pub log_file: PathBuf,
}

/// Execution order: alert -> collect sample -> kill.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct YaraActions {
    pub alert: bool,
    /// Send SIGKILL
    pub kill: bool,
    /// strip ELF header & save to `samples_dir`
    pub move_sample: bool,
}

#[derive(Debug, Clone)]
pub struct YaraConfig {
    pub rules_dir: Option<PathBuf>,
    pub log_file: PathBuf,
    pub max_scan_bytes_per_rule: Option<u64>,
    pub poll_interval_secs: Option<u64>,
    pub full_scan_interval_secs: Option<u64>,
    pub disabled_rules: HashSet<String>,
    pub disable_bundled_rules: bool,
    pub actions: YaraActions,
    pub samples_dir: PathBuf,
    pub fanotify_enabled: bool,
}

#[derive(Debug, Clone)]
pub struct FirewallConfig {
    pub binary_whitelist: HashSet<PathBuf>,
    pub log_file: PathBuf,
    pub enforcing: bool,

    pub producer: ProducerConfig,
    pub handler: HandlerConfig,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProducerConfig {
    Ebpf,
    Auditd,
    Nfq,
    Bsm,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandlerConfig {
    Kill,
    Nfq,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcessCollector {
    Ebpf,
    Auditd,
}

#[derive(Debug, Clone)]
pub struct ProcessConfig {
    pub collector: ProcessCollector,
    pub rhai_enabled: bool,
    /// Optional directory of extra YAML rules; loaded at startup only.
    pub rhai_rules_dir: Option<PathBuf>,
    pub log_file: PathBuf,
    pub alert_log_file: PathBuf,
    pub disabled_rules: Vec<String>,
    /// Enable ML scoring for process events. When false, no ML state is
    /// updated and no ML fields are attached to process logs.
    pub ml_enabled: bool,
    /// When true, include a full ML breakdown (per-component scores and
    /// template) in the process log. When false, only `ml_score` is logged.
    pub ml_debug: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthConfig {
    pub log_file: PathBuf,
    pub libpam_path: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditConfig {
    pub log_file: PathBuf,
}

#[derive(Debug, Clone)]
pub struct TTYConfig {
    pub encrypt: bool,
    pub authorized_keys_path: Option<PathBuf>,
    pub pubkey: Option<String>,
    pub session_recognition_idle_secs: u64,
    pub spool_dir: PathBuf,
    pub flush_interval_secs: u64,
    pub forward_to_s3: bool,
    pub s3_forward_interval_secs: u64,
}

#[derive(Debug, Clone)]
pub struct ObjectStorageConfig {
    pub endpoint: String,
    pub bucket_tty: String,
    pub bucket_samples: Option<String>,
    pub region: String,
    pub access_key: String,
    pub secret_key: String,
    pub path_style: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenObserveConfig {
    pub url: String,
    pub org: String,
    pub stream_prefix: String,
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SplunkConfig {
    pub url: String,
    pub token: String,
    pub index: Option<String>,
    pub source: String,
    pub sourcetype_prefix: String,
    pub gzip_enabled: bool,
    pub tls_skip_verify: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwarderConfig {
    pub name: String,
    pub forwarder_type: String,
    pub openobserve: Option<OpenObserveConfig>,
    pub splunk: Option<SplunkConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IngestorConfig {
    pub flush_interval_secs: u64,
    pub memory_trigger_size_mb: u64,
    pub stats_interval_secs: u64,
    pub forwarders: Vec<ForwarderConfig>,
}

impl IngestorConfig {
    pub fn first_openobserve_forwarder(&self) -> Option<(&str, &OpenObserveConfig)> {
        self.forwarders.iter().find_map(|forwarder| {
            forwarder
                .openobserve
                .as_ref()
                .map(|cfg| (forwarder.name.as_str(), cfg))
        })
    }

    pub fn openobserve_forwarder_count(&self) -> usize {
        self.forwarders
            .iter()
            .filter(|forwarder| forwarder.openobserve.is_some())
            .count()
    }
}

#[derive(Debug, Clone)]
pub struct FeaturesConfig {
    pub firewall: bool,
    pub process: bool,
    pub auth: bool,
    pub audit: bool,
    pub yara: bool,
    pub scan: bool,
    pub networking: bool,
    pub ingestor: bool,
    pub tty: bool,
    pub file_integrity: bool,
}

#[derive(Debug, Clone)]
pub struct LoggingConfig {
    pub log_dir: PathBuf,
    pub rollover_size_bytes: u64,
    /// Number of archived log files to keep per appender
    pub rollover_count: u32,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            log_dir: PathBuf::from("/var/log/rb2"),
            rollover_size_bytes: 10 * 1024 * 1024, // 10 MB
            rollover_count: 5,
        }
    }
}

#[derive(Debug, Clone)]
pub struct FileIntegrityConfig {
    pub log_paths: Vec<PathBuf>,
    pub log_file: PathBuf,
}

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub yara: Option<YaraConfig>,
    pub firewall: Option<FirewallConfig>,
    pub process: Option<ProcessConfig>,
    pub auth: Option<AuthConfig>,
    pub audit: Option<AuditConfig>,
    pub scan: Option<ScanConfig>,
    pub networking: Option<NetworkingConfig>,
    pub tty: Option<TTYConfig>,
    pub ingestor: Option<IngestorConfig>,
    pub object_storage: Option<ObjectStorageConfig>,
    pub logging: LoggingConfig,
    pub file_integrity: Option<FileIntegrityConfig>,
    /// Health check log file, derived from logging.log_dir
    pub health_log_file: PathBuf,
}

static CONFIG: OnceLock<AppConfig> = OnceLock::new();

pub fn get_config() -> Result<&'static AppConfig> {
    if let Some(cfg) = CONFIG.get() {
        return Ok(cfg);
    }

    let cfg = init_from_env()?;
    match CONFIG.set(cfg) {
        Ok(()) => CONFIG.get().context("config missing after initialization"),
        Err(_) => CONFIG
            .get()
            .context("config missing after initialization race"),
    }
}

pub fn init_from_env() -> Result<AppConfig> {
    const DEFAULT_PATH: &str = "/etc/rb2.yaml";

    let path = match env::var("RB2_CONFIG") {
        Ok(p) => p,
        Err(_) => {
            if Path::new(DEFAULT_PATH).exists() {
                info!(
                    "RB2_CONFIG not set; using default config at {}",
                    DEFAULT_PATH
                );
                DEFAULT_PATH.to_string()
            } else {
                bail!(
                    "RB2_CONFIG env var not set and default config not found at {}",
                    DEFAULT_PATH
                );
            }
        }
    };

    let content =
        fs::read_to_string(&path).with_context(|| format!("Failed to read config {}", path))?;

    parse_config_from_str(&content).with_context(|| format!("Config parse failed for {}", path))
}

/// Parse the last ed25519 public key from an authorized_keys file.
/// Returns None if the file doesn't exist, is unreadable, or contains no ed25519 keys.
fn parse_last_ed25519_key(path: &Path) -> Option<String> {
    let content = fs::read_to_string(path).ok()?;
    let mut lines = content.lines().filter(|line| {
        let trimmed = line.trim();
        !trimmed.is_empty() && !trimmed.starts_with('#') && trimmed.starts_with("ssh-ed25519 ")
    });
    lines.next_back().map(|s| s.to_string())
}

/// Get the default authorized_keys path for the current user.
fn default_authorized_keys_path() -> Option<PathBuf> {
    env::var("HOME")
        .ok()
        .map(|home| PathBuf::from(home).join(".ssh").join("authorized_keys"))
}

fn parse_openobserve_config(doc: &Yaml, path: &str) -> Result<OpenObserveConfig> {
    Ok(OpenObserveConfig {
        url: doc["url"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("{path}.url missing"))?
            .to_string(),
        org: doc["org"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("{path}.org missing"))?
            .to_string(),
        stream_prefix: doc["stream_prefix"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("{path}.stream_prefix missing"))?
            .to_string(),
        username: doc["username"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("{path}.username missing"))?
            .to_string(),
        password: doc["password"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("{path}.password missing"))?
            .to_string(),
    })
}

fn parse_splunk_config(doc: &Yaml, path: &str) -> Result<SplunkConfig> {
    Ok(SplunkConfig {
        url: doc["url"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("{path}.url missing"))?
            .to_string(),
        token: doc["token"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("{path}.token missing"))?
            .to_string(),
        index: doc["index"].as_str().map(|s| s.to_string()),
        source: doc["source"].as_str().unwrap_or("rb2").to_string(),
        sourcetype_prefix: doc["sourcetype_prefix"]
            .as_str()
            .unwrap_or("rb2")
            .to_string(),
        gzip_enabled: doc["gzip_enabled"].as_bool().unwrap_or(true),
        tls_skip_verify: doc["tls_skip_verify"].as_bool().unwrap_or(false),
    })
}

fn parse_forwarder_config(
    doc: &Yaml,
    path: &str,
    default_name: Option<String>,
) -> Result<ForwarderConfig> {
    let forwarder_type = doc["type"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("{path}.type missing"))?
        .to_string();

    let name = match doc["name"].as_str() {
        Some(name) => name.to_string(),
        None => default_name.ok_or_else(|| anyhow::anyhow!("{path}.name missing"))?,
    };

    let (openobserve, splunk) = match forwarder_type.as_str() {
        "openobserve" => (
            Some(parse_openobserve_config(
                &doc["openobserve"],
                &format!("{path}.openobserve"),
            )?),
            None,
        ),
        "splunk" => (
            None,
            Some(parse_splunk_config(
                &doc["splunk"],
                &format!("{path}.splunk"),
            )?),
        ),
        other => {
            bail!("Unknown ingestor forwarder type '{}'", other);
        }
    };

    Ok(ForwarderConfig {
        name,
        forwarder_type,
        openobserve,
        splunk,
    })
}

fn parse_ingestor_forwarders(doc: &Yaml) -> Result<Vec<ForwarderConfig>> {
    if let Some(items) = doc["ingestor"]["forwarders"].as_vec() {
        let mut forwarders = Vec::with_capacity(items.len());
        let mut seen_names = HashSet::with_capacity(items.len());

        for (idx, item) in items.iter().enumerate() {
            let forwarder =
                parse_forwarder_config(item, &format!("ingestor.forwarders[{idx}]"), None)?;
            if !seen_names.insert(forwarder.name.clone()) {
                bail!("Duplicate ingestor forwarder name '{}'", forwarder.name);
            }
            forwarders.push(forwarder);
        }
        if forwarders.is_empty() {
            bail!("ingestor.forwarders must contain at least one forwarder");
        }
        return Ok(forwarders);
    }

    bail!("ingestor.forwarders missing")
}

fn parse_config_from_str(yaml: &str) -> Result<AppConfig> {
    let docs = YamlLoader::load_from_str(yaml).context("Failed to parse YAML")?;
    let doc = docs
        .first()
        .ok_or_else(|| anyhow::anyhow!("Empty YAML config"))?;

    // features (default-on if omitted)
    let features = FeaturesConfig {
        firewall: doc["features"]["firewall"].as_bool().unwrap_or(true),
        process: doc["features"]["process"].as_bool().unwrap_or(true),
        auth: doc["features"]["auth"].as_bool().unwrap_or(true),
        audit: doc["features"]["audit"].as_bool().unwrap_or(true),
        yara: doc["features"]["yara"].as_bool().unwrap_or(true),
        scan: doc["features"]["scan"].as_bool().unwrap_or(true),
        networking: doc["features"]["networking"].as_bool().unwrap_or(false),
        tty: doc["features"]["tty"].as_bool().unwrap_or(true),
        ingestor: doc["features"]["ingestor"].as_bool().unwrap_or(false),
        file_integrity: doc["features"]["file_integrity"].as_bool().unwrap_or(false),
    };

    // logging (optional, all fields have sane defaults) - parsed early so
    // log_dir is available for the feature sections that derive log paths.
    let logging = {
        let default = LoggingConfig::default();

        let log_dir = doc["logging"]["log_dir"]
            .as_str()
            .map(PathBuf::from)
            .unwrap_or_else(|| default.log_dir.clone());

        let rollover_size_bytes = doc["logging"]["rollover_size_mb"]
            .as_i64()
            .map(|mb| mb as u64 * 1024 * 1024)
            .unwrap_or(default.rollover_size_bytes);

        let rollover_count = doc["logging"]["rollover_count"]
            .as_i64()
            .map(|v| v as u32)
            .unwrap_or(default.rollover_count);

        if !log_dir.exists() {
            if let Err(e) = fs::create_dir_all(&log_dir) {
                error!("Failed to create log dir {:?}: {}", log_dir, e);
            }

            if let Err(e) = fs::set_permissions(&log_dir, fs::Permissions::from_mode(0o700)) {
                error!("Failed to chmod 0700 on log dir {:?}: {}", log_dir, e);
            }
        }

        LoggingConfig {
            log_dir,
            rollover_size_bytes,
            rollover_count,
        }
    };

    let log_dir = &logging.log_dir;

    // yara
    let yara = if features.yara {
        let rules_dir = doc["yara"]["rules_dir"].as_str().map(PathBuf::from);

        let max_scan_bytes_per_rule = doc["yara"]["max_scan_bytes_per_rule"]
            .as_i64()
            .map(|v| v as u64);

        let poll_interval_secs = doc["yara"]["poll_interval_secs"].as_i64().map(|v| v as u64);

        let full_scan_interval_secs = doc["yara"]["full_scan_interval_secs"]
            .as_i64()
            .map(|v| v as u64);

        let disabled_rules: HashSet<String> = doc["yara"]["disabled_rules"]
            .as_vec()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        let disable_bundled_rules = doc["yara"]["disable_bundled_rules"]
            .as_bool()
            .unwrap_or(false);

        let actions = {
            let raw: Vec<String> = doc["yara"]["actions"]
                .as_vec()
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(|s| s.to_lowercase()))
                        .collect()
                })
                .unwrap_or_else(|| ["kill".to_string()].into());

            let mut kill = false;
            let mut move_sample = false;
            for item in &raw {
                match item.as_str() {
                    "kill" => kill = true,
                    "move" => move_sample = true,
                    other => {
                        warn!("Unknown yara.actions entry '{}', ignoring", other);
                    }
                }
            }

            YaraActions {
                alert: true, // always alert
                kill,
                move_sample,
            }
        };

        let samples_dir = doc["yara"]["samples_dir"]
            .as_str()
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/var/lib/rb2/samples"));

        let fanotify_enabled = doc["yara"]["fanotify_enabled"].as_bool().unwrap_or(true);

        Some(YaraConfig {
            rules_dir,
            log_file: log_dir.join("yara"),
            max_scan_bytes_per_rule,
            poll_interval_secs,
            full_scan_interval_secs,
            disabled_rules,
            disable_bundled_rules,
            actions,
            samples_dir,
            fanotify_enabled,
        })
    } else {
        None
    };

    // firewall
    let firewall = if features.firewall {
        let binary_whitelist: HashSet<PathBuf> = doc["firewall"]["binary_whitelist"]
            .as_vec()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(PathBuf::from))
                    .collect::<Vec<PathBuf>>()
            })
            .unwrap_or_default()
            .into_iter()
            .collect();

        let enforcing = doc["firewall"]["enforcing"].as_bool().unwrap_or(false);

        let mut producer = match doc["firewall"]["producer"].as_str().unwrap_or("ebpf") {
            "nfq" => ProducerConfig::Nfq,
            "auditd" => ProducerConfig::Auditd,
            "ebpf" => ProducerConfig::Ebpf,
            "bsm" => ProducerConfig::Bsm,
            other => {
                warn!(
                    "Unknown firewall producer type '{}', falling back to nfq",
                    other
                );
                ProducerConfig::Nfq
            }
        };

        let mut handler = match doc["firewall"]["handler"].as_str().unwrap_or("kill") {
            "nfq" => HandlerConfig::Nfq,
            "kill" => HandlerConfig::Kill,
            other => {
                warn!(
                    "Unknown firewall handler type '{}', falling back to kill",
                    other
                );
                HandlerConfig::Nfq
            }
        };

        if (producer == ProducerConfig::Nfq) && (handler != HandlerConfig::Nfq) {
            warn!(
                "Firewall producer is of type nfq, but handler {:?} is not. Making handler also nfq",
                handler
            );
            handler = HandlerConfig::Nfq;
        } else if (producer != ProducerConfig::Nfq) && (handler == HandlerConfig::Nfq) {
            warn!(
                "Firewall handler is of type nfq, but producer {:?} is not. Making producer also nfq",
                producer
            );
            producer = ProducerConfig::Nfq;
        }

        debug!(
            "Firewall producer {:?} Firewall handler {:?}",
            producer, handler
        );

        Some(FirewallConfig {
            binary_whitelist,
            log_file: log_dir.join("firewall"),
            enforcing,
            producer,
            handler,
        })
    } else {
        None
    };

    // process
    let process = if features.process {
        let collector = match doc["process"]["collector"].as_str().unwrap_or("ebpf") {
            "auditd" => ProcessCollector::Auditd,
            "ebpf" => ProcessCollector::Ebpf,
            other => {
                warn!(
                    "Unknown process collector '{}', falling back to ebpf",
                    other
                );
                ProcessCollector::Ebpf
            }
        };

        let rhai_enabled = doc["process"]["rhai_enabled"].as_bool().unwrap_or(true);

        let rhai_rules_dir = doc["process"]["rhai_rules_dir"].as_str().map(PathBuf::from);

        let disabled_rules: Vec<String> = doc["process"]["disabled_rules"]
            .as_vec()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        let ml_enabled = doc["process"]["ml_enabled"].as_bool().unwrap_or(true);
        let ml_debug = doc["process"]["ml_debug"].as_bool().unwrap_or(false);

        Some(ProcessConfig {
            collector,
            rhai_enabled,
            rhai_rules_dir,
            log_file: log_dir.join("process"),
            alert_log_file: log_dir.join("alert"),
            disabled_rules,
            ml_enabled,
            ml_debug,
        })
    } else {
        None
    };

    // auth
    let auth = if features.auth {
        Some(AuthConfig {
            log_file: log_dir.join("auth"),
            libpam_path: doc["auth"]["libpam_path"].as_str().map(PathBuf::from),
        })
    } else {
        None
    };

    // audit (BSM audit events: setuid, ptrace, modload, sudo, etc.)
    let audit = if features.audit {
        Some(AuditConfig {
            log_file: log_dir.join("audit"),
        })
    } else {
        None
    };

    // scan
    let scan = if features.scan {
        let poll_interval_secs = doc["scan"]["poll_interval_secs"].as_i64().map(|v| v as u64);
        Some(ScanConfig {
            log_file: log_dir.join("scan"),
            poll_interval_secs,
        })
    } else {
        None
    };

    let networking = if features.networking {
        let interfaces = doc["networking"]["interfaces"]
            .as_vec()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str())
                    .map(str::trim)
                    .filter(|name| !name.is_empty())
                    .map(String::from)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        let dns_enabled = doc["networking"]["dns_enabled"].as_bool().unwrap_or(true);
        let http_enabled = doc["networking"]["http_enabled"].as_bool().unwrap_or(true);
        let https_enabled = doc["networking"]["https_enabled"].as_bool().unwrap_or(true);
        let http_capture_inbound = doc["networking"]["http_capture_inbound"]
            .as_bool()
            .unwrap_or(false);
        let snaplen_bytes = doc["networking"]["snaplen_bytes"]
            .as_i64()
            .filter(|v| *v > 0)
            .map(|v| (v as u64).min(65_535))
            .unwrap_or(2_048);

        Some(NetworkingConfig {
            interfaces,
            dns_enabled,
            http_enabled,
            https_enabled,
            http_capture_inbound,
            snaplen_bytes,
            log_file: log_dir.join("network"),
        })
    } else {
        None
    };

    // tty
    let tty = if features.tty {
        let encrypt = doc["tty"]["encrypt"].as_bool().unwrap_or(true);

        let session_recognition_idle_secs = doc["tty"]["session_recognition_idle_secs"]
            .as_i64()
            .map(|v| v as u64)
            .unwrap_or(300);

        let spool_dir = doc["tty"]["spool_dir"]
            .as_str()
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/var/lib/rb2/tty"));

        let flush_interval_secs = doc["tty"]["flush_interval_secs"]
            .as_i64()
            .map(|v| v as u64)
            .unwrap_or(30);

        let forward_to_s3 = doc["tty"]["forward_to_s3"].as_bool().unwrap_or(false);
        let s3_forward_interval_secs = doc["tty"]["s3_forward_interval_secs"]
            .as_i64()
            .map(|v| v as u64)
            .unwrap_or(60);

        let authorized_keys_path = doc["tty"]["authorized_keys"]
            .as_str()
            .map(|s| {
                if s.starts_with("~/") {
                    env::var("HOME")
                        .ok()
                        .map(|home| PathBuf::from(home).join(&s[2..]))
                        .unwrap_or_else(|| PathBuf::from(s))
                } else {
                    PathBuf::from(s)
                }
            })
            .or_else(default_authorized_keys_path);

        if encrypt {
            let pubkey = authorized_keys_path
                .as_ref()
                .and_then(|path| parse_last_ed25519_key(path));

            match &pubkey {
                Some(key) => {
                    debug!(
                        "TTY encryption enabled with ed25519 key from {:?}",
                        authorized_keys_path
                    );
                    Some(TTYConfig {
                        encrypt: true,
                        authorized_keys_path,
                        pubkey: Some(key.clone()),
                        session_recognition_idle_secs,
                        spool_dir,
                        flush_interval_secs,
                        forward_to_s3,
                        s3_forward_interval_secs,
                    })
                }
                None => {
                    error!(
                        "TTY encryption is enabled but no valid ed25519 key found in {:?}. \
                         TTY session recording has been disabled. \
                         Either add an ssh-ed25519 key to your authorized_keys file, \
                         or set tty.encrypt: false in the config.",
                        authorized_keys_path
                    );
                    None
                }
            }
        } else {
            debug!("TTY encryption disabled, session recordings will not be encrypted");
            Some(TTYConfig {
                encrypt: false,
                authorized_keys_path,
                pubkey: None,
                session_recognition_idle_secs,
                spool_dir,
                flush_interval_secs,
                forward_to_s3,
                s3_forward_interval_secs,
            })
        }
    } else {
        None
    };

    // ingestor
    let ingestor = if features.ingestor {
        let flush_interval_secs = doc["ingestor"]["flush_interval_secs"]
            .as_i64()
            .map(|v| v as u64)
            .unwrap_or(10);

        let memory_trigger_size_mb = doc["ingestor"]["memory_trigger_size_mb"]
            .as_i64()
            .map(|v| v as u64)
            .unwrap_or(5);

        let stats_interval_secs = doc["ingestor"]["stats_interval_secs"]
            .as_i64()
            .map(|v| v as u64)
            .unwrap_or(120);

        let forwarders = parse_ingestor_forwarders(doc)?;

        Some(IngestorConfig {
            flush_interval_secs,
            memory_trigger_size_mb,
            stats_interval_secs,
            forwarders,
        })
    } else {
        None
    };

    // object_storage (optional - needed when TTY S3 forwarding is enabled)
    let needs_object_storage = tty.as_ref().is_some_and(|t| t.forward_to_s3);
    let object_storage = if needs_object_storage && !doc["object_storage"]["endpoint"].is_badvalue()
    {
        let os_doc = &doc["object_storage"];
        Some(ObjectStorageConfig {
            endpoint: os_doc["endpoint"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("object_storage.endpoint missing"))?
                .to_string(),
            bucket_tty: os_doc["bucket_tty"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("object_storage.bucket_tty missing"))?
                .to_string(),
            bucket_samples: os_doc["bucket_samples"].as_str().map(String::from),
            region: os_doc["region"].as_str().unwrap_or("us-east-1").to_string(),
            access_key: os_doc["access_key"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("object_storage.access_key missing"))?
                .to_string(),
            secret_key: os_doc["secret_key"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("object_storage.secret_key missing"))?
                .to_string(),
            path_style: os_doc["path_style"].as_bool().unwrap_or(true),
        })
    } else {
        None
    };

    let file_integrity = if features.file_integrity {
        if let Some(log_paths) = doc["file_integrity"]["log_paths"].as_vec() {
            let log_paths = log_paths
                .iter()
                .filter_map(|x| x.as_str())
                .map(PathBuf::from)
                .collect();

            Some(FileIntegrityConfig {
                log_paths,
                log_file: log_dir.join("fim"),
            })
        } else {
            warn!(
                "features.file_integrity is enabled but file_integrity.log_paths is missing or invalid, fim will not start"
            );
            None
        }
    } else {
        None
    };

    Ok(AppConfig {
        yara,
        firewall,
        process,
        auth,
        audit,
        scan,
        networking,
        tty,
        ingestor,
        object_storage,
        health_log_file: logging.log_dir.join("health"),
        logging,
        file_integrity,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_minimal() {
        let yaml = r#"
features: { firewall: true, process: true, yara: true }
yara: { rules_dir: "/tmp/rules" }
firewall: { binary_whitelist: ["/bin/ls"] }
process: { rhai_rules_dir: "/tmp/rhai" }
"#;
        let cfg = parse_config_from_str(yaml).expect("parse ok");
        assert!(cfg.yara.is_some());
        assert!(cfg.firewall.is_some());
        assert!(cfg.process.is_some());
        assert!(cfg.auth.is_some());
        assert!(cfg.networking.is_none());
        assert!(cfg.ingestor.is_none());
    }

    #[test]
    fn firewall_auditd_producer_is_parsed() {
        let yaml = r#"
features: { firewall: true, process: false, yara: false }
firewall:
  producer: auditd
  handler: kill
"#;

        let cfg = parse_config_from_str(yaml).expect("parse ok");
        let firewall = cfg.firewall.expect("firewall enabled");
        assert_eq!(firewall.producer, ProducerConfig::Auditd);
        assert_eq!(firewall.handler, HandlerConfig::Kill);
    }

    #[test]
    fn firewall_bsm_producer_is_parsed() {
        let yaml = r#"
features: { firewall: true, process: false, yara: false }
firewall:
  producer: bsm
  handler: kill
"#;

        let cfg = parse_config_from_str(yaml).expect("parse ok");
        let firewall = cfg.firewall.expect("firewall enabled");
        assert_eq!(firewall.producer, ProducerConfig::Bsm);
        assert_eq!(firewall.handler, HandlerConfig::Kill);
    }

    #[test]
    fn disabled_features_are_none() {
        let yaml = r#"
features: { firewall: false, process: false, auth: false, audit: false, yara: false, ingestor: false }
"#;
        let cfg = parse_config_from_str(yaml).expect("parse ok");
        assert!(cfg.yara.is_none());
        assert!(cfg.firewall.is_none());
        assert!(cfg.process.is_none());
        assert!(cfg.auth.is_none());
        assert!(cfg.audit.is_none());
        assert!(cfg.networking.is_none());
        assert!(cfg.ingestor.is_none());
    }

    #[test]
    fn yara_rules_dir_optional() {
        let yaml = r#"
features: { firewall: false, process: false, yara: true }
yara: {}
"#;
        let cfg = parse_config_from_str(yaml).expect("parse ok");
        assert!(cfg.yara.is_some());
        assert!(cfg.yara.unwrap().rules_dir.is_none());
    }

    #[test]
    fn parse_full_user_config() {
        let yaml = r#"
features:
  firewall: true
  yara: true
  process: true
  auth: true
  tty: true
  scan: true
  networking: true
  file_integrity: false
  ingestor: true

firewall:
  enforcing: false
  producer: ebpf
  handler: kill
  binary_whitelist:
    - /snap/amazon-ssm-agent/12322/ssm-agent-worker
    - /usr/bin/docker-proxy
    - /usr/lib/systemd/systemd
    - /usr/lib/systemd/systemd-networkd
    - /usr/lib/systemd/systemd-resolved
    - /usr/sbin/chronyd
    - /usr/sbin/sshd
    - /usr/bin/sudo
    - /home/ubuntu/rb2

yara:
  rules_dir: # /var/lib/rb2/yara # optional for extra rules
  disable_bundled_rules: false
  disabled_rules: # optional
  #   - Multi_EICAR
  actions:
    - kill
    # - move
  samples_dir: /var/lib/rb2/samples

tty:
  encrypt: false
  authorized_keys: /root/.ssh/authorized_keys
  session_recognition_idle_secs: 300
  spool_dir: /var/lib/rb2/tty
  flush_interval_secs: 30
  forward_to_s3: true
  s3_forward_interval_secs: 60

ingestor:
  flush_interval_secs: 10
  memory_trigger_size_mb: 5
  forwarders:
    - name: openobserve-default
      type: openobserve
      openobserve:
        url: http://openobserve.example.com:5080
        org: default
        stream_prefix: rb2-logs
        username: root@example.com
        password: Complexpass#123
    - name: splunk-primary
      type: splunk
      splunk:
        url: https://splunk.example.com:8088
        token: splunk-hec-token
        index: security
        source: rb2
        sourcetype_prefix: rb2
        gzip_enabled: true
        tls_skip_verify: false

object_storage:
   endpoint: "http://127.0.0.1:9000"
   bucket_tty: "rb2-tty"
   bucket_samples: "rb2-samples"
   region: "us-east-1"
   access_key: "fakeaccesskey"
   secret_key: "fakesecretkey"
   path_style: true

logging:
  log_dir: /var/log/rb2
  rollover_size_mb: 10
  rollover_count: 5

networking:
  interfaces:
    - eth0
  dns_enabled: true
  http_enabled: true
  https_enabled: true
  http_capture_inbound: false
  snaplen_bytes: 4096

auth:
  libpam_path: /lib/x86_64-linux-gnu/libpam.so.0

process:
  rhai_enabled: true
  disabled_rules:
"#;
        let cfg = parse_config_from_str(yaml).expect("parse ok");
        assert!(cfg.yara.is_some());
        let yara = cfg.yara.unwrap();
        assert!(yara.actions.alert);
        assert!(yara.actions.kill);
        assert!(!yara.actions.move_sample);
        assert!(cfg.object_storage.is_some());
        let os = cfg.object_storage.unwrap();
        assert_eq!(os.bucket_samples.as_deref(), Some("rb2-samples"));
        let ingestor = cfg.ingestor.expect("ingestor should be parsed");
        assert_eq!(ingestor.forwarders.len(), 2);
        assert_eq!(ingestor.forwarders[0].name, "openobserve-default");
        assert_eq!(ingestor.forwarders[1].forwarder_type, "splunk");
        assert_eq!(
            cfg.tty
                .as_ref()
                .map(|tty| tty.session_recognition_idle_secs),
            Some(300)
        );
        assert_eq!(
            cfg.tty.as_ref().map(|tty| tty.flush_interval_secs),
            Some(30)
        );
        assert_eq!(
            ingestor.forwarders[1]
                .splunk
                .as_ref()
                .and_then(|cfg| cfg.index.as_deref()),
            Some("security")
        );
        assert_eq!(
            cfg.auth
                .as_ref()
                .and_then(|auth| auth.libpam_path.as_deref()),
            Some(Path::new("/lib/x86_64-linux-gnu/libpam.so.0"))
        );
        let networking = cfg.networking.expect("networking enabled");
        assert_eq!(networking.interfaces, vec!["eth0".to_string()]);
        assert_eq!(networking.snaplen_bytes, 4096);
        assert!(networking.dns_enabled);
        assert!(networking.http_enabled);
        assert!(networking.https_enabled);
        assert!(!networking.http_capture_inbound);
        assert_eq!(networking.log_file, cfg.logging.log_dir.join("network"));
    }

    #[test]
    fn duplicate_forwarder_names_are_rejected() {
        let yaml = r#"
features:
  firewall: false
  process: false
  auth: false
  yara: false
  scan: false
  networking: false
  tty: false
  ingestor: true

ingestor:
  forwarders:
    - name: duplicate
      type: openobserve
      openobserve:
        url: http://localhost:5080
        org: default
        stream_prefix: rb2-logs
        username: root@example.com
        password: secret
    - name: duplicate
      type: splunk
      splunk:
        url: http://localhost:8088
        token: token
"#;

        let err = parse_config_from_str(yaml).expect_err("duplicate names should fail");
        assert!(
            err.to_string()
                .contains("Duplicate ingestor forwarder name")
        );
    }

    #[test]
    fn ingestor_defaults_are_applied() {
        let yaml = r#"
features:
  firewall: false
  process: false
  auth: false
  yara: false
  scan: false
  networking: false
  tty: false
  ingestor: true

ingestor:
  forwarders:
    - name: openobserve-default
      type: openobserve
      openobserve:
        url: http://localhost:5080
        org: default
        stream_prefix: rb2-logs
        username: root@example.com
        password: secret
"#;

        let cfg = parse_config_from_str(yaml).expect("parse ok");
        let ingestor = cfg.ingestor.expect("ingestor enabled");
        assert_eq!(ingestor.flush_interval_secs, 10);
        assert_eq!(ingestor.memory_trigger_size_mb, 5);
        assert_eq!(ingestor.stats_interval_secs, 120);
    }

    #[test]
    fn ingestor_explicit_values_are_parsed() {
        let yaml = r#"
features:
  firewall: false
  process: false
  yara: false
  scan: false
  tty: false
  ingestor: true

ingestor:
  flush_interval_secs: 7
  memory_trigger_size_mb: 42
  stats_interval_secs: 9
  forwarders:
    - name: splunk-primary
      type: splunk
      splunk:
        url: http://localhost:8088
        token: token
"#;

        let cfg = parse_config_from_str(yaml).expect("parse ok");
        let ingestor = cfg.ingestor.expect("ingestor enabled");
        assert_eq!(ingestor.flush_interval_secs, 7);
        assert_eq!(ingestor.memory_trigger_size_mb, 42);
        assert_eq!(ingestor.stats_interval_secs, 9);
    }

    #[test]
    fn tty_session_idle_timeout_defaults_to_five_minutes() {
        let yaml = r#"
features:
  firewall: false
  process: false
  auth: false
  yara: false
  scan: false
  networking: false
  tty: true
  ingestor: false

tty:
  encrypt: false
"#;

        let cfg = parse_config_from_str(yaml).expect("parse ok");
        let tty = cfg.tty.expect("tty enabled");
        assert_eq!(tty.session_recognition_idle_secs, 300);
    }

    #[test]
    fn tty_session_idle_timeout_can_be_overridden() {
        let yaml = r#"
features:
  firewall: false
  process: false
  auth: false
  yara: false
  scan: false
  networking: false
  tty: true
  ingestor: false

tty:
  encrypt: false
  session_recognition_idle_secs: 123
"#;

        let cfg = parse_config_from_str(yaml).expect("parse ok");
        let tty = cfg.tty.expect("tty enabled");
        assert_eq!(tty.session_recognition_idle_secs, 123);
    }

    #[test]
    fn file_integrity_log_paths_parse_when_enabled() {
        let yaml = r#"
features: { firewall: false, process: false, yara: false, file_integrity: true }
file_integrity:
  log_paths:
    - /var/log/auth.log
    - /var/log/syslog
"#;

        let cfg = parse_config_from_str(yaml).expect("parse ok");
        let file_integrity = cfg
            .file_integrity
            .as_ref()
            .expect("file_integrity config present");

        assert_eq!(file_integrity.log_paths.len(), 2);
        assert_eq!(
            file_integrity.log_paths[0],
            PathBuf::from("/var/log/auth.log")
        );
        assert_eq!(
            file_integrity.log_paths[1],
            PathBuf::from("/var/log/syslog")
        );
        assert_eq!(file_integrity.log_file, cfg.logging.log_dir.join("fim"));
    }

    #[test]
    fn file_integrity_missing_log_paths_is_non_fatal() {
        let yaml = r#"
features: { firewall: false, process: false, yara: false, file_integrity: true }
file_integrity: {}
"#;

        let cfg = parse_config_from_str(yaml).expect("parse ok");

        assert!(cfg.file_integrity.is_none());
    }

    #[test]
    fn file_integrity_invalid_log_paths_is_non_fatal() {
        let yaml = r#"
features: { firewall: false, process: false, yara: false, file_integrity: true }
file_integrity:
  log_paths: invalid
"#;

        let cfg = parse_config_from_str(yaml).expect("parse ok");

        assert!(cfg.file_integrity.is_none());
    }

    #[test]
    fn auth_feature_builds_default_log_path() {
        let yaml = r#"
features:
  firewall: false
  process: false
  auth: true
  yara: false
  scan: false
  networking: false
  tty: false
  ingestor: false

logging:
  log_dir: /tmp/rb2-auth-tests
"#;
        let cfg = parse_config_from_str(yaml).expect("parse ok");
        let auth = cfg.auth.expect("auth enabled");
        assert_eq!(auth.log_file, PathBuf::from("/tmp/rb2-auth-tests/auth"));
        assert!(auth.libpam_path.is_none());
    }

    #[test]
    fn auth_libpam_path_is_parsed() {
        let yaml = r#"
features:
  firewall: false
  process: false
  auth: true
  yara: false
  scan: false
  networking: false
  tty: false
  ingestor: false

auth:
  libpam_path: /custom/libpam.so.0
"#;
        let cfg = parse_config_from_str(yaml).expect("parse ok");
        assert_eq!(
            cfg.auth
                .as_ref()
                .and_then(|auth| auth.libpam_path.as_deref()),
            Some(Path::new("/custom/libpam.so.0"))
        );
    }

    #[test]
    fn networking_defaults_are_applied_when_enabled() {
        let yaml = r#"
features:
  firewall: false
  process: false
  auth: false
  yara: false
  scan: false
  networking: true
  tty: false
  ingestor: false
"#;

        let cfg = parse_config_from_str(yaml).expect("parse ok");
        let networking = cfg.networking.expect("networking enabled");
        assert!(networking.interfaces.is_empty());
        assert!(networking.dns_enabled);
        assert!(networking.http_enabled);
        assert!(networking.https_enabled);
        assert!(!networking.http_capture_inbound);
        assert_eq!(networking.snaplen_bytes, 2_048);
    }

    #[test]
    fn networking_explicit_values_are_parsed() {
        let yaml = r#"
features:
  firewall: false
  process: false
  auth: false
  yara: false
  scan: false
  networking: true
  tty: false
  ingestor: false

networking:
  interfaces:
    - eth0
    - wlan0
  dns_enabled: false
  http_enabled: true
  https_enabled: false
  http_capture_inbound: true
  snaplen_bytes: 999999
"#;

        let cfg = parse_config_from_str(yaml).expect("parse ok");
        let networking = cfg.networking.expect("networking enabled");
        assert_eq!(networking.interfaces, vec!["eth0", "wlan0"]);
        assert!(!networking.dns_enabled);
        assert!(networking.http_enabled);
        assert!(!networking.https_enabled);
        assert!(networking.http_capture_inbound);
        assert_eq!(networking.snaplen_bytes, 65_535);
    }
}
