use log::LevelFilter;
use log::warn;
use log4rs::{
    Handle,
    append::Append,
    append::console::{ConsoleAppender, Target},
    append::rolling_file::{
        RollingFileAppender,
        policy::compound::{
            CompoundPolicy, roll::fixed_window::FixedWindowRoller, trigger::size::SizeTrigger,
        },
    },
    config::{Appender, Config, Logger, Root, runtime::ConfigBuilder},
    encode::pattern::PatternEncoder,
    filter::threshold::ThresholdFilter,
};
use std::env;
use std::path::Path;
use std::sync::OnceLock;

use crate::ingest::queue::{QueueAppender, global_queue};

/// Paths and settings for domain log file appenders.
#[derive(Default)]
pub struct FileAppenderPaths<'a> {
    pub firewall: Option<&'a Path>,
    pub process: Option<&'a Path>,
    pub ace: Option<&'a Path>,
    pub auth: Option<&'a Path>,
    pub network: Option<&'a Path>,
    pub audit: Option<&'a Path>,
    pub yara: Option<&'a Path>,
    pub scan: Option<&'a Path>,
    pub fim: Option<&'a Path>,
    pub health: Option<&'a Path>,
    pub rollover_size_bytes: u64,
    pub rollover_count: u32,
    pub queue_ingest_enabled: bool,
}

static HANDLE: OnceLock<Handle> = OnceLock::new();

const CONSOLE_APPENDER: &str = "console";
const CONSOLE_PATTERN: &str = "{d(%Y-%m-%d %H:%M:%S)} {h({l:5.5})} {t} - {m}{n}";
const JOURNAL_CONSOLE_PATTERN: &str = "{h({l:5.5})} {t} - {m}{n}";
const FILE_PATTERN: &str = "{m}{n}";

const ROOT_LEVEL: LevelFilter = LevelFilter::Trace;
const DEFAULT_LOGGER: (&str, LevelFilter) = ("rb2_userspace", LevelFilter::Trace);

pub(crate) fn parse_level_str(value: &str) -> Option<LevelFilter> {
    match value.trim().to_ascii_lowercase().as_str() {
        "off" => Some(LevelFilter::Off),
        "error" => Some(LevelFilter::Error),
        "warn" => Some(LevelFilter::Warn),
        "info" => Some(LevelFilter::Info),
        "debug" => Some(LevelFilter::Debug),
        "trace" => Some(LevelFilter::Trace),
        _ => None,
    }
}

pub(crate) fn console_level_from_env() -> LevelFilter {
    env::var("LOG")
        .ok()
        .as_deref()
        .and_then(parse_level_str)
        .unwrap_or(LevelFilter::Info)
}

fn build_console() -> ConsoleAppender {
    let pattern = if in_journald() {
        JOURNAL_CONSOLE_PATTERN
    } else {
        CONSOLE_PATTERN
    };

    ConsoleAppender::builder()
        .target(Target::Stderr)
        .encoder(Box::new(PatternEncoder::new(pattern)))
        .build()
}

fn in_journald() -> bool {
    env::var_os("JOURNAL_STREAM").is_some()
}

fn build_rolling_file(
    path: &Path,
    rollover_size_bytes: u64,
    rollover_count: u32,
) -> Option<RollingFileAppender> {
    // Keep numbering stable and compress archives.
    let archive_pattern = format!("{}.{{}}.gz", path.display());

    let roller = FixedWindowRoller::builder()
        .build(&archive_pattern, rollover_count)
        .ok()?;

    let trigger = SizeTrigger::new(rollover_size_bytes);
    let policy = CompoundPolicy::new(Box::new(trigger), Box::new(roller));

    RollingFileAppender::builder()
        .encoder(Box::new(PatternEncoder::new(FILE_PATTERN)))
        .build(path, Box::new(policy))
        .ok()
}

fn base_builder(queue_ingest_enabled: bool) -> ConfigBuilder {
    let console_level = console_level_from_env();

    let builder = Config::builder().appender(
        Appender::builder()
            .filter(Box::new(ThresholdFilter::new(console_level)))
            .build(CONSOLE_APPENDER, Box::new(build_console())),
    );

    let builder = if queue_ingest_enabled {
        builder.appender(Appender::builder().build(
            crate::ingest::queue::IngestQueue::appender_name(),
            build_queue_appender(),
        ))
    } else {
        builder
    };

    builder.logger(Logger::builder().build(DEFAULT_LOGGER.0, DEFAULT_LOGGER.1))
}

fn build_queue_appender() -> Box<dyn Append> {
    Box::new(QueueAppender::new(global_queue().clone()))
}

fn build(builder: ConfigBuilder) -> Config {
    builder
        .build(Root::builder().appender(CONSOLE_APPENDER).build(ROOT_LEVEL))
        .expect("valid log4rs config")
}

fn add_file_logger(
    mut builder: ConfigBuilder,
    appender_name: &str,
    logger_name: &str,
    path: &Path,
    rollover_size_bytes: u64,
    rollover_count: u32,
    queue_ingest_enabled: bool,
) -> ConfigBuilder {
    let Some(appender) = build_rolling_file(path, rollover_size_bytes, rollover_count) else {
        warn!("unable to build rolling file appender properly");
        return builder;
    };

    builder = builder.appender(Appender::builder().build(appender_name, Box::new(appender)));

    let logger = if queue_ingest_enabled {
        Logger::builder()
            .appender(appender_name)
            .appender(crate::ingest::queue::IngestQueue::appender_name())
            .additive(false)
            .build(logger_name, LevelFilter::Info)
    } else {
        Logger::builder()
            .appender(appender_name)
            .additive(false)
            .build(logger_name, LevelFilter::Info)
    };

    builder.logger(logger)
}

pub fn init() {
    let config = build(base_builder(false));
    let handle = log4rs::init_config(config).expect("log4rs init");
    let _ = HANDLE.set(handle);
}

/// Add rolling-file appenders for each domain log.
/// Call after YAML config is parsed so paths are known.
///
/// rollover_count = number of archived copies to keep per appender.
pub fn add_file_appenders(paths: &FileAppenderPaths<'_>) {
    let Some(handle) = HANDLE.get() else {
        // init() was never called; nothing to update.
        return;
    };

    let mut builder = base_builder(paths.queue_ingest_enabled);
    let (size, count) = (paths.rollover_size_bytes, paths.rollover_count);

    if let Some(path) = paths.firewall {
        builder = add_file_logger(
            builder,
            "firewall_file",
            "rb2_firewall",
            path,
            size,
            count,
            paths.queue_ingest_enabled,
        );
    }
    if let Some(path) = paths.process {
        builder = add_file_logger(
            builder,
            "process_file",
            "rb2_process",
            path,
            size,
            count,
            paths.queue_ingest_enabled,
        );
    }
    if let Some(path) = paths.ace {
        builder = add_file_logger(
            builder,
            "ace_file",
            "rb2_ace",
            path,
            size,
            count,
            paths.queue_ingest_enabled,
        );
    }
    if let Some(path) = paths.auth {
        builder = add_file_logger(
            builder,
            "auth_file",
            "rb2_auth",
            path,
            size,
            count,
            paths.queue_ingest_enabled,
        );
    }
    if let Some(path) = paths.network {
        builder = add_file_logger(
            builder,
            "network_file",
            "rb2_network",
            path,
            size,
            count,
            paths.queue_ingest_enabled,
        );
    }
    if let Some(path) = paths.audit {
        builder = add_file_logger(
            builder,
            "audit_file",
            "rb2_audit",
            path,
            size,
            count,
            paths.queue_ingest_enabled,
        );
    }
    if let Some(path) = paths.yara {
        builder = add_file_logger(
            builder,
            "yara_file",
            "rb2_yara",
            path,
            size,
            count,
            paths.queue_ingest_enabled,
        );
    }
    if let Some(path) = paths.scan {
        builder = add_file_logger(
            builder,
            "scan_file",
            "rb2_scan",
            path,
            size,
            count,
            paths.queue_ingest_enabled,
        );
    }
    if let Some(path) = paths.fim {
        builder = add_file_logger(
            builder,
            "fim_file",
            "rb2_fim",
            path,
            size,
            count,
            paths.queue_ingest_enabled,
        );
    }
    if let Some(path) = paths.health {
        builder = add_file_logger(
            builder,
            "health_file",
            "rb2_health",
            path,
            size,
            count,
            paths.queue_ingest_enabled,
        );
    }

    handle.set_config(build(builder));
}

#[cfg(test)]
mod tests {
    use super::{console_level_from_env, parse_level_str};
    use log::LevelFilter;
    use std::env;
    use std::sync::{Mutex, OnceLock};

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    #[test]
    fn parses_supported_log_levels() {
        assert_eq!(parse_level_str("off"), Some(LevelFilter::Off));
        assert_eq!(parse_level_str("error"), Some(LevelFilter::Error));
        assert_eq!(parse_level_str("warn"), Some(LevelFilter::Warn));
        assert_eq!(parse_level_str("info"), Some(LevelFilter::Info));
        assert_eq!(parse_level_str("debug"), Some(LevelFilter::Debug));
        assert_eq!(parse_level_str("trace"), Some(LevelFilter::Trace));
    }

    #[test]
    fn parser_is_case_and_whitespace_insensitive() {
        assert_eq!(parse_level_str(" DeBuG\n"), Some(LevelFilter::Debug));
    }

    #[test]
    fn parser_rejects_invalid_levels() {
        assert_eq!(parse_level_str("verbose"), None);
    }

    #[test]
    fn env_parser_defaults_to_info_when_missing() {
        let _guard = env_lock().lock().expect("env lock poisoned");
        unsafe { env::remove_var("LOG") };

        assert_eq!(console_level_from_env(), LevelFilter::Info);
    }

    #[test]
    fn env_parser_reads_log_level() {
        let _guard = env_lock().lock().expect("env lock poisoned");
        unsafe { env::set_var("LOG", " trace ") };

        assert_eq!(console_level_from_env(), LevelFilter::Trace);

        unsafe { env::remove_var("LOG") };
    }

    #[test]
    fn env_parser_defaults_to_info_when_invalid() {
        let _guard = env_lock().lock().expect("env lock poisoned");
        unsafe { env::set_var("LOG", "verbose") };

        assert_eq!(console_level_from_env(), LevelFilter::Info);

        unsafe { env::remove_var("LOG") };
    }
}
