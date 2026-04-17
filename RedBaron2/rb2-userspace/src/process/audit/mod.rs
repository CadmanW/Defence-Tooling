mod normalize;
mod source;

use crate::config::yaml::{AppConfig, ProcessCollector, ProducerConfig};
use log::error;
use rb2_auditd::AuditEventFlags;

pub use source::{is_external_auditd_running, run, run_with_stream};

pub fn derive_audit_event_flags(cfg: &AppConfig) -> AuditEventFlags {
    let mut flags = AuditEventFlags::NONE;

    if cfg
        .process
        .as_ref()
        .is_some_and(|process_cfg| process_cfg.collector == ProcessCollector::Auditd)
    {
        flags |= AuditEventFlags::EXEC;
    }

    if cfg
        .firewall
        .as_ref()
        .is_some_and(|firewall_cfg| firewall_cfg.producer == ProducerConfig::Auditd)
    {
        flags |= AuditEventFlags::NETWORK;
    }

    flags
}

pub fn log_audit_feature_degradation(
    cfg: &AppConfig,
    audit_daemon_started: bool,
    audit_unavailable_reason: Option<&str>,
) {
    if audit_daemon_started {
        return;
    }

    let mut disabled_features = Vec::new();
    if cfg
        .process
        .as_ref()
        .is_some_and(|process_cfg| process_cfg.collector == ProcessCollector::Auditd)
    {
        disabled_features.push("process collector");
    }
    if cfg
        .firewall
        .as_ref()
        .is_some_and(|firewall_cfg| firewall_cfg.producer == ProducerConfig::Auditd)
    {
        disabled_features.push("firewall producer");
    }

    if disabled_features.is_empty() {
        return;
    }

    let reason = audit_unavailable_reason.unwrap_or("shared audit daemon is unavailable");
    error!(
        "Audit-backed {} disabled: {}. Continuing without those features.",
        disabled_features.join(" and "),
        reason
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::yaml::{FirewallConfig, HandlerConfig, LoggingConfig, ProcessConfig};
    use std::collections::HashSet;
    use std::path::PathBuf;

    fn base_config() -> AppConfig {
        AppConfig {
            yara: None,
            firewall: None,
            process: None,
            auth: None,
            audit: None,
            scan: None,
            networking: None,
            tty: None,
            ingestor: None,
            object_storage: None,
            logging: LoggingConfig::default(),
            file_integrity: None,
            health_log_file: PathBuf::from("/tmp/rb2-health"),
        }
    }

    #[test]
    fn derive_audit_event_flags_returns_none_by_default() {
        let cfg = base_config();
        assert!(derive_audit_event_flags(&cfg).is_empty());
    }

    #[test]
    fn derive_audit_event_flags_includes_exec_and_network() {
        let mut cfg = base_config();
        cfg.process = Some(ProcessConfig {
            collector: ProcessCollector::Auditd,
            rhai_enabled: true,
            rhai_rules_dir: None,
            log_file: PathBuf::from("/tmp/process"),
            alert_log_file: PathBuf::from("/tmp/alert"),
            disabled_rules: Vec::new(),
            ml_enabled: true,
            ml_debug: false,
        });
        cfg.firewall = Some(FirewallConfig {
            binary_whitelist: HashSet::new(),
            log_file: PathBuf::from("/tmp/firewall"),
            enforcing: false,
            producer: ProducerConfig::Auditd,
            handler: HandlerConfig::Kill,
        });

        let flags = derive_audit_event_flags(&cfg);
        assert!(flags.contains(AuditEventFlags::EXEC));
        assert!(flags.contains(AuditEventFlags::NETWORK));
    }
}
