use crate::config::yaml::{AppConfig, ForwarderConfig, OpenObserveConfig, SplunkConfig};
#[cfg(target_os = "linux")]
use crate::network::model::ParsedNetworkEvent;
use reqwest::Url;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::net::lookup_host;
use tokio::time::timeout;

const FORWARDER_DNS_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Debug, Clone, Default)]
pub struct SelfObservationFilter {
    firewall_rules: Vec<FirewallIgnoreRule>,
    #[cfg(target_os = "linux")]
    network_rules: Vec<NetworkIgnoreRule>,
}

#[derive(Debug, Clone)]
struct FirewallIgnoreRule {
    process_path: PathBuf,
    dst_ips: Vec<IpAddr>,
    dst_port: u16,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone)]
struct NetworkIgnoreRule {
    dst_ips: Vec<IpAddr>,
    hosts: Vec<String>,
    dst_port: u16,
    path_prefixes: Vec<String>,
}

#[derive(Debug, Clone)]
struct ForwarderTarget {
    #[cfg(target_os = "linux")]
    host: String,
    port: u16,
    ips: Vec<IpAddr>,
    base_path: String,
}

impl SelfObservationFilter {
    pub async fn from_app_config(cfg: &AppConfig) -> anyhow::Result<Self> {
        let Some(ingestor) = &cfg.ingestor else {
            return Ok(Self::default());
        };

        let process_path = std::env::current_exe()?;
        let mut firewall_rules = Vec::new();
        #[cfg(target_os = "linux")]
        let mut network_rules = Vec::new();

        for forwarder in &ingestor.forwarders {
            let mut rules = rules_for_forwarder(forwarder, &process_path).await?;
            firewall_rules.append(&mut rules.firewall_rules);
            #[cfg(target_os = "linux")]
            network_rules.append(&mut rules.network_rules);
        }

        Ok(Self {
            firewall_rules,
            #[cfg(target_os = "linux")]
            network_rules,
        })
    }

    pub fn should_ignore_firewall(
        &self,
        process_path: &Path,
        dst_ip: Option<&str>,
        dst_port: Option<u16>,
    ) -> bool {
        let Some(ip_str) = dst_ip else {
            return false;
        };
        let Ok(ip) = ip_str.parse::<IpAddr>() else {
            return false;
        };
        let Some(port) = dst_port else {
            return false;
        };

        self.firewall_rules.iter().any(|rule| {
            process_path == rule.process_path && port == rule.dst_port && rule.dst_ips.contains(&ip)
        })
    }

    #[cfg(target_os = "linux")]
    pub fn should_ignore_network(&self, ev: &ParsedNetworkEvent) -> bool {
        match ev {
            ParsedNetworkEvent::Http(event) => {
                let Ok(dst_ip) = event.common.dst_ip.parse::<IpAddr>() else {
                    return false;
                };

                self.network_rules.iter().any(|rule| {
                    event.common.dst_port == rule.dst_port
                        && rule.dst_ips.contains(&dst_ip)
                        && rule
                            .path_prefixes
                            .iter()
                            .any(|prefix| event.path.starts_with(prefix))
                })
            }
            ParsedNetworkEvent::Https(event) => {
                let Some(host) = event.host.as_deref() else {
                    return false;
                };
                let normalized_host = normalize_host(host);

                self.network_rules.iter().any(|rule| {
                    rule.hosts
                        .iter()
                        .any(|candidate| candidate == &normalized_host)
                        && rule
                            .path_prefixes
                            .iter()
                            .any(|prefix| event.path.starts_with(prefix))
                })
            }
            ParsedNetworkEvent::Dns(_) => false,
        }
    }
}

#[derive(Default)]
struct RuleSet {
    firewall_rules: Vec<FirewallIgnoreRule>,
    #[cfg(target_os = "linux")]
    network_rules: Vec<NetworkIgnoreRule>,
}

async fn rules_for_forwarder(
    forwarder: &ForwarderConfig,
    process_path: &Path,
) -> anyhow::Result<RuleSet> {
    match forwarder.forwarder_type.as_str() {
        "openobserve" => {
            let Some(cfg) = &forwarder.openobserve else {
                return Ok(RuleSet::default());
            };
            openobserve_rules(cfg, process_path).await
        }
        "splunk" => {
            let Some(cfg) = &forwarder.splunk else {
                return Ok(RuleSet::default());
            };
            splunk_rules(cfg, process_path).await
        }
        _ => Ok(RuleSet::default()),
    }
}

async fn openobserve_rules(
    cfg: &OpenObserveConfig,
    process_path: &Path,
) -> anyhow::Result<RuleSet> {
    let target = parse_target(&cfg.url).await?;
    let path_prefix = join_path_prefix(&target.base_path, &format!("api/{}/_bulk", cfg.org));
    Ok(build_rules(process_path, target, vec![path_prefix]))
}

async fn splunk_rules(cfg: &SplunkConfig, process_path: &Path) -> anyhow::Result<RuleSet> {
    let target = parse_target(&cfg.url).await?;
    let path_prefix = join_path_prefix(&target.base_path, "services/collector/event");
    Ok(build_rules(process_path, target, vec![path_prefix]))
}

fn build_rules(
    process_path: &Path,
    target: ForwarderTarget,
    #[cfg(target_os = "linux")] path_prefixes: Vec<String>,
    #[cfg(not(target_os = "linux"))] _path_prefixes: Vec<String>,
) -> RuleSet {
    RuleSet {
        firewall_rules: vec![FirewallIgnoreRule {
            process_path: process_path.to_path_buf(),
            dst_ips: target.ips.clone(),
            dst_port: target.port,
        }],
        #[cfg(target_os = "linux")]
        network_rules: vec![NetworkIgnoreRule {
            dst_ips: target.ips,
            hosts: host_variants(&target.host, target.port),
            dst_port: target.port,
            path_prefixes,
        }],
    }
}

async fn parse_target(raw_url: &str) -> anyhow::Result<ForwarderTarget> {
    let url = Url::parse(raw_url)?;
    let host = url
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("forwarder url missing host: {raw_url}"))?
        .to_string();
    let port = url
        .port_or_known_default()
        .ok_or_else(|| anyhow::anyhow!("forwarder url missing port: {raw_url}"))?;
    let ips = resolve_host_ips(&host, port).await;
    let base_path = normalize_base_path(url.path());

    Ok(ForwarderTarget {
        #[cfg(target_os = "linux")]
        host,
        port,
        ips,
        base_path,
    })
}

async fn resolve_host_ips(host: &str, port: u16) -> Vec<IpAddr> {
    let mut ips = Vec::new();
    if let Ok(ip) = host.parse::<IpAddr>() {
        ips.push(ip);
        return ips;
    }

    if let Ok(Ok(addrs)) = timeout(FORWARDER_DNS_TIMEOUT, lookup_host((host, port))).await {
        for addr in addrs {
            let ip = addr.ip();
            if !ips.contains(&ip) {
                ips.push(ip);
            }
        }
    }

    ips
}

#[cfg(target_os = "linux")]
fn host_variants(host: &str, port: u16) -> Vec<String> {
    let normalized = normalize_host(host);
    let mut hosts = vec![normalized.clone()];
    if let Ok(ip) = normalized.parse::<IpAddr>() {
        hosts.push(match ip {
            IpAddr::V4(_) => format!("{normalized}:{port}"),
            IpAddr::V6(_) => format!("[{normalized}]:{port}"),
        });
    } else {
        hosts.push(format!("{normalized}:{port}"));
    }
    hosts
}

#[cfg(target_os = "linux")]
fn normalize_host(host: &str) -> String {
    parse_host_header(host).0
}

#[cfg(target_os = "linux")]
fn parse_host_header(host: &str) -> (String, Option<u16>) {
    let host = host.trim();

    if let Some(rest) = host.strip_prefix('[')
        && let Some(end) = rest.find(']')
    {
        let addr = rest[..end].to_ascii_lowercase();
        let remainder = rest[end + 1..].trim();
        let port = remainder
            .strip_prefix(':')
            .and_then(|value| value.parse::<u16>().ok());
        return (addr, port);
    }

    if host.matches(':').count() > 1 {
        return (host.to_ascii_lowercase(), None);
    }

    if let Some((name, port)) = host.rsplit_once(':')
        && !name.is_empty()
        && let Ok(port) = port.parse::<u16>()
    {
        return (name.to_ascii_lowercase(), Some(port));
    }

    (host.to_ascii_lowercase(), None)
}

fn normalize_base_path(path: &str) -> String {
    let trimmed = path.trim().trim_end_matches('/');
    if trimmed.is_empty() || trimmed == "/" {
        String::new()
    } else if trimmed.starts_with('/') {
        trimmed.to_string()
    } else {
        format!("/{trimmed}")
    }
}

fn join_path_prefix(base: &str, suffix: &str) -> String {
    let suffix = suffix.trim_start_matches('/');
    if base.is_empty() {
        format!("/{suffix}")
    } else {
        format!("{base}/{suffix}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn normalize_host_handles_bracketed_ipv6_with_port() {
        assert_eq!(normalize_host("[::1]:443"), "::1");
        assert_eq!(normalize_host("[2001:db8::1]:8443"), "2001:db8::1");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn normalize_host_handles_hostname_and_port() {
        assert_eq!(normalize_host("Example.COM:443"), "example.com");
        assert_eq!(normalize_host("example.com"), "example.com");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn host_variants_include_ipv6_port_form() {
        assert_eq!(host_variants("[::1]:443", 443), vec!["::1", "[::1]:443"]);
    }
}
