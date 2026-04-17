use anyhow::{Context, bail};
use log::{info, warn};
use std::{env, fs, os::unix::fs::OpenOptionsExt, path::PathBuf, process::Command};

pub fn render_default_config() -> anyhow::Result<String> {
    #[cfg(target_os = "linux")]
    let mut paths = crate::firewall::sockets::get_active_socket_paths()?;
    #[cfg(target_os = "freebsd")]
    let mut paths = get_active_socket_paths_bsd()?;
    // Sudo tries to do network activity
    paths.extend(get_privsec_utils_path());

    if let Some(p) = get_self_path() {
        paths.push(p);
    }

    paths.sort();
    paths.dedup();

    let yaml = render_config(&paths);
    Ok(yaml)
}

pub fn write_config_with_fallback(filename: &str) -> anyhow::Result<PathBuf> {
    let yaml = render_default_config()?;
    let etc_path = PathBuf::from("/etc").join(filename);
    match write_file(&etc_path, &yaml) {
        Ok(()) => Ok(etc_path),
        Err(e) => {
            warn!(
                "Failed to write {} ({}), falling back to CWD",
                etc_path.display(),
                e
            );
            let out_path = env::current_dir()?.join(filename);
            write_file(&out_path, &yaml)?;
            Ok(out_path)
        }
    }
}

fn render_binary_whitelist(paths: &[PathBuf]) -> String {
    let mut yaml = String::new();
    for p in paths {
        let s = p.to_string_lossy();
        info!("Adding path {s} to binary built allow list");
        yaml.push_str("    - ");
        yaml.push_str(&s);
        yaml.push('\n');
    }
    yaml
}

fn write_temp_rendered_config(prefix: &str, contents: &str) -> anyhow::Result<PathBuf> {
    let pid = std::process::id();
    for attempt in 0..100u32 {
        let path = env::temp_dir().join(format!("{prefix}-{pid}-{attempt}.yaml"));
        match write_file(&path, contents) {
            Ok(()) => return Ok(path),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e.into()),
        }
    }

    bail!(
        "failed to allocate temporary config path in {}",
        env::temp_dir().display()
    )
}

fn run_diff_command(
    temp_path: &std::path::Path,
    config_path: &std::path::Path,
) -> std::io::Result<std::process::ExitStatus> {
    #[cfg(target_os = "freebsd")]
    {
        std::process::Command::new("diff")
            .arg("-u")
            .arg(temp_path)
            .arg(config_path)
            .stdout(std::process::Stdio::inherit())
            .stderr(std::process::Stdio::inherit())
            .status()
    }

    #[cfg(target_os = "linux")]
    {
        let colored = std::process::Command::new("diff")
            .arg("-u")
            .arg("--color=always")
            .arg(temp_path)
            .arg(config_path)
            .output();

        match colored {
            Ok(output) if should_retry_plain_diff(&output) => {
                run_plain_diff(temp_path, config_path)
            }
            Ok(output) => {
                use std::io::Write;

                std::io::stdout().write_all(&output.stdout)?;
                std::io::stderr().write_all(&output.stderr)?;
                Ok(output.status)
            }
            Err(_) => run_plain_diff(temp_path, config_path),
        }
    }
}

#[cfg(target_os = "linux")]
fn run_plain_diff(
    temp_path: &std::path::Path,
    config_path: &std::path::Path,
) -> std::io::Result<std::process::ExitStatus> {
    std::process::Command::new("diff")
        .arg("-u")
        .arg(temp_path)
        .arg(config_path)
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .status()
}

#[cfg(target_os = "linux")]
fn should_retry_plain_diff(output: &std::process::Output) -> bool {
    if output.status.code() != Some(2) {
        return false;
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    stderr.contains("--color")
        || stderr.contains("unrecognized")
        || stderr.contains("illegal")
        || stderr.contains("unknown")
}

#[cfg(target_os = "linux")]
fn render_config(paths: &[PathBuf]) -> String {
    let authorized_keys_path = env::var("HOME")
        .map(|home| format!("{}/.ssh/authorized_keys", home))
        .unwrap_or_else(|_| "~/.ssh/authorized_keys".to_string());
    let whitelist = render_binary_whitelist(paths);

    format!(
        r#"features:
  firewall: true
  yara: true
  process: true
  auth: true
  tty: true
  scan: true
  networking: true
  file_integrity: true
  ingestor: false

firewall:
  enforcing: false
  producer: ebpf  # "ebpf" (default), "auditd", or "nfq"
  handler: kill
  binary_whitelist:
{whitelist}

yara:
  rules_dir: # /var/lib/rb2/yara # optional for extra rules
  disable_bundled_rules: false
  disabled_rules: # optional
    #- Multi_EICAR
  actions:
    - kill
    #- move
  samples_dir: /var/lib/rb2/samples
  fanotify_enabled: true

tty:
  encrypt: true
  authorized_keys: {authorized_keys_path}
  session_recognition_idle_secs: 300
  spool_dir: /var/lib/rb2/tty
  flush_interval_secs: 30
  forward_to_s3: false
  s3_forward_interval_secs: 60

file_integrity:
  log_paths:
    - /etc
    - /root
    - /home

networking:
  # interfaces: [eth0]              # optional; default is all non-loopback interfaces
  dns_enabled: true
  http_enabled: true
  https_enabled: true
  http_capture_inbound: false
  snaplen_bytes: 2048

ingestor:
  # Note: The rb2 binary path must be added to firewall.binary_whitelist for log forwarding to work
  flush_interval_secs: 10
  memory_trigger_size_mb: 5
  stats_interval_secs: 120   # 0 = disabled
  forwarders:
    - name: openobserve-default
      type: openobserve
      openobserve:
        url: http://localhost:5080
        org: default
        stream_prefix: rb2-logs
        username: root@example.com
        password: Complexpass#123
    # - name: splunk-primary
    #   type: splunk
    #   splunk:
    #     url: https://localhost:8088
    #     token: splunk-hec-token
    #     index: main
    #     source: rb2
    #     sourcetype_prefix: rb2
    #     gzip_enabled: true
    #     tls_skip_verify: false

object_storage:
  endpoint: "http://minio.local:9000"
  bucket_tty: "rb2-tty"
  bucket_samples: "rb2-samples"
  region: "us-east-1"
  access_key: "minioadmin"
  secret_key: "minioadmin"
  path_style: true

logging:
  log_dir: /var/log/rb2
  rollover_size_mb: 10
  rollover_count: 5

auth:
  # optional: override libpam auto-detection if needed
  # libpam_path: /lib/x86_64-linux-gnu/libpam.so.0

process:
  collector: ebpf  # "ebpf" (default) or "auditd"
  rhai_enabled: true
  # rhai_rules_dir: /var/lib/rb2/rhai
  ml_enabled: true          # enable ML scoring for process events
  ml_debug: false           # when true, log full ML breakdown; otherwise only ml_score
  disabled_rules: # remove specific rules by name
  #   - bash_c_execution
"#
    )
}

#[cfg(target_os = "freebsd")]
fn render_config(paths: &[PathBuf]) -> String {
    let whitelist = render_binary_whitelist(paths);

    format!(
        r#"features:
  firewall: true
  yara: true
  process: true
  auth: true
  audit: true
  ingestor: false

firewall:
  enforcing: false
  producer: bsm
  binary_whitelist:
{whitelist}

yara:
  rules_dir: # /var/lib/rb2/yara # optional for extra rules
  disable_bundled_rules: false
  disabled_rules: # optional
    #- Multi_EICAR
  actions:
    - kill
    #- move
  samples_dir: /var/lib/rb2/samples

ingestor:
  # Note: The rb2 binary path must be added to firewall.binary_whitelist for log forwarding to work
  flush_interval_secs: 10
  memory_trigger_size_mb: 5
  stats_interval_secs: 120   # 0 = disabled
  forwarders:
    - name: openobserve-default
      type: openobserve
      openobserve:
        url: http://localhost:5080
        org: default
        stream_prefix: rb2-logs
        username: root@example.com
        password: Complexpass#123

logging:
  log_dir: /var/log/rb2
  rollover_size_mb: 10
  rollover_count: 5

process:
  rhai_enabled: true
  # rhai_rules_dir: /var/lib/rb2/rhai
  ml_enabled: true          # enable ML scoring for process events
  ml_debug: false           # when true, log full ML breakdown; otherwise only ml_score
  disabled_rules: # remove specific rules by name
  #   - bash_c_execution
"#
    )
}

/// Create with 0600
fn write_file(path: &std::path::Path, contents: &str) -> std::io::Result<()> {
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true).mode(0o600);
    let mut f = opts.open(path)?;
    use std::io::Write;
    f.write_all(contents.as_bytes())?;
    f.sync_all()?;
    Ok(())
}

fn get_self_path() -> Option<PathBuf> {
    std::env::current_exe().ok()
}

fn get_privsec_utils_path() -> Vec<PathBuf> {
    let mut paths = Vec::new();

    let sudo_path = Command::new("which")
        .arg("sudo")
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|path| path.trim().to_string());

    let doas_path = Command::new("which")
        .arg("doas")
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|path| path.trim().to_string());

    if let Some(path) = sudo_path {
        paths.push(PathBuf::from(path));
    }

    if let Some(path) = doas_path {
        paths.push(PathBuf::from(path));
    }

    paths
}

/// FreeBSD: enumerate processes with any non-loopback socket (connected or
/// listening) using `sockstat -4 -6 -q`, then resolve each PID to its exe
/// path via sysctl. Mirrors the Linux behaviour where all /proc/net/tcp
/// entries with at least one non-loopback endpoint are included.
#[cfg(target_os = "freebsd")]
fn get_active_socket_paths_bsd() -> anyhow::Result<Vec<PathBuf>> {
    let output = Command::new("sockstat").args(["-4", "-6", "-q"]).output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("sockstat exited with {}: {}", output.status, stderr.trim());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut paths: Vec<PathBuf> = Vec::new();

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

        // Mirror Linux: skip only when both endpoints are loopback.
        // Listeners have foreign "*:*" which is not loopback, so they pass.
        let local = parts[5];
        let remote = parts[6];
        let local_is_loopback = local.starts_with("127.") || local.starts_with("::1");
        let remote_is_loopback = remote.starts_with("127.") || remote.starts_with("::1");
        if local_is_loopback && remote_is_loopback {
            continue;
        }

        if let Some(path) = exe_path_bsd(pid) {
            paths.push(path);
        }
    }

    paths.sort();
    paths.dedup();
    Ok(paths)
}

#[cfg(target_os = "freebsd")]
fn exe_path_bsd(pid: i32) -> Option<PathBuf> {
    let mib: [libc::c_int; 4] = [
        libc::CTL_KERN,
        libc::KERN_PROC,
        libc::KERN_PROC_PATHNAME,
        pid,
    ];
    let mut size: libc::size_t = 0;
    let ret = unsafe {
        libc::sysctl(
            mib.as_ptr(),
            4,
            std::ptr::null_mut(),
            &mut size,
            std::ptr::null(),
            0,
        )
    };
    if ret != 0 || size == 0 {
        return None;
    }
    let alloc = size * 4 / 3;
    let mut buf = vec![0u8; alloc];
    let mut actual = alloc;
    let ret = unsafe {
        libc::sysctl(
            mib.as_ptr(),
            4,
            buf.as_mut_ptr().cast(),
            &mut actual,
            std::ptr::null(),
            0,
        )
    };
    if ret != 0 {
        return None;
    }
    buf.truncate(actual);
    let s = String::from_utf8_lossy(&buf[..buf.len().saturating_sub(1)]).into_owned();
    if s.is_empty() {
        None
    } else {
        Some(PathBuf::from(s))
    }
}

pub fn diff_config(temp_filename: &str) -> anyhow::Result<()> {
    let config_path = match std::env::var("RB2_CONFIG") {
        Ok(p) => std::path::PathBuf::from(p),
        Err(_) => std::path::PathBuf::from("/etc/rb2.yaml"),
    };

    if !config_path.exists() {
        bail!("No config file found at {:?}", config_path);
    }

    // will output whitelist info unless log level is set to warn
    let old_level = log::max_level();
    log::set_max_level(log::LevelFilter::Warn);
    let rendered = render_default_config();
    log::set_max_level(old_level);
    let rendered = rendered?;
    let temp_path = write_temp_rendered_config(temp_filename, &rendered)?;

    let diff_result = (|| -> anyhow::Result<()> {
        let status = run_diff_command(&temp_path, &config_path).context("failed to spawn diff")?;

        match status.code() {
            Some(0) => info!("Config is unchanged"),
            Some(1) => info!("End of config diff"),
            Some(x) => bail!("diff failed with code: {:?}", x),
            None => bail!("diff failed with no exit code"),
        };

        Ok(())
    })();

    let _ = std::fs::remove_file(&temp_path);
    diff_result
}
