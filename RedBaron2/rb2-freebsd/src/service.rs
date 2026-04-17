use log::{error, info, warn};
use std::env;
use std::fs::{self, File};
use std::io::{self, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

const FSTAB_PATH: &str = "/etc/fstab";
const PROCFS_MOUNT: &str = "proc\t/proc\tprocfs\trw\t0\t0";
const AUDIT_CONTROL_PATH: &str = "/etc/security/audit_control";
/// Audit classes rb2 requires on top of whatever is already configured.
const REQUIRED_AUDIT_CLASSES: &[&str] = &["lo", "aa", "ex", "nt"];

/// Back up a file before modifying it, writing to `{path}.rb2.bak`.
fn backup_file(path: &str) -> io::Result<()> {
    let bak = format!("{path}.rb2.bak");
    if Path::new(path).exists() && !Path::new(&bak).exists() {
        fs::copy(path, &bak)?;
        info!("Backed up {} to {}", path, bak);
    }
    Ok(())
}

/// Ensure procfs is mounted and will persist across reboots.
fn ensure_procfs() -> io::Result<()> {
    // On FreeBSD, query mount(8) directly /etc/mtab does not exist.
    let mounts = Command::new("mount")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default();

    let proc_mounted = mounts
        .lines()
        .any(|l| l.contains("/proc") && l.contains("procfs"));

    if !proc_mounted {
        info!("Mounting procfs on /proc");
        fs::create_dir_all("/proc")?;
        let status = Command::new("mount")
            .args(["-t", "procfs", "proc", "/proc"])
            .status()?;
        if !status.success() {
            error!("Failed to mount procfs (exit {})", status);
        }
    } else {
        info!("procfs already mounted on /proc");
    }

    // Ensure it's in /etc/fstab for persistence
    let fstab = fs::read_to_string(FSTAB_PATH).unwrap_or_default();
    let has_procfs = fstab
        .lines()
        .any(|l| !l.trim_start().starts_with('#') && l.contains("/proc") && l.contains("procfs"));

    if !has_procfs {
        backup_file(FSTAB_PATH)?;
        info!("Adding procfs entry to {}", FSTAB_PATH);
        let mut f = fs::OpenOptions::new().append(true).open(FSTAB_PATH)?;
        // Ensure we start on a new line
        if !fstab.ends_with('\n') && !fstab.is_empty() {
            f.write_all(b"\n")?;
        }
        writeln!(f, "{PROCFS_MOUNT}")?;
    } else {
        info!("procfs already in {}", FSTAB_PATH);
    }

    Ok(())
}

/// Ensure /etc/security/audit_control has the classes rb2 needs in both
/// `flags` (attributable) and `naflags` (non-attributable / daemons).
/// Inserts `flags` and `naflags` lines if they are absent entirely.
fn ensure_audit_config() -> io::Result<()> {
    backup_file(AUDIT_CONTROL_PATH)?;

    let content = match fs::read_to_string(AUDIT_CONTROL_PATH) {
        Ok(s) => s,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            warn!(
                "{} is missing; skipping audit class update to avoid creating an incomplete audit_control file",
                AUDIT_CONTROL_PATH
            );
            return Ok(());
        }
        Err(e) => return Err(e),
    };

    let mut found_flags = false;
    let mut found_naflags = false;
    let mut lines: Vec<String> = content
        .lines()
        .map(|line| {
            let (key, rest) = match line.split_once(':') {
                Some(pair) => pair,
                None => return line.to_string(),
            };
            if key != "flags" && key != "naflags" {
                return line.to_string();
            }
            if key == "flags" {
                found_flags = true;
            } else {
                found_naflags = true;
            }
            let mut classes: Vec<&str> = rest
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .collect();
            for &required in REQUIRED_AUDIT_CLASSES {
                if !classes.contains(&required) {
                    classes.push(required);
                }
            }
            format!("{}:{}", key, classes.join(","))
        })
        .collect();

    if !found_flags {
        lines.push(format!("flags:{}", REQUIRED_AUDIT_CLASSES.join(",")));
    }
    if !found_naflags {
        lines.push(format!("naflags:{}", REQUIRED_AUDIT_CLASSES.join(",")));
    }

    let mut new_content = lines.join("\n");

    // Preserve trailing newline
    if content.ends_with('\n') || !found_flags || !found_naflags {
        new_content.push('\n');
    }

    if new_content != content {
        fs::write(AUDIT_CONTROL_PATH, &new_content)?;
        info!("Updated {} with required audit classes", AUDIT_CONTROL_PATH);
    } else {
        info!("{} already has required audit classes", AUDIT_CONTROL_PATH);
    }

    Ok(())
}

/// Ensure auditd is enabled in rc.conf and running. Reloads audit_control
/// with `audit -s` if already running, otherwise starts the daemon.
fn ensure_auditd() -> io::Result<()> {
    // Read rc.conf, treating NotFound as empty but propagating other I/O errors.
    let rc_conf = match fs::read_to_string("/etc/rc.conf") {
        Ok(s) => s,
        Err(e) if e.kind() == io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(e),
    };

    // Find any non-comment line that assigns auditd_enable.
    let existing_line = rc_conf
        .lines()
        .find(|l| !l.trim_start().starts_with('#') && l.contains("auditd_enable="))
        .map(str::to_owned);

    let already_yes = existing_line
        .as_deref()
        .and_then(|l| l.split_once('='))
        .map(|(_, val)| val.trim().trim_matches('"').eq_ignore_ascii_case("yes"))
        .unwrap_or(false);

    if already_yes {
        info!("auditd already enabled in /etc/rc.conf");
    } else {
        backup_file("/etc/rc.conf")?;
        if existing_line.is_some() {
            // auditd_enable is present but not YES — replace it in-place.
            info!("auditd_enable found but not YES; updating /etc/rc.conf");
            let new_content = rc_conf
                .lines()
                .map(|l| {
                    if !l.trim_start().starts_with('#') && l.contains("auditd_enable=") {
                        "auditd_enable=\"YES\"".to_string()
                    } else {
                        l.to_string()
                    }
                })
                .collect::<Vec<_>>()
                .join("\n");
            let new_content = if rc_conf.ends_with('\n') {
                format!("{new_content}\n")
            } else {
                new_content
            };
            fs::write("/etc/rc.conf", new_content)?;
        } else {
            // auditd_enable is absent — append it.
            info!("Enabling auditd in /etc/rc.conf");
            let mut f = fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open("/etc/rc.conf")?;
            if !rc_conf.ends_with('\n') && !rc_conf.is_empty() {
                f.write_all(b"\n")?;
            }
            writeln!(f, "auditd_enable=\"YES\"")?;
        }
    }

    // Start or reload auditd.
    let running = Command::new("service")
        .args(["auditd", "status"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    if running {
        info!("auditd is running; reloading audit_control with 'audit -s'");
        let status = Command::new("audit").arg("-s").status()?;
        if !status.success() {
            warn!("'audit -s' exited with non-zero status");
        }
    } else {
        info!("auditd is not running; starting it");
        let status = Command::new("service").args(["auditd", "start"]).status()?;
        if !status.success() {
            warn!("'service auditd start' exited with non-zero status");
        }
    }

    Ok(())
}

pub fn install_rc_service() -> io::Result<()> {
    // 1. Ensure procfs
    if let Err(e) = ensure_procfs() {
        warn!("Could not set up procfs (non-fatal): {e}");
    }

    // 2. Ensure audit_control
    if let Err(e) = ensure_audit_config() {
        warn!("Could not update audit_control (non-fatal): {e}");
    }

    // 3. Ensure auditd is enabled and running (independent of audit_control state).
    if let Err(e) = ensure_auditd() {
        warn!("Could not enable/start auditd (non-fatal): {e}");
    }

    // 4. Write rc.d script
    let exe_path = env::current_exe()?;
    let bin_name = exe_path
        .file_stem()
        .and_then(|s| s.to_str())
        .ok_or_else(|| io::Error::other("Could not determine binary name"))?
        .to_string();

    let rc_path = PathBuf::from(format!("/usr/local/etc/rc.d/{bin_name}"));

    if rc_path.exists() {
        warn!(
            "rc.d script already exists at {}. Not overwriting.",
            rc_path.display()
        );
        return Ok(());
    }

    let exec_path = exe_path
        .to_str()
        .ok_or_else(|| io::Error::other("Non-UTF8 path to executable"))?;

    let rust_log = env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string());
    let rb2_config = env::var("RB2_CONFIG").unwrap_or_else(|_| "/etc/rb2.yaml".to_string());

    // Reject values that would break or escape the shell script.
    for (name, val) in [
        ("exec_path", exec_path),
        ("RUST_LOG", &rust_log),
        ("RB2_CONFIG", &rb2_config),
    ] {
        if val.contains('"')
            || val.contains('\n')
            || val.contains('\r')
            || val.contains('`')
            || val.contains('$')
        {
            return Err(io::Error::other(format!(
                "{name} contains shell-unsafe characters and cannot be embedded in the rc.d script"
            )));
        }
    }

    let rc_script = format!(
        r#"#!/bin/sh

# PROVIDE: {name}
# REQUIRE: LOGIN NETWORKING
# KEYWORD: shutdown

. /etc/rc.subr

name="{name}"
rcvar="{name}_enable"

load_rc_config $name

: ${{{name}_enable:="NO"}}
: ${{{name}_config:="{config}"}}
: ${{{name}_rust_log:="{rust_log}"}}

pidfile="/var/run/${{name}}.pid"
childpidfile="/var/run/${{name}}_child.pid"
command="/usr/sbin/daemon"
command_args="-P $pidfile -p $childpidfile -f -r -o /var/log/rb2/rb2.log {exec}"

start_precmd="{name}_prestart"

{name}_prestart()
{{
    mkdir -m 700 -p /var/log/rb2
    export RUST_LOG="${{{name}_rust_log}}"
    export RB2_CONFIG="${{{name}_config}}"
}}

run_rc_command "$1"
"#,
        name = bin_name,
        exec = exec_path,
        config = rb2_config,
        rust_log = rust_log,
    );

    // Write atomically
    let tmp_path = rc_path.with_extension("tmp");
    {
        let mut f = File::create(&tmp_path)?;
        f.write_all(rc_script.as_bytes())?;
        f.sync_all()?;
        let mut perms = f.metadata()?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&tmp_path, perms)?;
    }
    fs::rename(&tmp_path, &rc_path)?;

    info!("Installed rc.d script to {}", rc_path.display());

    // 5. Enable the service in rc.conf
    let rc_conf = fs::read_to_string("/etc/rc.conf").unwrap_or_default();
    let enable_line = format!("{bin_name}_enable=\"YES\"");

    let already_enabled = rc_conf
        .lines()
        .any(|l| !l.trim_start().starts_with('#') && l.contains(&format!("{bin_name}_enable")));

    if !already_enabled {
        backup_file("/etc/rc.conf")?;
        info!("Adding {enable_line} to /etc/rc.conf");
        let mut f = fs::OpenOptions::new().append(true).open("/etc/rc.conf")?;
        if !rc_conf.ends_with('\n') && !rc_conf.is_empty() {
            f.write_all(b"\n")?;
        }
        writeln!(f, "{enable_line}")?;
    } else {
        info!("{bin_name} already referenced in /etc/rc.conf");
    }

    // 6. Start the service
    match Command::new("service").args([&bin_name, "start"]).status() {
        Ok(status) if status.success() => {
            info!("{bin_name} service started");
        }
        Ok(status) => {
            error!("'service {bin_name} start' exited with status: {status}");
        }
        Err(e) => {
            error!("Failed to start service: {e}");
            return Err(e);
        }
    }

    Ok(())
}
