use chrono::SecondsFormat;
use log::{debug, error, info, warn};
use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use sha2::{Digest, Sha256};
use std::fs;
use std::io;
use std::io::{Read, Write};
use std::path::Path;
use yara_x::Rule;

use crate::config::yaml::YaraActions;
use crate::misc::{get_hostname, get_machine_id};

pub struct YaraMatchResult {
    pub pid_terminated: bool,
}

struct Ctx {
    ts: String,
    hostname: Option<String>,
    host_id: Option<String>,
}

impl Ctx {
    fn new() -> Self {
        Self {
            ts: chrono::Local::now().to_rfc3339_opts(SecondsFormat::Millis, true),
            hostname: get_hostname(),
            host_id: get_machine_id(),
        }
    }
}

fn action_str(actions: &YaraActions, kill_label: &str) -> String {
    let mut parts = Vec::with_capacity(4);

    if actions.alert {
        parts.push("alert");
    }
    if actions.move_sample {
        parts.push("move");
    }
    if actions.kill {
        parts.push(kill_label);
    }

    if parts.is_empty() {
        "none".to_string()
    } else {
        parts.join(",")
    }
}

fn log_match_events(
    ctx: &Ctx,
    pid: Option<i32>,
    original_path: &str,
    rule_names: &[String],
    action_taken: &str,
) {
    for rule_name in rule_names {
        info!(
            "Found malware with rule: {} path: {} actions {}",
            rule_name, original_path, action_taken
        );

        let mut json = serde_json::json!({
            "timestamp": ctx.ts,
            "event": "yara_match",
            "host_name": ctx.hostname,
            "host_id": ctx.host_id,
            "path": original_path,
            "rule": rule_name,
            "action_taken": action_taken,
        });

        if let Some(p) = pid {
            json["pid"] = serde_json::json!(p);
        }

        info!(target: "rb2_yara", "{}", json);
    }
}

/// Reusable path handler (fanotify uses this directly).
/// - `kill_label`: what to print when actions.kill is set (e.g. "kill" vs "deny_exec")
/// - `src_path`: path to copy from when move_sample is set (may differ from original_path,
///   e.g. `/proc/self/fd/N` for fanotify so we copy from the open fd)
#[cfg(target_os = "linux")]
pub fn handle_yara_path_match(
    pid: Option<i32>,
    original_path: &str,
    rule_names: &[String],
    actions: &YaraActions,
    samples_dir: &Path,
    kill_label: &str,
    src_path: &str,
) {
    let ctx = Ctx::new();
    let action_taken = action_str(actions, kill_label);

    if actions.alert {
        log_match_events(&ctx, pid, original_path, rule_names, &action_taken);
    }

    if actions.move_sample
        && let Err(e) = collect_sample_from_path(
            src_path,
            pid,
            original_path,
            samples_dir,
            &ctx,
            rule_names,
            &action_taken,
        )
    {
        error!(
            "Failed to collect sample: pid={:?} path={} err={:#}",
            pid, original_path, e
        );
    }
}

/// Live-process entrypoint. Execution order: alert -> move -> kill(SIGKILL)
pub fn handle_yara_match<'a, I>(
    pid: i32,
    matching: I,
    actions: &YaraActions,
    samples_dir: &Path,
) -> YaraMatchResult
where
    I: IntoIterator<Item = Rule<'a, 'a>>,
{
    let original_path = get_pid_path(pid).unwrap_or_else(|_| "<unknown>".to_string());

    let rule_names: Vec<String> = matching
        .into_iter()
        .map(|r| r.identifier().to_string())
        .collect();

    let ctx = Ctx::new();
    let action_taken = action_str(actions, "kill");

    if actions.alert {
        log_match_events(&ctx, Some(pid), &original_path, &rule_names, &action_taken);
    }

    if actions.move_sample {
        let procfs_path = get_procfs_exe_path(pid);
        if let Err(e) = collect_sample_from_path(
            &procfs_path,
            Some(pid),
            &original_path,
            samples_dir,
            &ctx,
            &rule_names,
            &action_taken,
        ) {
            error!(
                "Failed to collect sample: pid={} path={} err={:#}",
                pid, original_path, e
            );
        }
    }

    let pid_terminated = if actions.kill {
        kill_logging_errors(pid)
    } else {
        false
    };

    YaraMatchResult { pid_terminated }
}

/// Copy from a filesystem path (e.g. procfs), strip ELF header in-place.
/// Streams src into a temp file while hashing — single pass, no in-memory buffering.
/// Atomically renames the temp file to the final `<sha256>` path so the filename
/// always matches the bytes on disk. A `.yara.json` sidecar is always written.
fn collect_sample_from_path(
    src_path: &str,
    pid: Option<i32>,
    original_path: &str,
    samples_dir: &Path,
    ctx: &Ctx,
    rule_names: &[String],
    action_taken: &str,
) -> anyhow::Result<()> {
    let host_dir = samples_dir.join(ctx.hostname.as_deref().unwrap_or("unknown"));
    fs::create_dir_all(&host_dir)?;

    // Single pass: hash while writing to a temp file so the sha256 name always
    // matches the exact bytes stored, and we never buffer the whole binary.
    let tmp_path = host_dir.join(format!(".tmp-{}", uuid::Uuid::new_v4()));
    let hash = {
        let mut src =
            fs::File::open(src_path).map_err(|e| anyhow::anyhow!("opening {}: {}", src_path, e))?;
        let mut dst = fs::File::create(&tmp_path)?;
        let mut hasher = Sha256::new();
        let mut buf = [0u8; 65536];
        loop {
            let n = src.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
            dst.write_all(&buf[..n])?;
        }
        format!("{:x}", hasher.finalize())
    };

    // Strip before rename so the file at sample_path is always fully stripped
    // once it lands — avoids leaving an unstripped sample if we crash between
    // rename and strip, which would never be re-stripped on future matches.
    strip_elf_header_in_place(&tmp_path)?;

    let sample_path = host_dir.join(&hash);
    if sample_path.exists() {
        let _ = fs::remove_file(&tmp_path);
        debug!(
            "Stripped sample already exists at {}, skipping write",
            sample_path.display()
        );
    } else {
        // Atomic rename — on Unix this replaces the destination atomically if it
        // appeared concurrently (same content, same hash, so overwriting is fine).
        if let Err(e) = fs::rename(&tmp_path, &sample_path) {
            let _ = fs::remove_file(&tmp_path);
            return Err(anyhow::anyhow!(
                "renaming tmp -> {}: {}",
                sample_path.display(),
                e
            ));
        }
        debug!("Collected stripped sample -> {}", sample_path.display());
    }

    if !original_path.contains("(deleted)") && !original_path.starts_with('<') {
        match fs::remove_file(original_path) {
            Ok(()) => debug!("Removed malware binary: {}", original_path),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                debug!("Original binary already gone: {}", original_path)
            }
            Err(e) => warn!("Failed to remove {}: {}", original_path, e),
        }
    }

    let sidecar_path = host_dir.join(format!("{}.yara.json", hash));
    let sidecar_json = serde_json::json!({
        "timestamp": ctx.ts,
        "event": "yara_match",
        "host_name": ctx.hostname,
        "host_id": ctx.host_id,
        "pid": pid,
        "path": original_path,
        "rules": rule_names,
        "sha256": hash,
        "action_taken": action_taken,
    });
    let mut f = fs::File::create(&sidecar_path)?;
    f.write_all(serde_json::to_string_pretty(&sidecar_json)?.as_bytes())?;
    debug!("Wrote sidecar {}", sidecar_path.display());

    Ok(())
}

/// Zero out the ELF header magic on a file already copied to disk.
fn strip_elf_header_in_place(path: &Path) -> io::Result<()> {
    use std::io::{Seek, SeekFrom};
    let mut f = fs::OpenOptions::new().read(true).write(true).open(path)?;
    let mut magic = [0u8; 4];
    match f.read_exact(&mut magic) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
        Err(e) => return Err(e),
    }
    if magic == *b"\x7fELF" {
        f.seek(SeekFrom::Start(0))?;
        f.write_all(&[0u8; 4])?;
        debug!("Stripped ELF magic from sample");
    }
    Ok(())
}

/// Send SIGKILL and log if it fails
fn kill_logging_errors(pid: i32) -> bool {
    match kill_pid(pid) {
        Ok(()) => {
            debug!("PID {} killed", pid);
            true
        }
        Err(e) => {
            warn!("YARA kill failed: pid={} error={}", pid, e);
            false
        }
    }
}

fn kill_pid(pid: i32) -> io::Result<()> {
    let me = nix::unistd::getpid().as_raw();

    if pid == me {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "refusing to kill self",
        ));
    }

    kill(Pid::from_raw(pid), Signal::SIGKILL)
        .map_err(|e| io::Error::from_raw_os_error(e as i32))?;

    Ok(())
}

#[cfg(target_os = "linux")]
fn get_procfs_exe_path(pid: i32) -> String {
    format!("/proc/{}/exe", pid)
}

#[cfg(target_os = "freebsd")]
fn get_procfs_exe_path(pid: i32) -> String {
    format!("/proc/{}/file", pid)
}

#[cfg(not(any(target_os = "linux", target_os = "freebsd")))]
fn get_procfs_exe_path(_pid: i32) -> String {
    String::new()
}

#[cfg(any(target_os = "linux", target_os = "freebsd"))]
fn get_pid_path(pid: i32) -> io::Result<String> {
    fs::read_link(get_procfs_exe_path(pid)).map(|p| p.to_string_lossy().into_owned())
}

#[cfg(not(any(target_os = "linux", target_os = "freebsd")))]
fn get_pid_path(_pid: i32) -> io::Result<String> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "get_pid_path is only supported on linux and freebsd",
    ))
}
