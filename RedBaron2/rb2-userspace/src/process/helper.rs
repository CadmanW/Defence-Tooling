use nix::errno::Errno;
use std::collections::HashMap;
use std::path::{Component, Path};
use std::sync::RwLock;
use std::time::{Duration, Instant};
use std::{fs, io, sync::OnceLock};

// Re-export host utilities so existing callers (process_monitor) keep working.
pub use crate::misc::{get_hostname, get_machine_id};

// uid -> (username, timestamp)
type UserCache = HashMap<u32, (String, Instant)>;
type PasswdMap = HashMap<u32, String>;
type PasswdCache = Option<(PasswdMap, Instant)>;

static USER_CACHE: OnceLock<RwLock<UserCache>> = OnceLock::new();
static PASSWD_CACHE: OnceLock<RwLock<PasswdCache>> = OnceLock::new();
const CACHE_TTL: Duration = Duration::from_secs(60);

fn get_user_cache() -> &'static RwLock<UserCache> {
    USER_CACHE.get_or_init(|| RwLock::new(HashMap::new()))
}

fn get_passwd_cache() -> &'static RwLock<PasswdCache> {
    PASSWD_CACHE.get_or_init(|| RwLock::new(None))
}

// Minimal /etc/passwd lookup (no extra deps)
fn read_passwd_map() -> Option<PasswdMap> {
    let content = fs::read_to_string("/etc/passwd").ok()?;
    let mut users = HashMap::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // name:passwd:uid:gid:gecos:home:shell
        let mut parts = line.split(':');
        let name = parts.next()?;
        let _passwd = parts.next();
        let uid_field = parts.next()?;
        if let Ok(uid) = uid_field.parse::<u32>() {
            users.insert(uid, name.to_string());
        }
    }
    Some(users)
}

/// Cached lookup with staleness window.
pub fn get_username(uid: u32) -> Option<String> {
    // Fast: get from cache
    {
        let map = get_user_cache().read().unwrap();
        if let Some((val, ts)) = map.get(&uid)
            && ts.elapsed() < CACHE_TTL
        {
            return Some(val.clone());
        }
    }

    {
        let cache = get_passwd_cache().read().unwrap();
        if let Some((users, ts)) = cache.as_ref()
            && ts.elapsed() < CACHE_TTL
            && let Some(fresh) = users.get(&uid)
        {
            let fresh = fresh.clone();
            let mut map = get_user_cache().write().unwrap();
            map.insert(uid, (fresh.clone(), Instant::now()));
            drop(map);
            return Some(fresh);
        }
    }

    // Slow: refresh from /etc/passwd
    if let Some(users) = read_passwd_map() {
        let fresh = users.get(&uid).cloned();
        {
            let mut cache = get_passwd_cache().write().unwrap();
            *cache = Some((users, Instant::now()));
        }

        if let Some(fresh) = fresh {
            let mut map = get_user_cache().write().unwrap();
            map.insert(uid, (fresh.clone(), Instant::now()));
            drop(map);
            return Some(fresh);
        }
    }

    let mut map = get_user_cache().write().unwrap();
    map.remove(&uid);

    None
}

fn read_proc_link(pid: u32, name: &str) -> io::Result<String> {
    let link = fs::read_link(format!("/proc/{}/{}", pid, name))?;
    // Linux may append " (deleted)" to exe; strip it for comparison/display.
    let mut s = link.to_string_lossy().into_owned();
    if s.ends_with(" (deleted)") {
        s.truncate(s.len() - " (deleted)".len());
    }
    Ok(s)
}

pub fn get_proc_exe(pid: u32) -> Option<String> {
    read_proc_link(pid, "exe").ok()
}

pub fn get_proc_cwd(pid: u32) -> Option<String> {
    read_proc_link(pid, "cwd").ok()
}

pub fn get_proc_argv(pid: u32) -> Option<Vec<String>> {
    // /proc/<pid>/cmdline is NUL-separated and may end with a trailing NUL
    let path = format!("/proc/{}/cmdline", pid);
    let bytes = fs::read(path).ok()?;
    let parts = bytes
        .split(|&b| b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .collect();
    Some(parts)
}

/// Kernel process session ID (session leader PID) from /proc/<pid>/stat.
/// This matches what eBPF reads (task session), unlike audit's "ses" which is
/// the audit sessionid (userspace-set for audit correlation).
pub fn get_proc_session_id(pid: u32) -> Option<u32> {
    let path = format!("/proc/{}/stat", pid);
    let stat = fs::read_to_string(path).ok()?;
    // Format: pid (comm) state ppid pgrp session ...
    // comm can contain spaces and parens, so find the last ')' that closes comm
    let close = stat.rfind(')')?;
    let rest = stat.get(close + 1..)?.trim_start();
    // state=0, ppid=1, pgrp=2, session=3
    rest.split_whitespace().nth(3).and_then(|s| s.parse().ok())
}

fn split_norm_components(path: &str) -> Vec<String> {
    Path::new(path)
        .components()
        .filter_map(|c| match c {
            Component::RootDir => None,
            Component::CurDir => None,
            Component::ParentDir => None,
            Component::Normal(os) => Some(os.to_string_lossy().into_owned()),
            _ => None,
        })
        .collect()
}

/// Check that `ebpf_tail` (possibly truncated from the left) matches the tail of `proc_full`.
/// If ebpf is empty, we consider it a match (let /proc win).
pub fn path_tail_matches(proc_full: &str, ebpf_tail: &str) -> bool {
    if ebpf_tail.is_empty() {
        return true;
    }
    let full = split_norm_components(proc_full);
    let tail = split_norm_components(ebpf_tail);
    if tail.is_empty() {
        return true;
    }
    if tail.len() > full.len() {
        return false;
    }
    let start = full.len() - tail.len();
    full[start..] == tail
}

/// Verify that the limited eBPF argv prefixes match the /proc argv.
/// Each eBPF arg (possibly truncated) must be a prefix of the corresponding /proc arg.
/// If eBPF argv is empty, we consider it a match (let /proc win).
pub fn argv_prefixes_match(proc_args: &[String], ebpf_args: &[String]) -> bool {
    if ebpf_args.is_empty() {
        return true;
    }
    let n = ebpf_args.len().min(proc_args.len());
    for i in 0..n {
        let eb = &ebpf_args[i];
        if eb.is_empty() {
            continue;
        }
        let pr = &proc_args[i];
        if !pr.starts_with(eb) {
            return false;
        }
    }
    true
}

pub fn exec_status(ret: i64) -> String {
    if ret >= 0 {
        return "success".to_string();
    }

    let errno = (-ret).clamp(0, i64::from(i32::MAX)) as i32;
    match Errno::from_raw(errno) {
        Errno::UnknownErrno => format!("ERRNO_{errno}"),
        known => format!("{known:?}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_norm_components() {
        assert_eq!(
            split_norm_components("/usr//local/./bin/bash"),
            vec!["usr", "local", "bin", "bash"]
        );
    }

    #[test]
    fn test_path_tail_matches() {
        assert!(path_tail_matches("/usr/bin/bash", "/bin/bash"));
        assert!(path_tail_matches("/usr/bin/bash", ""));
        assert!(path_tail_matches("/usr/sbin/nginx", "/nginx"));
        assert!(!path_tail_matches("/usr/bin/bash", "/sbin/bash"));
        assert!(!path_tail_matches("/usr/bin/bash", "/usr/bin/bash/extra"));
    }

    #[test]
    fn test_argv_prefixes_match() {
        let proc = vec![
            "python3".to_string(),
            "-m".to_string(),
            "http.server".to_string(),
        ];
        let ebpf_good = vec!["py".to_string(), "-".to_string(), "http".to_string()];
        let ebpf_empty: Vec<String> = vec![];
        let ebpf_bad = vec!["ruby".to_string()];

        assert!(argv_prefixes_match(&proc, &ebpf_good));
        assert!(argv_prefixes_match(&proc, &ebpf_empty));
        assert!(!argv_prefixes_match(&proc, &ebpf_bad));
    }

    #[test]
    fn test_get_proc_session_id() {
        assert_eq!(get_proc_session_id(99_999_999), None);
        let my_pid = std::process::id();
        let sid = get_proc_session_id(my_pid);
        assert!(sid.is_some(), "current process should have /proc/stat");
        assert!(
            sid.unwrap() > 0,
            "session id is typically the session leader pid"
        );
    }

    #[test]
    fn test_exec_status() {
        assert_eq!(exec_status(0), "success");
        assert_eq!(exec_status(-2), "ENOENT");
    }
}
