use crate::firewall::event::nfq::Ipv4Key;
use crate::misc::{get_hostname, get_machine_id};
use chrono::SecondsFormat;
use log::{debug, info, warn};
use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use std::{
    collections::HashSet,
    fs,
    fs::File,
    io::{self, BufRead, BufReader},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::{Path, PathBuf},
};

fn socket_table_fields(line: &str) -> Option<(&str, &str, &str, &str)> {
    let mut parts = line.split_whitespace();
    parts.next()?;
    let local = parts.next()?;
    let remote = parts.next()?;
    let state = parts.next()?;
    let inode = parts.nth(5)?;
    Some((local, remote, state, inode))
}

pub async fn enumerate_udp_sockets(
    allow_paths: &HashSet<PathBuf>,
    enforcing: bool,
) -> io::Result<()> {
    kill_disallowed_sockets("/proc/net/udp", allow_paths, enforcing).await?;
    kill_disallowed_sockets("/proc/net/udp6", allow_paths, enforcing).await
}

pub async fn enumerate_tcp_sockets(
    allow_paths: &HashSet<PathBuf>,
    enforcing: bool,
) -> io::Result<()> {
    kill_disallowed_sockets("/proc/net/tcp", allow_paths, enforcing).await?;
    kill_disallowed_sockets("/proc/net/tcp6", allow_paths, enforcing).await
}

// needed for nfq
// XXX: should I move this?
pub fn socket_exists(key: &Ipv4Key, target_pid: i32) -> bool {
    let k_sport = key.sport;
    let k_dport = key.dport;
    let k_daddr = key.daddr;

    for path in ["/proc/net/tcp", "/proc/net/udp"] {
        if let Ok(file) = File::open(path) {
            let reader = BufReader::new(file);
            for line in reader.lines().skip(1).flatten() {
                let Some((local, remote, state, inode_str)) = socket_table_fields(&line) else {
                    continue;
                };

                // 01 = TCP_ESTABLISHED, 02 = TCP_SYN_SENT, 03 = TCP_SYN_RECV
                if path.contains("tcp") && !["01", "02", "03"].contains(&state) {
                    continue;
                }

                let (_, sport) = match parse_socket_endpoint(local) {
                    Some(v) => v,
                    None => continue,
                };
                let (daddr, dport) = match parse_socket_endpoint(remote) {
                    Some(v) => v,
                    None => continue,
                };

                if let Ok(inode) = inode_str.parse::<u64>()
                    && let Some(pid) = find_pid_by_inode(inode)
                {
                    if pid != target_pid {
                        continue;
                    }

                    if daddr.is_unspecified() && dport == 0 {
                        // For UDP, remote might be 0:0 until first packet is sent
                        if path.contains("udp") && pid == target_pid && k_sport == sport {
                            return true;
                        }
                        // Skip TCP listening sockets
                        continue;
                    }

                    if path.contains("tcp") && daddr.is_unspecified() && dport == 0 {
                        continue;
                    }

                    if pid == target_pid
                        && matches!(daddr, IpAddr::V4(addr) if u32::from(addr) == k_daddr)
                        && k_sport == sport
                        && k_dport == dport
                    {
                        return true;
                    }
                }
            }
        }
    }

    false
}

pub fn get_active_socket_paths() -> anyhow::Result<Vec<PathBuf>> {
    let mut paths = list_active_socket_paths("/proc/net/tcp")?;
    paths.extend(list_active_socket_paths("/proc/net/tcp6")?);
    paths.extend(list_active_socket_paths("/proc/net/udp")?);
    paths.extend(list_active_socket_paths("/proc/net/udp6")?);
    paths.sort();
    paths.dedup();
    Ok(paths)
}

/// List executable paths that have at least one active (non-local) socket
fn list_active_socket_paths(socket_table_path: &str) -> anyhow::Result<Vec<PathBuf>> {
    let file = File::open(socket_table_path)?;
    let reader = BufReader::new(file);
    let mut paths: Vec<PathBuf> = Vec::new();

    for line in reader.lines().skip(1) {
        let line = line?;
        let Some((local, remote, _state, inode_str)) = socket_table_fields(&line) else {
            continue;
        };

        let (local_ip, _local_port) = match parse_socket_endpoint(local) {
            Some(v) => v,
            None => continue,
        };
        let (remote_ip, _remote_port) = match parse_socket_endpoint(remote) {
            Some(v) => v,
            None => continue,
        };

        // Skip sockets where both endpoints are loopback
        if is_local_ip(&local_ip) && is_local_ip(&remote_ip) {
            continue;
        }

        let inode = match inode_str.parse::<u64>() {
            Ok(v) => v,
            Err(_) => continue,
        };
        if inode == 0 {
            continue;
        }

        let pid = match find_pid_by_inode(inode) {
            Some(pid) => pid,
            None => continue,
        };

        if let Some(exe_path_str) = get_exe_path(pid) {
            paths.push(PathBuf::from(exe_path_str));
        }
    }

    Ok(paths)
}

/// Kills disallowed pre-existing sockets on non-local bindings,
/// and logs to the firewall file target
async fn kill_disallowed_sockets(
    socket_table_path: &str,
    allow_paths: &HashSet<PathBuf>,
    enforcing: bool,
) -> io::Result<()> {
    use tokio::{
        fs::File,
        io::{AsyncBufReadExt, BufReader},
    };
    let file = File::open(socket_table_path).await?;
    let reader = BufReader::new(file);
    let mut lines = reader.lines();

    // skip header
    lines.next_line().await?;

    while let Some(line) = lines.next_line().await? {
        let Some((local, remote, _state, inode_str)) = socket_table_fields(&line) else {
            continue;
        };

        let (local_ip, local_port) = match parse_socket_endpoint(local) {
            Some(v) => v,
            None => continue,
        };
        let (remote_ip, remote_port) = match parse_socket_endpoint(remote) {
            Some(v) => v,
            None => continue,
        };

        if is_local_ip(&local_ip) && is_local_ip(&remote_ip) {
            continue;
        }

        let inode = match inode_str.parse::<u64>() {
            Ok(v) => v,
            Err(_) => continue,
        };
        if inode == 0 {
            continue;
        }

        let pid = match find_pid_by_inode_async(inode).await {
            Some(pid) => pid,
            None => {
                info!("Could not find pid by inode {}", inode);
                continue;
            }
        };

        let exe_path_str = match get_exe_path_async(pid).await {
            Some(p) => p,
            None => {
                info!("Could not find exe_path_str by pid {}", pid);
                continue;
            }
        };

        let exe_path = Path::new(&exe_path_str);
        let allow = allow_paths.contains(exe_path);

        // console log
        let action = if !allow { "DENY" } else { "ALLOW" };
        if !allow {
            info!(
                "path={} pid={} action={} enforcing={} saddr={} sport={} daddr={} dport={}",
                exe_path_str, pid, action, enforcing, local_ip, local_port, remote_ip, remote_port
            );
        } else {
            debug!(
                "path={} pid={} action={} enforcing={} saddr={} sport={} daddr={} dport={}",
                exe_path_str, pid, action, enforcing, local_ip, local_port, remote_ip, remote_port
            );
        }

        if !allow {
            // kill logic
            if enforcing {
                match kill_pid(pid) {
                    Ok(()) => debug!("Killed pid: {} with active sockets", pid),
                    Err(e) => warn!(
                        "Failed to kill pid {} path {} with active sockets: {}",
                        pid, exe_path_str, e
                    ),
                }
            } else {
                warn!(
                    "Would have killed pid {} path {} if enforcing due to active socket",
                    pid, exe_path_str
                );
            }

            // log denies to file + send out of function in offenders
            let ts = chrono::Local::now().to_rfc3339_opts(SecondsFormat::Millis, true);
            let json = serde_json::json!({
                "timestamp": ts,
                "decision": action,
                "enforcing": enforcing,
                "pid": pid,
                "path": exe_path_str,
                "ip": local_ip.to_string(),
                "port": local_port,
                "remote_ip": remote_ip.to_string(),
                "remote_port": remote_port,
                "op": "existing_socket",
                "host_name": get_hostname(),
                "host_id": get_machine_id(),
            });

            info!(target: "rb2_firewall", "{}", json);
        }
    }

    Ok(())
}

fn is_local_ip(ip: &IpAddr) -> bool {
    ip.is_loopback()
}

pub fn kill_pid(pid: i32) -> io::Result<()> {
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

/// returns the pid associated with the inode entry
fn find_pid_by_inode(target_inode: u64) -> Option<i32> {
    for entry in fs::read_dir("/proc").ok()? {
        let pid_dir = entry.ok()?.path();
        let pid_str = pid_dir.file_name()?.to_string_lossy();
        let pid: i32 = match pid_str.parse() {
            Ok(n) => n,
            Err(_) => continue, // skip non-numeric directories
        };
        let fd_dir = pid_dir.join("fd");

        let fd_entries = match fs::read_dir(&fd_dir) {
            Ok(entries) => entries,
            Err(_) => continue,
        };

        for fd in fd_entries {
            let fd_path = match fd {
                Ok(p) => p.path(),
                Err(_) => continue,
            };

            let link = match fs::read_link(&fd_path) {
                Ok(link) => link.to_string_lossy().to_string(),
                Err(_) => continue,
            };

            if link.starts_with("socket:[")
                && let Some(inode_str) = link
                    .strip_prefix("socket:[")
                    .and_then(|s| s.strip_suffix("]"))
                && let Ok(inode) = inode_str.parse::<u64>()
                && inode == target_inode
            {
                return Some(pid);
            }
        }
    }
    None
}

async fn find_pid_by_inode_async(target_inode: u64) -> Option<i32> {
    if target_inode == 0 {
        return None;
    }

    let mut proc = tokio::fs::read_dir("/proc").await.ok()?;

    loop {
        let entry = match proc.next_entry().await {
            Ok(Some(e)) => e,
            Ok(None) => break,
            Err(_) => continue,
        };

        let pid_str = entry.file_name().to_string_lossy().to_string();
        let pid: i32 = match pid_str.parse() {
            Ok(n) => n,
            Err(_) => continue,
        };

        let fd_dir = entry.path().join("fd");
        let mut fds = match tokio::fs::read_dir(&fd_dir).await {
            Ok(d) => d,
            Err(_) => continue,
        };

        loop {
            let fd = match fds.next_entry().await {
                Ok(Some(f)) => f,
                Ok(None) => break,
                Err(_) => continue,
            };

            let link = match tokio::fs::read_link(fd.path()).await {
                Ok(l) => l,
                Err(_) => continue,
            };

            let link = link.to_string_lossy();
            if link.starts_with("socket:[")
                && let Some(inode_str) = link
                    .strip_prefix("socket:[")
                    .and_then(|s| s.strip_suffix(']'))
                && let Ok(inode) = inode_str.parse::<u64>()
                && inode == target_inode
            {
                return Some(pid);
            }
        }
    }

    None
}

fn get_exe_path(pid: i32) -> Option<String> {
    fs::read_link(format!("/proc/{}/exe", pid))
        .ok()
        .map(|p| p.to_string_lossy().to_string())
}

async fn get_exe_path_async(pid: i32) -> Option<String> {
    tokio::fs::read_link(format!("/proc/{}/exe", pid))
        .await
        .ok()
        .map(|p| p.to_string_lossy().to_string())
}

fn parse_socket_endpoint(field: &str) -> Option<(IpAddr, u16)> {
    let mut parts = field.split(':');
    let ip = parts.next()?;
    let port = parts.next()?;

    let port = parse_hex_u16(port)?;

    Some((parse_proc_ip(ip)?, port))
}

fn parse_proc_ip(hex: &str) -> Option<IpAddr> {
    match hex.len() {
        8 => Some(IpAddr::V4(parse_proc_ipv4(hex)?)),
        32 => Some(IpAddr::V6(parse_proc_ipv6(hex)?)),
        _ => None,
    }
}

fn parse_proc_ipv4(hex: &str) -> Option<Ipv4Addr> {
    let ip_num = parse_hex_u32(hex)?;
    Some(Ipv4Addr::from(u32::from_be(ip_num)))
}

fn parse_proc_ipv6(hex: &str) -> Option<Ipv6Addr> {
    let mut bytes = [0u8; 16];
    for (i, chunk) in hex.as_bytes().chunks_exact(8).enumerate() {
        let chunk = std::str::from_utf8(chunk).ok()?;
        let word = u32::from_str_radix(chunk, 16).ok()?;
        bytes[i * 4..(i + 1) * 4].copy_from_slice(&word.to_le_bytes());
    }
    Some(Ipv6Addr::from(bytes))
}

fn parse_hex_u16(s: &str) -> Option<u16> {
    u16::from_str_radix(s, 16).ok()
}

fn parse_hex_u32(s: &str) -> Option<u32> {
    u32::from_str_radix(s, 16).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ipv4_socket_endpoint() {
        let endpoint = parse_socket_endpoint("0100007F:0016").expect("ipv4 endpoint");
        assert_eq!(endpoint, (IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 22));
    }

    #[test]
    fn parses_ipv6_socket_endpoint() {
        let endpoint =
            parse_socket_endpoint("00000000000000000000000001000000:01BB").expect("ipv6 endpoint");
        assert_eq!(endpoint, (IpAddr::V6(Ipv6Addr::LOCALHOST), 443));
    }

    #[test]
    fn detects_loopback_for_ipv4_and_ipv6() {
        assert!(is_local_ip(&IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(is_local_ip(&IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert!(!is_local_ip(&IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));
    }
}
