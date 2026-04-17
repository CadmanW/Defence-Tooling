use crate::firewall::BsmFirewallEvent;
use flying_ace_engine::ProcessEvent;
use log::{error, warn};
use nix::errno::Errno;
use nix::poll::{PollFd, PollFlags, poll};
use std::io::BufReader;
use std::os::fd::AsFd;
use tokio::sync::{mpsc, watch};

pub fn run_auditpipe(
    shutdown_rx: watch::Receiver<bool>,
    tx: mpsc::Sender<ProcessEvent>,
    fw_tx: Option<mpsc::Sender<BsmFirewallEvent>>,
) {
    let file = match std::fs::File::open("/dev/auditpipe") {
        Ok(f) => f,
        Err(e) => {
            error!("Failed to open /dev/auditpipe: {}", e);
            return;
        }
    };

    let mut reader = BufReader::new(file);

    loop {
        if *shutdown_rx.borrow() {
            break;
        }

        // Only poll if BufReader has no buffered bytes avoids blocking when
        // data is already buffered but the fd is not signalled as readable.
        if reader.buffer().is_empty() {
            let mut pollfd = [PollFd::new(reader.get_ref().as_fd(), PollFlags::POLLIN)];
            match poll(&mut pollfd, 500u16) {
                Ok(0) => continue, // timeout, loop back to check shutdown
                Ok(_) => {}
                Err(nix::errno::Errno::EINTR) => continue,
                Err(e) => {
                    warn!("poll error on auditpipe: {}", e);
                    break;
                }
            }
        }

        match bsm::read_record(&mut reader) {
            Ok(bsm::AuditRecord::Exec {
                timestamp,
                subject,
                exe,
                args,
                return_error,
                ..
            }) => {
                let event = engine_event_from_exec(timestamp, &subject, exe, args, return_error);
                if tx.blocking_send(event).is_err() {
                    warn!("process pipeline channel closed; stopping auditpipe consumer");
                    break;
                }
            }
            Ok(bsm::AuditRecord::Connect {
                timestamp,
                subject,
                remote,
                success,
                ..
            }) => {
                if let Some(addr) = remote {
                    process_net("connect", timestamp, &subject, addr, success);
                    if success {
                        send_fw_event(&fw_tx, "connect", &subject, addr);
                    }
                }
            }
            Ok(bsm::AuditRecord::Bind {
                timestamp,
                subject,
                local,
                success,
                ..
            }) => {
                if let Some(addr) = local {
                    process_net("bind", timestamp, &subject, addr, success);
                    if success {
                        send_fw_event(&fw_tx, "bind", &subject, addr);
                    }
                }
            }
            Ok(bsm::AuditRecord::Accept {
                timestamp,
                subject,
                remote,
                success,
                ..
            }) => {
                if let Some(addr) = remote {
                    process_net("accept", timestamp, &subject, addr, success);
                    if success {
                        send_fw_event(&fw_tx, "accept", &subject, addr);
                    }
                }
            }
            Ok(bsm::AuditRecord::Login {
                timestamp,
                subject,
                success,
                ..
            }) => {
                process_login("login", timestamp, &subject, success);
            }
            Ok(bsm::AuditRecord::Logout {
                timestamp, subject, ..
            }) => {
                process_login("logout", timestamp, &subject, true);
            }
            Ok(bsm::AuditRecord::SshLogin {
                timestamp,
                subject,
                success,
                ..
            }) => {
                process_login("login", timestamp, &subject, success);
            }
            Ok(bsm::AuditRecord::Su {
                timestamp,
                subject,
                success,
                ..
            }) => {
                process_login("su", timestamp, &subject, success);
            }
            Ok(bsm::AuditRecord::Sudo {
                timestamp,
                subject,
                args,
                failure_text,
                success,
                ..
            }) => {
                process_audit_event("sudo", timestamp, &subject, success, |log| {
                    log["command"] = serde_json::json!(args.join(" "));
                    if let Some(reason) = failure_text {
                        log["failure_reason"] = serde_json::json!(reason);
                    }
                });
            }
            Ok(bsm::AuditRecord::SetUid {
                timestamp,
                subject,
                new_uid,
                success,
                ..
            }) => {
                process_audit_event("setuid", timestamp, &subject, success, |log| {
                    log["new_uid"] = serde_json::json!(new_uid);
                });
            }
            Ok(bsm::AuditRecord::SetGid {
                timestamp,
                subject,
                new_gid,
                success,
                ..
            }) => {
                process_audit_event("setgid", timestamp, &subject, success, |log| {
                    log["new_gid"] = serde_json::json!(new_gid);
                });
            }
            Ok(bsm::AuditRecord::Ptrace {
                timestamp,
                subject,
                request,
                target_pid,
                data,
                success,
                ..
            }) => {
                process_audit_event("ptrace", timestamp, &subject, success, |log| {
                    log["request"] = serde_json::json!(request);
                    log["target_pid"] = serde_json::json!(target_pid);
                    log["data"] = serde_json::json!(data);
                });
            }
            Ok(bsm::AuditRecord::Ktrace {
                timestamp,
                subject,
                ops,
                trpoints,
                target_pid,
                output_file,
                success,
                ..
            }) => {
                process_audit_event("ktrace", timestamp, &subject, success, |log| {
                    log["ops"] = serde_json::json!(ops);
                    log["trpoints"] = serde_json::json!(trpoints);
                    log["target_pid"] = serde_json::json!(target_pid);
                    log["output_file"] = serde_json::json!(output_file);
                });
            }
            Ok(bsm::AuditRecord::ModLoad {
                timestamp,
                subject,
                success,
                ..
            }) => {
                process_audit_event("modload", timestamp, &subject, success, |_| {});
            }
            Ok(bsm::AuditRecord::ModUnload {
                timestamp,
                subject,
                success,
                ..
            }) => {
                process_audit_event("modunload", timestamp, &subject, success, |_| {});
            }
            Ok(bsm::AuditRecord::AuditShutdown {
                timestamp,
                subject,
                text,
                success,
                ..
            }) => {
                process_audit_event("audit_shutdown", timestamp, &subject, success, |log| {
                    log["text"] = serde_json::json!(text);
                });
            }
            Ok(bsm::AuditRecord::Passwd {
                timestamp,
                subject,
                text_tokens,
                success,
                ..
            }) => {
                process_audit_event("passwd", timestamp, &subject, success, |log| {
                    log["text_tokens"] = serde_json::json!(text_tokens);
                });
            }
            Ok(bsm::AuditRecord::ModifyPassword {
                timestamp,
                subject,
                text_tokens,
                success,
                ..
            }) => {
                process_audit_event("modify_password", timestamp, &subject, success, |log| {
                    log["text_tokens"] = serde_json::json!(text_tokens);
                });
            }
            Ok(bsm::AuditRecord::CreateUser {
                timestamp,
                subject,
                text_tokens,
                success,
                ..
            }) => {
                process_audit_event("create_user", timestamp, &subject, success, |log| {
                    log["text_tokens"] = serde_json::json!(text_tokens);
                });
            }
            Ok(bsm::AuditRecord::DeleteUser {
                timestamp,
                subject,
                text_tokens,
                success,
                ..
            }) => {
                process_audit_event("delete_user", timestamp, &subject, success, |log| {
                    log["text_tokens"] = serde_json::json!(text_tokens);
                });
            }
            Ok(bsm::AuditRecord::ModifyUser {
                timestamp,
                subject,
                text_tokens,
                success,
                ..
            }) => {
                process_audit_event("modify_user", timestamp, &subject, success, |log| {
                    log["text_tokens"] = serde_json::json!(text_tokens);
                });
            }
            Ok(_) => {}
            Err(bsm::ParseError::Io(ref io_err))
                if matches!(
                    io_err.raw_os_error(),
                    Some(libc::EINTR) | Some(libc::EAGAIN)
                ) =>
            {
                // Transient signal interrupt or non-blocking retry; loop back.
                continue;
            }
            Err(e) => {
                warn!("BSM read error: {}", e);
                break;
            }
        }
    }
}

fn send_fw_event(
    fw_tx: &Option<mpsc::Sender<BsmFirewallEvent>>,
    op: &'static str,
    subject: &bsm::Subject,
    addr: std::net::SocketAddr,
) {
    let Some(tx) = fw_tx else { return };
    let ip = addr.ip();
    // Skip loopback; the firewall cares about external traffic.
    if ip.is_loopback() || ip.is_unspecified() {
        return;
    }
    let ev = BsmFirewallEvent {
        pid: subject.pid as i32,
        comm: crate::sysctl::get_process_name(subject.pid as i32),
        dport: Some(addr.port()),
        ip: Some(ip.to_string()),
        op: Some(op.to_string()),
    };
    if let Err(e) = tx.blocking_send(ev) {
        warn!("BSM firewall channel send failed: {}", e);
    }
}

// Exec
fn engine_event_from_exec(
    timestamp: u64,
    subject: &bsm::Subject,
    exe: Option<String>,
    args: Vec<String>,
    return_error: Option<u8>,
) -> ProcessEvent {
    let uid = subject.uid;
    let pid = subject.pid;
    let user = lookup_username(uid);
    let exe = exe.unwrap_or_default();
    let process_args = {
        let joined = args.join(" ");
        if joined.is_empty() {
            None
        } else {
            Some(joined)
        }
    };

    let ppid = crate::sysctl::get_ppid(pid);
    let parent_name = ppid
        .and_then(|p| crate::sysctl::get_exe_path(p as _))
        .and_then(|p| p.rsplit('/').next().map(|s| s.to_string()))
        .unwrap_or_else(|| "unknown".to_string());

    let cwd = crate::sysctl::get_cwd(pid as i32).unwrap_or_else(|| "unknown".to_string());

    let ts_rfc3339 = chrono::DateTime::from_timestamp(timestamp as i64, 0)
        .map(|dt: chrono::DateTime<chrono::Utc>| dt.to_rfc3339())
        .unwrap_or_else(|| timestamp.to_string());

    ProcessEvent {
        timestamp: ts_rfc3339,
        process_name: rb2_ml::basename(&exe).to_string(),
        process_pid: pid,
        process_sid: subject.session_id,
        process_args,
        process_executable: Some(exe.clone()),
        process_ppid: ppid,
        process_pname: Some(parent_name.clone()),
        process_working_directory: Some(cwd.clone()),
        audit_loginuid: subject.audit_id,
        audit_sessionid: subject.session_id,
        user_name: Some(user.clone()),
        user_id: Some(uid),
        event_category: "process-started".to_string(),
        event_module: Some("bsm".to_string()),
        status: Some(exec_status(return_error)),
        ecs_version: "1.0.0".to_string(),
        host_name: rb2_userspace::misc::get_hostname(),
        host_id: rb2_userspace::misc::get_machine_id(),
    }
}

fn exec_status(return_error: Option<u8>) -> String {
    match return_error {
        None | Some(0) => "success".to_string(),
        Some(errno) => match Errno::from_raw(i32::from(errno)) {
            Errno::UnknownErrno => format!("ERRNO_{errno}"),
            known => format!("{known:?}"),
        },
    }
}

// Login

fn process_login(event: &'static str, timestamp: u64, subject: &bsm::Subject, success: bool) {
    let pid = subject.pid;
    let rhost = subject.terminal.map(|ip| ip.to_string());

    let comm = crate::sysctl::get_process_name(pid as i32);

    let log = serde_json::json!({
        "_timestamp": timestamp * 1000,
        "event": event,
        "result": if success { "success" } else { "failure" },
        "resolved_user": lookup_username(subject.uid),
        "audit_loginuid": subject.audit_id,
        "audit_sessionid": subject.session_id,
        "comm": comm,
        "pid": pid,
        "rhost": rhost,
        "host_id": rb2_userspace::misc::get_machine_id(),
        "host_name": rb2_userspace::misc::get_hostname(),
        "event_module": "bsm",
    });

    log::info!(target: "rb2_auth", "{}", log);
}

// Network

fn process_net(
    op: &'static str,
    timestamp: u64,
    subject: &bsm::Subject,
    addr: std::net::SocketAddr,
    success: bool,
) {
    let pid = subject.pid;
    let uid = subject.uid;

    let comm = crate::sysctl::get_process_name(pid as i32);

    let path = crate::sysctl::get_exe_path(pid as i32);

    let log = serde_json::json!({
        "_timestamp": timestamp * 1000,
        "op": op,
        "pid": pid,
        "user_name": lookup_username(uid),
        "user_id": uid,
        "ip": addr.ip().to_string(),
        "port": addr.port(),
        "comm": comm,
        "path": path,
        "result": if success { "success" } else { "failure" },
        "host_id": rb2_userspace::misc::get_machine_id(),
        "host_name": rb2_userspace::misc::get_hostname(),
        "event_module": "bsm",
        "log_type": "network",
    });
    log::info!(target: "rb2_firewall", "{}", log);
}

// Audit events

fn process_audit_event(
    event: &'static str,
    timestamp: u64,
    subject: &bsm::Subject,
    success: bool,
    extra: impl FnOnce(&mut serde_json::Value),
) {
    let pid = subject.pid;
    let uid = subject.uid;
    let comm = crate::sysctl::get_process_name(pid as i32);

    let mut log = serde_json::json!({
        "_timestamp": timestamp * 1000,
        "event": event,
        "result": if success { "success" } else { "failure" },
        "pid": pid,
        "user_name": lookup_username(uid),
        "user_id": uid,
        "audit_loginuid": subject.audit_id,
        "audit_sessionid": subject.session_id,
        "comm": comm,
        "host_id": rb2_userspace::misc::get_machine_id(),
        "host_name": rb2_userspace::misc::get_hostname(),
        "event_module": "bsm",
    });

    extra(&mut log);

    log::info!(target: "rb2_audit", "{}", log);
}

// Helpers
fn lookup_username(uid: u32) -> String {
    use nix::unistd::{Uid, User};
    User::from_uid(Uid::from_raw(uid))
        .ok()
        .flatten()
        .map(|u| u.name)
        .unwrap_or_else(|| uid.to_string())
}
