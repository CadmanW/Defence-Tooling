use crate::process::helper;
use chrono::{SecondsFormat, TimeZone};
use flying_ace_engine::ProcessEvent as EngineEvent;
use rb2_auditd::ExecEvent;

fn get_proc_comm(pid: u32) -> Option<String> {
    std::fs::read_to_string(format!("/proc/{pid}/comm"))
        .ok()
        .map(|s| s.trim_end_matches(&['\n', '\0'][..]).to_string())
        .filter(|s| !s.is_empty())
}

fn exec_event_failed(event: &ExecEvent) -> bool {
    if let Some(exit) = event.exit {
        return exit < 0;
    }

    matches!(event.success, Some(false))
}

pub(super) fn engine_event_from_exec_event(event: ExecEvent) -> EngineEvent {
    let exec_failed = exec_event_failed(&event);
    let status = event
        .exit
        .map(helper::exec_status)
        .or_else(|| match event.success {
            Some(true) => Some("success".to_string()),
            Some(false) => Some("failure".to_string()),
            None => None,
        });

    let process_sid = helper::get_proc_session_id(event.pid).unwrap_or(0);
    let comm = event.comm.unwrap_or_else(|| "unknown".to_string());
    let audit_exe = event.exe.filter(|s| !s.is_empty());
    let audit_cwd = event.cwd.filter(|s| !s.is_empty());
    let audit_argv = event.args;
    let audit_argv_joined = {
        let s = audit_argv.join(" ");
        if s.is_empty() { None } else { Some(s) }
    };

    let proc_exe = if exec_failed {
        None
    } else {
        helper::get_proc_exe(event.pid)
    };
    let proc_cwd = if exec_failed {
        None
    } else {
        helper::get_proc_cwd(event.pid)
    };
    let proc_argv = if exec_failed {
        None
    } else {
        helper::get_proc_argv(event.pid)
    };

    let process_args = if exec_failed {
        audit_argv_joined
    } else if let Some(proc_argv) = &proc_argv {
        if audit_argv.is_empty() || helper::argv_prefixes_match(proc_argv, &audit_argv) {
            let joined = proc_argv.join(" ");
            if joined.is_empty() {
                audit_argv_joined
            } else {
                Some(joined)
            }
        } else {
            audit_argv_joined
        }
    } else {
        audit_argv_joined
    };

    let process_executable = if exec_failed {
        audit_exe
    } else if let Some(proc_exe) = &proc_exe {
        match audit_exe.as_deref() {
            Some(audit) if helper::path_tail_matches(proc_exe, audit) || audit.is_empty() => {
                Some(proc_exe.clone())
            }
            None => Some(proc_exe.clone()),
            _ => audit_exe,
        }
    } else {
        audit_exe
    };

    let process_working_directory = if exec_failed {
        audit_cwd
    } else if let Some(proc_cwd) = &proc_cwd {
        match audit_cwd.as_deref() {
            Some(audit) if helper::path_tail_matches(proc_cwd, audit) || audit.is_empty() => {
                Some(proc_cwd.clone())
            }
            None => Some(proc_cwd.clone()),
            _ => audit_cwd,
        }
    } else {
        audit_cwd
    };

    let timestamp = chrono::Local
        .timestamp_opt(
            event.event_id.timestamp_sec as i64,
            (event.event_id.timestamp_ms * 1_000_000) as u32,
        )
        .single()
        .map(|ts| ts.to_rfc3339_opts(SecondsFormat::Millis, true))
        .unwrap_or_else(|| "unknown".to_string());

    let pname = event.ppid.and_then(get_proc_comm).or_else(|| {
        event.ppid.and_then(|ppid| {
            helper::get_proc_exe(ppid).and_then(|p| {
                std::path::Path::new(&p)
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
            })
        })
    });

    EngineEvent {
        timestamp,
        process_name: comm,
        process_pid: event.pid,
        process_sid,
        process_args,
        process_executable,
        process_ppid: event.ppid,
        process_pname: pname,
        process_working_directory,
        audit_loginuid: event.audit_loginuid,
        audit_sessionid: event.audit_sessionid,
        user_name: event.uid.and_then(helper::get_username),
        user_id: event.uid,
        event_category: "process-started".to_string(),
        event_module: Some("auditd".to_string()),
        status,
        ecs_version: "1.0.0".to_string(),
        host_name: helper::get_hostname(),
        host_id: helper::get_machine_id(),
    }
}
