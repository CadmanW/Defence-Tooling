use chrono::SecondsFormat;
use log::info;
use lru::LruCache;
use nix::{
    fcntl::AT_FDCWD,
    sys::fanotify::{EventFFlags, Fanotify, FanotifyEvent, InitFlags, MarkFlags, MaskFlags},
};
use serde_json::json;
use std::num::NonZeroUsize;
use std::os::fd::{AsRawFd, BorrowedFd};
use std::path::PathBuf;

use crate::{
    config::yaml::FileIntegrityConfig,
    misc::{get_hostname, get_machine_id},
};

fn fd_to_path(fd: &BorrowedFd) -> Option<PathBuf> {
    let p = format!("/proc/self/fd/{}", fd.as_raw_fd());
    std::fs::read_link(&p).ok()
}

fn operation_labels(mask: MaskFlags) -> Vec<&'static str> {
    let mut labels = Vec::new();

    if mask.contains(MaskFlags::FAN_Q_OVERFLOW) {
        labels.push("queue_overflow");
    }
    if mask.contains(MaskFlags::FAN_MODIFY) {
        labels.push("modify");
    }
    if mask.contains(MaskFlags::FAN_DELETE) {
        labels.push("delete");
    }
    if mask.contains(MaskFlags::FAN_DELETE_SELF) {
        labels.push("delete_self");
    }
    if mask.contains(MaskFlags::FAN_MOVED_FROM) {
        labels.push("moved_from");
    }
    if mask.contains(MaskFlags::FAN_MOVED_TO) {
        labels.push("moved_to");
    }
    if labels.is_empty() && mask.contains(MaskFlags::FAN_MOVE) {
        labels.push("move");
    }
    if mask.contains(MaskFlags::FAN_ATTRIB) {
        labels.push("attrib");
    }
    if mask.contains(MaskFlags::FAN_CLOSE_WRITE) {
        labels.push("close_write");
    }
    if mask.contains(MaskFlags::FAN_CLOSE_NOWRITE) {
        labels.push("close_nowrite");
    }
    if mask.contains(MaskFlags::FAN_OPEN) {
        labels.push("open");
    }
    if mask.contains(MaskFlags::FAN_ACCESS) {
        labels.push("access");
    }
    if mask.contains(MaskFlags::FAN_CREATE) {
        labels.push("create");
    }
    if mask.contains(MaskFlags::FAN_MOVE_SELF) {
        labels.push("move_self");
    }
    if mask.contains(MaskFlags::FAN_OPEN_EXEC) {
        labels.push("open_exec");
    }
    if mask.contains(MaskFlags::FAN_FS_ERROR) {
        labels.push("fs_error");
    }

    labels
}

fn build_fim_event(path: &PathBuf, pid: i32, mask: MaskFlags) -> serde_json::Value {
    json!({
        "timestamp": chrono::Local::now().to_rfc3339_opts(SecondsFormat::Millis, true),
        "path": path,
        "ops": operation_labels(mask),
        "pid": pid,
        "is_dir": mask.contains(MaskFlags::FAN_ONDIR),
        "host_name": get_hostname(),
        "host_id": get_machine_id(),
    })
}

fn event_payload(event: &FanotifyEvent, path: &PathBuf) -> serde_json::Value {
    let mask = event.mask();

    build_fim_event(path, event.pid(), mask)
}

pub fn init_fanotify_monitoring(cfg: &FileIntegrityConfig) -> anyhow::Result<()> {
    let fd = Fanotify::init(
        InitFlags::FAN_CLOEXEC,
        EventFFlags::O_RDONLY | EventFFlags::O_LARGEFILE,
    )?;

    fd.mark(
        MarkFlags::FAN_MARK_ADD | MarkFlags::FAN_MARK_FILESYSTEM,
        MaskFlags::FAN_MODIFY,
        AT_FDCWD,
        Some("/"),
    )?;

    let mut dedup_cache = LruCache::new(NonZeroUsize::new(4).unwrap());

    loop {
        let events = Fanotify::read_events(&fd)?;

        for event in events {
            let Some(event_fd) = event.fd() else {
                continue;
            };
            let Some(path) = fd_to_path(&event_fd) else {
                continue;
            };
            for log_path in &cfg.log_paths {
                if path.starts_with(log_path) {
                    let key = (path.clone(), event.pid());
                    if dedup_cache.get(&key).is_some() {
                        break;
                    } else {
                        dedup_cache.put(key, ());
                    }
                    let payload = event_payload(&event, &path);

                    info!(target: "rb2_fim", "{}", payload);
                    break;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_fim_event_uses_json_shape() {
        let event = build_fim_event(&PathBuf::from("/etc/passwd"), 1234, MaskFlags::FAN_MODIFY);

        assert_eq!(event["ops"], json!(["modify"]));
        assert_eq!(event["is_dir"], false);
        assert_eq!(event["path"], "/etc/passwd");
        assert_eq!(event["pid"], 1234);
        assert!(event.get("timestamp").is_some());
    }

    #[test]
    fn operation_labels_include_specific_move_flags() {
        let mask = MaskFlags::FAN_MOVED_FROM | MaskFlags::FAN_ONDIR;

        assert_eq!(operation_labels(mask), vec!["moved_from"]);
    }

    #[test]
    fn operation_labels_are_ordered_by_importance() {
        let mask = MaskFlags::FAN_CREATE | MaskFlags::FAN_MODIFY | MaskFlags::FAN_DELETE;

        assert_eq!(operation_labels(mask), vec!["modify", "delete", "create"]);
    }
}
