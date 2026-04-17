use crate::config::yaml::YaraConfig;
use crate::yara::helper::handle_yara_path_match;
use crate::yara::yara_scan::CHUNK_SIZE_BYTES;
use fastrace::prelude::*;
use log::{debug, info, warn};
use lru::LruCache;
use nix::fcntl::AT_FDCWD;
use nix::poll::{PollFd, PollFlags, poll};
use nix::sys::fanotify::{
    EventFFlags, Fanotify, FanotifyResponse, InitFlags, MarkFlags, MaskFlags, Response,
};
use nix::sys::stat::fstat;
use nix::unistd::{Whence, lseek, read};
use std::collections::HashSet;
use std::num::NonZeroUsize;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd};
use std::sync::atomic::Ordering;
use tokio::sync::watch;
use yara_x::{Rules, ScanResults, blocks::Scanner};

#[derive(Clone)]
struct CacheEntry {
    is_safe: bool,
    rule_names: Vec<String>,
}

fn fd_to_path(fd: &BorrowedFd) -> String {
    let p = format!("/proc/self/fd/{}", fd.as_raw_fd());
    std::fs::read_link(&p)
        .map(|x| x.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "<unknown>".to_string())
}

fn read_to_fill(fd: &BorrowedFd, buf: &mut [u8]) -> usize {
    let mut read_index = 0;
    while read_index < buf.len() {
        match read(fd, &mut buf[read_index..]) {
            Ok(0) | Err(_) => break,
            Ok(bytes_read) => read_index += bytes_read,
        };
    }
    read_index
}

fn yara_scan_fd<'a>(
    fd: &BorrowedFd,
    scanner: &'a mut Scanner,
    buf: &mut Vec<u8>,
) -> anyhow::Result<ScanResults<'a, 'a>> {
    buf.resize(CHUNK_SIZE_BYTES.load(Ordering::Relaxed), 0);
    lseek(fd, 0, Whence::SeekSet)?;

    let mut offset = 0;
    loop {
        let read_len = read_to_fill(fd, buf);
        if read_len == 0 {
            break;
        }
        scanner.scan(offset, &buf[0..read_len])?;
        offset += read_len;
    }
    Ok(scanner.finish()?)
}

fn should_stop(shutdown_rx: &watch::Receiver<bool>) -> bool {
    *shutdown_rx.borrow()
}

fn write_allow(fd: &Fanotify, event_fd: BorrowedFd<'_>) {
    if let Err(err) = fd.write_response(FanotifyResponse::new(event_fd, Response::FAN_ALLOW)) {
        warn!("failed to fail-open YARA fanotify event during shutdown: {err}");
    }
}

pub fn yara_init_fanotify_scan(
    cfg: &YaraConfig,
    rules: &Rules,
    shutdown_rx: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let fd = Fanotify::init(
        InitFlags::FAN_CLOEXEC | InitFlags::FAN_CLASS_CONTENT,
        EventFFlags::O_RDONLY | EventFFlags::O_LARGEFILE,
    )?;

    fd.mark(
        MarkFlags::FAN_MARK_FILESYSTEM | MarkFlags::FAN_MARK_ADD,
        MaskFlags::FAN_OPEN_EXEC_PERM,
        AT_FDCWD,
        Some("/"),
    )?;

    let mut buf = vec![0u8; CHUNK_SIZE_BYTES.load(Ordering::Relaxed)];
    let mut cache = LruCache::new(NonZeroUsize::new(512).unwrap());
    let mut scanner = Scanner::new(rules);
    let disabled_rules: HashSet<String> = cfg.disabled_rules.iter().cloned().collect();

    info!("Yara fanotify scanning started");

    loop {
        if should_stop(&shutdown_rx) {
            debug!("YARA fanotify scanning stopping during shutdown");
            return Ok(());
        }

        let mut pollfd = [PollFd::new(fd.as_fd(), PollFlags::POLLIN)];
        match poll(&mut pollfd, 500u16) {
            Ok(0) => continue,
            Ok(_) => {}
            Err(nix::errno::Errno::EINTR) => continue,
            Err(err) => return Err(err.into()),
        }

        if should_stop(&shutdown_rx) {
            debug!("YARA fanotify scanning stopping during shutdown");
            return Ok(());
        }

        let events = Fanotify::read_events(&fd)?;
        for event in events {
            let Some(event_fd) = event.fd() else {
                continue;
            };

            if should_stop(&shutdown_rx) {
                write_allow(&fd, event_fd);
                continue;
            }

            let original_path = fd_to_path(&event_fd);
            let response;

            'scan: {
                let Ok(stat) = fstat(event_fd) else {
                    response = Response::FAN_ALLOW;
                    break 'scan;
                };

                let entry = match cache.get(&stat).cloned() {
                    Some(e) => e,
                    None => {
                        if should_stop(&shutdown_rx) {
                            response = Response::FAN_ALLOW;
                            break 'scan;
                        }

                        let _scan_span = Span::root("yara.scan_fanotify_fd", SpanContext::random())
                            .with_properties(|| vec![("path", original_path.clone())]);

                        let Ok(results) = yara_scan_fd(&event_fd, &mut scanner, &mut buf) else {
                            response = Response::FAN_ALLOW;
                            break 'scan;
                        };

                        if should_stop(&shutdown_rx) {
                            response = Response::FAN_ALLOW;
                            break 'scan;
                        }

                        let rule_names: Vec<String> = results
                            .matching_rules()
                            .filter(|rule| !disabled_rules.contains(rule.identifier()))
                            .map(|r| r.identifier().to_string())
                            .collect();

                        let is_safe = rule_names.is_empty();
                        let e = CacheEntry {
                            is_safe,
                            rule_names,
                        };
                        cache.put(stat, e.clone());
                        e
                    }
                };

                if !entry.is_safe {
                    if should_stop(&shutdown_rx) {
                        response = Response::FAN_ALLOW;
                        break 'scan;
                    }
                    let fd_path = format!("/proc/self/fd/{}", event_fd.as_raw_fd());
                    handle_yara_path_match(
                        None,
                        &original_path,
                        &entry.rule_names,
                        &cfg.actions,
                        &cfg.samples_dir,
                        "deny_exec",
                        &fd_path,
                    );

                    // enforcement only when actions.kill is enabled
                    if cfg.actions.kill {
                        response = Response::FAN_DENY;
                    } else {
                        response = Response::FAN_ALLOW;
                    }
                } else {
                    response = Response::FAN_ALLOW;
                }
            }

            if let Err(err) = fd.write_response(FanotifyResponse::new(event_fd, response)) {
                warn!("failed to write YARA fanotify response: {err}");
            }
        }
    }
}
