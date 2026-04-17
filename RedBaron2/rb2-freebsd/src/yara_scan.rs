use fastrace::prelude::*;
use log::{debug, info, warn};
use rb2_userspace::config::yaml::YaraConfig;
use rb2_userspace::yara::handle_yara_match;
use std::fs::File;
use std::{
    cmp::min,
    collections::{HashMap, HashSet},
    error::Error,
    io::{self},
    os::unix::fs::FileExt,
    path::Path,
    process,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering, Ordering as AtomicOrdering},
    thread::sleep,
    time::{Duration, Instant},
};
use sysinfo::{Pid as SysPid, ProcessRefreshKind, ProcessesToUpdate, System};
use xxhash_rust::xxh3;
use xxhash_rust::xxh3::Xxh3DefaultBuilder;
use yara_x::{Rules, blocks::Scanner};

use crate::sysctl::{get_exe_inode, get_process_name, sysctl_buf};

/// Default max bytes per YARA scan chunk (10 MiB). Adjustable at runtime.
pub static CHUNK_SIZE_BYTES: AtomicUsize = AtomicUsize::new(10 * 1024 * 1024);

/// Optionally adjust the maximum bytes scanned per rule chunk.
pub fn set_max_scan_bytes_per_rule(bytes: usize) {
    let min_bytes = 1024; // 1 KiB
    let value = if bytes < min_bytes { min_bytes } else { bytes };
    CHUNK_SIZE_BYTES.store(value, Ordering::Relaxed);
}

/// Default full scan interval if not specified in config (5 minutes)
const DEFAULT_FULL_SCAN_INTERVAL_SECS: u64 = 5 * 60;
/// Default polling interval if not specified in config
const DEFAULT_POLL_INTERVAL_SECS: u64 = 1;

// FreeBSD platform

struct MemRegion {
    base: usize,
    len: usize,
}

/// Check whether procfs is mounted by probing /proc/curproc/mem.
fn check_procfs_mounted() -> bool {
    Path::new("/proc/curproc/mem").exists()
}

static PROCFS_CHECKED: AtomicBool = AtomicBool::new(false);
static PROCFS_AVAILABLE: AtomicBool = AtomicBool::new(false);

/// One-time procfs availability check. Logs a warning if missing.
fn ensure_procfs_available() {
    if !PROCFS_CHECKED.swap(true, AtomicOrdering::Relaxed) {
        let available = check_procfs_mounted();
        PROCFS_AVAILABLE.store(available, AtomicOrdering::Relaxed);
        if !available {
            warn!(
                "procfs is not mounted at /proc \u{2014} FreeBSD memory scanning requires procfs. \
                 Mount it with: mount -t procfs proc /proc"
            );
        }
    }
}

fn is_procfs_available() -> bool {
    PROCFS_AVAILABLE.load(AtomicOrdering::Relaxed)
}

fn get_readable_memory_regions(pid: i32) -> Result<Vec<MemRegion>, io::Error> {
    let mib: [libc::c_int; 4] = [libc::CTL_KERN, libc::KERN_PROC, libc::KERN_PROC_VMMAP, pid];
    let buf = sysctl_buf(&mib)?;

    // Parse variable-length kinfo_vmentry structs.
    //
    // Layout reference (stable since FreeBSD 12, see sys/user.h):
    //   Offset  Field               Type
    //    0      kve_structsize       i32
    //    4      kve_type             i32
    //    8      kve_start            u64
    //   16      kve_end              u64
    //   24      kve_offset           u64
    //   32      kve_vn_fileid        u64
    //   40      kve_vn_fsid_freebsd11 u32
    //   44      kve_flags            i32
    //   48      kve_resident         i32
    //   52      kve_private_resident i32
    //   56      kve_protection       i32
    //   60      kve_ref_count        i32
    //   64      kve_shadow_count     i32
    //
    // Each entry starts with kve_structsize which gives the entry's total
    // size. The kernel guarantees this layout is stable on FreeBSD >= 12
    // (KERN_PROC_VMMAP v3).
    const KVE_START_OFF: usize = 8;
    const KVE_END_OFF: usize = 16;
    const KVE_PROTECTION_OFF: usize = 56;
    const KVE_MIN_SIZE: usize = KVE_PROTECTION_OFF + 4;

    let mut regions = Vec::new();
    let mut offset: usize = 0;

    while offset + 4 <= buf.len() {
        let entry_size_i32 = i32::from_ne_bytes(buf[offset..offset + 4].try_into().unwrap());
        if entry_size_i32 <= 0 {
            break;
        }
        let entry_size = entry_size_i32 as usize;
        if offset
            .checked_add(entry_size)
            .is_none_or(|end| end > buf.len())
        {
            break;
        }

        if entry_size >= KVE_MIN_SIZE {
            let start = u64::from_ne_bytes(
                buf[offset + KVE_START_OFF..offset + KVE_START_OFF + 8]
                    .try_into()
                    .unwrap(),
            );
            let end = u64::from_ne_bytes(
                buf[offset + KVE_END_OFF..offset + KVE_END_OFF + 8]
                    .try_into()
                    .unwrap(),
            );
            let protection = i32::from_ne_bytes(
                buf[offset + KVE_PROTECTION_OFF..offset + KVE_PROTECTION_OFF + 4]
                    .try_into()
                    .unwrap(),
            );

            // KVME_PROT_READ = 1
            if protection & 1 != 0 && start < end {
                regions.push(MemRegion {
                    base: start as usize,
                    len: (end - start) as usize,
                });
            }
        }

        offset += entry_size;
    }

    Ok(regions)
}

/// Handle to a process's memory via `/proc/{pid}/mem`.
///
/// On FreeBSD, root can read `/proc/<pid>/mem` directly without ptrace.
/// The kernel's `procfs_doprocmem` calls `p_candebug`, which grants
/// access to uid 0 unconditionally via the superuser policy in
/// `priv_check_cred` - regardless of securelevel or
/// `security.bsd.unprivileged_proc_debug` settings.
///
/// This means memory scanning does not stop target processes.
struct ProcessHandle {
    mem_file: File,
}

impl ProcessHandle {
    fn attach(pid: i32) -> Result<Self, io::Error> {
        if !is_procfs_available() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "procfs not mounted",
            ));
        }
        let mem_file = File::open(format!("/proc/{}/mem", pid))?;
        Ok(Self { mem_file })
    }
}

fn read_process_memory(
    handle: &ProcessHandle,
    regions: &[MemRegion],
    buffer: &mut [u8],
    read_size: usize,
) -> usize {
    let mut offset = 0;
    for region in regions {
        let to_read = min(region.len, read_size - offset);
        if to_read == 0 {
            break;
        }
        match handle
            .mem_file
            .read_at(&mut buffer[offset..offset + to_read], region.base as u64)
        {
            Ok(n) => offset += n,
            Err(_) => {
                // Fill unreadable region with zeros and continue
                buffer[offset..offset + to_read].fill(0);
                offset += to_read;
            }
        }
    }
    offset
}

fn list_pids() -> Vec<i32> {
    let mut sys = System::new();
    sys.refresh_processes_specifics(ProcessesToUpdate::All, true, ProcessRefreshKind::nothing());
    sys.processes()
        .keys()
        .map(|pid| pid.as_u32() as i32)
        .collect()
}

// Scanning logic

enum ScanOutcome {
    NoMatch,
    Matched { pid_terminated: bool },
}

enum ScanSource {
    FullScan,
    Incremental,
}

fn scan_pid(
    pid: i32,
    self_pid: i32,
    scanner: &mut Scanner,
    seen_hashes: &mut HashMap<usize, u64, Xxh3DefaultBuilder>,
    scratch: &mut Vec<u8>,
    cfg: &YaraConfig,
    source: ScanSource,
) -> Result<ScanOutcome, Box<dyn Error>> {
    if pid == self_pid {
        return Ok(ScanOutcome::NoMatch);
    }

    let proc_name: String = match get_process_name(pid) {
        Some(name) => name,
        None => return Ok(ScanOutcome::NoMatch),
    };

    if proc_name.starts_with("kworker") {
        return Ok(ScanOutcome::NoMatch);
    }

    let span_name = match source {
        ScanSource::FullScan => "yara.scan_full",
        ScanSource::Incremental => "yara.scan_pid",
    };

    let scan_span = Span::root(span_name, SpanContext::random()).with_properties(|| {
        vec![
            ("process.pid", pid.to_string()),
            ("process.name", proc_name.to_string()),
        ]
    });

    debug!("Starting scan for PID {} ({})", pid, proc_name);

    let mut outcome = ScanOutcome::NoMatch;
    let mut regions_seen: HashSet<usize, Xxh3DefaultBuilder> = Default::default();
    let mut regions_updated = 0;

    let buffer_size = CHUNK_SIZE_BYTES.load(Ordering::Relaxed);
    let max_iovecs = 256;

    scratch.resize(buffer_size, 0);
    let buffer: &mut [u8] = &mut scratch[..];

    let mut xxh3 = Box::new(xxh3::Xxh3::new());

    let Ok(all_regions) = get_readable_memory_regions(pid) else {
        return Ok(ScanOutcome::NoMatch);
    };

    // Open /proc/{pid}/mem for reading
    let handle = match ProcessHandle::attach(pid) {
        Ok(h) => h,
        Err(_) => return Ok(ScanOutcome::NoMatch),
    };

    let mut region_idx = 0;
    let mut region_offset = 0;

    loop {
        let mut current_regions: Vec<MemRegion> = Vec::with_capacity(max_iovecs);
        let mut available_bytes = buffer_size;

        while available_bytes > 0
            && current_regions.len() < max_iovecs
            && region_idx < all_regions.len()
        {
            let region = &all_regions[region_idx];
            let remaining_len = region.len - region_offset;
            let usable_bytes = min(available_bytes, remaining_len);
            available_bytes -= usable_bytes;
            current_regions.push(MemRegion {
                base: region.base + region_offset,
                len: usable_bytes,
            });

            if usable_bytes < remaining_len {
                region_offset += usable_bytes;
            } else {
                region_idx += 1;
                region_offset = 0;
            }
        }

        if current_regions.is_empty() {
            break;
        }

        let read_size = buffer_size - available_bytes;
        let bytes_read = read_process_memory(&handle, &current_regions, buffer, read_size);

        if bytes_read == 0 && read_size > 0 {
            break;
        }

        if bytes_read < read_size {
            buffer[bytes_read..read_size].fill(0);
        }

        let mut buffer_index = 0;
        for region in &current_regions {
            if buffer_index + region.len > read_size {
                break;
            }
            let region_buffer = &buffer[buffer_index..buffer_index + region.len];
            buffer_index += region.len;

            xxh3.reset();
            xxh3.update(region_buffer);
            let hash = xxh3.digest();
            let key = region.base;

            if seen_hashes.insert(key, hash) != Some(hash) {
                regions_updated += 1;
                scanner.scan(region.base, region_buffer)?;
            }
            regions_seen.insert(key);
        }
    }

    // Detach before match handling (which may kill the process).
    drop(handle);

    if regions_updated > 0
        && let Ok(results) = scanner.finish()
    {
        let mut matching = results
            .matching_rules()
            .filter(|rule| !cfg.disabled_rules.contains(rule.identifier()))
            .peekable();

        if matching.peek().is_some() {
            let result = handle_yara_match(pid, matching, &cfg.actions, &cfg.samples_dir);
            outcome = ScanOutcome::Matched {
                pid_terminated: result.pid_terminated,
            };
        }
    }

    seen_hashes.retain(|k, _| regions_seen.contains(k));

    let terminated = matches!(
        outcome,
        ScanOutcome::Matched {
            pid_terminated: true
        }
    );
    let matched = matches!(outcome, ScanOutcome::Matched { .. });

    scan_span.add_properties(|| {
        vec![
            ("yara.matched", matched.to_string()),
            ("yara.terminated", terminated.to_string()),
            ("yara.regions_updated", regions_updated.to_string()),
        ]
    });

    debug!(
        "PID {}: scanned {} regions{}{}",
        pid,
        regions_updated,
        if terminated { " (terminated)" } else { "" },
        if matched && !terminated {
            " (matched, alert-only)"
        } else {
            ""
        },
    );

    Ok(outcome)
}

pub fn full_scan_all(
    self_pid: i32,
    scanner: &mut Scanner,
    seen_hashes: &mut HashMap<i32, HashMap<usize, u64, Xxh3DefaultBuilder>>,
    scanned_exes: &mut HashSet<u64>,
    scratch: &mut Vec<u8>,
    cfg: &YaraConfig,
) {
    let mut total = 0;
    for pid in list_pids() {
        total += 1;

        let inode = get_exe_inode(pid);

        if inode != 0 && scanned_exes.contains(&inode) {
            debug!("Skipping PID {}: exe inode {} already scanned", pid, inode);
            continue;
        }

        match scan_pid(
            pid,
            self_pid,
            scanner,
            seen_hashes.entry(pid).or_default(),
            scratch,
            cfg,
            ScanSource::FullScan,
        ) {
            Err(e) => debug!("Error scanning PID {}: {}", pid, e),
            Ok(ScanOutcome::Matched { .. }) => {
                debug!("PID {} matched by YARA -> not tracking its inode", pid);
            }
            Ok(ScanOutcome::NoMatch) => {
                if inode != 0 {
                    scanned_exes.insert(inode);
                }
            }
        }
    }

    info!(
        "Full scan complete: attempted scanning {} PIDs (exe-inodes tracked: {})",
        total,
        scanned_exes.len()
    );
}

pub fn yara_init_memory_scan(cfg: &YaraConfig, rules: &Rules) -> anyhow::Result<()> {
    let self_pid: i32 = process::id() as i32;

    let poll_interval =
        Duration::from_secs(cfg.poll_interval_secs.unwrap_or(DEFAULT_POLL_INTERVAL_SECS));
    debug!(
        "YARA polling interval set to {} seconds",
        poll_interval.as_secs()
    );

    let full_scan_interval = Duration::from_secs(
        cfg.full_scan_interval_secs
            .unwrap_or(DEFAULT_FULL_SCAN_INTERVAL_SECS),
    );
    debug!(
        "YARA full scan interval set to {} seconds",
        full_scan_interval.as_secs()
    );

    let mut seen_hashes: HashMap<i32, HashMap<usize, u64, Xxh3DefaultBuilder>> = HashMap::new();
    let mut scanner = Scanner::new(rules);

    ensure_procfs_available();

    if !cfg.disabled_rules.is_empty() {
        let all_rule_names: HashSet<String> = rules
            .iter()
            .map(|rule| rule.identifier().to_string())
            .collect();

        let invalid_disabled: Vec<String> = cfg
            .disabled_rules
            .iter()
            .filter(|name| !all_rule_names.contains(*name))
            .cloned()
            .collect();

        if !invalid_disabled.is_empty() {
            warn!(
                "The following disabled_rules do not match any loaded rules: {:?}",
                invalid_disabled
            );
        } else {
            info!("Disabling {} YARA rules", cfg.disabled_rules.len());
        }
    }

    let mut sys = System::new();
    sys.refresh_processes_specifics(
        ProcessesToUpdate::All,
        true,
        ProcessRefreshKind::everything().without_tasks(),
    );

    let mut known_pids: HashSet<i32> = sys
        .processes()
        .keys()
        .map(|pid| pid.as_u32() as i32)
        .collect();

    let mut scanned_exes: HashSet<u64> = HashSet::new();
    let mut last_full_scan = Instant::now();
    let mut scratch: Vec<u8> = Vec::new();

    full_scan_all(
        self_pid,
        &mut scanner,
        &mut seen_hashes,
        &mut scanned_exes,
        &mut scratch,
        cfg,
    );

    loop {
        sys.refresh_processes_specifics(
            ProcessesToUpdate::All,
            true,
            ProcessRefreshKind::everything().without_tasks(),
        );

        for pid in sys.processes().keys().map(|pid| pid.as_u32() as i32) {
            if !known_pids.insert(pid) {
                continue;
            }

            let inode = get_exe_inode(pid);

            if inode != 0 && scanned_exes.contains(&inode) {
                debug!(
                    "Skipping new PID {}: exe inode {} already scanned",
                    pid, inode
                );
                continue;
            }

            debug!("Detected new PID: {}", pid);

            match scan_pid(
                pid,
                self_pid,
                &mut scanner,
                seen_hashes.entry(pid).or_default(),
                &mut scratch,
                cfg,
                ScanSource::Incremental,
            ) {
                Err(e) => debug!("Error scanning new PID {}: {}", pid, e),
                Ok(ScanOutcome::Matched { .. }) => {
                    debug!("New PID {} matched by YARA -> not tracking its inode", pid);
                }
                Ok(ScanOutcome::NoMatch) => {
                    if inode != 0 {
                        scanned_exes.insert(inode);
                    }
                }
            }
        }

        known_pids.retain(|pid| sys.process(SysPid::from_u32(*pid as u32)).is_some());

        if scratch.is_empty() {
            scratch.truncate(0);
        }

        if last_full_scan.elapsed() >= full_scan_interval {
            info!("Time for full scan of all running processes");

            known_pids.clear();
            seen_hashes.clear();
            scanned_exes.clear();

            full_scan_all(
                self_pid,
                &mut scanner,
                &mut seen_hashes,
                &mut scanned_exes,
                &mut scratch,
                cfg,
            );

            last_full_scan = Instant::now();
        }

        sleep(poll_interval);
    }
}
