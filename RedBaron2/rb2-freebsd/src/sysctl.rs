use std::io;

/// Issue a sysctl query by MIB and return the raw byte buffer.
/// Handles the two-call pattern (size query -> allocate -> fetch) with a 4/3x
/// over-allocation to account for kernel-side growth between calls.
pub fn sysctl_buf(mib: &[libc::c_int]) -> Result<Vec<u8>, io::Error> {
    let mut size: libc::size_t = 0;
    let ret = unsafe {
        libc::sysctl(
            mib.as_ptr(),
            mib.len() as libc::c_uint,
            std::ptr::null_mut(),
            &mut size,
            std::ptr::null(),
            0,
        )
    };
    if ret != 0 || size == 0 {
        return Err(io::Error::last_os_error());
    }

    let alloc_size = size * 4 / 3;
    let mut buf = vec![0u8; alloc_size];
    let mut actual_size = alloc_size;

    let ret = unsafe {
        libc::sysctl(
            mib.as_ptr(),
            mib.len() as libc::c_uint,
            buf.as_mut_ptr().cast(),
            &mut actual_size,
            std::ptr::null(),
            0,
        )
    };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }

    buf.truncate(actual_size);
    Ok(buf)
}

pub fn get_exe_path(pid: i32) -> Option<String> {
    let mib: [libc::c_int; 4] = [
        libc::CTL_KERN,
        libc::KERN_PROC,
        libc::KERN_PROC_PATHNAME,
        pid,
    ];
    let buf = sysctl_buf(&mib).ok()?;
    let path = String::from_utf8_lossy(&buf[..buf.len().saturating_sub(1)]).into_owned();
    if path.is_empty() { None } else { Some(path) }
}

pub fn get_exe_inode(pid: i32) -> u64 {
    let Some(path) = get_exe_path(pid) else {
        return 0;
    };
    std::fs::metadata(&path)
        .map(|md| {
            use std::os::unix::fs::MetadataExt;
            md.ino()
        })
        .unwrap_or(0)
}

pub fn get_process_name(pid: i32) -> Option<String> {
    let path = get_exe_path(pid)?;
    let name = path.rsplit('/').next().unwrap_or(&path).to_string();
    if name.is_empty() { None } else { Some(name) }
}

pub fn get_cwd(pid: i32) -> Option<String> {
    let mib: [libc::c_int; 4] = [libc::CTL_KERN, libc::KERN_PROC, libc::KERN_PROC_CWD, pid];
    let buf = sysctl_buf(&mib).ok()?;
    // KERN_PROC_CWD returns a kinfo_file struct. kf_path (char[PATH_MAX=1024])
    // begins at byte offset 368 after the fixed header fields.
    const KF_PATH_OFFSET: usize = 0x170;
    let path_buf = buf.get(KF_PATH_OFFSET..)?;
    let end = path_buf
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(path_buf.len());
    let path = String::from_utf8_lossy(&path_buf[..end]).into_owned();
    if path.is_empty() { None } else { Some(path) }
}

pub fn get_ppid(pid: u32) -> Option<u32> {
    // FreeBSD /proc/<pid>/status is space-separated, ppid is the 3rd field
    let status = std::fs::read_to_string(format!("/proc/{}/status", pid)).ok()?;
    status.split_whitespace().nth(2)?.parse().ok()
}
