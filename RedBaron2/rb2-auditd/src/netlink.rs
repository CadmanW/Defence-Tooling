use log::{debug, error, warn};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

pub const NETLINK_AUDIT: i32 = 9;

pub const AUDIT_SET: u16 = 1001;

pub const AUDIT_STATUS_ENABLED: u32 = 0x01;
pub const AUDIT_STATUS_PID_MASK: u32 = 0x04;

pub const MAX_AUDIT_MESSAGE_LENGTH: usize = 8970;

pub const NLMSG_HDR_LEN: usize = 16; // sizeof(struct nlmsghdr)

const NLMSG_ERROR: u16 = 2;

#[repr(C)]
pub struct AuditStatusPayload {
    pub mask: u32,
    pub enabled: u32,
    pub failure: u32,
    pub pid: u32,
    pub rate_limit: u32,
    pub backlog_limit: u32,
    pub lost: u32,
    pub backlog: u32,
    pub version: u32,
    pub backlog_wait_time: u32,
}

#[repr(C)]
pub struct NlMsgHdr {
    pub nlmsg_len: u32,
    pub nlmsg_type: u16,
    pub nlmsg_flags: u16,
    pub nlmsg_seq: u32,
    pub nlmsg_pid: u32,
}

pub struct AuditNetlinkClient {
    pub fd: OwnedFd,
    pub seq: u32,
}

impl AuditNetlinkClient {
    pub fn new(recv_buf_size: i32) -> anyhow::Result<Self> {
        let fd = unsafe {
            let raw = libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                NETLINK_AUDIT,
            );
            if raw < 0 {
                let err = std::io::Error::last_os_error();
                return Err(anyhow::anyhow!(
                    "Failed to create netlink audit socket: {err}"
                ));
            }
            OwnedFd::from_raw_fd(raw)
        };

        // Use our PID as port id so the kernel's NETLINK_CB(skb).portid matches a valid
        // destination; some kernels do not reliably assign a port when nl_pid=0.
        let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        addr.nl_family = libc::AF_NETLINK as u16;
        addr.nl_pid = std::process::id();
        addr.nl_groups = 0;

        let ret = unsafe {
            libc::bind(
                fd.as_raw_fd(),
                &addr as *const libc::sockaddr_nl as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_nl>() as u32,
            )
        };
        if ret < 0 {
            let err = std::io::Error::last_os_error();
            return Err(anyhow::anyhow!(
                "Failed to bind netlink audit socket: {err}"
            ));
        }

        if recv_buf_size > 0 {
            let ret = unsafe {
                libc::setsockopt(
                    fd.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_RCVBUF,
                    &recv_buf_size as *const i32 as *const libc::c_void,
                    std::mem::size_of::<i32>() as u32,
                )
            };
            if ret < 0 {
                warn!("Failed to set netlink recv buffer size");
            }
        }

        // Set a receive timeout so the blocking reader can check for shutdown
        let tv = libc::timeval {
            tv_sec: 1,
            tv_usec: 0,
        };
        unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &tv as *const libc::timeval as *const libc::c_void,
                std::mem::size_of::<libc::timeval>() as u32,
            );
        }

        Ok(Self { fd, seq: 0 })
    }

    /// Register our PID as the audit daemon (mirrors `go-audit` `KeepConnection`).
    pub fn register_pid(&mut self) -> anyhow::Result<()> {
        let pid = std::process::id();

        let payload = AuditStatusPayload {
            mask: AUDIT_STATUS_ENABLED | AUDIT_STATUS_PID_MASK,
            enabled: 1,
            failure: 0,
            pid,
            rate_limit: 0,
            backlog_limit: 0,
            lost: 0,
            backlog: 0,
            version: 0,
            backlog_wait_time: 0,
        };

        self.seq = self.seq.wrapping_add(1);

        let payload_size = std::mem::size_of::<AuditStatusPayload>();
        let total_len = NLMSG_HDR_LEN + payload_size;

        let hdr = NlMsgHdr {
            nlmsg_len: total_len as u32,
            nlmsg_type: AUDIT_SET,
            nlmsg_flags: (libc::NLM_F_REQUEST | libc::NLM_F_ACK) as u16,
            nlmsg_seq: self.seq,
            nlmsg_pid: pid,
        };

        let mut buf = vec![0u8; total_len];
        unsafe {
            std::ptr::copy_nonoverlapping(
                &hdr as *const NlMsgHdr as *const u8,
                buf.as_mut_ptr(),
                NLMSG_HDR_LEN,
            );
            std::ptr::copy_nonoverlapping(
                &payload as *const AuditStatusPayload as *const u8,
                buf.as_mut_ptr().add(NLMSG_HDR_LEN),
                payload_size,
            );
        }

        let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        addr.nl_family = libc::AF_NETLINK as u16;

        let ret = unsafe {
            libc::sendto(
                self.fd.as_raw_fd(),
                buf.as_ptr() as *const libc::c_void,
                total_len,
                0,
                &addr as *const libc::sockaddr_nl as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_nl>() as u32,
            )
        };

        if ret < 0 {
            let err = std::io::Error::last_os_error();
            return Err(anyhow::anyhow!("Failed to send AUDIT_SET: {err}"));
        }

        let mut ack_buf = vec![0u8; 4096];
        loop {
            let nlen = unsafe {
                libc::recvfrom(
                    self.fd.as_raw_fd(),
                    ack_buf.as_mut_ptr() as *mut libc::c_void,
                    ack_buf.len(),
                    0,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            };

            if nlen < 0 {
                let err = std::io::Error::last_os_error();
                match err.kind() {
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => {
                        return Err(anyhow::anyhow!(
                            "timed out waiting for AUDIT_SET ack (seq={})",
                            self.seq
                        ));
                    }
                    std::io::ErrorKind::Interrupted => continue,
                    _ => {
                        return Err(anyhow::anyhow!("AUDIT_SET ack recv failed: {err}"));
                    }
                }
            }

            if nlen < NLMSG_HDR_LEN as isize {
                continue;
            }

            let msg = &ack_buf[..nlen as usize];
            let msg_type = u16::from_ne_bytes([msg[4], msg[5]]);
            let seq = u32::from_ne_bytes([msg[8], msg[9], msg[10], msg[11]]);

            if seq != self.seq {
                continue;
            }

            if msg_type != NLMSG_ERROR || msg.len() < NLMSG_HDR_LEN + 4 {
                continue;
            }

            let err = i32::from_ne_bytes([msg[16], msg[17], msg[18], msg[19]]);
            if err != 0 {
                return Err(anyhow::anyhow!("AUDIT_SET failed: errno {err}"));
            }

            debug!("Registered PID {pid} as audit daemon");
            return Ok(());
        }
    }

    /// Blocking receive of a single netlink message.
    /// Returns (msg_type, data) or None on timeout/error.
    pub fn receive(&self) -> Option<(u16, Vec<u8>)> {
        let mut buf = vec![0u8; MAX_AUDIT_MESSAGE_LENGTH];

        let nlen = unsafe {
            libc::recvfrom(
                self.fd.as_raw_fd(),
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };

        if nlen < NLMSG_HDR_LEN as isize {
            if nlen < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() != std::io::ErrorKind::Interrupted
                    && err.kind() != std::io::ErrorKind::WouldBlock
                {
                    error!("audit netlink recv error: {err}");
                }
            }
            return None;
        }

        let msg_type = u16::from_ne_bytes([buf[4], buf[5]]);
        let data = buf[NLMSG_HDR_LEN..nlen as usize].to_vec();

        Some((msg_type, data))
    }
}

/// Spawn the periodic keepalive task that re-registers our PID with the kernel
/// every 5 seconds (mirrors `go-audit` `KeepConnection`).
pub fn spawn_keepalive(fd_raw: i32, stop: std::sync::Arc<std::sync::atomic::AtomicBool>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            interval.tick().await;
            if stop.load(std::sync::atomic::Ordering::Relaxed) {
                return;
            }

            let pid = std::process::id();
            let payload = AuditStatusPayload {
                mask: AUDIT_STATUS_ENABLED | AUDIT_STATUS_PID_MASK,
                enabled: 1,
                failure: 0,
                pid,
                rate_limit: 0,
                backlog_limit: 0,
                lost: 0,
                backlog: 0,
                version: 0,
                backlog_wait_time: 0,
            };

            let payload_size = std::mem::size_of::<AuditStatusPayload>();
            let total_len = NLMSG_HDR_LEN + payload_size;

            let hdr = NlMsgHdr {
                nlmsg_len: total_len as u32,
                nlmsg_type: AUDIT_SET,
                // Do not request ACKs here; otherwise the reader loop will consume
                // keepalive ACKs as if they were audit traffic.
                nlmsg_flags: libc::NLM_F_REQUEST as u16,
                nlmsg_seq: 0,
                nlmsg_pid: pid,
            };

            let mut buf = vec![0u8; total_len];
            unsafe {
                std::ptr::copy_nonoverlapping(
                    &hdr as *const NlMsgHdr as *const u8,
                    buf.as_mut_ptr(),
                    NLMSG_HDR_LEN,
                );
                std::ptr::copy_nonoverlapping(
                    &payload as *const AuditStatusPayload as *const u8,
                    buf.as_mut_ptr().add(NLMSG_HDR_LEN),
                    payload_size,
                );
            }

            let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
            addr.nl_family = libc::AF_NETLINK as u16;

            let ret = unsafe {
                libc::sendto(
                    fd_raw,
                    buf.as_ptr() as *const libc::c_void,
                    total_len,
                    0,
                    &addr as *const libc::sockaddr_nl as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_nl>() as u32,
                )
            };

            if ret < 0 {
                let err = std::io::Error::last_os_error();
                warn!("audit keepalive send failed: {err}");
            }
        }
    });
}
