//! Direct netlink audit rule add/delete.
//! Layout matches Linux kernel UAPI `audit_rule_data`; see `linux/audit.h`.

use crate::AuditEventFlags;
use log::{debug, info, warn};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

const NETLINK_AUDIT: i32 = 9;

#[allow(dead_code)]
const AUDIT_GET: u16 = 1000;
const AUDIT_ADD_RULE: u16 = 1011;
const AUDIT_DEL_RULE: u16 = 1012;

const AUDIT_FILTER_EXIT: u32 = 0x04;
const AUDIT_ALWAYS: u32 = 2;

const AUDIT_ARCH: u32 = 11;
const AUDIT_SUCCESS: u32 = 104;
const AUDIT_ARG0: u32 = 200;
const AUDIT_FILTERKEY: u32 = 210;
const AUDIT_EQUAL: u32 = 0x4000_0000;

const __AUDIT_ARCH_64BIT: u32 = 0x8000_0000;
const __AUDIT_ARCH_LE: u32 = 0x4000_0000;
const EM_X86_64: u32 = 62;
const EM_386: u32 = 3;
const AUDIT_ARCH_X86_64: u32 = EM_X86_64 | __AUDIT_ARCH_64BIT | __AUDIT_ARCH_LE;
const AUDIT_ARCH_I386: u32 = EM_386 | __AUDIT_ARCH_LE;

const AUDIT_BITMASK_SIZE: usize = 64;
const AUDIT_MAX_FIELDS: usize = 64;

const SOCKETCALL_SYSCALL_B32: u32 = 102;

const EXECVE_SYSCALL_B64: u32 = 59;
const EXECVE_SYSCALL_B32: u32 = 11;
const EXECVEAT_SYSCALL_B64: u32 = 322;
const EXECVEAT_SYSCALL_B32: u32 = 358;

const CONNECT_SYSCALL_B64: u32 = 42;
const ACCEPT_SYSCALL_B64: u32 = 43;
const SENDTO_SYSCALL_B64: u32 = 44;
const SENDMSG_SYSCALL_B64: u32 = 46;
const BIND_SYSCALL_B64: u32 = 49;
const ACCEPT4_SYSCALL_B64: u32 = 288;
const SENDMMSG_SYSCALL_B64: u32 = 307;

const ACCEPT4_SYSCALL_B32: u32 = 364;
const SENDMMSG_SYSCALL_B32: u32 = 345;

const EXEC_RULE_KEY: &[u8] = b"rb2_exec";
const NETWORK_RULE_KEY: &[u8] = b"rb2_net";

const NLMSG_HDR_LEN: usize = 16;
const FIXED_RULE_PART_LEN: usize = 1040;
#[cfg(test)]
const BUFLEN_OFFSET: usize = 1036;
#[cfg(test)]
const BUF_OFFSET: usize = 1040;
#[cfg(test)]
const FIELD_COUNT_OFFSET: usize = 8;
#[cfg(test)]
const MASK_OFFSET: usize = 12;
#[cfg(test)]
const FIELDS_OFFSET: usize = 268;
#[cfg(test)]
const VALUES_OFFSET: usize = 524;
#[cfg(test)]
const FIELDFLAGS_OFFSET: usize = 780;

#[repr(C)]
struct NlMsgHdr {
    nlmsg_len: u32,
    nlmsg_type: u16,
    nlmsg_flags: u16,
    nlmsg_seq: u32,
    nlmsg_pid: u32,
}

/// Kernel `audit_rule_data` layout (`linux/audit.h`). `buf` is sized for the
/// longest rule key we emit.
#[repr(C)]
struct AuditRuleData {
    flags: u32,
    action: u32,
    field_count: u32,
    mask: [u32; AUDIT_BITMASK_SIZE],
    fields: [u32; AUDIT_MAX_FIELDS],
    values: [u32; AUDIT_MAX_FIELDS],
    fieldflags: [u32; AUDIT_MAX_FIELDS],
    buflen: u32,
    buf: [u8; 24],
}

struct RuleSpec {
    key: &'static [u8],
    syscalls_b64: &'static [u32],
    syscalls_b32: &'static [u32],
    syscall_arg0_b64: Option<u32>,
    syscall_arg0_b32: Option<u32>,
    success_only: bool,
}

const EXEC_RULE_SPEC: RuleSpec = RuleSpec {
    key: EXEC_RULE_KEY,
    syscalls_b64: &[EXECVE_SYSCALL_B64, EXECVEAT_SYSCALL_B64],
    syscalls_b32: &[EXECVE_SYSCALL_B32, EXECVEAT_SYSCALL_B32],
    syscall_arg0_b64: None,
    syscall_arg0_b32: None,
    success_only: false,
};

const NETWORK_CONNECT_RULE_SPEC: RuleSpec = RuleSpec {
    key: NETWORK_RULE_KEY,
    syscalls_b64: &[CONNECT_SYSCALL_B64],
    syscalls_b32: &[SOCKETCALL_SYSCALL_B32],
    syscall_arg0_b64: None,
    syscall_arg0_b32: Some(3),
    success_only: false,
};

const NETWORK_IO_RULE_SPEC: RuleSpec = RuleSpec {
    key: NETWORK_RULE_KEY,
    syscalls_b64: &[
        ACCEPT_SYSCALL_B64,
        SENDTO_SYSCALL_B64,
        SENDMSG_SYSCALL_B64,
        BIND_SYSCALL_B64,
        ACCEPT4_SYSCALL_B64,
        SENDMMSG_SYSCALL_B64,
    ],
    syscalls_b32: &[
        ACCEPT4_SYSCALL_B32,
        SENDMMSG_SYSCALL_B32,
        SOCKETCALL_SYSCALL_B32,
    ],
    syscall_arg0_b64: None,
    syscall_arg0_b32: None,
    success_only: true,
};

const fn audit_word(nr: u32) -> usize {
    (nr / 32) as usize
}

const fn audit_bit(nr: u32) -> u32 {
    1 << (nr - (nr / 32) * 32)
}

fn active_rule_specs(flags: AuditEventFlags) -> Vec<&'static RuleSpec> {
    let mut specs = Vec::new();
    if flags.contains(AuditEventFlags::EXEC) {
        specs.push(&EXEC_RULE_SPEC);
    }
    if flags.contains(AuditEventFlags::NETWORK) {
        specs.push(&NETWORK_CONNECT_RULE_SPEC);
        specs.push(&NETWORK_IO_RULE_SPEC);
    }
    specs
}

fn build_rule(arch_b64: bool, spec: &RuleSpec) -> Vec<u8> {
    let syscall_arg0 = if arch_b64 {
        spec.syscall_arg0_b64
    } else {
        spec.syscall_arg0_b32
    };
    let mut field_count = 2;
    if syscall_arg0.is_some() {
        field_count += 1;
    }
    if spec.success_only {
        field_count += 1;
    }

    let mut rule = AuditRuleData {
        flags: AUDIT_FILTER_EXIT,
        action: AUDIT_ALWAYS,
        field_count,
        mask: [0u32; AUDIT_BITMASK_SIZE],
        fields: [0u32; AUDIT_MAX_FIELDS],
        values: [0u32; AUDIT_MAX_FIELDS],
        fieldflags: [0u32; AUDIT_MAX_FIELDS],
        buflen: spec.key.len() as u32,
        buf: [0u8; 24],
    };

    let (arch, syscalls) = if arch_b64 {
        (AUDIT_ARCH_X86_64, spec.syscalls_b64)
    } else {
        (AUDIT_ARCH_I386, spec.syscalls_b32)
    };

    for &syscall in syscalls {
        let word = audit_word(syscall);
        rule.mask[word] |= audit_bit(syscall);
    }

    rule.fields[0] = AUDIT_ARCH;
    rule.values[0] = arch;
    rule.fieldflags[0] = AUDIT_EQUAL;

    let mut next_field = 1;
    if let Some(arg0) = syscall_arg0 {
        rule.fields[next_field] = AUDIT_ARG0;
        rule.values[next_field] = arg0;
        rule.fieldflags[next_field] = AUDIT_EQUAL;
        next_field += 1;
    }

    if spec.success_only {
        rule.fields[next_field] = AUDIT_SUCCESS;
        rule.values[next_field] = 1;
        rule.fieldflags[next_field] = AUDIT_EQUAL;
        next_field += 1;
    }

    rule.fields[next_field] = AUDIT_FILTERKEY;
    rule.values[next_field] = spec.key.len() as u32;
    rule.fieldflags[next_field] = AUDIT_EQUAL;

    let key_len = spec.key.len().min(rule.buf.len());
    rule.buf[..key_len].copy_from_slice(&spec.key[..key_len]);

    let payload_len = FIXED_RULE_PART_LEN + spec.key.len();
    let bytes = unsafe {
        std::slice::from_raw_parts(
            &rule as *const AuditRuleData as *const u8,
            std::mem::size_of::<AuditRuleData>(),
        )
    };
    bytes[..payload_len].to_vec()
}

fn with_audit_control_socket<F, T>(f: F) -> anyhow::Result<T>
where
    F: FnOnce(i32) -> anyhow::Result<T>,
{
    let fd = unsafe {
        let raw = libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            NETLINK_AUDIT,
        );
        if raw < 0 {
            let err = std::io::Error::last_os_error();
            return Err(anyhow::anyhow!(
                "Failed to create audit control socket: {err}"
            ));
        }
        OwnedFd::from_raw_fd(raw)
    };

    let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    addr.nl_family = libc::AF_NETLINK as u16;
    addr.nl_pid = 0;
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
            "Failed to bind audit control socket: {err}"
        ));
    }

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

    let result = f(fd.as_raw_fd());
    drop(fd);
    result
}

fn send_rule(fd: i32, msg_type: u16, payload: &[u8], seq: u32) -> anyhow::Result<()> {
    let total_len = NLMSG_HDR_LEN + payload.len();

    let hdr = NlMsgHdr {
        nlmsg_len: total_len as u32,
        nlmsg_type: msg_type,
        nlmsg_flags: (libc::NLM_F_REQUEST | libc::NLM_F_ACK) as u16,
        nlmsg_seq: seq,
        nlmsg_pid: 0,
    };

    let mut buf = vec![0u8; total_len];
    unsafe {
        std::ptr::copy_nonoverlapping(
            &hdr as *const NlMsgHdr as *const u8,
            buf.as_mut_ptr(),
            NLMSG_HDR_LEN,
        );
        std::ptr::copy_nonoverlapping(
            payload.as_ptr(),
            buf.as_mut_ptr().add(NLMSG_HDR_LEN),
            payload.len(),
        );
    }

    let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    addr.nl_family = libc::AF_NETLINK as u16;

    let ret = unsafe {
        libc::sendto(
            fd,
            buf.as_ptr() as *const libc::c_void,
            total_len,
            0,
            &addr as *const libc::sockaddr_nl as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_nl>() as u32,
        )
    };
    if ret < 0 {
        let err = std::io::Error::last_os_error();
        return Err(anyhow::anyhow!("audit sendto failed: {err}"));
    }
    Ok(())
}

const NLMSG_ERROR: u16 = 2;

fn recv_ack(fd: i32, expected_seq: u32) -> anyhow::Result<()> {
    let mut buf = vec![0u8; 4096];

    loop {
        let nlen = unsafe {
            libc::recvfrom(
                fd,
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
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
                        "timed out waiting for audit rule ACK (seq={expected_seq})"
                    ));
                }
                std::io::ErrorKind::Interrupted => continue,
                _ => return Err(anyhow::anyhow!("audit recv failed: {err}")),
            }
        }

        if nlen < NLMSG_HDR_LEN as isize {
            continue;
        }

        let msg = &buf[..nlen as usize];
        let msg_type = u16::from_ne_bytes([msg[4], msg[5]]);
        let seq = u32::from_ne_bytes([msg[8], msg[9], msg[10], msg[11]]);

        if seq != expected_seq {
            continue;
        }

        if msg_type != NLMSG_ERROR || msg.len() < NLMSG_HDR_LEN + 4 {
            continue;
        }

        let err = i32::from_ne_bytes([msg[16], msg[17], msg[18], msg[19]]);
        if err == 0 || err == -libc::EEXIST || err == libc::EEXIST {
            return Ok(());
        }

        return Err(anyhow::anyhow!("audit rule request failed: errno {err}"));
    }
}

#[allow(dead_code)]
fn send_audit_get_and_drain(fd: i32) -> anyhow::Result<()> {
    let pid = std::process::id();
    let hdr = NlMsgHdr {
        nlmsg_len: NLMSG_HDR_LEN as u32,
        nlmsg_type: AUDIT_GET,
        nlmsg_flags: (libc::NLM_F_REQUEST | libc::NLM_F_ACK) as u16,
        nlmsg_seq: 0,
        nlmsg_pid: pid,
    };
    let mut buf = [0u8; NLMSG_HDR_LEN];
    unsafe {
        std::ptr::copy_nonoverlapping(
            &hdr as *const NlMsgHdr as *const u8,
            buf.as_mut_ptr(),
            NLMSG_HDR_LEN,
        );
    }
    let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    addr.nl_family = libc::AF_NETLINK as u16;
    let ret = unsafe {
        libc::sendto(
            fd,
            buf.as_ptr() as *const libc::c_void,
            buf.len(),
            0,
            &addr as *const libc::sockaddr_nl as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_nl>() as u32,
        )
    };
    if ret < 0 {
        let err = std::io::Error::last_os_error();
        return Err(anyhow::anyhow!("AUDIT_GET send failed: {err}"));
    }
    recv_ack(fd, 0)?;
    let mut drain = [0u8; 256];
    let _ = unsafe {
        libc::recvfrom(
            fd,
            drain.as_mut_ptr() as *mut libc::c_void,
            drain.len(),
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    Ok(())
}

fn add_rule(fd: i32, payload: &[u8], seq: u32) -> anyhow::Result<()> {
    send_rule(fd, AUDIT_ADD_RULE, payload, seq)?;
    recv_ack(fd, seq)
}

fn del_rule(fd: i32, payload: &[u8], seq: u32) -> anyhow::Result<()> {
    send_rule(fd, AUDIT_DEL_RULE, payload, seq)?;
    recv_ack(fd, seq)
}

fn install_rule_specs_on_socket(fd: i32, specs: &[&RuleSpec]) -> anyhow::Result<()> {
    let mut installed: Vec<Vec<u8>> = Vec::new();
    let mut seq = 1u32;

    let result = (|| {
        for &spec in specs {
            for &(arch_b64, label) in &[(true, "b64"), (false, "b32")] {
                let syscall_arg0 = if arch_b64 {
                    spec.syscall_arg0_b64
                } else {
                    spec.syscall_arg0_b32
                };
                let payload = build_rule(arch_b64, spec);
                add_rule(fd, &payload, seq)?;
                info!(
                    "Loaded audit rule: always,exit arch={label}{}{} -k {}",
                    if let Some(arg0) = syscall_arg0 {
                        format!(" -F a0={arg0}")
                    } else {
                        String::new()
                    },
                    if spec.success_only {
                        " -F success=1"
                    } else {
                        ""
                    },
                    String::from_utf8_lossy(spec.key)
                );
                installed.push(payload);
                seq = seq.wrapping_add(1);
            }
        }
        Ok::<(), anyhow::Error>(())
    })();

    if let Err(e) = &result
        && !installed.is_empty()
    {
        warn!("audit rule install failed, rolling back partially installed rules: {e}");
        for (idx, payload) in installed.iter().rev().enumerate() {
            let rollback_seq = 10_000 + idx as u32;
            if let Err(del_err) = del_rule(fd, payload, rollback_seq) {
                warn!("rollback failed for installed rule #{idx}: {del_err}");
            }
        }
    }

    result
}

/// Load audit rules for the requested event kinds on the daemon socket.
pub fn load_audit_rules_on_socket(fd: i32, flags: AuditEventFlags) -> anyhow::Result<()> {
    let specs = active_rule_specs(flags);
    if specs.is_empty() {
        info!("No audit rule groups enabled; starting netlink listener without rules");
        return Ok(());
    }
    install_rule_specs_on_socket(fd, &specs)
}

#[allow(dead_code)]
pub fn load_audit_rules(flags: AuditEventFlags) -> anyhow::Result<()> {
    with_audit_control_socket(|fd| load_audit_rules_on_socket(fd, flags))
}

/// Remove audit rules for the requested event kinds.
pub fn remove_audit_rules(flags: AuditEventFlags) {
    let specs = active_rule_specs(flags);

    if let Err(e) = with_audit_control_socket(|fd| {
        let mut seq = 1u32;
        for &spec in &specs {
            for arch_b64 in [true, false] {
                let payload = build_rule(arch_b64, spec);
                let _ = send_rule(fd, AUDIT_DEL_RULE, &payload, seq);
                let _ = recv_ack(fd, seq);
                seq = seq.wrapping_add(1);
            }
        }
        Ok::<(), anyhow::Error>(())
    }) {
        warn!("remove_audit_rules (netlink): {e}");
    }
    if !specs.is_empty() {
        debug!("Removed audit rules for {:?}", flags);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read_u32(bytes: &[u8], offset: usize) -> u32 {
        u32::from_ne_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ])
    }

    #[test]
    fn test_build_exec_rule_size() {
        let b64 = build_rule(true, &EXEC_RULE_SPEC);
        let b32 = build_rule(false, &EXEC_RULE_SPEC);
        assert_eq!(b64.len(), FIXED_RULE_PART_LEN + EXEC_RULE_KEY.len());
        assert_eq!(b32.len(), b64.len());
    }

    #[test]
    fn test_build_exec_rule_key_in_buf() {
        let b64 = build_rule(true, &EXEC_RULE_SPEC);
        assert_eq!(read_u32(&b64, BUFLEN_OFFSET), EXEC_RULE_KEY.len() as u32);
        assert_eq!(
            &b64[BUF_OFFSET..BUF_OFFSET + EXEC_RULE_KEY.len()],
            EXEC_RULE_KEY
        );
    }

    #[test]
    fn test_build_exec_rule_mask_b64() {
        let b64 = build_rule(true, &EXEC_RULE_SPEC);
        let word = audit_word(EXECVE_SYSCALL_B64);
        let bit = audit_bit(EXECVE_SYSCALL_B64);
        let v = read_u32(&b64, MASK_OFFSET + word * 4);
        assert_eq!(v & bit, bit);

        let execveat_word = audit_word(EXECVEAT_SYSCALL_B64);
        let execveat_bit = audit_bit(EXECVEAT_SYSCALL_B64);
        let execveat_v = read_u32(&b64, MASK_OFFSET + execveat_word * 4);
        assert_eq!(execveat_v & execveat_bit, execveat_bit);
    }

    #[test]
    fn test_build_exec_rule_mask_b32() {
        let b32 = build_rule(false, &EXEC_RULE_SPEC);
        let word = audit_word(EXECVE_SYSCALL_B32);
        let bit = audit_bit(EXECVE_SYSCALL_B32);
        let v = read_u32(&b32, MASK_OFFSET + word * 4);
        assert_eq!(v & bit, bit);

        let execveat_word = audit_word(EXECVEAT_SYSCALL_B32);
        let execveat_bit = audit_bit(EXECVEAT_SYSCALL_B32);
        let execveat_v = read_u32(&b32, MASK_OFFSET + execveat_word * 4);
        assert_eq!(execveat_v & execveat_bit, execveat_bit);
    }

    #[test]
    fn test_build_network_rule_has_success_filter() {
        let b64 = build_rule(true, &NETWORK_IO_RULE_SPEC);
        assert_eq!(read_u32(&b64, FIELD_COUNT_OFFSET), 3);
        assert_eq!(read_u32(&b64, FIELDS_OFFSET + 4), AUDIT_SUCCESS);
        assert_eq!(read_u32(&b64, VALUES_OFFSET + 4), 1);
        assert_eq!(read_u32(&b64, FIELDFLAGS_OFFSET + 4), AUDIT_EQUAL);
        assert_eq!(
            &b64[BUF_OFFSET..BUF_OFFSET + NETWORK_RULE_KEY.len()],
            NETWORK_RULE_KEY
        );
    }

    #[test]
    fn test_build_network_rule_mask_b64() {
        let b64 = build_rule(true, &NETWORK_IO_RULE_SPEC);
        for syscall in [
            ACCEPT_SYSCALL_B64,
            SENDTO_SYSCALL_B64,
            SENDMSG_SYSCALL_B64,
            BIND_SYSCALL_B64,
            ACCEPT4_SYSCALL_B64,
            SENDMMSG_SYSCALL_B64,
        ] {
            let word = audit_word(syscall);
            let bit = audit_bit(syscall);
            let v = read_u32(&b64, MASK_OFFSET + word * 4);
            assert_eq!(v & bit, bit, "missing syscall bit {syscall}");
        }
    }

    #[test]
    fn test_build_network_rule_mask_b32() {
        let b32 = build_rule(false, &NETWORK_IO_RULE_SPEC);
        for syscall in [
            ACCEPT4_SYSCALL_B32,
            SENDMMSG_SYSCALL_B32,
            SOCKETCALL_SYSCALL_B32,
        ] {
            let word = audit_word(syscall);
            let bit = audit_bit(syscall);
            let v = read_u32(&b32, MASK_OFFSET + word * 4);
            assert_eq!(v & bit, bit, "missing syscall bit {syscall}");
        }
    }

    #[test]
    fn test_build_network_connect_rule_has_arg0_and_no_success_filter() {
        let b64 = build_rule(true, &NETWORK_CONNECT_RULE_SPEC);
        assert_eq!(read_u32(&b64, FIELD_COUNT_OFFSET), 2);
        assert_eq!(read_u32(&b64, FIELDS_OFFSET + 4), AUDIT_FILTERKEY);

        let b32 = build_rule(false, &NETWORK_CONNECT_RULE_SPEC);
        assert_eq!(read_u32(&b32, FIELD_COUNT_OFFSET), 3);
        assert_eq!(read_u32(&b32, FIELDS_OFFSET + 4), AUDIT_ARG0);
        assert_eq!(read_u32(&b32, VALUES_OFFSET + 4), 3);
        assert_eq!(read_u32(&b32, FIELDFLAGS_OFFSET + 4), AUDIT_EQUAL);
        assert_eq!(read_u32(&b32, FIELDS_OFFSET + 8), AUDIT_FILTERKEY);
    }
}
