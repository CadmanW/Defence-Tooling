use crate::AuditEventFlags;
use serde::Serialize;
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};

pub const AUDIT_SYSCALL: u16 = 1300;
pub const AUDIT_PATH: u16 = 1302;
pub const AUDIT_SOCKADDR: u16 = 1306;
pub const AUDIT_CWD: u16 = 1307;
pub const AUDIT_EXECVE: u16 = 1309;
pub const AUDIT_EOE: u16 = 1320;

const EXECVE_SYSCALLS: &[u32] = &[11, 59, 322, 358];
const SOCKETCALL_SYSCALL: u32 = 102;

const SYS_BIND: u32 = 2;
const SYS_CONNECT: u32 = 3;
const SYS_ACCEPT: u32 = 5;
const SYS_SENDTO: u32 = 11;
const SYS_SENDMSG: u32 = 16;
const SYS_ACCEPT4: u32 = 18;
const SYS_SENDMMSG: u32 = 20;

const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;

/// Unique identifier for a correlated set of audit records.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct EventId {
    pub timestamp_sec: u64,
    pub timestamp_ms: u64,
    pub serial: u64,
}

/// A single parsed audit record line.
#[derive(Debug)]
pub struct AuditRecord {
    pub msg_type: u16,
    pub event_id: EventId,
    pub fields: HashMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AuditEvent {
    Exec(ExecEvent),
    Network(NetworkEvent),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExecEvent {
    pub event_id: EventId,
    pub syscall: u32,
    pub pid: u32,
    pub ppid: Option<u32>,
    pub uid: Option<u32>,
    pub audit_loginuid: u32,
    pub audit_sessionid: u32,
    pub comm: Option<String>,
    pub exe: Option<String>,
    pub cwd: Option<String>,
    pub args: Vec<String>,
    pub success: Option<bool>,
    pub exit: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NetworkEvent {
    pub event_id: EventId,
    pub syscall: u32,
    pub op: String,
    pub pid: u32,
    pub ppid: Option<u32>,
    pub uid: Option<u32>,
    pub audit_loginuid: u32,
    pub audit_sessionid: u32,
    pub comm: Option<String>,
    pub exe: Option<String>,
    pub success: bool,
    pub family: String,
    pub address: String,
    pub port: u16,
}

pub struct AuditEventAssembler {
    pending: HashMap<EventId, PendingEvent>,
    enabled_flags: AuditEventFlags,
}

struct PendingEvent {
    syscall: Option<HashMap<String, String>>,
    execve_args: Vec<Option<String>>,
    cwd: Option<String>,
    exe_path: Option<String>,
    saddr: Option<String>,
}

#[derive(Debug, Clone)]
struct DecodedSockaddr {
    family: &'static str,
    address: String,
    port: u16,
    is_loopback: bool,
}

impl AuditEventAssembler {
    pub fn new(enabled_flags: AuditEventFlags) -> Self {
        Self {
            pending: HashMap::new(),
            enabled_flags,
        }
    }

    pub fn push(&mut self, record: AuditRecord) -> Option<AuditEvent> {
        if record.msg_type == AUDIT_EOE {
            return self.finish(&record.event_id);
        }

        let mut finish_network_now = false;
        let entry = self
            .pending
            .entry(record.event_id.clone())
            .or_insert_with(|| PendingEvent {
                syscall: None,
                execve_args: Vec::new(),
                cwd: None,
                exe_path: None,
                saddr: None,
            });

        match record.msg_type {
            AUDIT_SYSCALL => {
                entry.syscall = Some(record.fields);
            }
            AUDIT_EXECVE => {
                let argc = record
                    .fields
                    .get("argc")
                    .and_then(|v| v.parse::<usize>().ok())
                    .unwrap_or(0);

                if entry.execve_args.len() < argc {
                    entry.execve_args.resize(argc, None);
                }

                for i in 0..argc {
                    let key = format!("a{i}");
                    if let Some(val) = record.fields.get(&key) {
                        if i >= entry.execve_args.len() {
                            entry.execve_args.resize(i + 1, None);
                        }
                        if entry.execve_args[i].is_none() {
                            entry.execve_args[i] = Some(val.clone());
                        }
                    }
                }
            }
            AUDIT_CWD => {
                if let Some(cwd) = record.fields.get("cwd") {
                    entry.cwd = Some(cwd.clone());
                }
            }
            AUDIT_PATH => {
                if let Some(item) = record.fields.get("item")
                    && item == "0"
                    && let Some(name) = record.fields.get("name")
                {
                    entry.exe_path = Some(name.clone());
                }
            }
            AUDIT_SOCKADDR => {
                if entry.saddr.is_none()
                    && let Some(saddr) = record.fields.get("saddr")
                {
                    entry.saddr = Some(saddr.clone());
                }
            }
            _ => {}
        }

        if self.enabled_flags.contains(AuditEventFlags::NETWORK)
            && entry.saddr.is_some()
            && entry
                .syscall
                .as_ref()
                .and_then(classify_network_op)
                .is_some()
        {
            finish_network_now = true;
        }

        if finish_network_now {
            return self.finish(&record.event_id);
        }

        None
    }

    pub fn evict_stale(&mut self, max_age_secs: u64) -> Vec<AuditEvent> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let stale_ids: Vec<EventId> = self
            .pending
            .keys()
            .filter(|id| now.saturating_sub(id.timestamp_sec) > max_age_secs)
            .cloned()
            .collect();

        let mut events = Vec::new();
        for id in stale_ids {
            if let Some(event) = self.finish(&id) {
                events.push(event);
            }
        }
        events
    }

    fn finish(&mut self, event_id: &EventId) -> Option<AuditEvent> {
        let pending = self.pending.remove(event_id)?;
        let syscall = pending.syscall.clone()?;
        let syscall_nr = parse_u32_field(&syscall, "syscall")?;

        if self.enabled_flags.contains(AuditEventFlags::EXEC)
            && EXECVE_SYSCALLS.contains(&syscall_nr)
        {
            return Some(AuditEvent::Exec(build_exec_event(
                event_id.clone(),
                syscall_nr,
                &syscall,
                pending,
            )));
        }

        if self.enabled_flags.contains(AuditEventFlags::NETWORK)
            && let Some(op) = classify_network_op(&syscall)
        {
            return build_network_event(event_id.clone(), syscall_nr, op, &syscall, pending)
                .map(AuditEvent::Network);
        }

        None
    }
}

/// Parse the raw data payload of a netlink audit message into an `AuditRecord`.
pub fn parse_audit_message(msg_type: u16, data: &[u8]) -> Option<AuditRecord> {
    let text = std::str::from_utf8(data)
        .ok()?
        .trim_end_matches('\0')
        .trim();
    if text.is_empty() {
        return None;
    }

    let event_id = parse_event_id(text)?;
    let body = text.find("): ").map_or("", |i| &text[i + 3..]);

    let fields = parse_fields(body);

    Some(AuditRecord {
        msg_type,
        event_id,
        fields,
    })
}

fn parse_event_id(text: &str) -> Option<EventId> {
    let start = text.find("audit(")?;
    let rest = &text[start + 6..];
    let end = rest.find(')')?;
    let inner = &rest[..end];

    let colon = inner.find(':')?;
    let ts_part = &inner[..colon];
    let serial_str = &inner[colon + 1..];

    let (sec_str, ms_str) = ts_part
        .find('.')
        .map_or((ts_part, "0"), |dot| (&ts_part[..dot], &ts_part[dot + 1..]));

    Some(EventId {
        timestamp_sec: sec_str.parse().ok()?,
        timestamp_ms: ms_str.parse().ok()?,
        serial: serial_str.parse().ok()?,
    })
}

fn parse_fields(body: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    let mut rest = body.trim();

    while !rest.is_empty() {
        let eq_pos = match rest.find('=') {
            Some(p) => p,
            None => break,
        };

        let key = rest[..eq_pos].trim().trim_start_matches('\u{1d}');
        let key = key.rsplit(' ').next().unwrap_or(key);
        rest = &rest[eq_pos + 1..];

        let (value, advance) = if let Some(after_quote) = rest.strip_prefix('"') {
            match after_quote.find('"') {
                Some(end) => (&after_quote[..end], 1 + end + 1),
                None => (after_quote, rest.len()),
            }
        } else {
            let end = rest.find(' ').unwrap_or(rest.len());
            (&rest[..end], end)
        };

        let decoded = if key == "saddr" {
            value.split('\u{1d}').next().unwrap_or(value).to_string()
        } else {
            decode_value(value)
        };
        map.insert(key.to_string(), decoded);
        rest = rest[advance..].trim_start_matches('\u{1d}').trim_start();
    }

    map
}

fn decode_value(raw: &str) -> String {
    let raw = raw.split('\u{1d}').next().unwrap_or(raw);
    if raw.is_empty() {
        return String::new();
    }

    if raw.len() >= 4
        && raw.len().is_multiple_of(2)
        && raw.bytes().all(|b| b.is_ascii_hexdigit())
        && !raw.bytes().all(|b| b.is_ascii_digit())
        && let Some(decoded) = hex_decode(raw)
    {
        return decoded;
    }

    raw.to_string()
}

fn hex_decode(hex: &str) -> Option<String> {
    let bytes: Option<Vec<u8>> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
        .collect();

    bytes.and_then(|b| {
        let b = if b.last() == Some(&0) {
            &b[..b.len() - 1]
        } else {
            &b
        };
        String::from_utf8(b.to_vec()).ok()
    })
}

fn parse_u32_field(fields: &HashMap<String, String>, key: &str) -> Option<u32> {
    fields.get(key).and_then(|value| parse_u32_value(value))
}

fn parse_u32_value(value: &str) -> Option<u32> {
    value
        .parse::<u32>()
        .ok()
        .or_else(|| {
            value
                .strip_prefix("0x")
                .and_then(|v| u32::from_str_radix(v, 16).ok())
        })
        .or_else(|| {
            if value.bytes().all(|b| b.is_ascii_hexdigit()) {
                u32::from_str_radix(value, 16).ok()
            } else {
                None
            }
        })
}

fn parse_i64_field(fields: &HashMap<String, String>, key: &str) -> Option<i64> {
    fields.get(key).and_then(|v| v.parse::<i64>().ok())
}

fn parse_success(fields: &HashMap<String, String>) -> Option<bool> {
    if let Some(exit) = parse_i64_field(fields, "exit") {
        return Some(exit >= 0);
    }

    match fields.get("success").map(String::as_str) {
        Some("yes") => Some(true),
        Some("no") => Some(false),
        _ => None,
    }
}

fn build_exec_event(
    event_id: EventId,
    syscall: u32,
    syscall_fields: &HashMap<String, String>,
    pending: PendingEvent,
) -> ExecEvent {
    ExecEvent {
        event_id,
        syscall,
        pid: parse_u32_field(syscall_fields, "pid").unwrap_or(0),
        ppid: parse_u32_field(syscall_fields, "ppid"),
        uid: parse_u32_field(syscall_fields, "uid"),
        audit_loginuid: parse_u32_field(syscall_fields, "auid").unwrap_or(u32::MAX),
        audit_sessionid: parse_u32_field(syscall_fields, "ses").unwrap_or(u32::MAX),
        comm: syscall_fields.get("comm").cloned(),
        exe: pending
            .exe_path
            .or_else(|| syscall_fields.get("exe").cloned())
            .filter(|s| !s.is_empty()),
        cwd: pending.cwd.filter(|s| !s.is_empty()),
        args: pending.execve_args.into_iter().flatten().collect(),
        success: parse_success(syscall_fields),
        exit: parse_i64_field(syscall_fields, "exit"),
    }
}

fn classify_network_op(fields: &HashMap<String, String>) -> Option<&'static str> {
    match parse_u32_field(fields, "syscall")? {
        42 => Some("connect"),
        43 => Some("accept"),
        44 => Some("sendto"),
        46 => Some("sendmsg"),
        49 => Some("bind"),
        288 => Some("accept4"),
        307 => Some("sendmmsg"),
        345 => Some("sendmmsg"),
        364 => Some("accept4"),
        SOCKETCALL_SYSCALL => match parse_u32_field(fields, "a0")? {
            SYS_BIND => Some("bind"),
            SYS_CONNECT => Some("connect"),
            SYS_ACCEPT => Some("accept"),
            SYS_SENDTO => Some("sendto"),
            SYS_SENDMSG => Some("sendmsg"),
            SYS_ACCEPT4 => Some("accept4"),
            SYS_SENDMMSG => Some("sendmmsg"),
            _ => None,
        },
        _ => None,
    }
}

fn build_network_event(
    event_id: EventId,
    syscall: u32,
    op: &str,
    syscall_fields: &HashMap<String, String>,
    pending: PendingEvent,
) -> Option<NetworkEvent> {
    let connect_in_progress = op == "connect"
        && parse_i64_field(syscall_fields, "exit") == Some(-(libc::EINPROGRESS as i64));
    if !parse_success(syscall_fields).unwrap_or(false) && !connect_in_progress {
        return None;
    }

    let decoded = decode_sockaddr(pending.saddr.as_deref()?)?;
    if decoded.is_loopback {
        return None;
    }

    Some(NetworkEvent {
        event_id,
        syscall,
        op: op.to_string(),
        pid: parse_u32_field(syscall_fields, "pid").unwrap_or(0),
        ppid: parse_u32_field(syscall_fields, "ppid"),
        uid: parse_u32_field(syscall_fields, "uid"),
        audit_loginuid: parse_u32_field(syscall_fields, "auid").unwrap_or(u32::MAX),
        audit_sessionid: parse_u32_field(syscall_fields, "ses").unwrap_or(u32::MAX),
        comm: syscall_fields.get("comm").cloned(),
        exe: pending
            .exe_path
            .or_else(|| syscall_fields.get("exe").cloned())
            .filter(|s| !s.is_empty()),
        success: true,
        family: decoded.family.to_string(),
        address: decoded.address,
        port: decoded.port,
    })
}

fn decode_sockaddr(raw: &str) -> Option<DecodedSockaddr> {
    let bytes = hex_bytes(raw)?;
    if bytes.len() < 8 {
        return None;
    }

    let family = u16::from_le_bytes([bytes[0], bytes[1]]);
    match family {
        AF_INET => {
            let port = u16::from_be_bytes([bytes[2], bytes[3]]);
            let addr = Ipv4Addr::new(bytes[4], bytes[5], bytes[6], bytes[7]);
            Some(DecodedSockaddr {
                family: "ipv4",
                address: addr.to_string(),
                port,
                is_loopback: addr.octets()[0] == 127,
            })
        }
        AF_INET6 => {
            if bytes.len() < 24 {
                return None;
            }
            let port = u16::from_be_bytes([bytes[2], bytes[3]]);
            let mut addr_bytes = [0u8; 16];
            addr_bytes.copy_from_slice(&bytes[8..24]);
            let addr = Ipv6Addr::from(addr_bytes);
            Some(DecodedSockaddr {
                family: "ipv6",
                address: addr.to_string(),
                port,
                is_loopback: addr == Ipv6Addr::LOCALHOST,
            })
        }
        _ => None,
    }
}

fn hex_bytes(raw: &str) -> Option<Vec<u8>> {
    if raw.is_empty() || !raw.len().is_multiple_of(2) || !raw.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return None;
    }

    (0..raw.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&raw[i..i + 2], 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(msg_type: u16, event_id: &EventId, fields: &[(&str, &str)]) -> AuditRecord {
        AuditRecord {
            msg_type,
            event_id: event_id.clone(),
            fields: fields
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect(),
        }
    }

    #[test]
    fn test_parse_event_id() {
        let text = r#"audit(1678901234.567:1234): pid=100 uid=0"#;
        let id = parse_event_id(text).unwrap();
        assert_eq!(id.timestamp_sec, 1678901234);
        assert_eq!(id.timestamp_ms, 567);
        assert_eq!(id.serial, 1234);
    }

    #[test]
    fn test_parse_fields_basic() {
        let body = r#"pid=1234 uid=0 comm="bash" exe="/usr/bin/bash""#;
        let fields = parse_fields(body);
        assert_eq!(fields.get("pid").unwrap(), "1234");
        assert_eq!(fields.get("uid").unwrap(), "0");
        assert_eq!(fields.get("comm").unwrap(), "bash");
        assert_eq!(fields.get("exe").unwrap(), "/usr/bin/bash");
    }

    #[test]
    fn test_parse_fields_hex_value() {
        let body = r#"argc=1 a0=6C73"#;
        let fields = parse_fields(body);
        assert_eq!(fields.get("argc").unwrap(), "1");
        assert_eq!(fields.get("a0").unwrap(), "ls");
    }

    #[test]
    fn test_parse_audit_message_syscall() {
        let data = b"audit(1678901234.567:100): arch=c000003e syscall=59 pid=5678 ppid=1000 uid=0 ses=1 comm=\"bash\" exe=\"/usr/bin/bash\"\0";
        let rec = parse_audit_message(AUDIT_SYSCALL, data).unwrap();
        assert_eq!(rec.msg_type, AUDIT_SYSCALL);
        assert_eq!(rec.fields.get("pid").unwrap(), "5678");
        assert_eq!(rec.fields.get("ppid").unwrap(), "1000");
        assert_eq!(rec.fields.get("comm").unwrap(), "bash");
    }

    #[test]
    fn test_parse_audit_message_execve() {
        let data = b"audit(1678901234.567:100): argc=3 a0=\"ls\" a1=\"-la\" a2=\"/tmp\"\0";
        let rec = parse_audit_message(AUDIT_EXECVE, data).unwrap();
        assert_eq!(rec.fields.get("argc").unwrap(), "3");
        assert_eq!(rec.fields.get("a0").unwrap(), "ls");
        assert_eq!(rec.fields.get("a1").unwrap(), "-la");
    }

    #[test]
    fn test_parse_sockaddr_with_interpreted_suffix() {
        let data = b"audit(1678901234.567:100): saddr=020001BBC633640A0000000000000000\x1dSADDR={ saddr_fam=inet laddr=198.51.100.10 lport=443 }\0";
        let rec = parse_audit_message(AUDIT_SOCKADDR, data).unwrap();
        assert_eq!(
            rec.fields.get("saddr").unwrap(),
            "020001BBC633640A0000000000000000"
        );
    }

    #[test]
    fn test_parse_sockaddr_preserves_non_utf8ish_hex_for_wildcard_bind() {
        let data = b"audit(1775352641.050:15431): saddr=0200115C000000000000000000000000\x1dSADDR={ saddr_fam=inet laddr=0.0.0.0 lport=4444 }\0";
        let rec = parse_audit_message(AUDIT_SOCKADDR, data).unwrap();
        assert_eq!(
            rec.fields.get("saddr").unwrap(),
            "0200115C000000000000000000000000"
        );
    }

    #[test]
    fn test_assembler_emits_exec_event() {
        let event_id = EventId {
            timestamp_sec: 1,
            timestamp_ms: 2,
            serial: 3,
        };

        let mut asm = AuditEventAssembler::new(AuditEventFlags::EXEC);
        assert!(
            asm.push(record(
                AUDIT_SYSCALL,
                &event_id,
                &[
                    ("syscall", "59"),
                    ("pid", "123"),
                    ("ppid", "1"),
                    ("uid", "1000"),
                    ("auid", "1000"),
                    ("ses", "4"),
                    ("comm", "bash"),
                    ("exe", "/usr/bin/bash"),
                    ("success", "yes"),
                    ("exit", "0"),
                ],
            ))
            .is_none()
        );
        assert!(
            asm.push(record(
                AUDIT_EXECVE,
                &event_id,
                &[("argc", "2"), ("a0", "bash"), ("a1", "-lc")],
            ))
            .is_none()
        );
        assert!(
            asm.push(record(AUDIT_CWD, &event_id, &[("cwd", "/home/ubuntu")]))
                .is_none()
        );

        let event = asm
            .push(record(AUDIT_EOE, &event_id, &[]))
            .expect("expected exec event");

        let AuditEvent::Exec(event) = event else {
            panic!("expected exec event");
        };

        assert_eq!(event.pid, 123);
        assert_eq!(event.exe.as_deref(), Some("/usr/bin/bash"));
        assert_eq!(event.cwd.as_deref(), Some("/home/ubuntu"));
        assert_eq!(event.args, vec!["bash".to_string(), "-lc".to_string()]);
        assert_eq!(event.success, Some(true));
    }

    #[test]
    fn test_assembler_emits_network_event() {
        let event_id = EventId {
            timestamp_sec: 1,
            timestamp_ms: 2,
            serial: 4,
        };

        let mut asm = AuditEventAssembler::new(AuditEventFlags::NETWORK);
        assert!(
            asm.push(record(
                AUDIT_SYSCALL,
                &event_id,
                &[
                    ("syscall", "42"),
                    ("pid", "4321"),
                    ("ppid", "1"),
                    ("uid", "1000"),
                    ("auid", "1000"),
                    ("ses", "4"),
                    ("comm", "curl"),
                    ("exe", "/usr/bin/curl"),
                    ("success", "yes"),
                    ("exit", "0"),
                ],
            ))
            .is_none()
        );
        let event = asm
            .push(record(
                AUDIT_SOCKADDR,
                &event_id,
                &[("saddr", "020001BBC633640A")],
            ))
            .expect("expected network event");

        let AuditEvent::Network(event) = event else {
            panic!("expected network event");
        };

        assert_eq!(event.op, "connect");
        assert_eq!(event.family, "ipv4");
        assert_eq!(event.address, "198.51.100.10");
        assert_eq!(event.port, 443);
    }

    #[test]
    fn test_assembler_emits_connect_event_for_einprogress() {
        let event_id = EventId {
            timestamp_sec: 1,
            timestamp_ms: 2,
            serial: 44,
        };

        let mut asm = AuditEventAssembler::new(AuditEventFlags::NETWORK);
        assert!(
            asm.push(record(
                AUDIT_SYSCALL,
                &event_id,
                &[
                    ("syscall", "42"),
                    ("pid", "4321"),
                    ("ppid", "1"),
                    ("uid", "1000"),
                    ("auid", "1000"),
                    ("ses", "4"),
                    ("comm", "curl"),
                    ("exe", "/usr/bin/curl"),
                    ("success", "no"),
                    ("exit", "-115"),
                ],
            ))
            .is_none()
        );
        let event = asm
            .push(record(
                AUDIT_SOCKADDR,
                &event_id,
                &[("saddr", "020001BBC633640A")],
            ))
            .expect("expected network event");

        let AuditEvent::Network(event) = event else {
            panic!("expected network event");
        };

        assert_eq!(event.op, "connect");
        assert_eq!(event.family, "ipv4");
        assert_eq!(event.address, "198.51.100.10");
        assert_eq!(event.port, 443);
    }

    #[test]
    fn test_assembler_emits_bind_event_for_wildcard_listener() {
        let event_id = EventId {
            timestamp_sec: 1,
            timestamp_ms: 2,
            serial: 45,
        };

        let mut asm = AuditEventAssembler::new(AuditEventFlags::NETWORK);
        assert!(
            asm.push(record(
                AUDIT_SYSCALL,
                &event_id,
                &[
                    ("syscall", "49"),
                    ("pid", "13395"),
                    ("ppid", "13392"),
                    ("uid", "0"),
                    ("auid", "1000"),
                    ("ses", "115"),
                    ("comm", "nc"),
                    ("exe", "/usr/bin/nc.openbsd"),
                    ("success", "yes"),
                    ("exit", "0"),
                ],
            ))
            .is_none()
        );
        let event = asm
            .push(record(
                AUDIT_SOCKADDR,
                &event_id,
                &[("saddr", "0200115C000000000000000000000000")],
            ))
            .expect("expected bind network event");

        let AuditEvent::Network(event) = event else {
            panic!("expected network event");
        };

        assert_eq!(event.op, "bind");
        assert_eq!(event.family, "ipv4");
        assert_eq!(event.address, "0.0.0.0");
        assert_eq!(event.port, 4444);
    }

    #[test]
    fn test_assembler_drops_loopback_network_event() {
        let event_id = EventId {
            timestamp_sec: 1,
            timestamp_ms: 2,
            serial: 5,
        };

        let mut asm = AuditEventAssembler::new(AuditEventFlags::NETWORK);
        assert!(
            asm.push(record(
                AUDIT_SYSCALL,
                &event_id,
                &[
                    ("syscall", "42"),
                    ("pid", "4321"),
                    ("success", "yes"),
                    ("exit", "0"),
                ],
            ))
            .is_none()
        );
        assert!(
            asm.push(record(
                AUDIT_SOCKADDR,
                &event_id,
                &[("saddr", "020000507F000001")],
            ))
            .is_none()
        );

        assert!(asm.push(record(AUDIT_EOE, &event_id, &[])).is_none());
    }

    #[test]
    fn test_assembler_drops_network_without_sockaddr() {
        let event_id = EventId {
            timestamp_sec: 1,
            timestamp_ms: 2,
            serial: 6,
        };

        let mut asm = AuditEventAssembler::new(AuditEventFlags::NETWORK);
        assert!(
            asm.push(record(
                AUDIT_SYSCALL,
                &event_id,
                &[
                    ("syscall", "49"),
                    ("pid", "4321"),
                    ("success", "yes"),
                    ("exit", "0"),
                ],
            ))
            .is_none()
        );

        assert!(asm.push(record(AUDIT_EOE, &event_id, &[])).is_none());
    }

    #[test]
    fn test_decode_sockaddr_ipv6_loopback() {
        let decoded = decode_sockaddr("0A0000500000000000000000000000000000000000000001").unwrap();
        assert_eq!(decoded.family, "ipv6");
        assert!(decoded.is_loopback);
    }
}
