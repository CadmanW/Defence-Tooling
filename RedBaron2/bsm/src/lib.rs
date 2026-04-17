use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

// --- Token type IDs (1 byte, from audit_record.h) ---
const AUT_TRAILER: u8 = 0x13;
const AUT_HEADER32: u8 = 0x14;
const AUT_HEADER32_EX: u8 = 0x15;
const AUT_ARG32: u8 = 0x2d;
const AUT_ARG64: u8 = 0x71;
const AUT_PATH: u8 = 0x23;
const AUT_SOCKINET32: u8 = 0x80;
const AUT_SOCKINET128: u8 = 0x81;
const AUT_SOCKUNIX: u8 = 0x82;
const AUT_SUBJECT32: u8 = 0x24;
const AUT_SUBJECT32_EX: u8 = 0x7a;
const AUT_RETURN32: u8 = 0x27;
const AUT_RETURN64: u8 = 0x72;
const AUT_TEXT: u8 = 0x28;
const AUT_EXEC_ARGS: u8 = 0x3c;
const AUT_EXEC_ENV: u8 = 0x3d;
const AUT_HEADER64: u8 = 0x74;
const AUT_HEADER64_EX: u8 = 0x79;
const AUT_SUBJECT64: u8 = 0x75;
const AUT_SUBJECT64_EX: u8 = 0x7c;
const AUT_ATTR32: u8 = 0x3e;

const AU_IPV4: u32 = 4;
const AU_IPV6: u32 = 16;

const AUT_TRAILER_MAGIC: u16 = 0xb105;

// --- Event type IDs (from audit_kevents.h) ---
const AUE_EXECVE: u16 = 23;
const AUE_CONNECT: u16 = 32;
const AUE_ACCEPT: u16 = 33;
const AUE_BIND: u16 = 34;
const AUE_LOGIN: u16 = 6152;
const AUE_LOGOUT: u16 = 6153;
const AUE_SU: u16 = 6159;
const AUE_SSH: u16 = 6172;
const AUE_OPENSSH: u16 = 32800;
const AUE_SUDO: u16 = 45028;
const AUE_PASSWD: u16 = 6163;
const AUE_MODIFY_PASSWORD: u16 = 45014;
const AUE_CREATE_USER: u16 = 6207;
const AUE_DELETE_USER: u16 = 6209;
const AUE_MODIFY_USER: u16 = 6208;
const AUE_PTRACE: u16 = 43002;
const AUE_SETUID: u16 = 200;
const AUE_SETGID: u16 = 205;
const AUE_AUDIT_SHUTDOWN: u16 = 45001;
const AUE_MODLOAD: u16 = 243;
const AUE_UNMODLOAD: u16 = 244;
const AUE_KTRACE: u16 = 43006;

// --- Error type ---

#[derive(Debug)]
pub enum ParseError {
    /// Not enough bytes in the buffer.
    Truncated { needed: usize, available: usize },
    /// Trailer token had an unexpected magic value.
    InvalidMagic(u16),
    /// An Ex token contained an unrecognised address-type field.
    UnknownAddrType(u32),
    /// record_size field was zero or outside the plausible range.
    InvalidRecordSize(usize),
    /// First token was not a header.
    NotAHeader(u8),
    /// parse_records detected that parse_record consumed zero bytes.
    NoProgress,
    /// Token type byte was not recognised.
    UnknownToken(u8),
    /// An underlying I/O error from read_record.
    Io(std::io::Error),
    /// Misc parsing error (e.g. missing NUL terminator).
    Other(String),
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseError::Truncated { needed, available } => {
                write!(f, "truncated: need {needed} bytes, have {available}")
            }
            ParseError::InvalidMagic(m) => write!(f, "invalid trailer magic: {m:#06x}"),
            ParseError::UnknownAddrType(t) => write!(f, "unknown address type: {t}"),
            ParseError::InvalidRecordSize(s) => write!(f, "invalid record size: {s}"),
            ParseError::NotAHeader(b) => write!(f, "expected header token, got {b:#04x}"),
            ParseError::NoProgress => write!(f, "parser made no progress"),
            ParseError::UnknownToken(t) => write!(f, "unknown token type: {t:#04x}"),
            ParseError::Io(e) => write!(f, "I/O error: {e}"),
            ParseError::Other(s) => write!(f, "{s}"),
        }
    }
}

impl std::error::Error for ParseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ParseError::Io(e) => Some(e),
            _ => None,
        }
    }
}

// --- Public API types ---

/// Normalized audit subject. Fields are the same regardless of whether the
/// wire record used Subject32, Subject64, or the Ex variants.
#[derive(Debug, Default)]
pub struct Subject {
    pub audit_id: u32,
    /// Real user ID.
    pub uid: u32,
    /// Real group ID.
    pub gid: u32,
    /// Effective user ID.
    pub euid: u32,
    /// Effective group ID.
    pub egid: u32,
    pub pid: u32,
    pub session_id: u32,
    /// Terminal port/device identifier.
    pub terminal_port: u64,
    /// Remote terminal address, if present (SSH source IP etc.). None for local sessions.
    pub terminal: Option<IpAddr>,
}

/// A parsed and interpreted BSM audit record.
///
/// `#[non_exhaustive]` ensures that adding new variants in the future is not
/// a breaking change for consumers - their `_ =>` arms continue to compile.
#[non_exhaustive]
#[derive(Debug)]
pub enum AuditRecord {
    Exec {
        timestamp: u64,
        milliseconds: u32,
        event_modifier: u16,
        subject: Subject,
        exe: Option<String>,
        args: Vec<String>,
        env: Vec<String>,
        success: bool,
        return_error: Option<u8>,
        return_value: Option<u64>,
    },
    Connect {
        timestamp: u64,
        milliseconds: u32,
        event_modifier: u16,
        subject: Subject,
        remote: Option<SocketAddr>,
        success: bool,
        return_value: Option<u64>,
    },
    Bind {
        timestamp: u64,
        milliseconds: u32,
        event_modifier: u16,
        subject: Subject,
        local: Option<SocketAddr>,
        success: bool,
        return_value: Option<u64>,
    },
    Accept {
        timestamp: u64,
        milliseconds: u32,
        event_modifier: u16,
        subject: Subject,
        remote: Option<SocketAddr>,
        success: bool,
        return_value: Option<u64>,
    },
    Login {
        timestamp: u64,
        milliseconds: u32,
        event_modifier: u16,
        subject: Subject,
        success: bool,
        return_value: Option<u64>,
    },
    Logout {
        timestamp: u64,
        milliseconds: u32,
        event_modifier: u16,
        subject: Subject,
    },
    SshLogin {
        timestamp: u64,
        milliseconds: u32,
        event_modifier: u16,
        subject: Subject,
        success: bool,
        return_value: Option<u64>,
    },
    Su {
        timestamp: u64,
        milliseconds: u32,
        event_modifier: u16,
        subject: Subject,
        /// The username that was switched to, if present in a text token.
        target_user: Option<String>,
        success: bool,
        return_value: Option<u64>,
    },
    Sudo {
        timestamp: u64,
        milliseconds: u32,
        event_modifier: u16,
        subject: Subject,
        args: Vec<String>,
        failure_text: Option<String>,
        success: bool,
        return_value: Option<u64>,
    },
    Ktrace {
        timestamp: u64,
        milliseconds: u32,
        event_modifier: u16,
        subject: Subject,
        /// Ktrace ops bitmask (KTROP_SET, KTROP_CLEAR, etc.).
        ops: Option<u32>,
        /// Trace points bitmask (KTRFAC_SYSCALL, KTRFAC_NAMEI, etc.).
        trpoints: Option<u32>,
        /// Target process PID, if the call targeted a single process.
        target_pid: Option<u32>,
        /// Path to the ktrace output file, if present.
        output_file: Option<String>,
        success: bool,
        return_value: Option<u64>,
    },
    SetUid {
        timestamp: u64,
        milliseconds: u32,
        event_modifier: u16,
        subject: Subject,
        /// New UID passed to setuid(2), if present.
        new_uid: Option<u32>,
        success: bool,
        return_value: Option<u64>,
    },
    SetGid {
        timestamp: u64,
        milliseconds: u32,
        event_modifier: u16,
        subject: Subject,
        /// New GID passed to setgid(2), if present.
        new_gid: Option<u32>,
        success: bool,
        return_value: Option<u64>,
    },
    Ptrace {
        timestamp: u64,
        milliseconds: u32,
        event_modifier: u16,
        subject: Subject,
        /// ptrace(2) request type (PT_TRACE_ME, PT_READ_I, etc.).
        request: Option<u32>,
        /// Target PID (from PROCESS_PID_TOKENS).
        target_pid: Option<u32>,
        /// ptrace data argument.
        data: Option<u32>,
        success: bool,
        return_value: Option<u64>,
    },
    ModLoad {
        timestamp: u64,
        milliseconds: u32,
        event_modifier: u16,
        subject: Subject,
        success: bool,
        return_value: Option<u64>,
    },
    ModUnload {
        timestamp: u64,
        milliseconds: u32,
        event_modifier: u16,
        subject: Subject,
        success: bool,
        return_value: Option<u64>,
    },
    AuditShutdown {
        timestamp: u64,
        milliseconds: u32,
        event_modifier: u16,
        subject: Subject,
        /// Description text (e.g. "auditd::Audit shutdown").
        text: Option<String>,
        success: bool,
        return_value: Option<u64>,
    },
    Passwd {
        timestamp: u64,
        milliseconds: u32,
        event_modifier: u16,
        subject: Subject,
        text_tokens: Vec<String>,
        success: bool,
        return_value: Option<u64>,
    },
    ModifyPassword {
        timestamp: u64,
        milliseconds: u32,
        event_modifier: u16,
        subject: Subject,
        text_tokens: Vec<String>,
        success: bool,
        return_value: Option<u64>,
    },
    CreateUser {
        timestamp: u64,
        milliseconds: u32,
        event_modifier: u16,
        subject: Subject,
        text_tokens: Vec<String>,
        success: bool,
        return_value: Option<u64>,
    },
    DeleteUser {
        timestamp: u64,
        milliseconds: u32,
        event_modifier: u16,
        subject: Subject,
        text_tokens: Vec<String>,
        success: bool,
        return_value: Option<u64>,
    },
    ModifyUser {
        timestamp: u64,
        milliseconds: u32,
        event_modifier: u16,
        subject: Subject,
        text_tokens: Vec<String>,
        success: bool,
        return_value: Option<u64>,
    },
    Other {
        event_type: u16,
        timestamp: u64,
        milliseconds: u32,
        event_modifier: u16,
        subject: Option<Subject>,
    },
}

// --- Internal token payload structs ---
// These are implementation details of the parser. Consumers use AuditRecord.

mod internal {
    #[allow(dead_code)]
    #[derive(Debug)]
    pub struct Header32 {
        pub record_size: u32,
        pub version: u8,
        pub event_type: u16,
        pub event_modifier: u16,
        pub seconds: u32,
        pub milliseconds: u32,
    }

    #[allow(dead_code)]
    #[derive(Debug)]
    pub struct Header64 {
        pub record_size: u32,
        pub version: u8,
        pub event_type: u16,
        pub event_modifier: u16,
        pub seconds: u64,
        pub milliseconds: u64,
    }

    #[allow(dead_code)]
    #[derive(Debug)]
    pub struct Header32Ex {
        pub record_size: u32,
        pub version: u8,
        pub event_type: u16,
        pub event_modifier: u16,
        pub addr_type: u32,
        pub machine_addr: [u8; 16],
        pub seconds: u32,
        pub milliseconds: u32,
    }

    #[allow(dead_code)]
    #[derive(Debug)]
    pub struct Header64Ex {
        pub record_size: u32,
        pub version: u8,
        pub event_type: u16,
        pub event_modifier: u16,
        pub addr_type: u32,
        pub machine_addr: [u8; 16],
        pub seconds: u64,
        pub milliseconds: u64,
    }

    #[allow(dead_code)]
    #[derive(Debug)]
    pub struct Trailer {
        pub record_size: u32,
    }

    #[allow(dead_code)]
    #[derive(Debug)]
    pub struct Subject32 {
        pub audit_id: u32,
        pub euid: u32,
        pub egid: u32,
        pub ruid: u32,
        pub rgid: u32,
        pub pid: u32,
        pub session_id: u32,
        pub terminal_port: u32,
        pub terminal_addr: u32,
    }

    #[allow(dead_code)]
    #[derive(Debug)]
    pub struct Subject64 {
        pub audit_id: u32,
        pub euid: u32,
        pub egid: u32,
        pub ruid: u32,
        pub rgid: u32,
        pub pid: u32,
        pub session_id: u32,
        pub terminal_port: u64,
        pub terminal_addr: u32,
    }

    #[allow(dead_code)]
    #[derive(Debug)]
    pub struct Subject32Ex {
        pub audit_id: u32,
        pub euid: u32,
        pub egid: u32,
        pub ruid: u32,
        pub rgid: u32,
        pub pid: u32,
        pub session_id: u32,
        pub terminal_port: u32,
        pub addr_type: u32,
        pub addr: [u8; 16],
    }

    #[allow(dead_code)]
    #[derive(Debug)]
    pub struct Subject64Ex {
        pub audit_id: u32,
        pub euid: u32,
        pub egid: u32,
        pub ruid: u32,
        pub rgid: u32,
        pub pid: u32,
        pub session_id: u32,
        pub terminal_port: u64,
        pub addr_type: u32,
        pub addr: [u8; 16],
    }

    #[allow(dead_code)]
    #[derive(Debug)]
    pub struct Attr32 {
        pub file_access_mode: u16,
        pub owner_id: u32,
        pub group_id: u32,
        pub filesystem_id: u32,
        pub node_id: u64,
        pub device: u32,
    }

    #[allow(dead_code)]
    #[derive(Debug)]
    pub struct Return32 {
        pub error: u8,
        pub value: u32,
    }

    #[allow(dead_code)]
    #[derive(Debug)]
    pub struct Return64 {
        pub error: u8,
        pub value: u64,
    }

    #[allow(dead_code)]
    #[derive(Debug)]
    pub struct Arg32 {
        pub num: u8,
        pub value: u32,
        pub text: String,
    }

    #[allow(dead_code)]
    #[derive(Debug)]
    pub struct Arg64 {
        pub num: u8,
        pub value: u64,
        pub text: String,
    }

    #[allow(dead_code)]
    #[derive(Debug)]
    pub struct SockInet32 {
        pub socket_family: u16,
        pub local_port: u16,
        pub socket_address: u32,
    }

    #[allow(dead_code)]
    #[derive(Debug)]
    pub struct SockInet128 {
        pub socket_family: u8,
        pub local_port: u16,
        pub socket_address: [u8; 16],
    }

    #[allow(dead_code)]
    #[derive(Debug)]
    pub struct SockUnix {
        pub socket_family: u8,
        pub path: String,
    }

    #[allow(dead_code)]
    #[derive(Debug)]
    pub struct Path {
        pub path: String,
    }

    #[allow(dead_code)]
    #[derive(Debug)]
    pub struct Text {
        pub text: String,
    }

    #[allow(dead_code)]
    #[derive(Debug)]
    pub struct ExecArgs {
        pub args: Vec<String>,
    }

    #[allow(dead_code)]
    #[derive(Debug)]
    pub struct ExecEnv {
        pub vars: Vec<String>,
    }
}

use internal::*;

#[allow(dead_code)]
#[derive(Debug)]
enum Token {
    Header32(Header32),
    Header32Ex(Header32Ex),
    Header64(Header64),
    Header64Ex(Header64Ex),
    Trailer(Trailer),
    Subject32(Subject32),
    Subject32Ex(Subject32Ex),
    Subject64(Subject64),
    Subject64Ex(Subject64Ex),
    Return32(Return32),
    Return64(Return64),
    SockInet32(SockInet32),
    SockInet128(SockInet128),
    SockUnix(SockUnix),
    Arg32(Arg32),
    Arg64(Arg64),
    Attr32(Attr32),
    Path(Path),
    Text(Text),
    ExecArgs(ExecArgs),
    ExecEnv(ExecEnv),
}

// --- Record accumulator ---
// Tokens are folded into this as they are parsed. into_record() then produces
// the typed AuditRecord. Adding a new token type means adding one fold arm here
// and one assembly arm in into_record().

#[derive(Default)]
struct RecordAccumulator {
    event_type: Option<u16>,
    event_modifier: Option<u16>,
    timestamp: Option<u64>,
    milliseconds: Option<u32>,
    subject: Option<Subject>,
    exe: Option<String>,
    args: Option<Vec<String>>,
    env: Vec<String>,
    socket: Option<SocketAddr>,
    text_tokens: Vec<String>,
    arg_tokens: Vec<(u8, u64)>,
    return_error: Option<u8>,
    return_value: Option<u64>,
}

impl RecordAccumulator {
    fn fold_token(&mut self, token: Token) {
        match token {
            Token::Header32(h) => {
                self.event_type = Some(h.event_type);
                self.event_modifier = Some(h.event_modifier);
                self.timestamp = Some(h.seconds as u64);
                self.milliseconds = Some(h.milliseconds);
            }
            Token::Header32Ex(h) => {
                self.event_type = Some(h.event_type);
                self.event_modifier = Some(h.event_modifier);
                self.timestamp = Some(h.seconds as u64);
                self.milliseconds = Some(h.milliseconds);
            }
            Token::Header64(h) => {
                self.event_type = Some(h.event_type);
                self.event_modifier = Some(h.event_modifier);
                self.timestamp = Some(h.seconds);
                self.milliseconds = Some(h.milliseconds as u32);
            }
            Token::Header64Ex(h) => {
                self.event_type = Some(h.event_type);
                self.event_modifier = Some(h.event_modifier);
                self.timestamp = Some(h.seconds);
                self.milliseconds = Some(h.milliseconds as u32);
            }
            Token::Subject32(s) => {
                self.subject = Some(Subject {
                    audit_id: s.audit_id,
                    uid: s.ruid,
                    gid: s.rgid,
                    euid: s.euid,
                    egid: s.egid,
                    pid: s.pid,
                    session_id: s.session_id,
                    terminal_port: s.terminal_port as u64,
                    terminal: ipv4_addr(s.terminal_addr),
                });
            }
            Token::Subject64(s) => {
                self.subject = Some(Subject {
                    audit_id: s.audit_id,
                    uid: s.ruid,
                    gid: s.rgid,
                    euid: s.euid,
                    egid: s.egid,
                    pid: s.pid,
                    session_id: s.session_id,
                    terminal_port: s.terminal_port,
                    terminal: ipv4_addr(s.terminal_addr),
                });
            }
            Token::Subject32Ex(s) => {
                self.subject = Some(Subject {
                    audit_id: s.audit_id,
                    uid: s.ruid,
                    gid: s.rgid,
                    euid: s.euid,
                    egid: s.egid,
                    pid: s.pid,
                    session_id: s.session_id,
                    terminal_port: s.terminal_port as u64,
                    terminal: ex_addr(s.addr_type, &s.addr),
                });
            }
            Token::Subject64Ex(s) => {
                self.subject = Some(Subject {
                    audit_id: s.audit_id,
                    uid: s.ruid,
                    gid: s.rgid,
                    euid: s.euid,
                    egid: s.egid,
                    pid: s.pid,
                    session_id: s.session_id,
                    terminal_port: s.terminal_port,
                    terminal: ex_addr(s.addr_type, &s.addr),
                });
            }
            Token::ExecArgs(e) => {
                self.args = Some(e.args);
            }
            Token::ExecEnv(e) => {
                self.env = e.vars;
            }
            Token::Path(p) => {
                // First path token is the executable
                if self.exe.is_none() {
                    self.exe = Some(p.path);
                }
            }
            Token::Text(t) => {
                self.text_tokens.push(t.text);
            }
            Token::Return32(r) => {
                self.return_error = Some(r.error);
                self.return_value = Some(r.value as u64);
            }
            Token::Return64(r) => {
                self.return_error = Some(r.error);
                self.return_value = Some(r.value);
            }
            Token::SockInet32(s) => {
                if self.socket.is_none() && s.socket_address != 0 {
                    self.socket = Some(SocketAddr::V4(SocketAddrV4::new(
                        Ipv4Addr::from(s.socket_address),
                        s.local_port,
                    )));
                }
            }
            Token::SockInet128(s) => {
                if self.socket.is_none() {
                    self.socket = Some(SocketAddr::V6(SocketAddrV6::new(
                        Ipv6Addr::from(s.socket_address),
                        s.local_port,
                        0,
                        0,
                    )));
                }
            }
            Token::Arg32(a) => {
                self.arg_tokens.push((a.num, a.value as u64));
            }
            Token::Arg64(a) => {
                self.arg_tokens.push((a.num, a.value));
            }
            // Trailer, Attr32, SockUnix - not needed for assembly
            _ => {}
        }
    }

    fn into_record(self) -> AuditRecord {
        let timestamp = self.timestamp.unwrap_or(0);
        let milliseconds = self.milliseconds.unwrap_or(0);
        let event_modifier = self.event_modifier.unwrap_or(0);
        let event_type = match self.event_type {
            Some(t) => t,
            None => {
                return AuditRecord::Other {
                    event_type: 0,
                    timestamp,
                    milliseconds,
                    event_modifier,
                    subject: self.subject,
                };
            }
        };
        let subject = self.subject.unwrap_or_default();
        let success = self.return_error == Some(0);
        let return_error = self.return_error;
        let return_value = self.return_value;

        match event_type {
            AUE_EXECVE => AuditRecord::Exec {
                timestamp,
                milliseconds,
                event_modifier,
                subject,
                exe: self.exe,
                args: self.args.unwrap_or_default(),
                env: self.env,
                success,
                return_error,
                return_value,
            },
            AUE_CONNECT => AuditRecord::Connect {
                timestamp,
                milliseconds,
                event_modifier,
                subject,
                remote: self.socket,
                success,
                return_value,
            },
            AUE_BIND => AuditRecord::Bind {
                timestamp,
                milliseconds,
                event_modifier,
                subject,
                local: self.socket,
                success,
                return_value,
            },
            AUE_ACCEPT => AuditRecord::Accept {
                timestamp,
                milliseconds,
                event_modifier,
                subject,
                remote: self.socket,
                success,
                return_value,
            },
            AUE_LOGIN => AuditRecord::Login {
                timestamp,
                milliseconds,
                event_modifier,
                subject,
                success,
                return_value,
            },
            AUE_LOGOUT => AuditRecord::Logout {
                timestamp,
                milliseconds,
                event_modifier,
                subject,
            },
            AUE_SSH | AUE_OPENSSH => AuditRecord::SshLogin {
                timestamp,
                milliseconds,
                event_modifier,
                subject,
                success,
                return_value,
            },
            AUE_SU => AuditRecord::Su {
                timestamp,
                milliseconds,
                event_modifier,
                subject,
                target_user: self.text_tokens.into_iter().next(),
                success,
                return_value,
            },
            AUE_SUDO => AuditRecord::Sudo {
                timestamp,
                milliseconds,
                event_modifier,
                subject,
                args: self.args.unwrap_or_default(),
                failure_text: self.text_tokens.into_iter().next(),
                success,
                return_value,
            },
            AUE_SETUID => AuditRecord::SetUid {
                timestamp,
                milliseconds,
                event_modifier,
                subject,
                new_uid: self
                    .arg_tokens
                    .iter()
                    .find(|(n, _)| *n == 1)
                    .map(|(_, v)| *v as u32),
                success,
                return_value,
            },
            AUE_SETGID => AuditRecord::SetGid {
                timestamp,
                milliseconds,
                event_modifier,
                subject,
                new_gid: self
                    .arg_tokens
                    .iter()
                    .find(|(n, _)| *n == 1)
                    .map(|(_, v)| *v as u32),
                success,
                return_value,
            },
            AUE_PTRACE => {
                let find_arg = |num: u8| -> Option<u32> {
                    self.arg_tokens
                        .iter()
                        .find(|(n, _)| *n == num)
                        .map(|(_, v)| *v as u32)
                };
                AuditRecord::Ptrace {
                    timestamp,
                    milliseconds,
                    event_modifier,
                    subject,
                    request: find_arg(1),
                    target_pid: find_arg(2),
                    data: find_arg(4),
                    success,
                    return_value,
                }
            }
            AUE_MODLOAD => AuditRecord::ModLoad {
                timestamp,
                milliseconds,
                event_modifier,
                subject,
                success,
                return_value,
            },
            AUE_UNMODLOAD => AuditRecord::ModUnload {
                timestamp,
                milliseconds,
                event_modifier,
                subject,
                success,
                return_value,
            },
            AUE_AUDIT_SHUTDOWN => AuditRecord::AuditShutdown {
                timestamp,
                milliseconds,
                event_modifier,
                subject,
                text: self.text_tokens.into_iter().next(),
                success,
                return_value,
            },
            AUE_PASSWD => AuditRecord::Passwd {
                timestamp,
                milliseconds,
                event_modifier,
                subject,
                text_tokens: self.text_tokens,
                success,
                return_value,
            },
            AUE_MODIFY_PASSWORD => AuditRecord::ModifyPassword {
                timestamp,
                milliseconds,
                event_modifier,
                subject,
                text_tokens: self.text_tokens,
                success,
                return_value,
            },
            AUE_CREATE_USER => AuditRecord::CreateUser {
                timestamp,
                milliseconds,
                event_modifier,
                subject,
                text_tokens: self.text_tokens,
                success,
                return_value,
            },
            AUE_DELETE_USER => AuditRecord::DeleteUser {
                timestamp,
                milliseconds,
                event_modifier,
                subject,
                text_tokens: self.text_tokens,
                success,
                return_value,
            },
            AUE_MODIFY_USER => AuditRecord::ModifyUser {
                timestamp,
                milliseconds,
                event_modifier,
                subject,
                text_tokens: self.text_tokens,
                success,
                return_value,
            },
            AUE_KTRACE => {
                let find_arg = |num: u8| -> Option<u32> {
                    self.arg_tokens
                        .iter()
                        .find(|(n, _)| *n == num)
                        .map(|(_, v)| *v as u32)
                };
                AuditRecord::Ktrace {
                    timestamp,
                    milliseconds,
                    event_modifier,
                    subject,
                    ops: find_arg(2),
                    trpoints: find_arg(3),
                    target_pid: find_arg(4),
                    output_file: self.exe,
                    success,
                    return_value,
                }
            }
            _ => AuditRecord::Other {
                event_type,
                timestamp,
                milliseconds,
                event_modifier,
                subject: Some(subject),
            },
        }
    }
}

// --- Address helpers ---

/// IPv4 from a u32 parsed big-endian; returns None for 0.0.0.0.
fn ipv4_addr(addr: u32) -> Option<IpAddr> {
    if addr == 0 {
        return None;
    }
    Some(IpAddr::V4(Ipv4Addr::from(addr)))
}

/// Address from an Ex token's (addr_type, 16-byte buffer) pair.
fn ex_addr(addr_type: u32, addr: &[u8; 16]) -> Option<IpAddr> {
    match addr_type {
        AU_IPV4 => {
            if addr[..4] == [0, 0, 0, 0] {
                return None;
            }
            let octets: [u8; 4] = addr[..4].try_into().unwrap();
            Some(IpAddr::V4(Ipv4Addr::from(octets)))
        }
        AU_IPV6 => Some(IpAddr::V6(Ipv6Addr::from(*addr))),
        _ => None,
    }
}

// --- Parsing primitives ---

type ParseResult<'a, T> = Result<(T, &'a [u8]), ParseError>;

fn take(buf: &[u8], n: usize) -> Result<(&[u8], &[u8]), ParseError> {
    if buf.len() < n {
        return Err(ParseError::Truncated {
            needed: n,
            available: buf.len(),
        });
    }
    Ok(buf.split_at(n))
}

fn take_u8(buf: &[u8]) -> Result<(u8, &[u8]), ParseError> {
    let (head, rest) = take(buf, 1)?;
    Ok((head[0], rest))
}

fn take_u16_be(buf: &[u8]) -> Result<(u16, &[u8]), ParseError> {
    let (head, rest) = take(buf, 2)?;
    Ok((u16::from_be_bytes(head.try_into().unwrap()), rest))
}

fn take_u32_be(buf: &[u8]) -> Result<(u32, &[u8]), ParseError> {
    let (head, rest) = take(buf, 4)?;
    Ok((u32::from_be_bytes(head.try_into().unwrap()), rest))
}

fn take_u64_be(buf: &[u8]) -> Result<(u64, &[u8]), ParseError> {
    let (head, rest) = take(buf, 8)?;
    Ok((u64::from_be_bytes(head.try_into().unwrap()), rest))
}

fn take_len16_str(buf: &[u8]) -> Result<(String, &[u8]), ParseError> {
    let (len, rest) = take_u16_be(buf)?;
    let (bytes, rest) = take(rest, len as usize)?;
    let s = String::from_utf8_lossy(bytes).into_owned();
    Ok((s, rest))
}

fn take_nul_strings(buf: &[u8], count: u32) -> Result<(Vec<String>, &[u8]), ParseError> {
    let mut rest = buf;
    let mut out = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let nul = rest
            .iter()
            .position(|&b| b == 0)
            .ok_or(ParseError::Truncated {
                needed: 1,
                available: 0,
            })?;
        let s = String::from_utf8_lossy(&rest[..nul]).into_owned();
        out.push(s);
        rest = &rest[nul + 1..];
    }
    Ok((out, rest))
}

// --- Token parsers (buf starts AFTER the type byte) ---

fn parse_header32(buf: &[u8]) -> ParseResult<'_, Token> {
    let (record_size, buf) = take_u32_be(buf)?;
    let (version, buf) = take_u8(buf)?;
    let (event_type, buf) = take_u16_be(buf)?;
    let (event_modifier, buf) = take_u16_be(buf)?;
    let (seconds, buf) = take_u32_be(buf)?;
    let (milliseconds, buf) = take_u32_be(buf)?;
    Ok((
        Token::Header32(Header32 {
            record_size,
            version,
            event_type,
            event_modifier,
            seconds,
            milliseconds,
        }),
        buf,
    ))
}

fn parse_header64(buf: &[u8]) -> ParseResult<'_, Token> {
    let (record_size, buf) = take_u32_be(buf)?;
    let (version, buf) = take_u8(buf)?;
    let (event_type, buf) = take_u16_be(buf)?;
    let (event_modifier, buf) = take_u16_be(buf)?;
    let (seconds, buf) = take_u64_be(buf)?;
    let (milliseconds, buf) = take_u64_be(buf)?;
    Ok((
        Token::Header64(Header64 {
            record_size,
            version,
            event_type,
            event_modifier,
            seconds,
            milliseconds,
        }),
        buf,
    ))
}

fn parse_header32_ex(buf: &[u8]) -> ParseResult<'_, Token> {
    let (record_size, buf) = take_u32_be(buf)?;
    let (version, buf) = take_u8(buf)?;
    let (event_type, buf) = take_u16_be(buf)?;
    let (event_modifier, buf) = take_u16_be(buf)?;
    let (addr_type, buf) = take_u32_be(buf)?;
    let (machine_addr, buf) = if addr_type == AU_IPV6 {
        let (bytes, buf) = take(buf, 16)?;
        (bytes.try_into().unwrap(), buf)
    } else if addr_type == AU_IPV4 {
        let (bytes, buf) = take(buf, 4)?;
        let mut addr = [0u8; 16];
        addr[..4].copy_from_slice(bytes);
        (addr, buf)
    } else {
        return Err(ParseError::UnknownAddrType(addr_type));
    };
    let (seconds, buf) = take_u32_be(buf)?;
    let (milliseconds, buf) = take_u32_be(buf)?;
    Ok((
        Token::Header32Ex(Header32Ex {
            record_size,
            version,
            event_type,
            event_modifier,
            addr_type,
            machine_addr,
            seconds,
            milliseconds,
        }),
        buf,
    ))
}

fn parse_header64_ex(buf: &[u8]) -> ParseResult<'_, Token> {
    let (record_size, buf) = take_u32_be(buf)?;
    let (version, buf) = take_u8(buf)?;
    let (event_type, buf) = take_u16_be(buf)?;
    let (event_modifier, buf) = take_u16_be(buf)?;
    let (addr_type, buf) = take_u32_be(buf)?;
    let (machine_addr, buf) = if addr_type == AU_IPV6 {
        let (bytes, buf) = take(buf, 16)?;
        (bytes.try_into().unwrap(), buf)
    } else if addr_type == AU_IPV4 {
        let (bytes, buf) = take(buf, 4)?;
        let mut addr = [0u8; 16];
        addr[..4].copy_from_slice(bytes);
        (addr, buf)
    } else {
        return Err(ParseError::UnknownAddrType(addr_type));
    };
    let (seconds, buf) = take_u64_be(buf)?;
    let (milliseconds, buf) = take_u64_be(buf)?;
    Ok((
        Token::Header64Ex(Header64Ex {
            record_size,
            version,
            event_type,
            event_modifier,
            addr_type,
            machine_addr,
            seconds,
            milliseconds,
        }),
        buf,
    ))
}

fn parse_trailer(buf: &[u8]) -> ParseResult<'_, Token> {
    let (magic, buf) = take_u16_be(buf)?;
    if magic != AUT_TRAILER_MAGIC {
        return Err(ParseError::InvalidMagic(magic));
    }
    let (record_size, buf) = take_u32_be(buf)?;
    Ok((Token::Trailer(Trailer { record_size }), buf))
}

fn parse_subject32(buf: &[u8]) -> ParseResult<'_, Token> {
    let (audit_id, buf) = take_u32_be(buf)?;
    let (euid, buf) = take_u32_be(buf)?;
    let (egid, buf) = take_u32_be(buf)?;
    let (ruid, buf) = take_u32_be(buf)?;
    let (rgid, buf) = take_u32_be(buf)?;
    let (pid, buf) = take_u32_be(buf)?;
    let (session_id, buf) = take_u32_be(buf)?;
    let (terminal_port, buf) = take_u32_be(buf)?;
    let (terminal_addr, buf) = take_u32_be(buf)?;
    Ok((
        Token::Subject32(Subject32 {
            audit_id,
            euid,
            egid,
            ruid,
            rgid,
            pid,
            session_id,
            terminal_port,
            terminal_addr,
        }),
        buf,
    ))
}

fn parse_subject32_ex(buf: &[u8]) -> ParseResult<'_, Token> {
    let (audit_id, buf) = take_u32_be(buf)?;
    let (euid, buf) = take_u32_be(buf)?;
    let (egid, buf) = take_u32_be(buf)?;
    let (ruid, buf) = take_u32_be(buf)?;
    let (rgid, buf) = take_u32_be(buf)?;
    let (pid, buf) = take_u32_be(buf)?;
    let (session_id, buf) = take_u32_be(buf)?;
    let (terminal_port, buf) = take_u32_be(buf)?;
    let (addr_type, buf) = take_u32_be(buf)?;
    let (addr, buf) = if addr_type == AU_IPV6 {
        let (bytes, buf) = take(buf, 16)?;
        (bytes.try_into().unwrap(), buf)
    } else if addr_type == AU_IPV4 {
        let (bytes, buf) = take(buf, 4)?;
        let mut addr = [0u8; 16];
        addr[..4].copy_from_slice(bytes);
        (addr, buf)
    } else {
        return Err(ParseError::UnknownAddrType(addr_type));
    };
    Ok((
        Token::Subject32Ex(Subject32Ex {
            audit_id,
            euid,
            egid,
            ruid,
            rgid,
            pid,
            session_id,
            terminal_port,
            addr_type,
            addr,
        }),
        buf,
    ))
}

fn parse_subject64(buf: &[u8]) -> ParseResult<'_, Token> {
    let (audit_id, buf) = take_u32_be(buf)?;
    let (euid, buf) = take_u32_be(buf)?;
    let (egid, buf) = take_u32_be(buf)?;
    let (ruid, buf) = take_u32_be(buf)?;
    let (rgid, buf) = take_u32_be(buf)?;
    let (pid, buf) = take_u32_be(buf)?;
    let (session_id, buf) = take_u32_be(buf)?;
    let (terminal_port, buf) = take_u64_be(buf)?;
    let (terminal_addr, buf) = take_u32_be(buf)?;
    Ok((
        Token::Subject64(Subject64 {
            audit_id,
            euid,
            egid,
            ruid,
            rgid,
            pid,
            session_id,
            terminal_port,
            terminal_addr,
        }),
        buf,
    ))
}

fn parse_subject64_ex(buf: &[u8]) -> ParseResult<'_, Token> {
    let (audit_id, buf) = take_u32_be(buf)?;
    let (euid, buf) = take_u32_be(buf)?;
    let (egid, buf) = take_u32_be(buf)?;
    let (ruid, buf) = take_u32_be(buf)?;
    let (rgid, buf) = take_u32_be(buf)?;
    let (pid, buf) = take_u32_be(buf)?;
    let (session_id, buf) = take_u32_be(buf)?;
    let (terminal_port, buf) = take_u64_be(buf)?;
    let (addr_type, buf) = take_u32_be(buf)?;
    let (addr, buf) = if addr_type == AU_IPV6 {
        let (bytes, buf) = take(buf, 16)?;
        (bytes.try_into().unwrap(), buf)
    } else if addr_type == AU_IPV4 {
        let (bytes, buf) = take(buf, 4)?;
        let mut addr = [0u8; 16];
        addr[..4].copy_from_slice(bytes);
        (addr, buf)
    } else {
        return Err(ParseError::UnknownAddrType(addr_type));
    };
    Ok((
        Token::Subject64Ex(Subject64Ex {
            audit_id,
            euid,
            egid,
            ruid,
            rgid,
            pid,
            session_id,
            terminal_port,
            addr_type,
            addr,
        }),
        buf,
    ))
}

fn parse_attr32(buf: &[u8]) -> ParseResult<'_, Token> {
    // BSD defines file mode as 2 bytes; BSM pads to 4 with a leading u16 zero.
    let (_pad, buf) = take_u16_be(buf)?;
    let (file_access_mode, buf) = take_u16_be(buf)?;
    let (owner_id, buf) = take_u32_be(buf)?;
    let (group_id, buf) = take_u32_be(buf)?;
    let (filesystem_id, buf) = take_u32_be(buf)?;
    let (node_id, buf) = take_u64_be(buf)?;
    let (device, buf) = take_u32_be(buf)?;
    Ok((
        Token::Attr32(Attr32 {
            file_access_mode,
            owner_id,
            group_id,
            filesystem_id,
            node_id,
            device,
        }),
        buf,
    ))
}

fn parse_return32(buf: &[u8]) -> ParseResult<'_, Token> {
    let (error, buf) = take_u8(buf)?;
    let (value, buf) = take_u32_be(buf)?;
    Ok((Token::Return32(Return32 { error, value }), buf))
}

fn parse_return64(buf: &[u8]) -> ParseResult<'_, Token> {
    let (error, buf) = take_u8(buf)?;
    let (value, buf) = take_u64_be(buf)?;
    Ok((Token::Return64(Return64 { error, value }), buf))
}

fn parse_arg32(buf: &[u8]) -> ParseResult<'_, Token> {
    let (num, buf) = take_u8(buf)?;
    let (value, buf) = take_u32_be(buf)?;
    let (text, buf) = take_len16_str(buf)?;
    Ok((Token::Arg32(Arg32 { num, value, text }), buf))
}

fn parse_arg64(buf: &[u8]) -> ParseResult<'_, Token> {
    let (num, buf) = take_u8(buf)?;
    let (value, buf) = take_u64_be(buf)?;
    let (text, buf) = take_len16_str(buf)?;
    Ok((Token::Arg64(Arg64 { num, value, text }), buf))
}

fn parse_sockinet32(buf: &[u8]) -> ParseResult<'_, Token> {
    let (socket_family, buf) = take_u16_be(buf)?;
    let (local_port, buf) = take_u16_be(buf)?;
    let (socket_address, buf) = take_u32_be(buf)?;
    Ok((
        Token::SockInet32(SockInet32 {
            socket_family,
            local_port,
            socket_address,
        }),
        buf,
    ))
}

fn parse_sockinet128(buf: &[u8]) -> ParseResult<'_, Token> {
    let (_pad, buf) = take_u8(buf)?;
    let (socket_family, buf) = take_u8(buf)?;
    let (local_port, buf) = take_u16_be(buf)?;
    let (addr_bytes, buf) = take(buf, 16)?;
    let mut socket_address = [0u8; 16];
    socket_address.copy_from_slice(addr_bytes);
    Ok((
        Token::SockInet128(SockInet128 {
            socket_family,
            local_port,
            socket_address,
        }),
        buf,
    ))
}

fn parse_sockunix(buf: &[u8]) -> ParseResult<'_, Token> {
    let (_pad, buf) = take_u8(buf)?;
    let (socket_family, buf) = take_u8(buf)?;
    let (mut paths, buf) = take_nul_strings(buf, 1)?;
    let path = paths.pop().unwrap_or_default();
    Ok((
        Token::SockUnix(SockUnix {
            socket_family,
            path,
        }),
        buf,
    ))
}

fn parse_path(buf: &[u8]) -> ParseResult<'_, Token> {
    let (len, buf) = take_u16_be(buf)?;
    let (bytes, buf) = take(buf, len as usize)?;
    let bytes = bytes.strip_suffix(b"\0").unwrap_or(bytes);
    let path = String::from_utf8_lossy(bytes).into_owned();
    Ok((Token::Path(Path { path }), buf))
}

fn parse_text(buf: &[u8]) -> ParseResult<'_, Token> {
    let (len, buf) = take_u16_be(buf)?;
    let (bytes, buf) = take(buf, len as usize)?;
    let bytes = bytes.strip_suffix(b"\0").unwrap_or(bytes);
    let text = String::from_utf8_lossy(bytes).into_owned();
    Ok((Token::Text(Text { text }), buf))
}

fn parse_exec_args(buf: &[u8]) -> ParseResult<'_, Token> {
    let (count, buf) = take_u32_be(buf)?;
    let (args, buf) = take_nul_strings(buf, count)?;
    Ok((Token::ExecArgs(ExecArgs { args }), buf))
}

fn parse_exec_env(buf: &[u8]) -> ParseResult<'_, Token> {
    let (count, buf) = take_u32_be(buf)?;
    let (vars, buf) = take_nul_strings(buf, count)?;
    Ok((Token::ExecEnv(ExecEnv { vars }), buf))
}

// --- Top-level dispatch ---

fn parse_token(buf: &[u8]) -> ParseResult<'_, Token> {
    let (type_byte, rest) = take_u8(buf)?;
    match type_byte {
        AUT_HEADER32 => parse_header32(rest),
        AUT_HEADER32_EX => parse_header32_ex(rest),
        AUT_HEADER64 => parse_header64(rest),
        AUT_HEADER64_EX => parse_header64_ex(rest),
        AUT_TRAILER => parse_trailer(rest),
        AUT_SUBJECT32 => parse_subject32(rest),
        AUT_SUBJECT32_EX => parse_subject32_ex(rest),
        AUT_SUBJECT64 => parse_subject64(rest),
        AUT_SUBJECT64_EX => parse_subject64_ex(rest),
        AUT_RETURN32 => parse_return32(rest),
        AUT_RETURN64 => parse_return64(rest),
        AUT_ARG32 => parse_arg32(rest),
        AUT_ARG64 => parse_arg64(rest),
        AUT_PATH => parse_path(rest),
        AUT_TEXT => parse_text(rest),
        AUT_EXEC_ARGS => parse_exec_args(rest),
        AUT_EXEC_ENV => parse_exec_env(rest),
        AUT_ATTR32 => parse_attr32(rest),
        AUT_SOCKINET32 => parse_sockinet32(rest),
        AUT_SOCKINET128 => parse_sockinet128(rest),
        AUT_SOCKUNIX => parse_sockunix(rest),
        other => Err(ParseError::UnknownToken(other)),
    }
}

// --- Record parsing ---

fn parse_record(buf: &[u8]) -> Result<(AuditRecord, &[u8]), ParseError> {
    let (type_byte, _) = take_u8(buf)?;
    let (header_token, after_header) = parse_token(buf)?;
    let record_size = match &header_token {
        Token::Header32(h) => h.record_size as usize,
        Token::Header32Ex(h) => h.record_size as usize,
        Token::Header64(h) => h.record_size as usize,
        Token::Header64Ex(h) => h.record_size as usize,
        _ => return Err(ParseError::NotAHeader(type_byte)),
    };

    if record_size == 0 {
        return Err(ParseError::InvalidRecordSize(0));
    }
    if record_size > buf.len() {
        return Err(ParseError::Truncated {
            needed: record_size,
            available: buf.len(),
        });
    }

    let record_buf = &buf[..record_size];
    let after_record = &buf[record_size..];

    let mut acc = RecordAccumulator::default();
    acc.fold_token(header_token);

    let mut rest = after_header;
    loop {
        let offset = rest.as_ptr() as usize - record_buf.as_ptr() as usize;
        if offset >= record_buf.len() {
            break;
        }
        match parse_token(rest) {
            Ok((token, next)) => {
                let done = matches!(token, Token::Trailer(_));
                acc.fold_token(token);
                rest = next;
                if done {
                    break;
                }
            }
            Err(e) => {
                log::warn!("unknown BSM token in record: {}", e);
                break;
            }
        }
    }

    Ok((acc.into_record(), after_record))
}

pub fn parse_records(mut buf: &[u8]) -> Result<Vec<AuditRecord>, ParseError> {
    let mut records = Vec::new();
    while !buf.is_empty() {
        let (record, rest) = parse_record(buf)?;
        if rest.len() >= buf.len() {
            return Err(ParseError::NoProgress);
        }
        records.push(record);
        buf = rest;
    }
    Ok(records)
}

pub fn read_record<R: Read>(reader: &mut R) -> Result<AuditRecord, ParseError> {
    let mut type_byte = [0u8; 1];
    reader.read_exact(&mut type_byte).map_err(ParseError::Io)?;

    match type_byte[0] {
        AUT_HEADER32 | AUT_HEADER32_EX | AUT_HEADER64 | AUT_HEADER64_EX => {
            let mut size_bytes = [0u8; 4];
            reader.read_exact(&mut size_bytes).map_err(ParseError::Io)?;
            let record_size = u32::from_be_bytes(size_bytes) as usize;

            // 5 = 1 type byte + 4 size bytes already consumed
            if !(5..=1024 * 1024).contains(&record_size) {
                return Err(ParseError::InvalidRecordSize(record_size));
            }

            let mut rest = vec![0u8; record_size - 5];
            reader.read_exact(&mut rest).map_err(ParseError::Io)?;

            let mut full_record = Vec::with_capacity(record_size);
            full_record.push(type_byte[0]);
            full_record.extend_from_slice(&size_bytes);
            full_record.extend_from_slice(&rest);

            let (record, _) = parse_record(&full_record)?;
            Ok(record)
        }
        other => Err(ParseError::NotAHeader(other)),
    }
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_return32() {
        let bytes = [0x00, 0x00, 0x00, 0x00, 0x05]; // error=0, value=5
        let (token, rest) = parse_return32(&bytes).unwrap();
        assert!(matches!(
            token,
            Token::Return32(Return32 { error: 0, value: 5 })
        ));
        assert!(rest.is_empty());
    }

    #[test]
    fn test_return32_error() {
        let bytes = [0x01, 0x00, 0x00, 0x00, 0x00]; // error=1, value=0
        let (token, _) = parse_return32(&bytes).unwrap();
        assert!(matches!(
            token,
            Token::Return32(Return32 { error: 1, value: 0 })
        ));
    }

    #[test]
    fn test_return64() {
        let bytes = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2a]; // error=0, value=42
        let (token, rest) = parse_return64(&bytes).unwrap();
        assert!(matches!(
            token,
            Token::Return64(Return64 {
                error: 0,
                value: 42
            })
        ));
        assert!(rest.is_empty());
    }

    #[test]
    fn test_text() {
        let bytes = [0x00, 0x06, b'h', b'e', b'l', b'l', b'o', 0x00];
        let (token, rest) = parse_text(&bytes).unwrap();
        if let Token::Text(t) = token {
            assert_eq!(t.text, "hello");
        } else {
            panic!("wrong token type");
        }
        assert!(rest.is_empty());
    }

    #[test]
    fn test_path() {
        let mut bytes = vec![0x00, 0x0a];
        bytes.extend_from_slice(b"/bin/tcsh\0");
        let (token, rest) = parse_path(&bytes).unwrap();
        if let Token::Path(p) = token {
            assert_eq!(p.path, "/bin/tcsh");
        } else {
            panic!("wrong token type");
        }
        assert!(rest.is_empty());
    }

    #[test]
    fn test_trailer_valid() {
        let bytes = [0xb1, 0x05, 0x00, 0x00, 0x00, 0x38];
        let (token, rest) = parse_trailer(&bytes).unwrap();
        assert!(matches!(token, Token::Trailer(Trailer { record_size: 56 })));
        assert!(rest.is_empty());
    }

    #[test]
    fn test_trailer_bad_magic() {
        let bytes = [0xFF, 0xFF, 0x00, 0x00, 0x00, 0x38];
        assert!(matches!(
            parse_trailer(&bytes),
            Err(ParseError::InvalidMagic(0xFFFF))
        ));
    }

    #[test]
    fn test_truncated_buffer() {
        let bytes = [0x00, 0x00];
        assert!(matches!(
            parse_return32(&bytes),
            Err(ParseError::Truncated { .. })
        ));
    }

    #[test]
    fn test_subject32ex_ipv4() {
        let mut bytes = vec![];
        for v in [1001u32, 1001, 1001, 1001, 1001, 50698, 50698, 36564] {
            bytes.extend_from_slice(&v.to_be_bytes());
        }
        bytes.extend_from_slice(&4u32.to_be_bytes()); // addr_type = IPv4
        bytes.extend_from_slice(&[10, 4, 10, 44]);
        let (token, rest) = parse_subject32_ex(&bytes).unwrap();
        if let Token::Subject32Ex(s) = token {
            assert_eq!(s.euid, 1001);
            assert_eq!(s.addr_type, 4);
            assert_eq!(s.addr[..4], [10, 4, 10, 44]);
        } else {
            panic!("wrong token type");
        }
        assert!(rest.is_empty());
    }

    #[test]
    fn test_subject32ex_invalid_addr_type() {
        let mut bytes = vec![];
        for v in [0u32; 8] {
            bytes.extend_from_slice(&v.to_be_bytes());
        }
        bytes.extend_from_slice(&99u32.to_be_bytes());
        assert!(matches!(
            parse_subject32_ex(&bytes),
            Err(ParseError::UnknownAddrType(99))
        ));
    }

    #[test]
    fn test_exec_args() {
        let mut bytes = vec![0x00, 0x00, 0x00, 0x02]; // count=2
        bytes.extend_from_slice(b"ls\0");
        bytes.extend_from_slice(b"-la\0");
        let (token, rest) = parse_exec_args(&bytes).unwrap();
        if let Token::ExecArgs(e) = token {
            assert_eq!(e.args, vec!["ls", "-la"]);
        } else {
            panic!("wrong token type");
        }
        assert!(rest.is_empty());
    }

    #[test]
    fn test_unknown_token_skips_record() {
        // A record with an unknown token type mid-stream - parser should warn
        // and stop at the unknown token, but still return a valid AuditRecord.
        let mut record: Vec<u8> = vec![
            0x14, // AUT_HEADER32
            0x00, 0x00, 0x00, 0x20, // record_size = 32
            0x0b, // version = 11
            0x00, 0x01, // event_type = 1 (unhandled -> Other)
            0x00, 0x00, // event_modifier = 0
            0x00, 0x00, 0x00, 0x00, // seconds = 0
            0x00, 0x00, 0x00, 0x00, // milliseconds = 0
            0xFF, // unknown token type
            0x13, // AUT_TRAILER
            0xb1, 0x05, // magic
            0x00, 0x00, 0x00, 0x20, // record_size = 32
        ];
        record.resize(32, 0x00);
        let records = parse_records(&record).unwrap();
        assert_eq!(records.len(), 1);
        assert!(matches!(
            records[0],
            AuditRecord::Other { event_type: 1, .. }
        ));
    }

    // --- integration tests against real audit capture ---
    // Run with: cargo test -p bsm -- --ignored
    // Requires a captured auditpipe dump at ../current

    #[test]
    #[ignore]
    fn parse_current() {
        let data = std::fs::read("../current").unwrap();
        let records = parse_records(&data).unwrap();
        assert!(!records.is_empty());
        println!("parsed {} records", records.len());
        for r in &records[..records.len().min(3)] {
            println!("{r:?}");
        }
    }

    #[test]
    #[ignore]
    fn parse_current_login_record() {
        let data = std::fs::read("../current").unwrap();
        let records = parse_records(&data).unwrap();
        // second record is the SSH login event
        match &records[1] {
            AuditRecord::SshLogin {
                subject, success, ..
            } => {
                assert_eq!(subject.uid, 1001);
                assert_eq!(
                    subject.terminal,
                    Some(IpAddr::V4(Ipv4Addr::new(10, 4, 10, 44)))
                );
                assert!(*success);
            }
            other => panic!("expected SshLogin, got {other:?}"),
        }
    }

    // --- New event variant tests ---

    #[test]
    fn test_setuid_record() {
        // AUE_SETUID=200=0x00C8. Total size: header(18)+subject32(37)+arg32(11)+return32(6)+trailer(7)=79=0x4F
        #[rustfmt::skip]
        let bytes: &[u8] = &[
            // Header32
            0x14, 0x00,0x00,0x00,0x4F, 0x02, 0x00,0xC8, 0x00,0x00,
            0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
            // Subject32: auid=1000, euid=0, egid=0, ruid=1000, rgid=1000, pid=1234, sid=1
            0x24,
            0x00,0x00,0x03,0xE8, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
            0x00,0x00,0x03,0xE8, 0x00,0x00,0x03,0xE8, 0x00,0x00,0x04,0xD2,
            0x00,0x00,0x00,0x01, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
            // Arg32: num=1, value=0 (uid=root), text="uid"
            0x2d, 0x01, 0x00,0x00,0x00,0x00, 0x00,0x03, b'u',b'i',b'd',
            // Return32: error=0, value=0
            0x27, 0x00, 0x00,0x00,0x00,0x00,
            // Trailer
            0x13, 0xb1,0x05, 0x00,0x00,0x00,0x4F,
        ];
        let records = parse_records(bytes).unwrap();
        assert_eq!(records.len(), 1);
        match &records[0] {
            AuditRecord::SetUid {
                new_uid,
                success,
                subject,
                ..
            } => {
                assert_eq!(*new_uid, Some(0));
                assert!(success);
                assert_eq!(subject.uid, 1000);
                assert_eq!(subject.pid, 1234);
            }
            other => panic!("expected SetUid, got {other:?}"),
        }
    }

    #[test]
    fn test_sudo_success_record() {
        // AUE_SUDO=45028=0xAFE4. Total: header(18)+subject32(37)+exec_args(13)+return32(6)+trailer(7)=81=0x51
        #[rustfmt::skip]
        let bytes: &[u8] = &[
            // Header32
            0x14, 0x00,0x00,0x00,0x51, 0x02, 0xAF,0xE4, 0x00,0x00,
            0x00,0x00,0x12,0x34, 0x00,0x00,0x00,0x00,
            // Subject32: auid=1000, euid=0, egid=0, ruid=1000, rgid=1000, pid=999, sid=1
            0x24,
            0x00,0x00,0x03,0xE8, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
            0x00,0x00,0x03,0xE8, 0x00,0x00,0x03,0xE8, 0x00,0x00,0x03,0xE7,
            0x00,0x00,0x00,0x01, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
            // ExecArgs: count=2, "sudo\0ls\0"
            0x3c, 0x00,0x00,0x00,0x02, b's',b'u',b'd',b'o',0x00, b'l',b's',0x00,
            // Return32: error=0 (success)
            0x27, 0x00, 0x00,0x00,0x00,0x00,
            // Trailer
            0x13, 0xb1,0x05, 0x00,0x00,0x00,0x51,
        ];
        let records = parse_records(bytes).unwrap();
        assert_eq!(records.len(), 1);
        match &records[0] {
            AuditRecord::Sudo {
                args,
                success,
                failure_text,
                ..
            } => {
                assert_eq!(args, &["sudo", "ls"]);
                assert!(success);
                assert!(failure_text.is_none());
            }
            other => panic!("expected Sudo, got {other:?}"),
        }
    }

    #[test]
    fn test_ptrace_arg64_request() {
        // AUE_PTRACE=43002=0xA7FA. Total: header(18)+subject32(37)+arg64(19)+return32(6)+trailer(7)=87=0x57
        // Uses Arg64 to verify 64-bit arg tokens are captured and correctly downcast to u32.
        #[rustfmt::skip]
        let bytes: &[u8] = &[
            // Header32
            0x14, 0x00,0x00,0x00,0x57, 0x02, 0xA7,0xFA, 0x00,0x00,
            0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
            // Subject32: auid=1000, euid=500, egid=500, ruid=1000, rgid=1000, pid=5678, sid=2
            0x24,
            0x00,0x00,0x03,0xE8, 0x00,0x00,0x01,0xF4, 0x00,0x00,0x01,0xF4,
            0x00,0x00,0x03,0xE8, 0x00,0x00,0x03,0xE8, 0x00,0x00,0x16,0x2E,
            0x00,0x00,0x00,0x02, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
            // Arg64: num=1, value=7 (PT_CONTINUE), text="request"
            0x71, 0x01, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x07,
            0x00,0x07, b'r',b'e',b'q',b'u',b'e',b's',b't',
            // Return32: error=0
            0x27, 0x00, 0x00,0x00,0x00,0x00,
            // Trailer
            0x13, 0xb1,0x05, 0x00,0x00,0x00,0x57,
        ];
        let records = parse_records(bytes).unwrap();
        assert_eq!(records.len(), 1);
        match &records[0] {
            AuditRecord::Ptrace {
                request, success, ..
            } => {
                assert_eq!(*request, Some(7));
                assert!(success);
            }
            other => panic!("expected Ptrace, got {other:?}"),
        }
    }
}
