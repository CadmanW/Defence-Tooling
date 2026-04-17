use anyhow::anyhow;

use super::super::model::{HttpsEvent, ParsedNetworkEvent};
use super::super::parser::{HttpRequest, parse_http_request_payload};

pub(super) const DEFAULT_CAPTURE_BYTES: u32 = 2_048;
pub(super) const TASK_COMM_LEN: usize = 16;
pub(super) const TLS_CAPTURE_MAX_BYTES: usize = 4_096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum TlsLibrary {
    OpenSsl = 1,
    GnuTls = 2,
    Nss = 3,
}

impl TlsLibrary {
    pub(super) const fn name(self) -> &'static str {
        match self {
            Self::OpenSsl => "openssl",
            Self::GnuTls => "gnutls",
            Self::Nss => "nss",
        }
    }
}

impl TryFrom<u32> for TlsLibrary {
    type Error = anyhow::Error;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::OpenSsl),
            2 => Ok(Self::GnuTls),
            3 => Ok(Self::Nss),
            _ => Err(anyhow!("unknown TLS library kind {value}")),
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct RawTlsWriteEvent {
    pid: u32,
    tid: u32,
    uid: u32,
    library_kind: u32,
    conn_ptr: u64,
    plaintext_len: u32,
    captured_len: u32,
    comm: [u8; TASK_COMM_LEN],
}

#[derive(Debug, Clone)]
pub(super) struct ParsedTlsWriteEvent {
    pub(super) pid: u32,
    pub(super) tid: u32,
    pub(super) uid: u32,
    pub(super) library: TlsLibrary,
    pub(super) conn_ptr: u64,
    pub(super) comm: String,
    pub(super) plaintext_len: u32,
    pub(super) captured_len: u32,
    pub(super) payload: Vec<u8>,
}

fn decode_string(buf: &[u8]) -> String {
    let end = buf.iter().position(|&byte| byte == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end]).trim().to_string()
}

pub(super) fn parse_tls_write_event(bytes: &[u8]) -> anyhow::Result<ParsedTlsWriteEvent> {
    let header_size = std::mem::size_of::<RawTlsWriteEvent>();
    if bytes.len() < header_size {
        return Err(anyhow!(
            "short https event: got {} bytes need {}",
            bytes.len(),
            header_size
        ));
    }

    let raw = unsafe {
        let mut uninit = std::mem::MaybeUninit::<RawTlsWriteEvent>::uninit();
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), uninit.as_mut_ptr() as *mut u8, header_size);
        uninit.assume_init()
    };

    let captured_len = usize::try_from(raw.captured_len)
        .unwrap_or(TLS_CAPTURE_MAX_BYTES)
        .min(TLS_CAPTURE_MAX_BYTES);
    let payload_end = header_size + captured_len;
    let payload = bytes.get(header_size..payload_end).ok_or_else(|| {
        anyhow!(
            "short https payload: got {} bytes need {}",
            bytes.len(),
            payload_end
        )
    })?;

    Ok(ParsedTlsWriteEvent {
        pid: raw.pid,
        tid: raw.tid,
        uid: raw.uid,
        library: TlsLibrary::try_from(raw.library_kind)?,
        conn_ptr: raw.conn_ptr,
        comm: decode_string(&raw.comm),
        plaintext_len: raw.plaintext_len,
        captured_len: captured_len as u32,
        payload: payload.to_vec(),
    })
}

pub(super) fn network_event_from_tls_write(
    event: &ParsedTlsWriteEvent,
) -> Option<ParsedNetworkEvent> {
    let request = parse_http_request_payload(&event.payload)?;

    Some(build_https_event(event, request))
}

pub(super) fn build_https_event(
    event: &ParsedTlsWriteEvent,
    request: HttpRequest,
) -> ParsedNetworkEvent {
    let HttpRequest {
        method,
        host,
        path,
        http_version,
        request_line,
    } = request;

    ParsedNetworkEvent::Https(HttpsEvent {
        pid: event.pid,
        tid: event.tid,
        uid: event.uid,
        comm: event.comm.clone(),
        tls_library: event.library.name(),
        truncated: event.captured_len < event.plaintext_len,
        method,
        host,
        path,
        http_version,
        request_line,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_raw_event(payload: &[u8], plaintext_len: u32) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(std::mem::size_of::<RawTlsWriteEvent>() + payload.len());
        bytes.extend_from_slice(&123u32.to_ne_bytes());
        bytes.extend_from_slice(&456u32.to_ne_bytes());
        bytes.extend_from_slice(&1000u32.to_ne_bytes());
        bytes.extend_from_slice(&(TlsLibrary::OpenSsl as u32).to_ne_bytes());
        bytes.extend_from_slice(&0xfeed_beefu64.to_ne_bytes());
        bytes.extend_from_slice(&plaintext_len.to_ne_bytes());
        bytes.extend_from_slice(&(payload.len() as u32).to_ne_bytes());
        let mut comm = [0u8; TASK_COMM_LEN];
        comm[..4].copy_from_slice(b"curl");
        bytes.extend_from_slice(&comm);
        bytes.extend_from_slice(payload);
        bytes
    }

    fn make_event(payload: &[u8], plaintext_len: u32) -> ParsedTlsWriteEvent {
        ParsedTlsWriteEvent {
            pid: 123,
            tid: 456,
            uid: 1000,
            library: TlsLibrary::OpenSsl,
            conn_ptr: 0xfeed_beef,
            comm: "curl".to_string(),
            plaintext_len,
            captured_len: payload.len() as u32,
            payload: payload.to_vec(),
        }
    }

    #[test]
    fn http_tls_write_becomes_https_network_event() {
        let payload = b"GET /health HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let event = network_event_from_tls_write(&make_event(payload, payload.len() as u32))
            .expect("https event");

        let ParsedNetworkEvent::Https(event) = event else {
            panic!("expected https event");
        };

        assert_eq!(event.method, "GET");
        assert_eq!(event.host.as_deref(), Some("example.com"));
        assert_eq!(event.path, "/health");
        assert_eq!(event.request_line, "GET /health HTTP/1.1");
        assert_eq!(event.tls_library, "openssl");
        assert!(!event.truncated);
    }

    #[test]
    fn non_http_tls_write_is_ignored() {
        let event = make_event(b"\x16\x03\x01\x02\x00", 5);
        assert!(network_event_from_tls_write(&event).is_none());
    }

    #[test]
    fn https_event_preserves_truncation_lengths() {
        let payload = b"POST /submit HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let event = network_event_from_tls_write(&make_event(payload, 4096)).expect("https event");

        let ParsedNetworkEvent::Https(event) = event else {
            panic!("expected https event");
        };

        assert!(event.truncated);
        assert_eq!(event.method, "POST");
    }

    #[test]
    fn parses_variable_size_tls_event_payload() {
        let payload = b"GET /health HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let parsed = parse_tls_write_event(&encode_raw_event(payload, payload.len() as u32))
            .expect("parse variable-size tls event");

        assert_eq!(parsed.payload, payload);
        assert_eq!(parsed.comm, "curl");
        assert_eq!(parsed.captured_len, payload.len() as u32);
    }

    #[test]
    fn rejects_short_variable_size_tls_payload() {
        let payload = b"GET / HTTP/1.1\r\n\r\n";
        let mut encoded = encode_raw_event(payload, payload.len() as u32);
        encoded.pop();

        let err = parse_tls_write_event(&encoded).expect_err("payload should be truncated");
        assert!(err.to_string().contains("short https payload"));
    }
}
