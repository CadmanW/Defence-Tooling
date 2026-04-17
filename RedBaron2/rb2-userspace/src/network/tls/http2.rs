use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use fluke_hpack::Decoder;

use super::event::{ParsedTlsWriteEvent, build_https_event};
use crate::network::model::ParsedNetworkEvent;

const HTTP2_CLIENT_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const FRAME_HEADER_LEN: usize = 9;
const FRAME_TYPE_HEADERS: u8 = 0x1;
const FRAME_TYPE_CONTINUATION: u8 = 0x9;
const FLAG_END_HEADERS: u8 = 0x4;
const FLAG_PADDED: u8 = 0x8;
const FLAG_PRIORITY: u8 = 0x20;
const MAX_BUFFER_BYTES: usize = 64 * 1024;
const MAX_FRAME_PAYLOAD_BYTES: usize = 64 * 1024;
const MAX_CONNECTIONS: usize = 512;
const IDLE_TTL: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct ConnectionKey {
    pid: u32,
    library: &'static str,
    conn_ptr: u64,
}

#[derive(Debug)]
struct PartialHeaders {
    stream_id: u32,
    block: Vec<u8>,
}

struct Http2ConnectionState {
    decoder: Decoder<'static>,
    buffer: VecDeque<u8>,
    preface_seen: bool,
    partial_headers: Option<PartialHeaders>,
    last_seen: Instant,
}

#[derive(Default)]
pub(super) struct Http2Tracker {
    connections: HashMap<ConnectionKey, Http2ConnectionState>,
}

pub(super) enum HandleResult {
    Events(Vec<ParsedNetworkEvent>),
    NeedMoreData,
    NotHttp2,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DecodedRequest {
    method: String,
    host: Option<String>,
    path: String,
}

impl Http2ConnectionState {
    fn new(now: Instant) -> Self {
        Self {
            decoder: Decoder::new(),
            buffer: VecDeque::new(),
            preface_seen: false,
            partial_headers: None,
            last_seen: now,
        }
    }

    fn push_bytes(&mut self, bytes: &[u8]) {
        self.buffer.extend(bytes.iter().copied());
    }

    fn parse_available(&mut self) -> Result<Vec<DecodedRequest>, ()> {
        let mut requests = Vec::new();

        loop {
            let Some((payload_len, frame_type, flags, stream_id)) = self.peek_frame_header() else {
                break;
            };
            if payload_len > MAX_FRAME_PAYLOAD_BYTES {
                return Err(());
            }
            if self.buffer.len() < FRAME_HEADER_LEN + payload_len {
                break;
            }

            let frame = self.take_frame(payload_len);
            let payload = &frame[FRAME_HEADER_LEN..];

            match frame_type {
                FRAME_TYPE_HEADERS => {
                    if let Some(request) = self.handle_headers_frame(stream_id, flags, payload) {
                        requests.push(request);
                    }
                }
                FRAME_TYPE_CONTINUATION => {
                    if let Some(request) = self.handle_continuation_frame(stream_id, flags, payload)
                    {
                        requests.push(request);
                    }
                }
                _ => {
                    if self.partial_headers.is_some() {
                        self.partial_headers = None;
                    }
                }
            }
        }

        Ok(requests)
    }

    fn ensure_preface_consumed(&mut self) -> Result<bool, ()> {
        if self.preface_seen {
            return Ok(true);
        }
        if self.buffer.is_empty() {
            return Ok(false);
        }

        let available = self.buffer.make_contiguous();
        if available.starts_with(HTTP2_CLIENT_PREFACE) {
            self.buffer.drain(..HTTP2_CLIENT_PREFACE.len());
            self.preface_seen = true;
            return Ok(true);
        }

        if HTTP2_CLIENT_PREFACE.starts_with(available) {
            return Ok(false);
        }

        Err(())
    }

    fn peek_frame_header(&mut self) -> Option<(usize, u8, u8, u32)> {
        if self.buffer.len() < FRAME_HEADER_LEN {
            return None;
        }
        let header = self.buffer.make_contiguous();
        let payload_len =
            ((header[0] as usize) << 16) | ((header[1] as usize) << 8) | header[2] as usize;
        let frame_type = header[3];
        let flags = header[4];
        let stream_id =
            u32::from_be_bytes([header[5], header[6], header[7], header[8]]) & 0x7fff_ffff;

        Some((payload_len, frame_type, flags, stream_id))
    }

    fn take_frame(&mut self, payload_len: usize) -> Vec<u8> {
        self.buffer
            .drain(..FRAME_HEADER_LEN + payload_len)
            .collect::<Vec<_>>()
    }

    fn handle_headers_frame(
        &mut self,
        stream_id: u32,
        flags: u8,
        payload: &[u8],
    ) -> Option<DecodedRequest> {
        let (fragment, end_headers) = parse_headers_payload(flags, payload)?;
        if end_headers {
            self.decode_request(stream_id, fragment)
        } else {
            self.partial_headers = Some(PartialHeaders {
                stream_id,
                block: fragment.to_vec(),
            });
            None
        }
    }

    fn handle_continuation_frame(
        &mut self,
        stream_id: u32,
        flags: u8,
        payload: &[u8],
    ) -> Option<DecodedRequest> {
        let partial = self.partial_headers.as_mut()?;
        if partial.stream_id != stream_id {
            self.partial_headers = None;
            return None;
        }

        partial.block.extend_from_slice(payload);
        if (flags & FLAG_END_HEADERS) != 0 {
            let partial = self.partial_headers.take()?;
            self.decode_request(partial.stream_id, &partial.block)
        } else {
            None
        }
    }

    fn decode_request(&mut self, _stream_id: u32, fragment: &[u8]) -> Option<DecodedRequest> {
        let mut method = None;
        let mut path = None;
        let mut host = None;

        self.decoder
            .decode_with_cb(fragment, |name, value| {
                match (name.as_ref(), value.as_ref()) {
                    (b":method", value) => {
                        method = Some(String::from_utf8_lossy(value).into_owned());
                    }
                    (b":path", value) => {
                        path = Some(String::from_utf8_lossy(value).into_owned());
                    }
                    (b":authority", value) => {
                        host = Some(String::from_utf8_lossy(value).into_owned());
                    }
                    _ => {}
                }
            })
            .ok()?;

        let method = method?;
        let path = path.unwrap_or_else(|| "/".to_string());

        Some(DecodedRequest { method, host, path })
    }
}

fn parse_headers_payload(flags: u8, payload: &[u8]) -> Option<(&[u8], bool)> {
    let end_headers = (flags & FLAG_END_HEADERS) != 0;

    let mut offset = 0usize;
    let mut end = payload.len();

    if (flags & FLAG_PADDED) != 0 {
        let pad_len = usize::from(*payload.first()?);
        offset += 1;
        if end < offset + pad_len {
            return None;
        }
        end -= pad_len;
    }

    if (flags & FLAG_PRIORITY) != 0 {
        offset += 5;
    }

    if end < offset {
        return None;
    }

    Some((&payload[offset..end], end_headers))
}

impl Http2Tracker {
    pub(super) fn new() -> Self {
        Self::default()
    }

    pub(super) fn handle_tls_write(&mut self, event: &ParsedTlsWriteEvent) -> HandleResult {
        if event.conn_ptr == 0 || event.payload.is_empty() {
            return HandleResult::NeedMoreData;
        }

        let now = Instant::now();
        self.evict_stale(now);

        let key = ConnectionKey {
            pid: event.pid,
            library: event.library.name(),
            conn_ptr: event.conn_ptr,
        };
        if self.connections.len() >= MAX_CONNECTIONS && !self.connections.contains_key(&key) {
            self.evict_oldest();
        }
        let state = self
            .connections
            .entry(key)
            .or_insert_with(|| Http2ConnectionState::new(now));

        state.last_seen = now;

        state.push_bytes(&event.payload);
        if state.buffer.len() > MAX_BUFFER_BYTES {
            self.connections.remove(&key);
            return HandleResult::NotHttp2;
        }

        match state.ensure_preface_consumed() {
            Ok(true) => {}
            Ok(false) => return HandleResult::NeedMoreData,
            Err(()) => {
                self.connections.remove(&key);
                return HandleResult::NotHttp2;
            }
        }

        let requests = match state.parse_available() {
            Ok(requests) => requests,
            Err(()) => {
                self.connections.remove(&key);
                return HandleResult::NotHttp2;
            }
        };

        if requests.is_empty() {
            return HandleResult::NeedMoreData;
        }

        HandleResult::Events(
            requests
                .into_iter()
                .filter(|request| !request.method.is_empty() && !request.path.is_empty())
                .map(|request| {
                    let request_line = format!("{} {} HTTP/2", request.method, request.path);
                    build_https_event(
                        event,
                        crate::network::parser::HttpRequest {
                            method: request.method,
                            host: request.host,
                            path: request.path,
                            http_version: Some("HTTP/2".to_string()),
                            request_line,
                        },
                    )
                })
                .collect(),
        )
    }

    fn evict_stale(&mut self, now: Instant) {
        self.connections
            .retain(|_, state| now.duration_since(state.last_seen) <= IDLE_TTL);
    }

    fn evict_oldest(&mut self) {
        let Some(oldest_key) = self
            .connections
            .iter()
            .min_by_key(|(_, state)| state.last_seen)
            .map(|(key, _)| *key)
        else {
            return;
        };

        self.connections.remove(&oldest_key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::tls::event::TlsLibrary;
    use fluke_hpack::Encoder;

    fn make_event(conn_ptr: u64, payload: &[u8]) -> ParsedTlsWriteEvent {
        ParsedTlsWriteEvent {
            pid: 123,
            tid: 456,
            uid: 1000,
            library: TlsLibrary::OpenSsl,
            conn_ptr,
            comm: "curl".to_string(),
            plaintext_len: payload.len() as u32,
            captured_len: payload.len() as u32,
            payload: payload.to_vec(),
        }
    }

    fn frame(frame_type: u8, flags: u8, stream_id: u32, payload: &[u8]) -> Vec<u8> {
        let len = payload.len() as u32;
        let mut out = Vec::with_capacity(FRAME_HEADER_LEN + payload.len());
        out.push(((len >> 16) & 0xff) as u8);
        out.push(((len >> 8) & 0xff) as u8);
        out.push((len & 0xff) as u8);
        out.push(frame_type);
        out.push(flags);
        out.extend_from_slice(&(stream_id & 0x7fff_ffff).to_be_bytes());
        out.extend_from_slice(payload);
        out
    }

    fn literal_header(name: &[u8], value: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(0x00);
        out.push(name.len() as u8);
        out.extend_from_slice(name);
        out.push(value.len() as u8);
        out.extend_from_slice(value);
        out
    }

    fn request_headers_block() -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&[0x82]);
        out.extend_from_slice(&[0x84]);
        out.extend_from_slice(&literal_header(b":authority", b"example.com"));
        out
    }

    fn encoded_request_headers(host: &str) -> Vec<u8> {
        let mut encoder = Encoder::new();
        encoder.encode([
            (&b":method"[..], &b"GET"[..]),
            (&b":path"[..], &b"/"[..]),
            (&b":authority"[..], host.as_bytes()),
        ])
    }

    #[test]
    fn parses_preface_and_single_headers_frame() {
        let mut tracker = Http2Tracker::new();
        let mut payload = HTTP2_CLIENT_PREFACE.to_vec();
        payload.extend_from_slice(&frame(
            FRAME_TYPE_HEADERS,
            FLAG_END_HEADERS,
            1,
            &request_headers_block(),
        ));

        let HandleResult::Events(events) = tracker.handle_tls_write(&make_event(0x1000, &payload))
        else {
            panic!("expected http2 events");
        };
        assert_eq!(events.len(), 1);

        let ParsedNetworkEvent::Https(event) = &events[0] else {
            panic!("expected https event");
        };
        assert_eq!(event.method, "GET");
        assert_eq!(event.path, "/");
        assert_eq!(event.host.as_deref(), Some("example.com"));
        assert_eq!(event.http_version.as_deref(), Some("HTTP/2"));
    }

    #[test]
    fn parses_headers_split_across_tls_writes() {
        let mut tracker = Http2Tracker::new();
        let headers = request_headers_block();
        let first = frame(FRAME_TYPE_HEADERS, 0, 3, &headers[..5]);
        let second = frame(FRAME_TYPE_CONTINUATION, FLAG_END_HEADERS, 3, &headers[5..]);

        let mut first_payload = HTTP2_CLIENT_PREFACE.to_vec();
        first_payload.extend_from_slice(&first);
        assert!(matches!(
            tracker.handle_tls_write(&make_event(0x2000, &first_payload)),
            HandleResult::NeedMoreData
        ));

        let HandleResult::Events(events) = tracker.handle_tls_write(&make_event(0x2000, &second))
        else {
            panic!("expected http2 events");
        };
        assert_eq!(events.len(), 1);
        let ParsedNetworkEvent::Https(event) = &events[0] else {
            panic!("expected https event");
        };
        assert_eq!(event.method, "GET");
        assert_eq!(event.host.as_deref(), Some("example.com"));
    }

    #[test]
    fn tracks_hpack_state_per_connection() {
        let mut tracker = Http2Tracker::new();
        let mut first_payload = HTTP2_CLIENT_PREFACE.to_vec();
        first_payload.extend_from_slice(&frame(
            FRAME_TYPE_HEADERS,
            FLAG_END_HEADERS,
            1,
            &encoded_request_headers("example.com"),
        ));
        let HandleResult::Events(first_events) =
            tracker.handle_tls_write(&make_event(0x3000, &first_payload))
        else {
            panic!("expected http2 events");
        };
        assert_eq!(first_events.len(), 1);

        let second_headers = encoded_request_headers("example.com");
        let second_payload = frame(FRAME_TYPE_HEADERS, FLAG_END_HEADERS, 5, &second_headers);
        let HandleResult::Events(second_events) =
            tracker.handle_tls_write(&make_event(0x3000, &second_payload))
        else {
            panic!("expected http2 events");
        };
        assert_eq!(second_events.len(), 1);
        let ParsedNetworkEvent::Https(event) = &second_events[0] else {
            panic!("expected https event");
        };
        assert_eq!(event.host.as_deref(), Some("example.com"));
    }

    #[test]
    fn rejects_non_preface_bytes_without_poisoning_connection() {
        let mut tracker = Http2Tracker::new();

        assert!(matches!(
            tracker.handle_tls_write(&make_event(
                0x4000,
                b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
            )),
            HandleResult::NotHttp2
        ));

        let mut payload = HTTP2_CLIENT_PREFACE.to_vec();
        payload.extend_from_slice(&frame(
            FRAME_TYPE_HEADERS,
            FLAG_END_HEADERS,
            1,
            &request_headers_block(),
        ));

        let HandleResult::Events(events) = tracker.handle_tls_write(&make_event(0x4000, &payload))
        else {
            panic!("expected recovered http2 events");
        };
        assert_eq!(events.len(), 1);
    }
}
