use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use super::event::{ParsedTlsWriteEvent, build_https_event};
use crate::network::model::ParsedNetworkEvent;
use crate::network::parser::parse_http_request_payload;

const MAX_BUFFER_BYTES: usize = 64 * 1024;
const MAX_CONNECTIONS: usize = 512;
const IDLE_TTL: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct ConnectionKey {
    pid: u32,
    library: &'static str,
    conn_ptr: u64,
}

struct Http1ConnectionState {
    buffer: VecDeque<u8>,
    last_seen: Instant,
}

#[derive(Default)]
pub(super) struct Http1Tracker {
    connections: HashMap<ConnectionKey, Http1ConnectionState>,
}

impl Http1ConnectionState {
    fn new(now: Instant) -> Self {
        Self {
            buffer: VecDeque::new(),
            last_seen: now,
        }
    }
}

impl Http1Tracker {
    pub(super) fn new() -> Self {
        Self::default()
    }

    pub(super) fn handle_tls_write(
        &mut self,
        event: &ParsedTlsWriteEvent,
    ) -> Vec<ParsedNetworkEvent> {
        if event.conn_ptr == 0 || event.payload.is_empty() {
            return Vec::new();
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
            .or_insert_with(|| Http1ConnectionState::new(now));
        state.last_seen = now;
        state.buffer.extend(event.payload.iter().copied());

        if state.buffer.len() > MAX_BUFFER_BYTES {
            state.buffer.clear();
            return Vec::new();
        }

        let mut events = Vec::new();

        while let Some(head_len) = request_head_len(&mut state.buffer) {
            let payload = state.buffer.drain(..head_len).collect::<Vec<_>>();
            let Some(request) = parse_http_request_payload(&payload) else {
                continue;
            };

            events.push(build_https_event(event, request));
        }

        events
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

fn request_head_len(buffer: &mut VecDeque<u8>) -> Option<usize> {
    let bytes = buffer.make_contiguous();

    bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|pos| pos + 4)
        .or_else(|| {
            bytes
                .windows(2)
                .position(|window| window == b"\n\n")
                .map(|pos| pos + 2)
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::tls::event::TlsLibrary;

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

    #[test]
    fn reassembles_split_http1_request_across_tls_writes() {
        let mut tracker = Http1Tracker::new();

        assert!(
            tracker
                .handle_tls_write(&make_event(0x1000, b"GET /secure HTTP/1.1\r\nHo"))
                .is_empty()
        );

        let events = tracker.handle_tls_write(&make_event(0x1000, b"st: example.com\r\n\r\n"));
        assert_eq!(events.len(), 1);

        let ParsedNetworkEvent::Https(event) = &events[0] else {
            panic!("expected https event");
        };

        assert_eq!(event.method, "GET");
        assert_eq!(event.path, "/secure");
        assert_eq!(event.host.as_deref(), Some("example.com"));
        assert_eq!(event.http_version.as_deref(), Some("HTTP/1.1"));
    }

    #[test]
    fn drops_oversized_http1_buffer() {
        let mut tracker = Http1Tracker::new();
        let oversized = vec![b'a'; MAX_BUFFER_BYTES + 1];

        assert!(
            tracker
                .handle_tls_write(&make_event(0x2000, &oversized))
                .is_empty()
        );

        let events = tracker.handle_tls_write(&make_event(
            0x2000,
            b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
        ));
        assert_eq!(events.len(), 1);
    }
}
