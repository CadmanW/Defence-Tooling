use crate::NetworkEvent;
use lru::LruCache;
use std::num::NonZeroUsize;
use std::time::{Duration, Instant};

const NETWORK_DEDUPE_TTL: Duration = Duration::from_secs(30);
const NETWORK_DEDUPE_CAPACITY: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct NetworkDedupeKey {
    pid: u32,
    op: String,
    family: String,
    address: String,
    port: u16,
}

pub(crate) struct NetworkDeduper {
    seen: LruCache<NetworkDedupeKey, Instant>,
    ttl: Duration,
}

impl NetworkDeduper {
    pub(crate) fn new() -> Self {
        Self {
            seen: LruCache::new(
                NonZeroUsize::new(NETWORK_DEDUPE_CAPACITY).expect("capacity must be non-zero"),
            ),
            ttl: NETWORK_DEDUPE_TTL,
        }
    }

    pub(crate) fn should_emit(&mut self, event: &NetworkEvent, now: Instant) -> bool {
        let key = NetworkDedupeKey {
            pid: event.pid,
            op: event.op.clone(),
            family: event.family.clone(),
            address: event.address.clone(),
            port: event.port,
        };

        if let Some(last_seen) = self.seen.get(&key)
            && now.duration_since(*last_seen) < self.ttl
        {
            return false;
        }

        self.seen.put(key, now);
        true
    }

    pub(crate) fn prune_expired(&mut self, now: Instant) {
        while let Some((_, last_seen)) = self.seen.peek_lru() {
            if now.duration_since(*last_seen) < self.ttl {
                break;
            }
            let _ = self.seen.pop_lru();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::EventId;

    fn network_event(pid: u32, op: &str, address: &str, port: u16) -> NetworkEvent {
        NetworkEvent {
            event_id: EventId {
                timestamp_sec: 1,
                timestamp_ms: 2,
                serial: pid as u64,
            },
            syscall: 42,
            op: op.to_string(),
            pid,
            ppid: Some(1),
            uid: Some(0),
            audit_loginuid: 1000,
            audit_sessionid: 2000,
            comm: Some("curl".to_string()),
            exe: Some("/usr/bin/curl".to_string()),
            success: true,
            family: "ipv4".to_string(),
            address: address.to_string(),
            port,
        }
    }

    #[test]
    fn network_deduper_suppresses_repeated_event_for_same_pid() {
        let mut deduper = NetworkDeduper::new();
        let event = network_event(1234, "connect", "1.1.1.1", 443);
        let now = Instant::now();

        assert!(deduper.should_emit(&event, now));
        assert!(!deduper.should_emit(&event, now + Duration::from_secs(1)));
    }

    #[test]
    fn network_deduper_allows_same_destination_for_different_pid() {
        let mut deduper = NetworkDeduper::new();
        let first = network_event(1234, "connect", "1.1.1.1", 443);
        let second = network_event(1235, "connect", "1.1.1.1", 443);
        let now = Instant::now();

        assert!(deduper.should_emit(&first, now));
        assert!(deduper.should_emit(&second, now + Duration::from_secs(1)));
    }

    #[test]
    fn network_deduper_allows_event_after_ttl_expires() {
        let mut deduper = NetworkDeduper::new();
        let event = network_event(1234, "connect", "1.1.1.1", 443);
        let now = Instant::now();

        assert!(deduper.should_emit(&event, now));
        assert!(deduper.should_emit(&event, now + Duration::from_secs(31)));
    }
}
