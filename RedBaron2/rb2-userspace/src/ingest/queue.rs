use super::reader::{LogRecord, parse_log_line};
use anyhow::Context;
use log::Record;
use log4rs::append::Append;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use tokio::sync::Notify;

const QUEUE_APPENDER: &str = "ingestor_queue";

#[derive(Debug, Clone)]
pub struct QueuedRecord {
    pub seq: u64,
    pub encoded_len: u64,
    pub record: Arc<LogRecord>,
}

#[derive(Debug, Clone, Copy)]
pub struct QueueSnapshot {
    pub next_seq: u64,
    pub live_start_seq: u64,
    pub total_bytes: u64,
}

#[derive(Debug)]
struct Node {
    entry: Option<QueuedRecord>,
    next: Mutex<Option<Arc<Self>>>,
}

#[derive(Debug, Default)]
struct ForwarderState {
    next_seq: u64,
    current_seq: Option<u64>,
    current_node: Option<Arc<Node>>,
    pending_next_seq: Option<u64>,
    pending_node: Option<Arc<Node>>,
}

impl Node {
    const fn sentinel() -> Self {
        Self {
            entry: None,
            next: Mutex::new(None),
        }
    }

    const fn from_entry(entry: QueuedRecord) -> Self {
        Self {
            entry: Some(entry),
            next: Mutex::new(None),
        }
    }
}

struct QueueState {
    head: Arc<Node>,
    tail: Arc<Node>,
    next_seq: u64,
    live_start_seq: u64,
    total_bytes: u64,
    total_records: usize,
    max_bytes: Option<u64>,
    forwarders: HashMap<String, ForwarderState>,
}

pub struct IngestQueue {
    state: Mutex<QueueState>,
    notify: Notify,
}

impl IngestQueue {
    fn new() -> Self {
        let sentinel = Arc::new(Node::sentinel());
        Self {
            state: Mutex::new(QueueState {
                head: sentinel.clone(),
                tail: sentinel,
                next_seq: 1,
                live_start_seq: 1,
                total_bytes: 0,
                total_records: 0,
                max_bytes: None,
                forwarders: HashMap::new(),
            }),
            notify: Notify::new(),
        }
    }

    pub const fn appender_name() -> &'static str {
        QUEUE_APPENDER
    }

    pub fn register_forwarder(&self, name: &str, next_seq: u64) {
        let mut state = self.state.lock().expect("queue poisoned");
        state.forwarders.insert(
            name.to_string(),
            ForwarderState {
                next_seq,
                current_seq: None,
                current_node: None,
                pending_next_seq: None,
                pending_node: None,
            },
        );
        drop(state);
        self.notify.notify_waiters();
    }

    pub fn unregister_forwarder(&self, name: &str) {
        let mut state = self.state.lock().expect("queue poisoned");
        state.forwarders.remove(name);
        Self::gc_consumed_locked(&mut state);
        drop(state);
    }

    pub fn snapshot(&self) -> QueueSnapshot {
        let state = self.state.lock().expect("queue poisoned");
        QueueSnapshot {
            next_seq: state.next_seq,
            live_start_seq: state.live_start_seq,
            total_bytes: state.total_bytes,
        }
    }

    pub fn configure_max_bytes(&self, max_bytes: u64) {
        let mut state = self.state.lock().expect("queue poisoned");
        state.max_bytes = if max_bytes == 0 {
            None
        } else {
            Some(max_bytes)
        };
        Self::trim_to_cap_locked(&mut state);
    }

    pub fn memory_bytes(&self) -> u64 {
        self.state.lock().expect("queue poisoned").total_bytes
    }

    pub fn live_start_seq(&self) -> u64 {
        self.state.lock().expect("queue poisoned").live_start_seq
    }

    pub fn take_batch(
        &self,
        forwarder_name: &str,
        start_seq: u64,
        max_records: usize,
    ) -> TakeBatchResult {
        let mut state = self.state.lock().expect("queue poisoned");

        if start_seq < state.live_start_seq {
            return TakeBatchResult::Gap {
                live_start_seq: state.live_start_seq,
            };
        }

        if start_seq >= state.next_seq {
            return TakeBatchResult::Empty {
                next_seq: state.next_seq,
                memory_bytes: state.total_bytes,
            };
        }

        let mut out = Vec::new();
        let mut start_node = state.forwarders.get(forwarder_name).and_then(|forwarder| {
            if forwarder.current_seq == Some(start_seq) {
                forwarder.current_node.clone()
            } else {
                None
            }
        });

        if start_node.is_none() {
            let mut next = Self::first_node(&state);
            while let Some(node) = next {
                let Some(entry) = node.entry.as_ref() else {
                    next = node.next.lock().expect("queue node poisoned").clone();
                    continue;
                };

                if entry.seq >= start_seq {
                    start_node = Some(node);
                    break;
                }

                next = node.next.lock().expect("queue node poisoned").clone();
            }
        }

        let mut next = start_node.clone();
        let mut pending_node = None;

        while let Some(node) = next {
            let maybe_entry = node.entry.clone();
            if let Some(entry) = maybe_entry
                && entry.seq >= start_seq
            {
                out.push(entry);
                if out.len() >= max_records {
                    pending_node = node.next.lock().expect("queue node poisoned").clone();
                    break;
                }
            }
            next = node.next.lock().expect("queue node poisoned").clone();
            pending_node = next.clone();
        }

        let next_seq = out
            .last()
            .map(|entry| entry.seq + 1)
            .unwrap_or(state.next_seq);

        if let Some(forwarder) = state.forwarders.get_mut(forwarder_name) {
            forwarder.current_seq = start_node
                .as_ref()
                .and_then(|node| node.entry.as_ref().map(|entry| entry.seq));
            forwarder.current_node = start_node;
            forwarder.pending_next_seq = Some(next_seq);
            forwarder.pending_node = pending_node;
        }

        TakeBatchResult::Records {
            records: out,
            next_seq,
            memory_bytes: state.total_bytes,
        }
    }

    pub fn ack_forwarder(&self, name: &str, next_seq: u64) {
        let mut state = self.state.lock().expect("queue poisoned");
        if let Some(slot) = state.forwarders.get_mut(name) {
            slot.next_seq = next_seq;
            if slot.pending_next_seq == Some(next_seq) {
                slot.current_seq = slot.pending_next_seq;
                slot.current_node = slot.pending_node.take();
            } else {
                slot.current_seq = None;
                slot.current_node = None;
            }
            slot.pending_next_seq = None;
            slot.pending_node = None;
            Self::gc_consumed_locked(&mut state);
        }
    }

    fn gc_consumed_locked(state: &mut QueueState) {
        let oldest_needed = state
            .forwarders
            .values()
            .map(|forwarder| forwarder.next_seq)
            .min()
            .unwrap_or(state.next_seq);

        loop {
            let Some(next_node) = Self::first_node(state) else {
                Self::reset_empty_locked(state);
                break;
            };

            let Some(entry) = next_node.entry.as_ref() else {
                let next_after = next_node.next.lock().expect("queue node poisoned").clone();
                *state.head.next.lock().expect("queue node poisoned") = next_after;
                continue;
            };

            let entry_seq = entry.seq;
            let encoded_len = entry.encoded_len;

            if entry_seq >= oldest_needed {
                state.live_start_seq = entry_seq;
                break;
            }

            Self::drop_head_locked(state, next_node, encoded_len);
        }
    }

    fn trim_to_cap_locked(state: &mut QueueState) {
        let Some(max_bytes) = state.max_bytes else {
            return;
        };

        while state.total_bytes > max_bytes && state.total_records > 1 {
            let Some(next_node) = Self::first_node(state) else {
                Self::reset_empty_locked(state);
                break;
            };

            let Some(entry) = next_node.entry.as_ref() else {
                let next_after = next_node.next.lock().expect("queue node poisoned").clone();
                *state.head.next.lock().expect("queue node poisoned") = next_after;
                continue;
            };

            let encoded_len = entry.encoded_len;
            Self::drop_head_locked(state, next_node, encoded_len);

            if state.total_bytes == 0 {
                break;
            }
        }
    }

    fn first_node(state: &QueueState) -> Option<Arc<Node>> {
        state.head.next.lock().expect("queue node poisoned").clone()
    }

    fn drop_head_locked(state: &mut QueueState, next_node: Arc<Node>, encoded_len: u64) {
        let next_after = next_node.next.lock().expect("queue node poisoned").clone();
        *state.head.next.lock().expect("queue node poisoned") = next_after.clone();
        state.total_bytes = state.total_bytes.saturating_sub(encoded_len);
        state.total_records = state.total_records.saturating_sub(1);

        if state.total_records == 0 {
            Self::reset_empty_locked(state);
            return;
        }

        if let Some(next_entry) = next_after.and_then(|node| node.entry.clone()) {
            state.live_start_seq = next_entry.seq;
        }

        Self::invalidate_cursors_locked(state);
    }

    fn invalidate_cursors_locked(state: &mut QueueState) {
        let live_start_seq = state.live_start_seq;
        for forwarder in state.forwarders.values_mut() {
            if forwarder
                .current_seq
                .is_some_and(|seq| seq < live_start_seq)
            {
                forwarder.current_seq = None;
                forwarder.current_node = None;
            }
            if forwarder
                .pending_next_seq
                .is_some_and(|seq| seq < live_start_seq)
            {
                forwarder.pending_next_seq = None;
                forwarder.pending_node = None;
            }
        }
    }

    fn reset_empty_locked(state: &mut QueueState) {
        let sentinel = Arc::new(Node::sentinel());
        state.head = sentinel.clone();
        state.tail = sentinel;
        state.live_start_seq = state.next_seq;
        state.total_bytes = 0;
        state.total_records = 0;
        Self::invalidate_cursors_locked(state);
    }

    fn enqueue(&self, record: Arc<LogRecord>, encoded_len: u64) {
        let mut state = self.state.lock().expect("queue poisoned");
        let seq = state.next_seq;
        state.next_seq += 1;

        let node = Arc::new(Node::from_entry(QueuedRecord {
            seq,
            encoded_len,
            record,
        }));

        let mut tail_next = state.tail.next.lock().expect("queue node poisoned");
        *tail_next = Some(node.clone());
        drop(tail_next);
        state.tail = node;
        state.total_bytes = state.total_bytes.saturating_add(encoded_len);
        state.total_records += 1;
        if state.total_records == 1 {
            state.live_start_seq = seq;
        }

        Self::trim_to_cap_locked(&mut state);
        drop(state);
        self.notify.notify_waiters();
    }

    pub async fn wait_for_records(&self) {
        self.notify.notified().await;
    }
}

pub enum TakeBatchResult {
    Records {
        records: Vec<QueuedRecord>,
        next_seq: u64,
        memory_bytes: u64,
    },
    Empty {
        next_seq: u64,
        memory_bytes: u64,
    },
    Gap {
        live_start_seq: u64,
    },
}

pub struct QueueAppender {
    queue: Arc<IngestQueue>,
}

impl QueueAppender {
    pub const fn new(queue: Arc<IngestQueue>) -> Self {
        Self { queue }
    }
}

impl std::fmt::Debug for QueueAppender {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("QueueAppender")
    }
}

impl Append for QueueAppender {
    fn append(&self, record: &Record<'_>) -> anyhow::Result<()> {
        let Some(log_type) = log_type_for_target(record.target()) else {
            return Ok(());
        };

        let rendered = record.args().to_string();
        let parsed = parse_log_line(&rendered, log_type)
            .with_context(|| format!("parsing queued log for target {}", record.target()))?;

        self.queue.enqueue(
            Arc::new(LogRecord {
                log_type,
                record: parsed,
            }),
            rendered.len() as u64 + 1,
        );
        Ok(())
    }

    fn flush(&self) {}
}

pub fn log_type_for_target(target: &str) -> Option<&'static str> {
    match target {
        "rb2_ace" => Some("alerts"),
        "rb2_audit" => Some("audit"),
        "rb2_auth" => Some("auth"),
        "rb2_fim" => Some("fim"),
        "rb2_firewall" => Some("firewall"),
        "rb2_health" => Some("health"),
        "rb2_network" => Some("network"),
        "rb2_process" => Some("process"),
        "rb2_scan" => Some("scan"),
        "rb2_yara" => Some("yara"),
        _ => None,
    }
}

pub fn global_queue() -> &'static Arc<IngestQueue> {
    static QUEUE: OnceLock<Arc<IngestQueue>> = OnceLock::new();
    QUEUE.get_or_init(|| Arc::new(IngestQueue::new()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample_record(message: &str) -> Arc<LogRecord> {
        Arc::new(LogRecord {
            log_type: "process",
            record: json!({"message": message}),
        })
    }

    #[test]
    fn gc_advances_to_oldest_forwarder() {
        let queue = IngestQueue::new();
        queue.register_forwarder("a", 1);
        queue.register_forwarder("b", 1);

        queue.enqueue(
            Arc::new(LogRecord {
                log_type: "process",
                record: json!({"message":"one"}),
            }),
            4,
        );
        queue.enqueue(
            Arc::new(LogRecord {
                log_type: "process",
                record: json!({"message":"two"}),
            }),
            4,
        );

        queue.ack_forwarder("a", 3);
        assert_eq!(queue.live_start_seq(), 1);
        queue.ack_forwarder("b", 2);
        assert_eq!(queue.live_start_seq(), 2);
        queue.ack_forwarder("b", 3);
        assert_eq!(queue.live_start_seq(), 3);
    }

    #[test]
    fn take_batch_returns_gap_when_forwarder_falls_behind() {
        let queue = IngestQueue::new();
        queue.register_forwarder("slow", 1);
        queue.register_forwarder("fast", 1);

        queue.enqueue(sample_record("one"), 4);
        queue.enqueue(sample_record("two"), 4);

        queue.ack_forwarder("fast", 3);
        queue.ack_forwarder("slow", 2);

        match queue.take_batch("slow", 1, 10) {
            TakeBatchResult::Gap { live_start_seq } => assert_eq!(live_start_seq, 2),
            _ => panic!("expected gap result"),
        }
    }

    #[test]
    fn take_batch_respects_max_records() {
        let queue = IngestQueue::new();
        queue.register_forwarder("fwd", 1);

        queue.enqueue(sample_record("one"), 4);
        queue.enqueue(sample_record("two"), 4);
        queue.enqueue(sample_record("three"), 6);

        match queue.take_batch("fwd", 1, 2) {
            TakeBatchResult::Records {
                records, next_seq, ..
            } => {
                assert_eq!(records.len(), 2);
                assert_eq!(records[0].seq, 1);
                assert_eq!(records[1].seq, 2);
                assert_eq!(next_seq, 3);
            }
            _ => panic!("expected records result"),
        }
    }

    #[test]
    fn unregistering_slowest_forwarder_triggers_gc() {
        let queue = IngestQueue::new();
        queue.register_forwarder("slow", 1);
        queue.register_forwarder("fast", 1);

        queue.enqueue(sample_record("one"), 4);
        queue.enqueue(sample_record("two"), 4);

        queue.ack_forwarder("fast", 3);
        assert_eq!(queue.live_start_seq(), 1);

        queue.unregister_forwarder("slow");

        assert_eq!(queue.live_start_seq(), 3);
        assert_eq!(queue.memory_bytes(), 0);
    }

    #[test]
    fn hard_cap_drops_oldest_records() {
        let queue = IngestQueue::new();
        queue.configure_max_bytes(8);
        queue.register_forwarder("slow", 1);

        queue.enqueue(sample_record("one"), 4);
        queue.enqueue(sample_record("two"), 4);
        queue.enqueue(sample_record("three"), 6);

        assert_eq!(queue.memory_bytes(), 6);
        assert_eq!(queue.live_start_seq(), 3);

        match queue.take_batch("slow", 1, 10) {
            TakeBatchResult::Gap { live_start_seq } => assert_eq!(live_start_seq, 3),
            _ => panic!("expected gap after trimming"),
        }
    }

    #[test]
    fn zero_cap_means_unbounded_queue() {
        let queue = IngestQueue::new();
        queue.configure_max_bytes(0);
        queue.register_forwarder("fwd", 1);

        queue.enqueue(sample_record("one"), 4);
        queue.enqueue(sample_record("two"), 4);
        queue.enqueue(sample_record("three"), 6);

        assert_eq!(queue.memory_bytes(), 14);
        assert_eq!(queue.live_start_seq(), 1);
    }

    #[test]
    fn oversized_single_record_is_retained() {
        let queue = IngestQueue::new();
        queue.configure_max_bytes(4);
        queue.register_forwarder("fwd", 1);

        queue.enqueue(sample_record("large"), 10);

        assert_eq!(queue.memory_bytes(), 10);
        assert_eq!(queue.live_start_seq(), 1);
        match queue.take_batch("fwd", 1, 10) {
            TakeBatchResult::Records {
                records, next_seq, ..
            } => {
                assert_eq!(records.len(), 1);
                assert_eq!(records[0].seq, 1);
                assert_eq!(next_seq, 2);
            }
            _ => panic!("expected oversized record to remain queued"),
        }
    }

    #[test]
    fn cached_forwarder_cursor_is_invalidated_after_trim() {
        let queue = IngestQueue::new();
        queue.configure_max_bytes(8);
        queue.register_forwarder("slow", 1);

        queue.enqueue(sample_record("one"), 4);
        queue.enqueue(sample_record("two"), 4);

        match queue.take_batch("slow", 1, 1) {
            TakeBatchResult::Records { records, .. } => assert_eq!(records[0].seq, 1),
            _ => panic!("expected cached first record"),
        }

        queue.enqueue(sample_record("three"), 6);

        match queue.take_batch("slow", 1, 10) {
            TakeBatchResult::Gap { live_start_seq } => assert_eq!(live_start_seq, 3),
            _ => panic!("expected gap after cached cursor was trimmed"),
        }
    }

    #[test]
    fn unknown_targets_are_not_forwarded() {
        assert_eq!(log_type_for_target("rb2_health"), Some("health"));
        assert_eq!(log_type_for_target("rb2_auth"), Some("auth"));
        assert_eq!(log_type_for_target("rb2_audit"), Some("audit"));
        assert_eq!(log_type_for_target("rb2_network"), Some("network"));
        assert_eq!(log_type_for_target("rb2_other"), None);
    }
}
