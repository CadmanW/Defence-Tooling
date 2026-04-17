//! Session tracking for TTY recordings using audit identity.
//!
//! Only the first PTY seen for an active audit identity is recorded. Additional
//! PTYs for the same identity are treated as duplicates while the identity
//! remains active within the configured idle timeout window.

use std::collections::HashMap;
use std::io;
use std::path::PathBuf;

use log::debug;
use nix::time::{ClockId, clock_gettime};
use uuid::Uuid;

use super::ParsedTtyWrite;
use super::cast_writer::CastSession;

const UNSET_AUDIT_ID: u32 = u32::MAX;

/// Describes which storage backend sessions should use.
pub enum StorageBackend {
    /// Write sealed chunk files under `spool_dir`.
    Spool { spool_dir: PathBuf },
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct AuditSessionKey {
    audit_loginuid: u32,
    audit_sessionid: u32,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct FallbackSessionKey {
    tid: u32,
    start_time_ns: u64,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum SessionKey {
    Audit(AuditSessionKey),
    Fallback(FallbackSessionKey),
}

impl SessionKey {
    const fn from_event(ev: &ParsedTtyWrite) -> Self {
        if ev.audit_loginuid != UNSET_AUDIT_ID && ev.audit_sessionid != UNSET_AUDIT_ID {
            Self::Audit(AuditSessionKey {
                audit_loginuid: ev.audit_loginuid,
                audit_sessionid: ev.audit_sessionid,
            })
        } else {
            // Fall back to a per-process identity so unset audit IDs never merge
            // unrelated TTY streams together.
            Self::Fallback(FallbackSessionKey {
                tid: ev.tid,
                start_time_ns: ev.start_time_ns,
            })
        }
    }

    fn log_label(self) -> String {
        match self {
            Self::Audit(key) => format!(
                "auid={} audit_sessionid={}",
                key.audit_loginuid, key.audit_sessionid
            ),
            Self::Fallback(key) => {
                format!(
                    "fallback tid={} start_time_ns={}",
                    key.tid, key.start_time_ns
                )
            }
        }
    }
}

/// An active recording session for an audit identity.
struct ActiveSession {
    root_tty: (u16, u16),
    cast_session: CastSession,
    uuid: Uuid,
    last_activity_ts: u64,
}

/// Tracks TTY sessions and maps them to cast files.
/// Only the first (root) PTY per active audit identity is recorded.
pub struct SessionTracker {
    backend: StorageBackend,
    pubkey: Option<String>,
    idle_timeout_ns: u64,
    sessions: HashMap<SessionKey, ActiveSession>,
}

impl SessionTracker {
    pub fn new(
        backend: StorageBackend,
        pubkey: Option<String>,
        idle_timeout_secs: u64,
    ) -> io::Result<Self> {
        let label = match &backend {
            StorageBackend::Spool { .. } => "spool",
        };
        if pubkey.is_some() {
            debug!(
                "Session tracker initialized ({label}) with encryption enabled (idle_timeout={}s)",
                idle_timeout_secs
            );
        } else {
            debug!(
                "Session tracker initialized ({label}) without encryption (idle_timeout={}s)",
                idle_timeout_secs
            );
        }
        Ok(Self {
            backend,
            pubkey,
            idle_timeout_ns: idle_timeout_secs.saturating_mul(1_000_000_000),
            sessions: HashMap::new(),
        })
    }

    /// Proper async API: handle an event end-to-end (create session if needed, write data, resize).
    ///
    /// This replaces the old "return &mut CastSession" pattern (which can't be used correctly with .await).
    pub async fn handle_tty_write(&mut self, ev: &ParsedTtyWrite) -> io::Result<()> {
        let key = SessionKey::from_event(ev);
        let tty = (ev.tty_major, ev.tty_minor);

        if self
            .sessions
            .get(&key)
            .is_some_and(|active| self.idle_expired(active.last_activity_ts, ev.ts))
        {
            self.close_session(
                key,
                format!(
                    "idle timeout exceeded before next event on PTY {}:{}",
                    tty.0, tty.1
                ),
            )
            .await?;
        }

        if let Some(active) = self.sessions.get_mut(&key) {
            active.last_activity_ts = ev.ts;
            if active.root_tty != tty {
                debug!(
                    "Skipping duplicate PTY {}:{} for {} (root is {}:{})",
                    tty.0,
                    tty.1,
                    key.log_label(),
                    active.root_tty.0,
                    active.root_tty.1
                );
                return Ok(());
            }
        } else {
            self.create_session(key, ev).await?;
        }

        let active = self.sessions.get_mut(&key).unwrap();
        active.last_activity_ts = ev.ts;
        active
            .cast_session
            .write_tty_output(ev.ts, ev.rows, ev.cols, ev.tty_out.as_slice())
            .await?;

        Ok(())
    }

    /// Flush all active sessions and close any that have gone idle.
    pub async fn flush_all(&mut self) -> io::Result<()> {
        if let Some(now_ts) = monotonic_now_ns() {
            let expired_keys: Vec<SessionKey> = self
                .sessions
                .iter()
                .filter(|(_, active)| self.idle_expired(active.last_activity_ts, now_ts))
                .map(|(key, _)| *key)
                .collect();

            for key in expired_keys {
                self.close_session(key, "idle timeout exceeded during periodic flush")
                    .await?;
            }
        }

        for active in self.sessions.values_mut() {
            active.cast_session.flush().await?;
        }
        Ok(())
    }

    /// Flush and close all active sessions (use during graceful shutdown).
    pub async fn close_all(&mut self) -> io::Result<()> {
        for active in self.sessions.values_mut() {
            active.cast_session.close().await?;
        }
        self.sessions.clear();
        Ok(())
    }

    const fn idle_expired(&self, last_activity_ts: u64, now_ts: u64) -> bool {
        now_ts.saturating_sub(last_activity_ts) > self.idle_timeout_ns
    }

    async fn close_session(&mut self, key: SessionKey, reason: impl AsRef<str>) -> io::Result<()> {
        if let Some(mut active) = self.sessions.remove(&key) {
            debug!(
                "Closing session {} for {} ({})",
                active.uuid,
                key.log_label(),
                reason.as_ref()
            );
            active.cast_session.close().await?;
        }
        Ok(())
    }

    async fn create_session(&mut self, key: SessionKey, ev: &ParsedTtyWrite) -> io::Result<()> {
        let tty = (ev.tty_major, ev.tty_minor);
        let uuid = Uuid::new_v4();
        debug!(
            "Creating new session {} for root PTY {}:{} ({}){}",
            uuid,
            tty.0,
            tty.1,
            key.log_label(),
            if self.pubkey.is_some() {
                " [encrypted]"
            } else {
                ""
            }
        );

        let cast_session = match &self.backend {
            StorageBackend::Spool { spool_dir } => CastSession::new_spool(
                spool_dir,
                uuid,
                ev.rows,
                ev.cols,
                ev.ts,
                self.pubkey.as_deref(),
            )?,
        };

        self.sessions.insert(
            key,
            ActiveSession {
                root_tty: tty,
                cast_session,
                uuid,
                last_activity_ts: ev.ts,
            },
        );

        Ok(())
    }
}

fn monotonic_now_ns() -> Option<u64> {
    let ts = clock_gettime(ClockId::CLOCK_MONOTONIC).ok()?;
    let secs = u64::try_from(ts.tv_sec()).ok()?;
    let nanos = u64::try_from(ts.tv_nsec()).ok()?;
    Some(secs.saturating_mul(1_000_000_000).saturating_add(nanos))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn temp_output_dir(test_name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("rb2-tty-{test_name}-{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).expect("create temp output dir");
        dir
    }

    fn test_backend(test_name: &str) -> StorageBackend {
        StorageBackend::Spool {
            spool_dir: temp_output_dir(test_name),
        }
    }

    fn test_event(
        ts: u64,
        tid: u32,
        start_time_ns: u64,
        tty_minor: u16,
        sid: u32,
        audit_loginuid: u32,
        audit_sessionid: u32,
    ) -> ParsedTtyWrite {
        ParsedTtyWrite {
            ts,
            ts_boot: ts,
            tty_out_truncated: 0,
            start_time_ns,
            tid,
            ppid: 1,
            sid,
            audit_loginuid,
            audit_sessionid,
            ctty_major: 136,
            ctty_minor: tty_minor,
            tty_major: 136,
            tty_minor,
            rows: 24,
            cols: 80,
            comm: "bash".to_string(),
            tty_out: b"echo hi\n".to_vec(),
        }
    }

    #[tokio::test]
    async fn audit_tuple_survives_sid_changes() {
        let mut tracker = SessionTracker::new(test_backend("sid-change"), None, 300).unwrap();
        let ev1 = test_event(0, 101, 1_000, 1, 100, 1000, 42);
        tracker.handle_tty_write(&ev1).await.unwrap();

        let uuid = tracker.sessions.values().next().unwrap().uuid;

        let ev2 = test_event(100_000_000_000, 101, 1_000, 1, 200, 1000, 42);
        tracker.handle_tty_write(&ev2).await.unwrap();

        assert_eq!(tracker.sessions.len(), 1);
        assert_eq!(tracker.sessions.values().next().unwrap().uuid, uuid);

        tracker.close_all().await.unwrap();
    }

    #[tokio::test]
    async fn repeated_activity_refreshes_idle_timeout() {
        let mut tracker = SessionTracker::new(test_backend("refresh-timeout"), None, 300).unwrap();
        let ev1 = test_event(0, 101, 1_000, 1, 100, 1000, 42);
        tracker.handle_tty_write(&ev1).await.unwrap();
        let uuid = tracker.sessions.values().next().unwrap().uuid;

        let ev2 = test_event(200_000_000_000, 101, 1_000, 1, 200, 1000, 42);
        tracker.handle_tty_write(&ev2).await.unwrap();
        assert_eq!(tracker.sessions.values().next().unwrap().uuid, uuid);

        let ev3 = test_event(450_000_000_000, 101, 1_000, 2, 300, 1000, 42);
        tracker.handle_tty_write(&ev3).await.unwrap();
        let active = tracker.sessions.values().next().unwrap();
        assert_eq!(active.uuid, uuid);
        assert_eq!(active.root_tty, (136, 1));

        let ev4 = test_event(751_000_000_000, 101, 1_000, 1, 400, 1000, 42);
        tracker.handle_tty_write(&ev4).await.unwrap();

        assert_eq!(tracker.sessions.len(), 1);
        assert_ne!(tracker.sessions.values().next().unwrap().uuid, uuid);

        tracker.close_all().await.unwrap();
    }

    #[tokio::test]
    async fn different_audit_tuples_create_distinct_sessions() {
        let mut tracker = SessionTracker::new(test_backend("distinct-tuples"), None, 300).unwrap();
        tracker
            .handle_tty_write(&test_event(0, 101, 1_000, 1, 100, 1000, 42))
            .await
            .unwrap();
        tracker
            .handle_tty_write(&test_event(1, 102, 2_000, 2, 200, 1000, 43))
            .await
            .unwrap();

        assert_eq!(tracker.sessions.len(), 2);

        tracker.close_all().await.unwrap();
    }

    #[tokio::test]
    async fn unset_audit_ids_do_not_collapse_unrelated_sessions() {
        let mut tracker = SessionTracker::new(test_backend("unset-audit"), None, 300).unwrap();
        tracker
            .handle_tty_write(&test_event(
                0,
                101,
                1_000,
                1,
                100,
                UNSET_AUDIT_ID,
                UNSET_AUDIT_ID,
            ))
            .await
            .unwrap();
        tracker
            .handle_tty_write(&test_event(
                1,
                202,
                2_000,
                2,
                200,
                UNSET_AUDIT_ID,
                UNSET_AUDIT_ID,
            ))
            .await
            .unwrap();

        assert_eq!(tracker.sessions.len(), 2);

        tracker.close_all().await.unwrap();
    }
}
