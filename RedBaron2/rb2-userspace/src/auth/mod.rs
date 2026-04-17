mod ebpf;

use crate::{config::yaml, misc};
use chrono::SecondsFormat;
use log::{debug, error, info};
use lru::LruCache;
use serde_json::{Value, json};
use std::num::NonZeroUsize;
use std::time::Instant;
use tokio::io::unix::AsyncFd;

use ebpf::{PamStage, ParsedAuthEvent};

const AUTH_TXN_CAPACITY: usize = 200;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct AuthTxnKey {
    tgid: u32,
    pamh: u64,
}

#[derive(Debug, Clone)]
struct PendingAuthLog {
    last_seen: Instant,
    pid: u32,
    tgid: u32,
    pamh: u64,
    audit_loginuid: u32,
    audit_sessionid: u32,
    comm: String,
    service: String,
    requested_user: String,
    resolved_user: String,
    rhost: String,
    ruser: String,
    tty: String,
    auth_rc: i32,
    acct_rc: i32,
    session_rc: i32,
    session_opened: bool,
    final_rc: i32,
    saw_start: bool,
    saw_get_user: bool,
    saw_authenticate: bool,
    saw_acct_mgmt: bool,
    saw_open_session: bool,
    saw_close_session: bool,
    saw_end: bool,
}

fn null_if_empty(value: &str) -> Value {
    if value.is_empty() {
        Value::Null
    } else {
        Value::String(value.to_string())
    }
}

fn maybe_replace_string(dst: &mut String, src: &str) {
    if !src.is_empty() {
        dst.clear();
        dst.push_str(src);
    }
}

impl PendingAuthLog {
    fn from_event(event: &ParsedAuthEvent, now: Instant) -> Self {
        let mut txn = Self {
            last_seen: now,
            pid: event.pid,
            tgid: event.tgid,
            pamh: event.pamh,
            audit_loginuid: event.audit_loginuid,
            audit_sessionid: event.audit_sessionid,
            comm: event.comm.clone(),
            service: String::new(),
            requested_user: String::new(),
            resolved_user: String::new(),
            rhost: String::new(),
            ruser: String::new(),
            tty: String::new(),
            auth_rc: ebpf::AUTH_RC_UNSET,
            acct_rc: ebpf::AUTH_RC_UNSET,
            session_rc: ebpf::AUTH_RC_UNSET,
            session_opened: false,
            final_rc: event.rc,
            saw_start: false,
            saw_get_user: false,
            saw_authenticate: false,
            saw_acct_mgmt: false,
            saw_open_session: false,
            saw_close_session: false,
            saw_end: false,
        };
        apply_event(&mut txn, event, now);
        txn
    }

    fn stages_seen(&self) -> Vec<&'static str> {
        let mut stages = Vec::with_capacity(7);
        if self.saw_start {
            stages.push("pam_start");
        }
        if self.saw_get_user {
            stages.push("pam_get_user");
        }
        if self.saw_authenticate {
            stages.push("pam_authenticate");
        }
        if self.saw_acct_mgmt {
            stages.push("pam_acct_mgmt");
        }
        if self.saw_open_session {
            stages.push("pam_open_session");
        }
        if self.saw_close_session {
            stages.push("pam_close_session");
        }
        if self.saw_end {
            stages.push("pam_end");
        }
        stages
    }

    const fn result(&self) -> &'static str {
        let auth_failed = self.auth_rc != ebpf::AUTH_RC_UNSET && self.auth_rc != 0;
        let acct_failed = self.acct_rc != ebpf::AUTH_RC_UNSET && self.acct_rc != 0;
        let session_failed = self.session_rc != ebpf::AUTH_RC_UNSET && self.session_rc != 0;
        let has_auth_path = self.saw_authenticate || self.saw_acct_mgmt || self.saw_open_session;

        if self.final_rc != 0 || auth_failed || acct_failed || session_failed {
            "failure"
        } else if has_auth_path {
            "success"
        } else {
            "incomplete"
        }
    }
}

const fn txn_key(event: &ParsedAuthEvent) -> Option<AuthTxnKey> {
    if event.pamh == 0 {
        None
    } else {
        Some(AuthTxnKey {
            tgid: event.tgid,
            pamh: event.pamh,
        })
    }
}

fn apply_event(txn: &mut PendingAuthLog, event: &ParsedAuthEvent, now: Instant) {
    txn.last_seen = now;
    txn.pid = event.pid;
    txn.tgid = event.tgid;
    txn.pamh = event.pamh;
    txn.final_rc = event.rc;

    if event.audit_loginuid != u32::MAX {
        txn.audit_loginuid = event.audit_loginuid;
    }
    if event.audit_sessionid != u32::MAX {
        txn.audit_sessionid = event.audit_sessionid;
    }

    maybe_replace_string(&mut txn.comm, &event.comm);
    maybe_replace_string(&mut txn.service, &event.service);
    maybe_replace_string(&mut txn.requested_user, &event.requested_user);
    maybe_replace_string(&mut txn.resolved_user, &event.resolved_user);
    maybe_replace_string(&mut txn.rhost, &event.rhost);
    maybe_replace_string(&mut txn.ruser, &event.ruser);
    maybe_replace_string(&mut txn.tty, &event.tty);

    if event.auth_rc != ebpf::AUTH_RC_UNSET {
        txn.auth_rc = event.auth_rc;
    }
    if event.acct_rc != ebpf::AUTH_RC_UNSET {
        txn.acct_rc = event.acct_rc;
    }
    if event.session_rc != ebpf::AUTH_RC_UNSET {
        txn.session_rc = event.session_rc;
    }
    if event.session_opened {
        txn.session_opened = true;
    }

    match event.stage {
        PamStage::Start => txn.saw_start = true,
        PamStage::GetUser => txn.saw_get_user = true,
        PamStage::Authenticate => txn.saw_authenticate = true,
        PamStage::AcctMgmt => txn.saw_acct_mgmt = true,
        PamStage::OpenSession => txn.saw_open_session = true,
        PamStage::CloseSession => txn.saw_close_session = true,
        PamStage::End => txn.saw_end = true,
        PamStage::Unknown(_) => {}
    }
}

const fn rc_or_none(value: i32) -> Option<i32> {
    if value == ebpf::AUTH_RC_UNSET {
        None
    } else {
        Some(value)
    }
}

fn is_failed_start_without_handle(event: &ParsedAuthEvent) -> bool {
    event.stage == PamStage::Start && event.pamh == 0 && event.rc != 0
}

const fn is_terminal_event(event: &ParsedAuthEvent) -> bool {
    event.stage.is_terminal()
}

const fn is_session_event(event: &ParsedAuthEvent) -> bool {
    event.stage.is_session()
}

fn should_emit_final_auth_log(txn: &PendingAuthLog) -> bool {
    !(txn.saw_open_session && txn.result() == "success")
}

const fn auth_log_rcs(txn: &PendingAuthLog) -> [Option<i32>; 4] {
    [
        Some(txn.final_rc),
        rc_or_none(txn.auth_rc),
        rc_or_none(txn.acct_rc),
        rc_or_none(txn.session_rc),
    ]
}

fn build_final_auth_log(txn: &PendingAuthLog) -> String {
    let payload = json!({
        "_timestamp": chrono::Local::now().to_rfc3339_opts(SecondsFormat::Millis, true),
        "resolved_user": null_if_empty(&txn.resolved_user),
        "requested_user": null_if_empty(&txn.requested_user),
        "result": txn.result(),
        "rhost": null_if_empty(&txn.rhost),
        "comm": &txn.comm,
        "pid": txn.pid,
        "tgid": txn.tgid,
        "audit_loginuid": txn.audit_loginuid,
        "audit_sessionid": txn.audit_sessionid,
        "service": null_if_empty(&txn.service),
        "session_opened": txn.session_opened,
        "ruser": null_if_empty(&txn.ruser),
        "tty": null_if_empty(&txn.tty),
        "stages_seen": txn.stages_seen(),
        "rcs": auth_log_rcs(txn),
        "host_id": misc::get_machine_id(),
        "host_name": misc::get_hostname(),
    });

    serde_json::to_string(&payload)
        .unwrap_or_else(|_| "{\"result\":\"serialization_error\"}".to_string())
}

fn build_session_event_log(txn: &PendingAuthLog, stage: PamStage) -> String {
    let (result, event) = match stage {
        PamStage::OpenSession if txn.final_rc == 0 => ("success", "login"),
        PamStage::OpenSession => ("failure", "login"),
        PamStage::CloseSession if txn.final_rc == 0 => ("success", "logout"),
        PamStage::CloseSession => ("failure", "logout"),
        _ => ("failure", "unknown"),
    };
    let payload = json!({
        "_timestamp": chrono::Local::now().to_rfc3339_opts(SecondsFormat::Millis, true),
        "resolved_user": null_if_empty(&txn.resolved_user),
        "requested_user": null_if_empty(&txn.requested_user),
        "result": result,
        "rhost": null_if_empty(&txn.rhost),
        "comm": &txn.comm,
        "pid": txn.pid,
        "tgid": txn.tgid,
        "audit_loginuid": txn.audit_loginuid,
        "audit_sessionid": txn.audit_sessionid,
        "service": null_if_empty(&txn.service),
        "ruser": null_if_empty(&txn.ruser),
        "tty": null_if_empty(&txn.tty),
        "event": event,
        "stages_seen": txn.stages_seen(),
        "rcs": auth_log_rcs(txn),
        "host_id": misc::get_machine_id(),
        "host_name": misc::get_hostname(),
    });

    serde_json::to_string(&payload)
        .unwrap_or_else(|_| "{\"result\":\"serialization_error\"}".to_string())
}

fn new_txn_cache() -> LruCache<AuthTxnKey, PendingAuthLog> {
    LruCache::new(NonZeroUsize::new(AUTH_TXN_CAPACITY).expect("auth txn capacity must be nonzero"))
}

fn log_capacity_eviction(txn: PendingAuthLog) {
    debug!(
        "auth txn evicted by LRU capacity tgid={} pamh=0x{:x} result={} stages={:?}",
        txn.tgid,
        txn.pamh,
        txn.result(),
        txn.stages_seen()
    );
}

fn finalize_transaction(txns: &mut LruCache<AuthTxnKey, PendingAuthLog>, key: AuthTxnKey) {
    if let Some(txn) = txns.pop(&key) {
        debug!(
            "auth txn finalized tgid={} pamh=0x{:x} result={}",
            txn.tgid,
            txn.pamh,
            txn.result()
        );
        if should_emit_final_auth_log(&txn) {
            info!(target: "rb2_auth", "{}", build_final_auth_log(&txn));
        }
    }
}

async fn drain_events(
    afd: &mut AsyncFd<aya::maps::RingBuf<aya::maps::MapData>>,
) -> anyhow::Result<Vec<ParsedAuthEvent>> {
    let mut guard = afd.readable_mut().await?;
    let events = guard.try_io(|inner| {
        let rb = inner.get_mut();
        let mut out = Vec::new();

        while let Some(item) = rb.next() {
            let event = ebpf::parse_auth_event(&item).map_err(std::io::Error::other)?;
            out.push(event);
        }

        if out.is_empty() {
            Err(std::io::Error::from(std::io::ErrorKind::WouldBlock))
        } else {
            Ok(out)
        }
    });

    match events {
        Ok(Ok(events)) => Ok(events),
        Ok(Err(err)) if err.kind() == std::io::ErrorKind::WouldBlock => Ok(Vec::new()),
        Ok(Err(err)) => Err(err.into()),
        Err(_would_block) => Ok(Vec::new()),
    }
}

pub async fn run<P: AsRef<std::path::Path>>(
    btf_file_path: P,
    cfg: yaml::AuthConfig,
) -> anyhow::Result<()> {
    let ebpf = ebpf::load_and_attach_ebpf(btf_file_path, cfg.libpam_path.as_deref()).await?;
    let (mut afd, _ebpf) = ebpf::take_ringbuf_asyncfd(ebpf)?;
    let mut txns = new_txn_cache();

    info!("PAM auth collector attached");

    loop {
        match drain_events(&mut afd).await {
            Ok(events) => {
                for event in events {
                    let now = Instant::now();

                    if is_failed_start_without_handle(&event) {
                        let txn = PendingAuthLog::from_event(&event, now);
                        debug!(
                            "auth txn immediate failure stage={} rc={} tgid={} pamh=0x{:x}",
                            event.stage.name(),
                            event.rc,
                            event.tgid,
                            event.pamh
                        );
                        info!(target: "rb2_auth", "{}", build_final_auth_log(&txn));
                    } else if let Some(key) = txn_key(&event) {
                        let mut session_log = None;
                        if let Some(txn) = txns.get_mut(&key) {
                            apply_event(txn, &event, now);
                            debug!(
                                "auth txn update tgid={} pamh=0x{:x} stage={} rc={} auth_rc={} acct_rc={} session_rc={} opened={}",
                                txn.tgid,
                                txn.pamh,
                                event.stage.name(),
                                event.rc,
                                txn.auth_rc,
                                txn.acct_rc,
                                txn.session_rc,
                                txn.session_opened
                            );
                            if is_session_event(&event) {
                                session_log = Some(build_session_event_log(txn, event.stage));
                            }
                        } else {
                            debug!(
                                "auth txn created tgid={} pamh=0x{:x} stage={} service={:?} user={:?}",
                                event.tgid,
                                event.pamh,
                                event.stage.name(),
                                event.service,
                                event.requested_user
                            );
                            let txn = PendingAuthLog::from_event(&event, now);
                            if is_session_event(&event) {
                                session_log = Some(build_session_event_log(&txn, event.stage));
                            }
                            if let Some((_, evicted_txn)) = txns.push(key, txn) {
                                log_capacity_eviction(evicted_txn);
                            }
                        }

                        if let Some(session_log) = session_log {
                            info!(target: "rb2_auth", "{}", session_log);
                        }

                        if is_terminal_event(&event) {
                            finalize_transaction(&mut txns, key);
                        }
                    } else {
                        debug!(
                            "auth event without handle ignored stage={} rc={} tgid={}",
                            event.stage.name(),
                            event.rc,
                            event.tgid
                        );
                    }
                }
            }
            Err(err) => {
                error!("auth collector read failed: {err}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn parse_log(log: &str) -> Value {
        serde_json::from_str(log).expect("final auth log should be valid json")
    }

    fn event(stage: PamStage, rc: i32, pamh: u64) -> ParsedAuthEvent {
        ParsedAuthEvent {
            pamh,
            pid: 101,
            tgid: 100,
            audit_loginuid: 1000,
            audit_sessionid: 2000,
            stage,
            rc,
            auth_rc: ebpf::AUTH_RC_UNSET,
            acct_rc: ebpf::AUTH_RC_UNSET,
            session_rc: ebpf::AUTH_RC_UNSET,
            session_opened: false,
            comm: "sshd".to_string(),
            service: String::new(),
            requested_user: String::new(),
            resolved_user: String::new(),
            rhost: String::new(),
            ruser: String::new(),
            tty: String::new(),
        }
    }

    #[test]
    fn apply_event_keeps_existing_fields() {
        let now = Instant::now();
        let mut start = event(PamStage::Start, 0, 0xabc);
        start.service = "sshd".to_string();
        start.requested_user = "alice".to_string();

        let mut txn = PendingAuthLog::from_event(&start, now);

        let mut later = event(PamStage::Authenticate, 0, 0xabc);
        later.auth_rc = 0;
        apply_event(&mut txn, &later, now + Duration::from_secs(1));

        assert_eq!(txn.service, "sshd");
        assert_eq!(txn.requested_user, "alice");
        assert_eq!(txn.auth_rc, 0);
    }

    #[test]
    fn successful_signin() {
        let now = Instant::now();
        let mut start = event(PamStage::Start, 0, 0xabc);
        start.service = "sshd".to_string();
        start.requested_user = "alice".to_string();

        let mut txn = PendingAuthLog::from_event(&start, now);

        let mut auth = event(PamStage::Authenticate, 0, 0xabc);
        auth.resolved_user = "alice".to_string();
        apply_event(&mut txn, &auth, now + Duration::from_millis(3));

        let mut acct = event(PamStage::AcctMgmt, 0, 0xabc);
        acct.acct_rc = 0;
        apply_event(&mut txn, &acct, now + Duration::from_millis(5));

        let mut open = event(PamStage::OpenSession, 0, 0xabc);
        open.session_rc = 0;
        open.session_opened = true;
        apply_event(&mut txn, &open, now + Duration::from_millis(10));

        let mut end = event(PamStage::End, 0, 0xabc);
        end.acct_rc = 0;
        end.session_rc = 0;
        apply_event(&mut txn, &end, now + Duration::from_millis(20));

        let payload = parse_log(&build_final_auth_log(&txn));
        assert_eq!(payload["result"], "success");
        assert_eq!(payload["service"], "sshd");
        assert_eq!(payload["requested_user"], "alice");
        assert_eq!(payload["resolved_user"], "alice");
        assert_eq!(payload["rcs"], serde_json::json!([0, null, 0, 0]));
        assert!(payload.get("event_action").is_none());
        assert!(payload.get("final_stage").is_none());
        assert!(payload.get("pamh").is_none());
        assert!(payload.get("rc").is_none());
        assert!(payload.get("auth_rc").is_none());
        assert!(payload.get("acct_rc").is_none());
        assert!(payload.get("session_rc").is_none());
    }

    #[test]
    fn interrupted_login_is_incomplete() {
        let now = Instant::now();
        let mut start = event(PamStage::Start, 0, 0xabc);
        start.service = "sshd".to_string();
        start.requested_user = "ubuntu1".to_string();

        let mut txn = PendingAuthLog::from_event(&start, now);

        let end = event(PamStage::End, 0, 0xabc);
        apply_event(&mut txn, &end, now + Duration::from_millis(20));

        let payload = parse_log(&build_final_auth_log(&txn));
        assert_eq!(payload["result"], "incomplete");
        assert_eq!(payload["rcs"], serde_json::json!([0, null, null, null]));
    }

    #[test]
    fn failed_auth_is_failure() {
        let now = Instant::now();
        let mut start = event(PamStage::Start, 0, 0xabc);
        start.service = "sshd".to_string();
        start.requested_user = "ubuntu1".to_string();

        let mut txn = PendingAuthLog::from_event(&start, now);

        let mut get_user = event(PamStage::GetUser, 0, 0xabc);
        get_user.resolved_user = "ubuntu1".to_string();
        apply_event(&mut txn, &get_user, now + Duration::from_millis(5));

        let mut auth = event(PamStage::Authenticate, 0, 0xabc);
        auth.auth_rc = 7;
        apply_event(&mut txn, &auth, now + Duration::from_millis(10));

        let mut end = event(PamStage::End, 0, 0xabc);
        end.auth_rc = 7;
        apply_event(&mut txn, &end, now + Duration::from_millis(20));

        let payload = parse_log(&build_final_auth_log(&txn));
        assert_eq!(payload["result"], "failure");
        assert_eq!(payload["rcs"], serde_json::json!([0, 7, null, null]));
    }

    #[test]
    fn session_opened_stays_true_after_close() {
        let now = Instant::now();
        let mut txn = PendingAuthLog::from_event(&event(PamStage::Start, 0, 0xabc), now);

        let mut open = event(PamStage::OpenSession, 0, 0xabc);
        open.session_rc = 0;
        open.session_opened = true;
        apply_event(&mut txn, &open, now + Duration::from_millis(5));

        let mut close = event(PamStage::CloseSession, 0, 0xabc);
        close.session_opened = false;
        apply_event(&mut txn, &close, now + Duration::from_millis(10));

        assert!(txn.session_opened);
    }

    #[test]
    fn failed_start_without_handle_is_immediate() {
        let start = event(PamStage::Start, 7, 0);
        assert!(is_failed_start_without_handle(&start));

        let txn = PendingAuthLog::from_event(&start, Instant::now());
        let payload = parse_log(&build_final_auth_log(&txn));
        assert_eq!(payload["result"], "failure");
        assert_eq!(payload["rcs"], serde_json::json!([7, null, null, null]));
        assert!(payload.get("rc").is_none());
        assert!(payload.get("final_stage").is_none());
    }

    #[test]
    fn session_login_log_uses_minimal_fields() {
        let now = Instant::now();
        let mut txn = PendingAuthLog::from_event(&event(PamStage::Start, 0, 0xabc), now);

        let mut open = event(PamStage::OpenSession, 0, 0xabc);
        open.service = "sshd".to_string();
        open.requested_user = "ubuntu".to_string();
        open.resolved_user = "ubuntu".to_string();
        open.rhost = "10.10.10.20".to_string();
        open.tty = "ssh".to_string();
        open.session_rc = 0;
        open.session_opened = true;
        apply_event(&mut txn, &open, now + Duration::from_millis(5));

        let payload = parse_log(&build_session_event_log(&txn, PamStage::OpenSession));
        assert_eq!(payload["result"], "success");
        assert_eq!(payload["event"], "login");
        assert_eq!(payload["service"], "sshd");
        assert_eq!(payload["resolved_user"], "ubuntu");
        assert_eq!(payload["rhost"], "10.10.10.20");
        assert_eq!(payload["rcs"], serde_json::json!([0, null, null, 0]));
        assert_eq!(
            payload["stages_seen"],
            serde_json::json!(["pam_start", "pam_open_session"])
        );
        assert!(payload.get("session_opened").is_none());
    }

    #[test]
    fn session_logout_log_uses_minimal_fields() {
        let now = Instant::now();
        let mut txn = PendingAuthLog::from_event(&event(PamStage::Start, 0, 0xabc), now);

        let mut open = event(PamStage::OpenSession, 0, 0xabc);
        open.service = "sshd".to_string();
        open.requested_user = "ubuntu".to_string();
        open.resolved_user = "ubuntu".to_string();
        open.rhost = "10.10.10.20".to_string();
        open.tty = "ssh".to_string();
        open.session_rc = 0;
        open.session_opened = true;
        apply_event(&mut txn, &open, now + Duration::from_millis(5));

        let mut close = event(PamStage::CloseSession, 0, 0xabc);
        close.session_rc = 0;
        apply_event(&mut txn, &close, now + Duration::from_millis(10));

        let payload = parse_log(&build_session_event_log(&txn, PamStage::CloseSession));
        assert_eq!(payload["result"], "success");
        assert_eq!(payload["event"], "logout");
        assert_eq!(payload["service"], "sshd");
        assert_eq!(payload["resolved_user"], "ubuntu");
        assert_eq!(payload["rhost"], "10.10.10.20");
        assert_eq!(payload["rcs"], serde_json::json!([0, null, null, 0]));
        assert_eq!(
            payload["stages_seen"],
            serde_json::json!(["pam_start", "pam_open_session", "pam_close_session"])
        );
        assert!(payload.get("session_opened").is_none());
    }

    #[test]
    fn final_auth_log_is_suppressed_for_sessions() {
        let now = Instant::now();
        let mut txn = PendingAuthLog::from_event(&event(PamStage::Start, 0, 0xabc), now);

        let mut open = event(PamStage::OpenSession, 0, 0xabc);
        open.session_rc = 0;
        open.session_opened = true;
        apply_event(&mut txn, &open, now + Duration::from_millis(5));

        assert!(!should_emit_final_auth_log(&txn));
    }

    #[test]
    fn final_auth_log_is_kept_for_failed_open_session() {
        let now = Instant::now();
        let mut txn = PendingAuthLog::from_event(&event(PamStage::Start, 0, 0xabc), now);

        let mut open = event(PamStage::OpenSession, 7, 0xabc);
        open.session_rc = 7;
        apply_event(&mut txn, &open, now + Duration::from_millis(5));

        assert!(should_emit_final_auth_log(&txn));
    }

    #[test]
    fn active_sessions_are_not_evicted() {
        let now = Instant::now();
        let mut txn = PendingAuthLog::from_event(&event(PamStage::Start, 0, 0xabc), now);

        let mut open = event(PamStage::OpenSession, 0, 0xabc);
        open.session_rc = 0;
        open.session_opened = true;
        apply_event(&mut txn, &open, now + Duration::from_millis(5));

        let key = AuthTxnKey {
            tgid: 100,
            pamh: 0xabc,
        };
        let mut txns = new_txn_cache();
        txns.put(key, txn);

        assert!(txns.peek(&key).is_some());
    }

    #[test]
    fn close_session_removes_transaction() {
        let now = Instant::now();
        let key = AuthTxnKey {
            tgid: 100,
            pamh: 0xabc,
        };
        let mut txns = new_txn_cache();
        txns.put(
            key,
            PendingAuthLog::from_event(&event(PamStage::Start, 0, 0xabc), now),
        );

        {
            let txn = txns.get_mut(&key).expect("txn should exist");
            let mut close = event(PamStage::CloseSession, 0, 0xabc);
            close.session_rc = 0;
            apply_event(txn, &close, now + Duration::from_millis(5));
        }

        finalize_transaction(&mut txns, key);
        assert!(txns.is_empty());
    }

    #[test]
    fn end_removes_transaction() {
        let now = Instant::now();
        let key = AuthTxnKey {
            tgid: 100,
            pamh: 0xabc,
        };
        let mut txns = new_txn_cache();
        txns.put(
            key,
            PendingAuthLog::from_event(&event(PamStage::Start, 0, 0xabc), now),
        );

        {
            let txn = txns.get_mut(&key).expect("txn should exist");
            let end = event(PamStage::End, 0, 0xabc);
            apply_event(txn, &end, now + Duration::from_millis(5));
        }

        finalize_transaction(&mut txns, key);
        assert!(txns.is_empty());
    }

    #[test]
    fn lru_evicts_least_recent_transaction() {
        let now = Instant::now();
        let mut txns = new_txn_cache();

        for pamh in 0..AUTH_TXN_CAPACITY as u64 {
            let ev = event(PamStage::Start, 0, pamh + 1);
            txns.put(txn_key(&ev).unwrap(), PendingAuthLog::from_event(&ev, now));
        }

        let hot_key = AuthTxnKey { tgid: 100, pamh: 1 };
        let hot_txn = txns.get_mut(&hot_key).expect("hot txn should exist");
        apply_event(
            hot_txn,
            &event(PamStage::GetUser, 0, 1),
            now + Duration::from_millis(1),
        );

        let next = event(PamStage::Start, 0, AUTH_TXN_CAPACITY as u64 + 1);
        let evicted = txns.push(
            txn_key(&next).unwrap(),
            PendingAuthLog::from_event(&next, now + Duration::from_millis(2)),
        );

        let (evicted_key, _) = evicted.expect("should evict oldest txn");
        assert_eq!(evicted_key.pamh, 2);
        assert!(txns.peek(&hot_key).is_some());
    }
}
