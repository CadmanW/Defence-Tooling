use crate::firewall::{EventProducer, FirewallEvent};
use async_trait::async_trait;
use log::{debug, warn};
use rb2_auditd::{AuditEvent, NetworkEvent};
use tokio::sync::{broadcast, mpsc, watch};

pub struct AuditEventProducer {
    receiver: broadcast::Receiver<AuditEvent>,
    shutdown: watch::Receiver<bool>,
}

impl AuditEventProducer {
    pub fn new(receiver: broadcast::Receiver<AuditEvent>, shutdown: watch::Receiver<bool>) -> Self {
        Self { receiver, shutdown }
    }
}

pub(crate) fn firewall_event_from_network_event(event: &NetworkEvent) -> FirewallEvent {
    FirewallEvent {
        pid: event.pid as i32,
        comm: event.comm.clone(),
        dport: Some(event.port),
        ip: Some(event.address.clone()),
        op: Some(event.op.clone()),
    }
}

#[async_trait]
impl EventProducer for AuditEventProducer {
    async fn run(&self, tx: mpsc::Sender<FirewallEvent>) -> anyhow::Result<()> {
        let mut receiver = self.receiver.resubscribe();
        let mut shutdown = self.shutdown.clone();

        loop {
            tokio::select! {
                recv = receiver.recv() => {
                    match recv {
                        Ok(AuditEvent::Network(event)) => {
                            let firewall_event = firewall_event_from_network_event(&event);
                            debug!(
                                "audit firewall_event pid={} op={} dport={}",
                                firewall_event.pid,
                                firewall_event.op.as_deref().unwrap_or("unknown"),
                                firewall_event.dport.unwrap_or_default()
                            );

                            if tx.send(firewall_event).await.is_err() {
                                debug!("firewall event receiver dropped; stopping audit event producer");
                                return Ok(());
                            }
                        }
                        Ok(AuditEvent::Exec(_)) => {}
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                            warn!("audit firewall producer lagged and missed {} events", n);
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                            debug!("audit firewall producer broadcast closed");
                            return Ok(());
                        }
                    }
                }
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        debug!("audit firewall producer shutting down");
                        return Ok(());
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rb2_auditd::parser::EventId;

    #[test]
    fn network_event_maps_to_firewall_event() {
        let event = NetworkEvent {
            event_id: EventId {
                timestamp_sec: 1,
                timestamp_ms: 2,
                serial: 3,
            },
            syscall: 42,
            op: "connect".to_string(),
            pid: 1234,
            ppid: Some(100),
            uid: Some(0),
            audit_loginuid: 1000,
            audit_sessionid: 2000,
            comm: Some("curl".to_string()),
            exe: Some("/usr/bin/curl".to_string()),
            success: true,
            family: "ipv4".to_string(),
            address: "198.51.100.10".to_string(),
            port: 443,
        };

        let firewall_event = firewall_event_from_network_event(&event);
        assert_eq!(firewall_event.pid, 1234);
        assert_eq!(firewall_event.comm.as_deref(), Some("curl"));
        assert_eq!(firewall_event.dport, Some(443));
        assert_eq!(firewall_event.ip.as_deref(), Some("198.51.100.10"));
        assert_eq!(firewall_event.op.as_deref(), Some("connect"));
    }
}
