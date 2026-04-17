use crate::firewall::{FirewallEvent, Handler};
use async_trait::async_trait;
use nfq::Verdict;
use tokio::sync::mpsc::Sender;

pub struct NfqFirewall {
    pub sender: Sender<Verdict>,
}

impl NfqFirewall {
    pub const fn new(sender: Sender<Verdict>) -> Self {
        Self { sender }
    }
}

#[async_trait]
impl Handler for NfqFirewall {
    async fn run(&self) -> anyhow::Result<()> {
        Ok(())
    }

    async fn handle_event(&self, _ev: &FirewallEvent, dec: bool) -> anyhow::Result<()> {
        let verdict = match dec {
            true => Verdict::Accept,
            false => Verdict::Drop,
        };
        self.sender.send(verdict).await?;
        Ok(())
    }
}
