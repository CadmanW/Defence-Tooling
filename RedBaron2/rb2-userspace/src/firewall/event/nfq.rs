use crate::firewall::sockets;
use crate::firewall::{EventProducer, FirewallEvent};
use anyhow::Context;
use anyhow::anyhow;
use async_trait::async_trait;
use aya::maps::{HashMap, MapData, MapError};
use aya::programs::KProbe;
use aya::{Btf, Ebpf, EbpfLoader, Endianness, Pod};
use log::{debug, error, info, trace, warn};
use nfq::{Queue, Verdict};
use std::error::Error;
use std::io;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::Duration;
use tokio::sync::{
    mpsc::{Receiver, Sender},
    watch,
};

/*
 *      +--->|userspace|
 *      |          ^V
 * --> |ebpf| --> |nfq| -->
 */

// TODO: build up nft support

pub struct NfqEventProducer {
    pub btf_path: PathBuf,
    pub enforcing: bool,
    shutdown: watch::Receiver<bool>,
    receiver: OnceLock<Arc<Mutex<Receiver<Verdict>>>>,
}

impl NfqEventProducer {
    pub fn new(btf_path: PathBuf, enforcing: bool, shutdown: watch::Receiver<bool>) -> Self {
        Self {
            btf_path,
            enforcing,
            shutdown,
            receiver: OnceLock::new(),
        }
    }

    /// this sender must send back processed events for the firewall to work!
    pub fn get_sender(&self) -> anyhow::Result<Sender<Verdict>> {
        let (tx, rx) = tokio::sync::mpsc::channel(1024);
        let rx = Arc::new(Mutex::new(rx));
        self.receiver.set(rx).map_err(|_| {
            anyhow::anyhow!("Unable to set receiver OnceLock. Has get_sender been called twice?")
        })?;
        Ok(tx)
    }
}

#[async_trait]
impl EventProducer for NfqEventProducer {
    async fn run(&self, tx: Sender<FirewallEvent>) -> anyhow::Result<()> {
        let btf_path = self.btf_path.clone();
        let enforcing = self.enforcing;
        let shutdown = self.shutdown.clone();
        let receiver = self
            .receiver
            .get()
            .ok_or_else(|| anyhow!("Corresponding nfq event receiver not set up yet"))?
            .clone();

        tokio::task::spawn_blocking(move || {
            run_firewall_blocking(btf_path, enforcing, shutdown, tx, receiver)
        })
        .await??;

        Ok(())
    }
}

fn run_firewall_blocking(
    btf_path: PathBuf,
    enforcing: bool,
    shutdown: watch::Receiver<bool>,
    tx: Sender<FirewallEvent>,
    receiver: Arc<Mutex<Receiver<Verdict>>>,
) -> anyhow::Result<()> {
    let mut ebpf = EbpfLoader::new()
        .btf(
            Btf::parse_file(btf_path, Endianness::default())
                .ok()
                .as_ref(),
        )
        .load(aya::include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/nfq_firewall.bpf.o"
        )))?;

    attach_kprobes(&mut ebpf)?;

    let tcp_raw = ebpf.take_map("tcpMap").unwrap();
    let udp_raw = ebpf.take_map("udpMap").unwrap();

    let mut tcp_map: HashMap<MapData, Ipv4Key, Owner> = HashMap::try_from(tcp_raw)?;
    let mut udp_map: HashMap<MapData, Ipv4Key, Owner> = HashMap::try_from(udp_raw)?;

    const MAX_QUEUE_NUM: u16 = 100;
    let mut queue = Queue::open().context("failed to open nfqueue")?;

    let mut queue_num = None;
    for num in 0..MAX_QUEUE_NUM {
        match queue.bind(num) {
            Ok(_) => {
                queue_num = Some(num);
                break;
            }
            Err(e) => {
                trace!("Failed to bind to nfqueue {}: {}", num, e);
            }
        }
    }

    let queue_num = queue_num.ok_or_else(|| {
        anyhow!(
            "Failed to bind to any nfqueue (tried 0-{})",
            MAX_QUEUE_NUM - 1
        )
    })?;

    info!("Netfilter queue {} ready", queue_num);

    ensure_iptables(queue_num)?;
    queue.set_nonblocking(true);

    let mut last_cleanup = std::time::Instant::now();
    let mut recv_error_streak = 0u32;

    loop {
        if *shutdown.borrow() {
            info!("NFQ producer shutting down");
            break;
        }

        let mut msg = match queue.recv() {
            Ok(m) => m,
            Err(e) => {
                if e.kind() == io::ErrorKind::WouldBlock {
                    recv_error_streak = 0;
                    thread::sleep(Duration::from_millis(50));
                    continue;
                }

                recv_error_streak = recv_error_streak.saturating_add(1);
                let backoff_ms = (25u64).saturating_mul(1u64 << recv_error_streak.min(2));
                error!("NFQ recv failed: {e}");
                thread::sleep(Duration::from_millis(backoff_ms.min(100)));
                continue;
            }
        };
        recv_error_streak = 0;

        let verdict = handle_packet(&tcp_map, &udp_map, msg.get_payload(), &tx, &receiver);

        match enforcing {
            true => msg.set_verdict(verdict),
            false => msg.set_verdict(Verdict::Accept),
        }

        if let Err(e) = queue.verdict(msg) {
            error!(
                "Failed to set verdict {} for packet: {e}",
                if verdict == Verdict::Accept {
                    "ALLOW"
                } else {
                    "DENY"
                }
            );
        }

        if last_cleanup.elapsed() >= Duration::from_secs(5) {
            if let Err(e) = delete_old_elements(&mut tcp_map) {
                error!("Failed to clean tcp map: {e}");
            }
            if let Err(e) = delete_old_elements(&mut udp_map) {
                error!("Failed to clean udp map: {e}");
            }
            last_cleanup = std::time::Instant::now();
        }
    }

    if let Err(e) = queue.unbind(queue_num) {
        error!("Failed to unbind nfqueue {} on shutdown: {e}", queue_num);
    }

    Ok(())
}

fn handle_packet(
    tcp_map: &HashMap<MapData, Ipv4Key, Owner>,
    udp_map: &HashMap<MapData, Ipv4Key, Owner>,
    payload: &[u8],
    tx: &Sender<FirewallEvent>,
    receiver: &Arc<Mutex<Receiver<Verdict>>>,
) -> Verdict {
    if payload.is_empty() || (payload[0] >> 4) != 4 {
        warn!("Not parsing non-ipv4 packet");
        return Verdict::Drop;
    }

    let protocol = payload.get(9).copied().unwrap_or(0);

    let key = match parse_ipv4_key(payload) {
        Ok(k) => k,
        Err(e) => {
            error!("Malformed packet: {e}");
            return Verdict::Drop;
        }
    };

    let owner = match protocol {
        0x06 => tcp_map.get(&key, 0).ok(),
        0x11 => udp_map.get(&key, 0).ok(),
        _ => None,
    };

    if let Some(owner) = owner {
        // "comm=<comm> ip=<ip> dport=<dport> op=<op>"
        let ev = FirewallEvent {
            pid: owner.pid,
            comm: comm_to_string(&owner.comm),
            dport: Some(key.dport),
            ip: Some(Ipv4Addr::from(key.daddr).to_string()),
            op: None,
        };

        if let Err(e) = tx.blocking_send(ev) {
            let pid = owner.pid;
            debug!(
                "Unable to send off firewall event to dispatcher pid={} {}",
                pid, e
            );
            return Verdict::Drop;
        }

        let mut rx = match receiver.lock() {
            Ok(guard) => guard,
            Err(_) => {
                error!("Dispatcher receiver mutex poisoned");
                return Verdict::Drop;
            }
        };

        rx.blocking_recv().unwrap_or_else(|| {
            debug!("Dispatcher receiver closed");
            Verdict::Drop
        })
    } else {
        warn!("Unknown socket connection from nfq");
        Verdict::Drop
    }
}

#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct Ipv4Key {
    pub sport: u16,
    pub daddr: u32,
    pub dport: u16,
}
unsafe impl Pod for Ipv4Key {}

#[allow(dead_code)]
#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct Owner {
    pub pid: i32,
    pub comm: [u8; 16],
}
unsafe impl Pod for Owner {}

fn comm_to_string(comm: &[u8; 16]) -> Option<String> {
    let nul = comm.iter().position(|&b| b == 0).unwrap_or(comm.len());
    let s = std::str::from_utf8(&comm[..nul]).ok()?.trim();
    if s.is_empty() {
        None
    } else {
        Some(s.to_string())
    }
}

fn delete_old_elements(map: &mut HashMap<MapData, Ipv4Key, Owner>) -> Result<(), MapError> {
    // TODO: also remove sockets that no longer exist
    // (can be a problem for which doesn't die but can open several sockets that close)
    let keys: Vec<Ipv4Key> = map.keys().filter_map(Result::ok).collect();
    for key in keys {
        if let Ok(decision) = map.get(&key, 0) {
            let pid = decision.pid;
            if !pid_exists(pid) || !sockets::socket_exists(&key, pid) {
                trace!("Removing key for pid: {}", pid);
                map.remove(&key)?;
            }
        }
    }
    Ok(())
}

fn pid_exists(pid: i32) -> bool {
    Path::new(&format!("/proc/{}", pid)).exists()
}

fn parse_ipv4_key(payload: &[u8]) -> io::Result<Ipv4Key> {
    if payload.len() < 20 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Payload too short",
        ));
    }

    let ihl_words = usize::from(payload[0] & 0x0f);
    if ihl_words < 5 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Invalid IPv4 header length",
        ));
    }

    let transport_offset = ihl_words * 4;
    if payload.len() < transport_offset + 4 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Payload shorter than IPv4 transport header",
        ));
    }

    let daddr = u32::from_be_bytes(payload[16..20].try_into().unwrap());
    let sport = u16::from_be_bytes(
        payload[transport_offset..transport_offset + 2]
            .try_into()
            .unwrap(),
    );
    let dport = u16::from_be_bytes(
        payload[transport_offset + 2..transport_offset + 4]
            .try_into()
            .unwrap(),
    );

    Ok(Ipv4Key {
        sport,
        daddr,
        dport,
    })
}

fn ensure_iptables(queue_num: u16) -> anyhow::Result<()> {
    match iptables_attached(queue_num)? {
        true => {
            debug!("iptables rule already exists for queue {}", queue_num);
            Ok(())
        }
        false => {
            attach_iptables(queue_num)?;
            Ok(())
        }
    }
}

fn iptables_attached(queue_num: u16) -> anyhow::Result<bool> {
    let ipt = iptables::new(false)
        .map_err(|e: Box<dyn Error>| anyhow::anyhow!("{}", e))
        .context("failed to open iptables")?;

    let rules = ipt
        .list("mangle", "OUTPUT")
        .map_err(|e: Box<dyn Error>| anyhow::anyhow!("{}", e))
        .context("failed to list iptables rules on mangle OUTPUT chain")?;

    let target_rule = format!(
        "-A OUTPUT -m addrtype ! --dst-type LOCAL -m conntrack --ctstate NEW,RELATED -j NFQUEUE --queue-num {} --queue-bypass",
        queue_num
    );

    for line in &rules {
        if line.trim() == target_rule {
            return Ok(true);
        }
    }

    Ok(false)
}

fn attach_iptables(queue_num: u16) -> anyhow::Result<()> {
    let ipt = iptables::new(false)
        .map_err(|e: Box<dyn Error>| anyhow::anyhow!("{}", e))
        .context("failed to open iptables")?;

    let rule = format!(
        "-m addrtype ! --dst-type LOCAL -m conntrack --ctstate NEW,RELATED -j NFQUEUE --queue-num {} --queue-bypass",
        queue_num
    );

    ipt.insert("mangle", "OUTPUT", &rule, 1)
        .map_err(|e: Box<dyn Error>| anyhow::anyhow!("{}", e))
        .context("failed to insert NFQUEUE rule into mangle output at position 1")?;

    info!(
        "Iptables output to netfilter queue {} is now set up",
        queue_num
    );

    Ok(())
}

fn attach_kprobes(ebpf: &mut Ebpf) -> anyhow::Result<()> {
    let tcpv4_kprobe: &mut KProbe = ebpf
        .program_mut("kprobe__tcp_v4_connect")
        .unwrap()
        .try_into()?;
    tcpv4_kprobe.load()?;
    tcpv4_kprobe.attach("tcp_v4_connect", 0)?;
    let tcpv4_kretprobe: &mut KProbe = ebpf
        .program_mut("kretprobe__tcp_v4_connect")
        .unwrap()
        .try_into()?;
    tcpv4_kretprobe.load()?;
    tcpv4_kretprobe.attach("tcp_v4_connect", 0)?;

    let udpv4_kprobe: &mut KProbe = ebpf
        .program_mut("kprobe__udp_sendmsg")
        .unwrap()
        .try_into()?;
    udpv4_kprobe.load()?;
    udpv4_kprobe.attach("udp_sendmsg", 0)?;

    let icmp_kprobe: &mut KProbe = ebpf
        .program_mut("kprobe__inet_dgram_connect")
        .unwrap()
        .try_into()?;
    icmp_kprobe.load()?;
    icmp_kprobe.attach("inet_dgram_connect", 0)?;
    let icmp_kretprobe: &mut KProbe = ebpf
        .program_mut("kretprobe__inet_dgram_connect")
        .unwrap()
        .try_into()?;
    icmp_kretprobe.load()?;
    icmp_kretprobe.attach("inet_dgram_connect", 0)?;

    let iptunnel_kprobe: &mut KProbe = ebpf
        .program_mut("kprobe__iptunnel_xmit")
        .unwrap()
        .try_into()?;
    iptunnel_kprobe.load()?;
    iptunnel_kprobe.attach("iptunnel_xmit", 0)?;

    debug!("Firewall kprobes attached");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::parse_ipv4_key;
    use std::io;

    #[test]
    fn parse_ipv4_key_reads_standard_ipv4_header() {
        let payload = [
            0x45, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x00, 0x40, 0x06, 0x00, 0x00, 0x0a, 0x00,
            0x00, 0x01, 0xc0, 0xa8, 0x01, 0x0a, 0x1f, 0x90, 0x01, 0xbb,
        ];

        let key = parse_ipv4_key(&payload).expect("parse standard ipv4 header");
        let sport = key.sport;
        let dport = key.dport;
        let daddr = key.daddr;
        assert_eq!(sport, 8080);
        assert_eq!(dport, 443);
        assert_eq!(daddr, u32::from_be_bytes([0xc0, 0xa8, 0x01, 0x0a]));
    }

    #[test]
    fn parse_ipv4_key_respects_ipv4_options_length() {
        let payload = [
            0x46, 0x00, 0x00, 0x2c, 0x00, 0x00, 0x00, 0x00, 0x40, 0x06, 0x00, 0x00, 0x0a, 0x00,
            0x00, 0x01, 0xc0, 0xa8, 0x01, 0x0a, 0x01, 0x02, 0x03, 0x04, 0x1f, 0x90, 0x01, 0xbb,
        ];

        let key = parse_ipv4_key(&payload).expect("parse ipv4 header with options");
        let sport = key.sport;
        let dport = key.dport;
        assert_eq!(sport, 8080);
        assert_eq!(dport, 443);
    }

    #[test]
    fn parse_ipv4_key_rejects_invalid_ihl() {
        let payload = [0x44; 24];
        assert!(matches!(
            parse_ipv4_key(&payload),
            Err(err) if err.kind() == io::ErrorKind::InvalidData
        ));
    }
}
