use std::collections::{BTreeMap, BTreeSet};
use std::convert::TryInto;
use std::ffi::{CStr, CString};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
use std::sync::Arc;

use anyhow::{Context, anyhow};
use aya::programs::SocketFilter;
use aya::{Ebpf, EbpfLoader};
use log::{debug, info, warn};
use tokio::io::unix::AsyncFd;
use tokio::sync::watch;

use crate::config::yaml::NetworkingConfig;
use crate::ingest::SelfObservationFilter;

use super::parser::{PacketContext, ParseConfig, parse_frame};

const ETH_P_ALL: u16 = 0x0003;
const SOCKET_RCVBUF_BYTES: i32 = 1 << 20;

#[derive(Debug, Clone)]
pub struct CaptureInterface {
    pub name: String,
    pub index: u32,
    pub addresses: Vec<IpAddr>,
    flags: u32,
}

impl CaptureInterface {
    fn is_loopback(&self) -> bool {
        (self.flags & (libc::IFF_LOOPBACK as u32)) != 0
    }
}

#[derive(Debug, Default)]
struct InterfaceEntry {
    flags: u32,
    addresses: BTreeSet<IpAddr>,
}

struct AttachedSocket {
    fd: AsyncFd<OwnedFd>,
    _ebpf: Ebpf,
}

impl AttachedSocket {
    fn open(interface: &CaptureInterface) -> anyhow::Result<Self> {
        let fd = open_raw_socket(interface.index)
            .with_context(|| format!("failed to open raw socket for {}", interface.name))?;
        let ebpf = load_and_attach_socket_filter(&fd)
            .with_context(|| format!("failed to attach socket filter on {}", interface.name))?;

        Ok(Self {
            fd: AsyncFd::new(fd)?,
            _ebpf: ebpf,
        })
    }

    async fn recv_into(&self, buffer: &mut [u8]) -> io::Result<(usize, bool)> {
        loop {
            let mut guard = self.fd.readable().await?;
            let received = guard.try_io(|inner| recv_packet(inner.get_ref().as_raw_fd(), buffer));
            match received {
                Ok(result) => return result,
                Err(_would_block) => continue,
            }
        }
    }
}

pub fn select_interfaces(requested: &[String]) -> io::Result<Vec<CaptureInterface>> {
    let mut discovered = enumerate_interfaces()?;

    if requested.is_empty() {
        return Ok(discovered
            .into_values()
            .filter(|interface| !interface.is_loopback())
            .collect());
    }

    let mut selected = Vec::new();
    for name in requested {
        if let Some(interface) = discovered.remove(name) {
            selected.push(interface);
        } else {
            warn!(
                "networking interface '{}' was requested but not found",
                name
            );
        }
    }

    Ok(selected)
}

pub async fn run_interface(
    interface: CaptureInterface,
    cfg: NetworkingConfig,
    filter: Arc<SelfObservationFilter>,
    mut shutdown_rx: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let parse_config = ParseConfig {
        dns_enabled: cfg.dns_enabled,
        http_enabled: cfg.http_enabled,
        http_capture_inbound: cfg.http_capture_inbound,
    };
    let snaplen = usize::try_from(cfg.snaplen_bytes.min(65535))
        .unwrap_or(2048)
        .max(1);
    let attached = AttachedSocket::open(&interface)?;
    let context = PacketContext {
        interface_name: &interface.name,
        interface_addresses: &interface.addresses,
    };
    let mut buffer = vec![0u8; snaplen];

    info!(
        "network capture attached interface={} addresses={:?} snaplen_bytes={}",
        interface.name, interface.addresses, snaplen
    );

    loop {
        tokio::select! {
            changed = shutdown_rx.changed() => {
                if changed.is_err() || *shutdown_rx.borrow() {
                    debug!("network capture shutting down on {}", interface.name);
                    return Ok(());
                }
            }
            packet = attached.recv_into(&mut buffer) => {
                let (copied, truncated) = packet?;
                if copied == 0 {
                    continue;
                }

                if let Some(event) = parse_frame(&buffer[..copied], truncated, context, parse_config)
                    && !filter.should_ignore_network(&event) {
                        event.log();
                    }
            }
        }
    }
}

fn enumerate_interfaces() -> io::Result<BTreeMap<String, CaptureInterface>> {
    let mut addrs: *mut libc::ifaddrs = std::ptr::null_mut();
    let rc = unsafe { libc::getifaddrs(&mut addrs) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }

    let mut discovered: BTreeMap<String, InterfaceEntry> = BTreeMap::new();
    let mut cursor = addrs;

    while !cursor.is_null() {
        let ifa = unsafe { &*cursor };
        if !ifa.ifa_name.is_null() {
            let name = unsafe { CStr::from_ptr(ifa.ifa_name) }
                .to_string_lossy()
                .into_owned();
            let entry = discovered.entry(name).or_default();
            entry.flags = ifa.ifa_flags;
            if let Some(ip) = sockaddr_to_ip(ifa.ifa_addr) {
                entry.addresses.insert(ip);
            }
        }
        cursor = ifa.ifa_next;
    }

    unsafe { libc::freeifaddrs(addrs) };

    let mut interfaces = BTreeMap::new();
    for (name, entry) in discovered {
        let c_name = CString::new(name.as_str())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid interface name"))?;
        let index = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
        if index == 0 {
            continue;
        }
        interfaces.insert(
            name.clone(),
            CaptureInterface {
                name,
                index,
                addresses: entry.addresses.into_iter().collect(),
                flags: entry.flags,
            },
        );
    }

    Ok(interfaces)
}

fn sockaddr_to_ip(addr: *const libc::sockaddr) -> Option<IpAddr> {
    if addr.is_null() {
        return None;
    }

    match unsafe { (*addr).sa_family as i32 } {
        libc::AF_INET => {
            let addr = unsafe { &*(addr as *const libc::sockaddr_in) };
            Some(IpAddr::V4(Ipv4Addr::from(u32::from_be(
                addr.sin_addr.s_addr,
            ))))
        }
        libc::AF_INET6 => {
            let addr = unsafe { &*(addr as *const libc::sockaddr_in6) };
            Some(IpAddr::V6(Ipv6Addr::from(addr.sin6_addr.s6_addr)))
        }
        _ => None,
    }
}

fn open_raw_socket(ifindex: u32) -> io::Result<OwnedFd> {
    let protocol = i32::from(u16::to_be(ETH_P_ALL));
    let raw_fd = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            protocol,
        )
    };
    if raw_fd < 0 {
        return Err(io::Error::last_os_error());
    }

    let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };
    set_rcvbuf(fd.as_raw_fd())?;

    let bind_addr = libc::sockaddr_ll {
        sll_family: libc::AF_PACKET as u16,
        sll_protocol: u16::to_be(ETH_P_ALL),
        sll_ifindex: ifindex as i32,
        sll_hatype: 0,
        sll_pkttype: 0,
        sll_halen: 0,
        sll_addr: [0; 8],
    };

    let rc = unsafe {
        libc::bind(
            fd.as_raw_fd(),
            (&bind_addr as *const libc::sockaddr_ll).cast(),
            std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(fd)
}

fn set_rcvbuf(fd: i32) -> io::Result<()> {
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            (&SOCKET_RCVBUF_BYTES as *const i32).cast(),
            std::mem::size_of::<i32>() as libc::socklen_t,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn load_and_attach_socket_filter<T: AsFd>(fd: T) -> anyhow::Result<Ebpf> {
    let mut ebpf = EbpfLoader::new().load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/network_capture.bpf.o"
    )))?;

    let program: &mut SocketFilter = ebpf
        .program_mut("network_capture")
        .ok_or_else(|| anyhow!("network_capture program not found"))?
        .try_into()?;
    program.load()?;
    program.attach(fd)?;
    Ok(ebpf)
}

fn recv_packet(fd: i32, buffer: &mut [u8]) -> io::Result<(usize, bool)> {
    let received = unsafe {
        libc::recv(
            fd,
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            libc::MSG_TRUNC | libc::MSG_DONTWAIT,
        )
    };

    if received < 0 {
        return Err(io::Error::last_os_error());
    }

    let received = received as usize;
    let copied = received.min(buffer.len());
    Ok((copied, received > buffer.len()))
}
