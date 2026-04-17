use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::model::{CommonFields, Direction, DnsEvent, HttpEvent, ParsedNetworkEvent};

const ETH_HEADER_LEN: usize = 14;
const ETH_P_IPV4: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86DD;
const ETH_P_VLAN: u16 = 0x8100;
const ETH_P_QINQ: u16 = 0x88A8;
const TCP_PROTOCOL: u8 = 6;
const UDP_PROTOCOL: u8 = 17;
const DNS_PORT: u16 = 53;
const DNS_MAX_POINTER_JUMPS: usize = 16;

#[derive(Debug, Clone, Copy)]
pub struct ParseConfig {
    pub dns_enabled: bool,
    pub http_enabled: bool,
    pub http_capture_inbound: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct PacketContext<'a> {
    pub interface_name: &'a str,
    pub interface_addresses: &'a [IpAddr],
}

#[derive(Debug, Clone, Copy)]
struct TransportView<'a> {
    src_ip: IpAddr,
    dst_ip: IpAddr,
    src_port: u16,
    dst_port: u16,
    payload: &'a [u8],
    transport: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DnsQuestion {
    query_name: String,
    query_type: u16,
    query_class: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HttpRequest {
    pub(crate) method: String,
    pub(crate) path: String,
    pub(crate) http_version: Option<String>,
    pub(crate) request_line: String,
    pub(crate) host: Option<String>,
}

pub fn parse_frame(
    frame: &[u8],
    truncated: bool,
    context: PacketContext<'_>,
    config: ParseConfig,
) -> Option<ParsedNetworkEvent> {
    let (l3_offset, ether_type) = parse_l3_offset(frame)?;
    let transport = match ether_type {
        ETH_P_IPV4 => parse_ipv4(frame, l3_offset)?,
        ETH_P_IPV6 => parse_ipv6(frame, l3_offset)?,
        _ => return None,
    };

    let direction = determine_direction(
        &transport.src_ip,
        &transport.dst_ip,
        context.interface_addresses,
    );

    if config.dns_enabled
        && transport.transport == "udp"
        && transport.dst_port == DNS_PORT
        && matches!(direction, Direction::Outbound)
        && let Some(question) = parse_dns_question(transport.payload)
    {
        return Some(ParsedNetworkEvent::Dns(DnsEvent {
            common: common_fields(&transport, context.interface_name, direction, truncated),
            query_name: question.query_name,
            query_type: dns_type_name(question.query_type),
            query_class: dns_class_name(question.query_class),
        }));
    }

    if config.http_enabled
        && transport.transport == "tcp"
        && (config.http_capture_inbound || matches!(direction, Direction::Outbound))
        && let Some(request) = parse_http_request_payload(transport.payload)
    {
        return Some(ParsedNetworkEvent::Http(HttpEvent {
            common: common_fields(&transport, context.interface_name, direction, truncated),
            method: request.method,
            host: request.host,
            path: request.path,
            http_version: request.http_version,
            request_line: request.request_line,
        }));
    }

    None
}

fn common_fields(
    transport: &TransportView<'_>,
    interface_name: &str,
    direction: Direction,
    truncated: bool,
) -> CommonFields {
    CommonFields {
        interface: interface_name.to_string(),
        src_ip: transport.src_ip.to_string(),
        src_port: transport.src_port,
        dst_ip: transport.dst_ip.to_string(),
        dst_port: transport.dst_port,
        transport: transport.transport,
        direction,
        truncated,
    }
}

fn parse_l3_offset(frame: &[u8]) -> Option<(usize, u16)> {
    if frame.len() < ETH_HEADER_LEN {
        return None;
    }

    let mut ether_type = u16::from_be_bytes([frame[12], frame[13]]);
    let mut offset = ETH_HEADER_LEN;

    for _ in 0..2 {
        if ether_type != ETH_P_VLAN && ether_type != ETH_P_QINQ {
            break;
        }
        if frame.len() < offset + 4 {
            return None;
        }
        ether_type = u16::from_be_bytes([frame[offset + 2], frame[offset + 3]]);
        offset += 4;
    }

    Some((offset, ether_type))
}

fn parse_ipv4(frame: &[u8], offset: usize) -> Option<TransportView<'_>> {
    if frame.len() < offset + 20 {
        return None;
    }

    let version = frame[offset] >> 4;
    if version != 4 {
        return None;
    }

    let ihl = usize::from(frame[offset] & 0x0f) * 4;
    if ihl < 20 || frame.len() < offset + ihl {
        return None;
    }

    let total_length = usize::from(u16::from_be_bytes([frame[offset + 2], frame[offset + 3]]));
    let packet_end = offset.checked_add(total_length)?.min(frame.len());
    if packet_end < offset + ihl {
        return None;
    }

    let fragment = u16::from_be_bytes([frame[offset + 6], frame[offset + 7]]);
    if (fragment & 0x3fff) != 0 {
        return None;
    }

    let protocol = frame[offset + 9];
    let src_ip = IpAddr::V4(Ipv4Addr::new(
        frame[offset + 12],
        frame[offset + 13],
        frame[offset + 14],
        frame[offset + 15],
    ));
    let dst_ip = IpAddr::V4(Ipv4Addr::new(
        frame[offset + 16],
        frame[offset + 17],
        frame[offset + 18],
        frame[offset + 19],
    ));

    parse_transport(frame, offset + ihl, packet_end, protocol, src_ip, dst_ip)
}

fn parse_ipv6(frame: &[u8], offset: usize) -> Option<TransportView<'_>> {
    if frame.len() < offset + 40 {
        return None;
    }

    let version = frame[offset] >> 4;
    if version != 6 {
        return None;
    }

    let payload_length = usize::from(u16::from_be_bytes([frame[offset + 4], frame[offset + 5]]));
    let packet_end = offset.checked_add(40 + payload_length)?.min(frame.len());
    if packet_end < offset + 40 {
        return None;
    }

    let protocol = frame[offset + 6];
    let src_ip = IpAddr::V6(Ipv6Addr::from(
        <[u8; 16]>::try_from(&frame[offset + 8..offset + 24]).ok()?,
    ));
    let dst_ip = IpAddr::V6(Ipv6Addr::from(
        <[u8; 16]>::try_from(&frame[offset + 24..offset + 40]).ok()?,
    ));

    parse_transport(frame, offset + 40, packet_end, protocol, src_ip, dst_ip)
}

fn parse_transport(
    frame: &[u8],
    offset: usize,
    packet_end: usize,
    protocol: u8,
    src_ip: IpAddr,
    dst_ip: IpAddr,
) -> Option<TransportView<'_>> {
    match protocol {
        UDP_PROTOCOL => {
            if packet_end < offset + 8 || frame.len() < offset + 8 {
                return None;
            }
            Some(TransportView {
                src_ip,
                dst_ip,
                src_port: u16::from_be_bytes([frame[offset], frame[offset + 1]]),
                dst_port: u16::from_be_bytes([frame[offset + 2], frame[offset + 3]]),
                payload: &frame[offset + 8..packet_end],
                transport: "udp",
            })
        }
        TCP_PROTOCOL => {
            if packet_end < offset + 20 || frame.len() < offset + 20 {
                return None;
            }
            let tcp_header_len = usize::from(frame[offset + 12] >> 4) * 4;
            if tcp_header_len < 20 || packet_end < offset + tcp_header_len {
                return None;
            }
            Some(TransportView {
                src_ip,
                dst_ip,
                src_port: u16::from_be_bytes([frame[offset], frame[offset + 1]]),
                dst_port: u16::from_be_bytes([frame[offset + 2], frame[offset + 3]]),
                payload: &frame[offset + tcp_header_len..packet_end],
                transport: "tcp",
            })
        }
        _ => None,
    }
}

pub(crate) fn determine_direction(
    src_ip: &IpAddr,
    dst_ip: &IpAddr,
    interface_addresses: &[IpAddr],
) -> Direction {
    let src_matches = interface_addresses.iter().any(|ip| ip == src_ip);
    let dst_matches = interface_addresses.iter().any(|ip| ip == dst_ip);

    match (src_matches, dst_matches) {
        (true, false) => Direction::Outbound,
        (false, true) => Direction::Inbound,
        _ => Direction::Unknown,
    }
}

fn parse_dns_question(payload: &[u8]) -> Option<DnsQuestion> {
    if payload.len() < 12 {
        return None;
    }

    let flags = u16::from_be_bytes([payload[2], payload[3]]);
    let is_response = (flags & 0x8000) != 0;
    if is_response {
        return None;
    }

    let question_count = u16::from_be_bytes([payload[4], payload[5]]);
    if question_count == 0 {
        return None;
    }

    let (query_name, next_offset) = parse_dns_name(payload, 12)?;
    if payload.len() < next_offset + 4 {
        return None;
    }

    Some(DnsQuestion {
        query_name,
        query_type: u16::from_be_bytes([payload[next_offset], payload[next_offset + 1]]),
        query_class: u16::from_be_bytes([payload[next_offset + 2], payload[next_offset + 3]]),
    })
}

fn parse_dns_name(payload: &[u8], mut offset: usize) -> Option<(String, usize)> {
    let mut labels = Vec::new();
    let mut next_offset = None;
    let mut jumps = 0usize;

    loop {
        let len = *payload.get(offset)? as usize;

        if len == 0 {
            if next_offset.is_none() {
                next_offset = Some(offset + 1);
            }
            break;
        }

        if (len & 0b1100_0000) == 0b1100_0000 {
            let second = usize::from(*payload.get(offset + 1)?);
            let pointer = ((len & 0b0011_1111) << 8) | second;
            if pointer >= payload.len() || jumps >= DNS_MAX_POINTER_JUMPS {
                return None;
            }
            if next_offset.is_none() {
                next_offset = Some(offset + 2);
            }
            offset = pointer;
            jumps += 1;
            continue;
        }

        if (len & 0b1100_0000) != 0 {
            return None;
        }

        offset += 1;
        let label = payload.get(offset..offset + len)?;
        labels.push(String::from_utf8_lossy(label).into_owned());
        offset += len;
    }

    let name = if labels.is_empty() {
        ".".to_string()
    } else {
        labels.join(".")
    };

    Some((name, next_offset.unwrap_or(offset)))
}

pub(crate) fn parse_http_request_payload(payload: &[u8]) -> Option<HttpRequest> {
    let first_line_end = payload
        .iter()
        .position(|&byte| byte == b'\n')
        .unwrap_or(payload.len());
    let request_line = trim_line_end(&payload[..first_line_end]);
    let request_line = std::str::from_utf8(request_line).ok()?.trim();
    if request_line.is_empty() {
        return None;
    }

    let mut parts = request_line.split_whitespace();
    let method = parts.next()?.to_string();
    let path = parts.next()?.to_string();
    let http_version = parts.next().map(str::to_string);

    if !is_http_method(&method) {
        return None;
    }

    let mut host = None;
    for raw_line in payload.split(|&byte| byte == b'\n').skip(1) {
        let line = trim_line_end(raw_line);
        if line.is_empty() {
            break;
        }
        if let Some(value) = strip_header_prefix(line, b"host:") {
            let value = std::str::from_utf8(value).ok()?.trim();
            if !value.is_empty() {
                host = Some(value.to_string());
                break;
            }
        }
    }

    if host.is_none() {
        host = host_from_absolute_path(&path);
    }

    Some(HttpRequest {
        method,
        path,
        http_version,
        request_line: request_line.to_string(),
        host,
    })
}

fn trim_line_end(line: &[u8]) -> &[u8] {
    line.strip_suffix(b"\r").unwrap_or(line)
}

fn strip_header_prefix<'a>(line: &'a [u8], prefix: &[u8]) -> Option<&'a [u8]> {
    if line.len() < prefix.len() {
        return None;
    }
    let (head, tail) = line.split_at(prefix.len());
    if head.eq_ignore_ascii_case(prefix) {
        Some(tail)
    } else {
        None
    }
}

fn host_from_absolute_path(path: &str) -> Option<String> {
    let rest = path
        .strip_prefix("http://")
        .or_else(|| path.strip_prefix("https://"))?;
    let host = rest.split('/').next()?.trim();
    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
}

fn is_http_method(method: &str) -> bool {
    matches!(
        method,
        "GET" | "POST" | "PUT" | "DELETE" | "HEAD" | "OPTIONS" | "PATCH" | "CONNECT" | "TRACE"
    )
}

fn dns_type_name(query_type: u16) -> String {
    match query_type {
        1 => "A".to_string(),
        2 => "NS".to_string(),
        5 => "CNAME".to_string(),
        6 => "SOA".to_string(),
        12 => "PTR".to_string(),
        15 => "MX".to_string(),
        16 => "TXT".to_string(),
        28 => "AAAA".to_string(),
        33 => "SRV".to_string(),
        255 => "ANY".to_string(),
        other => format!("TYPE{other}"),
    }
}

fn dns_class_name(query_class: u16) -> String {
    match query_class {
        1 => "IN".to_string(),
        3 => "CH".to_string(),
        4 => "HS".to_string(),
        255 => "ANY".to_string(),
        other => format!("CLASS{other}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOCAL_ADDRS: [IpAddr; 1] = [IpAddr::V4(Ipv4Addr::new(10, 0, 0, 10))];

    fn outbound_context() -> PacketContext<'static> {
        PacketContext {
            interface_name: "eth0",
            interface_addresses: &LOCAL_ADDRS,
        }
    }

    fn unknown_context() -> PacketContext<'static> {
        PacketContext {
            interface_name: "cni0",
            interface_addresses: &[],
        }
    }

    fn parse_config(http_capture_inbound: bool) -> ParseConfig {
        ParseConfig {
            dns_enabled: true,
            http_enabled: true,
            http_capture_inbound,
        }
    }

    fn ethernet_header(ethertype: u16) -> Vec<u8> {
        let mut out = vec![0u8; ETH_HEADER_LEN];
        out[12..14].copy_from_slice(&ethertype.to_be_bytes());
        out
    }

    fn build_ipv4_udp_packet(
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
        fragment: u16,
    ) -> Vec<u8> {
        let total_length = 20 + 8 + payload.len();
        let mut packet = ethernet_header(ETH_P_IPV4);
        let ip_offset = packet.len();
        packet.extend_from_slice(&[
            0x45,
            0,
            0,
            0,
            0,
            0,
            (fragment >> 8) as u8,
            fragment as u8,
            64,
            UDP_PROTOCOL,
            0,
            0,
            src_ip[0],
            src_ip[1],
            src_ip[2],
            src_ip[3],
            dst_ip[0],
            dst_ip[1],
            dst_ip[2],
            dst_ip[3],
        ]);
        packet[ip_offset + 2..ip_offset + 4].copy_from_slice(&(total_length as u16).to_be_bytes());
        packet.extend_from_slice(&src_port.to_be_bytes());
        packet.extend_from_slice(&dst_port.to_be_bytes());
        packet.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        packet.extend_from_slice(payload);
        packet
    }

    fn build_ipv4_tcp_packet(
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
        fragment: u16,
    ) -> Vec<u8> {
        let total_length = 20 + 20 + payload.len();
        let mut packet = ethernet_header(ETH_P_IPV4);
        let ip_offset = packet.len();
        packet.extend_from_slice(&[
            0x45,
            0,
            0,
            0,
            0,
            0,
            (fragment >> 8) as u8,
            fragment as u8,
            64,
            TCP_PROTOCOL,
            0,
            0,
            src_ip[0],
            src_ip[1],
            src_ip[2],
            src_ip[3],
            dst_ip[0],
            dst_ip[1],
            dst_ip[2],
            dst_ip[3],
        ]);
        packet[ip_offset + 2..ip_offset + 4].copy_from_slice(&(total_length as u16).to_be_bytes());
        packet.extend_from_slice(&src_port.to_be_bytes());
        packet.extend_from_slice(&dst_port.to_be_bytes());
        packet.extend_from_slice(&0u32.to_be_bytes());
        packet.extend_from_slice(&0u32.to_be_bytes());
        packet.push(5 << 4);
        packet.push(0);
        packet.extend_from_slice(&0u16.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        packet.extend_from_slice(payload);
        packet
    }

    fn sample_dns_query() -> Vec<u8> {
        let mut query = Vec::new();
        query.extend_from_slice(&0x1234u16.to_be_bytes());
        query.extend_from_slice(&0x0100u16.to_be_bytes());
        query.extend_from_slice(&1u16.to_be_bytes());
        query.extend_from_slice(&0u16.to_be_bytes());
        query.extend_from_slice(&0u16.to_be_bytes());
        query.extend_from_slice(&0u16.to_be_bytes());
        query.extend_from_slice(&[
            3, b'w', b'w', b'w', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm',
            0,
        ]);
        query.extend_from_slice(&1u16.to_be_bytes());
        query.extend_from_slice(&1u16.to_be_bytes());
        query
    }

    #[test]
    fn determines_direction_from_interface_addresses() {
        let direction = determine_direction(
            &IpAddr::V4(Ipv4Addr::new(10, 0, 0, 10)),
            &IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            &[IpAddr::V4(Ipv4Addr::new(10, 0, 0, 10))],
        );
        assert_eq!(direction, Direction::Outbound);
    }

    #[test]
    fn parses_outbound_dns_query() {
        let frame = build_ipv4_udp_packet(
            [10, 0, 0, 10],
            [1, 1, 1, 1],
            53000,
            53,
            &sample_dns_query(),
            0,
        );

        let parsed =
            parse_frame(&frame, false, outbound_context(), parse_config(false)).expect("dns event");

        match parsed {
            ParsedNetworkEvent::Dns(event) => {
                assert_eq!(event.common.direction, Direction::Outbound);
                assert_eq!(event.query_name, "www.example.com");
                assert_eq!(event.query_type, "A");
                assert_eq!(event.query_class, "IN");
            }
            other => panic!("expected dns event, got {other:?}"),
        }
    }

    #[test]
    fn skips_inbound_dns_queries() {
        let frame = build_ipv4_udp_packet(
            [9, 9, 9, 9],
            [10, 0, 0, 10],
            53000,
            53,
            &sample_dns_query(),
            0,
        );

        assert!(parse_frame(&frame, false, outbound_context(), parse_config(false)).is_none());
    }

    #[test]
    fn skips_unknown_direction_dns_queries() {
        let frame = build_ipv4_udp_packet(
            [10, 0, 0, 10],
            [1, 1, 1, 1],
            53000,
            53,
            &sample_dns_query(),
            0,
        );

        assert!(parse_frame(&frame, false, unknown_context(), parse_config(false)).is_none());
    }

    #[test]
    fn parses_outbound_http_request() {
        let payload = b"GET /hello HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let frame =
            build_ipv4_tcp_packet([10, 0, 0, 10], [93, 184, 216, 34], 44000, 8080, payload, 0);

        let parsed = parse_frame(&frame, false, outbound_context(), parse_config(false))
            .expect("http event");

        match parsed {
            ParsedNetworkEvent::Http(event) => {
                assert_eq!(event.common.direction, Direction::Outbound);
                assert_eq!(event.method, "GET");
                assert_eq!(event.path, "/hello");
                assert_eq!(event.host.as_deref(), Some("example.com"));
                assert_eq!(event.http_version.as_deref(), Some("HTTP/1.1"));
                assert_eq!(event.request_line, "GET /hello HTTP/1.1");
            }
            other => panic!("expected http event, got {other:?}"),
        }
    }

    #[test]
    fn drops_inbound_http_when_disabled() {
        let payload = b"GET /hello HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let frame =
            build_ipv4_tcp_packet([93, 184, 216, 34], [10, 0, 0, 10], 8080, 44000, payload, 0);

        assert!(parse_frame(&frame, false, outbound_context(), parse_config(false)).is_none());
        assert!(parse_frame(&frame, false, outbound_context(), parse_config(true)).is_some());
    }

    #[test]
    fn skips_unknown_direction_http_when_inbound_capture_disabled() {
        let payload = b"GET /hello HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let frame =
            build_ipv4_tcp_packet([10, 0, 0, 10], [93, 184, 216, 34], 44000, 8080, payload, 0);

        assert!(parse_frame(&frame, false, unknown_context(), parse_config(false)).is_none());
        assert!(parse_frame(&frame, false, unknown_context(), parse_config(true)).is_some());
    }

    #[test]
    fn drops_fragmented_ipv4_requests() {
        let dns_frame = build_ipv4_udp_packet(
            [10, 0, 0, 10],
            [1, 1, 1, 1],
            53000,
            53,
            &sample_dns_query(),
            0x2000,
        );
        let http_frame = build_ipv4_tcp_packet(
            [10, 0, 0, 10],
            [93, 184, 216, 34],
            44000,
            8080,
            b"GET /hello HTTP/1.1\r\nHost: example.com\r\n\r\n",
            0x2000,
        );

        assert!(parse_frame(&dns_frame, false, outbound_context(), parse_config(false)).is_none());
        assert!(parse_frame(&http_frame, false, outbound_context(), parse_config(false)).is_none());
    }

    #[test]
    fn preserves_truncation_flag_on_http_events() {
        let payload = b"GET /partial HTTP/1.1";
        let frame =
            build_ipv4_tcp_packet([10, 0, 0, 10], [93, 184, 216, 34], 44000, 80, payload, 0);

        let parsed =
            parse_frame(&frame, true, outbound_context(), parse_config(false)).expect("http event");

        match parsed {
            ParsedNetworkEvent::Http(event) => assert!(event.common.truncated),
            other => panic!("expected http event, got {other:?}"),
        }
    }

    #[test]
    fn parses_dns_question_with_compression_pointer() {
        let mut query = Vec::new();
        query.extend_from_slice(&0x1234u16.to_be_bytes());
        query.extend_from_slice(&0x0100u16.to_be_bytes());
        query.extend_from_slice(&1u16.to_be_bytes());
        query.extend_from_slice(&0u16.to_be_bytes());
        query.extend_from_slice(&0u16.to_be_bytes());
        query.extend_from_slice(&1u16.to_be_bytes());
        query.extend_from_slice(&[3, b'w', b'w', b'w', 0xc0, 0x16]);
        query.extend_from_slice(&1u16.to_be_bytes());
        query.extend_from_slice(&1u16.to_be_bytes());
        query.extend_from_slice(&[
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
        ]);

        let frame = build_ipv4_udp_packet([10, 0, 0, 10], [1, 1, 1, 1], 53000, 53, &query, 0);
        let parsed =
            parse_frame(&frame, false, outbound_context(), parse_config(false)).expect("dns event");

        match parsed {
            ParsedNetworkEvent::Dns(event) => assert_eq!(event.query_name, "www.example.com"),
            other => panic!("expected dns event, got {other:?}"),
        }
    }
}
