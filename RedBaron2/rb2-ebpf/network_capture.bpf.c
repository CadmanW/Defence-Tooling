// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

#define ETH_HLEN 14
#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD
#define ETH_P_VLAN 0x8100
#define ETH_P_QINQ 0x88A8
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define DNS_PORT 53

static __always_inline int payload_has_prefix(const unsigned char *payload,
                                              __u32 payload_len,
                                              const char *prefix,
                                              __u32 prefix_len) {
  return payload_len >= prefix_len &&
         __builtin_memcmp(payload, prefix, prefix_len) == 0;
}

static __always_inline int
skip_vlan_headers(struct __sk_buff *skb, __u16 *ether_type, __u32 *l3_offset) {
  if (*ether_type == ETH_P_VLAN || *ether_type == ETH_P_QINQ) {
    if (skb->len < *l3_offset + 4)
      return -1;
    if (bpf_skb_load_bytes(skb, *l3_offset + 2, ether_type,
                           sizeof(*ether_type)) < 0)
      return -1;

    *ether_type = bpf_ntohs(*ether_type);
    *l3_offset += 4;

    if (*ether_type == ETH_P_VLAN || *ether_type == ETH_P_QINQ) {
      if (skb->len < *l3_offset + 4)
        return -1;
      if (bpf_skb_load_bytes(skb, *l3_offset + 2, ether_type,
                             sizeof(*ether_type)) < 0)
        return -1;

      *ether_type = bpf_ntohs(*ether_type);
      *l3_offset += 4;
    }
  }

  return 0;
}

static __always_inline int keep_packet(struct __sk_buff *skb) {
  return skb->len;
}

static __always_inline int is_http_request_prefix(const unsigned char *payload,
                                                  __u32 payload_len) {
  if (payload_len < 4)
    return 0;

  switch (payload[0]) {
  case 'G':
    return payload_has_prefix(payload, payload_len, "GET ", 4);
  case 'P':
    return payload_has_prefix(payload, payload_len, "POST ", 5) ||
           payload_has_prefix(payload, payload_len, "PUT ", 4) ||
           payload_has_prefix(payload, payload_len, "PATCH ", 6);
  case 'D':
    return payload_has_prefix(payload, payload_len, "DELETE ", 7);
  case 'H':
    return payload_has_prefix(payload, payload_len, "HEAD ", 5);
  case 'O':
    return payload_has_prefix(payload, payload_len, "OPTIONS ", 8);
  case 'C':
    return payload_has_prefix(payload, payload_len, "CONNECT ", 8);
  case 'T':
    return payload_has_prefix(payload, payload_len, "TRACE ", 6);
  default:
    return 0;
  }
}

static __always_inline int handle_udp(struct __sk_buff *skb, __u32 l4_offset,
                                      __u32 packet_end) {
  struct udphdr udp = {};
  if (packet_end < l4_offset + sizeof(udp))
    return 0;
  if (bpf_skb_load_bytes(skb, l4_offset, &udp, sizeof(udp)) < 0)
    return 0;

  if (bpf_ntohs(udp.dest) == DNS_PORT)
    return keep_packet(skb);
  return 0;
}

static __always_inline int handle_tcp(struct __sk_buff *skb, __u32 l4_offset,
                                      __u32 packet_end) {
  struct tcphdr tcp = {};
  unsigned char payload[8] = {};
  __u32 payload_offset = 0;
  __u32 tcp_header_len = 0;

  if (packet_end < l4_offset + sizeof(tcp))
    return 0;
  if (bpf_skb_load_bytes(skb, l4_offset, &tcp, sizeof(tcp)) < 0)
    return 0;

  tcp_header_len = ((__u32)tcp.doff) * 4;
  if (tcp_header_len < sizeof(tcp))
    return 0;

  payload_offset = l4_offset + tcp_header_len;
  if (payload_offset >= packet_end)
    return 0;

  // Keep this read fixed-size so the verifier never sees a possible zero-length
  // helper call. Real HTTP request lines are longer than 8 bytes anyway.
  if (packet_end - payload_offset < sizeof(payload))
    return 0;
  if (bpf_skb_load_bytes(skb, payload_offset, payload, sizeof(payload)) < 0)
    return 0;

  if (is_http_request_prefix(payload, sizeof(payload)))
    return keep_packet(skb);

  return 0;
}

static __always_inline int handle_ipv4(struct __sk_buff *skb, __u32 l3_offset) {
  struct iphdr ip = {};
  __u16 frag_off = 0;
  __u32 packet_end = 0;
  __u32 l4_offset = 0;
  __u32 ihl = 0;

  if (skb->len < l3_offset + sizeof(ip))
    return 0;
  if (bpf_skb_load_bytes(skb, l3_offset, &ip, sizeof(ip)) < 0)
    return 0;

  ihl = ip.ihl * 4;
  if (ihl < sizeof(ip))
    return 0;

  frag_off = bpf_ntohs(ip.frag_off);
  if ((frag_off & 0x3fff) != 0)
    return 0;

  packet_end = l3_offset + bpf_ntohs(ip.tot_len);
  if (packet_end > skb->len || packet_end < l3_offset + ihl)
    return 0;

  l4_offset = l3_offset + ihl;
  if (ip.protocol == IPPROTO_UDP)
    return handle_udp(skb, l4_offset, packet_end);
  if (ip.protocol == IPPROTO_TCP)
    return handle_tcp(skb, l4_offset, packet_end);

  return 0;
}

static __always_inline int handle_ipv6(struct __sk_buff *skb, __u32 l3_offset) {
  struct ipv6hdr ip6 = {};
  __u32 packet_end = 0;
  __u32 l4_offset = l3_offset + sizeof(ip6);

  if (skb->len < l3_offset + sizeof(ip6))
    return 0;
  if (bpf_skb_load_bytes(skb, l3_offset, &ip6, sizeof(ip6)) < 0)
    return 0;

  packet_end = l4_offset + bpf_ntohs(ip6.payload_len);
  if (packet_end > skb->len || packet_end < l4_offset)
    return 0;

  if (ip6.nexthdr == IPPROTO_UDP)
    return handle_udp(skb, l4_offset, packet_end);
  if (ip6.nexthdr == IPPROTO_TCP)
    return handle_tcp(skb, l4_offset, packet_end);

  return 0;
}

SEC("socket")
int network_capture(struct __sk_buff *skb) {
  __u16 ether_type = 0;
  __u32 l3_offset = ETH_HLEN;

  if (skb->len < ETH_HLEN)
    return 0;
  if (bpf_skb_load_bytes(skb, 12, &ether_type, sizeof(ether_type)) < 0)
    return 0;

  ether_type = bpf_ntohs(ether_type);

  if (skip_vlan_headers(skb, &ether_type, &l3_offset) < 0)
    return 0;

  if (ether_type == ETH_P_IP)
    return handle_ipv4(skb, l3_offset);
  if (ether_type == ETH_P_IPV6)
    return handle_ipv6(skb, l3_offset);

  return 0;
}
