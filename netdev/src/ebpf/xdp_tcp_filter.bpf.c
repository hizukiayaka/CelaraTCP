/*
 * SPDX-License-Identifier: GPL-2.0-only
 * SPDX-FileCopyrightText: Hsia-Jun(Randy) Li
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

// Map 1: Destination TCP ports -> inner map FD (IPv4)
struct
{
  __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
  __uint(max_entries, 20);
  __type(key, __u16);
  __type(value, int); // FD of inner src_map
} port_map_v4 SEC(".maps");

// Map 1: Destination TCP ports -> inner map FD (IPv6)
struct
{
  __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
  __uint(max_entries, 20);
  __type(key, __u16);
  __type(value, int); // FD of inner src_map
} port_map_v6 SEC(".maps");

// src_key for IPv4
struct src_key_v4
{
  __u32 src_ip;
  __u16 src_port;
};

// src_key for IPv6
struct src_key_v6
{
  __u8 src_ip[16];
  __u16 src_port;
};

// src_map for IPv4
struct
{
  __uint(type, BPF_MAP_TYPE_XSKMAP);
  __uint(max_entries, 5);
  __type(key, struct src_key_v4);
  __type(value, int);
} src_map_v4 SEC(".maps");

// src_map for IPv6
struct
{
  __uint(type, BPF_MAP_TYPE_XSKMAP);
  __uint(max_entries, 5);
  __type(key, struct src_key_v6);
  __type(value, int);
} src_map_v6 SEC(".maps");

SEC("xdp")
int
xdp_tcp_filter(struct xdp_md *ctx)
{
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;

  // Parse Ethernet header
  struct ethhdr *eth = data;
  if ((void *)eth + sizeof(*eth) > data_end)
    return XDP_PASS; // Not enough room for Ethernet header

  __u16 h_proto = eth->h_proto;
  void *nh = (void *)eth + sizeof(*eth);

  // Check for IPv4 or IPv6
  if (h_proto == __bpf_htons(ETH_P_IP)) {
      // IPv4
      struct iphdr *ip = nh;
      if ((void *)ip + sizeof(*ip) > data_end)
        return XDP_PASS; // Not enough room for IP header
      if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS; // Not TCP

      struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
      if ((void *)tcp + sizeof(*tcp) > data_end)
        return XDP_DROP; // courrupted TCP header

      __u16 dst_port = __bpf_ntohs(tcp->dest);
      int *src_map_fd = bpf_map_lookup_elem(&port_map_v4, &dst_port);
      if (!src_map_fd)
        return XDP_PASS; // Destination port not found in port_map_v4

      struct src_key_v4 key = {
        .src_ip = ip->saddr,
        .src_port = tcp->source,
      };
      // Lookup in the inner src_map
      int *xdp_sock = bpf_map_lookup_elem((void *)(long)*src_map_fd, &key);
      if (xdp_sock)
        return bpf_redirect_map((void *)(long)*src_map_fd, *xdp_sock,
                                0); // Redirect to socket in src_map_v4

      // No src_ip/src_port match, redirect to fallback (all-zero key)
      struct src_key_v4 zero_key = {};
      int *first_sock
          = bpf_map_lookup_elem((void *)(long)*src_map_fd, &zero_key);
      if (first_sock)
        return bpf_redirect_map((void *)(long)*src_map_fd, *first_sock, 0);

      return XDP_DROP;
  } else if (h_proto == __bpf_htons(ETH_P_IPV6)) {
      // IPv6
      struct ipv6hdr *ip6 = nh;
      if ((void *)ip6 + sizeof(*ip6) > data_end)
        return XDP_PASS; // Not enough room for IPv6 header
      if (ip6->nexthdr != IPPROTO_TCP)
        return XDP_PASS; // Not TCP

      struct tcphdr *tcp = (void *)ip6 + sizeof(*ip6);
      if ((void *)tcp + sizeof(*tcp) > data_end)
        return XDP_DROP; // courrupted TCP header

      __u16 dst_port = __bpf_ntohs(tcp->dest);
      int *src_map_fd = bpf_map_lookup_elem(&port_map_v6, &dst_port);
      if (!src_map_fd)
        return XDP_PASS; // Destination port not found in port_map_v6

      struct src_key_v6 key = {};
      __builtin_memcpy(key.src_ip, ip6->saddr.s6_addr, 16);
      key.src_port = tcp->source;
      int *xdp_sock = bpf_map_lookup_elem((void *)(long)*src_map_fd, &key);
      if (xdp_sock)
        return bpf_redirect_map((void *)(long)*src_map_fd, *xdp_sock,
                                0); // Redirect to socket in src_map_v6
      // No src_ip/src_port match, redirect to fallback (all-zero key)
      struct src_key_v6 zero_key = {};
      int *first_sock
          = bpf_map_lookup_elem((void *)(long)*src_map_fd, &zero_key);

      if (first_sock)
        return bpf_redirect_map((void *)(long)*src_map_fd, *first_sock, 0);

      return XDP_DROP;
  } else {
      return XDP_PASS; // Not IPv4 or IPv6
    }

  return XDP_PASS; // Pass if no redirection is possible
}

char LICENSE[] SEC("license") = "GPL";