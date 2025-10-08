/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * SPDX-FileCopyrightText: Hsia-Jun(Randy) Li
 */

#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "tun_egress.bpf.h"

char LICENSE[] SEC("license") = "GPL";

#define IPV6_EQ_U32x4(a32, b32) \
    ({ __u32 __diff = 0; \
       __diff |= ((a32)[0] ^ (b32)[0]); \
       __diff |= ((a32)[1] ^ (b32)[1]); \
       __diff |= ((a32)[2] ^ (b32)[2]); \
       __diff |= ((a32)[3] ^ (b32)[3]); \
       __diff == 0; })

struct
{
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct filter_list_value);
} filter_list SEC(".maps");

struct inner_map_v4
{
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, PER_SERVICE_MAX_CONNECTION);
  __uint(map_flags, BPF_F_INNER_MAP);
  __type(key, __u32);
  __type(value, struct peer_value_v4);
} peers_v4_inner_map SEC(".maps");

struct inner_map_v6
{
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, PER_SERVICE_MAX_CONNECTION);
  __uint(map_flags, BPF_F_INNER_MAP);
  __type(key, __u32);
  __type(value, struct peer_value_v6);
} peers_v6_inner_map SEC(".maps");

struct
{
  __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
  __uint(max_entries, 4);
  __type(key, __u16);
  __array(values, struct inner_map_v4);
} services_v4_list SEC(".maps");

struct
{
  __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
  __uint(max_entries, 4);
  __type(key, __u16);
  __array(values, struct inner_map_v6);
} services_v6_list SEC(".maps");


static int
drop_ipv4_or_v6(struct __sk_buff *skb, __u8 drop_ipv4)
{
  __u8 v1;
  bpf_skb_load_bytes(skb, 0, &v1, sizeof(__u8));
  __u8 ver = v1 >> 4;

  if (drop_ipv4 && ver == 4)
    return TC_ACT_SHOT; // Drop IPv4 packet

  if (!drop_ipv4 && ver == 6)
    return TC_ACT_SHOT; // Drop IPv6 packet

  return TC_ACT_OK; // Pass packet
}

static int
allow_only_tcp(struct __sk_buff *skb, __u8 drop_ipv4,
                   __u8 drop_ipv6)
{
  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;

  __u8 v1;
  bpf_skb_load_bytes(skb, 0, &v1, sizeof(__u8));
  __u8 ver = v1 >> 4;

  // Check for IPv4 or IPv6
  if (ver == 4) {
      // IPv4
      if (drop_ipv4)
        return TC_ACT_SHOT; // Drop IPv4 packet
      struct iphdr *ip = data;
      if ((void *)ip + sizeof(*ip) > data_end)
        return TC_ACT_SHOT; // Not enough room for IP header
      if (ip->protocol != IPPROTO_TCP)
        return TC_ACT_SHOT; // Not TCP

      struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
      if ((void *)tcp + sizeof(*tcp) > data_end)
        return TC_ACT_SHOT; // courrupted TCP header

      return TC_ACT_OK;
  } else if (ver == 6) {
      // IPv6
      if (drop_ipv6)
        return TC_ACT_SHOT; // Drop IPv6 packet
      struct ipv6hdr *ip6 = data;
      if ((void *)ip6 + sizeof(*ip6) > data_end)
        return TC_ACT_SHOT; // Not enough room for IPv6 header
      if (ip6->nexthdr != IPPROTO_TCP)
        return TC_ACT_SHOT; // Not TCP

      struct tcphdr *tcp = (void *)ip6 + sizeof(*ip6);
      if ((void *)tcp + sizeof(*tcp) > data_end)
        return TC_ACT_SHOT; // courrupted TCP header

      return TC_ACT_OK; // Pass packet
  }

  return TC_ACT_SHOT;
}

static int
filter_tcp_packets(struct __sk_buff *skb, __u8 drop_ipv4,
                   __u8 drop_ipv6)
{
  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;

  __u8 v1;
  bpf_skb_load_bytes(skb, 0, &v1, sizeof(__u8));
  __u8 ver = v1 >> 4;

  // Check for IPv4 or IPv6
  if (ver == 4) {
      // IPv4
      if (drop_ipv4)
        return TC_ACT_SHOT; // Drop IPv4 packet

      struct iphdr *ip = data;
      if ((void *)ip + sizeof(*ip) > data_end)
        return TC_ACT_SHOT; // Not enough room for IP header
      if (ip->protocol != IPPROTO_TCP)
        return TC_ACT_SHOT; // Not TCP

      struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
      if ((void *)tcp + sizeof(*tcp) > data_end)
        return TC_ACT_SHOT; // corrupted TCP header

      __u16 dst_port = bpf_ntohs(tcp->dest);

      void *inner_map = bpf_map_lookup_elem(&services_v4_list, &dst_port);
      if (!inner_map)
        return TC_ACT_SHOT; // No service for this dport

      // If SYN packet, skip further filtering (already checked above)
      if (tcp->syn && !tcp->ack)
        return TC_ACT_OK;

      __u32 src_ip = ip->saddr;
      __u16 src_port = bpf_ntohs(tcp->source);
      int found = 0;
#if 1
      for (__u32 i = 0; i < PER_SERVICE_MAX_CONNECTION; ++i) {
        struct peer_value_v4 *val = bpf_map_lookup_elem(inner_map, &i);
        if (!val)
          continue;
        if (val->src_ip == src_ip && val->src_port == src_port) {
          found = 1;
          break;
        }
      }
#endif
      if (!found)
        return TC_ACT_SHOT;
      return TC_ACT_OK; // Pass packet
  } else if (ver == 6) {
      // IPv6
      if (drop_ipv6)
        return TC_ACT_SHOT; // Drop IPv6 packet

      struct ipv6hdr *ip6 = data;
      if ((void *)ip6 + sizeof(*ip6) > data_end)
        return TC_ACT_SHOT; // Not enough room for IPv6 header
      if (ip6->nexthdr != IPPROTO_TCP)
        return TC_ACT_SHOT; // Not TCP

      struct tcphdr *tcp = (void *)ip6 + sizeof(*ip6);
      if ((void *)tcp + sizeof(*tcp) > data_end)
        return TC_ACT_SHOT; // courrupted TCP header

      __u16 dst_port = bpf_ntohs(tcp->dest);
      void *inner_map = bpf_map_lookup_elem(&services_v6_list, &dst_port);
      if (!inner_map)
        return TC_ACT_SHOT; // No service for this dport

      // If SYN packet, skip filtering
      if (tcp->syn && !tcp->ack)
        return TC_ACT_OK;

      int found = 0;
#if 0
      __u8 src_ip[16];
      __builtin_memcpy(src_ip, ip6->saddr.s6_addr, 16);
      __u16 src_port = bpf_ntohs(tcp->source);
      #pragma unroll
      for (__u32 i = 0; i < PER_SERVICE_MAX_CONNECTION; ++i) {
        struct peer_value_v6 *val = bpf_map_lookup_elem(inner_map, &i);
        if (!val)
          continue;
        if (__builtin_memcmp(val->src_ip, src_ip, 16) == 0 && val->src_port == src_port) {
          found = 1;
          break;
        }
      }
#endif
      if (!found)
        return TC_ACT_SHOT;

      return TC_ACT_OK; // Pass packet
  }

  return TC_ACT_OK; // Pass packet
}

SEC("tcx/egress")
int
egress_filter(struct __sk_buff *skb)
{
  struct filter_list_value *filter;
  int key = 0;

  filter = bpf_map_lookup_elem(&filter_list, &key);
  if (!filter)
    return TC_ACT_OK;

  if (filter->drop_ipv4 && filter->drop_ipv6) {
      return TC_ACT_SHOT;
  }

  if (filter->drop_nomatch_tcp) {
      return filter_tcp_packets(skb, filter->drop_ipv4, filter->drop_ipv6);
  } else if (filter->drop_non_tcp) {
      return allow_only_tcp(skb, filter->drop_ipv4, filter->drop_ipv6);
  } else if (filter->drop_ipv4) {
      return drop_ipv4_or_v6(skb, 1);
  } else if (filter->drop_ipv6) {
      return drop_ipv4_or_v6(skb, 0);
  }

  return TC_ACT_OK;
}
