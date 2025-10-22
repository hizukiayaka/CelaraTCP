/*
 * SPDX-License-Identifier: GPL-2.0-only
 * SPDX-FileCopyrightText: Hsia-Jun(Randy) Li
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int
xdp_syn_ack(struct xdp_md *ctx)
{
  // Get pointers to the start of the packet data
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;

  // Parse Ethernet header
  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end) {
      return XDP_PASS;
  }

  // Check if the packet is an IPv4 packet
  if (eth->h_proto != __constant_htons(ETH_P_IP)) {
      return XDP_PASS;
  }

  // Parse IP header
  struct iphdr *ip = (void *)(eth + 1);
  if ((void *)(ip + 1) > data_end) {
      return XDP_PASS;
  }

  // Check if the packet is a TCP packet
  if (ip->protocol != IPPROTO_TCP) {
      return XDP_PASS;
  }

  // Parse TCP header
  struct tcphdr *tcp = (void *)((void *)ip + (ip->ihl * 4));
  if ((void *)(tcp + 1) > data_end) {
      return XDP_PASS;
  }

  __u16 dst_port = __bpf_ntohs(tcp->dest);
  // if (dst_port != 51001) {
  if (dst_port != 43155) {
      return XDP_PASS; // Not HTTP traffic
  }

  // Check if the packet is a SYN packet
  if (tcp->syn && !tcp->ack) {
      // Validate TCP header before accessing it
      if ((void *)(tcp + 1) > data_end) {
          return XDP_PASS;
      }

      // Validate IP header before accessing it
      if ((void *)(ip + 1) > data_end) {
          return XDP_PASS;
      }

      // Swap source and destination MAC addresses
      __u8 tmp_mac[ETH_ALEN];
      __builtin_memcpy(tmp_mac, eth->h_source, ETH_ALEN);
      __builtin_memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
      __builtin_memcpy(eth->h_dest, tmp_mac, ETH_ALEN);

#if 1
      __bpf_vprintk("Incoming src IP: %u.%u.%u.%u\n",
                    sizeof("Incoming src IP: %u.%u.%u.%u\n"),
                    (ip->saddr & 0xFF), (ip->saddr >> 8) & 0xFF,
                    (ip->saddr >> 16) & 0xFF, (ip->saddr >> 24) & 0xFF);
#endif

      // Swap source and destination IP addresses
      __u32 tmp_ip = ip->saddr;
      ip->saddr = ip->daddr;
      ip->daddr = tmp_ip;

      // Swap source and destination TCP ports
      __u16 tmp_port = tcp->source;
      tcp->source = tcp->dest;
      tcp->dest = tmp_port;

      // Set the TCP flags to ACK
      tcp->ack = 1;
      tcp->syn = 0;
      tcp->psh = 0;
      tcp->fin = 0;
      tcp->rst = 0;

      // Update the TCP sequence and acknowledgment numbers
      tcp->ack_seq = __constant_htonl(__constant_ntohl(tcp->seq) + 1);
      tcp->seq = 0;

      // Recalculate TCP checksum
      tcp->check = 0;
      __u32 csum = bpf_csum_diff(0, 0, (__be32 *)tcp, sizeof(*tcp), 0);
      tcp->check = bpf_csum_diff((__be32 *)&ip->saddr, 4, (__be32 *)&ip->daddr,
                                 4, csum);

      // Redirect the packet back to the sender
      return XDP_TX;
  }

  return XDP_PASS; // Pass the packet to the network stack
}

char _license[] SEC("license") = "GPL";