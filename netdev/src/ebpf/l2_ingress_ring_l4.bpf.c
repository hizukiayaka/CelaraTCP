/*
 * SPDX-License-Identifier: GPL-2.0-only
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

#include "l2_ingress_ring_l4.bpf.h"

char LICENSE[] SEC("license") = "GPL";

struct inner_ring_buffer {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 28);
	__uint(key_size, 0);
	__uint(value_size, 0);
} inner_ring_buf_templ SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
	__uint(max_entries, MAX_TCP_WATCH_PORT_RESTRICTION);
	__type(key, __be16);
	__array(values, struct inner_ring_buffer);
} v4_tcp_map_dict SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
	__uint(max_entries, MAX_TCP_WATCH_PORT_RESTRICTION);
	__type(key, __be16);
	__array(values, struct inner_ring_buffer);
} v6_tcp_map_dict SEC(".maps");

static int commit_tcp_sample(struct __sk_buff *skb, void *ip_hdr,
			     struct tcphdr *tcp, __u32 is_ipv4)
{
	__be16 dst_port = tcp->dest;
	void *ring = NULL;

	if (is_ipv4) {
		ring = bpf_map_lookup_elem(&v4_tcp_map_dict, &dst_port);
	} else {
		ring = bpf_map_lookup_elem(&v6_tcp_map_dict, &dst_port);
	}

	if (ring) {
		struct capture_tcp_sample *info =
		    bpf_ringbuf_reserve(ring, sizeof(*info), 0);

		if (info) {
			if (is_ipv4) {
				struct iphdr *ip = ip_hdr;
				info->addr_h0 = ip->saddr;
				info->addr_h1 = 0;
				info->addr_l1 = 0;
				info->addr_l0 = 0;
			} else {
				struct ipv6hdr *ip6 = ip_hdr;
				info->addr_h0 = ip6->saddr.in6_u.u6_addr32[0];
				info->addr_h1 = ip6->saddr.in6_u.u6_addr32[1];
				info->addr_l1 = ip6->saddr.in6_u.u6_addr32[2];
				info->addr_l0 = ip6->saddr.in6_u.u6_addr32[3];
			}

			info->sport = tcp->source;
			info->seq = tcp->seq;
			info->ack_seq = tcp->ack_seq;

			void *data = (void *)(long)skb->data;
			__u32 payload_offset = ((void *)tcp) - data;

			/* offset should start from tcp */
			bpf_skb_load_bytes(skb, payload_offset + 12,
					   &(info->DORsFlags), sizeof(__be16));

			/* The actual offset we want */
			payload_offset += sizeof(*tcp);

			__u32 payload_size = skb->len;
			payload_size -= payload_offset;

			if (payload_size > MAX_TCP_PAYLOAD_SIZE) {
				payload_size = MAX_TCP_PAYLOAD_SIZE;
			} else if (payload_size == 0) {
				info->data_size = 0;
				bpf_ringbuf_submit(info, 0);
				/* We submit the TCP info to user, drop it from stack */
				return TC_ACT_SHOT;
			}

			info->data_size = payload_size;

			if (bpf_skb_load_bytes
			    (skb, payload_offset, &(info->l4_payload),
			     payload_size) == 0) {
				bpf_ringbuf_submit(info, 0);
			} else {
				bpf_ringbuf_discard(info, 0);
			}
		}
		/* Either we copy the data or no free space, we drop it */
		return TC_ACT_SHOT;
	}
	return TC_ACT_OK;
}

SEC("tcx/ingress")
int ingress_filter(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	struct ethhdr *eth = data;
	if ((void *)eth + sizeof(*eth) > data_end)
		/* Not enough data for Ethernet header */
		return TC_ACT_OK;

	// Check for IPv4 or IPv6
	if (eth->h_proto == bpf_htons(ETH_P_IP)) {
		// IPv4
		struct iphdr *ip = (void *)eth + sizeof(*eth);
		if ((void *)ip + sizeof(*ip) > data_end)
			/* Not enough room for IP header, ignore */
			return TC_ACT_OK;

		if (ip->protocol != IPPROTO_TCP)
			return TC_ACT_OK;	// Not TCP, ignore

		struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
		if ((void *)tcp + sizeof(*tcp) > data_end)
			return TC_ACT_SHOT;	// corrupted TCP header

		return commit_tcp_sample(skb, (void *)ip, tcp, 1);
	} else if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
		// IPv6
		struct ipv6hdr *ip6 = (void *)eth + sizeof(*eth);
		if ((void *)ip6 + sizeof(*ip6) > data_end)
			/* Not enough room for IPv6 header, ignore */
			return TC_ACT_OK;

		if (ip6->nexthdr != IPPROTO_TCP)
			return TC_ACT_OK;	// Not TCP, ignore

		struct tcphdr *tcp = (void *)ip6 + sizeof(*ip6);
		if ((void *)tcp + sizeof(*tcp) > data_end)
			return TC_ACT_SHOT;	// courrupted TCP header

		return commit_tcp_sample(skb, (void *)ip6, tcp, 0);
	}

	/* Pass packet, ignore */
	return TC_ACT_OK;
}
