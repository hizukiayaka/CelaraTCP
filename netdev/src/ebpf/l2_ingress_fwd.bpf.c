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

#define MAX_TCP_WATCH_PORT_RESTRICTION (20)

char LICENSE[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_TCP_WATCH_PORT_RESTRICTION);
	__type(key, __u16);
	__type(value, __u32);
} v4_tcp_fwd_dict SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_TCP_WATCH_PORT_RESTRICTION);
	__type(key, __u16);
	__type(value, __u32);
} v6_tcp_fwd_dict SEC(".maps");

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

		__u16 dst_port = bpf_ntohs(tcp->dest);
		__u32 *ifindex =
		    bpf_map_lookup_elem(&v4_tcp_fwd_dict, &dst_port);

		if (ifindex)
			return bpf_redirect(*ifindex, BPF_F_INGRESS);

		return TC_ACT_OK;	// Pass packet, ignore
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

		__u16 dst_port = bpf_ntohs(tcp->dest);
		__u32 *ifindex =
		    bpf_map_lookup_elem(&v6_tcp_fwd_dict, &dst_port);

		if (ifindex)
			return bpf_redirect(*ifindex, BPF_F_INGRESS);

		/* Pass packet, ignore */
		return TC_ACT_OK;
	}

	/* Pass packet, ignore */
	return TC_ACT_OK;
}
