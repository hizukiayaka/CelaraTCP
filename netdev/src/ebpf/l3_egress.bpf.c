/*
 * SPDX-License-Identifier: GPL-2.0-only
 * SPDX-FileCopyrightText: Hsia-Jun(Randy) Li
 */

#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "l3_egress.bpf.h"

char LICENSE[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct filter_list_value);
} filter_list SEC(".maps");

static int drop_ipv4_or_v6(struct __sk_buff *skb, __u8 drop_ipv4) {
	__u8 v1;
	bpf_skb_load_bytes(skb, 0, &v1, sizeof(__u8));
	__u8 ver = v1 >> 4;

	if (drop_ipv4 && ver == 4)
		return TC_ACT_SHOT; // Drop IPv4 packet

	if (!drop_ipv4 && ver == 6)
		return TC_ACT_SHOT; // Drop IPv6 packet

	return TC_ACT_OK; // Pass packet
}

static int allow_only_tcp(struct __sk_buff *skb, __u8 drop_ipv4,
                          __u8 drop_ipv6) {
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

SEC("tcx/egress")
int egress_filter(struct __sk_buff *skb) {
	struct filter_list_value *filter;
	int key = 0;

	filter = bpf_map_lookup_elem(&filter_list, &key);
	if (!filter)
		return TC_ACT_OK;

	if (filter->drop_ipv4 && filter->drop_ipv6) {
		return TC_ACT_SHOT;
	}

	return allow_only_tcp(skb, filter->drop_ipv4, filter->drop_ipv6);
}
