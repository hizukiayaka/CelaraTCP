/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * SPDX-FileCopyrightText: Hsia-Jun(Randy) Li
 */

#include <stddef.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define IP_MF	  0x2000
#define IP_OFFSET 0x1FFF

char LICENSE[] SEC("license") = "AGPLv3";

struct whitelist_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct whitelist_key);
    __type(value, int);
} whitelist SEC(".maps");

SEC("socket")
int socket_handler(struct __sk_buff *skb)
{
    __u32 proto;

    bpf_skb_load_bytes(skb, offsetof(struct __sk_buff, protocol), &proto, sizeof(__u32));
    proto = __bpf_ntohl(proto);

    if (proto != ETH_P_IP)
        return -1;

    return 0;
}

SEC("socket")
int drop_ipv6_packets(struct __sk_buff *skb)
{
    __u32 proto;

    bpf_skb_load_bytes(skb, offsetof(struct __sk_buff, protocol), &proto, sizeof(__u32));
    proto = __bpf_ntohl(proto);

    if (proto == ETH_P_IPV6)
        return -1; // Drop packet

    return 0; // Pass packet
}

SEC("socket")
int drop_ipv4_packets(struct __sk_buff *skb)
{
    __u32 proto;

    bpf_skb_load_bytes(skb, offsetof(struct __sk_buff, protocol), &proto, sizeof(__u32));
    proto = __bpf_ntohl(proto);

    if (proto == ETH_P_IP)
        return -1; // Drop packet

    return 0; // Pass packet
}

SEC("socket")
int filter_tcp_packets(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct iphdr *ip = data;
    struct tcphdr *tcp;

    // Ensure the IP header is within bounds
    if ((void *)ip + sizeof(*ip) > data_end)
        return -1; // Drop if IP header is out of bounds

    // Check if the protocol is TCP
    if (ip->protocol != IPPROTO_TCP)
        return -1; // Drop non-TCP packets

    // Calculate the TCP header position
    tcp = (void *)ip + (ip->ihl * 4);

    // Ensure the TCP header is within bounds
    if ((void *)tcp + sizeof(*tcp) > data_end)
        return -1; // Drop if TCP header is out of bounds

    // At this point, we know it's a TCP packet
    // ...additional filtering logic (e.g., whitelist checks) can go here...

    return 0; // Pass packet
}