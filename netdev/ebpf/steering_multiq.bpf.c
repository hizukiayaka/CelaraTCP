/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * SPDX-FileCopyrightText: Hsia-Jun(Randy) Li
 */

#include <stddef.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define IP_MF	  0x2000
#define IP_OFFSET 0x1FFF

char LICENSE[] SEC("license") = "AGPLv3";

SEC("socket")
int socket_handler(struct __sk_buff *skb)
{
    __u32 proto;
    
    bpf_skb_load_bytes(skb, offsetof(struct __sk_buff, protocol), &proto, sizeof(__u32));
    proto = __bpf_ntohl(proto);

    if (proto != ETH_P_IP)
        return 0;

}