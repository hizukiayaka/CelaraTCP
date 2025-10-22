/*
 * SPDX-License-Identifier: GPL-2.0-only
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
}