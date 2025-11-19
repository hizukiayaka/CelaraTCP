/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * SPDX-FileCopyrightText: Hsia-Jun(Randy) Li
 */

#include <linux/types.h>

#define PER_SERVICE_MAX_CONNECTION 5

struct filter_list_value
{
    __u8 drop_ipv4;        // Drop IPv4 packets
    __u8 drop_ipv6;        // Drop IPv6 packets
    __u8 drop_non_tcp;     // Drop non-TCP packets
    __u8 drop_nomatch_tcp; // Drop TCP packets with no matching service connection
};

struct peer_value_v4 {
  __u32 src_ip;
  __u16 src_port;
};

struct peer_value_v6 {
  __u8 src_ip[16];
  __u16 src_port;
};