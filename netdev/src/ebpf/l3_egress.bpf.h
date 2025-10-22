/*
 * SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
 * SPDX-FileCopyrightText: Hsia-Jun(Randy) Li
 */

#ifndef L3_EGRESS_BPF_H_
#define L3_EGRESS_BPF_H_

#include <linux/types.h>

struct filter_list_value
{
  __u8 drop_ipv4; // Drop IPv4 packets
  __u8 drop_ipv6; // Drop IPv6 packets
};

#endif
