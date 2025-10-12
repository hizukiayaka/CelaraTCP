/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * SPDX-FileCopyrightText: Hsia-Jun(Randy) Li
 */

#include <linux/types.h>

struct filter_list_value
{
  __u8 drop_ipv4; // Drop IPv4 packets
  __u8 drop_ipv6; // Drop IPv6 packets
};
