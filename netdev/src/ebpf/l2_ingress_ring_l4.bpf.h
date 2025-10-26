/*
 * SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
 * SPDX-FileCopyrightText: Hsia-Jun(Randy) Li
 */

#ifndef L2_INGRESS_RING_L4_BPF_H_
#define L2_INGRESS_RING_L4_BPF_H_

#include <linux/types.h>

#define MAX_TCP_WATCH_PORT_RESTRICTION (5)
#define MAX_TCP_PAYLOAD_SIZE (1460)

struct capture_tcp_sample {
	__be32 addr_h0;
	__be32 addr_h1;
	__be32 addr_l1;
	__be32 addr_l0;
	__be16 sport;
	__u16 data_size;
	__be32 seq;
	__be32 ack_seq;
	/**
	 * copy from offset 12
	 * DOffset | Rsrvd | Flags
	 */
	__be16 DORsFlags;
	__u8 l4_payload[MAX_TCP_PAYLOAD_SIZE];
} __attribute__((aligned(8)));

#endif
