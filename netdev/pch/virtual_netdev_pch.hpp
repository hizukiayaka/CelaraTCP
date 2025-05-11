/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * SPDX-FileCopyrightText: Hsia-Jun(Randy) Li
 */

#include <forward_list>
#include <optional>

#include <asio.hpp>
#include <asio/spawn.hpp>
#include "net_packet.hpp"

#include "virtual_netdev.hpp"

#ifdef __linux__
#include <linux/if_tun.h>
#endif

#ifdef __gnu_linux__
#include <netlink/socket.h>
#include <netlink/route/route.h>
#include <netlink/route/addr.h>
#include <netlink/route/link.h>

#include <bpf/bpf.h>

#include "tun_gnu_linux_impl.hpp"
#endif