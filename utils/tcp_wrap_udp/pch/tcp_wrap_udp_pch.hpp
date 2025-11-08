/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * SPDX-FileCopyrightText: Hsia-Jun(Randy) Li
 */

#include <asio/awaitable.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/ip/udp.hpp>
#include <asio/experimental/concurrent_channel.hpp>
#include <asio/write.hpp>
#include <asio/signal_set.hpp>
#include <asio/redirect_error.hpp>

#include <condition_variable>
#include <cstdlib>
#include <getopt.h>
#include <iostream>
#include <string>
#include <thread>

#include <recycle/shared_pool.hpp>

#include "net_packet_allocator.hpp"
#include "userspace_tcp_stack_helper.hpp"
#include "virtual_netdev.hpp"
