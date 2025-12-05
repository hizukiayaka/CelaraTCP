/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * SPDX-FileCopyrightText: Hsia-Jun(Randy) Li
 */

extern "C"
{
#include <getopt.h>
}

#include <condition_variable>
#include <cstdlib>
#include <iostream>
#include <string>
#include <thread>

#include <asio/awaitable.hpp>
#include <asio/bind_executor.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/experimental/concurrent_channel.hpp>
#include <asio/ip/udp.hpp>
#include <asio/redirect_error.hpp>
#include <asio/signal_set.hpp>
#include <asio/strand.hpp>

#ifdef LOGGER_USE_SPDLOG
#include <spdlog/async.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>
#endif

#include "net_packet.hpp"

#include "ethernet_netdev.hpp"

#include "ebpf_tcp_service.hpp"
#include "packet_socket_linux.hpp"
#include "userspace_tcp_stack.hpp"
