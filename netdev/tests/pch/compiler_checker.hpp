/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * SPDX-FileCopyrightText: Hsia-Jun(Randy) Li
 */

#include <algorithm>
#include <coroutine>
#include <forward_list>
#include <iomanip>
#include <iostream>
#include <list>
#include <optional>

#include <asio/awaitable.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/experimental/channel.hpp>
#include <asio/experimental/coro.hpp>
#include <asio/signal_set.hpp>
#include <asio/use_awaitable.hpp>

#include "net_packet.hpp"

#include "ethernet_netdev.hpp"
#include "net_filter_inf.hpp"
#include "virtual_netdev.hpp"
