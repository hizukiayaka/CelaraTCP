/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * SPDX-FileCopyrightText: Hsia-Jun(Randy) Li
 */

#include <coroutine>
#include <forward_list>
#include <iostream>
#include <list>
#include <optional>

#include <asio.hpp>
#include <asio/awaitable.hpp>
#include <asio/experimental/channel.hpp>
#include <asio/experimental/coro.hpp>

#include "net_packet.hpp"

#include "ethernet_netdev.hpp"
#include "net_filter_inf.hpp"
#include "virtual_netdev.hpp"
