/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * SPDX-FileCopyrightText: Hsia-Jun(Randy) Li
 */

#include <net_packet.hpp>
#include <worker_interface.hpp>

#include "tun_gnu_linux_impl.hpp"
#include "userspace_tcp_stack_helper.hpp"

int
main(int argc, char *argv[])
{
  asio::io_context ioc;

  asio::ip::network_v4 net1(asio::ip::make_address_v4("169.254.3.1"), 32);
  celaratcp::netdev::TunGnuLinuxImpl tun(ioc, "test0", net1.address());

  celaratcp::SyncUserspaceTcpStack<asio::ip::address_v4> tcpStack;

  ioc.run();

  return 0;
}