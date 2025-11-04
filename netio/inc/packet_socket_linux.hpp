/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * SPDX-FileCopyrightText: Hsia-Jun(Randy) Li
 */

#pragma once
#include <experimental/propagate_const>

#include <asio/any_io_executor.hpp>
#include <asio/awaitable.hpp>
#include <asio/posix/stream_descriptor.hpp>
#include <asio/use_awaitable.hpp>

#include "packet_socket_linux_impl.hpp"
#include "physical_netdev_base.hpp"

namespace celaratcp {
namespace netio {

class PacketSocketLinux
{
private:
  std::experimental::propagate_const<std::unique_ptr<PacketSocketLinuxImpl> >
      pImpl_;

  std::shared_ptr<netdev::PhysicalNetdevBase> netdev_;
  void CalculateTxBufSize();
public:
  PacketSocketLinux(asio::any_io_executor &ex,
                    std::shared_ptr<netdev::PhysicalNetdevBase> netdev);
};

} // namespace netio
} // namespace celaratcp
