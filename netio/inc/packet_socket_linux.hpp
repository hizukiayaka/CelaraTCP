/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * SPDX-FileCopyrightText: Hsia-Jun(Randy) Li
 */

#pragma once
#include <experimental/propagate_const>

#include <asio/any_io_executor.hpp>
#include <asio/awaitable.hpp>
#include <asio/use_awaitable.hpp>

#include "net_packet.hpp"

namespace celaratcp {

namespace netdev {
class PhysicalNetdevBase;
} // namespace netdev

namespace memmanager {
template <typename Value>
class AFPacketTxRingAsyncBase;
} // namespace memmanager

namespace netio {
class PacketSocketLinuxImpl;

class PacketSocketLinux
{
private:
  asio::any_io_executor ex_;
  std::experimental::propagate_const<std::unique_ptr<PacketSocketLinuxImpl> >
      pImpl_;

  std::shared_ptr<netdev::PhysicalNetdevBase> netdev_;
  const bool is_ipv6_;
  const bool user_fill_l2_;

  std::experimental::propagate_const<
      std::unique_ptr<memmanager::AFPacketTxRingAsyncBase<NetMemChunk> > >
      tx_pool_;

public:
  PacketSocketLinux(asio::any_io_executor ex,
                    std::shared_ptr<netdev::PhysicalNetdevBase> netdev,
                    bool is_ipv6, bool user_fill_l2);

  ~PacketSocketLinux();

  bool SetupTxPool() noexcept;

  asio::awaitable<std::shared_ptr<NetMemChunk> > Allocate() noexcept;
};

} // namespace netio
} // namespace celaratcp
