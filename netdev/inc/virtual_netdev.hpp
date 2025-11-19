/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * SPDX-FileCopyrightText: Hsia-Jun(Randy) Li
 */

#ifndef _VIRTUAL_NETDEV_HPP_
#define _VIRTUAL_NETDEV_HPP_

#include <experimental/propagate_const>
#include <forward_list>
#include <memory>

#include <asio.hpp>
#include <asio/spawn.hpp>

#include "net_packet.hpp"

namespace celaratcp {
namespace netdev {

class VirtualNetDev
{
private:
#ifdef __gnu_linux__
  class TunGnuLinuxImpl;
  std::experimental::propagate_const<std::unique_ptr<TunGnuLinuxImpl> > pImpl_;
#endif

public:
  VirtualNetDev(asio::io_context &io_context, const std::string &intl_name,
                const asio::ip::address_v4 &addr);
  ~VirtualNetDev();

  template <typename MutableBufferSequence>
  void async_read(MutableBufferSequence &bufs, asio::yield_context yield);
  template <typename ConstBufferSequence>
  void async_write(ConstBufferSequence &bufs, asio::yield_context yield);

  void async_read(NetPacket &buf, asio::yield_context yield);
  void async_read(std::forward_list<std::shared_ptr<NetPacket> > packets,
                  asio::yield_context yield);

  void async_write(NetPacket &buf, asio::yield_context yield);
  void async_write(std::forward_list<std::shared_ptr<NetPacket> > packets,
                   asio::yield_context yield);

  bool up();
  bool down();
};

} // namespace netdev

} // namespace celaratcp

#endif // _VIRTUAL_NETDEV_HPP_