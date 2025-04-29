/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * SPDX-FileCopyrightText: Hsia-Jun(Randy) Li
 */

#ifndef TUN_GNU_LINUX_IMPL_HPP
#define TUN_GNU_LINUX_IMPL_HPP

namespace celaratcp {
namespace netdev {

class VirtualNetDev::TunGnuLinuxImpl
{
private:
  asio::posix::stream_descriptor stream_;

  struct nl_sock *sk_;
  struct rtnl_link *link_;
  int ifindex_;

  bool isMasterNode_;
  bool isClient_;
private:
  TunGnuLinuxImpl(asio::io_context &io_context, const std::string &intl_name);
  /* it would create a new queue */
  // TunGnuLinuxImpl (const TunGnuLinuxImpl &other);
public:
  ~TunGnuLinuxImpl();
  /* client peer */
  TunGnuLinuxImpl(asio::io_context &io_context, const std::string &intl_name,
                  const asio::ip::address_v4 &addr);

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

  // std::optional<TunGnuLinuxImpl> addNode(asio::ip::address_v4 &addr);

  bool up();
  bool down();

  std::list<NetDevFiltertype> getSupportFilterType() const
  {
    return std::list<NetDevFiltertype>{};
  }
  bool setNetDevFilterType(std::list<NetDevFiltertype> type)
  {
    return false;
  }
};

}
}

#endif