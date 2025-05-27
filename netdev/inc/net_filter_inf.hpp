/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * SPDX-FileCopyrightText: Hsia-Jun(Randy) Li
 */

#ifndef __NET_FILTER_INF_HPP__
#define __NET_FILTER_INF_HPP__

namespace celaratcp {
namespace netdev {

enum class NetDevFiltertype
{
  DROP_IPV6,
  DROP_IPV4,
  DROP_UDP,
  DROP_TCP,
  REJECT_SOURCE_IP,
  ACCEPT_4_TUPLE,
};

class IPacketFilter
{
public:
  virtual ~IPacketFilter() = default;

  virtual std::list<NetDevFiltertype> getSupportFilterType() const = 0;
  virtual bool
  setNetDevFilterType([[maybe_unused]] std::list<NetDevFiltertype> types)
  {
    return false;
  }

  virtual bool
  addWatchIpv4Port([[maybe_unused]] uint16_t port)
  {
    return false;
  }
  virtual bool
  removeWatchIpv4Port([[maybe_unused]] uint16_t port)
  {
    return false;
  }
  virtual bool
  addWatchIpv6Port([[maybe_unused]] uint16_t port)
  {
    return false;
  }
  virtual bool
  removeWatchIpv6Port([[maybe_unused]] uint16_t port)
  {
    return false;
  }

  virtual bool
  addPeerNode([[maybe_unused]] const asio::ip::address &addr,
              [[maybe_unused]] uint16_t src_port,
              [[maybe_unused]] uint16_t dst_port)
  {
    return false;
  }
  virtual bool
  removePeerNode([[maybe_unused]] const asio::ip::address &addr,
                 [[maybe_unused]] uint16_t src_port,
                 [[maybe_unused]] uint16_t dst_port)
  {
    return false;
  }
};

} // namespace netdev

} // namespace celaratcp

#endif