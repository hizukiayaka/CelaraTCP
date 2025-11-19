/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * SPDX-FileCopyrightText: Hsia-Jun(Randy) Li
 */

#ifndef NET_FILTER_INF_HPP_
#define NET_FILTER_INF_HPP_

#include <cstdint>
#include <list>

#include <asio/ip/address.hpp>

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

  virtual std::list<NetDevFiltertype> GetSupportFilterType() const = 0;

  virtual bool
  LoadFilter()
  {
    return false;
  }

  virtual bool
  SetNetDevFilterType([[maybe_unused]] std::list<NetDevFiltertype> types)
  {
    return false;
  }

  virtual bool
  AddWatchIpv4Port([[maybe_unused]] uint16_t port)
  {
    return false;
  }

  virtual bool
  RemoveWatchIpv4Port([[maybe_unused]] uint16_t port)
  {
    return false;
  }

  virtual bool
  AddWatchIpv6Port([[maybe_unused]] uint16_t port)
  {
    return false;
  }

  virtual bool
  RemoveWatchIpv6Port([[maybe_unused]] uint16_t port)
  {
    return false;
  }

  virtual bool
  AddPeerNode([[maybe_unused]] const asio::ip::address &addr,
              [[maybe_unused]] uint16_t src_port,
              [[maybe_unused]] uint16_t dst_port)
  {
    return false;
  }

  virtual bool
  RemovePeerNode([[maybe_unused]] const asio::ip::address &addr,
                 [[maybe_unused]] uint16_t src_port,
                 [[maybe_unused]] uint16_t dst_port)
  {
    return false;
  }
};

} // namespace netdev
} // namespace celaratcp

#endif
