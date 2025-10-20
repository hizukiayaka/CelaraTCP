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

enum class FilterAction
{
  DROP_IPV6,
  DROP_IPV4,
  DROP_UDP,
  DROP_TCP,
  REJECT_SOURCE_IP,
  ACCEPT_TCP_ONLY,
  ACCEPT_4_TUPLE,
  TCP_DPORT_FORWARD,
};

enum class FilterAttachPoint
{
  /* Network stack general points */
  XDP,        // XDP program (earliest point)
  TC_INGRESS, // TC hook ingress
  TC_EGRESS,  // TC hook egress

  /* Socket specific points */
  SOCK_RX, // Receiving on socket
  SOCK_TX, // Transmitting on socket

  /* TUN/TAP specific attach points */
  TUN_RX_KERNEL, // Filter packets from kernel to userspace
  // Queue management
  QUEUE_STEERING, // Steer packets between internal queues
};

class IPacketFilter
{
public:
  virtual ~IPacketFilter() = default;

  virtual std::list<FilterAction> GetSupportFilterActions() const = 0;

  virtual bool
  EnableFilters([[maybe_unused]] std::list<FilterAction> &types)
  {
    return false;
  }

  virtual void
  DisableFilter()
  {
    return;
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

  virtual bool
  AddWatchIpv4PortForward([[maybe_unused]] uint_fast16_t port,
                          [[maybe_unused]] uint_fast32_t ifindex)
  {
    return false;
  }

  virtual bool
  AddWatchIpv6PortForward([[maybe_unused]] uint_fast16_t port,
                          [[maybe_unused]] uint_fast32_t ifindex)
  {
    return false;
  }
};

class IFilterProvider
{
public:
  virtual ~IFilterProvider() = default;

  virtual std::list<FilterAttachPoint> GetSupportAttachPoint() const = 0;

  virtual IPacketFilter *AttachFilter(FilterAttachPoint point) = 0;

  virtual bool
  DetachFilter([[maybe_unused]] FilterAttachPoint point)
  {
    return false;
  }
};

} // namespace netdev
} // namespace celaratcp

#endif
