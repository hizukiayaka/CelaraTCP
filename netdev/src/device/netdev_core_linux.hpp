/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * SPDX-FileCopyrightText: Hsia-Jun(Randy) Li
 */

#pragma once

extern "C"
{
#include <netlink/route/addr.h>
#include <netlink/route/link.h>
#include <netlink/route/neighbour.h>
#include <netlink/route/route.h>
#include <netlink/socket.h>
}

#include <array>
#include <optional>
#include <string_view>

#include <asio/ip/address.hpp>
#include <asio/ip/network_v4.hpp>
#include <asio/ip/network_v6.hpp>

#include "physical_netdev_base.hpp"

namespace celaratcp {
namespace netdev {

class NetDevCoreLinux
{
protected:
  struct nl_sock *sk_;
  struct rtnl_link *link_;

  int ifindex_;

protected:
  NetDevCoreLinux();
  NetDevCoreLinux(int ifindex);
  NetDevCoreLinux(std::string_view inf_name);

  bool Initialize(int ifindex);
  bool Initialize(std::string_view inf_name);

public:
  ~NetDevCoreLinux();

  std::string GetInterfaceName() const;

  int GetInterfaceIndex() const;

  int GetMtu() const;

  std::optional<asio::ip::address_v4> GetIPv4Address() const;

  std::optional<asio::ip::address_v6>
  GetIPv6Address(ipv6::AddressScope scope) const;

  std::array<uint8_t, ETH_ALEN> GetMacAddress() const;

  std::optional<std::array<uint8_t, ETH_ALEN> > GetGatewayMacAddress() const;

  std::error_code SetMtu(uint_fast16_t mtu);

  bool SetLocalIPv4Address(const asio::ip::address_v4 &addr,
                           uint_fast8_t prefix);
  bool SetLocalIPv6Address(const asio::ip::address_v6 &addr,
                           uint_fast8_t prefix);

  bool Up();
  bool Down();
};

} // namespace netdev
} // namespace celaratcp
