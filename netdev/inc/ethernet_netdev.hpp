/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * SPDX-FileCopyrightText: Hsia-Jun(Randy) Li
 */

#ifndef ETHERNET_NETDEV_HPP_
#define ETHERNET_NETDEV_HPP_

#include <experimental/propagate_const>

#include "physical_netdev_base.hpp"

namespace celaratcp {
namespace netdev {

class EthernetNetdev : public PhysicalNetdevBase, public IFilterProvider
{
private:
#ifdef __gnu_linux__
  class EthernetNetdevLinux;
  std::experimental::propagate_const<std::unique_ptr<EthernetNetdevLinux> >
      pImpl_;
#endif
public:
  EthernetNetdev(std::string_view inf_name);
  ~EthernetNetdev() override;

  std::string GetInterfaceName() const override;

  int GetInterfaceIndex() const override;

  std::optional<asio::ip::address_v4> GetIPv4Address() const override;

  std::optional<asio::ip::address_v6> GetIPv6Address() const override;

  std::array<uint8_t, ETH_ALEN> GetMacAddress() const override;

  std::optional<std::array<uint8_t, ETH_ALEN> >
  GetGatewayMacAddress() const override;

  bool
  HasDirectGatewayMac() const override
  {
    return false;
  }

  bool
  IsSuitableForAfPacket() const override
  {
    return true;
  }

  std::list<FilterAttachPoint> GetSupportAttachPoint() const override;
  IPacketFilter *AttachFilter(FilterAttachPoint point) override;
};

} // namespace netdev
} // namespace celaratcp

#endif
