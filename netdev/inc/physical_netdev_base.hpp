/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * SPDX-FileCopyrightText: Hsia-Jun(Randy) Li
 */

#ifndef PHYSICAL_NETDEV_BASE_HPP_
#define PHYSICAL_NETDEV_BASE_HPP_

extern "C"
{
#include <linux/if_ether.h>
}

#include <array>
#include <memory>
#include <optional>
#include <string>

#include <asio/ip/address.hpp>

#include "net_filter_inf.hpp"

namespace celaratcp {
namespace netdev {

class PhysicalNetdevBase
{
public:
  virtual ~PhysicalNetdevBase() = default;

  // Get interface name (eth0, ppp0, etc)
  virtual std::string GetInterfaceName() const = 0;

  // Get interface index
  virtual int GetInterfaceIndex() const = 0;

  // Get interface IPv4/IPv6 addresses
  virtual std::optional<asio::ip::address_v4> GetIPv4Address() const = 0;
  virtual std::optional<asio::ip::address_v6> GetIPv6Address() const = 0;

  // Get interface MAC address
  virtual std::array<uint8_t, ETH_ALEN> GetMacAddress() const = 0;

  // Get gateway/peer MAC address if available
  virtual std::optional<std::array<uint8_t, ETH_ALEN> >
  GetGatewayMacAddress() const = 0;

  // Check if gateway MAC is directly available
  virtual bool HasDirectGatewayMac() const = 0;

  // For AF_PACKET usage
  virtual bool IsSuitableForAfPacket() const = 0;
};

#if 0
// Derived interface-specific classes
class EthernetInterface : public PhysicalNetworkInterface
{
  // Standard Ethernet (eth0, en0, etc.)
  bool
  HasDirectGatewayMac() const override
  {
    return false;
  } // Requires ARP lookup
  bool
  IsSuitableForAfPacket() const override
  {
    return true;
  }
};

class PPPoEInterface : public PhysicalNetworkInterface
{
  // PPPoE tunnel interface
  bool
  HasDirectGatewayMac() const override
  {
    return true;
  } // PPPoE has peer MAC
  bool
  IsSuitableForAfPacket() const override
  {
    return false;
  } // Not suitable for direct AF_PACKET
};

class IPvEInterface : public PhysicalNetworkInterface
{
  // IPoE interface
  bool
  HasDirectGatewayMac() const override
  {
    return true;
  } // Has gateway MAC
  bool
  IsSuitableForAfPacket() const override
  {
    return true;
  }
};

class VlanInterface : public PhysicalNetworkInterface
{
  // VLAN interface
  bool
  HasDirectGatewayMac() const override
  {
    return false;
  } // Requires ARP lookup
  bool
  IsSuitableForAfPacket() const override
  {
    return true;
  }
};
#endif

} // namespace netdev
} // namespace celaratcp

#endif // PHYSICAL_NETDEV_BASE_HPP_
