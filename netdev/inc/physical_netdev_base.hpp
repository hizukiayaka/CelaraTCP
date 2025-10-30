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
#include <variant>

#include <asio/ip/address.hpp>
#include <asio/ip/network_v4.hpp>
#include <asio/ip/network_v6.hpp>

#include "net_filter_inf.hpp"

namespace celaratcp {

namespace ipv6 {
enum class AddressScope
{
  // fe80::/10, link local
  LinkLocal,
  // fc00::/7, ULA
  UniqueLocal,
  // 2000::/3, GUA
  GlobalUnicast,
};
} // namespace ipv6

namespace netdev {
class PhysicalNetdevBase
{
public:
  virtual ~PhysicalNetdevBase() = default;

  // Get interface name (eth0, ppp0, etc)
  virtual std::string GetInterfaceName() const = 0;

  // Get interface index
  virtual int GetInterfaceIndex() const = 0;

  // Get the MTU (Maximum Transmission Unit) of the interface
  virtual int GetMtu() const = 0;

  // Get interface IPv4/IPv6 addresses
  virtual std::optional<asio::ip::address_v4> GetIPv4Address() const = 0;
  virtual std::optional<asio::ip::address_v6>
  GetIPv6Address(ipv6::AddressScope scope) const = 0;

  // Get peer IPv4 address (for tunnel interfaces)
  virtual std::optional<asio::ip::address_v4>
  GetPeerIPv4Address() const
  {
    return std::nullopt;
  }

  // Get peer IPv6 address (for tunnel interfaces)
  virtual std::optional<asio::ip::address_v6>
  GetPeerIPv6Address() const
  {
    return std::nullopt;
  }

  // Get interface MAC address
  virtual std::array<uint8_t, ETH_ALEN> GetMacAddress() const = 0;

  // Get gateway/peer MAC address if available
  virtual std::optional<std::array<uint8_t, ETH_ALEN> >
  GetGatewayMacAddress() const = 0;

  // Check if gateway MAC is directly available
  virtual bool HasDirectGatewayMac() const = 0;

  // For AF_PACKET usage
  virtual bool IsSuitableForAfPacket() const = 0;

  // Set interface MTU (Maximum Transmission Unit)
  virtual std::error_code SetMtu(uint_fast16_t mtu) = 0;

  // Set the local address with a prefix
  virtual bool SetLocalAddress(
      const std::variant<asio::ip::network_v4, asio::ip::network_v6> &network)
      = 0;
  // Set peer IPv4/IPv6 address (requires local IPv4 address)
  virtual bool
  SetPeerIPAddress(const asio::ip::address &local_addr,
                   const asio::ip::address &peer_addr)
  {
    (void)local_addr;
    (void)peer_addr;
    return false;
  }

  virtual bool
  SetPeerIPAddress(const asio::ip::address &peer_addr)
  {
    (void)peer_addr;
    return false;
  }
};

#if 0
// Derived interface-specific classes
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
