/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * SPDX-FileCopyrightText: Hsia-Jun(Randy) Li
 */

#include "ethernet_netdev.hpp"
#include "netdev_core_linux.hpp"
#include "tc_ingress_ringbuf.hpp"

namespace celaratcp {
namespace netdev {

class EthernetNetdev::EthernetNetdevLinux : public NetDevCoreLinux,
                                            public IFilterProvider
{
private:
  std::unique_ptr<IPacketFilter> ingress_filter_;

public:
  EthernetNetdevLinux(std::string_view inf_name);
  EthernetNetdevLinux(int ifindex);

  ~EthernetNetdevLinux();

  bool
  HasDirectGatewayMac() const
  {
    return false;
  }

  bool
  IsSuitableForAfPacket() const
  {
    return true;
  }

  std::list<FilterAttachPoint> GetSupportAttachPoint() const override;
  IPacketFilter *AttachFilter(FilterAttachPoint point) override;
};

EthernetNetdev::EthernetNetdevLinux::EthernetNetdevLinux(int ifindex)
    : NetDevCoreLinux(ifindex), ingress_filter_(nullptr)
{
}

EthernetNetdev::EthernetNetdevLinux::EthernetNetdevLinux(
    std::string_view inf_name)
    : NetDevCoreLinux(inf_name), ingress_filter_(nullptr)
{
}

std::list<FilterAttachPoint>
EthernetNetdev::EthernetNetdevLinux::GetSupportAttachPoint() const
{
  return { FilterAttachPoint::TC_INGRESS };
}

IPacketFilter *
EthernetNetdev::EthernetNetdevLinux::AttachFilter(FilterAttachPoint point)
{
#ifndef EBPF_OBJECT_DIR
#error "EBPF_OBJECT_DIR must be defined by the build system"
#endif

  constexpr std::string_view ingress_obj_path
      = EBPF_OBJECT_DIR "/l2_ingress_ring_l4.o";
  switch (point) {
  case FilterAttachPoint::TC_INGRESS:
    try {
      auto ifindex = GetInterfaceIndex();
      ingress_filter_
          = std::make_unique<TcIngressRingbuf>(ingress_obj_path, ifindex);
    }
    catch (...) {
      return nullptr;
    }
    return ingress_filter_.get();
    break;
  default:
    return nullptr;
  }
  return nullptr;
}

EthernetNetdev::EthernetNetdevLinux::~EthernetNetdevLinux()
{
  ingress_filter_.reset();
}

EthernetNetdev::EthernetNetdev(std::string_view inf_name)
    : pImpl_(std::make_unique<EthernetNetdev::EthernetNetdevLinux>(inf_name))
{
}

EthernetNetdev::EthernetNetdev(int ifindex)
    : pImpl_(std::make_unique<EthernetNetdev::EthernetNetdevLinux>(ifindex))
{
}

std::string
EthernetNetdev::GetInterfaceName() const
{
  return pImpl_->GetInterfaceName();
}

int
EthernetNetdev::GetInterfaceIndex() const
{
  return pImpl_->GetInterfaceIndex();
}

int
EthernetNetdev::GetMtu() const
{
  return pImpl_->GetMtu();
}

std::optional<asio::ip::address_v4>
EthernetNetdev::GetIPv4Address() const
{
  return pImpl_->GetIPv4Address();
}

std::optional<asio::ip::address_v6>
EthernetNetdev::GetIPv6Address(ipv6::AddressScope scope) const
{
  return pImpl_->GetIPv6Address(scope);
}

std::array<uint8_t, ETH_ALEN>
EthernetNetdev::GetMacAddress() const
{
  return pImpl_->GetMacAddress();
}

std::optional<std::array<uint8_t, ETH_ALEN> >
EthernetNetdev::GetGatewayMacAddress() const
{
  return pImpl_->GetGatewayMacAddress();
}

std::error_code
EthernetNetdev::SetMtu(uint_fast16_t mtu)
{
  return pImpl_->SetMtu(mtu);
}

bool
EthernetNetdev::SetLocalAddress(
    const std::variant<asio::ip::network_v4, asio::ip::network_v6> &network)
{
  return std::visit(
      [this](auto &&net) {
        using T = std::decay_t<decltype(net)>;
        if constexpr (std::is_same_v<T, asio::ip::network_v4>) {
          // Set IPv4 address
          return pImpl_->SetLocalIPv4Address(net.address(),
                                             net.prefix_length());
        } else if constexpr (std::is_same_v<T, asio::ip::network_v6>) {
          // Set IPv6 address
          return pImpl_->SetLocalIPv6Address(net.address(),
                                             net.prefix_length());
        }
        return false;
      },
      network);
}

std::list<FilterAttachPoint>
EthernetNetdev::GetSupportAttachPoint() const
{
  return pImpl_->GetSupportAttachPoint();
}

IPacketFilter *
EthernetNetdev::AttachFilter(FilterAttachPoint point)
{
  return pImpl_->AttachFilter(point);
}

EthernetNetdev::~EthernetNetdev() = default;

} // namespace netdev
} // namespace celaratcp
