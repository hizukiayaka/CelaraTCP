/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * SPDX-FileCopyrightText: Hsia-Jun(Randy) Li
 */

extern "C"
{
#include <netlink/route/addr.h>
#include <netlink/route/link.h>
#include <netlink/route/neighbour.h>
#include <netlink/route/route.h>
#include <netlink/socket.h>
}

#define IN_LINKLOCAL(a) ((((a) & 0xffff0000) == 0xa9fe0000))

#include "ethernet_netdev.hpp"
#include "tc_ingress_ringbuf.hpp"

namespace celaratcp {
namespace netdev {

class EthernetNetdev::EthernetNetdevLinux : public IFilterProvider
{
private:
  struct nl_sock *sk_;
  struct rtnl_link *link_;

  int ifindex_;

  std::unique_ptr<IPacketFilter> ingress_filter_;

public:
  EthernetNetdevLinux(std::string_view inf_name);
  EthernetNetdevLinux(int ifindex);

  ~EthernetNetdevLinux();

  std::string GetInterfaceName() const;

  int GetInterfaceIndex() const;

  int GetMtu() const;

  std::optional<asio::ip::address_v4> GetIPv4Address() const;

  std::optional<asio::ip::address_v6>
  GetIPv6Address(ipv6::AddressScope scope) const;
  std::array<uint8_t, ETH_ALEN> GetMacAddress() const;

  std::optional<std::array<uint8_t, ETH_ALEN> > GetGatewayMacAddress() const;

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

  std::error_code SetMtu(const uint_fast16_t mtu);

  bool SetLocalIPv4Address(const asio::ip::address_v4 &addr,
                           uint_fast8_t prefix);
  bool SetLocalIPv6Address(const asio::ip::address_v6 &addr,
                           uint_fast8_t prefix);

  std::list<FilterAttachPoint> GetSupportAttachPoint() const override;
  IPacketFilter *AttachFilter(FilterAttachPoint point) override;
};

EthernetNetdev::EthernetNetdevLinux::EthernetNetdevLinux(int ifindex)
    : sk_(nullptr), link_(nullptr), ifindex_(ifindex), ingress_filter_(nullptr)
{
  sk_ = nl_socket_alloc();

  auto ret = nl_connect(sk_, NETLINK_ROUTE);
  if (ret) {
    nl_socket_free(sk_);
    throw std::runtime_error("failed to connect to netlink");
  }

  ret = rtnl_link_get_kernel(sk_, ifindex, nullptr, &link_);
  if (ret)
    throw std::logic_error("can't bind request interface");
}

EthernetNetdev::EthernetNetdevLinux::EthernetNetdevLinux(
    std::string_view inf_name)
    : sk_(nullptr), link_(nullptr), ingress_filter_(nullptr)
{
  sk_ = nl_socket_alloc();

  auto ret = nl_connect(sk_, NETLINK_ROUTE);
  if (ret) {
    nl_socket_free(sk_);
    throw std::runtime_error("failed to connect to netlink");
  }

  ret = rtnl_link_get_kernel(sk_, -1, std::data(inf_name), &link_);
  if (ret)
    throw std::logic_error("can't bind request interface");

  ifindex_ = rtnl_link_get_ifindex(link_);
}

std::string
EthernetNetdev::EthernetNetdevLinux::GetInterfaceName() const
{
  auto name = rtnl_link_get_name(link_);
  if (!name)
    return std::string();

  return std::string(name);
}

int
EthernetNetdev::EthernetNetdevLinux::GetInterfaceIndex() const
{
  return ifindex_;
}

int
EthernetNetdev::EthernetNetdevLinux::GetMtu() const
{
  return rtnl_link_get_mtu(link_);
}

std::array<uint8_t, ETH_ALEN>
EthernetNetdev::EthernetNetdevLinux::GetMacAddress() const
{
  auto addr = rtnl_link_get_addr(link_);
  auto len = nl_addr_get_len(addr);

  if (len > 0 && len <= ETH_ALEN) {
    std::array<uint8_t, ETH_ALEN> hw_addr;
    std::memcpy(std::data(hw_addr), addr, len);
    return hw_addr;
  }

  return {};
}

std::optional<asio::ip::address_v4>
EthernetNetdev::EthernetNetdevLinux::GetIPv4Address() const
{
  struct nl_cache *addr_cache = nullptr;
  std::optional<asio::ip::address_v4> result;

  // Get all addresses
  if (rtnl_addr_alloc_cache(sk_, &addr_cache) < 0) {
    return std::nullopt;
  }

  // Find addresses for our interface
  struct rtnl_addr *filter = rtnl_addr_alloc();
  rtnl_addr_set_ifindex(filter, ifindex_);

  // Filter for IPv4 addresses
  for (struct nl_object *obj = nl_cache_get_first(addr_cache); obj != nullptr;
       obj = nl_cache_get_next(obj))
  {

    struct rtnl_addr *addr = (struct rtnl_addr *)obj;

    // Skip if not our interface
    if (rtnl_addr_get_ifindex(addr) != ifindex_) {
      continue;
    }

    // Skip if not IPv4
    struct nl_addr *local = rtnl_addr_get_local(addr);
    if (!local || nl_addr_get_family(local) != AF_INET) {
      continue;
    }

    // Skip if loopback/link-local/etc
    if (nl_addr_get_prefixlen(local) == 0 || nl_addr_get_prefixlen(local) == 32
        || IN_LINKLOCAL(ntohl(*(uint32_t *)nl_addr_get_binary_addr(local))))
    {
      continue;
    }

    // Convert to asio address
    asio::ip::address_v4::bytes_type bytes;
    std::memcpy(bytes.data(), nl_addr_get_binary_addr(local),
                std::min(bytes.size(), (size_t)nl_addr_get_len(local)));

    result = asio::ip::address_v4(bytes);
    break;
  }

  rtnl_addr_put(filter);
  nl_cache_free(addr_cache);
  return result;
}

std::optional<asio::ip::address_v6>
EthernetNetdev::EthernetNetdevLinux::GetIPv6Address(
    ipv6::AddressScope scope) const
{
  struct nl_cache *addr_cache = nullptr;
  std::optional<asio::ip::address_v6> result;

  // Get all addresses
  if (rtnl_addr_alloc_cache(sk_, &addr_cache) < 0) {
    return std::nullopt;
  }

  // Find addresses for our interface
  struct rtnl_addr *filter = rtnl_addr_alloc();
  rtnl_addr_set_ifindex(filter, ifindex_);

  // Filter for IPv6 addresses
  for (struct nl_object *obj = nl_cache_get_first(addr_cache); obj != nullptr;
       obj = nl_cache_get_next(obj))
  {

    struct rtnl_addr *addr = (struct rtnl_addr *)obj;

    // Skip if not our interface
    if (rtnl_addr_get_ifindex(addr) != ifindex_) {
      continue;
    }

    // Skip if not IPv6
    struct nl_addr *local = rtnl_addr_get_local(addr);
    if (!local || nl_addr_get_family(local) != AF_INET6) {
      continue;
    }

    const uint8_t *addr_bytes
        = (const uint8_t *)nl_addr_get_binary_addr(local);
    switch (scope) {
    case ipv6::AddressScope::LinkLocal:
      if (addr_bytes[0] == 0xfe && (addr_bytes[1] & 0xc0) == 0x80) {
        // Link-local address
        asio::ip::address_v6::bytes_type bytes;
        std::memcpy(bytes.data(), addr_bytes,
                    asio::ip::address_v6::bytes_type().size());
        result = asio::ip::address_v6(bytes);
        break;
      }
      continue;
    case ipv6::AddressScope::UniqueLocal:
      if (addr_bytes[0] == 0xfc || addr_bytes[0] == 0xfd) {
        // Unique local address
        asio::ip::address_v6::bytes_type bytes;
        std::memcpy(bytes.data(), addr_bytes,
                    asio::ip::address_v6::bytes_type().size());
        result = asio::ip::address_v6(bytes);
        break;
      }
      continue;
    case ipv6::AddressScope::GlobalUnicast:
      // Not link-local
      if (!(addr_bytes[0] == 0xfe && (addr_bytes[1] & 0xc0) == 0x80)
          && // Not ULA
          !(addr_bytes[0] == 0xfc || addr_bytes[0] == 0xfd))
      {
        asio::ip::address_v6::bytes_type bytes;
        std::memcpy(bytes.data(), addr_bytes,
                    asio::ip::address_v6::bytes_type().size());
        result = asio::ip::address_v6(bytes);
        break;
      }
      continue;
    }
  }

  rtnl_addr_put(filter);
  nl_cache_free(addr_cache);
  return result;
}

std::optional<std::array<uint8_t, ETH_ALEN> >
EthernetNetdev::EthernetNetdevLinux::GetGatewayMacAddress() const
{
  struct nl_cache *route_cache = nullptr;
  struct nl_cache *neigh_cache = nullptr;
  std::optional<std::array<uint8_t, ETH_ALEN> > result;

  // Get routing table
  if (rtnl_route_alloc_cache(sk_, AF_INET, 0, &route_cache) < 0) {
    return std::nullopt;
  }

  // Get neighbors (ARP) table
  if (rtnl_neigh_alloc_cache(sk_, &neigh_cache) < 0) {
    nl_cache_free(route_cache);
    return std::nullopt;
  }

  // Find default route for our interface
  struct nl_addr *gw_addr = nullptr;
  for (struct nl_object *obj = nl_cache_get_first(route_cache); obj != nullptr;
       obj = nl_cache_get_next(obj))
  {

    struct rtnl_route *route = (struct rtnl_route *)obj;

    // Check if default route
    struct nl_addr *dst = rtnl_route_get_dst(route);
    if (dst && nl_addr_get_prefixlen(dst) != 0) {
      continue;
    }

    // Check if for our interface
    int nexthops = rtnl_route_get_nnexthops(route);
    for (int i = 0; i < nexthops; i++) {
      struct rtnl_nexthop *nh = rtnl_route_nexthop_n(route, i);
      if (rtnl_route_nh_get_ifindex(nh) == ifindex_) {
        gw_addr = rtnl_route_nh_get_gateway(nh);
        if (gw_addr) {
          nl_addr_get(gw_addr); // Increase refcount
          goto found_gateway;
        }
      }
    }
  }

found_gateway:
  if (!gw_addr) {
    nl_cache_free(neigh_cache);
    nl_cache_free(route_cache);
    return std::nullopt;
  }

  // Look up gateway MAC in neighbor table
  for (struct nl_object *obj = nl_cache_get_first(neigh_cache); obj != nullptr;
       obj = nl_cache_get_next(obj))
  {

    struct rtnl_neigh *neigh = (struct rtnl_neigh *)obj;

    // Check if neighbor for our interface
    if (rtnl_neigh_get_ifindex(neigh) != ifindex_) {
      continue;
    }

    // Check if matches gateway IP
    struct nl_addr *dst = rtnl_neigh_get_dst(neigh);
    if (!dst || nl_addr_cmp(dst, gw_addr) != 0) {
      continue;
    }

    // Get MAC address
    struct nl_addr *lladdr = rtnl_neigh_get_lladdr(neigh);
    if (!lladdr || nl_addr_get_len(lladdr) != ETH_ALEN) {
      continue;
    }

    std::array<uint8_t, ETH_ALEN> mac;
    std::memcpy(mac.data(), nl_addr_get_binary_addr(lladdr), ETH_ALEN);
    result = mac;
    break;
  }

  nl_addr_put(gw_addr);
  nl_cache_free(neigh_cache);
  nl_cache_free(route_cache);
  return result;
}

std::error_code
EthernetNetdev::EthernetNetdevLinux::SetMtu(const uint_fast16_t mtu)
{
  struct rtnl_link *new_link = rtnl_link_alloc();
  if (!new_link) {
    return std::make_error_code(std::errc::not_enough_memory);
  }

  rtnl_link_set_ifindex(new_link, ifindex_);
  rtnl_link_set_mtu(new_link, mtu);

  int ret = rtnl_link_change(sk_, new_link, link_, 0);
  rtnl_link_put(new_link);

  if (ret < 0) {
    return std::error_code(-ret, std::generic_category());
  }

  return {};
}

bool
EthernetNetdev::EthernetNetdevLinux::SetLocalIPv4Address(
    const asio::ip::address_v4 &addr, uint_fast8_t prefix)
{
  auto addr_d = addr.to_bytes();
  struct nl_addr *local_addr
      = nl_addr_build(AF_INET, std::data(addr_d), std::size(addr_d));

  struct rtnl_addr *rt_addr = rtnl_addr_alloc();

  rtnl_addr_set_ifindex(rt_addr, ifindex_);
  rtnl_addr_set_local(rt_addr, local_addr);
  rtnl_addr_set_prefixlen(rt_addr, prefix);

  if (rtnl_addr_add(sk_, rt_addr, 0)) {
    nl_addr_put(local_addr);
    rtnl_addr_put(rt_addr);
    return false;
  }

  nl_addr_put(local_addr);
  rtnl_addr_put(rt_addr);

  return true;
}

bool
EthernetNetdev::EthernetNetdevLinux::SetLocalIPv6Address(
    const asio::ip::address_v6 &addr, uint_fast8_t prefix)
{
  auto addr_d = addr.to_bytes();
  struct nl_addr *local_addr
      = nl_addr_build(AF_INET6, std::data(addr_d), std::size(addr_d));

  struct rtnl_addr *rt_addr = rtnl_addr_alloc();

  rtnl_addr_set_ifindex(rt_addr, ifindex_);
  rtnl_addr_set_local(rt_addr, local_addr);
  rtnl_addr_set_prefixlen(rt_addr, prefix);

  if (rtnl_addr_add(sk_, rt_addr, 0)) {
    nl_addr_put(local_addr);
    rtnl_addr_put(rt_addr);
    return false;
  }

  nl_addr_put(local_addr);
  rtnl_addr_put(rt_addr);

  return true;
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

  if (link_)
    rtnl_link_put(link_);
  if (sk_)
    nl_socket_free(sk_);
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
