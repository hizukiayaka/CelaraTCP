/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * SPDX-FileCopyrightText: Hsia-Jun(Randy) Li
 */

#include "netdev_core_linux.hpp"

#define IN_LINKLOCAL(a) ((((a) & 0xffff0000) == 0xa9fe0000))

namespace celaratcp {
namespace netdev {

NetDevCoreLinux::NetDevCoreLinux() : sk_(nullptr), link_(nullptr), ifindex_(-1)
{
  sk_ = nl_socket_alloc();
  if (!sk_) {
    throw std::runtime_error("failed to allocate netlink socket");
  }

  auto ret = nl_connect(sk_, NETLINK_ROUTE);
  if (ret) {
    nl_socket_free(sk_);
    throw std::runtime_error("failed to connect to netlink");
  }
}

NetDevCoreLinux::NetDevCoreLinux(int ifindex) : NetDevCoreLinux()
{
  ifindex_ = ifindex;

  auto ret = rtnl_link_get_kernel(sk_, ifindex, nullptr, &link_);
  if (ret)
    throw std::logic_error("can't bind request interface");
}

NetDevCoreLinux::NetDevCoreLinux(std::string_view inf_name) : NetDevCoreLinux()
{
  auto ret = rtnl_link_get_kernel(sk_, -1, std::data(inf_name), &link_);
  if (ret)
    throw std::logic_error("can't bind request interface");

  ifindex_ = rtnl_link_get_ifindex(link_);
}

NetDevCoreLinux::~NetDevCoreLinux()
{
  if (link_)
    rtnl_link_put(link_);
  if (sk_)
    nl_socket_free(sk_);
}

bool
NetDevCoreLinux::Initialize(int ifindex)
{
  if (link_ != nullptr)
    return false;
  if (ifindex_ != -1)
    return false;

  int ret = rtnl_link_get_kernel(sk_, ifindex, nullptr, &link_);
  if (ret)
    return false;

  ifindex_ = ifindex;
  return true;
}

bool
NetDevCoreLinux::Initialize(std::string_view inf_name)
{
  if (link_ != nullptr)
    return false;
  if (ifindex_ != -1)
    return false;

  int ret = rtnl_link_get_kernel(sk_, -1, std::data(inf_name), &link_);
  if (ret)
    return false;

  ifindex_ = rtnl_link_get_ifindex(link_);
  return true;
}

std::string
NetDevCoreLinux::GetInterfaceName() const
{
  auto name = rtnl_link_get_name(link_);
  if (!name)
    return std::string();

  return std::string(name);
}

int
NetDevCoreLinux::GetInterfaceIndex() const
{
  return ifindex_;
}

int
NetDevCoreLinux::GetMtu() const
{
  return rtnl_link_get_mtu(link_);
}

std::array<uint8_t, ETH_ALEN>
NetDevCoreLinux::GetMacAddress() const
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
NetDevCoreLinux::GetIPv4Address() const
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
NetDevCoreLinux::GetIPv6Address(ipv6::AddressScope scope) const
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
NetDevCoreLinux::GetGatewayMacAddress() const
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
NetDevCoreLinux::SetMtu(const uint_fast16_t mtu)
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
NetDevCoreLinux::SetLocalIPv4Address(const asio::ip::address_v4 &addr,
                                     uint_fast8_t prefix)
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
NetDevCoreLinux::SetLocalIPv6Address(const asio::ip::address_v6 &addr,
                                     uint_fast8_t prefix)
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

bool
NetDevCoreLinux::Up()
{
  auto flags = rtnl_link_get_flags(link_);
  if (flags & IFF_UP) {
    // Already up
    return true;
  }

  rtnl_link_set_flags(link_, IFF_UP);
  int ret = rtnl_link_change(sk_, link_, link_, 0);
  if (ret < 0) {
    return false;
  }
  return true;
}

bool
NetDevCoreLinux::Down()
{
  auto flags = rtnl_link_get_flags(link_);
  if (!(flags & IFF_UP)) {
    // Already Down
    return true;
  }

  rtnl_link_unset_flags(link_, IFF_UP);
  int ret = rtnl_link_change(sk_, link_, link_, 0);
  if (ret < 0) {
    return false;
  }
  return true;
}

} // namespace netdev
} // namespace celaratcp
