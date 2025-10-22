/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * SPDX-FileCopyrightText: Hsia-Jun(Randy) Li
 */

extern "C"
{
#include <linux/if_tun.h>
#include <netlink/route/addr.h>
#include <netlink/route/link.h>
#include <netlink/route/route.h>
#include <netlink/socket.h>
}

#if HAVE_INT128
// Use native 128-bit integer
using int128_t = __int128;
using uint128_t = unsigned __int128;
#else
// Use abseil's 128-bit integer implementation
#include <absl/numeric/int128.h>
using int128_t = absl::int128;
using uint128_t = absl::uint128;
#endif

#include "tc_egress_filter.hpp"
#include "tc_egress_filter_lite.hpp"

#include "tun_gnu_linux_impl.hpp"

namespace celaratcp {
namespace netdev {

class TunGnuLinuxImpl::TunGnuLinuxDetailImpl : public IFilterProvider
{
private:
  struct nl_sock *sk_;
  struct rtnl_link *link_;
  int ifindex_;

  asio::ip::address_v4 peer4_address_;
  asio::ip::address_v6 peer6_address_;

  std::unique_ptr<IPacketFilter> egress_filter_;
  std::unique_ptr<IPacketFilter> steering_filter_;
  std::unique_ptr<IPacketFilter> xmit_filter_;

  /* ioctl callback */
  std::function<bool(unsigned long, int)> on_load_ebpf_callback_;

public:
  TunGnuLinuxDetailImpl();
  ~TunGnuLinuxDetailImpl() override;

  void
  Initialize(const std::string &intl_name,
             std::function<bool(unsigned long, int)> &&on_load_ebpf_callback);

  void SetIpv4AddressPeer(const asio::ip::address_v4 &addr);
  void SetIpv6AddressPeer(const asio::ip::address_v6 &addr);

  asio::ip::address_v4 GetIPv4PeerAddress() const;
  asio::ip::address_v6 GetIPv6PeerAddress() const;

  void AddIpv4Address(const asio::ip::network_v4 &net);
  void AddIpv6Address(const asio::ip::network_v6 &net);

  bool Up();
  bool Down();

  std::list<FilterAttachPoint> GetSupportAttachPoint() const override;
  IPacketFilter *AttachFilter(FilterAttachPoint point) override;

  TunGnuLinuxDetailImpl(const TunGnuLinuxDetailImpl &other) = delete;
  TunGnuLinuxDetailImpl &operator=(const TunGnuLinuxDetailImpl &other)
      = delete;
  TunGnuLinuxDetailImpl(TunGnuLinuxDetailImpl &&other) = delete;
  TunGnuLinuxDetailImpl &operator=(TunGnuLinuxDetailImpl &&other) = delete;
};

TunGnuLinuxImpl::TunGnuLinuxDetailImpl::TunGnuLinuxDetailImpl()
    : sk_(nullptr), link_(nullptr), ifindex_(-1), peer4_address_(),
      peer6_address_(), egress_filter_(nullptr), steering_filter_(nullptr),
      xmit_filter_(nullptr)
{
}

TunGnuLinuxImpl::TunGnuLinuxDetailImpl::~TunGnuLinuxDetailImpl()
{
  nl_socket_free(sk_);

  xmit_filter_.release();
  steering_filter_.release();
  egress_filter_.release();
}

void
TunGnuLinuxImpl::TunGnuLinuxDetailImpl::Initialize(
    const std::string &intl_name,
    std::function<bool(unsigned long, int)> &&on_load_ebpf_callback)
{
  ifindex_ = if_nametoindex(intl_name.c_str());

  sk_ = nl_socket_alloc();
  auto err = nl_connect(sk_, NETLINK_ROUTE);
  if (err) {
    nl_socket_free(sk_);
    throw std::runtime_error("failed to connect to netlink");
  }

  err = rtnl_link_get_kernel(sk_, ifindex_, nullptr, &link_);
  if (err) {
    nl_socket_free(sk_);
    throw std::runtime_error("failed to get link");
  }

  on_load_ebpf_callback_ = on_load_ebpf_callback;
}

void
TunGnuLinuxImpl::TunGnuLinuxDetailImpl::SetIpv4AddressPeer(
    const asio::ip::address_v4 &addr)
{
  const auto n = addr.to_uint();
  if (n == 0xFFFFFFFFu)
    throw std::out_of_range("address_v4 overflow");

  auto addr_d = addr.to_bytes();
  struct nl_addr *local_addr
      = nl_addr_build(AF_INET, addr_d.data(), addr_d.size());

  struct rtnl_addr *rt_addr = rtnl_addr_alloc();

  rtnl_addr_set_ifindex(rt_addr, ifindex_);
  rtnl_addr_set_local(rt_addr, local_addr);

  peer4_address_ = asio::ip::make_address_v4(n + 1);

  addr_d = peer4_address_.to_bytes();
  struct nl_addr *peer_addr
      = nl_addr_build(AF_INET, addr_d.data(), addr_d.size());
  rtnl_addr_set_peer(rt_addr, peer_addr);

  rtnl_addr_set_prefixlen(rt_addr, 32);

  if (rtnl_addr_add(sk_, rt_addr, 0)) {
    nl_addr_put(local_addr);
    nl_addr_put(peer_addr);
    rtnl_addr_put(rt_addr);
    throw std::runtime_error("can't set peer addr");
  }

  nl_addr_put(local_addr);
  nl_addr_put(peer_addr);
  rtnl_addr_put(rt_addr);
}

void
TunGnuLinuxImpl::TunGnuLinuxDetailImpl::SetIpv6AddressPeer(
    const asio::ip::address_v6 &addr)
{
  auto addr_d = addr.to_bytes();
  struct nl_addr *local_addr
      = nl_addr_build(AF_INET6, addr_d.data(), addr_d.size());
  struct rtnl_addr *rt_addr = rtnl_addr_alloc();

  rtnl_addr_set_ifindex(rt_addr, ifindex_);
  rtnl_addr_set_local(rt_addr, local_addr);

  auto peer_addr_d = addr_d;

  if constexpr (std::endian::native == std::endian::big) {
    bool carry = true;
    for (auto it = peer_addr_d.rbegin(); it != peer_addr_d.rend() && carry;
         ++it)
    {
      ++(*it);
      carry = (*it == 0);
    }
  } else {
    uint128_t addr_n = 0;
    std::size_t shift = 0;
    for (auto it = peer_addr_d.rbegin(); it != peer_addr_d.rend(); ++it) {
      addr_n |= ((*it) << shift);
      shift += 8;
    }
    addr_n++;
    for (auto it = peer_addr_d.rbegin(); it != peer_addr_d.rend(); ++it) {
      *it = static_cast<uint8_t>(addr_n & 0xFF);
      addr_n >>= 8;
    }
  }

  struct nl_addr *peer_addr
      = nl_addr_build(AF_INET6, peer_addr_d.data(), peer_addr_d.size());

  peer6_address_ = asio::ip::make_address_v6(peer_addr_d, 0);

  rtnl_addr_set_peer(rt_addr, peer_addr);
  rtnl_addr_set_prefixlen(rt_addr, 128);

  if (rtnl_addr_add(sk_, rt_addr, 0)) {
    nl_addr_put(peer_addr);
    nl_addr_put(local_addr);
    rtnl_addr_put(rt_addr);
    throw std::runtime_error("can't set addr");
  }

  nl_addr_put(peer_addr);
  nl_addr_put(local_addr);
  rtnl_addr_put(rt_addr);
}

asio::ip::address_v4
TunGnuLinuxImpl::TunGnuLinuxDetailImpl::GetIPv4PeerAddress() const
{
  return peer4_address_;
}

asio::ip::address_v6
TunGnuLinuxImpl::TunGnuLinuxDetailImpl::GetIPv6PeerAddress() const
{
  return peer6_address_;
}

void
TunGnuLinuxImpl::TunGnuLinuxDetailImpl::AddIpv4Address(
    const asio::ip::network_v4 &net)
{
  auto addr = net.address();
  auto addr_d = addr.to_bytes();
  struct nl_addr *local_addr
      = nl_addr_build(AF_INET, addr_d.data(), addr_d.size());

  struct rtnl_addr *rt_addr = rtnl_addr_alloc();

  rtnl_addr_set_ifindex(rt_addr, ifindex_);
  rtnl_addr_set_local(rt_addr, local_addr);
  rtnl_addr_set_prefixlen(rt_addr, net.prefix_length());

  if (rtnl_addr_add(sk_, rt_addr, 0)) {
    nl_addr_put(local_addr);
    rtnl_addr_put(rt_addr);
    throw std::runtime_error("can't set addr");
  }
  nl_addr_put(local_addr);
  rtnl_addr_put(rt_addr);
}

void
TunGnuLinuxImpl::TunGnuLinuxDetailImpl::AddIpv6Address(
    const asio::ip::network_v6 &net)
{
  auto addr = net.address();
  auto addr_d = addr.to_bytes();
  struct nl_addr *local_addr
      = nl_addr_build(AF_INET6, addr_d.data(), addr_d.size());
  struct rtnl_addr *rt_addr = rtnl_addr_alloc();

  rtnl_addr_set_ifindex(rt_addr, ifindex_);
  rtnl_addr_set_local(rt_addr, local_addr);
  rtnl_addr_set_prefixlen(rt_addr, net.prefix_length());

  if (rtnl_addr_add(sk_, rt_addr, 0)) {
    nl_addr_put(local_addr);
    rtnl_addr_put(rt_addr);
    throw std::runtime_error("can't set addr");
  }
  nl_addr_put(local_addr);
  rtnl_addr_put(rt_addr);
}

bool
TunGnuLinuxImpl::TunGnuLinuxDetailImpl::Up()
{
  auto flags = rtnl_link_get_flags(link_);
  if (flags & IFF_UP) {
    return true; // Already up
  }
  // Set the interface up
  rtnl_link_set_flags(link_, IFF_UP);

  // Apply the changes using libnl
  int err = rtnl_link_change(sk_, link_, link_, 0);
  if (err) {
    return false;
  }

  return true;
}

bool
TunGnuLinuxImpl::TunGnuLinuxDetailImpl::Down()
{
  auto flags = rtnl_link_get_flags(link_);
  if (!(flags & IFF_UP)) {
    return true; // Already down
  }
  rtnl_link_unset_flags(link_, IFF_UP);

  // Apply the changes using libnl
  int err = rtnl_link_change(sk_, link_, link_, 0);
  if (err) {
    return false;
  }

  return true;
}

std::list<FilterAttachPoint>
TunGnuLinuxImpl::TunGnuLinuxDetailImpl::GetSupportAttachPoint() const
{
  return { FilterAttachPoint::TC_EGRESS };
}

IPacketFilter *
TunGnuLinuxImpl::TunGnuLinuxDetailImpl::AttachFilter(FilterAttachPoint point)
{
#ifndef EBPF_OBJECT_DIR
#error "EBPF_OBJECT_DIR must be defined by the build system"
#endif
  constexpr std::string_view egress_obj_path = EBPF_OBJECT_DIR "/tun_egress.o";
  constexpr std::string_view egress_lite_obj_path
      = EBPF_OBJECT_DIR "/l3_egress.o";

  switch (point) {
  case FilterAttachPoint::TC_EGRESS:
    try {
      egress_filter_
          = std::make_unique<TcEgressFilter>(egress_obj_path, ifindex_);
    }
    catch (...) {
      try {
        egress_filter_ = std::make_unique<TcEgressFilterLite>(
            egress_lite_obj_path, ifindex_);
      }
      catch (...) {
        return nullptr;
      }
    }
    return egress_filter_.get();
    break;
  default:
    return nullptr;
    break;
  }

  return nullptr;
}

TunGnuLinuxImpl::~TunGnuLinuxImpl() { stream_.close(); }

TunGnuLinuxImpl::TunGnuLinuxImpl(asio::any_io_executor &ex,
                                 const std::string &intl_name)
    : pImpl_(std::make_unique<TunGnuLinuxDetailImpl>()), stream_(ex),
      strand_write_(ex), is_master_node_(false), is_client_(false)
{
  struct ifreq ifr;

  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, intl_name.c_str(), IFNAMSIZ);
  ifr.ifr_flags = IFF_TUN | IFF_NO_PI | IFF_MULTI_QUEUE;

  int fd;
  if ((fd = open("/dev/net/tun", O_RDWR)) < 0)
    throw std::runtime_error("can't open tun control");

  auto err = ioctl(fd, TUNSETIFF, (void *)&ifr);
  if (err) {
    close(fd);
    throw std::runtime_error("failed to create tun");
  }

  err = ioctl(fd, TUNSETOFFLOAD, TUN_F_CSUM);
  if (err) {
    close(fd);
    throw std::runtime_error("failed to disable checksum");
  }

  stream_.assign(fd);

  pImpl_->Initialize(intl_name, [this](unsigned long op, int prog_fd) {
    if (ioctl(this->stream_.native_handle(), op, &prog_fd) < 0)
      return false;
    return true;
  });

  is_master_node_ = true;
}

TunGnuLinuxImpl::TunGnuLinuxImpl(asio::any_io_executor &ex,
                                 const std::string &intl_name,
                                 const asio::ip::address_v4 &addr)
    : TunGnuLinuxImpl(ex, intl_name)
{
  pImpl_->SetIpv4AddressPeer(addr);
}

asio::ip::address_v4
TunGnuLinuxImpl::GetIPv4PeerAddress() const
{
  return pImpl_->GetIPv4PeerAddress();
}

asio::ip::address_v6
TunGnuLinuxImpl::GetIPv6PeerAddress() const
{
  return pImpl_->GetIPv6PeerAddress();
}

bool
TunGnuLinuxImpl::Up()
{
  return pImpl_->Up();
}

bool
TunGnuLinuxImpl::Down()
{
  return pImpl_->Down();
}

std::list<FilterAttachPoint>
TunGnuLinuxImpl::GetSupportAttachPoint() const
{
  return pImpl_->GetSupportAttachPoint();
}

IPacketFilter *
TunGnuLinuxImpl::AttachFilter(FilterAttachPoint point)
{
  return pImpl_->AttachFilter(point);
}

#if 0
// FIXME: we should not use the default io_context
TunGnuLinuxImpl::TunGnuLinuxImpl(const TunGnuLinuxImpl &other)
  : stream_(other.stream_.get_executor())
{
  int fd;
  if ((fd = open("/dev/net/tun", O_RDWR)) < 0)
    throw std::runtime_error("can't open tun control");

  struct ifreq ifr;
  auto err = ioctl(other.stream_.native_handle(), TUNGETIFF, &ifr);
  if (err)
    {
      close(fd);
      throw std::runtime_error("failed to get the master device's name");
    }

  ifr.ifr_flags = IFF_TUN | IFF_NO_PI | IFF_MULTI_QUEUE;
  err = ioctl(fd, TUNSETIFF, (void *)&ifr);
  if (err)
    {
      close(fd);
      throw std::runtime_error("failed to create tun");
    }

  stream_.assign(fd);
  ifindex_ = other.ifindex_;
  sk_ = other.sk_;
}

std::optional<TunGnuLinuxImpl>
TunGnuLinuxImpl::addNode(asio::ip::address_v4 &addr)
{
  TunGnuLinuxImpl node(*this); // Use the copy constructor to create a copy
  node.is_master_node_ = false;
  auto rt_entry = rtnl_route_alloc();

  auto addr_d = addr.to_bytes();
  struct nl_addr *local_addr
      = nl_addr_build(AF_INET, addr_d.data(), addr_d.size());

  auto err = rtnl_route_set_dst(rt_entry, local_addr);
  nl_addr_put(local_addr);

  rtnl_route_set_scope(rt_entry, RT_SCOPE_LINK);
  rtnl_route_set_iif(rt_entry, ifindex_);

  if (rtnl_route_add(sk_, rt_entry, NLM_F_EXCL)){
    rtnl_route_put(rt_entry);
  }

  rtnl_route_put(rt_entry);

  return std::make_optional<TunGnuLinuxImpl>(std::move(node));
  return std::nullopt;
}
#endif

} // namespace netdev

} // namespace celaratcp
