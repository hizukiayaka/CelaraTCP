/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * SPDX-FileCopyrightText: Hsia-Jun(Randy) Li
 */

extern "C"
{
#include <linux/if_tun.h>
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

#include "netdev_core_linux.hpp"
#include "tun_gnu_linux_impl.hpp"

namespace celaratcp {
namespace netdev {

class TunGnuLinuxImpl::TunGnuLinuxDetailImpl : public NetDevCoreLinux,
                                               public IFilterProvider
{
private:
  int fd_;

  asio::ip::address_v4 peer4_address_;
  asio::ip::address_v6 peer6_address_;

  std::unique_ptr<IPacketFilter> egress_filter_;
  std::unique_ptr<IPacketFilter> steering_filter_;
  std::unique_ptr<IPacketFilter> xmit_filter_;

  bool SetIpv4AddressPeer(const asio::ip::address_v4 &local_addr,
                          const asio::ip::address_v4 &peer_addr) noexcept;
  bool SetIpv6AddressPeer(const asio::ip::address_v6 &local_addr,
                          const asio::ip::address_v6 &peer_addr) noexcept;

public:
  TunGnuLinuxDetailImpl(const std::string_view intl_name);
  ~TunGnuLinuxDetailImpl();

  TunGnuLinuxDetailImpl(const TunGnuLinuxDetailImpl &other) = delete;
  TunGnuLinuxDetailImpl &operator=(const TunGnuLinuxDetailImpl &other)
      = delete;
  TunGnuLinuxDetailImpl(TunGnuLinuxDetailImpl &&other) = delete;
  TunGnuLinuxDetailImpl &operator=(TunGnuLinuxDetailImpl &&other) = delete;

  int
  GetNativeHandle() const noexcept
  {
    return fd_;
  }

  asio::ip::address_v4 GetPeerIPv4Address() const;
  asio::ip::address_v6 GetPeerIPv6Address() const;

  bool SetPeerIPAddress(const asio::ip::address &local_addr,
                        const asio::ip::address &peer_addr);

  std::list<FilterAttachPoint> GetSupportAttachPoint() const override;
  IPacketFilter *AttachFilter(FilterAttachPoint point) override;
};

TunGnuLinuxImpl::TunGnuLinuxDetailImpl::TunGnuLinuxDetailImpl(
    const std::string_view intl_name)
    : NetDevCoreLinux(), fd_{ -1 }, peer4_address_(), peer6_address_(),
      egress_filter_(nullptr), steering_filter_(nullptr), xmit_filter_(nullptr)
{
  struct ifreq ifr;

  ::memset(&ifr, 0, sizeof(ifr));
  std::memcpy(
      &ifr.ifr_name, std::data(intl_name),
      std::min(std::size(intl_name), static_cast<std::size_t>(IFNAMSIZ)));
  ifr.ifr_flags = IFF_TUN | IFF_NO_PI | IFF_MULTI_QUEUE;

  int fd;
  if ((fd = ::open("/dev/net/tun", O_RDWR)) < 0)
    throw std::runtime_error("can't open tun control");

  auto err = ::ioctl(fd, TUNSETIFF, (void *)&ifr);
  if (err) {
    ::close(fd);
    throw std::runtime_error("failed to create tun");
  }

  err = ::ioctl(fd, TUNSETOFFLOAD, TUN_F_CSUM);
  if (err) {
    ::close(fd);
    throw std::runtime_error("failed to disable checksum");
  }
  fd_ = fd;

  if (NetDevCoreLinux::Initialize(intl_name) == false) {
    ::close(fd_);
    throw std::runtime_error("failed to initialize netlink");
  }
}

TunGnuLinuxImpl::TunGnuLinuxDetailImpl::~TunGnuLinuxDetailImpl()
{
  xmit_filter_.reset();
  steering_filter_.reset();
  egress_filter_.reset();

  ::close(fd_);
}

bool
TunGnuLinuxImpl::TunGnuLinuxDetailImpl::SetIpv4AddressPeer(
    const asio::ip::address_v4 &local_addr,
    const asio::ip::address_v4 &peer_addr) noexcept
{
  auto addr_d = local_addr.to_bytes();

  struct nl_addr *addr
      = nl_addr_build(AF_INET, std::data(addr_d), std::size(addr_d));

  struct rtnl_addr *rt_addr = rtnl_addr_alloc();

  if (addr == nullptr || rt_addr == nullptr) {
    nl_addr_put(addr);
    rtnl_addr_put(rt_addr);
    return false;
  }

  rtnl_addr_set_ifindex(rt_addr, ifindex_);
  rtnl_addr_set_local(rt_addr, addr);
  nl_addr_put(addr);

  addr_d = peer_addr.to_bytes();

  addr = nl_addr_build(AF_INET, std::data(addr_d), std::size(addr_d));
  if (addr == nullptr) {
    rtnl_addr_put(rt_addr);
    return false;
  }

  rtnl_addr_set_peer(rt_addr, addr);
  nl_addr_put(addr);

  rtnl_addr_set_prefixlen(rt_addr, 32);

  if (rtnl_addr_add(sk_, rt_addr, 0)) {
    rtnl_addr_put(rt_addr);
    return false;
  }

  peer4_address_ = asio::ip::address_v4(addr_d);

  rtnl_addr_put(rt_addr);
  return true;
}

bool
TunGnuLinuxImpl::TunGnuLinuxDetailImpl::SetIpv6AddressPeer(
    const asio::ip::address_v6 &local_addr,
    const asio::ip::address_v6 &peer_addr) noexcept
{
  auto addr_d = local_addr.to_bytes();

  struct nl_addr *addr
      = nl_addr_build(AF_INET6, std::data(addr_d), std::size(addr_d));

  struct rtnl_addr *rt_addr = rtnl_addr_alloc();

  if (addr == nullptr || rt_addr == nullptr) {
    nl_addr_put(addr);
    rtnl_addr_put(rt_addr);
    return false;
  }

  rtnl_addr_set_ifindex(rt_addr, ifindex_);
  rtnl_addr_set_local(rt_addr, addr);
  nl_addr_put(addr);

  addr_d = peer_addr.to_bytes();

  addr = nl_addr_build(AF_INET6, std::data(addr_d), std::size(addr_d));
  if (addr == nullptr) {
    rtnl_addr_put(rt_addr);
    return false;
  }

  rtnl_addr_set_peer(rt_addr, addr);
  nl_addr_put(addr);

  rtnl_addr_set_prefixlen(rt_addr, 128);

  if (rtnl_addr_add(sk_, rt_addr, 0)) {
    rtnl_addr_put(rt_addr);
    return false;
  }

  peer6_address_ = asio::ip::address_v6(addr_d, ifindex_);

  rtnl_addr_put(rt_addr);
  return true;
}

bool
TunGnuLinuxImpl::TunGnuLinuxDetailImpl::SetPeerIPAddress(
    const asio::ip::address &local_addr, const asio::ip::address &peer_addr)
{
  if (local_addr.is_v4() && peer_addr.is_v4()) {
    return SetIpv4AddressPeer(local_addr.to_v4(), peer_addr.to_v4());
  } else if (local_addr.is_v6() && peer_addr.is_v6()) {
    return SetIpv6AddressPeer(local_addr.to_v6(), peer_addr.to_v6());
  } else {
    return false;
  }
}

asio::ip::address_v4
TunGnuLinuxImpl::TunGnuLinuxDetailImpl::GetPeerIPv4Address() const
{
  return peer4_address_;
}

asio::ip::address_v6
TunGnuLinuxImpl::TunGnuLinuxDetailImpl::GetPeerIPv6Address() const
{
  return peer6_address_;
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

TunGnuLinuxImpl::~TunGnuLinuxImpl() { stream_.release(); }

TunGnuLinuxImpl::TunGnuLinuxImpl(asio::any_io_executor &ex,
                                 const std::string_view intl_name)
    : pImpl_(std::make_unique<TunGnuLinuxDetailImpl>(intl_name)), stream_(ex),
      strand_write_(ex), is_master_node_(false), is_client_(false)
{
  stream_.assign(pImpl_->GetNativeHandle());

  is_master_node_ = true;
}

TunGnuLinuxImpl::TunGnuLinuxImpl(asio::any_io_executor &ex,
                                 const std::string_view intl_name,
                                 const asio::ip::address_v4 &addr)
    : TunGnuLinuxImpl(ex, intl_name)
{
  const auto n = addr.to_uint();
  if (n == 0xFFFFFFFFu)
    throw std::out_of_range("address_v4 overflow");

  auto peer_addr = asio::ip::make_address_v4(n + 1);

  pImpl_->SetPeerIPAddress(addr, peer_addr);
}

TunGnuLinuxImpl::TunGnuLinuxImpl(asio::any_io_executor &ex,
                                 const std::string_view intl_name,
                                 const asio::ip::address_v6 &addr)
    : TunGnuLinuxImpl(ex, intl_name)
{
  auto peer_addr_d = addr.to_bytes();

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

  auto peer_addr = asio::ip::make_address_v6(peer_addr_d, 0);

  pImpl_->SetPeerIPAddress(addr, peer_addr);
}

asio::ip::address_v4
TunGnuLinuxImpl::GetPeerIPv4Address() const
{
  return pImpl_->GetPeerIPv4Address();
}

asio::ip::address_v6
TunGnuLinuxImpl::GetPeerIPv6Address() const
{
  return pImpl_->GetPeerIPv6Address();
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
} // namespace netdev

} // namespace celaratcp
