/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * SPDX-FileCopyrightText: Hsia-Jun(Randy) Li
 */

namespace celaratcp {
namespace netdev {

TunGnuLinuxImpl::~TunGnuLinuxImpl() { nl_socket_free(sk_); }

TunGnuLinuxImpl::TunGnuLinuxImpl(const TunGnuLinuxImpl &other)
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
  infindex_ = other.infindex_;
  sk_ = other.sk_;
}

TunGnuLinuxImpl::TunGnuLinuxImpl(const std::string &intl_name)
{
  struct ifreq ifr;

  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, intl_name.c_str(), IFNAMSIZ);
  ifr.ifr_flags = IFF_TUN | IFF_NO_PI | IFF_MULTI_QUEUE;

  int fd;
  if ((fd = open("/dev/net/tun", O_RDWR)) < 0)
    throw std::runtime_error("can't open tun control");

  auto err = ioctl(fd, TUNSETIFF, (void *)&ifr);
  if (err)
    {
      close(fd);
      throw std::runtime_error("failed to create tun");
    }

  err = iotcl(fd, TUNSETOFFLOAD, TUN_F_CSUM);
  if (err)
    {
      close(fd);
      throw std::runtime_error("failed to disable checksum");
    }

  ifindex_ = if_nametoindex(intl_name.c_str());
  stream_.assign(fd);

  sk_ = nl_socket_alloc();
}

TunGnuLinuxImpl::TunGnuLinuxImpl(const std::string &intl_name,
                                 asio::ip::address_v4 &addr)
    : TunGnuLinuxImpl(int_name)
{
  auto str_addr = addr->to_string();
  struct nl_addr *local_addr
      = nl_addr_build(AF_INET, str_addr.c_str(), str_addr.size());

  struct rtnl_addr *rt_addr = rtnl_addr_alloc();

  rtnl_addr_set_ifindex(rt_addr, ifindex_);
  rtnl_addr_set_local(rt_addr, local_addr);
  nl_addr_put(local_addr);

  if (rtnl_addr_add(sk, rt_addr, 0))
    {
      rtnl_addr_put(rt_addr);
      throw std::runtime_error("can't set addr");
    }
  rtnl_addr_put(rt_addr);
}

TunGnuLinuxImpl
TunGnuLinuxImpl::addNode(asio::ip::address_v4 &addr)
{
  TunGnuLinuxImpl node = *this;
  auto rt_entry = rtnl_route_alloc();

  struct nl_addr *local_addr
      = nl_addr_build(AF_INET, str_addr.c_str(), str_addr.size());

  auto err = rtnl_route_set_dst(rt_entry, local_addr);
  nl_addr_put(local_addr);

  rtnl_route_set_scope(rt_entry, RT_SCOPE_LINK);
  rtnl_route_set_iif(rt_entry, ifindex_);

  if (rtnl_route_add(sk_, rt_entry, NLM_F_EXCL)){
    rtnl_route_put(rt_entry);
  }

  rtnl_route_put(rt_entry);
  return node;
}

}
}