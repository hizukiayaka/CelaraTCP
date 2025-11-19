/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * SPDX-FileCopyrightText: Hsia-Jun(Randy) Li
 */

namespace celaratcp {
namespace netdev {

VirtualNetDev::TunGnuLinuxImpl::~TunGnuLinuxImpl()
{
  nl_socket_free(sk_);
  stream_.close();
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
#endif

VirtualNetDev::TunGnuLinuxImpl::TunGnuLinuxImpl(asio::io_context &io_context,
                                                const std::string &intl_name)
    : stream_(io_context) // Initialize stream_ with an executor
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

  ifindex_ = if_nametoindex(intl_name.c_str());
  stream_.assign(fd);

  sk_ = nl_socket_alloc();
  err = nl_connect(sk_, NETLINK_ROUTE);
  if (err) {
      nl_socket_free(sk_);
      close(fd);
      throw std::runtime_error("failed to connect to netlink");
  }

  isMasterNode_ = true;
}

VirtualNetDev::TunGnuLinuxImpl::TunGnuLinuxImpl(
    asio::io_context &io_context, const std::string &intl_name,
    const asio::ip::address_v4 &addr)
    : TunGnuLinuxImpl(io_context, intl_name)
{
  isClient_ = true;
  auto addr_d = addr.to_bytes();
  struct nl_addr *local_addr
      = nl_addr_build(AF_INET, addr_d.data(), addr_d.size());

  struct rtnl_addr *rt_addr = rtnl_addr_alloc();

  rtnl_addr_set_ifindex(rt_addr, ifindex_);
  rtnl_addr_set_local(rt_addr, local_addr);

  if (rtnl_addr_add(sk_, rt_addr, 0)) {
      nl_addr_put(local_addr);
      rtnl_addr_put(rt_addr);
      throw std::runtime_error("can't set addr");
  }
  nl_addr_put(local_addr);
  rtnl_addr_put(rt_addr);
}

template <typename MutableBufferSequence>
void
VirtualNetDev::TunGnuLinuxImpl::async_read(MutableBufferSequence &bufs,
                                           asio::yield_context yield)
{
  asio::async_read(stream_, bufs, std::move(yield));
}

template <typename ConstBufferSequence>
void
VirtualNetDev::TunGnuLinuxImpl::async_write(ConstBufferSequence &bufs,
                                            asio::yield_context yield)
{
  asio::async_write(stream_, bufs, std::move(yield));
}

void
VirtualNetDev::TunGnuLinuxImpl::async_read(NetPacket &buf,
                                           asio::yield_context yield)
{
  auto mbuf = buf.getMutableBuf();
  asio::async_read(stream_, mbuf, yield);
}

void
VirtualNetDev::TunGnuLinuxImpl::async_read(
    std::forward_list<std::shared_ptr<NetPacket> > packets,
    asio::yield_context yield)
{
  std::forward_list<asio::mutable_buffer> mbufs;
  auto it = mbufs.before_begin();
  for (auto &packet : packets) {
      auto mbuf = packet->getMutableBuf();
      it = mbufs.insert_after(it, mbuf);
    }
  asio::async_read(stream_, mbufs, yield);
}

void
VirtualNetDev::TunGnuLinuxImpl::async_write(NetPacket &buf,
                                            asio::yield_context yield)
{
  auto cbuf = buf.getConstBuf();
  asio::async_write(stream_, cbuf, yield);
}

void
VirtualNetDev::TunGnuLinuxImpl::async_write(
    std::forward_list<std::shared_ptr<NetPacket> > packets,
    asio::yield_context yield)
{
  std::forward_list<asio::const_buffer> cbufs;
  auto it = cbufs.before_begin();
  for (auto &packet : packets) {
      auto cbuf = packet->getConstBuf();
      it = cbufs.insert_after(it, cbuf);
    }
  asio::async_write(stream_, cbufs, yield);
}

bool
VirtualNetDev::TunGnuLinuxImpl::up()
{
#if 0
  struct ifreq ifr;
  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, stream_.native_handle(), IFNAMSIZ);
  if (ioctl(stream_.native_handle(), SIOCGIFFLAGS, &ifr) < 0)
    return false;

  ifr.ifr_flags |= IFF_UP;
  if (ioctl(stream_.native_handle(), SIOCSIFFLAGS, &ifr) < 0)
    return false;
#endif
  return true;
}

bool
VirtualNetDev::TunGnuLinuxImpl::down()
{
#if 0
  struct ifreq ifr;
  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, stream_.native_handle(), IFNAMSIZ);
  if (ioctl(stream_.native_handle(), SIOCGIFFLAGS, &ifr) < 0)
    return false;

  ifr.ifr_flags &= ~IFF_UP;
  if (ioctl(stream_.native_handle(), SIOCSIFFLAGS, &ifr) < 0)
    return false;
#endif

  return true;
}

#if 0
std::optional<TunGnuLinuxImpl>
VirtualNetDev::TunGnuLinuxImpl::addNode(asio::ip::address_v4 &addr)
{
  TunGnuLinuxImpl node(*this); // Use the copy constructor to create a copy
  node.isMasterNode_ = false;
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
