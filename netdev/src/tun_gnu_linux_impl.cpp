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
    : stream_(io_context), link_(nullptr), ifindex_(-1), isMasterNode_(false),
      isClient_(false)
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

  err = rtnl_link_get_kernel(sk_, ifindex_, nullptr, &link_);
  if (err) {
      nl_socket_free(sk_);
      close(fd);
      throw std::runtime_error("failed to get link");
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

bool
celaratcp::netdev::VirtualNetDev::TunGnuLinuxImpl::attachXdpProgram(
    const std::string &xdp_program_path)
{
  int prog_fd = bpf_obj_get(xdp_program_path.c_str());
  if (prog_fd < 0) {
      perror("Failed to load XDP program");
      return false;
  }

  if (bpf_prog_attach(prog_fd, ifindex_, BPF_XDP, 0) < 0) {
      perror("Failed to attach XDP program");
      close(prog_fd);
      return false;
  }

  return true;
}

bool
celaratcp::netdev::VirtualNetDev::TunGnuLinuxImpl::attachSteeringEbpf(
    const std::string &ebpf_program_path)
{
  // Load the eBPF program
  int prog_fd = bpf_obj_get(ebpf_program_path.c_str());
  if (prog_fd < 0) {
      perror("Failed to load eBPF program");
      return false;
  }

  // Attach the eBPF program to the TUN device using TUNSETSTEERINGEBPF
  if (ioctl(stream_.native_handle(), TUNSETSTEERINGEBPF, prog_fd) < 0) {
      perror("Failed to attach eBPF program with TUNSETSTEERINGEBPF");
      close(prog_fd);
      return false;
  }

  close(prog_fd);
  return true;
}

bool
celaratcp::netdev::VirtualNetDev::TunGnuLinuxImpl::attachFilterEbpf(
    const std::string &ebpf_program_path)
{
  // Load the eBPF program
  int prog_fd = bpf_obj_get(ebpf_program_path.c_str());
  if (prog_fd < 0) {
      perror("Failed to load eBPF program");
      return false;
  }

  if (ioctl(stream_.native_handle(), TUNSETFILTEREBPF, prog_fd) < 0) {
      perror("Failed to attach eBPF program with TUNSETFILTEREBPF");
      close(prog_fd);
      return false;
  }

  close(prog_fd);
  return true;
}

void
VirtualNetDev::TunGnuLinuxImpl::async_read(NetPacket &buf,
                                           callback_t &&callback)
{
  auto mbuf = buf.getMutableBuf();
  asio::async_read(stream_, mbuf, std::move(callback));
}

void
VirtualNetDev::TunGnuLinuxImpl::async_write(NetPacket &buf,
                                            callback_t &&callback)
{
  auto cbuf = buf.getConstBuf();
  asio::async_write(stream_, cbuf, std::move(callback));
}

bool
VirtualNetDev::TunGnuLinuxImpl::up()
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
VirtualNetDev::TunGnuLinuxImpl::down()
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
