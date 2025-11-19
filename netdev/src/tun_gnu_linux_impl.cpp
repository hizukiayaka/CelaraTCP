/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * SPDX-FileCopyrightText: Hsia-Jun(Randy) Li
 */

extern "C" {
#include "ebpf/xmit_filter.bpf.h"
}

namespace celaratcp {
namespace netdev {

VirtualNetDev::TunGnuLinuxImpl::~TunGnuLinuxImpl()
{
  nl_socket_free(sk_);
  stream_.close();

  if (filter_obj_)
    bpf_object__close(filter_obj_);
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
VirtualNetDev::TunGnuLinuxImpl::attachXdpProgram(
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
VirtualNetDev::TunGnuLinuxImpl::attachSteeringEbpf(
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

bool VirtualNetDev::TunGnuLinuxImpl::setNetDevFilterType(std::list<NetDevFiltertype> type)
{
  if (filter_map_fd_ < 0) {
      fprintf(stderr, "Filter map fd is not set\n");
      return false;
  }

  struct filter_list_value value = {};
  for (const auto &filter_type : type) {
      switch (filter_type) {
          case NetDevFiltertype::DROP_IPV4:
              value.drop_ipv4 = 1;
              break;
          case NetDevFiltertype::DROP_IPV6:
              value.drop_ipv6 = 1;
              break;
          case NetDevFiltertype::DROP_DEST_IP_PORT:
              value.drop_nomatch_tcp = 1;
              break;
          default:
              fprintf(stderr, "Unknown filter type\n");
              return false;
      }
  }
      int key = 0;
      if (bpf_map_update_elem(filter_map_fd_, &key, &value, BPF_ANY) != 0) {
          perror("bpf_map_update_elem failed");
          return false;
      }

  return true;
}

bool VirtualNetDev::TunGnuLinuxImpl::addWatchIpv4Port(uint16_t port)
{
  if (services_v4_mapfd_ < 0) {
      fprintf(stderr, "Services v4 map fd is not set\n");
      return false;
  }
  for (const auto &pair : services_mapfd_v4_list_) {
      if (pair.port == port) {
          return true; // Already exists
      }
  }
  std::string map_name = "port_ipv4_" + std::to_string(port);
  int inner_map_fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, map_name.c_str(), sizeof(__u32), sizeof(struct peer_value_v4), PER_SERVICE_MAX_CONNECTION, 0);
  if (inner_map_fd < 0) {
      fprintf(stderr, "Failed to create v4 inner map for port %u\n", port);
      return false;
  }
  if (bpf_map_update_elem(services_v4_mapfd_, &port, &inner_map_fd, BPF_ANY) != 0) {
      fprintf(stderr, "Failed to insert v4 inner map fd into outer map for port %u\n", port);
      close(inner_map_fd);
      return false;
  }
  PortMapFdPair pair = {port, inner_map_fd};
  services_mapfd_v4_list_.push_back(pair);

  return true;
}

bool VirtualNetDev::TunGnuLinuxImpl::addWatchIpv6Port(uint16_t port)
{
  if (services_v6_mapfd_ < 0) {
      fprintf(stderr, "Services v6 map fd is not set\n");
      return false;
  }
  for (const auto &pair : services_mapfd_v6_list_) {
      if (pair.port == port) {
          return true; // Already exists
      }
  }

  std::string map_name = "port_ipv6_" + std::to_string(port);
  int inner_map_fd = bpf_create_map(BPF_MAP_TYPE_ARRAY, map_name.c_str(), sizeof(__u32), sizeof(struct peer_value_v6), PER_SERVICE_MAX_CONNECTION, 0);
  if (inner_map_fd < 0) {
      return false;
  }
  if (bpf_map_update_elem(services_v6_mapfd_, &port, &inner_map_fd, BPF_ANY) != 0) {
      close(inner_map_fd);
      return false;
  }
  PortMapFdPair pair = {port, inner_map_fd};
  services_mapfd_v6_list_.push_back(pair);

  return true;
}

bool VirtualNetDev::TunGnuLinuxImpl::addPeerNode(const asio::ip::address &addr, uint16_t src_port,
                   uint16_t dst_port)
{
  if (addr.is_v4()) {
      if (services_v4_mapfd_ < 0) {
          return false;
      }
      // Find the map_fd for the given dst_port
      int map_fd = -1;
      auto it = services_mapfd_v4_list_.end();
      for (auto iter = services_mapfd_v4_list_.begin(); iter != services_mapfd_v4_list_.end(); ++iter) {
          if (iter->port == dst_port) {
              map_fd = iter->map_fd;
              it = iter;
              break;
          }
      }
      if (map_fd < 0 || it == services_mapfd_v4_list_.end()) {
          return false;
      }
      PeerEntry peer{addr, src_port};
      auto &peers = it->peers;
      auto found = std::find_if(peers.begin(), peers.end(), [&](const PeerEntry &p) {
        return p.src_addr == peer.src_addr && p.src_port == peer.src_port;
      });

      if (found == peers.end()) {
        uint32_t idx = peers.size();
        peers.push_back(peer);
        struct peer_value_v4 val = {peer.src_ip, peer.src_port};
        bpf_map_update_elem(map_fd, &idx, &val, BPF_ANY);
      }
  } else if (addr.is_v6()) {
      if (services_v6_mapfd_ < 0) {
          fprintf(stderr, "Services v6 map fd is not set\n");
          return false;
      }
      int map_fd = -1;
      auto it = services_mapfd_v6_list_.end();
      for (auto iter = services_mapfd_v6_list_.begin(); iter != services_mapfd_v6_list_.end(); ++iter) {
          if (iter->port == dst_port) {
              map_fd = iter->map_fd;
              it = iter;
              break;
          }
      }
      if (map_fd < 0 || it == services_mapfd_v6_list_.end()) {
          fprintf(stderr, "No map fd found for dport %u\n", dst_port);
          return false;
      }
      PeerEntry peer{addr, src_port};

      auto &peers = it->peers;
      auto found = std::find_if(peers.begin(), peers.end(), [&](const PeerEntryV6 &p) {
        return p.src_addr == peer.src_addr && p.src_port == peer.src_port;
      });

      if (found == peers.end()) {
        uint32_t idx = peers.size();
        peers.push_back(peer);
        struct peer_value_v6 val = {};
        std::copy(peer.src_ip.begin(), peer.src_ip.end(), val.src_ip);
        val.src_port = peer.src_port;
        bpf_map_update_elem(map_fd, &idx, &val, BPF_ANY);
      }
  } else {
      return false;
  }
  return true;
}

bool
VirtualNetDev::TunGnuLinuxImpl::attachFilterEbpf(
    const std::string &ebpf_program_path)
{
    struct bpf_object *obj = bpf_object__open_file(ebpf_program_path.c_str(), nullptr);
    if (!obj) {
        fprintf(stderr, "Failed to open eBPF object file\n");
        return false;
    }
    if (bpf_object__load(obj)) {
        fprintf(stderr, "Failed to load eBPF object\n");
        bpf_object__close(obj);
        return false;
    }

    filter_obj_ = obj;
    filter_prog_ = bpf_object__find_program_by_name(obj, "socket_handler");
    if (!filter_prog_) {
        fprintf(stderr, "Failed to find eBPF program by name\n");
        bpf_object__close(obj);
        return false;
    }

    int prog_fd = bpf_program__fd(filter_prog_);
    if (prog_fd < 0) {
        fprintf(stderr, "Failed to get program fd\n");
        bpf_object__close(obj);
        return false;
    }

    if (ioctl(stream_.native_handle(), TUNSETFILTEREBPF, prog_fd) < 0) {
        perror("Failed to attach eBPF program with TUNSETFILTEREBPF");
        bpf_object__close(obj);
        return false;
    }

    filter_map_fd_ = bpf_object__find_map_fd_by_name(obj, "filter_list");
    if (filter_map_fd_ < 0) {
        fprintf(stderr, "Failed to find map fd by name\n");
        bpf_object__close(obj);
        return false;
    }

    services_v4_mapfd_ = bpf_object__find_map_fd_by_name(obj, "services_v4_list");
    if (services_v4_mapfd_ < 0) {
        fprintf(stderr, "Failed to find services_v4_list map fd\n");
        bpf_object__close(obj);
        return false;
    }
    services_v6_mapfd_ = bpf_object__find_map_fd_by_name(obj, "services_v6_list");
    if (services_v6_mapfd_ < 0) {
        fprintf(stderr, "Failed to find services_v6_list map fd\n");
        bpf_object__close(obj);
        return false;
    }

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
