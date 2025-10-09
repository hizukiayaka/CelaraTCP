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

#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>

#include "tun_egress.bpf.h"
}

#include "tun_gnu_linux_impl.hpp"

namespace celaratcp {
namespace netdev {

class TunGnuLinuxImpl::TunGnuLinuxDetailImpl : public IPacketFilter
{
private:
  struct nl_sock *sk_;
  struct rtnl_link *link_;
  int ifindex_;

  /* TC egress filter */
  struct bpf_object *filter_obj_;
  struct bpf_program *filter_prog_;

  /* Tun eBPF */
  struct bpf_object *steering_obj_;
  struct bpf_program *steering_prog_;
  struct bpf_object *xmit_filter_obj_;
  struct bpf_program *xmit_filter_prog_;

  /* TC egress filter */
  int filter_map_fd_;
  int services_v4_mapfd_;
  int services_v6_mapfd_;

  struct PeerEntry
  {
    asio::ip::address src_addr;
    std::uint16_t src_port;
  };

  struct PortMapFdPair
  {
    std::uint16_t port;
    int map_fd;
    std::vector<std::optional<PeerEntry> > peers;
  };

  std::list<PortMapFdPair> services_mapfd_v4_list_;
  std::list<PortMapFdPair> services_mapfd_v6_list_;

  int LoadEgressFilterEbpf(std::string_view ebpf_program_path);
  /* TC egress filter end here */

  std::function<bool(unsigned long, int)> on_load_ebpf_callback_;

  bool AttachXdpProgram(std::string_view xdp_program_path);
  bool LoadSteeringEbpf(std::string_view ebpf_program_path);
  int LoadXmitFilterEbpf(std::string_view ebpf_program_path);

public:
  TunGnuLinuxDetailImpl();
  ~TunGnuLinuxDetailImpl() override;

  void
  Initialize(const std::string &intl_name,
             std::function<bool(unsigned long, int)> &&on_load_ebpf_callback);

  void SetIpv4AddressPeer(const asio::ip::address_v4 &addr);
  void SetIpv6AddressPeer(const asio::ip::address_v6 &addr);

  void AddIpv4Address(const asio::ip::address_v4 &addr);
  void AddIpv6Address(const asio::ip::address_v6 &addr);

  bool Up();
  bool Down();

  std::list<NetDevFiltertype> GetSupportFilterType() const override;
  bool LoadFilter() override;
  bool SetNetDevFilterType(std::list<NetDevFiltertype> type) override;
  bool AddWatchIpv4Port(uint16_t port) override;
  bool AddWatchIpv6Port(uint16_t port) override;
  bool RemoveWatchIpv4Port(uint16_t port) override;
  bool RemoveWatchIpv6Port(uint16_t port) override;
  bool AddPeerNode(const asio::ip::address &addr, uint16_t src_port,
                   uint16_t dst_port) override;
  bool RemovePeerNode(const asio::ip::address &addr, uint16_t src_port,
                      uint16_t dst_port) override;

  TunGnuLinuxDetailImpl(const TunGnuLinuxDetailImpl &other) = delete;
  TunGnuLinuxDetailImpl &operator=(const TunGnuLinuxDetailImpl &other)
      = delete;
  TunGnuLinuxDetailImpl(TunGnuLinuxDetailImpl &&other) = delete;
  TunGnuLinuxDetailImpl &operator=(TunGnuLinuxDetailImpl &&other) = delete;
};

TunGnuLinuxImpl::TunGnuLinuxDetailImpl::TunGnuLinuxDetailImpl()
    : sk_(nullptr), link_(nullptr), ifindex_(-1), filter_obj_(nullptr),
      filter_prog_(nullptr), steering_obj_(nullptr), steering_prog_(nullptr),
      xmit_filter_obj_(nullptr), xmit_filter_prog_(nullptr),
      filter_map_fd_(-1), services_v4_mapfd_(-1), services_v6_mapfd_(-1)
{
}

TunGnuLinuxImpl::TunGnuLinuxDetailImpl::~TunGnuLinuxDetailImpl()
{
  nl_socket_free(sk_);

  if (filter_prog_) {
    int prog_fd = bpf_program__fd(filter_prog_);
    if (prog_fd < 0) {
      bpf_object__close(filter_obj_);
    } else {
      LIBBPF_OPTS(bpf_tc_hook, hook, .ifindex = ifindex_,
                  .attach_point = BPF_TC_EGRESS, );

      LIBBPF_OPTS(bpf_tc_opts, opts, .prog_fd = prog_fd,
                  .flags = BPF_TC_F_REPLACE, .handle = 1, .priority = 1, );

      bpf_tc_detach(&hook, &opts);
      bpf_tc_hook_destroy(&hook);
    }
  }

  if (filter_obj_)
    bpf_object__close(filter_obj_);

  if (steering_obj_)
    bpf_object__close(steering_obj_);

  if (xmit_filter_obj_)
    bpf_object__close(xmit_filter_obj_);
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

  auto peer = asio::ip::make_address_v4(n + 1);
  addr_d = peer.to_bytes();
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
  /* FIXME: calculate IPv6 Peer address */
  if (rtnl_addr_add(sk_, rt_addr, 0)) {
    nl_addr_put(local_addr);
    rtnl_addr_put(rt_addr);
    throw std::runtime_error("can't set addr");
  }
  nl_addr_put(local_addr);
  rtnl_addr_put(rt_addr);
}

void
TunGnuLinuxImpl::TunGnuLinuxDetailImpl::AddIpv4Address(
    const asio::ip::address_v4 &addr)
{
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

void
TunGnuLinuxImpl::TunGnuLinuxDetailImpl::AddIpv6Address(
    const asio::ip::address_v6 &addr)
{
  auto addr_d = addr.to_bytes();
  struct nl_addr *local_addr
      = nl_addr_build(AF_INET6, addr_d.data(), addr_d.size());
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
TunGnuLinuxImpl::TunGnuLinuxDetailImpl::AttachXdpProgram(
    std::string_view xdp_program_path)
{
  int prog_fd = bpf_obj_get(xdp_program_path.data());
  if (prog_fd < 0) {
    return false;
  }

  if (bpf_prog_attach(prog_fd, ifindex_, BPF_XDP, 0) < 0) {
    close(prog_fd);
    return false;
  }

  return true;
}

bool
TunGnuLinuxImpl::TunGnuLinuxDetailImpl::LoadSteeringEbpf(
    std::string_view ebpf_program_path)
{
  struct bpf_object *obj
      = bpf_object__open_file(ebpf_program_path.data(), nullptr);
  if (!obj) {
    return false;
  }

  if (bpf_object__load(obj)) {
    bpf_object__close(obj);
    return false;
  }

  steering_obj_ = obj;
  steering_prog_ = bpf_object__find_program_by_name(obj, "socket_handler");
  if (!steering_prog_) {
    steering_obj_ = nullptr;
    bpf_object__close(obj);
    return false;
  }

  int prog_fd = bpf_program__fd(steering_prog_);
  if (prog_fd < 0) {
    steering_obj_ = nullptr;
    steering_prog_ = nullptr;
    bpf_object__close(obj);
    return false;
  }

  if (!on_load_ebpf_callback_(TUNSETSTEERINGEBPF, prog_fd)) {
    bpf_object__close(obj);
    steering_obj_ = nullptr;
    steering_prog_ = nullptr;
    return false;
  }

  return true;
}

int
TunGnuLinuxImpl::TunGnuLinuxDetailImpl::LoadXmitFilterEbpf(
    std::string_view ebpf_program_path)
{
  struct bpf_object *obj
      = bpf_object__open_file(ebpf_program_path.data(), nullptr);
  if (!obj) {
    return false;
  }

  if (bpf_object__load(obj)) {
    bpf_object__close(obj);
    return false;
  }

  xmit_filter_obj_ = obj;
  xmit_filter_prog_ = bpf_object__find_program_by_name(obj, "socket_handler");
  if (!xmit_filter_prog_) {
    bpf_object__close(obj);
    xmit_filter_obj_ = nullptr;
    return false;
  }

  int prog_fd = bpf_program__fd(xmit_filter_prog_);
  if (prog_fd < 0) {
    xmit_filter_prog_ = nullptr;
    xmit_filter_obj_ = nullptr;
    bpf_object__close(obj);
    return false;
  }

  if (!on_load_ebpf_callback_(TUNSETFILTEREBPF, prog_fd)) {
    xmit_filter_prog_ = nullptr;
    xmit_filter_obj_ = nullptr;
    bpf_object__close(obj);
    return false;
  }

  return true;
}

std::list<NetDevFiltertype>
TunGnuLinuxImpl::TunGnuLinuxDetailImpl::GetSupportFilterType() const
{
  return { NetDevFiltertype::DROP_IPV4, NetDevFiltertype::DROP_IPV6,
           NetDevFiltertype::DROP_UDP, NetDevFiltertype::ACCEPT_4_TUPLE };
}

bool
TunGnuLinuxImpl::TunGnuLinuxDetailImpl::LoadFilter()
{
#ifndef EBPF_OBJECT_DIR
#error "EBPF_OBJECT_DIR must be defined by the build system"
#endif
  constexpr std::string_view obj_path = EBPF_OBJECT_DIR "/tun_egress.o";
  return LoadEgressFilterEbpf(obj_path);
}

bool
TunGnuLinuxImpl::TunGnuLinuxDetailImpl::SetNetDevFilterType(
    std::list<NetDevFiltertype> type)
{
  if (filter_map_fd_ < 0) {
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
    case NetDevFiltertype::DROP_UDP:
      value.drop_non_tcp = 1;
      break;
    case NetDevFiltertype::ACCEPT_4_TUPLE:
      value.drop_nomatch_tcp = 1;
      break;
    default:
      return false;
    }
  }
  int key = 0;
  if (bpf_map_update_elem(filter_map_fd_, &key, &value, BPF_ANY) != 0) {
    return false;
  }

  return true;
}

bool
TunGnuLinuxImpl::TunGnuLinuxDetailImpl::AddWatchIpv4Port(uint16_t port)
{
  if (services_v4_mapfd_ < 0) {
    return false;
  }
  for (const auto &pair : services_mapfd_v4_list_) {
    if (pair.port == port) {
      return true; // Already exists
    }
  }
#if 1
  std::string map_name = "port_ipv4_" + std::to_string(port);
  int inner_map_fd = bpf_map_create(
      BPF_MAP_TYPE_ARRAY, map_name.c_str(), sizeof(__u32),
      sizeof(struct peer_value_v4), PER_SERVICE_MAX_CONNECTION, 0);
  if (inner_map_fd < 0) {
    return false;
  }

  auto ret
      = bpf_map_update_elem(services_v4_mapfd_, &port, &inner_map_fd, BPF_ANY);
  if (ret != 0) {
    close(inner_map_fd);
    return false;
  }
#else
  struct bpf_map_info o = { 0 };
  __u32 olen = sizeof(o);
  if (bpf_obj_get_info_by_fd(services_v4_mapfd_, &o, &olen) < 0) {
    return false;
  }

  int tmpl_fd
      = bpf_object__find_map_fd_by_name(filter_obj_, "peers_v4_inner_map");
  struct bpf_map_info t = { 0 };
  __u32 tlen = sizeof(t);
  if (bpf_obj_get_info_by_fd(tmpl_fd, &t, &tlen) < 0) {
    close(tmpl_fd);
    return false;
  }
  close(tmpl_fd);

  struct btf *btf = bpf_object__btf(filter_obj_);
  int btf_fd = btf__fd(btf);

  LIBBPF_OPTS(bpf_map_create_opts, opts, .btf_fd = btf_fd,
              .btf_key_type_id = t.btf_key_type_id,
              .btf_value_type_id = t.btf_value_type_id,
              .map_flags = (t.map_flags & ~BPF_F_INNER_MAP));
  std::string map_name = "svc_ipv4_" + std::to_string(port);
  int inner_map_fd
      = bpf_map_create((enum bpf_map_type)t.type, map_name.c_str(), t.key_size,
                       t.value_size, PER_SERVICE_MAX_CONNECTION, &opts);

  if (inner_map_fd < 0) {
    return false;
  }

  __u32 val_fd = (__u32)inner_map_fd;
  auto ret = bpf_map_update_elem(services_v4_mapfd_, &port, &val_fd, BPF_ANY);
  if (ret != 0) {
    close(inner_map_fd);
    return false;
  }

#endif
  PortMapFdPair pair = { port, inner_map_fd, {} };
  services_mapfd_v4_list_.push_back(pair);

  return true;
}

bool
TunGnuLinuxImpl::TunGnuLinuxDetailImpl::AddWatchIpv6Port(uint16_t port)
{
  if (services_v6_mapfd_ < 0) {
    return false;
  }
  for (const auto &pair : services_mapfd_v6_list_) {
    if (pair.port == port) {
      return true; // Already exists
    }
  }

  std::string map_name = "port_ipv6_" + std::to_string(port);
  int inner_map_fd = bpf_map_create(
      BPF_MAP_TYPE_ARRAY, map_name.c_str(), sizeof(__u32),
      sizeof(struct peer_value_v6), PER_SERVICE_MAX_CONNECTION, nullptr);
  if (inner_map_fd < 0) {
    return false;
  }
  if (bpf_map_update_elem(services_v6_mapfd_, &port, &inner_map_fd, BPF_ANY)
      != 0)
  {
    close(inner_map_fd);
    return false;
  }
  PortMapFdPair pair = { port, inner_map_fd, {} };
  services_mapfd_v6_list_.push_back(pair);

  return true;
}

bool
TunGnuLinuxImpl::TunGnuLinuxDetailImpl::RemoveWatchIpv4Port(uint16_t port)
{
  if (services_v4_mapfd_ < 0) {
    return false;
  }
  auto it = std::remove_if(
      services_mapfd_v4_list_.begin(), services_mapfd_v4_list_.end(),
      [port](const PortMapFdPair &pair) { return pair.port == port; });
  if (it != services_mapfd_v4_list_.end()) {
    bpf_map_delete_elem(services_v4_mapfd_, &port);
    close(it->map_fd);
    services_mapfd_v4_list_.erase(it, services_mapfd_v4_list_.end());
    return true;
  }
  return false;
}

bool
TunGnuLinuxImpl::TunGnuLinuxDetailImpl::RemoveWatchIpv6Port(uint16_t port)
{
  if (services_v6_mapfd_ < 0) {
    return false;
  }

  auto it = std::remove_if(
      services_mapfd_v6_list_.begin(), services_mapfd_v6_list_.end(),
      [port](const PortMapFdPair &pair) { return pair.port == port; });
  if (it != services_mapfd_v6_list_.end()) {
    bpf_map_delete_elem(services_v6_mapfd_, &port);
    close(it->map_fd);
    services_mapfd_v6_list_.erase(it, services_mapfd_v6_list_.end());
    return true;
  }
  return false;
}

bool
TunGnuLinuxImpl::TunGnuLinuxDetailImpl::AddPeerNode(
    const asio::ip::address &addr, uint16_t src_port, uint16_t dst_port)
{
  constexpr size_t MAX_PEERS
      = 64; // or use PER_SERVICE_MAX_CONNECTION if defined
  if (addr.is_v4()) {
    if (services_v4_mapfd_ < 0) {
      return false;
    }
    // Find the map_fd for the given dst_port
    auto it = std::find_if(services_mapfd_v4_list_.begin(),
                           services_mapfd_v4_list_.end(),
                           [dst_port](const PortMapFdPair &pair) {
                             return pair.port == dst_port;
                           });

    if (it == services_mapfd_v4_list_.end()) {
      return false;
    }

    int map_fd = it->map_fd;
    if (map_fd < 0)
      return false;

    PeerEntry peer{ addr, src_port };
    auto &peers = it->peers;
    // Find empty slot or existing peer
    auto found = std::find_if(peers.begin(), peers.end(),
                              [&](const std::optional<PeerEntry> &p) {
                                return p && p->src_addr == peer.src_addr
                                       && p->src_port == peer.src_port;
                              });
    if (found == peers.end()) {
      // Try to reuse an empty slot
      auto empty = std::find_if(
          peers.begin(), peers.end(),
          [](const std::optional<PeerEntry> &p) { return !p.has_value(); });
      uint32_t idx;
      if (empty != peers.end()) {
        idx = std::distance(peers.begin(), empty);
        *empty = peer;
      } else if (peers.size() < MAX_PEERS) {
        idx = peers.size();
        peers.push_back(peer);
      } else {
        // No available slot
        return false;
      }
      auto bytes = peer.src_addr.to_v4().to_bytes();
      uint32_t ip;
      std::memcpy(&ip, bytes.data(), 4);
      struct peer_value_v4 val = { ip, peer.src_port };
      bpf_map_update_elem(map_fd, &idx, &val, BPF_ANY);
    }
  } else if (addr.is_v6()) {
    if (services_v6_mapfd_ < 0) {
      return false;
    }

    // Find empty slot or existing peer
    auto it = std::find_if(services_mapfd_v6_list_.begin(),
                           services_mapfd_v6_list_.end(),
                           [dst_port](const PortMapFdPair &pair) {
                             return pair.port == dst_port;
                           });

    if (it == services_mapfd_v6_list_.end()) {
      return false;
    }

    int map_fd = it->map_fd;
    if (map_fd < 0)
      return false;

    PeerEntry peer{ addr, src_port };
    auto &peers = it->peers;
    // Find empty slot or existing peer
    auto found = std::find_if(peers.begin(), peers.end(),
                              [&](const std::optional<PeerEntry> &p) {
                                return p && p->src_addr == peer.src_addr
                                       && p->src_port == peer.src_port;
                              });
    if (found == peers.end()) {
      auto empty = std::find_if(
          peers.begin(), peers.end(),
          [](const std::optional<PeerEntry> &p) { return !p.has_value(); });
      uint32_t idx;
      if (empty != peers.end()) {
        idx = std::distance(peers.begin(), empty);
        *empty = peer;
      } else if (peers.size() < MAX_PEERS) {
        idx = peers.size();
        peers.push_back(peer);
      } else {
        // No available slot
        return false;
      }
      struct peer_value_v6 val = {};
      auto bytes6 = peer.src_addr.to_v6().to_bytes();
      std::copy(bytes6.begin(), bytes6.end(), val.src_ip);
      val.src_port = peer.src_port;
      bpf_map_update_elem(map_fd, &idx, &val, BPF_ANY);
    }
  }
  return false;
}

bool
TunGnuLinuxImpl::TunGnuLinuxDetailImpl::RemovePeerNode(
    const asio::ip::address &addr, uint16_t src_port, uint16_t dst_port)
{
  if (addr.is_v4()) {
    if (services_v4_mapfd_ < 0) {
      return false;
    }
    // Find the map_fd for the given dst_port
    auto it = std::find_if(services_mapfd_v4_list_.begin(),
                           services_mapfd_v4_list_.end(),
                           [dst_port](const PortMapFdPair &pair) {
                             return pair.port == dst_port;
                           });

    if (it == services_mapfd_v4_list_.end()) {
      return false;
    }

    int map_fd = it->map_fd;
    if (map_fd < 0)
      return false;

    PeerEntry peer{ addr, src_port };
    auto &peers = it->peers;
    auto found = std::find_if(peers.begin(), peers.end(),
                              [&](const std::optional<PeerEntry> &p) {
                                return p && p->src_addr == peer.src_addr
                                       && p->src_port == peer.src_port;
                              });

    if (found != peers.end()) {
      peers.erase(found);
      uint32_t idx = std::distance(peers.begin(), found);
      bpf_map_delete_elem(map_fd, &idx);
      return true;
    }
  } else if (addr.is_v6()) {
    if (services_v6_mapfd_ < 0) {
      return false;
    }

    // Find empty slot or existing peer
    auto it = std::find_if(services_mapfd_v6_list_.begin(),
                           services_mapfd_v6_list_.end(),
                           [dst_port](const PortMapFdPair &pair) {
                             return pair.port == dst_port;
                           });

    if (it == services_mapfd_v6_list_.end()) {
      return false;
    }

    int map_fd = it->map_fd;
    if (map_fd < 0)
      return false;

    PeerEntry peer{ addr, src_port };
    auto &peers = it->peers;
    auto found = std::find_if(
        peers.begin(), peers.end(), [&](const std::optional<PeerEntry> &p) {
          return p->src_addr == peer.src_addr && p->src_port == peer.src_port;
        });
    if (found != peers.end()) {
      peers.erase(found);
      uint32_t idx = std::distance(peers.begin(), found);
      bpf_map_delete_elem(map_fd, &idx);
      return true;
    }
  }
  return false;
}

int
TunGnuLinuxImpl::TunGnuLinuxDetailImpl::LoadEgressFilterEbpf(
    std::string_view ebpf_program_path)
{
  struct bpf_object *obj
      = bpf_object__open_file(ebpf_program_path.data(), nullptr);
  if (!obj) {
    return false;
  }

  if (bpf_object__load(obj)) {
    bpf_object__close(obj);
    return false;
  }

  filter_obj_ = obj;
  filter_prog_ = bpf_object__find_program_by_name(obj, "egress_filter");
  if (!filter_prog_) {
    bpf_object__close(obj);
    return false;
  }

  int prog_fd = bpf_program__fd(filter_prog_);
  if (prog_fd < 0) {
    bpf_object__close(obj);
    return false;
  }

  LIBBPF_OPTS(bpf_tc_hook, hook, .ifindex = ifindex_,
              .attach_point = BPF_TC_EGRESS, );

  int err = bpf_tc_hook_create(&hook);
  if (err && err != -EEXIST) {
    bpf_object__close(obj);
    return false;
  }

  LIBBPF_OPTS(bpf_tc_opts, opts, .prog_fd = prog_fd, .flags = BPF_TC_F_REPLACE,
              .handle = 1, .priority = 1, );

  err = bpf_tc_attach(&hook, &opts);
  if (err) {
    bpf_tc_hook_destroy(&hook);
    bpf_object__close(obj);
    return false;
  }

  filter_map_fd_ = bpf_object__find_map_fd_by_name(obj, "filter_list");
  if (filter_map_fd_ < 0) {
    bpf_tc_detach(&hook, &opts);
    bpf_tc_hook_destroy(&hook);
    bpf_object__close(obj);
    return false;
  }

  services_v4_mapfd_
      = bpf_object__find_map_fd_by_name(obj, "services_v4_list");
  if (services_v4_mapfd_ < 0) {
    bpf_tc_detach(&hook, &opts);
    bpf_tc_hook_destroy(&hook);
    bpf_object__close(obj);
    return false;
  }

  services_v6_mapfd_
      = bpf_object__find_map_fd_by_name(obj, "services_v6_list");
  if (services_v6_mapfd_ < 0) {
    bpf_tc_detach(&hook, &opts);
    bpf_tc_hook_destroy(&hook);
    bpf_object__close(obj);
    return false;
  }

  return true;
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

TunGnuLinuxImpl::
operator IPacketFilter *()
{
  return pImpl_.get();
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
