/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * SPDX-FileCopyrightText: Hsia-Jun(Randy) Li
 */

extern "C"
{
#include <bpf/libbpf.h>

#include "tun_egress.bpf.h"
}
#include <algorithm>

#include "tc_egress_filter.hpp"

namespace celaratcp {
namespace netdev {

TcEgressFilter::TcEgressFilter(std::string_view ebpf_program_path, int ifindex)
    : bpf_obj_(nullptr), bpf_prog_(nullptr), ifindex_(ifindex),
      filter_mapfd_(-1), services_v4_mapfd_(-1), services_v6_mapfd_(-1),
      services_mapfd_v4_list_{}, services_mapfd_v6_list_{}
{
  struct bpf_object *obj
      = bpf_object__open_file(ebpf_program_path.data(), nullptr);
  if (!obj)
    throw std::logic_error("can't open such object");

  if (bpf_object__load(obj)) {
    bpf_object__close(obj);
    throw std::logic_error("kernel rejected obj");
  }

  bpf_obj_ = obj;
  bpf_prog_ = bpf_object__find_program_by_name(obj, "egress_filter");
  if (!bpf_prog_) {
    bpf_object__close(obj);
    throw std::logic_error("can't find the handler");
  }

  int prog_fd = bpf_program__fd(bpf_prog_);
  if (prog_fd < 0) {
    bpf_object__close(obj);
    throw std::logic_error("invalid program");
  }

  LIBBPF_OPTS(bpf_tc_hook, hook, .ifindex = ifindex,
              .attach_point = BPF_TC_EGRESS, );

  int err = bpf_tc_hook_create(&hook);
  if (err && err != -EEXIST) {
    bpf_object__close(obj);
    throw std::logic_error("can't create a tc hook");
  }

  LIBBPF_OPTS(bpf_tc_opts, opts, .prog_fd = prog_fd, .flags = BPF_TC_F_REPLACE,
              .handle = 1, .priority = 1, );

  err = bpf_tc_attach(&hook, &opts);
  if (err) {
    bpf_tc_hook_destroy(&hook);
    bpf_object__close(obj);
    throw std::logic_error("can't attach the tc hook");
  }

  filter_mapfd_ = bpf_object__find_map_fd_by_name(obj, "filter_list");
  if (filter_mapfd_ < 0) {
    bpf_tc_detach(&hook, &opts);
    bpf_tc_hook_destroy(&hook);
    bpf_object__close(obj);
    throw std::logic_error("program cfg table is missing");
  }

  services_v4_mapfd_
      = bpf_object__find_map_fd_by_name(obj, "services_v4_list");
  if (services_v4_mapfd_ < 0) {
    bpf_tc_detach(&hook, &opts);
    bpf_tc_hook_destroy(&hook);
    bpf_object__close(obj);
    throw std::logic_error("program 2nd cfg table is missing");
  }

  services_v6_mapfd_
      = bpf_object__find_map_fd_by_name(obj, "services_v6_list");
  if (services_v6_mapfd_ < 0) {
    bpf_tc_detach(&hook, &opts);
    bpf_tc_hook_destroy(&hook);
    bpf_object__close(obj);
    throw std::logic_error("program 2nd cfg table is missing");
  }
}

TcEgressFilter::~TcEgressFilter()
{

  if (bpf_prog_) {
    int prog_fd = bpf_program__fd(bpf_prog_);
    if (prog_fd < 0) {
      bpf_object__close(bpf_obj_);
    } else {
      LIBBPF_OPTS(bpf_tc_hook, hook, .ifindex = ifindex_,
                  .attach_point = BPF_TC_EGRESS, );

      LIBBPF_OPTS(bpf_tc_opts, opts, .prog_fd = prog_fd,
                  .flags = BPF_TC_F_REPLACE, .handle = 1, .priority = 1, );

      bpf_tc_detach(&hook, &opts);
      bpf_tc_hook_destroy(&hook);
    }
  }

  if (bpf_obj_)
    bpf_object__close(bpf_obj_);
}

std::list<FilterAction>
TcEgressFilter::GetSupportFilterActions() const
{
  return { FilterAction::DROP_IPV4, FilterAction::DROP_IPV6,
           FilterAction::ACCEPT_TCP_ONLY, FilterAction::ACCEPT_4_TUPLE };
}

bool
TcEgressFilter::EnableFilters(std::list<FilterAction> &type)
{
  struct filter_list_value value = {};
  for (const auto &filter_type : type) {
    switch (filter_type) {
    case FilterAction::DROP_IPV4:
      value.drop_ipv4 = 1;
      break;
    case FilterAction::DROP_IPV6:
      value.drop_ipv6 = 1;
      break;
    case FilterAction::ACCEPT_TCP_ONLY:
      value.drop_non_tcp = 1;
      break;
    case FilterAction::ACCEPT_4_TUPLE:
      value.drop_nomatch_tcp = 1;
      break;
    default:
      return false;
    }
  }
  int key = 0;
  if (bpf_map_update_elem(filter_mapfd_, &key, &value, BPF_ANY) != 0) {
    return false;
  }

  return true;
}

bool
TcEgressFilter::AddWatchIpv4Port(uint16_t port)
{
  for (const auto &pair : services_mapfd_v4_list_) {
    if (pair.port == port) {
      return true; // Already exists
    }
  }
  std::string map_name = "port_ipv4_" + std::to_string(port);

  LIBBPF_OPTS(bpf_map_create_opts, opts, .map_flags = BPF_F_INNER_MAP);

  int inner_map_fd = bpf_map_create(
      BPF_MAP_TYPE_ARRAY, map_name.c_str(), sizeof(__u32),
      sizeof(struct peer_value_v4), PER_SERVICE_MAX_CONNECTION, &opts);
  if (inner_map_fd < 0)
    return false;

  auto ret
      = bpf_map_update_elem(services_v4_mapfd_, &port, &inner_map_fd, BPF_ANY);
  if (ret != 0) {
    close(inner_map_fd);
    return false;
  }

  PortMapFdPair pair = { port, inner_map_fd, {} };
  services_mapfd_v4_list_.push_back(pair);

  return true;
}

bool
TcEgressFilter::AddWatchIpv6Port(uint16_t port)
{
  for (const auto &pair : services_mapfd_v6_list_) {
    if (pair.port == port) {
      return true; // Already exists
    }
  }

  std::string map_name = "port_ipv6_" + std::to_string(port);

  LIBBPF_OPTS(bpf_map_create_opts, opts, .map_flags = BPF_F_INNER_MAP);

  int inner_map_fd = bpf_map_create(
      BPF_MAP_TYPE_ARRAY, map_name.c_str(), sizeof(__u32),
      sizeof(struct peer_value_v6), PER_SERVICE_MAX_CONNECTION, &opts);
  if (inner_map_fd < 0)
    return false;

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
TcEgressFilter::RemoveWatchIpv4Port(uint16_t port)
{
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
TcEgressFilter::RemoveWatchIpv6Port(uint16_t port)
{
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
TcEgressFilter::AddPeerNode(const asio::ip::address &addr, uint16_t src_port,
                            uint16_t dst_port)
{
  constexpr size_t kMaxPeers = PER_SERVICE_MAX_CONNECTION;
  if (addr.is_v4()) {
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
      } else if (peers.size() < kMaxPeers) {
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
      } else if (peers.size() < kMaxPeers) {
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
TcEgressFilter::RemovePeerNode(const asio::ip::address &addr,
                               uint16_t src_port, uint16_t dst_port)
{
  if (addr.is_v4()) {
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

} // namespace netdev
} // namespace celaratcp
