/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * SPDX-FileCopyrightText: Hsia-Jun(Randy) Li
 */

extern "C"
{
#include "l2_ingress_ring_l4.bpf.h"
#include <bpf/libbpf.h>
}
#include <algorithm>

#include "tc_ingress_ringbuf.hpp"

namespace celaratcp {
namespace netdev {

TcIngressRingbuf::TcIngressRingbuf(std::string_view ebpf_program_path,
                                   int ifindex)
    : bpf_obj_(nullptr), bpf_prog_(nullptr), ifindex_(ifindex),
      v4_tcp_map_mapfd_(-1), v6_tcp_map_mapfd_(-1)
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
  bpf_prog_ = bpf_object__find_program_by_name(obj, "ingress_filter");
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
              .attach_point = BPF_TC_INGRESS, );

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

  v4_tcp_map_mapfd_ = bpf_object__find_map_fd_by_name(obj, "v4_tcp_map_dict");
  if (v4_tcp_map_mapfd_ < 0) {
    bpf_tc_detach(&hook, &opts);
    bpf_tc_hook_destroy(&hook);
    bpf_object__close(obj);
    throw std::logic_error("program TCPv4 table is missing");
  }

  v6_tcp_map_mapfd_ = bpf_object__find_map_fd_by_name(obj, "v6_tcp_map_dict");
  if (v6_tcp_map_mapfd_ < 0) {
    bpf_tc_detach(&hook, &opts);
    bpf_tc_hook_destroy(&hook);
    bpf_object__close(obj);
    throw std::logic_error("program TCPv6 table is missing");
  }
}

TcIngressRingbuf::~TcIngressRingbuf()
{
  if (bpf_prog_) {
    int prog_fd = bpf_program__fd(bpf_prog_);
    if (prog_fd < 0) {
      bpf_object__close(bpf_obj_);
    } else {
      LIBBPF_OPTS(bpf_tc_hook, hook, .ifindex = ifindex_,
                  .attach_point = BPF_TC_INGRESS, );

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
TcIngressRingbuf::GetSupportFilterActions() const
{
  return { FilterAction::TCP_DPORT_FORWARD };
}

bool
TcIngressRingbuf::EnableFilters(std::list<FilterAction> &type)
{
  for (const auto &filter_type : type) {
    switch (filter_type) {
    case FilterAction::TCP_DPORT_FORWARD:
      return true;
    default:
      return false;
    }
  }
  return false;
}

int
TcIngressRingbuf::AddWatchIpv4PortRingbuf(uint_fast16_t port)
{
  for (const auto &p : v4_tcp_maps_list_) {
    if (p.port == port) {
      return p.map_fd;
    }
  }

  std::string map_name = "v4_" + std::to_string(port) + "_rbuf";
  LIBBPF_OPTS(bpf_map_create_opts, opts);

  int mapfd = bpf_map_create(BPF_MAP_TYPE_RINGBUF, map_name.c_str(), 0, 0,
                             sysconf(_SC_PAGE_SIZE) << 9, &opts);

  if (mapfd < 0) {
    return -1;
  }

  LIBBPF_OPTS(ring_buffer_opts, r_opts);
  auto rb = ring_buffer__new(mapfd, nullptr, nullptr, &r_opts);

  uint16_t port_v = static_cast<uint16_t>(port);

  auto ret
      = bpf_map_update_elem(v4_tcp_map_mapfd_, &port_v, &mapfd, BPF_NOEXIST);
  if (ret != 0) {
    return -1;
  }

  PortMapFdPair pair = {
    .port = port,
    .map_fd = mapfd,
  };

  v4_tcp_maps_list_.push_back(pair);

  return mapfd;
}

int
TcIngressRingbuf::AddWatchIpv6PortRingbuf(uint_fast16_t port)
{
  return -1;
}

bool
TcIngressRingbuf::RemoveWatchIpv4Port(uint16_t port)
{
  auto ret = bpf_map_delete_elem_flags(v4_tcp_map_mapfd_, &port, BPF_EXIST);
  if (ret) {
    if (ret == -ENOENT)
      return true;
    return false;
  }

  return true;
}

bool
TcIngressRingbuf::RemoveWatchIpv6Port(uint16_t port)
{
  auto ret = bpf_map_delete_elem_flags(v6_tcp_map_mapfd_, &port, BPF_EXIST);
  if (ret) {
    if (ret == -ENOENT)
      return true;
    return false;
  }

  return true;
}

} // namespace netdev
} // namespace celaratcp
