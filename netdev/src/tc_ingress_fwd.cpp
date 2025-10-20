/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * SPDX-FileCopyrightText: Hsia-Jun(Randy) Li
 */

extern "C"
{
#include <bpf/libbpf.h>
}
#include <algorithm>

#include "tc_ingress_fwd.hpp"

namespace celaratcp {
namespace netdev {

TcIngressFwd::TcIngressFwd(std::string_view ebpf_program_path, int ifindex)
    : bpf_obj_(nullptr), bpf_prog_(nullptr), ifindex_(ifindex),
      v4_fwd_dict_mapfd_(-1), v6_fwd_dict_mapfd_(-1)
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

  v4_fwd_dict_mapfd_ = bpf_object__find_map_fd_by_name(obj, "v4_tcp_fwd_dict");
  if (v4_fwd_dict_mapfd_ < 0) {
    bpf_tc_detach(&hook, &opts);
    bpf_tc_hook_destroy(&hook);
    bpf_object__close(obj);
    throw std::logic_error("program TCPv4 table is missing");
  }

  v6_fwd_dict_mapfd_ = bpf_object__find_map_fd_by_name(obj, "v6_tcp_fwd_dict");
  if (v6_fwd_dict_mapfd_ < 0) {
    bpf_tc_detach(&hook, &opts);
    bpf_tc_hook_destroy(&hook);
    bpf_object__close(obj);
    throw std::logic_error("program TCPv6 table is missing");
  }
}

TcIngressFwd::~TcIngressFwd()
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
TcIngressFwd::GetSupportFilterActions() const
{
  return { FilterAction::TCP_DPORT_FORWARD };
}

bool
TcIngressFwd::EnableFilters(std::list<FilterAction> &type)
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

bool
TcIngressFwd::AddWatchIpv4PortForward(uint_fast16_t port,
                                      uint_fast32_t ifindex)
{
  uint16_t port_v = static_cast<uint16_t>(port);
  uint32_t ifindex_v = static_cast<uint32_t>(ifindex);

  auto ret = bpf_map_update_elem(v4_fwd_dict_mapfd_, &port_v, &ifindex_v,
                                 BPF_NOEXIST);
  if (ret != 0) {
    return false;
  }

  return true;
}

bool
TcIngressFwd::AddWatchIpv6PortForward(uint_fast16_t port,
                                      uint_fast32_t ifindex)
{
  uint16_t port_v = static_cast<uint16_t>(port);
  uint32_t ifindex_v = static_cast<uint32_t>(ifindex);

  auto ret = bpf_map_update_elem(v6_fwd_dict_mapfd_, &port_v, &ifindex_v,
                                 BPF_NOEXIST);
  if (ret != 0) {
    return false;
  }

  return true;
}

bool
TcIngressFwd::RemoveWatchIpv4Port(uint16_t port)
{
  auto ret = bpf_map_delete_elem_flags(v4_fwd_dict_mapfd_, &port, BPF_EXIST);
  if (ret) {
    if (ret == -ENOENT)
      return true;
    return false;
  }

  return true;
}

bool
TcIngressFwd::RemoveWatchIpv6Port(uint16_t port)
{
  auto ret = bpf_map_delete_elem_flags(v6_fwd_dict_mapfd_, &port, BPF_EXIST);
  if (ret) {
    if (ret == -ENOENT)
      return true;
    return false;
  }

  return true;
}

} // namespace netdev
} // namespace celaratcp
