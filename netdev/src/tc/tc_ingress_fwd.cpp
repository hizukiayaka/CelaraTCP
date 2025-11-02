/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * SPDX-FileCopyrightText: Hsia-Jun(Randy) Li
 */

extern "C"
{
#include <bpf/bpf.h>
#include <bpf/libbpf_common.h>
}
#include <algorithm>

#include "tc_ingress_fwd.hpp"

namespace celaratcp {
namespace netdev {

TcIngressFwd::TcIngressFwd(std::string_view ebpf_program_path, int ifindex)
    : EbpfTcCore(ebpf_program_path, "ingress_filter"),
      target_ifindex_(ifindex), v4_fwd_dict_mapfd_(-1), v6_fwd_dict_mapfd_(-1)
{
  v4_fwd_dict_mapfd_
      = bpf_object__find_map_fd_by_name(bpf_obj_, "v4_tcp_fwd_dict");
  if (v4_fwd_dict_mapfd_ < 0) {
    throw std::logic_error("program TCPv4 table is missing");
  }

  v6_fwd_dict_mapfd_
      = bpf_object__find_map_fd_by_name(bpf_obj_, "v6_tcp_fwd_dict");
  if (v6_fwd_dict_mapfd_ < 0) {
    throw std::logic_error("program TCPv6 table is missing");
  }
}

TcIngressFwd::~TcIngressFwd() {}

std::list<FilterAction>
TcIngressFwd::GetSupportFilterActions() const
{
  return { FilterAction::TCP_DPORT_FORWARD };
}

bool
TcIngressFwd::EnableFilters(std::list<FilterAction> &type)
{
  auto ret = AttachToNetInterface(target_ifindex_, BPF_TC_INGRESS);
  if (ret)
    return false;

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

void
TcIngressFwd::DisableFilter()
{
  DetachFromNetInterface();
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
