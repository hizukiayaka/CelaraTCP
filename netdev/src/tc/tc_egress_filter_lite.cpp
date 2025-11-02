/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * SPDX-FileCopyrightText: Hsia-Jun(Randy) Li
 */

extern "C"
{
#include <bpf/bpf.h>
#include <bpf/libbpf_common.h>

#include "l3_egress.bpf.h"
}

#include "tc_egress_filter_lite.hpp"

namespace celaratcp {
namespace netdev {

TcEgressFilterLite::TcEgressFilterLite(std::string_view ebpf_program_path,
                                       int ifindex)
    : EbpfTcCore(ebpf_program_path, "egress_filter"), target_ifindex_(ifindex),
      filter_mapfd_(-1)
{
  filter_mapfd_ = bpf_object__find_map_fd_by_name(bpf_obj_, "filter_list");
  if (filter_mapfd_ < 0) {
    throw std::logic_error("program cfg table is missing");
  }
}

TcEgressFilterLite::~TcEgressFilterLite() {}

std::list<FilterAction>
TcEgressFilterLite::GetSupportFilterActions() const
{
  return { FilterAction::DROP_IPV4, FilterAction::DROP_IPV6,
           FilterAction::ACCEPT_TCP_ONLY };
}

bool
TcEgressFilterLite::EnableFilters(std::list<FilterAction> &type)
{
  auto ret = AttachToNetInterface(target_ifindex_, BPF_TC_EGRESS);
  if (!ret) {
    return false;
  }

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

void
TcEgressFilterLite::DisableFilter()
{
  struct filter_list_value value = {};

  int key = 0;
  if (bpf_map_update_elem(filter_mapfd_, &key, &value, BPF_ANY) != 0) {
    return;
  }

  DetachFromNetInterface();
}

} // namespace netdev
} // namespace celaratcp
