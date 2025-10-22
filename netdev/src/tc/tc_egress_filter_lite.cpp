/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * SPDX-FileCopyrightText: Hsia-Jun(Randy) Li
 */

extern "C"
{
#include <bpf/libbpf.h>

#include "l3_egress.bpf.h"
}
#include <algorithm>

#include "tc_egress_filter_lite.hpp"

namespace celaratcp {
namespace netdev {

TcEgressFilterLite::TcEgressFilterLite(std::string_view ebpf_program_path,
                                       int ifindex)
    : bpf_obj_(nullptr), bpf_prog_(nullptr), ifindex_(ifindex),
      filter_mapfd_(-1)
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
}

TcEgressFilterLite::~TcEgressFilterLite()
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
TcEgressFilterLite::GetSupportFilterActions() const
{
  return { FilterAction::DROP_IPV4, FilterAction::DROP_IPV6,
           FilterAction::ACCEPT_TCP_ONLY };
}

bool
TcEgressFilterLite::EnableFilters(std::list<FilterAction> &type)
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

} // namespace netdev
} // namespace celaratcp
