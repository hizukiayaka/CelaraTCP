/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * SPDX-FileCopyrightText: Hsia-Jun(Randy) Li
 */

#ifndef TC_EGRESS_FILTER_LITE_HPP_
#define TC_EGRESS_FILTER_LITE_HPP_

#include <bpf/bpf.h>
#include <cstdint>
#include <experimental/propagate_const>
#include <list>
#include <optional>

#include "net_filter_inf.hpp"

namespace celaratcp {
namespace netdev {

class TcEgressFilterLite : public IPacketFilter
{
private:
  struct bpf_object *bpf_obj_;
  struct bpf_program *bpf_prog_;

  int ifindex_;

  int filter_mapfd_;

public:
  TcEgressFilterLite(std::string_view ebpf_program_path, int ifindex);
  ~TcEgressFilterLite() override;

  std::list<FilterAction> GetSupportFilterActions() const override;

  bool EnableFilters(std::list<FilterAction> &types) override;
};

} // namespace netdev
} // namespace celaratcp

#endif
