/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * SPDX-FileCopyrightText: Hsia-Jun(Randy) Li
 */

#ifndef TC_EGRESS_FILTER_LITE_HPP_
#define TC_EGRESS_FILTER_LITE_HPP_

#include <cstdint>
#include <list>

#include "ebpf_tc_core.hpp"
#include "net_filter_inf.hpp"

namespace celaratcp {
namespace netdev {

class TcEgressFilterLite : public EbpfTcCore, public IPacketFilter
{
protected:
  const int target_ifindex_;
  int filter_mapfd_;
public:
  TcEgressFilterLite(std::string_view ebpf_program_path, int ifindex);
  ~TcEgressFilterLite() override;

  std::list<FilterAction> GetSupportFilterActions() const override;

  bool EnableFilters(std::list<FilterAction> &types) override;
  void DisableFilter() override;
};

} // namespace netdev
} // namespace celaratcp

#endif
