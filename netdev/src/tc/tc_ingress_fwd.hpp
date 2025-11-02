/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * SPDX-FileCopyrightText: Hsia-Jun(Randy) Li
 */

#ifndef TC_INGRESS_FORWARD_HPP_
#define TC_INGRESS_FORWARD_HPP_

#include <cstdint>
#include <list>
#include <optional>

#include "ebpf_tc_core.hpp"
#include "net_filter_inf.hpp"

namespace celaratcp {
namespace netdev {

class TcIngressFwd : public EbpfTcCore, public IPacketFilter
{
private:
  const int target_ifindex_;
  int v4_fwd_dict_mapfd_;
  int v6_fwd_dict_mapfd_;

public:
  TcIngressFwd(std::string_view ebpf_program_path, int ifindex);
  ~TcIngressFwd() override;

  std::list<FilterAction> GetSupportFilterActions() const override;

  bool EnableFilters(std::list<FilterAction> &types) override;
  void DisableFilter() override;

  bool AddWatchIpv4PortForward(uint_fast16_t port,
                               uint_fast32_t ifindex) override;
  bool RemoveWatchIpv4Port(uint16_t port) override;

  bool AddWatchIpv6PortForward(uint_fast16_t port,
                               uint_fast32_t ifindex) override;
  bool RemoveWatchIpv6Port(uint16_t port) override;
};

} // namespace netdev
} // namespace celaratcp

#endif
