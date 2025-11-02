/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * SPDX-FileCopyrightText: Hsia-Jun(Randy) Li
 */

#ifndef TC_EGRESS_FILTER_HPP_
#define TC_EGRESS_FILTER_HPP_

#include <list>
#include <optional>

#include "net_filter_inf.hpp"
#include "tc_egress_filter_lite.hpp"

namespace celaratcp {
namespace netdev {

class TcEgressFilter : public TcEgressFilterLite
{
private:
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

public:
  TcEgressFilter(std::string_view ebpf_program_path, int ifindex);
  ~TcEgressFilter() override;

  std::list<FilterAction> GetSupportFilterActions() const override;

  bool EnableFilters(std::list<FilterAction> &types) override;
  void DisableFilter() override;

  bool AddWatchIpv4Port(uint16_t port) override;
  bool RemoveWatchIpv4Port(uint16_t port) override;

  bool AddWatchIpv6Port(uint16_t port) override;
  bool RemoveWatchIpv6Port(uint16_t port) override;

  bool AddPeerNode(const asio::ip::address &addr, uint16_t src_port,
                   uint16_t dst_port) override;
  bool RemovePeerNode(const asio::ip::address &addr, uint16_t src_port,
                      uint16_t dst_port) override;
};

} // namespace netdev
} // namespace celaratcp

#endif
