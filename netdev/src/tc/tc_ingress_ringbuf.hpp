/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * SPDX-FileCopyrightText: Hsia-Jun(Randy) Li
 */

#ifndef TC_INGRESS_RINGBUF_HPP_
#define TC_INGRESS_RINGBUF_HPP_

#include <bpf/bpf.h>
#include <cstdint>
#include <experimental/propagate_const>
#include <list>
#include <optional>

#include "net_filter_inf.hpp"

namespace celaratcp {
namespace netdev {

class TcIngressRingbuf : public IPacketFilter
{
private:
  struct bpf_object *bpf_obj_;
  struct bpf_program *bpf_prog_;

  int ifindex_;

  int v4_tcp_map_mapfd_;
  int v6_tcp_map_mapfd_;

  struct PortMapFdPair
  {
    uint_fast16_t port;
    int map_fd;
  };

  std::list<PortMapFdPair> v4_tcp_maps_list_;
  std::list<PortMapFdPair> v6_tcp_maps_list_;

public:
  TcIngressRingbuf(std::string_view ebpf_program_path, int ifindex);
  ~TcIngressRingbuf() override;

  std::list<FilterAction> GetSupportFilterActions() const override;

  bool EnableFilters(std::list<FilterAction> &types) override;

  int AddWatchIpv4PortRingbuf(uint_fast16_t port) override;
  bool RemoveWatchIpv4Port(uint16_t port) override;

  int AddWatchIpv6PortRingbuf(uint_fast16_t port) override;
  bool RemoveWatchIpv6Port(uint16_t port) override;
};

} // namespace netdev
} // namespace celaratcp

#endif
