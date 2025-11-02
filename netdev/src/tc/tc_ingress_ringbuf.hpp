/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * SPDX-FileCopyrightText: Hsia-Jun(Randy) Li
 */

#ifndef TC_INGRESS_RINGBUF_HPP_
#define TC_INGRESS_RINGBUF_HPP_

#include <any>
#include <cstdint>
#include <list>

#include "bpf_tcp_ringbuf.hpp"
#include "ebpf_tc_core.hpp"
#include "net_filter_inf.hpp"

namespace celaratcp {
namespace netdev {

class TcIngressRingbuf : public EbpfTcCore, public IPacketFilter
{
private:
  const int target_ifindex_;
  int v4_tcp_map_mapfd_;
  int v6_tcp_map_mapfd_;

  struct PortMapFdPair
  {
    uint_fast16_t port;
    int map_fd;
    std::shared_ptr<ebpf::EbpfTcpRingAllocator> r;
  };

  std::list<PortMapFdPair> v4_tcp_maps_list_;
  std::list<PortMapFdPair> v6_tcp_maps_list_;

  static constexpr std::size_t kRingBufSize = (1 << 28);

  static std::size_t GetPageSize();
  static std::size_t GetAlignRingBufSize();

public:
  TcIngressRingbuf(std::string_view ebpf_program_path, int ifindex);
  ~TcIngressRingbuf() override;

  std::list<FilterAction> GetSupportFilterActions() const override;

  bool EnableFilters(std::list<FilterAction> &types) override;

  std::any AddWatchIpv4PortRingbuf(uint_fast16_t port,
                                   asio::any_io_executor ex) override;
  bool RemoveWatchIpv4Port(uint16_t port) override;

  std::any AddWatchIpv6PortRingbuf(uint_fast16_t port,
                                   asio::any_io_executor ex) override;
  bool RemoveWatchIpv6Port(uint16_t port) override;
};

} // namespace netdev
} // namespace celaratcp

#endif
