/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * SPDX-FileCopyrightText: Hsia-Jun(Randy) Li
 */

#pragma once
/* This header is from netio subdir */
#include "userspace_tcp_stack.hpp"
/* This is a local header */
#include "bpf_tcp_ringbuf.hpp"
/* include "net_filter_inf.hpp" before this file */

namespace celaratcp {
namespace ebpf {

template <typename AddrType, typename TcpConnFactory>
class TcpService : public netio::TcpService<AddrType, TcpConnFactory>
{
protected:
  netdev::IPacketFilter *filter_;

  template <typename>
  static constexpr bool kAlwaysFalse = false;

  template <NetMemChunkLike PacketT>
  asio::awaitable<netio::TcpStackState>
  ProcessParsedPacket(ebpf::BpfRingbufTcpMeta *meta,
                      std::shared_ptr<PacketT> packet)
  {
    const auto tcp_flags = meta->tcp_flags_;
    const auto src_port = meta->src_port_;
    const auto peer_seq = meta->seq_num;
    const auto peer_ack = meta->ack_num;

    auto src_addr = [](auto &addr) -> const AddrType {
      if constexpr (std::is_same_v<AddrType, asio::ip::address_v4>) {
        return addr.to_v4();
      } else {
        return addr.to_v6();
      }
    }(meta->addr_);

    std::size_t payload_size = packet ? packet->GetUsedBytes() : 0;

    co_return co_await this->HandleTcpLogic(src_addr, src_port, tcp_flags,
                                            peer_seq, peer_ack,
                                            std::move(packet), payload_size);
  }

public:
  TcpService(TcpConnFactory &&conn_factory, const AddrType &local_addr,
             uint_fast16_t local_port, netdev::IPacketFilter *filter)
      : netio::TcpService<AddrType, TcpConnFactory>(std::move(conn_factory),
                                                    local_addr, local_port),
        filter_(filter)
  {
  }
};

} // namespace ebpf
} // namespace celaratcp
