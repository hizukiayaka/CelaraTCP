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

  asio::awaitable<netio::TcpStackState>
  ProcessParsedPacket(ebpf::BpfRingbufTcpMeta *meta,
                      std::shared_ptr<NetMemChunk> packet)
  {
    const auto tcp_flags = meta->tcp_flags_;
    const auto src_port = meta->src_port_;
    const auto seq_num = meta->seq_num_;
    const auto ack_seq = meta->ack_num_;

    auto src_addr = [](auto &addr) -> const AddrType {
      if constexpr (std::is_same_v<AddrType, asio::ip::address_v4>) {
        return addr.to_v4();
      } else {
        return addr.to_v6();
      }
    }(meta->addr_);

    std::vector<std::shared_ptr<NetMemChunk> > payload_packets;
    std::size_t payload_size = 0;
    if (packet) {
      payload_size = packet->GetUsedBytes();
      payload_packets.push_back(std::move(packet));
    }

    co_return co_await this->HandleTcpLogic(
        src_addr, src_port, tcp_flags, seq_num, ack_seq,
        std::move(payload_packets), payload_size);
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
