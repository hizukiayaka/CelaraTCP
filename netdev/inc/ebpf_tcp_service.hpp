/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * SPDX-FileCopyrightText: Hsia-Jun(Randy) Li
 */

#pragma once
/* This header is from netio subdir */
#include "userspace_tcp_stack.hpp"
/* This is a local header */
#include "bpf_tcp_ringbuf.hpp"

namespace celaratcp {
namespace ebpf {

template <typename AddrType, typename TcpConnFactory>
class TcpService : public netio::TcpService<AddrType, TcpConnFactory>
{
protected:
  netdev::IPacketFilter *filter_;
  asio::any_io_executor &exec_;

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

    if (tcp_flags == 0x12) {
      // SYN-ACK
      auto conn = this->GetConnection(src_addr, src_port);
      if (conn) {
        if (conn->state_ == netio::TcpConnectionState::SYN_SENT) {
          // TODO: validate ack num accuracy
          auto seq = conn->GetInitialSequenceNumber();
          if (ack_seq <= seq) {
            co_return netio::TcpStackState::ERR_ARGUMENT;
          }

          conn->SetRemoteInitialSequenceNumber(seq_num);

          try {
            co_await conn->AsyncSendReply(netio::TcpPacketType::ACK,
                                          ack_seq + 1, seq_num, 0);
            conn->state_ = netio::TcpConnectionState::ESTABLISHED;
            conn->FreshActivity();
            conn->Established(ack_seq + 1, seq_num);
          }
          catch (...) {
            co_return netio::TcpStackState::DROP;
          }
          co_return netio::TcpStackState::SUCCESS;
        } else {
          co_return netio::TcpStackState::ERR_ARGUMENT;
        }
      }

      // We don't have such connection
      co_return netio::TcpStackState::ERR_ARGUMENT;
    } else if (tcp_flags == 0x11) {
      // FIN-ACK
      auto conn = this->GetConnection(src_addr, src_port);
      if (conn) {
        if (conn->state_ == netio::TcpConnectionState::ESTABLISHED) {
          conn->state_ = netio::TcpConnectionState::CLOSE_WAIT;
          // TODO
          co_return netio::TcpStackState::SUCCESS;
        } else {
          co_return netio::TcpStackState::ERR_ARGUMENT;
        }
      }
      co_return netio::TcpStackState::ERR_ARGUMENT;
    } else if (tcp_flags == 0x10) {
      // ACK
      auto conn = this->GetConnection(src_addr, src_port);
      if (conn) {
        if (conn->state_ == netio::TcpConnectionState::SYN_SENT) {
          // wrong flag, should be SYN-ACK
          co_return netio::TcpStackState::ERR_ARGUMENT;
        } else if (conn->state_ == netio::TcpConnectionState::SYN_RECEIVED) {
          conn->state_ = netio::TcpConnectionState::ESTABLISHED;
          conn->FreshActivity();

          // TODO: validate seq_num and ack_num
          // seq_num should be remote ISN + 1
          // ack_num should be local ISN + 1

          conn->Established(ack_seq, seq_num);
          // jump out state check
        } else if (conn->state_ == netio::TcpConnectionState::ESTABLISHED) {
          // jump out state check
        } else {
          co_return netio::TcpStackState::ERR_ARGUMENT;
        }

        if (packet) {
          typename std::remove_reference_t<decltype(*conn)>::PayloadWrapType
              payload_packet;

          conn->SetPacketSeqAck(*packet, seq_num, ack_seq);

          constexpr bool kAcceptedPackets = std::remove_reference_t<decltype(
              *conn)>::IsNetPacketContainer();

          if constexpr (kAcceptedPackets) {
            payload_packet.push_back(packet);
          } else {
            payload_packet.swap(packet);
          }

          conn->submitRxChann(std::move(payload_packet));
        } else {
          // We can't update packet record here, it may not exist
        }

        co_return netio::TcpStackState::SUCCESS;
      } else {
        co_return netio::TcpStackState::ERR_ARGUMENT;
      }
    } else if (tcp_flags == 0x02) {
      // SYN
      auto conn = this->AddConnection(src_addr, src_port);
      if (conn->state_ != netio::TcpConnectionState::LISTEN) {
        // TODO: reset existed connection
        co_return netio::TcpStackState::SUCCESS;
      }

      conn->state_ = netio::TcpConnectionState::SYN_RECEIVED;

      conn->SetRemoteInitialSequenceNumber(seq_num);

      auto ack_num = seq_num + 1;

      auto &local_addr = this->GetLocalAddr();
      auto local_port = this->GetPort();
      // Generate ISN
      auto seq_num = netio::GenerateInitialSequenceNumber(
          local_addr, local_port, src_addr, src_port);

      try {
        co_await conn->AsyncSendReply(netio::TcpPacketType::SYN_ACK, seq_num,
                                      ack_num, 0);
        conn->FreshActivity();
      }
      catch (...) {
        co_return netio::TcpStackState::DROP;
      }
      co_return netio::TcpStackState::SUCCESS;
    } else {
      co_return netio::TcpStackState::DROP;
    }
  }

public:
  TcpService(TcpConnFactory &&conn_factory, const AddrType &local_addr,
             uint_fast16_t local_port, netdev::IPacketFilter *filter,
             asio::any_io_executor &exec)
      : netio::TcpService<AddrType, TcpConnFactory>(std::move(conn_factory),
                                                    local_addr, local_port),
        filter_(filter), exec_(exec)
  {
  }
};

} // namespace ebpf
} // namespace celaratcp
