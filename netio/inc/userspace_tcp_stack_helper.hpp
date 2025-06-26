/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * SPDX-FileCopyrightText: Hsia-Jun(Randy) Li
 */

#ifndef USERSPACE_TCP_STACK_HELPER_HPP_
#define USERSPACE_TCP_STACK_HELPER_HPP_

#include <asio/experimental/channel.hpp>
#include <recycle/shared_pool.hpp>
#include <utility>

#include "userspace_tcp_stack.hpp"

namespace celaratcp {
namespace netio {

template <typename AddrType, NetPacketContainer PacketContainer
                             = std::vector<std::shared_ptr<NetPacket> > >
class TcpConnectionChan : public TcpConnection<AddrType>
{
public:
  // Use asio::experimental::channel_traits<asio::any_io_executor> for
  // compatibility
  using ChannelType = asio::experimental::channel<void(PacketContainer &&)>;

#if 0
  using typename TcpConnection<AddrType>::TcpConnectionCtorArgs;

  TcpConnectionChan(const TcpConnectionCtorArgs &args,
                    asio::any_io_executor &ex)
      : TcpConnection<AddrType>(std::apply(
            [](const auto &...params) {
              return TcpConnection<AddrType>(params...);
            },
            args)),
        rx_chan_(ex, 32)
  {
  }
#endif

  TcpConnectionChan(AddrType local_addr, uint_fast16_t local_port,
                    AddrType remote_addr, uint_fast16_t remote_port,
                    asio::any_io_executor &ex)
      : TcpConnection<AddrType>(local_addr, local_port, remote_addr,
                                remote_port),
        rx_chan_(ex, 32)
  {
  }

  TcpConnectionChan(TcpConnectionChan &&) = default;
  TcpConnectionChan &operator=(TcpConnectionChan &&) = default;

  void
  submitRxChann(PacketContainer &&packets)
  {
    rx_chan_.async_send(std::move(packets), asio::use_awaitable);
  }

  asio::awaitable<PacketContainer>
  fetchPackets()
  {
    PacketContainer packets;
    co_await rx_chan_.async_receive(packets, asio::use_awaitable);
    co_return packets;
  }

private:
  ChannelType rx_chan_;
};

template <typename AddrType, typename TcpConnectionT>
concept HasRequiredConnTCtor
    = requires(TcpConnectionT conn, AddrType local_addr,
               uint_fast16_t local_port, AddrType remote_addr,
               uint_fast16_t remote_port, asio::any_io_executor &ex)
{
  TcpConnectionT(local_addr, local_port, remote_addr, remote_port, ex);
};

using shared_netbuf_pool_t
    = std::shared_ptr<recycle::shared_pool<NetMemChunk> >;

template <typename AddrType, typename TcpConnectionT, typename TcpServiceT,
          typename NetworkIOObjectT>
requires
    HasRequiredConnTCtor<AddrType, TcpConnectionT> class AsyncUserspaceTcpStack
    : public UserspaceTcpStack<AddrType, TcpConnectionT, TcpServiceT>
{
protected:
  asio::any_io_executor &executor_;
  NetworkIOObjectT &nout_;
  shared_netbuf_pool_t hdr_pool_;

  // Wrapper coroutine for sending packets downstream
  template <typename ConstBufferSequence>
  asio::awaitable<std::size_t>
  tx_callback_(ConstBufferSequence &bufs)
  {
    co_return co_await asio::async_write(nout_, bufs, asio::use_awaitable);
  }

public:
  // Accept executor by value (copy/move), not by reference_wrapper
  AsyncUserspaceTcpStack(asio::any_io_executor &ex, NetworkIOObjectT &net_io,
                         shared_netbuf_pool_t hdr_pool)
      : UserspaceTcpStack<AddrType, TcpConnectionT, TcpServiceT>(),
        executor_(ex), nout_(net_io), hdr_pool_(hdr_pool)
  {
  }
  ~AsyncUserspaceTcpStack() = default;

  template <typename NetPacket>
  bool
  FilterIncomingPacket(NetPacket &packet) const
  {
    if constexpr (std::is_same_v<AddrType, asio::ip::address_v4>) {
      if (packet.GetUsedBytes() < (kIpv4HdrSize + kTcpHdrMinimalSize)) {
        return false;
      }
      auto data = packet.GetData().data();
      if (data[0] != 0x45) {
        return false;
      }
      if (data[9] != IPPROTO_TCP) {
        return false;
      }
    } else if constexpr (std::is_same_v<AddrType, asio::ip::address_v6>) {
      if (packet.GetUsedBytes() < (kIpv6HdrSize + kTcpHdrMinimalSize)) {
        return false;
      }
      auto data = packet.GetData().data();
      if (data[0] != 0x60) {
        return false;
      }
      if (data[6] != IPPROTO_TCP) {
        return false;
      }
    } else {
      return false;
    }
    return true;
  }

  template <NetPacketContainer PacketContainer>
  asio::awaitable<TcpStackState>
  ProcessIncomingPackets(PacketContainer &packets)
  {
    auto total_bytes_used = std::accumulate(
        packets.cbegin(), packets.cend(), std::size_t(0),
        [](std::size_t sum, const std::shared_ptr<NetPacket> &packet) {
          return sum + packet->GetUsedBytes();
        });

    auto packet = packets.front();
    bool success;
    std::size_t ip_payload_offset;
    std::size_t packet_length;
    AddrType src_addr, dst_addr;

    std::tie(success, ip_payload_offset)
        = this->ParseIpHeader(packet, packet_length, src_addr, dst_addr);
    if (!success) {
      co_return TcpStackState::ERR_WRONG_PROTOCOL;
    }

    std::size_t payloadOffset = ip_payload_offset + kTcpHdrMinimalSize;
    if (total_bytes_used < payloadOffset) {
      co_return TcpStackState::ERR_WRONG_PROTOCOL;
    }
    if (packet->GetUsedBytes() < payloadOffset) {
      co_return TcpStackState::ERR_WRONG_PROTOCOL;
    }
    /* safely packet checking */
    if (packet_length > total_bytes_used) {
      co_return TcpStackState::ERR_WRONG_PROTOCOL;
    }

    auto data = packet->GetData().data() + ip_payload_offset;

    auto dst_port = ntohs(*reinterpret_cast<const uint16_t *>(data + 2));
    auto it = std::find_if(
        this->services_.begin(), this->services_.end(),
        [dst_port](const std::shared_ptr<TcpServiceT> &service) {
          return service->GetPort() == dst_port;
        });
    if (it == this->services_.end()) {
      co_return TcpStackState::ERR_NO_SUCH_SERVICE;
    }
    auto service = it->get();

    auto src_port = ntohs(*reinterpret_cast<const uint16_t *>(data));
    auto tcpFlags = static_cast<uint8_t>(data[13]);
    if (tcpFlags == 0x12) {
      // SYN-ACK
      auto conn_op = service->GetConnection(src_addr, src_port);
      if (conn_op) {
        auto &conn = conn_op->get();
        if (conn.state_ == TcpConnectionState::SYN_SENT) {
          auto seqNum = ntohl(*reinterpret_cast<const uint32_t *>(data + 4));
          conn.UpdateRecvSeq(TcpPacketType::SYN_ACK, seqNum);

          auto reply = hdr_pool_->allocate();
          conn.FillPacketIpTcpHdr(TcpPacketType::ACK, *reply);
          std::list<asio::const_buffer> r = { reply->GetConstBuf() };

          auto ret = co_await tx_callback_(r);
          if (ret >= reply->GetUsedBytes()) {
            conn.UpdateSentSeq(TcpPacketType::ACK, 0, 1);

            conn.state_ = TcpConnectionState::ESTABLISHED;
            conn.FreshActivity();
            conn.Established();

            co_return TcpStackState::SUCCESS;
          }
          co_return TcpStackState::DROP;
        } else {
          co_return TcpStackState::ERR_ARGUMENT;
        }
      }
      co_return TcpStackState::ERR_ARGUMENT;
    } else if (tcpFlags == 0x11) {
      // FIN-ACK
      auto conn_op = service->GetConnection(src_addr, src_port);
      if (conn_op) {
        auto &conn = conn_op->get();
        if (conn.state_ == TcpConnectionState::ESTABLISHED) {
          conn.state_ = TcpConnectionState::CLOSE_WAIT;
          // TODO
          co_return TcpStackState::SUCCESS;
        } else {
          co_return TcpStackState::ERR_ARGUMENT;
        }
      }
      co_return TcpStackState::ERR_ARGUMENT;
    } else if (tcpFlags == 0x10) {
      // ACK
      auto conn_op = service->GetConnection(src_addr, src_port);
      if (conn_op) {
        auto &conn = conn_op->get();
        if (conn.state_ == TcpConnectionState::SYN_SENT) {
          // wrong flag, should be SYN-ACK
          co_return TcpStackState::ERR_ARGUMENT;
        } else if (conn.state_ == TcpConnectionState::SYN_RECEIVED) {
          conn.state_ = TcpConnectionState::ESTABLISHED;
          conn.FreshActivity();
          conn.Established();
          // jump out state check
        } else if (conn.state_ == TcpConnectionState::ESTABLISHED) {
          // jump out state check
        } else {
          co_return TcpStackState::ERR_ARGUMENT;
        }

        auto ackNum = ntohl(*reinterpret_cast<const uint32_t *>(data + 8));
        conn.UpdateRecvAck(TcpPacketType::ACK, ackNum);

        auto seqNum = ntohl(*reinterpret_cast<const uint32_t *>(data + 4));

        auto payloadSize = total_bytes_used - payloadOffset;
        if (payloadSize) {
          // TODO: process the case partial payload in header packet
          PacketContainer payloadPackets;
          auto pit = packets.begin();

          if (pit != packets.end())
            ++pit; // skip header
          conn.SetPacketMetaData(*pit, seqNum, ackNum);
          for (; pit != packets.end(); ++pit) {
            payloadPackets.push_back(*pit);
          }

          conn.UpdateRecvSeq(TcpPacketType::ACK, seqNum, payloadSize);
          conn.submitRxChann(std::move(payloadPackets));
        } else {
          conn.UpdateRecvSeq(TcpPacketType::ACK, seqNum);
        }

        co_return TcpStackState::SUCCESS;
      } else {
        co_return TcpStackState::ERR_ARGUMENT;
      }
    } else if (tcpFlags == 0x02) {
      // SYN
      auto conn = TcpConnectionT(service->GetLocalAddr(), service->GetPort(),
                                 src_addr, src_port, executor_);
      // TODO: check if the connection already exists, if it does, reset it

      conn.state_ = TcpConnectionState::SYN_RECEIVED;
      auto seqNum = ntohl(*reinterpret_cast<const uint32_t *>(data + 4));
      conn.UpdateRecvSeq(TcpPacketType::SYN, seqNum);

      auto reply = hdr_pool_->allocate();
      conn.FillPacketIpTcpHdr(TcpPacketType::SYN_ACK, *reply);
      std::forward_list<asio::const_buffer> r = { reply->GetConstBuf() };
      auto ret = co_await tx_callback_(r);
      if (ret >= reply->GetUsedBytes()) {
        seqNum = this->InitialConnSeq(service->GetLocalAddr(),
                                      service->GetPort(), src_addr, src_port);
        conn.UpdateSentSeq(TcpPacketType::SYN_ACK, seqNum, 1);
        conn.FreshActivity();

        service->AddConnection(std::move(conn));
        co_return TcpStackState::SUCCESS;
      }
      co_return TcpStackState::DROP;
    } else {
      co_return TcpStackState::DROP;
    }
  }
};

template <typename AddrType, typename NetworkIOObjectT,
          typename FactoryFunction>
auto
MakeAsyncTcpStack(asio::any_io_executor &ex, NetworkIOObjectT &net_io,
                  shared_netbuf_pool_t hdr_pool, FactoryFunction factory)
{

  using TcpConnectionTRealType = decltype(
      factory(std::declval<AddrType>(), std::declval<uint_fast16_t>(),
              std::declval<AddrType>(), std::declval<uint_fast16_t>()));

  return AsyncUserspaceTcpStack<AddrType, TcpConnectionTRealType,
                                TcpService<AddrType, TcpConnectionTRealType>,
                                NetworkIOObjectT>(ex, net_io, hdr_pool);
}

} // namespace netio
} // namespace celaratcp

#endif
