/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * SPDX-FileCopyrightText: Hsia-Jun(Randy) Li
 */

#ifndef USERSPACE_TCP_STACK_HELPER_HPP_
#define USERSPACE_TCP_STACK_HELPER_HPP_

#include <asio/experimental/concurrent_channel.hpp>
#include <iostream>
#include <memory>
#include <recycle/shared_pool.hpp>
#include <utility>

#include "userspace_tcp_stack.hpp"

namespace celaratcp {
namespace netio {

template <typename AddrType,
          NetPacketWrapper PacketContainer
          = std::vector<std::shared_ptr<NetPacket> >,
          CheckSumPolicy Policy = CheckSumPolicy::None>
class TcpConnectionChan : public TcpConnection<AddrType, Policy>
{
public:
  // Use asio::experimental::channel_traits<asio::any_io_executor> for
  // compatibility
  using ChannelType = asio::experimental::concurrent_channel<void(
      asio::error_code, PacketContainer &&)>;

  using PayloadWrapType = PacketContainer;

  static constexpr bool
  IsNetPacketContainer()
  {
    return NetPacketContainer<PacketContainer>;
  }

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
      : TcpConnection<AddrType, Policy>(local_addr, local_port, remote_addr,
                                        remote_port),
        rx_chan_(ex, 32)
  {
  }

  TcpConnectionChan(TcpConnectionChan &&) = default;
  TcpConnectionChan &operator=(TcpConnectionChan &&) = default;

  void
  submitRxChann(PacketContainer &&packets)
  {
    rx_chan_.async_send(asio::error_code{}, std::move(packets),
                        [](asio::error_code) {});
  }

  asio::awaitable<PacketContainer>
  fetchPackets()
  {
    PacketContainer packets
        = co_await rx_chan_.async_receive(asio::use_awaitable);
    co_return packets;
  }

private:
  ChannelType rx_chan_;
};

using shared_netbuf_pool_t
    = std::shared_ptr<recycle::shared_pool<NetMemChunk> >;

template <typename AddrType, typename TcpServiceT, typename NetworkIOObjectT>
class AsyncUserspaceTcpStack : public UserspaceTcpStack<AddrType, TcpServiceT>
{
protected:
  std::shared_ptr<NetworkIOObjectT> nout_;
  shared_netbuf_pool_t hdr_pool_;

  // Wrapper coroutine for sending packets downstream
  template <typename ConstBufferSequence>
  asio::awaitable<std::size_t>
  tx_callback_(ConstBufferSequence &&bufs)
  {
    co_return co_await asio::async_write(*nout_, std::move(bufs),
                                         asio::use_awaitable);
  }

public:
  AsyncUserspaceTcpStack(std::shared_ptr<NetworkIOObjectT> net_io,
                         shared_netbuf_pool_t hdr_pool)
      : UserspaceTcpStack<AddrType, TcpServiceT>(), nout_(std::move(net_io)),
        hdr_pool_(hdr_pool)
  {
  }

  ~AsyncUserspaceTcpStack() = default;

  template <typename NetPacket>
  bool
  FilterIncomingPacket(NetPacket &packet) const
  {
    auto print_reject
        = [](const char *reason, int proto, uint16_t port,
             const asio::ip::address &src, const asio::ip::address &dst) {
            std::string proto_name;
            switch (proto) {
            case IPPROTO_TCP:
              proto_name = "TCP";
              break;
            case IPPROTO_UDP:
              proto_name = "UDP";
              break;
            case IPPROTO_ICMP:
              proto_name = "ICMP";
              break;
            default:
              proto_name = std::format("Unknown {:#0x}", proto);
              break;
            }

            std::stringstream ss;
            ss << "[Filter] Rejected packet: " << reason
               << ", protocol=" << proto << " (" << proto_name << ")"
               << ", src=" << src.to_string() << ":" << port
               << ", dst=" << dst.to_string() << ":" << port;

            std::cerr << ss.str() << "\n";
          };

    if constexpr (std::is_same_v<AddrType, asio::ip::address_v4>) {
      if (packet.GetUsedBytes() < (kIpv4HdrSize + kTcpHdrMinimalSize)) {
        print_reject("IPv4: too short", -1, 0, asio::ip::address_v4::any(),
                     asio::ip::address_v4::any());
        return false;
      }
      auto data = packet.GetData().data();
      if (data[0] != 0x45) {
        print_reject("IPv4: wrong version/IHL", data[0], 0,
                     asio::ip::address_v4::any(), asio::ip::address_v4::any());
        return false;
      }
      uint16_t src_port = ntohs(*(uint16_t *)(data + 20));
      uint16_t dst_port = ntohs(*(uint16_t *)(data + 22));
      asio::ip::address_v4 src_addr(ntohl(*(uint32_t *)(data + 12)));
      asio::ip::address_v4 dst_addr(ntohl(*(uint32_t *)(data + 16)));
      if (data[9] != IPPROTO_TCP) {
        print_reject("IPv4: not TCP", data[9], dst_port, src_addr, dst_addr);
        return false;
      }
    } else if constexpr (std::is_same_v<AddrType, asio::ip::address_v6>) {
      if (packet.GetUsedBytes() < (kIpv6HdrSize + kTcpHdrMinimalSize)) {
        print_reject("IPv6: too short", -1, 0, asio::ip::address_v6::any(),
                     asio::ip::address_v6::any());
        return false;
      }
      auto data = packet.GetData().data();
      if (data[0] != 0x60) {
        print_reject("IPv6: wrong version", -1, 0, asio::ip::address_v6::any(),
                     asio::ip::address_v6::any());
        return false;
      }
      uint16_t src_port = ntohs(*(uint16_t *)(data + 4));
      uint16_t dst_port = ntohs(*(uint16_t *)(data + 6));
      std::array<unsigned char, 16> src_bytes;
      std::memcpy(src_bytes.data(), data + 8, 16);
      asio::ip::address_v6 src_addr(src_bytes, 0);

      std::array<unsigned char, 16> dst_bytes;
      std::memcpy(dst_bytes.data(), data + 24, 16);
      asio::ip::address_v6 dst_addr(dst_bytes, 0);
      if (data[6] != IPPROTO_TCP) {
        print_reject("IPv6: not TCP", data[6], dst_port, src_addr, dst_addr);
        return false;
      }
    } else {
      print_reject("Unknown address type", -1, 0, asio::ip::address_v4(),
                   asio::ip::address_v4());
      return false;
    }
    std::cout << "Pass" << std::endl;
    return true;
  }

  template <NetPacketWrapper PacketContainer>
  asio::awaitable<TcpStackState>
  ProcessIncomingPackets(PacketContainer &&packets)
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

    std::size_t payload_offset = ip_payload_offset + kTcpHdrMinimalSize;
    if (total_bytes_used < payload_offset) {
      co_return TcpStackState::ERR_WRONG_PROTOCOL;
    }
    if (packet->GetUsedBytes() < payload_offset) {
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
      auto conn = service->GetConnection(src_addr, src_port);
      if (conn) {
        if (conn->state_ == TcpConnectionState::SYN_SENT) {
          auto seq_num = ntohl(*reinterpret_cast<const uint32_t *>(data + 4));
          auto ack_num = ntohl(*reinterpret_cast<const uint32_t *>(data + 8));
          conn->UpdateRecvSeq(TcpPacketType::SYN_ACK, seqNum);

          auto reply = hdr_pool_->allocate();
          conn->FillPacketIpTcpHdr(TcpPacketType::ACK, *reply);

          auto ret = co_await tx_callback_(std::move(reply->GetConstBuf()));
          if (ret >= reply->GetUsedBytes()) {
            conn->UpdateSentSeq(TcpPacketType::ACK, 0, 1);

            conn->state_ = TcpConnectionState::ESTABLISHED;
            conn->FreshActivity();
            conn->Established();

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
      auto conn = service->GetConnection(src_addr, src_port);
      if (conn) {
        if (conn->state_ == TcpConnectionState::ESTABLISHED) {
          conn->state_ = TcpConnectionState::CLOSE_WAIT;
          // TODO
          co_return TcpStackState::SUCCESS;
        } else {
          co_return TcpStackState::ERR_ARGUMENT;
        }
      }
      co_return TcpStackState::ERR_ARGUMENT;
    } else if (tcpFlags == 0x10) {
      // ACK
      auto conn = service->GetConnection(src_addr, src_port);
      if (conn) {
        if (conn->state_ == TcpConnectionState::SYN_SENT) {
          // wrong flag, should be SYN-ACK
          co_return TcpStackState::ERR_ARGUMENT;
        } else if (conn->state_ == TcpConnectionState::SYN_RECEIVED) {
          conn->state_ = TcpConnectionState::ESTABLISHED;
          conn->FreshActivity();
          conn->Established();
          // jump out state check
        } else if (conn->state_ == TcpConnectionState::ESTABLISHED) {
          // jump out state check
        } else {
          co_return TcpStackState::ERR_ARGUMENT;
        }

        auto ackNum = ntohl(*reinterpret_cast<const uint32_t *>(data + 8));
        conn->UpdateRecvAck(TcpPacketType::ACK, ackNum);

        auto seqNum = ntohl(*reinterpret_cast<const uint32_t *>(data + 4));

        auto payload_size = total_bytes_used - payload_offset;
        if (payload_size) {
          constexpr bool kAcceptedPackets = std::remove_reference_t<decltype(
              *conn)>::IsNetPacketContainer();

          if constexpr (!kAcceptedPackets) {
            static_assert(std::is_same_v<typename std::remove_reference_t<
                                             decltype(*conn)>::PayloadWrapType,
                                         typename std::remove_reference_t<
                                             PacketContainer>::value_type>,
                          "mismatch type for payload packet");
          }

          typename std::remove_reference_t<decltype(*conn)>::PayloadWrapType
              payloadPackets;

          // TODO: process the case partial payload in header packet
          auto pit = packets.begin();
          if (pit != packets.end())
            ++pit; // skip header

          if constexpr (kAcceptedPackets) {
            for (; pit != packets.end(); ++pit) {
              payloadPackets.push_back(*pit);
            }
          } else {
            if (payload_size > (*pit)->GetUsedBytes())
              throw std::logic_error("We would lose payload here");

            payloadPackets.swap(*pit);
          }

          conn->UpdateRecvSeq(TcpPacketType::ACK, seqNum, payload_size);
          conn->submitRxChann(std::move(payloadPackets));
        } else {
          conn->UpdateRecvSeq(TcpPacketType::ACK, seqNum);
        }

        co_return TcpStackState::SUCCESS;
      } else {
        co_return TcpStackState::ERR_ARGUMENT;
      }
    } else if (tcpFlags == 0x02) {
      // SYN
      auto conn = service->AddConnection(src_addr, src_port);
      if (conn->state_ != TcpConnectionState::LISTEN) {
        // TODO: reset existed connection
        co_return TcpStackState::SUCCESS;
      }

      conn->state_ = TcpConnectionState::SYN_RECEIVED;
      auto seqNum = ntohl(*reinterpret_cast<const uint32_t *>(data + 4));
      conn->UpdateRecvSeq(TcpPacketType::SYN, seqNum);

      auto reply = hdr_pool_->allocate();
      conn->FillPacketIpTcpHdr(TcpPacketType::SYN_ACK, *reply);

      auto ret = co_await tx_callback_(std::move(reply->GetConstBuf()));
      if (ret >= reply->GetUsedBytes()) {
        seqNum = this->InitialConnSeq(service->GetLocalAddr(),
                                      service->GetPort(), src_addr, src_port);
        conn->UpdateSentSeq(TcpPacketType::SYN_ACK, seqNum, 1);
        conn->FreshActivity();

        co_return TcpStackState::SUCCESS;
      }
      co_return TcpStackState::DROP;
    } else {
      co_return TcpStackState::DROP;
    }
  }
};

template <typename AddrType, typename NetworkIOObjectT,
          typename TcpServiceFactory>
auto
MakeAsyncTcpStack(std::shared_ptr<NetworkIOObjectT> net_io,
                  shared_netbuf_pool_t hdr_pool, TcpServiceFactory)
{

  using ServiceTSharedPtrT
      = std::invoke_result_t<TcpServiceFactory, const AddrType &,
                             uint_fast16_t>;

  using TcpServiceT = typename ServiceTSharedPtrT::element_type;

  return AsyncUserspaceTcpStack<AddrType, TcpServiceT, NetworkIOObjectT>(
      std::move(net_io), hdr_pool);
}

} // namespace netio
} // namespace celaratcp

#endif
