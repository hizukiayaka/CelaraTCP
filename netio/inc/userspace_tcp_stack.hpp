/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * SPDX-FileCopyrightText: Hsia-Jun(Randy) Li
 */

#ifndef USERSPACE_TCP_STACK_HPP_
#define USERSPACE_TCP_STACK_HPP_

#include "tcp_connection.hpp"

namespace celaratcp {
namespace netio {

enum class TcpStackState
{
  SUCCESS,
  DROP,
  ERR_ARGUMENT,
  ERR_WRONG_FAMILY,
  ERR_WRONG_PROTOCOL,
  ERR_NO_SUCH_SERVICE,
};

template <typename AddrType, typename TcpConnFactory>
class TcpService
{
protected:
  AddrType local_addr_;
  uint_fast16_t port_;
  TcpConnFactory conn_factory_;

  using TcpConnectionT
      = std::invoke_result_t<decltype(conn_factory_), AddrType, uint_fast16_t,
                             AddrType, uint_fast16_t>::element_type;

  std::forward_list<std::shared_ptr<TcpConnectionT> > connections_list_;

public:
  template <NetPacketWrapper PacketContainer>
  asio::awaitable<TcpStackState>
  HandleTcpLogic(const AddrType &src_addr, uint_fast16_t src_port,
                 uint8_t tcp_flags, uint32_t seq_num, uint32_t ack_seq,
                 PacketContainer &&packets, std::size_t payload_size)
  {
    auto get_packet_ref = []<typename P>(P &&packet_like) -> NetPacket & {
      if constexpr (requires { packet_like->GetUsedBytes(); }) {
        return *packet_like; // It's a smart pointer
      } else {
        return packet_like; // It's a value
      }
    };

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

        if (payload_size) {
          constexpr bool kAcceptedPackets = std::remove_reference_t<decltype(
              *conn)>::IsNetPacketContainer();

          if constexpr (!kAcceptedPackets) {
            // determine the "element" type the caller passed:
            using RawPktCont = std::remove_reference_t<PacketContainer>;
            // Container case: deduce element type from *begin()
            if constexpr (std::ranges::range<RawPktCont>) {
              using PacketElementType = std::remove_cvref_t<decltype(
                  *std::begin(std::declval<RawPktCont &>()))>;

              using ConnPayloadType =
                  typename std::remove_reference_t<decltype(
                      *conn)>::PayloadWrapType;

              static_assert(std::is_same_v<ConnPayloadType, PacketElementType>,
                            "mismatch type for payload packet");
            } else {
              // Single-packet case: treat PacketContainer as the element type
              using PacketElementType = RawPktCont;

              using ConnPayloadType =
                  typename std::remove_reference_t<decltype(
                      *conn)>::PayloadWrapType;

              static_assert(std::is_same_v<ConnPayloadType, PacketElementType>,
                            "mismatch type for payload packet");
            }
          }

          typename std::remove_reference_t<decltype(*conn)>::PayloadWrapType
              payload_packets;

          if constexpr (NetPacketContainer<PacketContainer>) {
            auto pit = std::begin(packets);
            conn->SetPacketSeqAck(get_packet_ref(*pit), seq_num, ack_seq);

            if constexpr (kAcceptedPackets) {
              for (; pit != std::end(packets); std::advance(pit, 1)) {
                payload_packets.push_back(*pit);
              }
            } else {
              auto &packet = get_packet_ref(*pit);
              if (payload_size > packet.GetUsedBytes())
                throw std::logic_error("We would lose payload here");

              if constexpr (requires { (*pit)->GetUsedBytes(); }) {
                payload_packets.swap(*pit);
              } else {
                static_assert(false, "Unsupported packet container");
              }
            }
          } else {
            auto &packet = get_packet_ref(packets);
            conn->SetPacketSeqAck(packet, seq_num, ack_seq);
            if constexpr (kAcceptedPackets) {
              payload_packets.push_back(packet);
            } else {
              payload_packets.swap(packets);
            }
          }

          conn->submitRxChann(std::move(payload_packets));
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

  TcpService(TcpConnFactory &&conn_factory, const AddrType &addr,
             uint_fast16_t port) noexcept
      : local_addr_(addr),
        port_(port),
        conn_factory_(std::move(conn_factory))
  {
  }
  ~TcpService() = default;

  uint_fast16_t
  GetPort() const noexcept
  {
    return port_;
  }

  const AddrType &
  GetLocalAddr() const noexcept
  {
    return local_addr_;
  }

  virtual std::shared_ptr<TcpConnectionT>
  AddConnection(const AddrType &remote_addr, uint_fast16_t remote_port)
  {
    auto it
        = std::find_if(connections_list_.cbegin(), connections_list_.cend(),
                       [&](const std::shared_ptr<TcpConnectionT> &c) {
                         return c->remote_addr_ == remote_addr
                                && c->remote_port_ == remote_port;
                       });
    if (it == connections_list_.cend()) {
      auto conn = conn_factory_(local_addr_, port_, remote_addr, remote_port);
      connections_list_.push_front(conn);
      return conn;
    } else {
      return *it;
    }
  }

  virtual bool
  RemoveConnection(AddrType remoteAddr, uint_fast16_t remotePort)
  {
    auto it = std::find_if(connections_list_.begin(), connections_list_.end(),
                           [&](const std::shared_ptr<TcpConnectionT> &conn) {
                             return conn->remote_addr_ == remoteAddr
                                    && conn->remote_port_ == remotePort;
                           });
    if (it != connections_list_.end()) {
      connections_list_.erase_after(it);
      return true;
    }
    return false;
  }

  virtual bool
  RemoveConnection(AddrType remoteAddr)
  {
    auto num_removed = connections_list_.remove_if(
        [&](const std::shared_ptr<TcpConnectionT> &conn) {
          return conn->remote_addr_ == remoteAddr;
        });
    return num_removed > 0;
  }

  virtual std::shared_ptr<TcpConnectionT>
  GetConnection(const AddrType &remoteAddr, uint_fast16_t remotePort)
  {
    auto it = std::find_if(connections_list_.begin(), connections_list_.end(),
                           [&](const std::shared_ptr<TcpConnectionT> &conn) {
                             return conn->remote_addr_ == remoteAddr
                                    && conn->remote_port_ == remotePort;
                           });
    if (it != connections_list_.end()) {
      return *it;
    }
    return nullptr;
  }
};

template <typename Factory, typename TcpConnFactory, typename AddrType>
concept FactoryForTcpService
    = requires(Factory f, TcpConnFactory cf, AddrType a, uint_fast16_t p)
{
  { f(std::move(cf), a, p) }
      ->std::convertible_to<TcpService<AddrType, TcpConnFactory> >;
};

template <typename AddrType, typename TcpServiceT>
class UserspaceTcpStack
{
protected:
  asio::any_io_executor exec_;
  asio::strand<asio::any_io_executor> strand_;
  std::forward_list<std::shared_ptr<TcpServiceT> > services_;

protected:
  template <
      typename T = AddrType,
      typename std::enable_if_t<std::is_same_v<T, asio::ip::address_v4>, int>
      = 0>
  static std::pair<bool, std::size_t>
  ParseIpHeader(NetPacket &packet, std::size_t &packet_length, T &src_addr,
                T &dst_addr)
  {
    auto data = std::data(packet.GetData());

    packet_length = static_cast<std::size_t>(
        ntohs(*reinterpret_cast<const uint16_t *>(data + 2)));

    asio::ip::address_v4::bytes_type bytes
        = { data[12], data[13], data[14], data[15] };
    src_addr = asio::ip::address_v4(bytes);
    bytes = { data[16], data[17], data[18], data[19] };
    dst_addr = asio::ip::address_v4(bytes);

    auto ipHeaderLength = ((static_cast<uint8_t>(data[0])) & 0x0F) * 4;

    return { true, ipHeaderLength };
  }

  template <
      typename T = AddrType,
      typename std::enable_if_t<std::is_same_v<T, asio::ip::address_v6>, int>
      = 0>
  static std::pair<bool, std::size_t>
  ParseIpHeader(NetPacket &packet, std::size_t &packet_length, T &src_addr,
                T &dst_addr)
  {
    auto data = std::data(packet.GetData());

    packet_length = static_cast<std::size_t>(
        ntohs(*reinterpret_cast<const uint16_t *>(data + 4)));

    asio::ip::address_v6::bytes_type bytes;
    std::copy(data + 8, data + 24, bytes.begin());
    src_addr = asio::ip::address_v6(bytes);
    std::copy(data + 24, data + 40, bytes.begin());
    dst_addr = asio::ip::address_v6(bytes);

    constexpr auto ipHeaderLength = 40; // IPv6 header is always 40 bytes
    return { true, ipHeaderLength };
  }

  // Helper struct to hold parsed packet info
  struct ParsedPacketInfo
  {
    AddrType src_addr;
    AddrType dst_addr;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t tcp_flags;
    uint32_t seq_num;
    uint32_t ack_num;
    std::size_t payload_size;
  };

  // Step 1: Parse packet outside any strand. Purely computational.
  template <NetPacketWrapper PacketContainer>
  static std::optional<ParsedPacketInfo>
  parse_and_validate_packet(const PacketContainer &packets)
  {
    auto get_packet_ref = []<typename P>(P &&packet_like) -> NetPacket & {
      if constexpr (requires { packet_like->GetUsedBytes(); }) {
        // It's a smart pointer
        return *packet_like;
      } else {
        // It's a value
        return packet_like;
      }
    };

    auto total_bytes_used = std::accumulate(
        std::cbegin(packets), std::cend(packets), std::size_t(0),
        [&get_packet_ref](std::size_t sum, const auto &packet) {
          return sum + get_packet_ref(packet).GetUsedBytes();
        });

    auto &packet = get_packet_ref(*std::begin(packets));

    AddrType src_addr, dst_addr;
    std::size_t packet_length, ip_payload_offset;
    bool success;

    std::tie(success, ip_payload_offset)
        = ParseIpHeader(packet, packet_length, src_addr, dst_addr);
    if (!success) {
      return std::nullopt;
    }

    // ... (all your safety checks for packet lengths) ...
    if (total_bytes_used < (ip_payload_offset + kTcpHdrMinimalSize)) {
      return std::nullopt;
    }

    auto tcp = std::data(packet.GetData().subspan(ip_payload_offset));

    return ParsedPacketInfo{
      .src_addr = src_addr,
      .dst_addr = dst_addr,
      .src_port = ntohs(*reinterpret_cast<const uint16_t *>(tcp)),
      .dst_port = ntohs(*reinterpret_cast<const uint16_t *>(tcp + 2)),
      .tcp_flags = static_cast<uint8_t>(tcp[13]),
      .seq_num = ntohl(*reinterpret_cast<const uint32_t *>(tcp + 4)),
      .ack_num = ntohl(*reinterpret_cast<const uint32_t *>(tcp + 8)),
      .payload_size
      = total_bytes_used - (ip_payload_offset + kTcpHdrMinimalSize)
    };
  }

  // Step 2: The main logic coroutine, broken down into clear stages.
  template <NetPacketWrapper PacketContainer>
  asio::awaitable<TcpStackState>
  process_packets_impl(PacketContainer &&packets)
  {
    // Stage 1: Parse on any thread (no strand).
    auto parsed_info = parse_and_validate_packet(packets);
    if (!parsed_info) {
      co_return TcpStackState::ERR_WRONG_PROTOCOL;
    }

    // Stage 2: Switch to stack's strand ONLY to find the service.
    co_await asio::post(this->strand_, asio::use_awaitable);

    auto it = std::find_if(
        this->services_.begin(), this->services_.end(),
        [&](const auto &s) { return s->GetPort() == parsed_info->dst_port; });

    if (it == this->services_.end()) {
      co_return TcpStackState::ERR_NO_SUCH_SERVICE;
    }

    // Keep service alive
    auto service = *it;
    auto conn
        = service->AddConnection(parsed_info->src_addr, parsed_info->src_port);
    auto conn_strand = conn->GetStrand();

    // Stage 3: Hand off to the connection's strand to execute TCP logic.
    co_return co_await asio::co_spawn(
        conn_strand,
        [service, info = *parsed_info, packets = std::move(packets)]() mutable
            -> asio::awaitable<TcpStackState> {
          if (info.payload_size == 0) {
            PacketContainer empty_payload;
            co_return co_await service->HandleTcpLogic(
                info.src_addr, info.src_port, info.tcp_flags, info.seq_num,
                info.ack_num, std::move(empty_payload), info.payload_size);
          }

          auto pit = std::begin(packets);
          // TODO: process the case partial payload in header packet
          if (pit != std::end(packets)) {
            // Skip the header packet
            std::advance(pit, 1);
          }

          auto remaining = std::distance(pit, std::end(packets));
          if (remaining <= 0) {
            PacketContainer empty_payload;
            co_return co_await service->HandleTcpLogic(
                info.src_addr, info.src_port, info.tcp_flags, info.seq_num,
                info.ack_num, std::move(empty_payload), info.payload_size);
          } else if (remaining == 1) {
            co_return co_await service->HandleTcpLogic(
                info.src_addr, info.src_port, info.tcp_flags, info.seq_num,
                info.ack_num, std::move(*pit), info.payload_size);
          } else {
            PacketContainer payload_packets;
            // helper: move a range [first, last) into dest preserving order.
            auto append_move
                = [&]<typename It>(PacketContainer &dest, It first, It last) {
                    using DC = std::remove_cvref_t<PacketContainer>;
                    if constexpr (requires(DC & c) { c.before_begin(); }) {
                      // forward_list-like: use insert_after to preserve order
                      auto pos = dest.before_begin();
                      // advance pos to the last element (so insert_after
                      // appends)
                      for (auto it = dest.begin(); it != dest.end(); ++it)
                        ++pos;
                      for (auto it = first; it != last; ++it) {
                        pos = dest.insert_after(pos, std::move(*it));
                      }
                    } else {
                      // general sequence containers: move-insert at end
                      std::copy(std::make_move_iterator(first),
                                std::make_move_iterator(last),
                                std::inserter(dest, dest.end()));
                    }
                  };

            append_move(payload_packets, pit, std::end(packets));
            co_return co_await service->HandleTcpLogic(
                info.src_addr, info.src_port, info.tcp_flags, info.seq_num,
                info.ack_num, std::move(payload_packets), info.payload_size);
          }
        },
        asio::use_awaitable);
  }

public:
  UserspaceTcpStack(asio::any_io_executor ex)
      : exec_(ex), strand_(ex), services_{}
  {
  }
  ~UserspaceTcpStack() = default;

  asio::awaitable<bool>
  AddService(std::shared_ptr<TcpServiceT> service)
  {
    co_await asio::post(strand_, asio::use_awaitable);
    auto it = std::find_if(services_.begin(), services_.end(),
                           [service](std::shared_ptr<TcpServiceT> &s) {
                             return s->GetPort() == service->GetPort();
                           });
    if (it == services_.end()) {
      services_.push_front(service);
      co_return true;
    }
    co_return false;
  }

  asio::awaitable<bool>
  RemoveService(uint_fast16_t port)
  {
    co_await asio::post(strand_, asio::use_awaitable);
    auto num_removed
        = services_.remove_if([port](const std::shared_ptr<TcpServiceT> &s) {
            return s->GetPort() == port;
          });
    co_return num_removed > 0;
  }

  asio::awaitable<bool>
  RemoveService(std::weak_ptr<TcpServiceT> service_weak)
  {
    co_await asio::post(strand_, asio::use_awaitable);

    auto service = service_weak.lock();
    if (!service) {
      co_return false;
    }
    auto num_removed = services_.remove(service);
    co_return num_removed > 0;
  }

  asio::awaitable<bool>
  RemoveConnection(std::shared_ptr<TcpServiceT> service, AddrType addr)
  {
    co_await asio::post(strand_, asio::use_awaitable);

    auto it = std::find(services_.begin(), services_.end(), service);
    if (it != services_.end()) {
      co_return(*it)->RemoveConnection(addr);
    }
    co_return false;
  }

  asio::awaitable<bool>
  RemoveConnection(std::shared_ptr<TcpServiceT> service, AddrType addr,
                   uint_fast16_t port)
  {
    co_await asio::post(strand_, asio::use_awaitable);

    auto it = std::find(services_.begin(), services_.end(), service);
    if (it != services_.end()) {
      co_return(*it)->RemoveConnection(addr, port);
    }
    co_return false;
  }

  template <NetPacketWrapper PacketContainer,
            ASIO_COMPLETION_TOKEN_FOR(void(TcpStackState)) CompletionToken>
  auto
  ProcessIncomingPackets(PacketContainer &&packets, CompletionToken &&token)
  {
    return asio::async_initiate<CompletionToken, void(TcpStackState)>(
        [this, packets = std::forward<PacketContainer>(packets)](
            auto completion_handler) mutable {
          // Spawn the implementation coroutine on the stack's underlying
          // executor.
          asio::co_spawn(
              this->exec_,
              [this, packets = std::move(packets),
               handler = std::move(
                   completion_handler)]() mutable -> asio::awaitable<void> {
                // The result of the implementation is passed to the original
                // caller.
                handler(co_await process_packets_impl(std::move(packets)));
              },
              asio::detached);
        },
        token);
  }
};

template <typename AddrType, typename TcpServiceFactory>
auto
MakeAsyncTcpStack(asio::any_io_executor ex, TcpServiceFactory)
{

  using ServiceTSharedPtrT
      = std::invoke_result_t<TcpServiceFactory, const AddrType &,
                             uint_fast16_t>;

  using TcpServiceT = typename ServiceTSharedPtrT::element_type;

  return UserspaceTcpStack<AddrType, TcpServiceT>(std::move(ex));
}

} // namespace netio
} // namespace celaratcp

#endif
