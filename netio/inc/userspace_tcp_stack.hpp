/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * SPDX-FileCopyrightText: Hsia-Jun(Randy) Li
 */

#ifndef USERSPACE_TCP_STACK_HPP_
#define USERSPACE_TCP_STACK_HPP_

extern "C"
{
#include <arpa/inet.h>
}

#include <algorithm>
#include <chrono>
#include <concepts>
#include <cstdint>
#include <cstring>
#include <forward_list>
#include <iterator>
#include <memory>
#include <numeric>
#include <random>
#include <ranges>
#include <type_traits>
#include <utility>

#if PARALLEL
#include <execution>
#define PAR std::execution::par,
#else
#define PAR
#endif

#include <asio/ip/address.hpp>

#include "internet_checksum.hpp"
#include "net_packet.hpp"

namespace celaratcp {
namespace netio {

enum class TcpConnectionState
{
  CLOSED,
  LISTEN,
  SYN_SENT,
  SYN_RECEIVED,
  ESTABLISHED,
  FIN_WAIT_1,
  FIN_WAIT_2,
  CLOSE_WAIT,
  CLOSING,
  LAST_ACK,
  TIME_WAIT
};

enum class TcpStackState
{
  SUCCESS,
  DROP,
  ERR_ARGUMENT,
  ERR_WRONG_FAMILY,
  ERR_WRONG_PROTOCOL,
  ERR_NO_SUCH_SERVICE,
};

enum class TcpPacketType
{
  SYN,
  SYN_ACK,
  ACK,
  FIN,
  FIN_ACK,
  RST
};

enum class CheckSumPolicy
{
  None,
  IP,
  TCP,
  IP_TCP,
};

/**
 * Generates an initial sequence number based on the 4-tuple
 * (local address, local port, remote address, remote port).
 *
 * This approach avoids reliance on the wall clock and uses a hash-based
 * method for determinism and uniqueness.
 *
 * @param local_addr The local IP address
 * @param local_port The local port
 * @param remote_addr The remote IP address
 * @param remote_port The remote port
 * @return A deterministic initial sequence number
 */
template <typename AddrType>
static uint32_t
GenerateInitialSequenceNumber(const AddrType &local_addr,
                              uint_fast16_t local_port,
                              const AddrType &remote_addr,
                              uint_fast16_t remote_port)
{
  static std::array<uint32_t, 4> secret;
  static std::once_flag init_flag;

  // Initialize the secret key once
  std::call_once(init_flag, []() {
    std::random_device rd;
    std::mt19937 rng(rd());
    std::uniform_int_distribution<uint32_t> dist;
    for (auto &val : secret) {
      val = dist(rng);
    }
  });

  // Combine the 4-tuple with the secret key
  uint32_t hash = secret[0];
  hash ^= std::hash<AddrType>{}(local_addr) ^ secret[1];
  hash ^= static_cast<uint32_t>(local_port) ^ secret[2];
  hash ^= std::hash<AddrType>{}(remote_addr) ^ secret[3];
  hash ^= static_cast<uint32_t>(remote_port);

  // Finalize the hash
  hash = (hash >> 16) ^ (hash & 0xFFFF);
  return hash;
}

template <typename AddrType, CheckSumPolicy Policy = CheckSumPolicy::None>
class TcpConnection
{
public:
  TcpConnectionState state_;
  const AddrType remote_addr_;
  const uint_fast16_t remote_port_;

protected:
  // We can use std::byteswap() from c++23
  constexpr static uint16_t kTcpWindowNetworkOrder = [] {
    constexpr uint16_t kTcpWindowSize = 4000;
    if constexpr (std::endian::native == std::endian::little) {
      // Convert to big-endian (network byte order) if the platform is
      // little-endian
      return static_cast<uint16_t>((kTcpWindowSize >> 8)
                                   | (kTcpWindowSize << 8));
    } else {
      // Already in big-endian, no conversion needed
      return kTcpWindowSize;
    }
  }();

  // Data offset + Rsrvd
  constexpr static uint_fast8_t kTcpDOffsetRsrvd = 0x50;
  constexpr static uint_fast8_t kBSDIpTTLValue = 64;

  constexpr static uint_fast16_t kIPHdrSize = [] {
    if constexpr (std::is_same_v<AddrType, asio::ip::address_v4>) {
      return kIpv4HdrSize;
    } else {
      return kIpv6HdrSize;
    }
  }();

  using IpHdrArray = std::array<
      uint8_t, std::conditional_t<
                   std::is_same_v<AddrType, asio::ip::address_v4>,
                   std::integral_constant<std::size_t, kIpv4HdrSize>,
                   std::integral_constant<std::size_t, kIpv6HdrSize> >::value>;

  IpHdrArray ip_hdr_tmpl_;
  std::array<uint8_t, kTcpHdrMinimalSize> tcp_hdr_tmpl_;

  /**
   * included pseudo IP header sum(TCP seg len is not included),
   * TCP src and dest port fields,
   * data offset, reserved, window size fields
   */
  uint_fast32_t partial_sum_for_checksum_;
  // For IPv4 checksum calculation
  uint_fast32_t partial_ipv4_sum_for_checksum_;

  // The initial outoging sequence number
  uint_fast32_t initial_sequenceN_;
  // The remote initial sequence number
  uint_fast32_t remote_initial_sequenceN_;

  std::chrono::time_point<std::chrono::steady_clock> last_activity_;

  static uint_fast32_t
  SrcDstAddrInternetSum(AddrType::bytes_type &l_addr_nd,
                        AddrType::bytes_type &r_addr_nd)
  {
    uint_fast32_t addr_sum = InternetSum(l_addr_nd);
    addr_sum += InternetSum(r_addr_nd);

    return addr_sum;
  }

  static uint_fast32_t
  TcpSegPartialSum(uint_fast16_t lport, uint_fast16_t rport)
  {
    uint_fast32_t sum = lport + rport;
    sum += static_cast<uint_fast32_t>(kTcpDOffsetRsrvd << 8);
    sum += ntohs(kTcpWindowNetworkOrder);

    return sum;
  }

  // IPv4 specialization
  template <
      typename T = AddrType,
      typename std::enable_if_t<std::is_same_v<T, asio::ip::address_v4>, int>
      = 0>
  static uint_fast32_t
  TcpPseudoPartialSum(uint_fast32_t addr_sum)
  {
    uint_fast32_t sum = IPPROTO_TCP;
    sum += addr_sum;
    // Partial not included Tcp Segment length
    return sum;
  }

  template <
      typename T = AddrType,
      typename std::enable_if_t<std::is_same_v<T, asio::ip::address_v4>, int>
      = 0>
  void
  FillIpHdrTmpl(std::span<uint8_t> buf, AddrType::bytes_type &local_addr_ND,
                AddrType::bytes_type &remote_addr_ND) noexcept
  {
    // Version and IHL
    buf[0] = 0x45;
    // DSCP and ECN
    buf[1] = 0x00;
    // Flags and Fragment Offset
    buf[6] = 0x40;
    // Protocol
    buf[9] = IPPROTO_TCP;

    // Source and destination addresses
    std::copy(local_addr_ND.cbegin(), local_addr_ND.cend(),
              buf.subspan(12).begin());
    std::copy(remote_addr_ND.cbegin(), remote_addr_ND.cend(),
              buf.subspan(16).begin());

    if constexpr (Policy == CheckSumPolicy::IP
                  || Policy == CheckSumPolicy::IP_TCP)
    {
      partial_ipv4_sum_for_checksum_ = InternetSum(buf);
    }
  }

  /**
   * Constructs the IPv4 header in the provided buffer.
   * @param hdr The buffer to write the IPv4 header into.
   * @param payload_size The size of the payload that will follow the IP
   * header.
   * @param ttl The Time To Live (TTL) value for the packet.
   */
  template <
      typename T = AddrType,
      typename std::enable_if_t<std::is_same_v<T, asio::ip::address_v4>, int>
      = 0>
  std::size_t
  ConstructIpHdr(std::span<uint8_t> hdr, const std::size_t payload_size,
                 uint8_t ttl) noexcept
  {
    if (std::size(hdr) < kIpv4HdrSize)
      return 0;

    auto data = std::data(hdr);
    std::copy(ip_hdr_tmpl_.cbegin(), ip_hdr_tmpl_.cend(), hdr.begin());

    // Total Length
    auto total_length = kIpv4HdrSize + payload_size;
    *reinterpret_cast<uint16_t *>(data + 2)
        = htons(static_cast<uint16_t>(total_length));
    // TTL
    if (ttl == 0)
      data[8] = kBSDIpTTLValue;
    else
      data[8] = ttl;

    if constexpr (Policy == CheckSumPolicy::IP
                  || Policy == CheckSumPolicy::IP_TCP)
    {
      uint_fast32_t sum = partial_ipv4_sum_for_checksum_;
      sum += static_cast<uint16_t>(total_length);
      // TTL
      sum += static_cast<uint16_t>(data[8]) << 8;

      // One time fold should be enough, the maximum addition is 65535 + 255
      uint_fast16_t csum = (static_cast<uint16_t>(sum & UINT16_MAX)
                            + static_cast<uint16_t>(sum >> 16));

      *reinterpret_cast<uint16_t *>(data + 10) = htons(~csum);
    }

    return kIpv4HdrSize;
  }

  // IPv6 specialization
  template <
      typename T = AddrType,
      typename std::enable_if_t<std::is_same_v<T, asio::ip::address_v6>, int>
      = 0>
  void
  FillIpHdrTmpl(std::span<uint8_t> buf, AddrType::bytes_type &local_addr_ND,
                AddrType::bytes_type &remote_addr_ND) noexcept
  {
    // Version and Traffic Class
    buf[0] = 0x60;

    // Traffic Class and Flow Label
    buf[1] = 0;
    // Flow Label
    buf[2] = 0;
    // Flow Label
    buf[3] = 0;

    // Hop Limit
    buf[7] = 0;
    // Next Header
    buf[6] = IPPROTO_TCP;
    // Source and destination addresses
    std::copy(local_addr_ND.cbegin(), local_addr_ND.cend(),
              buf.subspan(8).begin());
    std::copy(remote_addr_ND.cbegin(), remote_addr_ND.cend(),
              buf.subspan(24).begin());
  }

  /**
   * Constructs the IPv6 header in the provided buffer.
   * @param hdr The buffer to write the IPv6 header into.
   * @param payload_size The size of the payload that will follow the IP
   * header.
   * @param ttl The Time To Live (TTL) value for the packet.
   */
  template <
      typename T = AddrType,
      typename std::enable_if_t<std::is_same_v<T, asio::ip::address_v6>, int>
      = 0>
  std::size_t
  ConstructIpHdr(std::span<uint8_t> hdr, const std::size_t payload_size,
                 uint8_t ttl) noexcept
  {
    if (std::size(hdr) < kIpv6HdrSize)
      return 0;

    auto data = std::data(hdr);
    std::copy(ip_hdr_tmpl_.cbegin(), ip_hdr_tmpl_.cend(), hdr.begin());

    // Total Length
    *reinterpret_cast<uint16_t *>(data + 4)
        = htons(kIpv6HdrSize + payload_size);

    // Hop Limit
    if (ttl == 0)
      data[7] = kBSDIpTTLValue;
    else
      data[7] = ttl;

    return kIpv6HdrSize;
  }

  template <
      typename T = AddrType,
      typename std::enable_if_t<std::is_same_v<T, asio::ip::address_v6>, int>
      = 0>
  static uint_fast32_t
  TcpPseudoPartialSum(uint_fast32_t addr_sum)
  {
    // https://www.ietf.org/rfc/rfc2460.txt
    // 8.1 Upper-Layer Checksums
    uint_fast32_t sum = IPPROTO_TCP;
    sum += addr_sum;
    // Partial not included Tcp Segment length
    return sum;
  }

  // We don't handle the checksum here
  virtual bool
  FillIpTcpHdr(TcpPacketType packet_type, NetPacket &packet,
               std::size_t payload_size, uint_fast32_t seq, uint_fast32_t ack,
               uint_fast32_t ttl)
  {
    std::size_t ip_hdr_size;
    auto hdr = packet.GetData();

    switch (packet_type) {
    case TcpPacketType::ACK:
      ip_hdr_size
          = ConstructIpHdr(hdr, kTcpHdrMinimalSize + payload_size, ttl);
      break;
    default:
      if (payload_size)
        return false;
      ip_hdr_size = ConstructIpHdr(hdr, kTcpHdrMinimalSize, ttl);
      break;
    }

    auto tcp = hdr.subspan(ip_hdr_size);
    std::copy(tcp_hdr_tmpl_.cbegin(), tcp_hdr_tmpl_.cend(), tcp.begin());
    auto data = std::data(tcp);

    // Sequence number
    *reinterpret_cast<uint32_t *>(data + 4) = htonl(seq);
    // Acknowledgment number
    *reinterpret_cast<uint32_t *>(data + 8) = htonl(ack);

    switch (packet_type) {
    case TcpPacketType::SYN:
      data[13] = 0x02; // Flag
      break;
    case TcpPacketType::SYN_ACK:
      data[13] = 0x12; // Flags
      break;
    case TcpPacketType::ACK:
      data[13] = 0x10; // Flags
      break;
    case TcpPacketType::FIN:
      data[13] = 0x01; // Flags
      break;
    case TcpPacketType::FIN_ACK:
      data[13] = 0x11; // Flags
      break;
    case TcpPacketType::RST:
      data[13] = 0x04; // Flags (RST)
      break;
    default:
      throw std::invalid_argument("Invalid TcpPacketType");
    }

    return true;
  }

  /**
   * It would fill TCP checksum field, with pre-calculated pseudo header sum
   * (except whole payload/Upper-layer length, aka. TCP segment length).
   */
  void
  CompleteTcpCheckSum(std::span<uint8_t> tcp, std::size_t payload_size,
                      uint_fast32_t seq, uint_fast32_t ack,
                      uint_fast32_t payload_sum = 0)
  {
    if (payload_size < kTcpHdrMinimalSize) {
      throw std::invalid_argument(
          "payload_size is less than kTcpHdrMinimalSize");
    }
    if (payload_sum == 0 && payload_size > kTcpHdrMinimalSize) {
      throw std::invalid_argument(
          "We don't have payload sum for non-empty payload");
    }

    uint_fast32_t tcp_sum = partial_sum_for_checksum_;
    tcp_sum += static_cast<uint16_t>(payload_size);

    // NOTE: the left Tcp Segment part here
    tcp_sum += static_cast<uint16_t>(seq >> 16);
    tcp_sum += static_cast<uint16_t>(seq & 0xFFFF);

    tcp_sum += static_cast<uint16_t>(ack >> 16);
    tcp_sum += static_cast<uint16_t>(ack & 0xFFFF);

    // TCP Flags
    tcp_sum += tcp[13];

    if (payload_sum)
      tcp_sum += payload_sum;

    tcp_sum = (tcp_sum & UINT16_MAX) + (tcp_sum >> 16);
    tcp_sum = (tcp_sum & UINT16_MAX) + (tcp_sum >> 16);

    *reinterpret_cast<uint16_t *>(std::data(tcp) + 16)
        = htons(static_cast<uint16_t>(~tcp_sum));
  }

public:
  using TcpConnectionCtorArgs = std::tuple<const AddrType &, uint_fast16_t,
                                           const AddrType &, uint_fast16_t>;

  TcpConnection(const AddrType &local_addr, uint_fast16_t local_port,
                const AddrType &remote_addr, uint_fast16_t remote_port)
      : state_(TcpConnectionState::LISTEN), remote_addr_(remote_addr),
        remote_port_(remote_port), ip_hdr_tmpl_{}, tcp_hdr_tmpl_{},
        partial_sum_for_checksum_(0), partial_ipv4_sum_for_checksum_(0),
        initial_sequenceN_(0), remote_initial_sequenceN_(0)
  {
    typename AddrType::bytes_type l_addr_nd{ local_addr.to_bytes() };
    typename AddrType::bytes_type r_addr_nd{ remote_addr.to_bytes() };

    FillIpHdrTmpl(std::span<uint8_t>(ip_hdr_tmpl_), l_addr_nd, r_addr_nd);

    uint16_t lport_nd = htons(local_port);
    auto data = tcp_hdr_tmpl_.data();
    // Construct TCP header
    *reinterpret_cast<uint16_t *>(data) = lport_nd;
    uint16_t rport_nd = htons(remote_port);
    *reinterpret_cast<uint16_t *>(data + 2) = rport_nd;

    // Data offset + Rsrvd
    data[12] = static_cast<uint8_t>(kTcpDOffsetRsrvd);

    // Window size
    *reinterpret_cast<uint16_t *>(data + 14) = kTcpWindowNetworkOrder;
    // Checksum
    *reinterpret_cast<uint16_t *>(data + 16) = 0;
    // Urgent pointer
    *reinterpret_cast<uint16_t *>(data + 18) = 0;

    if constexpr (Policy != CheckSumPolicy::None) {
      uint32_t addr_sum_for_checksum
          = SrcDstAddrInternetSum(l_addr_nd, r_addr_nd);
      partial_sum_for_checksum_ = TcpPseudoPartialSum(addr_sum_for_checksum);
      /* TCP header part */
      partial_sum_for_checksum_ += TcpSegPartialSum(local_port, remote_port);
    }
  }

  virtual ~TcpConnection() = default;
  TcpConnection(TcpConnection &&) = default;
  TcpConnection &operator=(TcpConnection &&) = default;

  virtual void
  SetPacketSeqAck(NetPacket &packet, uint_fast32_t seq, uint_fast32_t ack)
  {
    packet.meta.data[0] = seq;
    packet.meta.data[1] = ack;
  }

  /**
   * Handle all the case that IP and TCP headers with or without payload
   * in a single NetPacket.
   */
  virtual void
  FillPacketIpTcpHdr(TcpPacketType packet_type, NetPacket &packet,
                     uint_fast32_t seq, uint_fast32_t ack, uint_fast32_t ttl)
  {
    constexpr std::size_t kIpTcpHdrMinimalSize
        = kIPHdrSize + kTcpHdrMinimalSize;

    auto bytes_used = packet.GetUsedBytes();
    if (bytes_used > 0 && bytes_used <= kIpTcpHdrMinimalSize) {
      throw std::invalid_argument(
          "packet is too small or didn't reset bytes_used property");
    } else if (packet.GetMaximumSize() < kIpTcpHdrMinimalSize) {
      throw std::invalid_argument("packet is too small");
    }

    std::size_t payload_size;
    if (bytes_used > 0)
      payload_size = bytes_used - kIpTcpHdrMinimalSize;
    else
      payload_size = 0;

    auto success
        = FillIpTcpHdr(packet_type, packet, payload_size, seq, ack, ttl);
    if (!success) {
      throw std::runtime_error("Failed to fill IP and TCP headers");
    }

    auto tcp = packet.GetData().subspan(kIPHdrSize, kTcpHdrMinimalSize);
    if constexpr (Policy != CheckSumPolicy::None) {
      uint_fast32_t payload_sum = 0;
      if (payload_size > 0) {
        payload_sum = InternetSum(
            packet.GetData().subspan(kIpTcpHdrMinimalSize, payload_size));
      }
      auto ip_payload_size = payload_size + kTcpHdrMinimalSize;

      CompleteTcpCheckSum(tcp, ip_payload_size, seq, ack, payload_sum);
    }
  }

  template <NetPacketWrapper PacketContainer>
  void
  AssemblePacketHeaders(TcpPacketType packet_type, PacketContainer &packets,
                        uint_fast32_t seq = 0, uint_fast32_t ack = 0,
                        uint_fast32_t ttl = 0)
  {
    auto get_packet_ref = []<typename P>(P &&packet_like) -> NetPacket & {
      if constexpr (requires { packet_like->GetUsedBytes(); }) {
        return *packet_like; // It's a smart or raw pointer
      } else {
        return packet_like; // It's a value or reference
      }
    };

    if constexpr (NetPacketContainer<PacketContainer>) {
      auto p_begin = std::begin(packets);
      auto p_end = std::end(packets);

      if (p_begin == p_end) {
        // empty container
        return;
      }

      auto next_it = p_begin;
      if (++next_it == p_end) {
        // single packet case
        auto &packet = get_packet_ref(*p_begin);
        FillPacketIpTcpHdr(packet_type, packet, seq, ack, ttl);
        return;
      }

      std::size_t subseq_payload_size = 0;
      // For later TCP checksum calculation
      uint_fast32_t payload_sum = 0;

      for (auto it = next_it; it != p_end; ++it) {
        auto &packet = get_packet_ref(*it);

        subseq_payload_size += packet.GetUsedBytes();
        if constexpr (Policy != CheckSumPolicy::None) {
          payload_sum += InternetSum(
              packet.GetData().subspan(0, packet.GetUsedBytes()));
        }
        // we are done with subsequent packets
      }

      if (subseq_payload_size > 0) {
        // NOTE: We don't support first packet with payload in this case
        auto &packet = get_packet_ref(*p_begin);

        auto success = FillIpTcpHdr(packet_type, packet, subseq_payload_size,
                                    seq, ack, ttl);
        if (!success) {
          throw std::runtime_error("Failed to fill IP and TCP headers");
        }

        if constexpr (Policy != CheckSumPolicy::None) {
          auto tcp
              = (packet.GetData()).subspan(kIPHdrSize, kTcpHdrMinimalSize);

          CompleteTcpCheckSum(tcp, kTcpHdrMinimalSize + subseq_payload_size,
                              seq, ack, payload_sum);
        }
      } else {
        // Only first packet should be available
        auto &packet = get_packet_ref(*p_begin);

        FillPacketIpTcpHdr(packet_type, packet, seq, ack, ttl);
      }
    } else {
      // Single packet case - handle both reference and pointer types
      auto &packet = get_packet_ref(packets);
      FillPacketIpTcpHdr(packet_type, packet, seq, ack, ttl);
    }
  }

  virtual std::size_t SendReply(TcpPacketType, uint_fast32_t seq,
                                uint_fast32_t ack, uint_fast32_t ttl)
      = 0;

  virtual void Established(uint_fast32_t cur_seq_num,
                           uint_fast32_t cur_ack_num)
      = 0;

  uint_fast32_t
  GetInitialSequenceNumber() const noexcept
  {
    return initial_sequenceN_;
  }

  uint_fast32_t
  GetRemoteInitialSequenceNumber() const noexcept
  {
    return remote_initial_sequenceN_;
  }

  void
  SetInitialSequenceNumber(uint_fast32_t num) noexcept
  {
    initial_sequenceN_ = num;
  }

  void
  SetRemoteInitialSequenceNumber(uint_fast32_t num) noexcept
  {
    remote_initial_sequenceN_ = num;
  }

  void
  FreshActivity()
  {
    last_activity_ = std::chrono::steady_clock::now();
  }
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
  std::mutex mutex_;
  std::forward_list<std::shared_ptr<TcpServiceT> > services_;

protected:
  template <
      typename T = AddrType,
      typename std::enable_if_t<std::is_same_v<T, asio::ip::address_v4>, int>
      = 0>
  std::pair<bool, std::size_t>
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
  std::pair<bool, std::size_t>
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

  UserspaceTcpStack() : mutex_{}, services_{} {}
  ~UserspaceTcpStack() = default;

public:
  bool
  AddService(std::shared_ptr<TcpServiceT> service)
  {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = std::find_if(services_.begin(), services_.end(),
                           [service](std::shared_ptr<TcpServiceT> &it) {
                             return it->GetPort() == service->GetPort();
                           });
    if (it == services_.end()) {
      services_.push_front(service);
      return true;
    }
    return false;
  }

  bool
  RemoveService(uint_fast16_t port)
  {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = std::find_if(services_.begin(), services_.end(),
                           [port](std::shared_ptr<TcpServiceT> &it) {
                             return it->GetPort() == port;
                           });
    if (it != services_.end()) {
      services_.remove(it);
      return true;
    }
    return false;
  }

  bool
  RemoveService(std::weak_ptr<TcpServiceT> service_weak)
  {
    std::lock_guard<std::mutex> lock(mutex_);
    auto service = service_weak.lock();
    if (!service) {
      return false;
    }
    auto it = std::find(services_.begin(), services_.end(), service);
    if (it != services_.end()) {
      services_.remove(it);
      return true;
    }
    return false;
  }

  bool
  RemoveConnection(std::shared_ptr<TcpServiceT> service, AddrType addr)
  {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = std::find(services_.begin(), services_.end(), service);
    if (it != services_.end()) {
      return it->RemoveConnection(addr);
    }
    return false;
  }

  bool
  RemoveConnection(std::shared_ptr<TcpServiceT> service, AddrType addr,
                   uint_fast16_t port)
  {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = std::find(services_.begin(), services_.end(), service);
    if (it != services_.end()) {
      return it->RemoveConnection(addr, port);
    }
    return false;
  }
};

} // namespace netio
} // namespace celaratcp

#endif
