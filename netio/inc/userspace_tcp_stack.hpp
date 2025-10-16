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
#include <deque>
#include <forward_list>
#include <memory>
#include <numeric>
#include <random>

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

  // The initial outoging sequence number
  uint_fast32_t initial_sequenceN_;
  // The outgoing sequence number
  uint32_t sequenceN;
  // The outgoing ACK number
  uint32_t ackN;

  uint_fast8_t ip_ttl_value_;

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
  static void
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
  }

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
    *reinterpret_cast<uint16_t *>(data + 2)
        = htons(kIpv4HdrSize + payload_size);
    // TTL
    if (ttl == 0)
        data[8] = kBSDIpTTLValue;
    else
        data[8] = ttl;

    if constexpr (Policy == CheckSumPolicy::IP
                  || Policy == CheckSumPolicy::IP_TCP)
    {
      uint16_t csum
          = InternetChecksum(hdr.subspan(0, kIpv4HdrSize));
      *reinterpret_cast<uint16_t *>(data + 10) = htons(csum);
    }

    return kIpv4HdrSize;
  }

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

  // IPv6 specialization
  template <
      typename T = AddrType,
      typename std::enable_if_t<std::is_same_v<T, asio::ip::address_v6>, int>
      = 0>
  static void
  FillIpHdrTmpl(std::span<uint8_t> buf, AddrType::bytes_type &local_addr_ND,
                AddrType::bytes_type &remote_addr_ND) noexcept
  {
    // Version and Traffic Class
    buf[0] = 0x60;
#if 0
    // Traffic Class and Flow Label
    buf[1] = 0;
    // Flow Label
    buf[2] = 0;
    // Flow Label
    buf[3] = 0;
    // Hop Limit
    data[7] = 0;
#endif
    // Next Header
    buf[6] = IPPROTO_TCP;
    // Source and destination addresses
    std::copy(local_addr_ND.cbegin(), local_addr_ND.cend(),
              buf.subspan(8).begin());
    std::copy(remote_addr_ND.cbegin(), remote_addr_ND.cend(),
              buf.subspan(24).begin());
  }

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
    uint_fast32_t sum = IPPROTO_TCP << 8;
    sum += addr_sum;
    // Partial not included Tcp Segment length
    return sum;
  }

public:
  using TcpConnectionCtorArgs = std::tuple<const AddrType &, uint_fast16_t,
                                           const AddrType &, uint_fast16_t>;

  TcpConnection(const AddrType &local_addr, uint_fast16_t local_port,
                const AddrType &remote_addr, uint_fast16_t remote_port)
      : state_(TcpConnectionState::LISTEN), remote_addr_(remote_addr),
        remote_port_(remote_port), ip_hdr_tmpl_{}, tcp_hdr_tmpl_{},
        partial_sum_for_checksum_(0),
        initial_sequenceN(0),
        sequenceN(0), ackN(0)
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

  virtual void SetPacketSeqAck(NetPacket &packet, uint_fast32_t seq, uint_fast32_t ack)
  {
      packet.meta.data[0] = seq;
      packet.meta.data[1] = ack;
  }

#if 0
  virtual void
  UpdateRecvSeq(TcpPacketType type, uint32_t seq,
                uint32_t payload_size = 0) noexcept
  {
    switch (type) {
    case TcpPacketType::SYN:
    case TcpPacketType::SYN_ACK:
      if (payload_size == 0) {
        payload_size = 1;
      }
      ackN = seq + payload_size;

      break;
    case TcpPacketType::ACK:
      break;
    default:
      break;
    }
  }

  virtual void
  UpdateRecvAck([[maybe_unused]] TcpPacketType type,
                [[maybe_unused]] uint32_t ack) noexcept
  {
    // do nothing
  }

  virtual void
  UpdateSentSeq(TcpPacketType type, uint32_t seq = 0,
                uint32_t payload_size = 0) noexcept
  {
    switch (type) {
    case TcpPacketType::SYN:
    case TcpPacketType::SYN_ACK:
      if (payload_size == 0) {
        payload_size = 1;
      }
      if (seq == 0) {
        sequenceN += payload_size;
      } else {
        sequenceN = seq + payload_size;
      }

      break;
    case TcpPacketType::ACK:
      break;
    default:
      break;
    }
  }
#endif

  virtual void Established() {};

  // We don't handle the checksum here
  virtual bool
  FillIpTcpHdr(TcpPacketType packetType, NetPacket &packet,
               std::size_t payload_size,
               uint_fast32_t seq, uint_fast32_t ack,
               uint_fast32_t ttl)
  {
    std::size_t ip_hdr_size;
    auto hdr = packet.GetData();

    switch (packetType) {
    case TcpPacketType::ACK:
      if (payload) {
        ip_hdr_size = ConstructIpHdr(hdr, kTcpHdrMinimalSize + payload_size, ttl);
      } else {
        ip_hdr_size = ConstructIpHdr(hdr, kTcpHdrMinimalSize, ttl);
      }
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

    switch (packetType) {
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

  template <NetPacketWrapper PacketContainer>
  virtual void
  FillPacketIpTcpHdr(TcpPacketType packetType,
                     PacketContainer &packets,
                     uint_fast32_t seq = 0, uint_fast32_t ack = 0,
                     uint_fast32_t ttl = 0)
  {
    if constexpr (NetPacketContainer<PacketContainer>) {
        auto it = std::begin(packets);
        auto end = std::end(packets);

        if (it == end) {
            // empty container
            return;
        }

        auto total_bytes_used = std::accumulate(
            it, end, std::size_t(0),
            [] (std::size_t sum, auto &packet) {
                if constexpr (requires { packet->get(); } || requires { *packet; }) {
                    return sum + packet->GetUsedBytes();
                } else {
                    return sum + packet.GetUsedBytes();
                }
            });

    } else {
		// Single packet case - handle both reference and pointer types
		if constexpr (requires { packets->GetUsedBytes(); }) {
		  // Smart pointer case
		  auto bytes_used = packets->GetUsedBytes();
		  // FIXME: remove the IP header size
		  if (bytes_used > 0)
			FillIpTcpHdr(*packets, bytes_used - kTcpHdrMinimalSize, packetType, seq, ack, ttl);
		  else
			FillIpTcpHdr(*packets, 0, packetType, seq, ack, ttl);
		} 
		else if constexpr (requires { packets.GetUsedBytes(); }) {
		  // Reference case
		  auto bytes_used = packets.GetUsedBytes();
		  // FIXME: remove the IP header size
		  if (bytes_used > 0)
			FillIpTcpHdr(packets, bytes_used - kTcpHdrMinimalSize, packetType, seq, ack, ttl);
		  else
			FillIpTcpHdr(packets, 0, packetType, seq, ack, ttl);
		}
    }

    bool success = false;
    switch (packetType) {
    case TcpPacketType::ACK:
      if (payload) {
        success = ConstructIpHdr(hdr, payload->GetUsedBytes(), ttl);
      } else {
        success = ConstructIpHdr(hdr, 0, ttl);
      }
      break;
    default:
      if (payload) {
        payload.reset();
      }
      success = ConstructIpHdr(hdr, 0, ttl);
      break;
    }

    if (!success)
      throw std::logic_error("can't fill IP header");

    auto ip_hdr_size = hdr.GetUsedBytes();

    auto tcp = hdr.GetData().subspan(hdr.GetUsedBytes());
    std::copy(tcp_hdr_tmpl_.cbegin(), tcp_hdr_tmpl_.cend(), tcp.begin());
    auto data = tcp.data();

    // Sequence number
    *reinterpret_cast<uint32_t *>(data + 4) = htonl(seq);
    // Acknowledgment number
    *reinterpret_cast<uint32_t *>(data + 8) = htonl(ack);

    switch (packetType) {
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

    if constexpr (Policy != CheckSumPolicy::None) {
      uint32_t tcp_sum = partial_sum_for_checksum_;
      const std::size_t payload_size = payload ? payload->GetUsedBytes() : 0;
      tcp_sum += kTcpHdrMinimalSize + payload_size;

      // NOTE: the left Tcp Segment part here
      tcp_sum += static_cast<uint16_t>(seq >> 16);
      tcp_sum += static_cast<uint16_t>(seq & 0xFFFF);

      tcp_sum += static_cast<uint16_t>(ack >> 16);
      tcp_sum += static_cast<uint16_t>(ack & 0xFFFF);

      tcp_sum += static_cast<uint_fast32_t>(data[13]);

      if (payload) {
        auto tcp_checksum = InternetChecksum(payload->GetData(), tcp_sum);
        *reinterpret_cast<uint16_t *>(data + 16) = htons(tcp_checksum);
      } else {
        tcp_sum = (tcp_sum & 0xFFFF) + (tcp_sum >> 16);
        tcp_sum = (tcp_sum & 0xFFFF) + (tcp_sum >> 16);
        *reinterpret_cast<uint16_t *>(data + 16)
            = htons(static_cast<uint16_t>(~tcp_sum));
      }
    }

    hdr.SetUsedBytes(ip_hdr_size + kTcpHdrMinimalSize);
  }

  bool SetInitialSequenceNumber(uint_fast32_t num) {
      initial_sequenceN_ = num;
  }

  void
  FreshActivity()
  {
    last_activity_ = std::chrono::steady_clock::now();
  }
};

template <typename Factory, typename AddrType>
concept FactoryForTcpConnect = requires(Factory f, AddrType a, uint_fast16_t p,
                                        AddrType b, uint_fast16_t q)
{
  { f(a, p, b, q) };
}
&&std::is_constructible_v<TcpConnection<AddrType>, AddrType, uint_fast16_t,
                          AddrType, uint_fast16_t>;

template <typename AddrType, typename TcpConnFactory>
// requires FactoryForTcpConnect<TcpConnFactory, AddrType>
class TcpService
{
protected:
  AddrType local_addr_;
  uint_fast16_t port_;
  TcpConnFactory conn_factory_;

  using TcpConnectionT
      = std::invoke_result_t<decltype(conn_factory_), AddrType, uint_fast16_t,
                             AddrType, uint_fast16_t>;

  std::forward_list<std::shared_ptr<TcpConnectionT> > connections_list_;

public:
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
  AddConnection(AddrType &remote_addr, uint_fast16_t remote_port)
  {
    auto it
        = std::find_if(connections_list_.cbegin(), connections_list_.cend(),
                       [&](const std::shared_ptr<TcpConnectionT> &c) {
                         return c->remote_addr_ == remote_addr
                                && c->remote_port_ == remote_port;
                       });
    if (it == connections_list_.cend()) {
      auto c = conn_factory_(local_addr_, port_, remote_addr, remote_port);
      auto conn = std::make_shared<TcpConnectionT>(std::move(c));
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
  GetConnection(AddrType &remoteAddr, uint_fast16_t remotePort)
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
  // Remove connections_list_ from here
  std::forward_list<std::shared_ptr<TcpServiceT> > services_;
  AddrType local_addr_;

protected:
  template <
      typename T = AddrType,
      typename std::enable_if_t<std::is_same_v<T, asio::ip::address_v4>, int>
      = 0>
  std::pair<bool, std::size_t>
  ParseIpHeader(std::shared_ptr<NetPacket> packet, std::size_t &packet_length,
                T &src_addr, T &dst_addr)
  {
    auto data = packet->GetData().data();

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
  ParseIpHeader(std::shared_ptr<NetPacket> packet, std::size_t &packet_length,
                T &src_addr, T &dst_addr)
  {
    auto data = packet->GetData().data();

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

  UserspaceTcpStack() {}
  ~UserspaceTcpStack() = default;

public:
  void
  SetLocalAddress(const AddrType &addr)
  {
    std::lock_guard<std::mutex> lock(mutex_);
    local_addr_ = addr;
  }

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

  virtual uint32_t
  InitialConnSeq([[maybe_unused]] const AddrType &local_addr,
                 [[maybe_unused]] const uint_fast16_t local_port,
                 [[maybe_unused]] const AddrType &remote_addr,
                 [[maybe_unused]] const uint_fast16_t remote_port)
  {
    return 0;
  }
};

} // namespace netio
} // namespace celaratcp

#endif
