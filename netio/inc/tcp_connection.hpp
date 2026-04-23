#ifndef USERSPACE_TCP_CONNECTION_HPP_
#define USERSPACE_TCP_CONNECTION_HPP_

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
#include <future>
#include <iterator>
#include <memory>
#include <mutex>
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

#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/experimental/concurrent_channel.hpp>
#include <asio/ip/address.hpp>
#include <asio/strand.hpp>
#include <asio/use_future.hpp>

#include <recycle/shared_pool.hpp>

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

template <typename AddrType,
          NetPacketWrapper PacketContainer
          = std::vector<std::shared_ptr<NetPacket> >,
          CheckSumPolicy Policy = CheckSumPolicy::None>
class TcpConnection
{
public:
  using ChannelType = asio::experimental::concurrent_channel<void(
      asio::error_code, PacketContainer &&)>;

  using PayloadWrapType = PacketContainer;

  TcpConnectionState state_;
  const AddrType remote_addr_;
  const uint_fast16_t remote_port_;

protected:
  asio::strand<asio::any_io_executor> strand_;

  ChannelType rx_chan_;

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
  template <NetPacketLike PacketT>
  bool
  FillIpTcpHdr(TcpPacketType packet_type, PacketT &packet,
               std::size_t payload_size, uint_fast32_t ttl)
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

    using Meta = packet_meta_t<PacketT>;
    if constexpr (std::is_base_of_v<celaratcp::TcpSeqMeta, Meta>) {
      if (auto *m = packet.GetMeta()) {
        // Sequence number
        *reinterpret_cast<uint32_t *>(data + 4) = htonl(m->seq_num);
        // Acknowledgment number
        *reinterpret_cast<uint32_t *>(data + 8) = htonl(m->ack_num);
      }
    }

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

    // Sequence + ACK fields are bytes 4..11 in TCP header
    tcp_sum += InternetSum(tcp.subspan(4, 8));

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
  static constexpr bool
  IsNetPacketContainer()
  {
    return NetPacketContainer<PacketContainer>;
  }

  using TcpConnectionCtorArgs
      = std::tuple<const AddrType &, uint_fast16_t, const AddrType &,
                   uint_fast16_t, asio::any_io_executor>;

  TcpConnection(const AddrType &local_addr, uint_fast16_t local_port,
                const AddrType &remote_addr, uint_fast16_t remote_port,
                asio::any_io_executor ex)
      : state_(TcpConnectionState::LISTEN), remote_addr_(remote_addr),
        remote_port_(remote_port), strand_(ex), rx_chan_(ex, 32),
        ip_hdr_tmpl_{}, tcp_hdr_tmpl_{}, partial_sum_for_checksum_(0),
        partial_ipv4_sum_for_checksum_(0), initial_sequenceN_(0),
        remote_initial_sequenceN_(0)
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

  auto
  GetStrand()
  {
    return strand_;
  }

  template <NetPacketLike PacketT>
  void
  SetPacketSeqAck(PacketT &packet, uint_fast32_t seq, uint_fast32_t ack)
  {
    using Meta = packet_meta_t<PacketT>;

    if constexpr (std::is_base_of_v<celaratcp::TcpSeqMeta, Meta>) {
      if (auto *m = packet.GetMeta()) {
        m->seq_num = seq;
        m->ack_num = ack;
      }
    } else {
      // No-op for other meta types
      (void)packet;
      (void)seq;
      (void)ack;
    }
  }

  /**
   * Handle all the case that IP and TCP headers with or without payload
   * in a single NetPacket.
   */
  template <NetPacketLike PacketT>
  void
  FillPacketIpTcpHdr(TcpPacketType packet_type, PacketT &packet,
                     uint_fast32_t ttl)
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

    auto success = FillIpTcpHdr(packet_type, packet, payload_size, ttl);
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

      CompleteTcpCheckSum(tcp, ip_payload_size, payload_sum);
    }
    packet.SetUsedBytes(kIpTcpHdrMinimalSize + payload_size);
  }

  template <NetPacketWrapper AnyPacketContainer>
  void
  AssemblePacketHeaders(TcpPacketType packet_type, AnyPacketContainer &packets,
                        uint_fast32_t ttl = 0)
  {
    auto get_packet_ref = []<typename P>(P &&packet_like) -> decltype(auto) {
      if constexpr (requires { packet_like->GetUsedBytes(); }) {
        return *packet_like; // It's a smart or raw pointer
      } else {
        return packet_like; // It's a value or reference
      }
    };

    if constexpr (NetPacketContainer<AnyPacketContainer>) {
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
        FillPacketIpTcpHdr(packet_type, packet, ttl);
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
        auto &&packet = get_packet_ref(*p_begin);

        auto success
            = FillIpTcpHdr(packet_type, packet, subseq_payload_size, ttl);
        if (!success) {
          throw std::runtime_error("Failed to fill IP and TCP headers");
        }

        if constexpr (Policy != CheckSumPolicy::None) {
          auto tcp
              = (packet.GetData()).subspan(kIPHdrSize, kTcpHdrMinimalSize);

          CompleteTcpCheckSum(tcp, kTcpHdrMinimalSize + subseq_payload_size,
                              payload_sum);
        }
      } else {
        // Only first packet should be available
        auto &packet = get_packet_ref(*p_begin);

        FillPacketIpTcpHdr(packet_type, packet, ttl);
      }
    } else {
      // Single packet case - handle both reference and pointer types
      auto &packet = get_packet_ref(packets);
      FillPacketIpTcpHdr(packet_type, packet, ttl);
    }
  }

  /**
   * Called when the TCP handshake reaches ESTABLISHED.
   *
   * @param local_seq
   * Client path (we received SYN-ACK and sent ACK):
   * Server path (we received ACK after sending SYN-ACK):
   * sequence number we will send for the next ACK packet.
   *
   * @param peer_seq
   * Client path (we received SYN-ACK and sent ACK):
   * Server path (we received ACK after sending SYN-ACK):
   * expected sequence number we will receive from the
   * peer for the next ACK packet.
   */
  virtual void Established(uint_fast32_t local_seq, uint_fast32_t peer_seq)
      = 0;

  /* The below two methods are used for handshake only */
  virtual asio::awaitable<void>
  AsyncSendReply(TcpPacketType, uint_fast32_t seq, uint_fast32_t ack,
                 uint_fast32_t ttl)
      = 0;

  virtual std::size_t
  SendReply(TcpPacketType packet_type, uint_fast32_t seq, uint_fast32_t ack,
            uint_fast32_t ttl)
  {
    // Spawn a coroutine on the connection's strand to run the async
    // operation. Use asio::use_future to get a future that completes when
    // the coroutine is done.
    std::future<void> f = asio::co_spawn(
        strand_, AsyncSendReply(packet_type, seq, ack, ttl), asio::use_future);

    try {
      // Block this thread until the future is ready (i.e., async op is
      // complete).
      f.get();
    }
    catch (const std::exception &e) {
      // Handle or log exceptions from the async operation.
      // For now, we can just rethrow or return 0.
      return 0;
    }
    return 1; // Or return a more meaningful size if available.
  }

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
};

} // namespace netio
} // namespace celaratcp

#endif
