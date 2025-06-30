/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * SPDX-FileCopyrightText: Hsia-Jun(Randy) Li
 */

#ifndef USERSPACE_TCP_STACK_HPP_
#define USERSPACE_TCP_STACK_HPP_

#include <algorithm>
#include <arpa/inet.h>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <deque>
#include <forward_list>

#if PARALLEL
#include <execution>
#define PAR std::execution::par,
#else
#define PAR
#endif

#include <asio.hpp>
#include <memory>
#include <mutex>
#include <numeric>
#include <optional>

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
  using IpHdrArray = std::array<
      uint8_t, std::conditional_t<
                   std::is_same_v<AddrType, asio::ip::address_v4>,
                   std::integral_constant<std::size_t, kIpv4HdrSize>,
                   std::integral_constant<std::size_t, kIpv6HdrSize> >::value>;

  IpHdrArray ip_hdr_tmpl_;
  std::array<uint8_t, kTcpHdrMinimalSize> tcp_hdr_tmpl_;
  // The outgoing sequence number
  uint32_t sequenceN;
  // The outgoing ACK number
  uint32_t ackN;

  std::chrono::time_point<std::chrono::steady_clock> last_activity_;

protected:
  // IPv4 specialization
  template <
      typename T = AddrType,
      typename std::enable_if_t<std::is_same_v<T, asio::ip::address_v4>, int>
      = 0>
  static void
  FillIpHdrTmpl(std::span<uint8_t> buf, AddrType::bytes_type local_addr_ND,
                AddrType::bytes_type remote_addr_ND) noexcept
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
  bool
  ConstructIpHdr(NetPacket &hdr, const std::size_t payload_size = 0,
                 uint8_t ttl = 64) noexcept
  {
    if (hdr.GetMaximumSize() < kIpv4HdrSize) {
      return false;
    }

    auto data = hdr.GetData();
    std::copy(ip_hdr_tmpl_.begin(), ip_hdr_tmpl_.end(), data.begin());

    // Total Length
    *reinterpret_cast<uint16_t *>(data.data() + 2)
        = htons(kIpv4HdrSize + kTcpHdrMinimalSize + payload_size);
    // TTL
    data[8] = ttl;

    if constexpr (Policy == CheckSumPolicy::IP
                  || Policy == CheckSumPolicy::IP_TCP)
    {
    } else {
      // clear checksum
      *reinterpret_cast<uint16_t *>(data.data() + 10) = 0;
    }

    hdr.SetUsedBytes(kIpv4HdrSize);
    return true;
  }

  // IPv6 specialization
  template <
      typename T = AddrType,
      typename std::enable_if_t<std::is_same_v<T, asio::ip::address_v6>, int>
      = 0>
  static void
  FillIpHdrTmpl(std::span<uint8_t> buf, AddrType::bytes_type local_addr_ND,
                AddrType::bytes_type remote_addr_ND) noexcept
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
  bool
  ConstructIpHdr(NetPacket &hdr, const std::size_t payload_size = 0,
                 uint8_t ttl = 64) noexcept
  {
    // Construct IPv6 header
    if (hdr.GetMaximumSize() < kIpv6HdrSize) {
      return false;
    }
    auto data = hdr.GetData();
    std::copy(ip_hdr_tmpl_.begin(), ip_hdr_tmpl_.end(), data.begin());

    // Payload Length
    *reinterpret_cast<uint16_t *>(data.data() + 4)
        = htons(kIpv6HdrSize + kTcpHdrMinimalSize + payload_size);
    // Hop Limit
    data[7] = ttl;

    hdr.SetUsedBytes(kIpv6HdrSize);
    return true;
  }

public:
  using TcpConnectionCtorArgs = std::tuple<const AddrType &, uint_fast16_t,
                                           const AddrType &, uint_fast16_t>;

  TcpConnection(const AddrType &local_addr, uint_fast16_t local_port,
                const AddrType &remote_addr, uint_fast16_t remote_port)
      : remote_addr_(remote_addr), remote_port_(remote_port), ip_hdr_tmpl_{},
        tcp_hdr_tmpl_{}, sequenceN(0), ackN(0)
  {
    FillIpHdrTmpl(std::span<uint8_t>(ip_hdr_tmpl_), local_addr.to_bytes(),
                  remote_addr.to_bytes());
    uint16_t port_nd = htons(local_port);
    auto data = tcp_hdr_tmpl_.data();
    // Construct TCP header
    *reinterpret_cast<uint16_t *>(data) = port_nd;
    port_nd = htons(remote_port);
    *reinterpret_cast<uint16_t *>(data + 2) = port_nd;

    // Data offset + Rsrvd
    data[12] = 0x50;

    // Window size
    *reinterpret_cast<uint16_t *>(data + 14) = htons(4000);
#if 0
    // Checksum
    *reinterpret_cast<uint16_t *>(data + 16) = 0;
    // Urgent pointer
    *reinterpret_cast<uint16_t *>(data + 18) = 0;
#endif
  }

  ~TcpConnection() = default;

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
  UpdateRecvAck(TcpPacketType type, uint32_t ack) noexcept
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

  virtual void
  SetPacketMetaData(std::shared_ptr<NetPacket> packet, uint32_t seq,
                    uint32_t ack)
  {
    packet->meta.data[0] = seq;
    packet->meta.data[1] = ack;
  }

  virtual void Established() {};

  TcpConnection(TcpConnection &&) = default;
  TcpConnection &operator=(TcpConnection &&) = default;

  void
  FreshActivity()
  {
    last_activity_ = std::chrono::steady_clock::now();
  }

  virtual void
  FillPacketIpTcpHdr(TcpPacketType packetType, NetPacket &hdr,
                     std::shared_ptr<NetPacket> payload = nullptr)
  {
    bool success = false;
    switch (packetType) {
    case TcpPacketType::ACK:
      if (payload) {
        success = ConstructIpHdr(hdr, payload->GetUsedBytes());
      } else {
        success = ConstructIpHdr(hdr);
      }
      break;
    default:
      if (payload) {
        payload.reset();
      }
      success = ConstructIpHdr(hdr);
      break;
    }

    if (!success)
      throw std::logic_error("can't fill IP header");

    auto tcp = hdr.GetData().subspan(hdr.GetUsedBytes());
    std::copy(tcp_hdr_tmpl_.begin(), tcp_hdr_tmpl_.end(), tcp.begin());
    auto data = tcp.data();

    uint32_t seq, ack;
    seq = hdr.meta.data[0];
    ack = hdr.meta.data[1];
    *reinterpret_cast<uint32_t *>(data + 4)
        = htonl(sequenceN + seq); // Sequence number
    *reinterpret_cast<uint32_t *>(data + 8)
        = htonl(ackN + ack); // Acknowledgment number

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

    hdr.SetUsedBytes(hdr.GetUsedBytes() + kTcpHdrMinimalSize);
  }

  template <typename, typename>
  friend class TcpService;
  template <typename, typename, typename>
  friend class UserspaceTcpStack;
};

template <typename AddrType, typename TcpConnectionT>
class TcpConnectionTFactory
{
public:
  using FactoryFunction = std::function<TcpConnectionT(
      AddrType local_addr, uint_fast16_t local_port, AddrType remote_addr,
      uint_fast16_t remote_port)>;

  static TcpConnectionT
  Create(AddrType local_addr, uint_fast16_t local_port, AddrType remote_addr,
         uint_fast16_t remote_port)
  {
    return FactoryFunction{}(local_addr, local_port, remote_addr, remote_port);
  }

  using ConnectionType = decltype(std::declval<FactoryFunction>()(
      std::declval<AddrType>(), std::declval<uint_fast16_t>(),
      std::declval<AddrType>(), std::declval<uint_fast16_t>()));
};

template <typename AddrType,
          typename TcpConnectionT = TcpConnection<AddrType> >
class TcpService
{
protected:
  AddrType local_addr_;
  uint_fast16_t port_;
  std::forward_list<TcpConnectionT> connections_list_;

public:
  using TcpServiceCtorArgs = std::tuple<AddrType &, uint_fast16_t>;

  TcpService(AddrType &addr, uint_fast16_t port)
      : local_addr_(addr), port_(port)
  {
  }
  ~TcpService() = default;

  uint_fast16_t
  GetPort() const
  {
    return port_;
  }

  const AddrType &
  GetLocalAddr() const
  {
    return local_addr_;
  }

  virtual bool
  AddConnection(TcpConnectionT &&conn)
  {
    auto it
        = std::find_if(connections_list_.cbegin(), connections_list_.cend(),
                       [&](const TcpConnectionT &c) {
                         return c.remote_addr_ == conn.remote_addr_
                                && c.remote_port_ == conn.remote_port_;
                       });
    if (it == connections_list_.end()) {
      connections_list_.push_front(std::move(conn));
      return true;
    }
    return false;
  }

  virtual bool
  RemoveConnection(AddrType remoteAddr, uint_fast16_t remotePort)
  {
    auto it = std::find_if(connections_list_.begin(), connections_list_.end(),
                           [&](const TcpConnectionT &conn) {
                             return conn.remote_addr_ == remoteAddr
                                    && conn.remote_port_ == remotePort;
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
    bool found = false;
    for (auto it = connections_list_.begin(); it != connections_list_.end();) {
      if (it->remote_addr_ == remoteAddr) {
        it = connections_list_.erase_after(it);
        found = true;
      } else {
        ++it;
      }
    }
    return found;
  }

  virtual std::optional<std::reference_wrapper<TcpConnectionT> >
  GetConnection(AddrType remoteAddr, uint_fast16_t remotePort)
  {
    auto it = std::find_if(connections_list_.begin(), connections_list_.end(),
                           [&](const TcpConnectionT &conn) {
                             return conn.remote_addr_ == remoteAddr
                                    && conn.remote_port_ == remotePort;
                           });
    if (it != connections_list_.end()) {
      return std::optional<std::reference_wrapper<TcpConnectionT> >(
          std::ref(*it));
    }
    return std::nullopt;
  }
};

template <typename AddrType, typename TcpConnectionT = TcpConnection<AddrType>,
          typename TcpServiceT = TcpService<AddrType, TcpConnectionT> >
class UserspaceTcpStack
{
#if 0
  static_assert(std::is_base_of_v<TcpConnection<AddrType>, TcpConnectionT>,
                "TcpConnectionT must derive from TcpConnection<AddrType>");
  static_assert(std::is_base_of_v<TcpService<AddrType>, TcpServiceT>
                    || std::is_base_of_v<TcpService<AddrType, TcpConnectionT>,
                                         TcpServiceT>,
                "TcpServiceT must derive from TcpService");
#endif

protected:
  std::mutex mutex_;
  // Remove connections_list_ from here
  std::forward_list<std::shared_ptr<TcpServiceT> > services_;
  AddrType local_addr_;

private:
  template <typename CharIterator>
  class Uint16Iterator
  {
  public:
    using iterator_category = std::forward_iterator_tag;
    using value_type = uint16_t;
    using difference_type = std::ptrdiff_t;
    using pointer = uint16_t *;
    using reference = uint16_t &;

    Uint16Iterator(CharIterator it) : it_(it) {}

    uint16_t
    operator*() const
    {
#if __BYTE_ORDER == __LITTLE_ENDIAN
      return static_cast<uint16_t>(static_cast<uint8_t>(*(it_ + 1)) << 8)
             | static_cast<uint8_t>(*it_);
#else
      return *reinterpret_cast<const uint16_t *>(&*it_);
#endif
    }
    Uint16Iterator &
    operator++()
    {
      it_ += 2;
      return *this;
    }

    Uint16Iterator
    operator++(int)
    {
      Uint16Iterator tmp = *this;
      it_ += 2;
      return tmp;
    }

    bool
    operator==(const Uint16Iterator &other) const
    {
      return it_ == other.it_;
    }

    bool
    operator!=(const Uint16Iterator &other) const
    {
      return it_ != other.it_;
    }

  private:
    CharIterator it_;
  };

  template <typename Iterator>
  uint_fast16_t
  RangeCheckSum(Iterator begin, Iterator end)
  {
    uint_fast32_t sum
        = std::reduce(Uint16Iterator(begin), Uint16Iterator(end), 0u);

    while (sum >> 16)
      sum = (sum & 0xFFFF) + (sum >> 16);

    return static_cast<uint16_t>(~sum);
  }

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

  UserspaceTcpStack() {}
  ~UserspaceTcpStack() = default;

public:
  void
  SetLocalAddress(const AddrType &addr)
  {
    std::lock_guard<std::mutex> lock(mutex_);
    local_addr_ = addr;
  }

  auto
  AddSimpleService(uint_fast16_t port)
  {
    std::lock_guard<std::mutex> lock(mutex_);
    auto service = std::make_shared<TcpServiceT>(local_addr_, port);
    services_.emplace_front(service);
    return std::weak_ptr<TcpServiceT>(service);
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
  InitialConnSeq(const AddrType &localAddr, const uint_fast16_t localPort,
                 const AddrType &remoteAddr, const uint_fast16_t remotePort)
  {
    return 0;
  }
};

} // namespace netio
} // namespace celaratcp

#endif
