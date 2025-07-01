/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * SPDX-FileCopyrightText: Hsia-Jun(Randy) Li
 */

#include <asio/detail/socket_option.hpp>

#include "raw_ip_socket.hpp"

namespace celaratcp {
namespace netio {

template <typename AddrType>
RawIpSocket<AddrType>::RawIpSocket(asio::any_io_executor ex)
    : socket_(ex,
              asio::generic::raw_protocol(
                  std::is_same_v<AddrType, asio::ip::address_v4> ? AF_INET
                                                                 : AF_INET6,
                  IPPROTO_RAW)),
      strand_write_(std::move(ex))
{
}

RawIpv4Socket::RawIpv4Socket(asio::any_io_executor ex)
    : RawIpSocket<asio::ip::address_v4>(std::move(ex))
{
  asio::detail::socket_option::boolean<IPPROTO_IP, IP_HDRINCL> ip_inc_hdr(
      true);

  socket_.set_option(ip_inc_hdr);
}

Ipv6AncillaMeta::Ipv6AncillaMeta(const asio::ip::address_v6 &dst,
                                 const asio::ip::address_v6 &src,
                                 uint_fast8_t next_proto, uint_fast8_t ttl)
    : dst_{}, iov_{}, msg_{}
{
  dst_.sin6_family = AF_INET6;

  if constexpr (std::endian::native == std::endian::little)
    dst_.sin6_port = std::byteswap(next_proto);
  else
    dst_.sin6_port = next_proto;

  auto addr = dst.to_bytes();
  std::memcpy(&dst_.sin6_addr, std::data(addr),
              std::min(std::size(addr), sizeof(struct in6_addr)));

  auto *ctrls_buf_data = std::data(ctrls_buf_);

  auto *cmsg = reinterpret_cast<cmsghdr *>(ctrls_buf_data);
  cmsg->cmsg_level = IPPROTO_IPV6;
  cmsg->cmsg_type = IPV6_HOPLIMIT;
  cmsg->cmsg_len = CMSG_LEN(sizeof(int));

  int value = ttl;
  std::memcpy(CMSG_DATA(cmsg), &value, sizeof(int));

  cmsg = reinterpret_cast<cmsghdr *>(ctrls_buf_data + CMSG_SPACE(sizeof(int)));
  cmsg->cmsg_level = IPPROTO_IPV6;
  cmsg->cmsg_type = IPV6_PKTINFO;
  cmsg->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));

  struct in6_pktinfo *pkt_info
      = reinterpret_cast<struct in6_pktinfo *>(CMSG_DATA(cmsg));
  addr = src.to_bytes();
  std::memcpy(&(pkt_info->ipi6_addr), std::data(addr),
              std::min(std::size(addr), sizeof(struct in6_addr)));

  msg_.msg_name = &dst_;
  msg_.msg_namelen = sizeof(dst_);
  msg_.msg_iov = &iov_;
  msg_.msg_control = ctrls_buf_data;
  msg_.msg_controllen = std::size(ctrls_buf_);
}

RawIpv6Socket::RawIpv6Socket(asio::any_io_executor ex)
    : RawIpSocket<asio::ip::address_v6>(std::move(ex))
{
}

} // namespace netio
} // namespace celaratcp
