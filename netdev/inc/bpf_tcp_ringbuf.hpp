/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * SPDX-FileCopyrightText: Hsia-Jun(Randy) Li
 */

#pragma once

extern "C"
{
#include "l2_ingress_ring_l4.bpf.h"
}

#include <asio/ip/address.hpp>

#include "bpf_ringbuf.hpp"
#include "net_packet.hpp"

namespace celaratcp {
namespace ebpf {

class BpfRingbufTcpMeta : public TcpSeqMeta
{
private:
  static asio::ip::address
  ExtractIpAddr(const struct capture_tcp_sample *sample)
  {
    if ((sample->addr_l0 == 0) && (sample->addr_h1 == 0)) {
      asio::ip::address_v4::bytes_type src_bytes;

      std::memcpy(std::data(src_bytes), &sample->addr_h0, sizeof(__be32));

      return asio::ip::address_v4(src_bytes);
    } else {
      asio::ip::address_v6::bytes_type src_bytes;

      std::memcpy(std::data(src_bytes), &sample->addr_h0, sizeof(__be32));
      std::memcpy(std::data(src_bytes) + sizeof(__be32), &sample->addr_h1,
                  sizeof(__be32));
      std::memcpy(std::data(src_bytes) + sizeof(__be32) * 2, &sample->addr_l1,
                  sizeof(__be32));
      std::memcpy(std::data(src_bytes) + sizeof(__be32) * 3, &sample->addr_l0,
                  sizeof(__be32));

      return asio::ip::address_v6(src_bytes);
    }
  }

public:
  const asio::ip::address addr_;
  const uint_fast16_t src_port_;
  const uint_fast8_t tcp_flags_;

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
  explicit BpfRingbufTcpMeta(const struct capture_tcp_sample *sample)
      : TcpSeqMeta{ntohl(sample->seq), ntohl(sample->ack_seq)},
        addr_(ExtractIpAddr(sample)), src_port_(ntohs(sample->sport)),
        tcp_flags_(static_cast<uint8_t>(sample->DORsFlags >> 8))
  {
  }
#else
  explicit BpfRingbufTcpMeta(struct capture_tcp_sample *sample)
      : TcpSeqMeta{sample->seq, sample->ack_seq},
        addr_(ExtractIpAddr(sample)), src_port_(sample->sport),
        tcp_flags_(static_cast<uint8_t>(sample->DORsFlags & UINT8_MAX))
  {
  }
#endif

  ~BpfRingbufTcpMeta() {}
};

class BpfRingbufTcpPacket : public NetMemChunkMeta<BpfRingbufTcpMeta>
{
private:
  static const struct capture_tcp_sample *
  GetRawSample(std::span<const uint8_t> data)
  {
    return reinterpret_cast<const struct capture_tcp_sample *>(
        std::data(data));
  }

public:
  BpfRingbufTcpPacket(std::span<const uint8_t> data);

  std::span<unsigned char> GetData() final;

  asio::mutable_buffer
  GetMutableBuf() final
  {
    return asio::mutable_buffer();
  }
};

using EbpfTcpRingAllocator = EbpfRingbufAllocator<BpfRingbufTcpPacket>;

} // namesapce ebpf
} // namespace celaratcp
