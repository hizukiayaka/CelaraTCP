/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * SPDX-FileCopyrightText: Hsia-Jun(Randy) Li
 */

#include "bpf_tcp_ringbuf.hpp"

namespace celaratcp {
namespace ebpf {

BpfRingbufTcpPacket::BpfRingbufTcpPacket(std::span<const uint8_t> data)
    : NetMemChunkMeta<BpfRingbufTcpMeta>(
          const_cast<unsigned char *>(GetRawSample(data)->l4_payload),
          static_cast<std::size_t>(MAX_TCP_PAYLOAD_SIZE),
          std::make_unique<BpfRingbufTcpMeta>(GetRawSample(data)))
{
  used_bytes = GetRawSample(data)->data_size;
}

std::span<unsigned char>
BpfRingbufTcpPacket::GetData()
{
  return std::span<unsigned char>();
}

} // namespace ebpf
} // namespace celaratcp
