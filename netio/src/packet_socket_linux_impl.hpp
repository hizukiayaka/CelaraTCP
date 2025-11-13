/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * SPDX-FileCopyrightText: Hsia-Jun(Randy) Li
 */

#ifndef PACKET_SOCKET_LINUX_IMPL_HPP_
#define PACKET_SOCKET_LINUX_IMPL_HPP_

extern "C"
{
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <sys/socket.h>
}

#include <cstddef>
#include <span>

namespace celaratcp {
namespace netio {

class PacketSocketLinuxImpl
{
private:
  const int fd_;

  const int ifindex_;

  void *mmap_vaddr_;
  std::size_t mmap_length_;

public:
  PacketSocketLinuxImpl(int ifindex, int socket_type);

  ~PacketSocketLinuxImpl();

  int GetSocketHandle() const noexcept;
  bool BindNetworkDevice();

  bool SetTxRingBuf(struct tpacket_req3 *req);
  std::span<uint8_t> SetupMemMap(std::size_t ring_size);
};

} // namespace netio
} // namespace celaratcp

#endif
