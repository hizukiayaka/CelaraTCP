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

#include <mutex>

#include <asio/bind_executor.hpp>
#include <asio/posix/stream_descriptor.hpp>
#include <asio/strand.hpp>

namespace celaratcp {
namespace netio {

class PacketSocketLinuxImpl
{
private:
  class PacketSocketLinuxTxAllocator;
  const int fd_;
  asio::posix::stream_descriptor sd_;

  std::mutex mutex_;

  int ifindex_;
  std::array<uint8_t, ETH_ALEN> local_mac_addr_;

  struct sockaddr_ll peer_addr_;

  void *mmap_vaddr_;

  bool SetTxRingBuf(struct tpacket_req3 *req);
  void SetupMemMap();

public:
  PacketSocketLinuxImpl(asio::any_io_executor &ex, int ifindex,
                        std::span<uint8_t> mac_addr);
  ~PacketSocketLinuxImpl();

  bool BindNetworkDevice();
  bool SetPeerMacAddress(std::span<uint8_t> mac_addr);
};

} // namespace netio
} // namespace celaratcp

#endif
