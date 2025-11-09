/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * SPDX-FileCopyrightText: Hsia-Jun(Randy) Li
 */

extern "C"
{
#include <sys/mman.h>
#include <unistd.h>
}
#include <cstring>

#include "packet_socket_linux_impl.hpp"

namespace celaratcp {
namespace netio {

PacketSocketLinuxImpl::PacketSocketLinuxImpl(std::string_view interface_name)
    : fd_(socket(PF_PACKET, SOCK_RAW, 0)), mode_{ Mode::RAW }, ifindex_(-1),
      interface_name_(interface_name), mmap_vaddr_(MAP_FAILED)
{
}

PacketSocketLinuxImpl::PacketSocketLinuxImpl(int ifindex)
    : fd_(socket(PF_PACKET, SOCK_DGRAM, 0)), mode_{ Mode::DGRAM },
      ifindex_(ifindex), interface_name_{}, mmap_vaddr_(MAP_FAILED)
{
}

int
PacketSocketLinuxImpl::GetSocketHandle() const noexcept
{
  return fd_;
}

bool
PacketSocketLinuxImpl::BindNetworkDevice()
{
  if (mode_ == Mode::RAW && ifindex_ == -1) {
    struct sockaddr link_addr{};
    link_addr.sa_family = AF_PACKET;
    std::memcpy(
        link_addr.sa_data, std::data(interface_name_),
        std::min(sizeof(link_addr.sa_data) - 1, std::size(interface_name_)));

    if (bind(fd_, &link_addr, sizeof(link_addr))) {
      return false;
    }

    return true;

  } else {
    struct sockaddr_ll link_addr{};
    link_addr.sll_family = PF_PACKET;
    /**
     * The protocol can optionally be 0 in case we only want to transmit
     * via this socket, which avoids an expensive call to packet_rcv().
     * In this case, you also need to bind(2) the TX_RING
     * with sll_protocol = 0 set.
     */
    link_addr.sll_protocol = 0;
    link_addr.sll_ifindex = ifindex_;

    if (bind(fd_, reinterpret_cast<struct sockaddr *>(&link_addr),
             sizeof(link_addr)))
    {
      return false;
    }

    return true;
  }

  return false;
}

bool
PacketSocketLinuxImpl::SetTxRingBuf(struct tpacket_req3 *req)
{

  int v = TPACKET_V3;
  auto err = setsockopt(fd_, SOL_PACKET, PACKET_VERSION, &v, sizeof(v));
  if (err)
    return false;

  err = setsockopt(fd_, SOL_PACKET, PACKET_TX_RING,
                   reinterpret_cast<void *>(req), sizeof(*req));
  if (err)
    return false;

  return true;
}

std::span<uint8_t>
PacketSocketLinuxImpl::SetupMemMap(std::size_t ring_size)
{
  /**
   * To use one socket for capture and transmission, the mapping of
   * both the RX and TX buffer ring has to be done with one call to mmap.
   * RX must be the first as the kernel maps the TX ring memory right after
   * the RX one.
   */
  mmap_vaddr_
      = ::mmap(nullptr, ring_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd_, 0);

  if (MAP_FAILED == mmap_vaddr_)
    return std::span<uint8_t>{};

  mmap_length_ = ring_size;
  return std::span<uint8_t>{ reinterpret_cast<uint8_t *>(mmap_vaddr_),
                             mmap_length_ };
}

PacketSocketLinuxImpl::~PacketSocketLinuxImpl()
{
  if (MAP_FAILED != mmap_vaddr_) {
    ::munmap(reinterpret_cast<void *>(mmap_vaddr_), mmap_length_);
  }

  close(fd_);
}

} // namespace netio
} // namespace celaratcp
