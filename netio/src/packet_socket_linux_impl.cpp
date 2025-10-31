/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * SPDX-FileCopyrightText: Hsia-Jun(Randy) Li
 */

namespace celaratcp {
namespace netio {

class PacketSocketLinuxImpl::PacketSocketLinuxTxAllocator
{
};

PacketSocketLinuxImpl::PacketSocketLinuxImpl(asio::any_io_executor &ex,
                                             int ifindex,
                                             std::span<uint8_t> mac_addr)
    : fd_(socket(PF_PACKET, SOCK_DGRAM, 0)), sd_(ex, fd_), ifindex_(ifindex),
      local_mac_addr_{}, peer_addr_{}, mmap_vaddr_(MAP_FAILED)
{
  std::ranges::copy(mac_addr, local_mac_addr_.begin());
}

bool
PacketSocketLinuxImpl::BindNetworkDevice()
{
  std::lock_guard<std::mutex> lock(mutex_);

  struct sockaddr_ll link_addr{};

  link_addr.sll_family = PF_PACKET;
  /**
   * If protocol is set to zero, no packets are received.
   * bind(2) can optionally be called with a nonzero sll_protocol
   * to start receiving packets for the protocols
   * specified.
   * So, I think I don't want to receive any thing here, it
   * would be kept to zero?
   */
  link_addr.sll_protocol = 0;
  link_addr.sll_ifindex = ifindex_;

  auto hw_addr_size = std::size(local_mac_addr_);
  std::memcpy(&(link_addr.sll_addr), std::data(local_mac_addr_), hw_addr_size);
  link_addr.sll_halen = hw_addr_size;

  if (bind(fd_, reinterpret_cast<struct sockaddr *>(&link_addr),
           sizeof(link_addr)))
  {
    return false;
  }

  return true;
}

bool
PacketSocketLinuxImpl::SetPeerMacAddress(std::span<uint8_t> mac_addr)
{
  std::lock_guard<std::mutex> lock(mutex_);

  peer_addr_.sll_family = PF_PACKET;
  peer_addr_.sll_protocol = htons(ETH_P_IP);
  peer_addr_.sll_ifindex = ifindex_;

  auto hw_addr_size = std::size(mac_addr);
  std::memcpy(&(peer_addr_.sll_addr), std::data(mac_addr), hw_addr_size);
  peer_addr_.sll_halen = hw_addr_size;

  /**
   * From man packet(7):
   * If an address is passed using sendto(2) or sendmsg(2), then
   * that overrides the socket default.
   * So I am not going to use this.
   */
  return true;
}

bool
PacketSocketLinuxImpl::SetTxRingBuf(struct tpacket_req3 *req)
{
  std::lock_guard<std::mutex> lock(mutex_);

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

void
PacketSocketLinuxImpl::SetupMemMap()
{
  std::lock_guard<std::mutex> lock(mutex_);
  /**
   * To use one socket for capture and transmission, the mapping of
   * both the RX and TX buffer ring has to be done with one call to mmap.
   * RX must be the first as the kernel maps the TX ring memory right after
   * the RX one.
   */
  // FIXME: you need to map the right size
  std::size_t total_size = 0;
  mmap_vaddr_
      = mmap(nullptr, total_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd_, 0);

  if (MAP_FAILED == mmap_vaddr_)
    return;
}

PacketSocketLinuxImpl::~PacketSocketLinuxImpl()
{
  std::lock_guard<std::mutex> lock(mutex_);

  // FIXME: you need to map the right size
  std::size_t total_size = 0;

  if (MAP_FAILED != mmap_vaddr_) {
    auto err = munmap(reinterpret_cast<void *>(mmap_vaddr_), total_size);
  }
}

} // namespace netio
} // namespace celaratcp
