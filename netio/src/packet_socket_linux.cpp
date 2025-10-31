/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * SPDX-FileCopyrightText: Hsia-Jun(Randy) Li
 */

#include <numeric>

#include "packet_socket_linux.hpp"

namespace celaratcp {
namespace netio {

PacketSocketLinux::PacketSocketLinux(
    asio::any_io_executor &ex,
    std::shared_ptr<netdev::PhysicalNetdevBase> netdev)
    : netdev_(netdev),
      pImpl_([&] {
        auto mac_addr = netdev->GetMacAddress();

        return std::make_unique<PacketSocketLinuxImpl>(
            ex, netdev->GetInterfaceIndex(), mac_addr);
      }())
{
}

void PacketSocketLinux::CalculateTxBufSize()
{
  static const long page_size = sysconf(_SC_PAGESIZE);

  struct tpacket_req3 req {};
  auto mtu = netdev_->GetMtu();

  const std::size_t required_frame_space =
      sizeof(struct tpacket3_hdr) + ETH_HLEN + mtu;

  req.tp_frame_size =
      (required_frame_space + TPACKET_ALIGNMENT - 1) & ~(TPACKET_ALIGNMENT - 1);

  req.tp_block_size =
      (static_cast<std::size_t>(page_size) * req.tp_frame_size) /
      std::gcd(static_cast<std::size_t>(page_size), req.tp_frame_size);

  const std::size_t block_count = 128;
  req.tp_block_nr = block_count;

  req.tp_frame_nr = (req.tp_block_size / req.tp_frame_size) * req.tp_block_nr;

  /**
   * Check packet_set_ring() at kernel/net/packet/af_packet.c
   * TX ring should have zero tp_retire_blk_tov, tp_sizeof_priv
   * and tp_feature_req_word.
   */
  req.tp_retire_blk_tov = 0;
}

} // namespace netio
} // namespace celaratcp
