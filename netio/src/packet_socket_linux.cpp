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
    : pImpl_([&] {
        if (!netdev->IsSuitableForAfPacket()) {
          throw std::invalid_argument(
              std::format("Interface {} is not suitable for AF_PACKET",
                          netdev->GetInterfaceName()));
        }

        auto mac_addr = netdev->GetMacAddress();

        return std::make_unique<PacketSocketLinuxImpl>(
            ex, netdev->GetInterfaceIndex(), mac_addr);
      }()),
      netdev_(netdev)
{
}

/* private method */
void
PacketSocketLinux::CalculateTxBufSize()
{
  static const long page_size = sysconf(_SC_PAGESIZE);

  struct tpacket_req3 req{};
  auto mtu = netdev_->GetMtu();

  const std::size_t need
      = sizeof(tpacket3_hdr) + ETH_HLEN + static_cast<std::size_t>(mtu);

  auto align_up
      = [](std::size_t v, std::size_t a) { return (v + a - 1) & ~(a - 1); };

  std::size_t frame_size = align_up(need, TPACKET_ALIGNMENT);

  if (frame_size <= static_cast<std::size_t>(page_size)) {
    // Find smallest aligned frame_size dividing page_size (no gaps in a page).
    while (static_cast<std::size_t>(page_size) % frame_size != 0) {
      frame_size = align_up(frame_size + 1, TPACKET_ALIGNMENT);
      if (frame_size > static_cast<std::size_t>(page_size)) {
        // Fallback: just make frame span a whole page
        frame_size = static_cast<std::size_t>(page_size);
        break;
      }
    }
    req.tp_frame_size = frame_size;
    req.tp_block_size
        = static_cast<std::size_t>(page_size); // one page per block
  } else {
    // Large frame: expand to PAGE_SIZE multiple, 1 frame per block.
    frame_size = align_up(frame_size, static_cast<std::size_t>(page_size));
    req.tp_frame_size = frame_size;
    req.tp_block_size = frame_size;
  }

  // Frames per block
  const std::size_t frames_per_block = req.tp_block_size / req.tp_frame_size;

  // Choose block count (tunable). Keep total memory reasonable.
  const std::size_t target_total_bytes = 512 * 1024; // 512 KiB target
  std::size_t block_nr = target_total_bytes / req.tp_block_size;
  if (block_nr == 0)
    block_nr = 1;
  if (block_nr > 256)
    block_nr = 256; // cap

  req.tp_block_nr = block_nr;
  req.tp_frame_nr = frames_per_block * block_nr;

  /**
   * Check packet_set_ring() at kernel/net/packet/af_packet.c
   * TX ring should have zero tp_retire_blk_tov, tp_sizeof_priv
   * and tp_feature_req_word.
   */
  req.tp_retire_blk_tov = 0;
}

} // namespace netio
} // namespace celaratcp
