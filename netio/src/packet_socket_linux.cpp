/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * SPDX-FileCopyrightText: Hsia-Jun(Randy) Li
 */

#include <numeric>

#include "af_packet_tx_ring_async.hpp"
#include "packet_socket_linux.hpp"
#include "packet_socket_linux_impl.hpp"
#include "physical_netdev_base.hpp"

namespace celaratcp {
namespace netio {

PacketSocketLinux::PacketSocketLinux(
    asio::any_io_executor ex,
    std::shared_ptr<netdev::PhysicalNetdevBase> netdev, bool is_ipv6,
    bool user_fill_l2)
    : ex_(std::move(ex)), pImpl_([&] {
        if (!netdev->IsSuitableForAfPacket()) {
          throw std::invalid_argument(
              std::format("Interface {} is not suitable for AF_PACKET",
                          netdev->GetInterfaceName()));
        }

        if (user_fill_l2) {
          return std::make_unique<PacketSocketLinuxImpl>(
              netdev->GetInterfaceName());
        } else {
          return std::make_unique<PacketSocketLinuxImpl>(
              netdev->GetInterfaceIndex());
        }
      }()),
      netdev_(netdev), is_ipv6_(is_ipv6), user_fill_l2_(user_fill_l2)
{
  if (!pImpl_->BindNetworkDevice())
    throw std::logic_error(
        std::format("can't bind interface {}", netdev_->GetInterfaceName()));
}

PacketSocketLinux::~PacketSocketLinux()
{
  tx_pool_ = nullptr;
  pImpl_ = nullptr;

  netdev_.reset();
}

bool
PacketSocketLinux::SetupTxPool() noexcept
{
  static const long page_size = sysconf(_SC_PAGESIZE);

  auto mtu = netdev_->GetMtu();

  struct tpacket_req3 req{};

  const std::size_t need
      = sizeof(struct tpacket3_hdr) + ETH_HLEN + static_cast<std::size_t>(mtu);

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

  auto ret = pImpl_->SetTxRingBuf(&req);
  if (!ret)
    return false;

  auto buf = pImpl_->SetupMemMap(block_nr * req.tp_block_size);
  if (!std::size(buf))
    return false;

  auto gw_mac_op = netdev_->GetGatewayMacAddress();
  if (!gw_mac_op) {
    return false;
  }

  if (user_fill_l2_) {
    auto mac_addr = netdev_->GetMacAddress();
    // FIXME: this is local storage, need to be in heap.
    auto ether_hdr = GenerateEthernetFrame(*gw_mac_op, mac_addr,
                                           is_ipv6_ ? ETH_P_IPV6 : ETH_P_IP);

    tx_pool_ = std::make_unique<
        memmanager::AFPacketTxRingAsync<memmanager::raw_l2_tag, NetMemChunk> >(
        ex_, pImpl_->GetSocketHandle(), buf, frame_size, req.tp_block_size,
        ether_hdr);

  } else {
    auto ep = MakeEndpoint(netdev_->GetInterfaceIndex(), *gw_mac_op,
                           is_ipv6_ ? ETH_P_IPV6 : ETH_P_IP);

    tx_pool_ = std::make_unique<memmanager::AFPacketTxRingAsync<
        memmanager::dgram_l3_tag, NetMemChunk> >(
        ex_, pImpl_->GetSocketHandle(), buf, frame_size, req.tp_block_size,
        std::move(ep));
  }

  return true;
}

template <class T>
asio::awaitable<T>
ready_awaitable(T value)
{
  co_return std::move(value);
}

asio::awaitable<std::shared_ptr<NetMemChunk> >
PacketSocketLinux::Allocate() noexcept
{
  if (!tx_pool_) {
    return ready_awaitable<std::shared_ptr<NetMemChunk> >({});
  }

  return tx_pool_->Allocate();
}

} // namespace netio
} // namespace celaratcp
