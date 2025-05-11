/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * SPDX-FileCopyrightText: Hsia-Jun(Randy) Li
 */

#ifndef TUN_GNU_LINUX_IMPL_HPP
#define TUN_GNU_LINUX_IMPL_HPP

namespace celaratcp {
namespace netdev {

class VirtualNetDev::TunGnuLinuxImpl
{
private:
  asio::posix::stream_descriptor stream_;

  struct nl_sock *sk_;
  struct rtnl_link *link_;
  int ifindex_;

  bool isMasterNode_;
  bool isClient_;

private:
  TunGnuLinuxImpl(asio::io_context &io_context, const std::string &intl_name);
  /* it would create a new queue */
  // TunGnuLinuxImpl (const TunGnuLinuxImpl &other);
  bool attachXdpProgram(const std::string &xdp_program_path);
  bool attachSteeringEbpf(const std::string &ebpf_program_path);
  bool attachFilterEbpf(const std::string &ebpf_program_path);
public:
  ~TunGnuLinuxImpl();
  /* client peer */
  TunGnuLinuxImpl(asio::io_context &io_context, const std::string &intl_name,
                  const asio::ip::address_v4 &addr);

  template <typename MutableBufferSequence>
  void
  async_read(MutableBufferSequence &bufs, callback_t &&callback)
  {
    asio::async_read(stream_, bufs, std::move(callback));
  }

  template <typename ConstBufferSequence>
  void
  async_write(ConstBufferSequence &bufs, callback_t &&callback)
  {
    asio::async_write(stream_, bufs, std::move(callback));
  }

  void async_read(NetPacket &buf, callback_t &&callback);
  void async_write(NetPacket &buf, callback_t &&callback);

  template <NetPacketContainer PacketSequence>
  void
  async_read(PacketSequence &packets, callback_t &&callback)
  {
    std::forward_list<asio::mutable_buffer> mbufs;
    auto it = mbufs.before_begin();
    for (auto &packet : packets) {
        auto mbuf = packet->getMutableBuf();
        it = mbufs.insert_after(it, mbuf);
      }
    asio::async_read(stream_, mbufs, std::move(callback));
  }

  template <NetPacketContainer PacketSequence>
  void
  async_write(PacketSequence &packets, callback_t &&callback)
  {
    std::forward_list<asio::const_buffer> cbufs;
    auto it = cbufs.before_begin();
    for (auto &packet : packets) {
        auto cbuf = packet->getConstBuf();
        it = cbufs.insert_after(it, cbuf);
      }
    asio::async_write(stream_, cbufs, std::move(callback));
  }

  // std::optional<TunGnuLinuxImpl> addNode(asio::ip::address_v4 &addr);

  bool up();
  bool down();

  std::list<NetDevFiltertype>
  getSupportFilterType() const
  {
    return std::list<NetDevFiltertype>{};
  }

  bool
  setNetDevFilterType(std::list<NetDevFiltertype> type)
  {
    return false;
  }
};

}
}

#endif