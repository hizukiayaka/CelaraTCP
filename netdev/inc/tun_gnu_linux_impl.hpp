/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * SPDX-FileCopyrightText: Hsia-Jun(Randy) Li
 */

#ifndef TUN_GNU_LINUX_IMPL_HPP
#define TUN_GNU_LINUX_IMPL_HPP

namespace celaratcp {
namespace netdev {

class VirtualNetDev::TunGnuLinuxImpl : public IPacketFilter
{
private:
  asio::posix::stream_descriptor stream_;
  asio::strand<asio::any_io_executor> strand_read_;
  asio::strand<asio::any_io_executor> strand_write_;

  struct nl_sock *sk_;
  struct rtnl_link *link_;
  int ifindex_;

  struct bpf_object *filter_obj_;
  struct bpf_object *steering_obj_;

  struct bpf_program *filter_prog_;
  struct bpf_program *steering_prog_;

  int filter_map_fd_;

  int services_v4_mapfd_;
  int services_v6_mapfd_;

  struct PeerEntry
  {
    asio::ip::address src_addr;
    std::uint16_t src_port;
  };

  struct PortMapFdPair
  {
    std::uint16_t port;
    int map_fd;
    // Use slot-based container for peer management
    std::vector<std::optional<PeerEntry> > peers;
  };

  std::list<PortMapFdPair> services_mapfd_v4_list_;
  std::list<PortMapFdPair> services_mapfd_v6_list_;

  bool isMasterNode_;
  bool isClient_;

private:
  TunGnuLinuxImpl(asio::any_io_executor &ex, const std::string &intl_name);
  /* it would create a new queue */
  // TunGnuLinuxImpl (const TunGnuLinuxImpl &other);
  bool attachXdpProgram(const std::string &xdp_program_path);
  bool attachSteeringEbpf(const std::string &ebpf_program_path);
  bool attachFilterEbpf(const std::string &ebpf_program_path);

public:
  ~TunGnuLinuxImpl();
  /* client peer */
  TunGnuLinuxImpl(asio::any_io_executor &ex, const std::string &intl_name,
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

  template <typename MutableBufferSequence>
  asio::awaitable<std::size_t>
  async_read(MutableBufferSequence &&bufs)
  {
    co_return co_await asio::async_read(
        stream_, std::forward<MutableBufferSequence>(bufs),
        asio::bind_executor(strand_read_, asio::use_awaitable));
  }

  template <typename ConstBufferSequence>
  asio::awaitable<std::size_t>
  async_write(ConstBufferSequence &&bufs)
  {
    co_return co_await asio::async_write(
        stream_, std::forward<ConstBufferSequence>(bufs),
        asio::bind_executor(strand_write_, asio::use_awaitable));
  }

  // std::optional<TunGnuLinuxImpl> addNode(asio::ip::address_v4 &addr);

  bool up();
  bool down();

  // IPacketFilter interface
  std::list<NetDevFiltertype> getSupportFilterType() const override;
  bool setNetDevFilterType(std::list<NetDevFiltertype> type) override;
  bool addWatchIpv4Port(uint16_t port) override;
  bool addWatchIpv6Port(uint16_t port) override;
  bool removeWatchIpv4Port(uint16_t port) override;
  bool removeWatchIpv6Port(uint16_t port) override;

  bool addPeerNode(const asio::ip::address &addr, uint16_t src_port,
                   uint16_t dst_port) override;
  bool removePeerNode(const asio::ip::address &addr, uint16_t src_port,
                      uint16_t dst_port) override;
};

}
}

#endif
