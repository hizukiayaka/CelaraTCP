/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * SPDX-FileCopyrightText: Hsia-Jun(Randy) Li
 */

#include <coroutine>
#include <net_packet.hpp>
#include <worker_interface.hpp>

#include "virtual_netdev.hpp"
#include "userspace_tcp_stack_helper.hpp"
#include <asio.hpp>
#include <asio/awaitable.hpp>
#include <asio/experimental/coro.hpp>

using namespace celaratcp;

class manger{
public:
  SyncUserspaceTcpStack<asio::ip::address_v4> &tcpStack_;
  recycle::shared_pool<Ipv4TcpHdrPacket> hdrPool_;
  recycle::shared_pool<NetPacketSW<regularMtu - ipv4HdrSize>> payloadPool_;
public:
  manger(SyncUserspaceTcpStack<asio::ip::address_v4> &tcpStack) : tcpStack_(tcpStack), hdrPool_(), payloadPool_() {
    hdrPool_.reserve(20);
    payloadPool_.reserve(20);
  }
  ~manger() = default;
};

int main1(int argc, char *argv[])
{
#if 0
  asio::io_context ioc;

  asio::ip::network_v4 net1(asio::ip::make_address_v4("169.254.3.1"), 32);
  netdev::VirtualNetDev tun(ioc, "test0", net1.address());
  netdev::IPacketFilter *filter = tun;

  SyncUserspaceTcpStack<asio::ip::address_v4> tcpStack;
  tcpStack.addSimpleService(5162);

  recycle::shared_pool<Ipv4TcpHdrPacket> hdrPool;
  hdrPool.reserve(20);
  recycle::shared_pool<NetPacketSW<regularMtu - ipv4HdrSize>> payloadPool;
  payloadPool.reserve(20);

  auto hdr = hdrPool.allocate();
  auto payload = payloadPool.allocate();
  std::list<asio::mutable_buffer> mbufs = {hdr->getMutableBuf(), payload->getMutableBuf()};
  std::forward_list<std::shared_ptr<NetPacket>> packets = {hdr, payload};

  auto readHandler = [&tun, &tcpStack, &hdrPool, &payloadPool](auto&& readHandler, std::shared_ptr<Ipv4TcpHdrPacket> hdr,
    std::shared_ptr<NetPacketSW<regularMtu - ipv4HdrSize>> payload, std::error_code ec, std::size_t bytes_transferred) {
    if (ec) {
      std::cerr << "Error: " << ec.message() << "\n";
      return;
    }
    tcpStack.filterIncomingPacket(hdr);

    hdr = hdrPool.allocate();
    payload = payloadPool.allocate();

    std::forward_list<asio::mutable_buffer> packets = {hdr->getMutableBuf(), payload->getMutableBuf()};

    auto readCallback = std::bind(readHandler, std::ref(readHandler), hdr, payload, std::placeholders::_1, std::placeholders::_2);
    tun.async_read(packets, readCallback);
    std::cout << "Received " << bytes_transferred << " bytes\n";
  };

  auto readCallback = std::bind(readHandler, std::ref(readHandler), hdr, payload, std::placeholders::_1, std::placeholders::_2);

  auto testCallback = [&](std::error_code ec, std::size_t bytes_transferred) {
    if (ec) {
      std::cerr << "Error: " << ec.message() << "\n";
      return;
    }
    std::cout << "Received " << bytes_transferred << " bytes\n";
  };

  tun.async_read(packets, testCallback);
  tun.async_read(mbufs, testCallback);
#endif
  return 0;
}

asio::awaitable<void> run2()
{
  auto executor = co_await asio::this_coro::executor;

  asio::ip::network_v4 net1(asio::ip::make_address_v4("169.254.3.1"), 32);
  netdev::VirtualNetDev tun(executor, "test0", net1.address());
  netdev::IPacketFilter *filter = tun;

  recycle::shared_pool<Ipv4TcpHdrPacket> hdrPool;
  hdrPool.reserve(20);

  AsyncUserspaceTcpStack<asio::ip::address_v4> tcpStack(executor, std::ref(tun), hdrPool);
  tcpStack.setLocalAddress(net1.address());
  tcpStack.addSimpleService(5162);

  recycle::shared_pool<NetPacketSW<regularMtu - ipv4HdrSize>> payloadPool;
  payloadPool.reserve(20);

  auto hdr = hdrPool.allocate();
  auto payload = payloadPool.allocate();
  std::list<asio::mutable_buffer> mbufs = {hdr->getMutableBuf(), payload->getMutableBuf()};

  auto length = co_await tun.async_read(mbufs);
  if (length > 0) {
    std::vector<std::shared_ptr<NetPacket>> packets = {hdr, payload};
    co_await tcpStack.processIncomingPackets(packets);
  }
}

int main2(int argc, char *argv[])
{
  asio::io_context ioc;
  asio::co_spawn(ioc, run2(), asio::detached);

  return 0;
}

int main(int argc, char *argv[])
{
  main1(argc, argv);
  main2(argc, argv);

  return 0;
}
