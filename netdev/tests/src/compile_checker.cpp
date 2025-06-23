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

#if 0
class manger{
public:
  SyncUserspaceTcpStack<asio::ip::address_v4> &tcpStack_;
  recycle::shared_pool<Ipv4TcpHdrPacket> hdrPool_;
  recycle::shared_pool<NetPacketSW<kRegularMtu - kIpv4HdrSize>> payloadPool_;
public:
  manger(SyncUserspaceTcpStack<asio::ip::address_v4> &tcpStack) : tcpStack_(tcpStack), hdrPool_(), payloadPool_() {
    hdrPool_.reserve(20);
    payloadPool_.reserve(20);
  }
  ~manger() = default;
};

int main1(int argc, char *argv[])
{
  asio::io_context ioc;

  asio::ip::network_v4 net1(asio::ip::make_address_v4("169.254.3.1"), 32);
  netdev::VirtualNetDev tun(ioc, "test0", net1.address());
  netdev::IPacketFilter *filter = tun;

  SyncUserspaceTcpStack<asio::ip::address_v4> tcpStack;
  tcpStack.addSimpleService(5162);

  recycle::shared_pool<Ipv4TcpHdrPacket> hdrPool;
  hdrPool.reserve(20);
  recycle::shared_pool<NetPacketSW<kRegularMtu - kIpv4HdrSize>> payloadPool;
  payloadPool.reserve(20);

  auto hdr = hdrPool.allocate();
  auto payload = payloadPool.allocate();
  std::list<asio::mutable_buffer> mbufs = {hdr->GetMutableBuf(), payload->GetMutableBuf()};
  std::forward_list<std::shared_ptr<NetPacket>> packets = {hdr, payload};

  auto readHandler = [&tun, &tcpStack, &hdrPool, &payloadPool](auto&& readHandler, std::shared_ptr<Ipv4TcpHdrPacket> hdr,
    std::shared_ptr<NetPacketSW<kRegularMtu - kIpv4HdrSize>> payload, std::error_code ec, std::size_t bytes_transferred) {
    if (ec) {
      std::cerr << "Error: " << ec.message() << "\n";
      return;
    }
    tcpStack.FilterIncomingPacket(hdr);

    hdr = hdrPool.allocate();
    payload = payloadPool.allocate();

    std::forward_list<asio::mutable_buffer> packets = {hdr->GetMutableBuf(), payload->GetMutableBuf()};

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
  return 0;
}
#endif

asio::awaitable<void>
run2()
{
  auto executor = co_await asio::this_coro::executor;

  asio::ip::network_v4 net1(asio::ip::make_address_v4("169.254.3.1"), 32);
  netdev::VirtualNetDev tun(executor, "test0", net1.address());
  netdev::IPacketFilter *filter = tun;

  memmanger::SimpleHeapAllocator<NetMemChunk> alloc(kIpv4HdrSize);

  auto hdr_pool = std::make_shared<recycle::shared_pool<NetMemChunk>>(
      [&alloc]() { return alloc.Allocation(); });

  hdr_pool->reserve(20);

  auto tcpStack = MakeAsyncTcpWrapper<asio::ip::address_v4>(executor, tun, hdr_pool);
  tcpStack.SetLocalAddress(net1.address());
  tcpStack.AddSimpleService(5162);

  recycle::shared_pool<NetPacketSW<kRegularMtu - kIpv4HdrSize> > payloadPool;
  payloadPool.reserve(20);

  auto hdr = hdr_pool->allocate();
  auto payload = payloadPool.allocate();
  std::list<asio::mutable_buffer> mbufs
      = { hdr->GetMutableBuf(), payload->GetMutableBuf() };

  auto length = co_await asio::async_read(tun, mbufs, asio::use_awaitable);
  if (length > 0) {
    std::vector<std::shared_ptr<NetPacket> > packets = { hdr, payload };
    co_await tcpStack.ProcessIncomingPackets(packets);
  }
}

int
main2(int argc, char *argv[])
{
  asio::io_context ioc;
  asio::co_spawn(ioc, run2(), asio::detached);

  return 0;
}

int
testSimpleAllocPool()
{
  {
    memmanger::SimpleHeapAllocator<NetMemChunk> alloc(kIpv6HdrSize);

    recycle::shared_pool<NetMemChunk> pool(
        [&alloc]() { return alloc.Allocation(); });
    pool.reserve(2);

    auto packet = pool.allocate();

    {
      std::cout << "free " << pool.unused_resources() << std::endl;
      auto packet = pool.allocate();
      std::cout << "free " << pool.unused_resources() << std::endl;
    }
    pool.free_unused();
  }

  {
    memmanger::SimpleVectorAllocator<NetMemChunk> alloc(kIpv6HdrSize);

    recycle::shared_pool<NetMemChunk> pool(
        [&alloc]() { return alloc.Allocation(); });
    pool.reserve(2);

    auto packet = pool.allocate();

    {
      std::cout << "free " << pool.unused_resources() << std::endl;
      auto packet = pool.allocate();
      std::cout << "free " << pool.unused_resources() << std::endl;
    }
    pool.free_unused();
  }

  {
    std::vector<uint8_t> mems(2000);
    {
      auto alloc = memmanger::ManagedMemAllocator<NetMemChunk>::Create(
          mems.data(), mems.capacity(), kIpv6HdrSize, [&mems]() {
            mems.clear();
            mems.shrink_to_fit();
          });

      auto pool = std::make_shared<recycle::shared_pool<NetMemChunk> >(
          [&alloc]() { return alloc->Allocation(); });
      pool->reserve(20);

      auto packet = pool->allocate();
      std::cout << "container size is " << mems.size() << std::endl;
      {
        std::cout << "free " << pool->unused_resources() << std::endl;
        auto packet = pool->allocate();
        std::cout << "free " << pool->unused_resources() << std::endl;
        packet = pool->allocate();
        packet = pool->allocate();
      }
      std::cout << "packet location is " << packet->GetId() << std::endl;
      packet = pool->allocate();
      std::cout << "packet location is " << packet->GetId() << std::endl;
      pool->free_unused();

      try {
        pool->reserve(50);
      }
      catch (const std::bad_alloc &e) {
        std::cout << "can't allocate so many buffers: " << e.what()
                  << std::endl;
      }
      catch (...) {
        std::cout << "an unknown issue" << std::endl;
      }
    }

    std::cout << "clear mem, now container size is " << mems.size()
              << " capacity is " << mems.capacity() << std::endl;
  }

  return 0;
}

int
main(int argc, char *argv[])
{
  testSimpleAllocPool();
  main2(argc, argv);

  return 0;
}
