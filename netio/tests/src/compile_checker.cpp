/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * SPDX-FileCopyrightText: Hsia-Jun(Randy) Li
 */

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
  asio::posix::stream_descriptor stream(executor);

  memmanager::SimpleHeapAllocator<NetMemChunk> alloc(kIpv4HdrSize);
  auto hdr_pool = std::make_shared<recycle::shared_pool<NetMemChunk> >(
      [&alloc]() { return alloc.Allocation(); });

  hdr_pool->reserve(20);

  auto conn_factory = [&executor](const asio::ip::address_v4 &local_addr,
                                 uint_fast16_t local_port,
                                 const asio::ip::address_v4 &remote_addr,
                                 uint_fast16_t remote_port) {
    return netio::TcpConnectionChan<asio::ip::address_v4>(
        local_addr, local_port, remote_addr, remote_port, executor);
  };

  auto tcpStack = netio::MakeAsyncTcpStack<asio::ip::address_v4>(
      executor, stream, hdr_pool, conn_factory);
  tcpStack.SetLocalAddress(net1.address());
  tcpStack.AddSimpleService(5162);
}

int
main(int argc, char *argv[])
{
  asio::io_context ioc;

  asio::co_spawn(ioc, run2(), asio::detached);

  ioc.run();

  return 0;
}
