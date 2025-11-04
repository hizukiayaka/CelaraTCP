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
work(std::shared_ptr<recycle::shared_pool<NetMemChunk> > pool, auto stream,
     auto &tcp_stack)
{
  auto pkt = pool->allocate();
  auto buf = pkt->GetMutableBuf();

  auto bytes = co_await asio::async_read(*stream, buf, asio::use_awaitable);
  pkt->SetUsedBytes(bytes);
  std::vector<std::shared_ptr<celaratcp::NetPacket> > pkts = { pkt };

  co_await tcp_stack.ProcessIncomingPackets(pkts);
}

#if 0
void
run2()
{
  asio::io_context ioc;

  asio::ip::network_v4 net1(asio::ip::make_address_v4("169.254.3.1"), 32);

  asio::any_io_executor ex = ioc.get_executor();
  auto stream = std::make_shared<asio::posix::stream_descriptor>(ex);

  memmanager::SimpleHeapAllocator<NetMemChunk> alloc(kIpv4HdrSize);
  auto hdr_pool = std::make_shared<recycle::shared_pool<NetMemChunk> >(
      [&alloc]() { return alloc.Allocation(); });

  hdr_pool->reserve(20);

  auto conn_factory = [&ex]<typename AddrType>(const AddrType &local_addr,
                                               uint_fast16_t local_port,
                                               const AddrType &remote_addr,
                                               uint_fast16_t remote_port) {
    return netio::TcpConnectionChan<AddrType>(local_addr, local_port,
                                              remote_addr, remote_port, ex);
  };

  auto tcp_stack = netio::MakeAsyncTcpStack<asio::ip::address_v4>(
      stream, hdr_pool, conn_factory);
  tcp_stack.AddSimpleService(5162);

  asio::co_spawn(ioc, work(hdr_pool, stream, tcp_stack), asio::detached);

  ioc.run();
}
#endif

template <typename AddrType, typename NetworkIOObjectT,
          netio::CheckSumPolicy Policy = netio::CheckSumPolicy::IP_TCP>
class DummyTcpConnectionChan : public netio::TcpConnection<AddrType, Policy>
{
private:
  std::shared_ptr<NetworkIOObjectT> nout_;

public:
  DummyTcpConnectionChan(const AddrType &local_addr, uint_fast16_t local_port,
                         const AddrType &remote_addr,
                         uint_fast16_t remote_port,
                         std::shared_ptr<NetworkIOObjectT> net_io)
      : netio::TcpConnection<AddrType, Policy>(local_addr, local_port,
                                               remote_addr, remote_port),
        nout_(std::move(net_io))
  {
  }

  ~DummyTcpConnectionChan() override = default;

  void
  Established(uint_fast32_t, uint_fast32_t) override
  {
  }

  virtual std::size_t
  SendReply(netio::TcpPacketType, uint_fast32_t, uint_fast32_t,
            uint_fast32_t) override
  {
    return 0;
  }
};

int
main(int argc, char *argv[])
{
  // run2();

  (void)argc;
  (void)argv;

  asio::io_context ioc;
  auto stream = std::make_shared<asio::posix::stream_descriptor>(ioc);

  memmanager::SimpleHeapAllocator<NetMemChunk> alloc(kIpv4HdrSize);
  auto hdr_pool = std::make_shared<recycle::shared_pool<NetMemChunk> >(
      [&alloc]() { return alloc.Allocation(); });

  hdr_pool->reserve(20);

  auto conn_factory
      = [&stream, &hdr_pool](const asio::ip::address_v4 &local_addr,
                             uint_fast16_t local_port,
                             const asio::ip::address_v4 &remote_addr,
                             uint_fast16_t remote_port) {
          return std::make_shared<DummyTcpConnectionChan<
              asio::ip::address_v4, asio::posix::stream_descriptor> >(
              local_addr, local_port, remote_addr, remote_port, stream);
        };

  auto serv_factory = [&conn_factory](const asio::ip::address_v4 &local_addr,
                                      uint_fast16_t local_port) {
    return std::make_shared<
        netio::TcpService<asio::ip::address_v4, decltype(conn_factory)> >(
        std::move(conn_factory), local_addr, local_port);
  };

  auto tcp_stack
      = netio::MakeAsyncTcpStack<asio::ip::address_v4>(serv_factory);

  asio::ip::network_v4 net1(asio::ip::make_address_v4("169.254.3.1"), 32);
  // The correct address should be the peer address of the tun/tap device
  auto serv = serv_factory(net1.address(), 3000);

  tcp_stack.AddService(serv);

  return 0;
}
