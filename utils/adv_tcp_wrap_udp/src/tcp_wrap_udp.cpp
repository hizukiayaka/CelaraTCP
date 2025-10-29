/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * SPDX-FileCopyrightText: Hsia-Jun(Randy) Li
 */

using namespace celaratcp;
using namespace celaratcp::netio;

template <typename AddrType, typename NetworkIOObjectT,
          CheckSumPolicy Policy = CheckSumPolicy::IP_TCP>
class TcpUdpSession
    : public TcpConnectionChan<AddrType, std::shared_ptr<NetMemChunk>, Policy>
{
private:
  using pool_t = recycle::shared_pool<NetMemChunk>;

  asio::awaitable<void>
  tcp_receiver()
  {
    for (;;) {
      auto pkt = co_await this->fetchPackets();
      auto buf = pkt->GetConstBuf();

      co_await udp_socket_.async_send(buf, asio::use_awaitable);
    }
  }

  asio::awaitable<void>
  udp_receiver()
  {
    for (;;) {
      auto pkt = tx_payload_pool_->allocate();
      auto buf = pkt->GetMutableBuf();
      auto bytes
          = co_await udp_socket_.async_receive(buf, asio::use_awaitable);
      pkt->SetUsedBytes(bytes);
      co_await chan_tx_.async_send(asio::error_code{}, pkt,
                                   asio::use_awaitable);
    }
  }

  asio::awaitable<void>
  udp_forward_tcp(std::shared_ptr<pool_t> hdr_pool,
                  asio::experimental::concurrent_channel<void(
                      asio::error_code, std::shared_ptr<NetMemChunk>)> &chan)
  {
    for (;;) {
      auto pkt = co_await chan.async_receive(asio::use_awaitable);
      auto hdr = hdr_pool->allocate();

      std::forward_list<std::shared_ptr<NetPacket> > pkts = { hdr, pkt };

      this->AssemblePacketHeaders(TcpPacketType::ACK, pkts);

      std::list<asio::const_buffer> bufs
          = { hdr->GetConstBuf(), pkt->GetConstBuf() };

      // We just call network stream object to handle, TcpStack should have
      // been updated when it fills the packets.
      co_await asio::async_write(*nout_, std::move(bufs), asio::use_awaitable);
    }
  }

public:
  /**
   * tx_hdr_pool would be used for filling IP + TCP header, so CPU would
   * write it then netio would read it.
   * tx_payload_pool is used for sending payload, UDP socket would write
   * to it then netio would read it.
   */
  explicit TcpUdpSession(const AddrType &local_addr, uint_fast16_t local_port,
                         const AddrType &remote_addr,
                         uint_fast16_t remote_port, asio::any_io_executor &ex,
                         std::shared_ptr<NetworkIOObjectT> net_io,
                         uint_fast16_t udp_port,
                         std::shared_ptr<pool_t> tx_hdr_pool,
                         std::shared_ptr<pool_t> tx_payload_pool)
      : TcpConnectionChan<AddrType, std::shared_ptr<NetMemChunk>, Policy>(
            local_addr, local_port, remote_addr, remote_port, ex),
        ex_(ex), nout_(std::move(net_io)), udp_port_(udp_port),
        local_port_(local_port), chan_tx_(ex_, 32), udp_socket_(ex_),
        tcp_hdr_pool_(tx_hdr_pool), tx_payload_pool_(tx_payload_pool)
  {
#if 0
    netdev::IPacketFilter *filter = *nout_;
    filter->AddPeerNode(this->remote_addr_, this->remote_port_, local_port_);
#endif
  }

  ~TcpUdpSession()
  {
#if 0
    netdev::IPacketFilter *filter = *nout_;
    filter->RemovePeerNode(this->remote_addr_, this->remote_port_,
                           local_port_);
#endif
  }

  virtual void
  Established(uint_fast32_t cur_seq_num, uint_fast32_t cur_ack_num) override
  {
    asio::ip::udp::endpoint dest(asio::ip::make_address_v6("::1"), udp_port_);

    udp_socket_.open(asio::ip::udp::v6());
    udp_socket_.connect(dest);

    asio::co_spawn(ex_, tcp_receiver(), asio::detached);
    asio::co_spawn(ex_, udp_receiver(), asio::detached);
    asio::co_spawn(ex_, udp_forward_tcp(tcp_hdr_pool_, chan_tx_),
                   asio::detached);

    (void)cur_seq_num;
    (void)cur_ack_num;
  }

  virtual asio::awaitable<void>
  AsyncSendReply(TcpPacketType packet_type, uint_fast32_t seq,
                 uint_fast32_t ack, uint_fast32_t ttl) override
  {
    auto reply = tcp_hdr_pool_->allocate();
    this->AssemblePacketHeaders(packet_type, reply, seq, ack, ttl);
    co_await asio::async_write(*nout_, reply->GetConstBuf(),
                               asio::use_awaitable);
  }

private:
  asio::any_io_executor &ex_;
  std::shared_ptr<NetworkIOObjectT> nout_;
  uint_fast16_t udp_port_;
  uint_fast16_t local_port_;

  asio::experimental::concurrent_channel<void(asio::error_code,
                                              std::shared_ptr<NetMemChunk>)>
      chan_tx_;

  asio::ip::udp::socket udp_socket_;

  // IP + TCP header pool
  std::shared_ptr<pool_t> tcp_hdr_pool_;

  std::shared_ptr<pool_t> tx_payload_pool_;
};

template <typename AddrType, typename TcpConnFactory>
class TcpServiceRingBuf : public ebpf::TcpService<AddrType, TcpConnFactory>
{
private:
  static asio::awaitable<void>
  ProcessIncoming(auto service, auto r)
  {
    for (;;) {
      auto packet = co_await r->Allocation();
      auto meta = packet->GetMeta();

      auto state
          = co_await service->ProcessParsedPacket(meta, std::move(packet));
      // TODO: report errors
      (void)state;
    }
  }

public:
  TcpServiceRingBuf(TcpConnFactory &&conn_factory, const AddrType &local_addr,
                    uint_fast16_t local_port, netdev::IPacketFilter *filter,
                    asio::any_io_executor &exec)
      : ebpf::TcpService<AddrType, TcpConnFactory>(
            std::move(conn_factory), local_addr, local_port, filter, exec)
  {
  }

  void
  Accept()
  {
    auto r = this->filter_->AddWatchIpv4PortRingbuf(this->port_, this->exec_);
    auto r_ptr
        = std::any_cast<std::shared_ptr<ebpf::EbpfTcpRingAllocator> >(r);

    asio::co_spawn(this->exec_, ProcessIncoming(this, r_ptr), asio::detached);
  }
};

int
main(int argc, char *argv[])
{
  std::string local_interface_name, virt_interface_name;
  std::string address;
  int tcp_port = 0, udp_port = 0;

  int opt;
  while ((opt = getopt(argc, argv, "I:a:p:")) != -1) {
    switch (opt) {
    case 'I':
    {
      std::string interfaces(optarg);
      size_t colon = interfaces.find(':');
      if (colon == std::string::npos) {
        std::cerr << "Invalid interface format. Use <local>:<virtual net>\n";
        return 1;
      }
      local_interface_name = interfaces.substr(0, colon);
      virt_interface_name = interfaces.substr(colon + 1);
      break;
    }
    case 'a':
      address = optarg;
      break;
    case 'p':
    {
      std::string ports(optarg);
      size_t colon = ports.find(':');
      if (colon == std::string::npos) {
        std::cerr << "Invalid port format. Use <tcp>:<udp>\n";
        return 1;
      }
      tcp_port = std::stoi(ports.substr(0, colon));
      udp_port = std::stoi(ports.substr(colon + 1));
      break;
    }
    default:
      std::cerr << "Usage: " << argv[0]
                << " -I <interface> -a <address> -p <tcp>:<udp>\n";
      return 1;
    }
  }

  if (local_interface_name.empty() || address.empty() || tcp_port == 0
      || udp_port == 0)
  {
    std::cerr
        << "Usage: " << argv[0]
        << " -I <interface>:<virtual netdev> -a <address> -p <tcp>:<udp>\n";
    return 1;
  }

  asio::io_context ioc;
  asio::any_io_executor exec = ioc.get_executor();

  auto local_addr = asio::ip::make_address_v4(address);

  auto l_netdev
      = std::make_shared<netdev::EthernetNetdev>(local_interface_name);
  netdev::IPacketFilter *fwd_filter
      = l_netdev->AttachFilter(netdev::FilterAttachPoint::TC_INGRESS);
  if (!fwd_filter) {
    std::cerr << "Error: Failed to load the packet forward filter.\n";
    return 1;
  }

  std::list<netdev::FilterAction> apply_filters
      = { netdev::FilterAction::TCP_DPORT_FORWARD };
  if (!fwd_filter->EnableFilters(apply_filters)) {
    std::cerr << "Error: Failed to apply the packet forward filter.\n";
    return 1;
  }

  auto v_netdev = std::make_shared<netdev::VirtualNetDev>(
      exec, virt_interface_name, local_addr);
  auto attach_list = v_netdev->GetSupportAttachPoint();
  netdev::IPacketFilter *filter
      = v_netdev->AttachFilter(netdev::FilterAttachPoint::TC_EGRESS);

  if (!filter) {
    std::cerr << "Error: Failed to load the packet filter.\n";
    return 1;
  }
  auto filter_list = filter->GetSupportFilterActions();

  apply_filters = { netdev::FilterAction::DROP_IPV6,
                    netdev::FilterAction::ACCEPT_TCP_ONLY };

  auto all_supported = std::all_of(
      apply_filters.cbegin(), apply_filters.cend(),
      [&filter_list](const auto &filter) {
        return std::find(filter_list.cbegin(), filter_list.cend(), filter)
               != filter_list.cend();
      });

  if (all_supported) {
    if (!filter->EnableFilters(apply_filters)) {
      std::cerr << "Error: Failed to apply the packet filter.\n";
      return 1;
    }
  } else {
    std::cerr
        << "Error: The network device does not support all required filters."
        << std::endl;
    return 1;
  }

  constexpr auto kHdrSize = kIpv4HdrSize + kTcpHdrMinimalSize;
  memmanager::SimpleHeapAllocator<NetMemChunk> hdr_alloc(kHdrSize);
  std::shared_ptr<recycle::shared_pool<NetMemChunk> > hdr_pool
      = std::make_shared<recycle::shared_pool<NetMemChunk> >(
          [&hdr_alloc]() { return hdr_alloc.Allocation(); });
  hdr_pool->reserve(40);

  memmanager::SimpleHeapAllocator<NetMemChunk> payload_alloc(kRegularMtu
                                                             - kHdrSize);
  std::shared_ptr<recycle::shared_pool<NetMemChunk> > payload_pool
      = std::make_shared<recycle::shared_pool<NetMemChunk> >(
          [&payload_alloc]() { return payload_alloc.Allocation(); });
  payload_pool->reserve(40);

  auto conn_factory = [&exec, &v_netdev, &udp_port, &hdr_pool,
                       &payload_pool](const asio::ip::address_v4 &local_addr,
                                      uint_fast16_t local_port,
                                      const asio::ip::address_v4 &remote_addr,
                                      uint_fast16_t remote_port) {
    return std::make_shared<
        TcpUdpSession<asio::ip::address_v4, netdev::VirtualNetDev> >(
        local_addr, local_port, remote_addr, remote_port, exec, v_netdev,
        udp_port, hdr_pool, payload_pool);
  };

  auto serv_factory = [&conn_factory, &fwd_filter,
                       &exec](const asio::ip::address_v4 &local_addr,
                              uint_fast16_t local_port) {
    return std::make_shared<
        TcpServiceRingBuf<asio::ip::address_v4, decltype(conn_factory)> >(
        std::move(conn_factory), local_addr, local_port, fwd_filter, exec);
  };

  auto tcp_stack = MakeAsyncTcpStack<asio::ip::address_v4>(serv_factory);

  auto watch_addr = l_netdev->GetIPv4Address();
  if (watch_addr) {
    auto service = serv_factory(*watch_addr, tcp_port);
    tcp_stack.AddService(service);
    service->Accept();
  }

  v_netdev->Up();

  std::thread t1([&ioc]() { ioc.run(); });
  std::thread t2([&ioc]() { ioc.run(); });

  t2.join();
  t1.join();

  return 0;
}
