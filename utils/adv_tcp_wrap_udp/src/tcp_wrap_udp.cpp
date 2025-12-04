/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * SPDX-FileCopyrightText: Hsia-Jun(Randy) Li
 */

using namespace celaratcp;
namespace app {
namespace logging {
#ifdef LOGGER_USE_SPDLOG
static constexpr std::string logger_name = "tcp_wrap_udp";

inline std::shared_ptr<spdlog::logger> &
get_logger_internal()
{
  static std::shared_ptr<spdlog::logger> logger = spdlog::get(logger_name);

  if (!logger) {
    throw std::logic_error("You didn't initilize the logging system");
  }

  return logger;
}

template <typename... Args>
inline void
trace(spdlog::format_string_t<Args...> fmt, Args &&...args)
{
  get_logger_internal()->trace(fmt, std::forward<Args>(args)...);
}

template <typename... Args>
inline void
info(spdlog::format_string_t<Args...> fmt, Args &&...args)
{
  get_logger_internal()->info(fmt, std::forward<Args>(args)...);
}

template <typename... Args>
inline void
warn(spdlog::format_string_t<Args...> fmt, Args &&...args)
{
  get_logger_internal()->warn(fmt, std::forward<Args>(args)...);
}

template <typename... Args>
inline void
error(spdlog::format_string_t<Args...> fmt, Args &&...args)
{
  get_logger_internal()->error(fmt, std::forward<Args>(args)...);
}

#else
template <typename... Args>
inline void
trace(Args &&...)
{
}
template <typename... Args>
inline void
info(Args &&...)
{
}
template <typename... Args>
inline void
warn(Args &&...)
{
}
template <typename... Args>
inline void
error(Args &&...)
{
}
#endif
} // namespace logging

template <typename AddrType, typename NetworkDevObjectT,
          netio::CheckSumPolicy Policy = netio::CheckSumPolicy::IP_TCP>
class TcpUdpSession
    : public netio::TcpConnectionChan<AddrType, std::shared_ptr<NetMemChunk>,
                                      Policy>
{
private:
  asio::awaitable<void>
  tcp_receiver()
  {
    for (;;) {
      auto pkt = co_await this->fetchPackets();
      auto buf = pkt->GetConstBuf();

      asio::error_code ec;

      co_await udp_socket_.async_send(
          buf, asio::bind_executor(
                   strand_, asio::redirect_error(asio::use_awaitable, ec)));
      if (ec) {
        app::logging::error("can't forward to udp port: {}", ec.value());
        co_return;
      }
    }
  }

  asio::awaitable<void>
  udp_receiver()
  {
    constexpr auto kHdrSize = kIpv4HdrSize + kTcpHdrMinimalSize;
    for (;;) {
      auto pkt = co_await nout_socket_->Allocate();
      if (!pkt) {
        app::logging::error("can't allocate packet for udp receive");
        continue;
      }

      auto b = pkt->GetData();
      auto buf = b.subspan(kHdrSize);

      asio::error_code ec;

      auto bytes = co_await udp_socket_.async_receive(
          asio::buffer(std::data(buf), std::size(buf)),
          asio::bind_executor(strand_,
                              asio::redirect_error(asio::use_awaitable, ec)));

      if (ec) {
        app::logging::error("can't receive from udp port: {}", ec.value());
        co_return;
      }

      pkt->SetUsedBytes(bytes);
      co_await chan_tx_.async_send(
          asio::error_code{}, pkt,
          asio::redirect_error(asio::use_awaitable, ec));
      if (ec) {
        app::logging::error("can't push to pending forward chan: {}",
                            ec.value());
        co_return;
      }
    }
  }

  asio::awaitable<void>
  udp_forward_tcp()
  {
    for (;;) {
      asio::error_code ec;
      auto pkt = co_await chan_tx_.async_receive(
          asio::redirect_error(asio::use_awaitable, ec));
      if (ec) {
        app::logging::error("receive from the pending forward chan failed: {}",
                            ec.value());
        co_return;
      }

      this->AssemblePacketHeaders(netio::TcpPacketType::ACK, pkt);

      // We just call network stream object to handle, TcpStack should have
      // been updated when it fills the packets.

      co_return;
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
                         std::shared_ptr<NetworkDevObjectT> net_dev,
                         uint_fast16_t udp_port)
      : netio::TcpConnectionChan<AddrType, std::shared_ptr<NetMemChunk>,
                                 Policy>(local_addr, local_port, remote_addr,
                                         remote_port, ex),
        ex_(ex), strand_(ex_), net_dev_(std::move(net_dev)),
        nout_socket_{ std::make_unique<netio::PacketSocketLinux>(
            ex, net_dev_, false, true) },
        udp_port_(udp_port), local_port_(local_port), chan_tx_(ex_, 32),
        udp_socket_(ex_)
  {
    if (!nout_socket_) {
      app::logging::error("can't setup packet(7) socket");
      throw std::logic_error("can't setup packet(7) socket");
    }

    if (!nout_socket_->SetupTxPool()) {
      app::logging::error("can't setup packet(7) TX MMAP");
      throw std::logic_error("can't setup packet(7) TX MMAP");
    }
  }

  ~TcpUdpSession() {}

  virtual void
  Established(uint_fast32_t cur_seq_num, uint_fast32_t cur_ack_num) override
  {
    asio::ip::udp::endpoint dest(asio::ip::make_address_v6("::1"), udp_port_);

    udp_socket_.open(asio::ip::udp::v6());
    udp_socket_.connect(dest);

    asio::co_spawn(ex_, tcp_receiver(), asio::detached);
    asio::co_spawn(ex_, udp_receiver(), asio::detached);
    asio::co_spawn(ex_, udp_forward_tcp(), asio::detached);

    (void)cur_seq_num;
    (void)cur_ack_num;
  }

  virtual asio::awaitable<void>
  AsyncSendReply(netio::TcpPacketType packet_type, uint_fast32_t seq,
                 uint_fast32_t ack, uint_fast32_t ttl) override
  {
    auto reply = co_await nout_socket_->Allocate();
    if (!reply) {
      app::logging::error("can't allocate packet for reply");
      co_return;
    }

    this->AssemblePacketHeaders(packet_type, reply, seq, ack, ttl);
    co_return;
  }

private:
  asio::any_io_executor &ex_;
  asio::strand<asio::any_io_executor> strand_;
  std::shared_ptr<NetworkDevObjectT> net_dev_;
  std::unique_ptr<netio::PacketSocketLinux> nout_socket_;

  uint_fast16_t udp_port_;
  uint_fast16_t local_port_;

  asio::experimental::concurrent_channel<void(asio::error_code,
                                              std::shared_ptr<NetMemChunk>)>
      chan_tx_;

  asio::ip::udp::socket udp_socket_;
};

template <typename AddrType, typename TcpConnFactory>
class TcpServiceRingBuf : public ebpf::TcpService<AddrType, TcpConnFactory>
{
private:
  asio::any_io_executor exec_;

  static asio::awaitable<void>
  ProcessIncoming(auto service, auto r)
  {
    for (;;) {
      auto packet = co_await r->Allocation();
      auto meta = packet->GetMeta();

      auto state
          = co_await service->ProcessParsedPacket(meta, std::move(packet));
      if (state != netio::TcpStackState::SUCCESS
          && state != netio::TcpStackState::DROP)
      {
        app::logging::info("parse incoming packet failed");
      }
    }
  }

public:
  TcpServiceRingBuf(TcpConnFactory &&conn_factory, const AddrType &local_addr,
                    uint_fast16_t local_port, netdev::IPacketFilter *filter,
                    asio::any_io_executor &exec)
      : ebpf::TcpService<AddrType, TcpConnFactory>(
            std::move(conn_factory), local_addr, local_port, filter),
        exec_(std::move(exec))
  {
  }

  void
  Accept()
  {
    auto r = this->filter_->AddWatchIpv4PortRingbuf(this->port_, this->exec_);
    auto r_ptr
        = std::any_cast<std::shared_ptr<ebpf::EbpfTcpRingAllocator> >(r);

    app::logging::trace("will watch TCPv4 port {}", this->port_);
    asio::co_spawn(this->exec_, ProcessIncoming(this, r_ptr), asio::detached);
  }
};
} // namespace app

int
main(int argc, char *argv[])
{
#ifdef LOGGER_USE_SPDLOG
  spdlog::init_thread_pool(8192, 1);

  auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
  console_sink->set_level(spdlog::level::trace);

  std::vector<spdlog::sink_ptr> log_sinks{ console_sink };
  auto netio_logger
      = netio::PacketSocketLinux::InitializePsocketLogging(log_sinks);
  netio_logger->set_level(spdlog::level::trace);

  auto app_logger = std::make_shared<spdlog::logger>(app::logging::logger_name,
                                                     console_sink);
  app_logger->set_level(spdlog::level::trace);
  spdlog::register_logger(app_logger);
#endif

  std::string local_interface_name;
  int tcp_port = 0, udp_port = 0;

  int opt;
  while ((opt = getopt(argc, argv, "I:a:p:")) != -1) {
    switch (opt) {
    case 'I':
      local_interface_name = optarg;
      break;
    case 'p':
    {
      std::string ports(optarg);
      size_t colon = ports.find(':');
      if (colon == std::string::npos) {
        app::logging::error("Invalid port format. Use <tcp>:<udp>");
        return 1;
      }
      tcp_port = std::stoi(ports.substr(0, colon));
      udp_port = std::stoi(ports.substr(colon + 1));
      break;
    }
    default:
      app::logging::error("Usage {} -I <interface> -p <tcp>:<udp>", argv[0]);
      return 1;
    }
  }

  if (local_interface_name.empty() || tcp_port == 0 || udp_port == 0) {
    app::logging::error("Usage {} -I <interface> -p <tcp>:<udp>", argv[0]);
    return 1;
  }

  asio::io_context ioc;
  asio::any_io_executor exec = ioc.get_executor();

  auto l_netdev
      = std::make_shared<netdev::EthernetNetdev>(local_interface_name);

  netdev::IPacketFilter *filter
      = l_netdev->AttachFilter(netdev::FilterAttachPoint::TC_INGRESS);
  if (!filter) {
    app::logging::error("Error: Failed to load the packet forward filter.");
    return 1;
  }

  auto filter_list = filter->GetSupportFilterActions();

  std::list<netdev::FilterAction> apply_filters
      = { netdev::FilterAction::TCP_DPORT_CAPTURE };

  auto all_supported = std::all_of(
      apply_filters.cbegin(), apply_filters.cend(),
      [&filter_list](const auto &filter) {
        return std::find(filter_list.cbegin(), filter_list.cend(), filter)
               != filter_list.cend();
      });

  if (all_supported) {
    if (!filter->EnableFilters(apply_filters)) {
      app::logging::error("Error: Failed to apply the packet filter.");
      return 1;
    }
  } else {
    app::logging::error(
        "Error: The network device does not support all required filters.");
    return 1;
  }

  auto conn_factory = [&exec, &l_netdev,
                       &udp_port](const asio::ip::address_v4 &local_addr,
                                  uint_fast16_t local_port,
                                  const asio::ip::address_v4 &remote_addr,
                                  uint_fast16_t remote_port) {
    return std::make_shared<
        app::TcpUdpSession<asio::ip::address_v4, netdev::EthernetNetdev> >(
        local_addr, local_port, remote_addr, remote_port, exec, l_netdev,
        udp_port);
  };

  auto serv_factory = [&conn_factory, &filter,
                       &exec](const asio::ip::address_v4 &local_addr,
                              uint_fast16_t local_port) {
    return std::make_shared<
        app::TcpServiceRingBuf<asio::ip::address_v4, decltype(conn_factory)> >(
        std::move(conn_factory), local_addr, local_port, filter, exec);
  };

  auto tcp_stack
      = netio::MakeAsyncTcpStack<asio::ip::address_v4>(serv_factory);

  auto local_addr = l_netdev->GetIPv4Address();
  if (local_addr) {
    auto service = serv_factory(*local_addr, tcp_port);
    tcp_stack.AddService(service);
    service->Accept();
  }

  asio::signal_set signals(ioc, SIGINT, SIGTERM);
  signals.async_wait([&](std::error_code /*ec*/, int /*signal*/) {
    ioc.stop(); // Stop the io_context
  });

  std::thread t1([&ioc]() { ioc.run(); });
  std::thread t2([&ioc]() { ioc.run(); });

  t2.join();
  t1.join();

  spdlog::shutdown();

  return 0;
}
