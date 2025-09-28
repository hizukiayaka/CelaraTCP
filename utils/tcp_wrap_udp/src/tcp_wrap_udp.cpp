/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * SPDX-FileCopyrightText: Hsia-Jun(Randy) Li
 */

#include <asio.hpp>
#include <asio/awaitable.hpp>
#include <asio/co_spawn.hpp>
#include <asio/experimental/channel.hpp>
#include <condition_variable>
#include <cstdlib>
#include <getopt.h>
#include <iostream>
#include <string>

#include "net_packet_allocator.hpp"
#include "userspace_tcp_stack_helper.hpp"
#include "virtual_netdev.hpp"

using namespace celaratcp;
using namespace celaratcp::netio;

template <typename AddrType, typename NetworkIOObjectT>
class TcpUdpSession
    : public TcpConnectionChan<AddrType, std::shared_ptr<NetMemChunk> >
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
                  asio::experimental::channel<void(
                      asio::error_code, std::shared_ptr<NetMemChunk>)> &chan)
  {
    for (;;) {
      auto pkt = co_await chan.async_receive(asio::use_awaitable);
      auto hdr = hdr_pool->allocate();

      TcpConnection<AddrType>::FillPacketIpTcpHdr(TcpPacketType::ACK, *hdr,
                                                  pkt);
      std::list<asio::const_buffer> bufs
          = { hdr->GetConstBuf(), pkt->GetConstBuf() };

      // We just call network stream object to handle, TcpStack should have
      // been updated when it fills the packets.
      co_await asio::async_write(*nout_, std::move(bufs), asio::use_awaitable);
    }
  }

public:
  explicit TcpUdpSession(const AddrType &local_addr, uint_fast16_t local_port,
                         const AddrType &remote_addr,
                         uint_fast16_t remote_port, asio::any_io_executor &ex,
                         std::shared_ptr<NetworkIOObjectT> net_io,
                         uint_fast16_t udp_port)
      : TcpConnectionChan<AddrType, std::shared_ptr<NetMemChunk> >(
            local_addr, local_port, remote_addr, remote_port, ex),
        ex_(ex), nout_(std::move(net_io)), udp_port_(udp_port),
        local_port_(local_port), chan_tx_(ex_, 32), udp_socket_(ex_)
  {
    netdev::IPacketFilter *filter = *nout_;
    filter->AddPeerNode(this->remote_addr_, this->remote_port_, local_port_);

    tx_payload_pool_->reserve(20);
  }

  TcpUdpSession(TcpUdpSession &&) = default;
  TcpUdpSession &operator=(TcpUdpSession &&) = default;

  ~TcpUdpSession()
  {
    netdev::IPacketFilter *filter = *nout_;
    filter->RemovePeerNode(this->remote_addr_, this->remote_port_,
                           local_port_);
  }

  virtual void
  Established() override
  {
    asio::ip::udp::endpoint dest(asio::ip::address_v6::from_string("::1"),
                                 udp_port_);

    udp_socket_.open(asio::ip::udp::v6());
    udp_socket_.connect(dest);

    asio::co_spawn(ex_, tcp_receiver(), asio::detached);
    asio::co_spawn(ex_, udp_receiver(), asio::detached);
    asio::co_spawn(ex_, udp_forward_tcp(tx_hdr_pool_, chan_tx_),
                   asio::detached);
  }

private:
  asio::any_io_executor &ex_;
  std::shared_ptr<NetworkIOObjectT> nout_;
  uint_fast16_t udp_port_;
  uint_fast16_t local_port_;

  std::shared_ptr<pool_t> tx_hdr_pool_;
  std::shared_ptr<pool_t> tx_payload_pool_;

  asio::experimental::channel<void(asio::error_code,
                                   std::shared_ptr<NetMemChunk>)>
      chan_tx_;

  asio::ip::udp::socket udp_socket_;
};

asio::awaitable<void>
NetIncoming(auto netio, auto &tcp_stack)
{
  constexpr auto kHdrSize = kIpv4HdrSize + kTcpHdrMinimalSize;
  memmanger::SimpleHeapAllocator<NetMemChunk> hdr_alloc(kHdrSize);
  std::shared_ptr<recycle::shared_pool<NetMemChunk> > hdr_pool
      = std::make_shared<recycle::shared_pool<NetMemChunk> >(
          [&hdr_alloc]() { return hdr_alloc.Allocation(); });
  hdr_pool->reserve(20);

  memmanger::SimpleHeapAllocator<NetMemChunk> payload_alloc(kRegularMtu
                                                            - kHdrSize);
  std::shared_ptr<recycle::shared_pool<NetMemChunk> > payload_pool
      = std::make_shared<recycle::shared_pool<NetMemChunk> >(
          [&payload_alloc]() { return payload_alloc.Allocation(); });
  payload_pool->reserve(20);

  for (;;) {
    auto hdr = hdr_pool->allocate();
    auto pkt = payload_pool->allocate();

    std::forward_list<asio::mutable_buffer> bufs
        = { hdr->GetMutableBuf(), pkt->GetMutableBuf() };
    std::forward_list<std::shared_ptr<NetMemChunk> > chunks = { hdr, pkt };

    for (;;) {
      auto bytes
          = co_await asio::async_read(*netio, bufs, asio::use_awaitable);
      auto pkt_size = bytes - kHdrSize;

      if (pkt_size >= 0) {
        hdr->SetUsedBytes(kHdrSize);
        pkt->SetUsedBytes(pkt_size);
        auto state = co_await tcp_stack.ProcessIncomingPackets(chunks);

        break;
      }
      /* read again */
    }
  }
}

int
main(int argc, char *argv[])
{
  std::string interface_name;
  std::string address;
  int tcp_port = 0, udp_port = 0;

  int opt;
  while ((opt = getopt(argc, argv, "I:a:p:")) != -1) {
    switch (opt) {
    case 'I':
      interface_name = optarg;
      break;
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

  if (interface_name.empty() || address.empty() || tcp_port == 0
      || udp_port == 0)
  {
    std::cerr << "Usage: " << argv[0]
              << " -I <interface> -a <address> -p <tcp>:<udp>\n";
    return 1;
  }

  asio::io_context ioc;
  asio::any_io_executor exec = ioc.get_executor();

  auto local_addr = asio::ip::address_v4::from_string(address);

  auto netdev = std::make_shared<netdev::VirtualNetDev>(exec, interface_name,
                                                        local_addr);
  netdev::IPacketFilter *filter = *netdev;

  auto filter_list = filter->GetSupportFilterType();

  std::list<netdev::NetDevFiltertype> apply_filters
      = { netdev::NetDevFiltertype::DROP_IPV6,
          netdev::NetDevFiltertype::ACCEPT_4_TUPLE };

  auto all_supported = std::all_of(
      apply_filters.cbegin(), apply_filters.cend(),
      [&filter_list](const auto &filter) {
        return std::find(filter_list.cbegin(), filter_list.cend(), filter)
               != filter_list.cend();
      });

  if (all_supported) {
    filter->LoadFilter();
    filter->SetNetDevFilterType(apply_filters);
  } else {
    std::cerr
        << "Error: The network device does not support all required filters."
        << std::endl;
    return 1;
  }

  memmanger::SimpleHeapAllocator<NetMemChunk> hdr_alloc(kIpv4HdrSize
                                                        + kTcpHdrMinimalSize);
  std::shared_ptr<recycle::shared_pool<NetMemChunk> > hdr_pool
      = std::make_shared<recycle::shared_pool<NetMemChunk> >(
          [&hdr_alloc]() { return hdr_alloc.Allocation(); });
  hdr_pool->reserve(20);

  auto conn_factory
      = [&exec, &netdev, &udp_port](const asio::ip::address_v4 &local_addr,
                                    uint_fast16_t local_port,
                                    const asio::ip::address_v4 &remote_addr,
                                    uint_fast16_t remote_port) {
          return TcpUdpSession<asio::ip::address_v4, netdev::VirtualNetDev>(
              local_addr, local_port, remote_addr, remote_port, exec, netdev,
              udp_port);
        };

  auto serv_factory = [&conn_factory](const asio::ip::address_v4 &local_addr,
                                      uint_fast16_t local_port) {
    return std::make_shared<
        netio::TcpService<asio::ip::address_v4, decltype(conn_factory)> >(
        std::move(conn_factory), local_addr, local_port);
  };

  auto tcp_stack = MakeAsyncTcpStack<asio::ip::address_v4>(netdev, hdr_pool,
                                                           serv_factory);

  auto service = serv_factory(local_addr, tcp_port);
  tcp_stack.AddService(service);

  asio::co_spawn(exec, NetIncoming(netdev, tcp_stack), asio::detached);

  filter->AddWatchIpv4Port(tcp_port);

  ioc.run();

  filter->RemoveWatchIpv4Port(tcp_port);

  return 0;
}
