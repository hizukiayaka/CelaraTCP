/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * SPDX-FileCopyrightText: Hsia-Jun(Randy) Li
 */

#include <asio.hpp>
#include <asio/awaitable.hpp>
#include <asio/co_spawn.hpp>
#include <asio/experimental/as_tuple.hpp>
#include <asio/experimental/awaitable_operators.hpp>
#include <asio/experimental/channel.hpp>
#include <asio/use_awaitable.hpp>
#include <condition_variable>
#include <cstdlib>
#include <deque>
#include <getopt.h>
#include <iostream>
#include <mutex>
#include <string>

#include "net_packet_allocator.hpp"
#include "userspace_tcp_stack_helper.hpp"
#include "virtual_netdev.hpp"

using namespace celaratcp;
using namespace celaratcp::netio;

template <typename addrType>
class Session : public TcpConnectionChan<addrType, std::shared_ptr<NetPacket> >
{
private:
  asio::awaitable<void>
  tcp_receiver()
  {
    for (;;) {
      auto pkt = co_await this->fetchPackets();
      auto buf = pkt->GetConstBuf();

      co_await asio::async_write(udp_socket_, buf, asio::use_awaitable);
    }
  }

  asio::awaitable<void>
  udp_receiver()
  {
    for (;;) {
      auto pkt = this->tx_payload_pool_->allocate();
      auto buf = pkt->GetMutableBuf();
      auto [ec, bytes] = co_await asio::async_read(this->udp_socket_, buf,
                                                   asio::use_awaitable);
      if (!ec) {
        pkt->SetUsedBytes(bytes);
      }
      co_await this->chan_tx_.async_send(ec, pkt, asio::use_awaitable);
    }
  }

  asio::awaitable<void>
  udp_forward_tcp(recycle::shared_pool<NetMemChunk> &hdr_pool,
                  asio::experimental::channel<void(
                      asio::error_code, std::shared_ptr<NetPacket>)> &chan)
  {
    for (;;) {
      auto pkt = co_await chan.async_receive(asio::use_awaitable);
      auto hdr = hdr_pool.allocate();

      FillPacketIpTcpHdr(TcpPacketType::ACK, hdr, pkt);
      std::list<asio::const_buffer> bufs
          = { hdr->GetConstBuf(), pkt->GetConstBuf() };
      // TODO: ask the TcpStack send it.
    }
  }

public:
#if 0
  explicit Session(asio::io_context &ioc, const addrType &local_addr,
          uint_fast16_t local_port, const addrType &remote_addr,
          uint_fast16_t remote_port, uint16_t udp_port)
      : TcpConnectionChan<addrType, std::shared_ptr<NetPacket> >(
            ioc, local_addr, local_port, remote_addr, remote_port),
        ioc_(ioc), chan_tx_(ioc, 32), udp_socket_(ioc)
  {
    tx_payload_pool_->reserve(20);
  }
#endif
  explicit Session(const addrType &local_addr, uint_fast16_t local_port,
                   const addrType &remote_addr, uint_fast16_t remote_port,
                   asio::any_io_executor &ex)
      : TcpConnectionChan<addrType, std::shared_ptr<NetPacket> >(
            local_addr, local_port, remote_addr, remote_port, ex),
        ex_(ex), chan_tx_(ex_, 32), udp_socket_(ex_)
  {
    tx_payload_pool_->reserve(20);
  }

  virtual void
  Established() override
  {
#if 0
    asio::ip::udp::endpoint dest(asio::ip::address_v6::from_string("::1"),
                                 udp_port);

    udp_socket_.open(asio::ip::udp::v6());
    udp_socket_.connect(dest);
#endif

    asio::co_spawn(ex_, tcp_receiver(), asio::detached);
    asio::co_spawn(ex_, udp_receiver(), asio::detached);
    asio::co_spawn(ex_, udp_forward_tcp(tx_hdr_pool_, chan_tx_));
  }

private:
  asio::any_io_executor &ex_;

  using pool_t = recycle::shared_pool<NetMemChunk>;
  std::shared_ptr<pool_t> tx_hdr_pool_;
  std::shared_ptr<pool_t> tx_payload_pool_;

  asio::experimental::channel<void(asio::error_code,
                                   std::shared_ptr<NetPacket>)>
      chan_tx_;

  asio::ip::udp::socket udp_socket_;
};

#if 0
template<typename TcpStackT>
class TcpChanUdpService
{
private:
private:
  std::reference_wrapper<asio::io_context> ioc_;
  std::reference_wrapper<netdev::VirtualNetDev> netdev_;

  uint16_t service_port_;
  uint16_t udp_port_;

#if 0
  using HdrPacketType =
      typename std::conditional<std::is_same_v<addrType, asio::ip::address_v4>,
               Ipv4TcpHdrPacket, Ipv6TcpHdrPacket>::type;
#endif

  memmanger::SimpleHeapAllocator<NetMemChunk> hdr_alloc_;
  std::shared_ptr<recycle::shared_pool<NetMemChunk>> hdr_pool_;
  recycle::shared_pool<NetPacketSW<kRegularMtu> > rx_hdr_pool_;
  recycle::shared_pool<NetPacketSW<kRegularMtu> > rx_payload_pool_;

  asio::any_io_executor exec_;
  TcpStackT tcp_stack_;

public:
  TcpChanUdpService(asio::io_context &ioc, netdev::VirtualNetDev &netdev,
                    uint16_t source_port, uint16_t udp_port)
      : ioc_(ioc), netdev_(netdev), service_port_(source_port),
        udp_port_(udp_port), hdr_alloc_(kIpv4HdrSize),
        hdr_pool_([this]() {
          auto pool = std::make_shared<recycle::shared_pool<NetMemChunk>>(
              [this]() { return this->hdr_alloc_.Allocation(); });
          pool->reserve(20);
          return pool;
        }()),
        rx_hdr_pool_(), rx_payload_pool_(), exec_(ioc.get_executor()),
        tcp_stack_(exec_, netdev, hdr_pool_)
  {
    //tcp_stack_.addSimpleService(source_port);

    rx_hdr_pool_.reserve(80);
    rx_payload_pool_.reserve(50);
  }
};
#endif

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
  netdev::VirtualNetDev netdev(exec, interface_name,
                               asio::ip::address_v4::from_string(address));

  memmanger::SimpleHeapAllocator<NetMemChunk> hdr_alloc(kIpv4HdrSize);
  std::shared_ptr<recycle::shared_pool<NetMemChunk> > hdr_pool
      = std::make_shared<recycle::shared_pool<NetMemChunk> >(
          [&hdr_alloc]() { return hdr_alloc.Allocation(); });
  hdr_pool->reserve(20);

  auto tcp_stack
      = MakeAsyncTcpStack<asio::ip::address_v4, Session<asio::ip::address_v4>,
                          TcpService<asio::ip::address_v4> >(exec, netdev,
                                                             hdr_pool);

  // TcpChanUdpService service(ioc, netdev, tcp_port, udp_port);
  // service.start();

  ioc.run();

  return 0;
}
