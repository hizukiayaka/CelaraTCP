/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * SPDX-FileCopyrightText: Hsia-Jun(Randy) Li
 */

using namespace celaratcp;

asio::awaitable<void>
run()
{
  auto executor = co_await asio::this_coro::executor;

  asio::ip::network_v4 net1(asio::ip::make_address_v4("169.254.3.1"), 32);
  netdev::VirtualNetDev netif(executor, "test0", net1.address());
  netdev::IPacketFilter *filter
      = netif.AttachFilter(netdev::FilterAttachPoint::TC_EGRESS);

  auto filter_list = filter->GetSupportFilterActions();

  std::vector<uint8_t> hdr(kIpv4HdrSize + kTcpHdrMinimalSize),
      payload(kRegularMtu - kIpv4HdrSize - kTcpHdrMinimalSize);

  std::vector<asio::mutable_buffer> mbufs
      = { asio::buffer(hdr), asio::buffer(payload) };

  auto length = co_await asio::async_read(netif, mbufs, asio::use_awaitable);
  if (length > 0) {
  }
}

int
main(int argc, char *argv[])
{
  asio::io_context ioc;
  asio::co_spawn(ioc, run(), asio::detached);

  ioc.run();

  return 0;
}
