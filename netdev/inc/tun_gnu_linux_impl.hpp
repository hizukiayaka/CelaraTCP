/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * SPDX-FileCopyrightText: Hsia-Jun(Randy) Li
 */

#ifndef TUN_GNU_LINUX_IMPL_HPP_
#define TUN_GNU_LINUX_IMPL_HPP_

#include <experimental/propagate_const>
#include <string_view>
#include <variant>

#include <asio/bind_executor.hpp>
#include <asio/posix/stream_descriptor.hpp>
#include <asio/strand.hpp>

#include "net_filter_inf.hpp"
#include "virtual_netdev_base.hpp"

namespace celaratcp {
namespace netdev {

class TunGnuLinuxImpl : public VirtualNetDevBase<TunGnuLinuxImpl>,
                        public IFilterProvider
{
private:
  class TunGnuLinuxDetailImpl;
  std::experimental::propagate_const<std::unique_ptr<TunGnuLinuxDetailImpl> >
      pImpl_;

  asio::posix::stream_descriptor stream_;
  asio::strand<asio::any_io_executor> strand_write_;

  bool is_master_node_;
  bool is_client_;

private:
  TunGnuLinuxImpl(asio::any_io_executor &ex, const std::string_view intl_name);

public:
  using executor_type = asio::posix::stream_descriptor::executor_type;

  ~TunGnuLinuxImpl() override;

  TunGnuLinuxImpl(asio::any_io_executor &ex, const std::string_view intl_name,
                  const asio::ip::address_v4 &addr);

  TunGnuLinuxImpl(asio::any_io_executor &ex, const std::string_view intl_name,
                  const asio::ip::address_v6 &addr);

  template <typename Bufs, typename Token>
  auto
  read_some_impl(Bufs &b, Token &&t)
  {
    return stream_.async_read_some(b, std::forward<Token>(t));
  }

  template <typename Bufs, typename Token>
  auto
  write_some_impl(const Bufs &b, Token &&t)
  {
    return stream_.async_write_some(
        b, asio::bind_executor(strand_write_, std::forward<Token>(t)));
  }

  // Set interface MTU (Maximum Transmission Unit)
  std::error_code SetMtu(uint_fast16_t mtu) override;

  bool SetLocalAddress(
      const std::variant<asio::ip::network_v4, asio::ip::network_v6> &network)
      override;

  bool Up() override;
  bool Down() override;

  int GetMtu() const override;

  asio::ip::address_v4 GetPeerIPv4Address() const override;
  asio::ip::address_v6 GetPeerIPv6Address() const override;

  std::list<FilterAttachPoint> GetSupportAttachPoint() const override;
  IPacketFilter *AttachFilter(FilterAttachPoint point) override;
};

} // namespace netdev
} // namespace celaratcp

#endif
