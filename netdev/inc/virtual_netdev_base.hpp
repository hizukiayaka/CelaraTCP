/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * SPDX-FileCopyrightText: Hsia-Jun(Randy) Li
 */

#ifndef VIRTUAL_NETDEV_BASE_HPP_
#define VIRTUAL_NETDEV_BASE_HPP_

#include <concepts>
#include <list>
#include <memory>
#include <type_traits>

#include <asio/any_io_executor.hpp>
#include <asio/ip/address.hpp>
#include <asio/ip/network_v4.hpp>
#include <asio/ip/network_v6.hpp>

#include "net_filter_inf.hpp"

namespace celaratcp {
namespace netdev {

template <typename PlatformImpl>
class VirtualNetDevBase
{
private:
  PlatformImpl &
  derived()
  {
    return static_cast<PlatformImpl &>(*this);
  }
  const PlatformImpl &
  derived() const
  {
    return static_cast<const PlatformImpl &>(*this);
  }

public:
  virtual ~VirtualNetDevBase() = default;

  using executor_type = asio::any_io_executor;

  executor_type
  get_executor() const
  {
    return derived().get_executor_impl();
  }

  template <typename Bufs, typename Token>
  auto
  async_read_some(const Bufs &b, Token &&t)
  {
    return derived().read_some_impl(b, std::forward<Token>(t));
  }

  template <typename Bufs, typename Token>
  auto
  async_write_some(const Bufs &b, Token &&t)
  {
    return derived().write_some_impl(b, std::forward<Token>(t));
  }

  // Set interface MTU (Maximum Transmission Unit)
  virtual std::error_code SetMtu(uint_fast16_t mtu) = 0;

  // Set the local address with a prefix
  virtual bool SetLocalAddress(
      const std::variant<asio::ip::network_v4, asio::ip::network_v6> &network)
      = 0;

  virtual int GetMtu() const = 0;

  virtual bool Up() = 0;
  virtual bool Down() = 0;

  virtual asio::ip::address_v4 GetPeerIPv4Address() const = 0;
  virtual asio::ip::address_v6 GetPeerIPv6Address() const = 0;
};

} // namespace netdev
} // namespace celaratcp

#endif // VIRTUAL_NETDEV_BASE_HPP_
