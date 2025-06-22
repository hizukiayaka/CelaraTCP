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

#include "net_filter_inf.hpp"

namespace celaratcp {
namespace netdev {

template <typename PlatformImpl> class VirtualNetDevBase
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

  virtual bool Up() = 0;
  virtual bool Down() = 0;

  virtual operator IPacketFilter *() = 0;
};

} // namespace netdev
} // namespace celaratcp

#endif // VIRTUAL_NETDEV_BASE_HPP_
