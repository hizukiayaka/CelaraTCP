/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * SPDX-FileCopyrightText: Hsia-Jun(Randy) Li
 */

#ifndef _VIRTUAL_NETDEV_HPP_
#define _VIRTUAL_NETDEV_HPP_

#include <concepts>
#include <experimental/propagate_const>
#include <forward_list>
#include <list>
#include <memory>
#include <type_traits>

#include <asio.hpp>
#include <asio/spawn.hpp>

#include "net_packet.hpp"
#include "net_filter_inf.hpp"

namespace celaratcp {
namespace netdev {

// Define concepts for buffer containers
template <typename T> concept MutableBufferContainer = requires(T t)
{
  typename std::remove_reference_t<T>::value_type;
  requires std::is_convertible_v<
      typename std::remove_reference_t<T>::value_type, asio::mutable_buffer>;
};

template <typename T> concept ConstBufferContainer = requires(T t)
{
  typename std::remove_reference_t<T>::value_type;
  requires std::is_convertible_v<
      typename std::remove_reference_t<T>::value_type, asio::const_buffer>;
};

class VirtualNetDev
{
public:
  using callback_t = std::function<void(std::error_code, std::size_t)>;

private:
#ifdef __gnu_linux__
  class TunGnuLinuxImpl;
  std::experimental::propagate_const<std::unique_ptr<TunGnuLinuxImpl> > pImpl_;
#endif

public:
  VirtualNetDev(asio::io_context &io_context, const std::string &intl_name,
                const asio::ip::address_v4 &addr);
  ~VirtualNetDev();

  template <MutableBufferContainer BufferSequence>
  void async_read(BufferSequence &buffers, callback_t &&callback);
  template <ConstBufferContainer BufferSequence>
  void async_write(BufferSequence &buffers, callback_t &&callback);

  void async_read(NetPacket &buf, callback_t &&callback);
  void async_write(NetPacket &buf, callback_t &&callback);

  template<NetPacketContainer PacketSequence>
  void async_read(PacketSequence &packets,
                  callback_t &&callback);
  template<NetPacketContainer PacketSequence>
  void async_write(PacketSequence &packets,
                   callback_t &&callback);

  bool up();
  bool down();

  operator IPacketFilter *();
};

} // namespace netdev

} // namespace celaratcp

#endif // _VIRTUAL_NETDEV_HPP_