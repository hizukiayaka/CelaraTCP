/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * SPDX-FileCopyrightText: Hsia-Jun(Randy) Li
 */

namespace celaratcp {
namespace netdev {

VirtualNetDev::~VirtualNetDev() = default;

#ifdef __gnu_linux__
VirtualNetDev::VirtualNetDev(asio::io_context &io_context,
                             const std::string &intl_name,
                             const asio::ip::address_v4 &addr)
    : pImpl_(std::make_unique<TunGnuLinuxImpl>(io_context, intl_name, addr))
{
}
#endif

// Template definition for async_read
template <MutableBufferContainer BufferSequence>
void
VirtualNetDev::async_read(BufferSequence &buffers, callback_t &&callback)
{
  pImpl_->async_read(buffers, std::move(callback));
}

template void
VirtualNetDev::async_read<std::forward_list<asio::mutable_buffer> >(
    std::forward_list<asio::mutable_buffer> &bufs, callback_t &&callback);
template void VirtualNetDev::async_read<std::list<asio::mutable_buffer> >(
    std::list<asio::mutable_buffer> &bufs, callback_t &&callback);
template void VirtualNetDev::async_read<std::vector<asio::mutable_buffer> >(
    std::vector<asio::mutable_buffer> &bufs, callback_t &&callback);

template <ConstBufferContainer BufferSequence>
void
VirtualNetDev::async_write(BufferSequence &bufs, callback_t &&callback)
{
  pImpl_->async_write(bufs, std::move(callback));
}

template void
VirtualNetDev::async_write<std::forward_list<asio::const_buffer> >(
    std::forward_list<asio::const_buffer> &bufs, callback_t &&callback);
template void VirtualNetDev::async_write<std::list<asio::const_buffer> >(
    std::list<asio::const_buffer> &bufs, callback_t &&callback);
template void VirtualNetDev::async_write<std::vector<asio::const_buffer> >(
    std::vector<asio::const_buffer> &bufs, callback_t &&callback);

template <NetPacketContainer PacketSequence>
void
VirtualNetDev::async_read(PacketSequence &packets, callback_t &&callback)
{
  pImpl_->async_read(packets, std::move(callback));
}

template <NetPacketContainer PacketSequence>
void
VirtualNetDev::async_write(PacketSequence &packets, callback_t &&callback)
{
  pImpl_->async_write(packets, std::move(callback));
}

#define INSTANTIATE_ASYNC_METHODS(Container, PointerType)                     \
  template void                                                               \
      VirtualNetDev::async_read<Container<PointerType<NetPacket> > >(         \
          Container<PointerType<NetPacket> > & packets,                       \
          callback_t && callback);                                            \
  template void                                                               \
      VirtualNetDev::async_write<Container<PointerType<NetPacket> > >(        \
          Container<PointerType<NetPacket> > & packets,                       \
          callback_t && callback);

// Instantiate for std::list, std::vector, and std::forward_list with
// shared_ptr and unique_ptr
INSTANTIATE_ASYNC_METHODS(std::list, std::shared_ptr)
INSTANTIATE_ASYNC_METHODS(std::vector, std::shared_ptr)
INSTANTIATE_ASYNC_METHODS(std::forward_list, std::shared_ptr)

INSTANTIATE_ASYNC_METHODS(std::list, std::unique_ptr)
INSTANTIATE_ASYNC_METHODS(std::vector, std::unique_ptr)
INSTANTIATE_ASYNC_METHODS(std::forward_list, std::unique_ptr)

#undef INSTANTIATE_ASYNC_METHODS

void
VirtualNetDev::async_read(NetPacket &buf, callback_t &&callback)
{
  pImpl_->async_read(buf, std::move(callback));
}

void
VirtualNetDev::async_write(NetPacket &buf, callback_t &&callback)
{
  pImpl_->async_write(buf, std::move(callback));
}

bool
VirtualNetDev::up()
{
  pImpl_->up();
  return true;
}

bool
VirtualNetDev::down()
{
  pImpl_->down();
  return true;
}

VirtualNetDev::operator IPacketFilter *()
{
#ifdef __gnu_linux__
    return static_cast<IPacketFilter *>(pImpl_.get());
#else
    return nullptr;
#endif
}

} // namespace netdev
} // namespace celaratcp