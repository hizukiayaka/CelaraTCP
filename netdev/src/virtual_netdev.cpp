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

template <typename MutableBufferSequence>
void
VirtualNetDev::async_read(MutableBufferSequence &bufs,
                          asio::yield_context yield)
{
  pImpl_->async_read(bufs, yield);
}

void
VirtualNetDev::async_read(
    std::forward_list<std::shared_ptr<NetPacket> > packets,
    asio::yield_context yield)
{
  pImpl_->async_read(packets, yield);
}

void
VirtualNetDev::async_read(NetPacket &buf, asio::yield_context yield)
{
  pImpl_->async_read(buf, yield);
}

template <typename ConstBufferSequence>
void
VirtualNetDev::async_write(ConstBufferSequence &bufs,
                           asio::yield_context yield)
{
  pImpl_->async_write(bufs, yield);
}

void
VirtualNetDev::async_write(
    std::forward_list<std::shared_ptr<NetPacket> > packets,
    asio::yield_context yield)
{
  pImpl_->async_write(packets, yield);
}

void
VirtualNetDev::async_write(NetPacket &buf, asio::yield_context yield)
{
  pImpl_->async_write(buf, yield);
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
std::list<NetDevFiltertype>
VirtualNetDev::getSupportFilterType() const
{
  return pImpl_->getSupportFilterType();
}

bool
VirtualNetDev::setNetDevFilterType(std::list<NetDevFiltertype> type)
{
  return pImpl_->setNetDevFilterType(type);
}

} // namespace netdev

} // namespace celaratcp