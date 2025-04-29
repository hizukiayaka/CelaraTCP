/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * SPDX-FileCopyrightText: Hsia-Jun(Randy) Li
 */

#ifndef TUN_GNU_LINUX_IMPL_HPP
#define TUN_GNU_LINUX_IMPL_HPP

#include <forward_list>
#include <optional>

#include <asio.hpp>
#include <asio/spawn.hpp>
#include <netlink/socket.h>
#include <netlink/route/addr.h>
#include <netlink/route/link.h>

#include "net_packet.hpp"

namespace celaratcp {
namespace netdev {

class TunGnuLinuxImpl {
private:
    bool isMasterNode_;
    bool isClient_;
    TunGnuLinuxImpl(asio::io_context &io_context, const std::string &intl_name);
    asio::posix::stream_descriptor stream_;

    struct nl_sock *sk_;
    int ifindex_;

    /* it would create a new queue */
    //TunGnuLinuxImpl (const TunGnuLinuxImpl &other);
public:
    ~TunGnuLinuxImpl();
    /* client peer */
    TunGnuLinuxImpl(asio::io_context &io_context, const std::string &intl_name, const asio::ip::address_v4 &addr);

    template<typename MutableBufferSequence>
    void async_read(MutableBufferSequence& bufs, asio::yield_context yield);
    template<typename ConstBufferSequence>
    void async_write(ConstBufferSequence& bufs, asio::yield_context yield);

    void async_read(NetPacket &buf, asio::yield_context yield);
    void async_read(std::forward_list<std::shared_ptr<NetPacket>> packets,asio::yield_context yield);

    void async_write(NetPacket &buf, asio::yield_context yield);
    void async_write(std::forward_list<std::shared_ptr<NetPacket>> packets, asio::yield_context yield);

    std::optional<TunGnuLinuxImpl> addNode(asio::ip::address_v4 &addr);

    void up();
    void down();
};

}
}

#endif