/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * SPDX-FileCopyrightText: Hsia-Jun(Randy) Li
 */

#include <asio.hpp>
#include <netlink/socket.h>
#include <netlink/route/addr.h>
#include <netlink/route/link.h>

namespace celaratcp {
namespace netdev {

class TunGnuLinuxImpl {
private:
    bool isMasterNode_;
    bool isClient_;
    TunGnuLinuxImpl(const std::string &intl_name);
    asio::posix::stream_descriptor stream_;

    struct nl_sock *sk_;
    int ifindex_;

    /* it would create a new queue */
    TunGnuLinuxImpl (const TunGnuLinuxImpl &other);
public:
    ~TunGnuLinuxImpl();
    /* client peer */
    TunGnuLinuxImpl(const std::string &intl_name, asio::ip::address_v4 &addr);

    TunGnuLinuxImpl addNode(asio::ip::address_v4 &addr);
};

}
}