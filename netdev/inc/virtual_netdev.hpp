/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * SPDX-FileCopyrightText: Hsia-Jun(Randy) Li
 */

#ifndef VIRTUAL_NET_HPP_
#define VIRTUAL_NET_HPP_

#ifdef __gnu_linux__
#include "tun_gnu_linux_impl.hpp"
#endif // __gnu_linux__

namespace celaratcp {
namespace netdev {

#ifdef __gnu_linux__
using VirtualNetDev = netdev::TunGnuLinuxImpl;
#endif

} // namespace netdev
} // namespace celaratcp

#endif // VIRTUAL_NET_HPP_