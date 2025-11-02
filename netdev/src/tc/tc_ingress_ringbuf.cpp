/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * SPDX-FileCopyrightText: Hsia-Jun(Randy) Li
 */

extern "C"
{
#include <bpf/bpf.h>
#include <bpf/libbpf_common.h>

#include "l2_ingress_ring_l4.bpf.h"
}
#include <algorithm>

#include "tc_ingress_ringbuf.hpp"

namespace celaratcp {
namespace netdev {

// static method
std::size_t
TcIngressRingbuf::GetPageSize()
{
  static const std::size_t page_size = sysconf(_SC_PAGE_SIZE);
  return page_size;
}

std::size_t
TcIngressRingbuf::GetAlignRingBufSize()
{
  static const std::size_t align_ringbuf_size = []() {
    auto Get2Order = [](uint_fast64_t size) {
      std::size_t order = 0;
      while (size) {
        size >>= 1;
        order++;
      }
      return order;
    };
    auto page_2_order = Get2Order(GetPageSize());
    auto size_2_order = Get2Order(kRingBufSize);

    auto order = size_2_order - page_2_order;
    std::size_t expect_size = GetPageSize() << order;
    if (expect_size <= kRingBufSize)
      return expect_size;
    else
      return expect_size >> 1;
  }();
  return align_ringbuf_size;
}

TcIngressRingbuf::TcIngressRingbuf(std::string_view ebpf_program_path,
                                   int ifindex)
    : EbpfTcCore(ebpf_program_path, "ingress_filter"),
      target_ifindex_(ifindex), v4_tcp_map_mapfd_(-1), v6_tcp_map_mapfd_(-1)
{
  v4_tcp_map_mapfd_
      = bpf_object__find_map_fd_by_name(bpf_obj_, "v4_tcp_map_dict");
  if (v4_tcp_map_mapfd_ < 0) {
    throw std::logic_error("program TCPv4 table is missing");
  }

  v6_tcp_map_mapfd_
      = bpf_object__find_map_fd_by_name(bpf_obj_, "v6_tcp_map_dict");
  if (v6_tcp_map_mapfd_ < 0) {
    throw std::logic_error("program TCPv6 table is missing");
  }
}

TcIngressRingbuf::~TcIngressRingbuf()
{

  for (const auto &p : v4_tcp_maps_list_) {
    if (p.map_fd >= 0) {
      close(p.map_fd);
    }
  }

  for (const auto &p : v6_tcp_maps_list_) {
    if (p.map_fd >= 0) {
      close(p.map_fd);
    }
  }
}

std::list<FilterAction>
TcIngressRingbuf::GetSupportFilterActions() const
{
  return { FilterAction::TCP_DPORT_CAPTURE };
}

bool
TcIngressRingbuf::EnableFilters(std::list<FilterAction> &type)
{
  auto ret = AttachToNetInterface(target_ifindex_, BPF_TC_INGRESS);
  if (ret != 0) {
    return false;
  }

  for (const auto &filter_type : type) {
    switch (filter_type) {
    case FilterAction::TCP_DPORT_CAPTURE:
      return true;
    default:
      return false;
    }
  }
  return false;
}

std::any
TcIngressRingbuf::AddWatchIpv4PortRingbuf(uint_fast16_t port,
                                          asio::any_io_executor ex)
{
  for (const auto &p : v4_tcp_maps_list_) {
    if (p.port == port) {
      return p.map_fd;
    }
  }

  std::string map_name = "v4_" + std::to_string(port) + "_rbuf";
  LIBBPF_OPTS(bpf_map_create_opts, opts);

  int mapfd = bpf_map_create(BPF_MAP_TYPE_RINGBUF, map_name.c_str(), 0, 0,
                             GetAlignRingBufSize(), &opts);

  if (mapfd < 0) {
    return nullptr;
  }

  uint16_t port_v = static_cast<uint16_t>(htons(port));

  auto ret
      = bpf_map_update_elem(v4_tcp_map_mapfd_, &port_v, &mapfd, BPF_NOEXIST);
  if (ret != 0) {
    return nullptr;
  }

  auto r = std::make_shared<ebpf::EbpfTcpRingAllocator>(
      ex, mapfd, GetPageSize(), GetAlignRingBufSize());

  PortMapFdPair pair = {
    .port = port,
    .map_fd = mapfd,
    .r = r,
  };

  v4_tcp_maps_list_.push_back(pair);

  return r;
}

std::any
TcIngressRingbuf::AddWatchIpv6PortRingbuf(uint_fast16_t port,
                                          asio::any_io_executor ex)
{
  for (const auto &p : v6_tcp_maps_list_) {
    if (p.port == port) {
      return p.map_fd;
    }
  }

  std::string map_name = "v6_" + std::to_string(port) + "_rbuf";
  LIBBPF_OPTS(bpf_map_create_opts, opts);

  int mapfd = bpf_map_create(BPF_MAP_TYPE_RINGBUF, map_name.c_str(), 0, 0,
                             GetAlignRingBufSize(), &opts);

  if (mapfd < 0) {
    return nullptr;
  }

  uint16_t port_v = static_cast<uint16_t>(htons(port));

  auto ret
      = bpf_map_update_elem(v6_tcp_map_mapfd_, &port_v, &mapfd, BPF_NOEXIST);
  if (ret != 0) {
    return nullptr;
  }

  auto r = std::make_shared<ebpf::EbpfTcpRingAllocator>(
      ex, mapfd, GetPageSize(), GetAlignRingBufSize());

  PortMapFdPair pair = {
    .port = port,
    .map_fd = mapfd,
    .r = r,
  };

  v6_tcp_maps_list_.push_back(pair);

  return r;
}

bool
TcIngressRingbuf::RemoveWatchIpv4Port(uint16_t port)
{
  uint16_t port_v = static_cast<uint16_t>(htons(port));
  auto ret = bpf_map_delete_elem_flags(v4_tcp_map_mapfd_, &port_v, BPF_EXIST);
  if (ret) {
    if (ret == -ENOENT)
      return true;
    return false;
  }

  return true;
}

bool
TcIngressRingbuf::RemoveWatchIpv6Port(uint16_t port)
{
  uint16_t port_v = static_cast<uint16_t>(htons(port));
  auto ret = bpf_map_delete_elem_flags(v6_tcp_map_mapfd_, &port_v, BPF_EXIST);
  if (ret) {
    if (ret == -ENOENT)
      return true;
    return false;
  }

  return true;
}

} // namespace netdev
} // namespace celaratcp
