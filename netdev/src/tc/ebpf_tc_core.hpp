/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * SPDX-FileCopyrightText: Hsia-Jun(Randy) Li
 */

#pragma once

extern "C"
{
#include <bpf/libbpf.h>
}

#include <atomic>
#include <cstdint>
#include <string_view>

namespace celaratcp {
namespace netdev {

class EbpfTcCore
{
protected:
  struct bpf_object *bpf_obj_;
  struct bpf_program *bpf_prog_;

private:
  int ifindex_;
  uint32_t tc_handle_;
  uint32_t tc_priority_;

  enum bpf_tc_attach_point tc_attach_point_;
  std::atomic<bool> is_attached_;

public:
  EbpfTcCore(std::string_view ebpf_program_path,
             std::string_view ebpf_program_name);
  ~EbpfTcCore();

  bool IsAttached() const noexcept;

  bool AttachToNetInterface(int ifindex, enum bpf_tc_attach_point attach_point,
                            uint32_t tc_handle = 0,
                            uint32_t tc_priority = 0) noexcept;

  bool DetachFromNetInterface() noexcept;
};

} // namespace netdev
} // namespace celaratcp
