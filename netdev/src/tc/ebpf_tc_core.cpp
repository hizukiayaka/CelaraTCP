/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * SPDX-FileCopyrightText: Hsia-Jun(Randy) Li
 */

extern "C"
{
#include <bpf/libbpf_common.h>
}
#include <stdexcept>

#include "ebpf_tc_core.hpp"

namespace celaratcp {
namespace netdev {

EbpfTcCore::EbpfTcCore(std::string_view ebpf_program_path,
                       std::string_view ebpf_program_name)
    : bpf_obj_(nullptr), bpf_prog_(nullptr), ifindex_(-1), tc_handle_(0),
      tc_priority_(0), tc_attach_point_(BPF_TC_CUSTOM), is_attached_(false)
{
  struct bpf_object *obj
      = bpf_object__open_file(std::data(ebpf_program_path), nullptr);
  if (!obj)
    throw std::logic_error("can't open such object");

  if (bpf_object__load(obj)) {
    bpf_object__close(obj);
    throw std::logic_error("kernel rejected obj");
  }

  bpf_obj_ = obj;
  bpf_prog_
      = bpf_object__find_program_by_name(obj, std::data(ebpf_program_name));
  if (!bpf_prog_) {
    bpf_object__close(obj);
    throw std::logic_error("can't find the handler");
  }
}

bool
EbpfTcCore::IsAttached() const noexcept
{
  return is_attached_.load(std::memory_order_acquire);
}

bool
EbpfTcCore::AttachToNetInterface(int ifindex,
                                 enum bpf_tc_attach_point attach_point,
                                 uint32_t tc_handle,
                                 uint32_t tc_priority) noexcept
{
  if (is_attached_.load(std::memory_order_acquire)) {
    if (ifindex_ == ifindex && tc_attach_point_ == attach_point) {
      return true;
    }
    // throw std::logic_error("already attached");
    return false;
  }

  int prog_fd = bpf_program__fd(bpf_prog_);
  if (prog_fd < 0) {
    bpf_object__close(bpf_obj_);
    // throw std::logic_error("invalid program");
    return false;
  }

  LIBBPF_OPTS(bpf_tc_hook, hook, .ifindex = ifindex,
              .attach_point = attach_point);

  int err = bpf_tc_hook_create(&hook);
  if (err && err != -EEXIST) {
    bpf_object__close(bpf_obj_);
    // throw std::logic_error("can't create a tc hook");
    return false;
  }

  LIBBPF_OPTS(bpf_tc_opts, opts, .prog_fd = prog_fd, .flags = BPF_TC_F_REPLACE,
              .handle = tc_handle, .priority = tc_priority);

  err = bpf_tc_attach(&hook, &opts);
  if (err) {
    bpf_tc_hook_destroy(&hook);
    bpf_object__close(bpf_obj_);
    // throw std::logic_error("can't attach the tc hook");
    return false;
  }

  ifindex_ = ifindex;
  tc_attach_point_ = attach_point;
  tc_handle_ = opts.handle;
  tc_priority_ = opts.priority;
  is_attached_.store(true, std::memory_order_release);

  return true;
}

bool
EbpfTcCore::DetachFromNetInterface() noexcept
{
  if (!is_attached_.load(std::memory_order_acquire)) {
    // throw std::logic_error("not attached");
    return false;
  }

  LIBBPF_OPTS(bpf_tc_hook, hook, .ifindex = ifindex_,
              .attach_point = tc_attach_point_);

  LIBBPF_OPTS(bpf_tc_opts, opts, .handle = tc_handle_,
              .priority = tc_priority_);
  auto err = bpf_tc_detach(&hook, &opts);
  if (err) {
    return false;
  }
  err = bpf_tc_hook_destroy(&hook);
  if (err) {
    return false;
  }

  is_attached_.store(false, std::memory_order_release);
  return true;
}

EbpfTcCore::~EbpfTcCore()
{
  if (bpf_obj_)
    bpf_object__close(bpf_obj_);
}

} // namespace netdev
} // namespace celaratcp
