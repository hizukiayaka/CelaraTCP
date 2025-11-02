/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * SPDX-FileCopyrightText: Hsia-Jun(Randy) Li
 */

#pragma once

extern "C"
{
#include <fcntl.h>
#include <linux/bpf.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/poll.h>
#include <unistd.h>
}

#include <atomic>
#include <cassert>
#include <coroutine>
#include <deque>
#include <map>
#include <memory>
#include <mutex>
#include <span>
#include <stdexcept>
#include <vector>

#include <asio/any_io_executor.hpp>
#include <asio/awaitable.hpp>
#include <asio/posix/stream_descriptor.hpp>
#include <asio/use_awaitable.hpp>

#include "net_packet.hpp"

namespace celaratcp {
namespace ebpf {

template <typename T>
class EbpfRingbufAllocator
    : public std::enable_shared_from_this<EbpfRingbufAllocator<T> >
{
  static_assert(std::is_base_of_v<NetMemChunk, T>,
                "Allocator is for NetMemChunk types");

private:
  asio::any_io_executor ex_;
  asio::posix::stream_descriptor sd_;

  const int map_fd_;
  const std::size_t page_size_;
  const std::size_t data_size_;
  const std::size_t pos_mask_;
  const uint8_t *data_;

  std::atomic<uint64_t> *consumer_pos_;
  std::atomic<uint64_t> *producer_pos_;
  uint_fast64_t dispatch_pos_;

  std::mutex return_mutex_;
  std::map<std::size_t, std::size_t> returned_slices_;

  void
  return_slice(std::size_t offset, std::size_t size)
  {
    std::lock_guard<std::mutex> lock(return_mutex_);
    returned_slices_.emplace(offset, size);
    advance_consumer_nolock();
  }

  /* It need to be called under a lock */
  void
  advance_consumer_nolock()
  {
    uint64_t current_consumer_pos
        = consumer_pos_->load(std::memory_order_relaxed);
    uint64_t total_released_size = 0;

    auto it = returned_slices_.begin();
    while (it != returned_slices_.end()) {
      // Check if the start of this slice matches the current consumer position
      if (it->first == (current_consumer_pos & pos_mask_)) {
        total_released_size += it->second;
        current_consumer_pos += it->second;
        // Remove the processed slice and move to the next
        it = returned_slices_.erase(it);
      } else {
        // The first slice doesn't match, so we can't advance further.
        break;
      }
    }

    if (total_released_size > 0) {
      // Atomically advance the consumer pointer by the total size of all
      // contiguous released slices.
      consumer_pos_->fetch_add(total_released_size, std::memory_order_acq_rel);
    }
  }

public:
  EbpfRingbufAllocator(asio::any_io_executor ex, int map_fd,
                       std::size_t page_size, std::size_t data_sz)
      : ex_(std::move(ex)), sd_(ex_, map_fd), map_fd_(map_fd),
        page_size_(page_size), data_size_(data_sz), pos_mask_(data_sz - 1),
        returned_slices_{}
  {
    // 1. Map consumer_pos (read/write)
    void *tmp = ::mmap(nullptr, page_size_, PROT_READ | PROT_WRITE, MAP_SHARED,
                       map_fd_, 0);
    if (tmp == MAP_FAILED)
      throw std::runtime_error("Failed to mmap consumer_pos");

    consumer_pos_ = static_cast<std::atomic<uint64_t> *>(tmp);
    dispatch_pos_ = consumer_pos_->load(std::memory_order_acquire);

    // 2. Map producer_pos and data (read-only)
    std::size_t mmap_sz = page_size_ + 2 * data_size_;
    tmp = ::mmap(nullptr, mmap_sz, PROT_READ, MAP_SHARED, map_fd_, page_size_);
    if (tmp == MAP_FAILED) {
      ::munmap(consumer_pos_, page_size_);
      throw std::runtime_error("Failed to mmap producer_pos/data");
    }
    producer_pos_ = static_cast<std::atomic<uint64_t> *>(tmp);
    data_ = static_cast<const uint8_t *>(tmp) + page_size_;
  }

  ~EbpfRingbufAllocator()
  {
    if (consumer_pos_ && consumer_pos_ != MAP_FAILED)
      ::munmap(static_cast<void *>(consumer_pos_), page_size_);
    if (producer_pos_ && producer_pos_ != MAP_FAILED)
      ::munmap(static_cast<void *>(producer_pos_),
               page_size_ + 2 * (pos_mask_ + 1));
  }

  asio::awaitable<std::shared_ptr<T> >
  Allocation()
  {
    for (;;) {
      uint64_t prod = producer_pos_->load(std::memory_order_acquire);

      // *** FIX: Check against our internal dispatch position ***
      if (dispatch_pos_ >= prod) {
        co_await sd_.async_wait(asio::posix::stream_descriptor::wait_read,
                                asio::use_awaitable);
      }

      // *** FIX: Calculate offset from our internal dispatch position ***
      std::size_t off = dispatch_pos_ & pos_mask_;

      const std::atomic<uint32_t> *hdr_ptr
          = reinterpret_cast<const std::atomic<uint32_t> *>(data_ + off);
      uint32_t hdr = hdr_ptr->load(std::memory_order_acquire);

      uint32_t flags = hdr & (BPF_RINGBUF_BUSY_BIT | BPF_RINGBUF_DISCARD_BIT);

      if (flags & BPF_RINGBUF_BUSY_BIT) {
        co_await sd_.async_wait(asio::posix::stream_descriptor::wait_read,
                                asio::use_awaitable);
        continue;
      }

      const std::size_t total_record_size
          = ((BPF_RINGBUF_HDR_SZ + ((hdr >> 2) << 2)) + 7) & ~7;

      // *** FIX: Advance our internal dispatch position ***
      dispatch_pos_ += total_record_size;

      if (flags & BPF_RINGBUF_DISCARD_BIT) {
        return_slice(off, total_record_size);
        continue; // Immediately process the next record
      }

      std::span<const uint8_t> slice(data_ + off + BPF_RINGBUF_HDR_SZ,
                                     total_record_size - BPF_RINGBUF_HDR_SZ);
      auto deleter
          = [weak_self = this->weak_from_this(), off, total_record_size](T *) {
              if (auto self = weak_self.lock()) {
                self->return_slice(off, total_record_size);
              }
            };

      co_return std::shared_ptr<T>(new T(slice), deleter);
    }
  }
};

} // namespace ebpf
} // namespace celaratcp
