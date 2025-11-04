/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * SPDX-FileCopyrightText: Hsia-Jun(Randy) Li
 */

#pragma once

extern "C" {
#include <linux/if_packet.h>
#include <linux/if_ether.h>
}

#include <asio/any_io_executor.hpp>
#include <asio/awaitable.hpp>
#include <asio/experimental/concurrent_channel.hpp>
#include <asio/use_awaitable.hpp>

#include <cassert>
#include <cstdint>
#include <functional>
#include <list>
#include <memory>
#include <mutex>
#include <queue>
#include <span>
#include <system_error>
#include <type_traits>
#include <utility>
#include <vector>

#include "net_packet.hpp"

namespace celaratcp {
namespace memmanger {

struct mutex_locking_policy
{
  using mutex_type = std::mutex;
  using lock_type = std::lock_guard<mutex_type>;
};

template <class Value, class LockingPolicy = mutex_locking_policy>
class AFPacketTxPoolAsync
{
public:
  using value_type = Value;
  using value_ptr = std::shared_ptr<value_type>;
  using mutex_type = typename LockingPolicy::mutex_type;
  using lock_type = typename LockingPolicy::lock_type;

private:
  struct impl : public std::enable_shared_from_this<impl>
  {
    struct FrameSlice
    {
      const uint32_t idx;
      std::span<uint8_t> frame_base;
      tpacket3_hdr *hdr;

      FrameSlice(uint32_t i, std::span<uint8_t> frame)
          : idx(i), frame_base(frame),
            hdr(reinterpret_cast<tpacket3_hdr *>(std::data(frame)))
      {
        ResetHeader();
      }

      void
      ResetHeader()
      {
        hdr->tp_status = TP_STATUS_AVAILABLE;
        hdr->tp_len = 0;
        hdr->tp_snaplen = 0;
        hdr->tp_mac = sizeof(tpacket3_hdr);
        hdr->tp_net = hdr->tp_mac + ETH_HLEN;
      }

      value_type *
      CreateResource()
      {
        uint8_t *payload_start = std::data(frame_base) + hdr->tp_net;
        size_t payload_size = std::size(frame_base) - hdr->tp_net;
        return new value_type(payload_start, payload_size);
      }
    };

    mutable mutex_type mutex_;
    std::priority_queue<uint32_t, std::vector<uint32_t>,
                        std::greater<uint32_t> >
        available_indices_;
    std::vector<FrameSlice> frames_;
    asio::experimental::concurrent_channel<void(asio::error_code)> notifier_;

    void
    recycle(uint32_t frame_idx, std::size_t used_bytes)
    {
      bool was_empty;
      {
        lock_type lock(mutex_);

        was_empty = available_indices_.empty();
        auto &frame = frames_[frame_idx];

        if (used_bytes) {
          // TODO: Add to a 'released' queue for flush()
        } else {
          // Discard path: make available immediately
          frame.ResetHeader();
          available_indices_.push(frame_idx);
        }
      }

      // If the queue was empty, there might be waiters. Send a notification.
      if (was_empty) {
        notifier_.try_send(asio::error_code{});
      }
    }
    /* ctor */
    impl(asio::any_io_executor& ex, std::span<uint8_t> ring_buf,
         std::size_t frame_size, std::size_t block_size)
        : notifier_(ex)
    {
      const auto total_size = std::size(ring_buf);
      if (total_size % block_size)
        throw std::invalid_argument("unaligned block size");

      if (block_size % frame_size) {
        const std::size_t frame_nr = total_size / frame_size;
        frames_.reserve(frame_nr);

        for (std::size_t i = 0; i < frame_nr; i++) {
          frames_.emplace_back(i,
                               ring_buf.subspan(i * frame_size, frame_size));
          available_indices_.push(i);
        }
      } else {
        const uint_fast8_t frames_per_block
            = std::floor(block_size / frame_size);
        const std::size_t block_nr = total_size / block_size;
        const std::size_t frame_nr = block_nr * frames_per_block;
        frames_.reserve(frame_nr);

        for (std::size_t i = 0; i < block_nr; i++) {
          const auto frame_nr_prev_blocks = frames_per_block * i;
          for (std::size_t j = 0; j < frames_per_block; j++) {
            frames_.emplace_back(
                frame_nr_prev_blocks + j,
                ring_buf.subspan(i * block_size + j * frame_size, frame_size));
            available_indices_.push(frame_nr_prev_blocks + j);
          }
        }
      }
    }
    /* ctor end here */
  };
  struct deleter
  {
    std::weak_ptr<impl> pool_impl_;
    uint32_t frame_idx_;

    deleter(std::weak_ptr<impl> p, uint32_t idx)
        : pool_impl_(std::move(p)), frame_idx_(idx)
    {
    }

    void
    operator()(value_type *ptr)
    {
      auto used = ptr->GetUsedBytes();
      // Delete the temporary view object
      delete ptr;

      if (auto pool_sh = pool_impl_.lock()) {
        pool_sh->recycle(frame_idx_, used);
      }
    }
  };

  std::shared_ptr<impl> pool_;

public:
  AFPacketTxPoolAsync(asio::any_io_executor& ex, std::span<uint8_t> ring_buf,
                      std::size_t frame_size, std::size_t block_size)
      : pool_(std::make_shared<impl>(ex, ring_buf, frame_size, block_size))
  {
    static_assert(std::is_base_of_v<NetMemChunk, Value>,
                  "Value must derive from NetMemChunk");
  }

  asio::awaitable<value_ptr>
  allocate()
  {
    for (;;) {
      uint32_t frame_idx;
      bool allocated = false;
      {
        lock_type lock(pool_->mutex_);
        if (!pool_->available_indices_.empty()) {
          frame_idx = pool_->available_indices_.top();
          pool_->available_indices_.pop();
          allocated = true;
        }
      }

      if (allocated) {
        auto &frame = pool_->frames_[frame_idx];
        auto resource = frame.CreateResource();
        co_return value_ptr(resource, deleter(pool_, frame_idx));
      }

      // Queue is empty, so wait for a notification from the channel.
      co_await pool_->notifier_.async_receive(asio::use_awaitable);
      // FIXME error handling
#if 0
      if (ec) { // Channel was closed
        co_return nullptr;
      }
#endif
      // Loop back to try allocating again.
    }
  }

#if 0
  static void
  Submit(value_ptr &packet)
  {
    if (!packet)
      return;
    if (auto *d = std::get_deleter<deleter>(packet)) {
      d->m_committed = true;
    }

    packet.reset();
  }
#endif
};

#if 0
template<class Value>
class SharedPoolAsync
{
public:
  using value_ptr = std::shared_ptr<Value>;
  using allocate_function = std::function<value_ptr()>;
private:
  asio::experimental::channel<void(asio::error_code, value_ptr)> chan_;
  allocate_function alloc_;
  std::size_t cap_ = 0;
public:
  SharedPoolAsync(asio::any_io_executor ex, allocate_function fn)
    : chan_(ex), alloc_(std::move(fn))
  { if (!alloc_) throw std::invalid_argument("alloc fn"); }

  void reserve(std::size_t n)
  {
    while (cap_ < n) {
      chan_.try_send(asio::error_code{}, alloc_());
      ++cap_;
    }
  }

  asio::awaitable<value_ptr> allocate()
  {
    auto [ec, ptr] = co_await chan_.async_receive(asio::use_awaitable);
    if (ec) co_return {};
    co_return value_ptr(ptr.get(),
       [this, backing=std::move(ptr)](Value*) mutable {
         chan_.try_send(asio::error_code{}, std::move(backing));
       });
  }

  value_ptr tryAllocate()
  {
    asio::error_code ec; value_ptr ptr;
    if (chan_.try_receive(ec, ptr)) {
      return value_ptr(ptr.get(),
        [this, backing=std::move(ptr)](Value*) mutable {
          chan_.try_send(asio::error_code{}, std::move(backing));
        });
    }
    return {};
  }
};
#endif

} // namesapce memmanger
} // namespace celaratcp
