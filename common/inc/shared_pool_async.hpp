/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * SPDX-FileCopyrightText: Hsia-Jun(Randy) Li
 */

#pragma once

#if defined(__linux__)
#include <sys/eventfd.h>
#include <unistd.h>
#endif

#include <asio/any_io_executor.hpp>
#include <asio/awaitable.hpp>
#include <asio/posix/stream_descriptor.hpp>
#include <asio/use_awaitable.hpp>

#include <cassert>
#include <cstdint>
#include <functional>
#include <list>
#include <memory>
#include <mutex>
#include <system_error>
#include <type_traits>
#include <utility>
#include <vector>

namespace celaratcp {
namespace memmanager {

struct mutex_locking_policy
{
  using mutex_type = std::mutex;
  using lock_type = std::lock_guard<mutex_type>;
};

template <class Value, class LockingPolicy = mutex_locking_policy>
class SharedPoolAsync
{
public:
  using value_type = Value;
  using value_ptr = std::shared_ptr<value_type>;
  using allocate_function = std::function<value_ptr()>;
  using mutex_type = typename LockingPolicy::mutex_type;
  using lock_type = typename LockingPolicy::lock_type;

private:
  struct impl : public std::enable_shared_from_this<impl>
  {
    allocate_function allocate_cb_;
    std::list<value_ptr> free_list_;
    std::size_t in_use_{ 0 };
    std::size_t capacity_{ 0 };
    mutable mutex_type mutex_;
    int event_fd_;

    impl(allocate_function cb, int efd)
        : allocate_cb_(std::move(cb)), event_fd_(efd)
    {
      if (!allocate_cb_)
        throw std::invalid_argument("allocate_function is empty");
    }

    void
    recycle(const value_ptr &res)
    {
      {
        lock_type lock(mutex_);
        free_list_.push_back(res);
        if (in_use_ > 0)
          --in_use_;
      }
#if defined(__linux__)
      // Signal availability (best effort).
      uint64_t one = 1;
      ssize_t r;
      do {
        r = ::write(event_fd_, &one, sizeof(one));
      }
      while (r < 0 && errno == EINTR);
#endif
    }

    std::size_t
    unused() const
    {
      lock_type lock(mutex_);
      return free_list_.size();
    }

    std::size_t
    capacity() const
    {
      lock_type lock(mutex_);
      return capacity_;
    }
  };

  struct deleter
  {
    std::weak_ptr<impl> pool_;
    value_ptr backing_;

    deleter(std::weak_ptr<impl> p, value_ptr backing)
        : pool_(std::move(p)), backing_(std::move(backing))
    {
    }

    void
    operator()(value_type *)
    {
      auto p = pool_.lock();
      if (p) {
        p->recycle(backing_);
      }
      backing_.reset();
    }
  };

  asio::any_io_executor ex_;
  int event_fd_;
  asio::posix::stream_descriptor event_sd_;
  std::shared_ptr<impl> pool_;

public:
  SharedPoolAsync(asio::any_io_executor ex, allocate_function alloc)
      : ex_(std::move(ex)),
#if defined(__linux__)
        event_fd_(::eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC)),
#else
        event_fd_(-1),
#endif
        event_sd_(ex_, event_fd_),
        pool_(std::make_shared<impl>(std::move(alloc), event_fd_))
  {
#if defined(__linux__)
    if (event_fd_ < 0)
      throw std::runtime_error("eventfd failed");
#endif
  }

  ~SharedPoolAsync()
  {
#if defined(__linux__)
    if (event_fd_ >= 0)
      ::close(event_fd_);
#endif
  }

  // Pre-create resources. Subsequent allocate() only draws from free_list_.
  void
  reserve(std::size_t new_cap)
  {
    std::vector<value_ptr> newly;
    newly.reserve(new_cap);

    {
      lock_type lock(pool_->mutex_);
      if (new_cap <= pool_->capacity_)
        return;

      for (std::size_t i = pool_->capacity_; i < new_cap; ++i) {
        newly.push_back(pool_->allocate_cb_());
      }
      pool_->capacity_ = new_cap;
    }

    // Append outside lock to minimize contention.
    {
      lock_type lock(pool_->mutex_);
      for (auto &r : newly)
        pool_->free_list_.push_back(std::move(r));
    }
  }

  std::size_t
  unused_resources() const
  {
    return pool_->unused();
  }

  std::size_t
  capacity() const
  {
    return pool_->capacity();
  }

  // Async allocation. Waits until a resource is available.
  asio::awaitable<value_ptr>
  allocate()
  {
    for (;;) {
      value_ptr backing;
      {
        lock_type lock(pool_->mutex_);
        if (!pool_->free_list_.empty()) {
          backing = pool_->free_list_.back();
          pool_->free_list_.pop_back();
          pool_->in_use_++;
        }
      }

      if (backing) {
        auto p = pool_->shared_from_this();
        co_return value_ptr(backing.get(), deleter(p, std::move(backing)));
      }

      // Wait for a resource to be recycled.
      co_await event_sd_.async_wait(asio::posix::stream_descriptor::wait_read,
                                    asio::use_awaitable);

#if defined(__linux__)
      // Drain the eventfd counter (aggregate signals).
      uint64_t cnt;
      while (::read(event_fd_, &cnt, sizeof(cnt)) < 0 && errno == EINTR) {
      }
#endif
      // Loop to attempt allocation again.
    }
  }

  // Non-blocking tryAllocate: returns empty shared_ptr if none available.
  value_ptr
  tryAllocate()
  {
    value_ptr backing;
    {
      lock_type lock(pool_->mutex_);
      if (!pool_->free_list_.empty()) {
        backing = pool_->free_list_.back();
        pool_->free_list_.pop_back();
        pool_->in_use_++;
      }
    }
    if (!backing)
      return {};
    auto p = pool_->shared_from_this();
    return value_ptr(backing.get(), deleter(p, std::move(backing)));
  }
};

} // namesapce memmanager
} // namespace celaratcp
