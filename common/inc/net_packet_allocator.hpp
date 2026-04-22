/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * SPDX-FileCopyrightText: Hsia-Jun(Randy) Li
 */

#ifndef _NET_PACKET_ALLOCATOR_HPP_
#define _NET_PACKET_ALLOCATOR_HPP_

#include <array>
#include <cstddef>
#include <cstdint>
#include <format>
#include <functional>
#include <list>
#include <memory>
#include <span>
#include <stdexcept>
#include <type_traits>
#include <utility>
#include <vector>

#include "net_packet.hpp"

namespace celaratcp {
namespace memmanager {

template <typename T>
class SimpleHeapAllocator
{
private:
  static_assert(NetMemChunkLike<T>,
                "This allocator is designed for NetMemChunkT-based packets");

  class Impl : public T
  {
  private:
    std::unique_ptr<uint8_t[]> data_;
    std::size_t data_size_;

    template <typename U = T>
    static U
    CreatePacket(uint8_t *payload, std::size_t data_size)
    {
      if constexpr (requires {
                      typename U::meta_type;
                      U(payload, data_size,
                        std::declval<
                            std::unique_ptr<typename U::meta_type> >());
                    })
      {
        using M = typename U::meta_type;
        if constexpr (std::is_default_constructible_v<M>) {
          return U(payload, data_size, std::make_unique<M>());
        } else {
          return U(payload, data_size, std::unique_ptr<M>{});
        }
      } else {
        return U(payload, data_size);
      }
    }

  public:
    Impl(std::unique_ptr<uint8_t[]> &&payload, std::size_t data_size)
        : T(CreatePacket(payload.get(), data_size)), data_(std::move(payload)),
          data_size_(data_size)
    {
    }

    ~Impl() override { data_.reset(); }
  };

public:
  SimpleHeapAllocator(std::size_t buf_size) : buf_size_(buf_size) {}

  std::shared_ptr<T>
  Allocation()
  {
    auto payload = std::make_unique<uint8_t[]>(buf_size_);
    auto wrap = std::make_shared<Impl>(std::move(payload), buf_size_);
    return std::static_pointer_cast<T>(wrap);
  }

private:
  const std::size_t buf_size_;
};

template <typename T>
class SimpleVectorAllocator
{
private:
  static_assert(NetMemChunkLike<T>,
                "This allocator is designed for NetMemChunkT-based packets");

  class Impl : public T
  {
  public:
    Impl(std::vector<uint8_t> &&vec) : T(vec), vec_(std::move(vec)) {}
    ~Impl() override = default;

  private:
    std::vector<uint8_t> vec_;
  };

public:
  explicit SimpleVectorAllocator(std::size_t buf_size) : buf_size_(buf_size) {}

  std::shared_ptr<T>
  Allocation()
  {
    auto vec = std::vector<uint8_t>(buf_size_);
    return std::make_shared<Impl>(std::move(vec));
  }

private:
  const std::size_t buf_size_;
};

template <typename T>
class ManagedMemAllocator
    : public std::enable_shared_from_this<ManagedMemAllocator<T> >
{
private:
  class Slice
  {
  public:
    const std::span<uint8_t> slice_;
    const std::size_t index_;

    Slice(std::span<uint8_t> &&slice, std::size_t index)
        : slice_(slice), index_(index)
    {
    }
  };

  using slice_t = Slice;
  class Impl : public T
  {
  public:
    Impl(slice_t &&slice, std::weak_ptr<ManagedMemAllocator> allocator)
        : T(slice.slice_), slice_(slice), allocator_(allocator)
    {
    }
    ~Impl() override
    {
      if (auto alloc = allocator_.lock()) {
        alloc->ReleaseSlice(slice_);
      }
    }

    virtual std::size_t
    GetId() override
    {
      return slice_.index_;
    }

  private:
    slice_t slice_;
    std::weak_ptr<ManagedMemAllocator> allocator_;
  };

public:
  using deleter_t = std::function<void()>;

  static std::shared_ptr<ManagedMemAllocator>
  Create(uint8_t *mem, std::size_t total_size, std::size_t slice_size,
         deleter_t &&deleter)
  {
    return std::shared_ptr<ManagedMemAllocator>(new ManagedMemAllocator(
        mem, total_size, slice_size, std::move(deleter)));
  }
  ~ManagedMemAllocator() { delete_callback_(); }

  std::shared_ptr<T>
  Allocation()
  {
    if (free_list_.empty()) {
      throw std::bad_alloc();
      return nullptr;
    }
    slice_t slice = free_list_.back();
    free_list_.pop_back();

    return std::make_shared<Impl>(std::move(slice), this->shared_from_this());
  }

  std::size_t
  GetNumChunks()
  {
    return free_list_.capacity();
  }

private:
  ManagedMemAllocator(void *start, std::size_t total_bytes,
                      std::size_t chunk_size, deleter_t &&deleter)
      : mem_(static_cast<uint8_t *>(start), total_bytes),
        delete_callback_(std::move(deleter))
  {
    constexpr std::size_t alignment = alignof(void *);

    if (chunk_size % alignment != 0) {
      throw std::invalid_argument(
          "Chunk size must be aligned to pointer size");
    }

    if (nullptr == start || total_bytes <= 0 || total_bytes < chunk_size) {
      throw std::invalid_argument(std::format(
          "Invalid memory allocation parameters: start={}, totalBytes={}, "
          "chunkSize={}",
          start, total_bytes, chunk_size));
    }

    std::size_t n = total_bytes / chunk_size;
    free_list_.reserve(n);

    for (std::size_t i = 0; i < n; i++) {
      free_list_.emplace_back(mem_.subspan(i * chunk_size, chunk_size), i);
    }
  }

  void
  ReleaseSlice(slice_t slice)
  {
    free_list_.push_back(slice);
  }

  const std::span<uint8_t> mem_;
  std::vector<slice_t> free_list_;
  const deleter_t delete_callback_;
};

} // namespace memmanager

} // namespace celaratcp

#endif
