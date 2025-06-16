/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * SPDX-FileCopyrightText: Hsia-Jun(Randy) Li
 */

#ifndef _NET_PACKET_ALLOCATOR_HPP_
#define _NET_PACKET_ALLOCATOR_HPP_

#include "net_packet.hpp"
#include <recycle/shared_pool.hpp>

namespace celaratcp {
namespace memmanager {

template <typename T> class SimpleHeapAllocator
{
private:
  class Impl : public T
  {
  private:
    std::unique_ptr<uint8_t[]> data_;
    std::size_t dataSize_;

  public:
    Impl(std::unique_ptr<uint8_t[]> &&payload, std::size_t data_size)
        : T(payload.get(), data_size), data_(std::move(payload)),
          dataSize_(data_size)
    {
    }

    ~Impl() { data_.reset(); }
  };

  std::size_t bufSize_;

public:
  SimpleHeapAllocator(std::size_t buf_size) : bufSize_(buf_size) {}

  std::shared_ptr<T>
  allocation()
  {
    std::unique_ptr<uint8_t[]> payload
        = std::make_unique_for_overwrite<uint8_t[]>(bufSize_);
    auto wrap = std::make_shared<Impl>(std::move(payload), bufSize_);
    return static_cast<std::shared_ptr<T>>(wrap);
  }
};

template <typename T> class SimpleVectorAllocator
{
  class Impl : public T
  {
  public:
    Impl(std::vector<uint8_t> &&vec)
        : T(vec), vec_(std::move(vec))
    {
    }

  private:
    std::vector<uint8_t> vec_;
  };

public:
  explicit SimpleVectorAllocator(std::size_t bufSize) : bufSize_(bufSize) {}

  std::shared_ptr<T>
  allocation()
  {
    auto vec = std::vector<uint8_t>(bufSize_);
    return std::make_shared<Impl>(std::move(vec));
  }

private:
  std::size_t bufSize_;
};

} // namespace memmanager

} // namespace celaratcp

#endif
