/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * SPDX-FileCopyrightText: Hsia-Jun(Randy) Li
 */

#pragma once

#include <array>
#include <cstdint>
#include <span>

#include <asio/buffer.hpp>

namespace celaratcp {
constexpr uint_fast16_t kRegularMtu = 1500;
constexpr uint_fast16_t kPPPoEMtu = 1492;
constexpr uint_fast16_t kIpv4HdrSize = 20;
constexpr uint_fast16_t kIpv6HdrSize = 40;
constexpr uint_fast16_t kTcpHdrMinimalSize = 18;
constexpr uint_fast16_t kUdpHdrSize = 8;
constexpr uint_fast16_t kUdp6Payload = kRegularMtu - kIpv6HdrSize - 8;

class NetPacket
{
protected:
  uint_fast16_t used_bytes{ 0 };

public:
  class MetaData
  {
  public:
    std::array<uint32_t, 4> data{ 0 };
  } meta;

  NetPacket() = default;
  virtual ~NetPacket() = default;

  virtual asio::const_buffer getConstBuf() = 0;

  virtual asio::mutable_buffer getMutableBuf() = 0;

  virtual std::span<unsigned char> GetData() = 0;
  virtual constexpr std::size_t GetMaximumSize() = 0;

  uint_fast16_t
  GetUsedBytes() const
  {
    return used_bytes;
  }

  virtual bool
  SetUsedBytes(uint_fast16_t bytes)
  {
    used_bytes = bytes;
    return true;
  }
};

// Concept for containers holding items derived from NetPacket
template <typename T> concept NetPacketContainer = requires
{
  typename std::remove_reference_t<T>::value_type;
  requires std::is_base_of_v<
      NetPacket, typename std::pointer_traits<typename std::remove_reference_t<
                     T>::value_type>::element_type>;
};

template <std::size_t... Ns> class NetPacketSW : public NetPacket
{
private:
  static constexpr std::size_t kTotalSize = (Ns + ...);
  std::array<unsigned char, kTotalSize> data_;

public:
  explicit NetPacketSW() : data_() {}

  virtual asio::const_buffer
  getConstBuf() override
  {
    return asio::buffer(data_.data(), used_bytes);
  }

  virtual asio::mutable_buffer
  getMutableBuf() override
  {
    return asio::buffer(data_.data(), used_bytes);
  }

  virtual constexpr std::size_t
  GetMaximumSize() override
  {
    return kTotalSize;
  }

  virtual bool
  SetUsedBytes(uint_fast16_t bytes) override
  {
    if (bytes > data_.max_size())
      return false;

    used_bytes = bytes;

    return true;
  }

  std::span<unsigned char>
  GetData() override
  {
    return std::span<unsigned char>(data_.begin(), data_.end());
  };

  std::array<unsigned char, kTotalSize>
  getStorageBuffer()
  {
    return data_;
  };
};

using Ipv4TcpHdrPacket = NetPacketSW<kIpv4HdrSize, kTcpHdrMinimalSize>;
using Ipv6TcpHdrPacket = NetPacketSW<kIpv6HdrSize, kTcpHdrMinimalSize>;
using Ipv4UdpHdrPacket = NetPacketSW<kIpv4HdrSize, kUdpHdrSize>;
using Ipv6UdpHdrPacket = NetPacketSW<kIpv6HdrSize, kUdpHdrSize>;

class NetMemChunk : public NetPacket
{
private:
  std::span<uint8_t> chunk_;
  std::unique_ptr<uint8_t> meta_buf_;

public:
  template <typename It>
  NetMemChunk(It first, std::size_t count,
              std::unique_ptr<uint8_t> meta = nullptr)
      : chunk_(first, count), meta_buf_(std::move(meta))
  {
  }

  template <typename It, typename End>
  NetMemChunk(It first, End last, std::unique_ptr<uint8_t> meta = nullptr)
      : chunk_(first, last), meta_buf_(std::move(meta))
  {
  }

  template <typename Container>
  NetMemChunk(Container &cont)
      : chunk_(reinterpret_cast<uint8_t *>(std::data(cont)), std::size(cont))
  {
  }

  virtual ~NetMemChunk() = default;

  virtual asio::const_buffer
  getConstBuf() override
  {
    return asio::buffer(chunk_.data(), chunk_.size_bytes());
  }

  virtual asio::mutable_buffer
  getMutableBuf() override
  {
    return asio::buffer(chunk_.data(), chunk_.size_bytes());
  }

  virtual constexpr std::size_t
  GetMaximumSize() override
  {
    return chunk_.size_bytes();
  }

  virtual bool
  SetUsedBytes(uint_fast16_t bytes) override
  {
    if (bytes > chunk_.size_bytes())
      return false;

    used_bytes = bytes;

    return true;
  }

  std::span<unsigned char>
  GetData() override
  {
    return chunk_;
  };

  virtual std::size_t
  GetId()
  {
    return 0;
  };
};

}
