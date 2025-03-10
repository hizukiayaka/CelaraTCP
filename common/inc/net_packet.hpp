/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * SPDX-FileCopyrightText: Hsia-Jun(Randy) Li
 */

#pragma once

#include <array>
#include <cstdint>
#include <vector>

#include <asio/buffer.hpp>

namespace celaratcp {
constexpr uint_fast16_t regularMtu = 1500;
constexpr uint_fast16_t pppoeMtu = 1492;
constexpr uint_fast16_t ipv4HdrSize = 20;
constexpr uint_fast16_t ipv6HdrSize = 40;
constexpr uint_fast16_t tcpHdrMinimalSize = 18;
constexpr uint_fast16_t udpHdrSize = 8;
constexpr uint_fast16_t Udp6Payload = regularMtu - ipv6HdrSize - 8;

class NetPacket
{
protected:
  uint_fast16_t usedBytes {0};

  NetPacket() = default;
  ~NetPacket() = default;

public:
  virtual asio::const_buffer
  getConstBuf() = 0;

  virtual asio::mutable_buffer
  getMutableBuf() = 0;

  virtual std::vector<unsigned char> getData() = 0;
  virtual constexpr std::size_t getMaximumSize() = 0;

  const uint_fast16_t getUsedBytes()
  {
    return usedBytes;
  }

  virtual bool setUsedBytes(uint_fast16_t bytes)
  {
    usedBytes = bytes;
    return true;
  }
};

template <std::size_t... Ns>
class NetPacketSW : public NetPacket
{
private:
  static constexpr std::size_t totalSize = (Ns + ...);
  std::array<unsigned char, totalSize> data_;

  asio::const_buffer cbuf_;
  asio::mutable_buffer mbuf_;
public:
  explicit NetPacketSW()
      : cbuf_(asio::buffer(data_)), mbuf_(asio::buffer(data_)) {};

  virtual asio::const_buffer
  getConstBuf() override
  {
    return cbuf_;
  }

  virtual asio::mutable_buffer
  getMutableBuf() override
  {
    return mbuf_;
  }

  virtual constexpr std::size_t getMaximumSize() override
  {
    return totalSize;
  }

  virtual bool setUsedBytes(uint_fast16_t bytes) override {
    if (bytes > data_.max_size())
      return false;

    usedBytes = bytes;
    cbuf_ = asio::buffer(data_, bytes);
    mbuf_ = asio::buffer(data_, bytes);

    return true;
  }

  std::vector<unsigned char> getData() override {
    return std::vector<unsigned char>(data_.begin(), data_.end());
  };

  std::array<unsigned char, totalSize> getStorageBuffer() {
    return data_;
  };

};

using Ipv4TcpHdrPacket = NetPacketSW<ipv4HdrSize, tcpHdrMinimalSize>;
using Ipv6TcpHdrPacket = NetPacketSW<ipv6HdrSize, tcpHdrMinimalSize>;
using Ipv4UdpHdrPacket = NetPacketSW<ipv4HdrSize, udpHdrSize>;
using Ipv6UdpHdrPacket = NetPacketSW<ipv6HdrSize, udpHdrSize>;

}
