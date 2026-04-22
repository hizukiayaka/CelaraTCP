/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * SPDX-FileCopyrightText: Hsia-Jun(Randy) Li
 */

#pragma once

#include <array>
#include <cstdint>
#include <memory>
#include <span>
#include <type_traits>
#include <utility>

#include <asio/buffer.hpp>

namespace celaratcp {
constexpr uint_fast16_t kRegularMtu = 1500;
constexpr uint_fast16_t kPPPoEMtu = 1492;
constexpr uint_fast16_t kIpv4HdrSize = 20;
constexpr uint_fast16_t kIpv6HdrSize = 40;
constexpr uint_fast16_t kTcpHdrMinimalSize = 20;
constexpr uint_fast16_t kUdpHdrSize = 8;
constexpr uint_fast16_t kUdp6Payload = kRegularMtu - kIpv6HdrSize - 8;

struct NoneMeta
{
};

struct TcpSeqMeta
{
  uint_fast32_t seq_num{ 0 };
  uint_fast32_t ack_num{ 0 };
};

template <typename MetaT = TcpSeqMeta>
class NetPacketMeta
{
public:
  using meta_type = MetaT;
  using meta_ptr = std::unique_ptr<MetaT>;

protected:
  meta_ptr meta_;

  static meta_ptr
  MakeDefaultMeta()
  {
    if constexpr (std::is_default_constructible_v<MetaT>) {
      return std::make_unique<MetaT>();
    }

    return nullptr;
  }

public:
  NetPacketMeta() : meta_(MakeDefaultMeta()) {}

  explicit NetPacketMeta(meta_ptr meta) : meta_(std::move(meta)) {}

  void
  SetMeta(meta_ptr meta)
  {
    meta_ = std::move(meta);
  }

  MetaT *
  GetMeta()
  {
    return meta_.get();
  }

  const MetaT *
  GetMeta() const
  {
    return meta_.get();
  }
};

template <class P, class = void>
struct packet_meta
{
  using type = celaratcp::NoneMeta;
  static constexpr bool has_meta = false;
};

template <class P>
struct packet_meta<P, std::void_t<typename std::remove_cvref_t<P>::meta_type> >
{
  using type = typename std::remove_cvref_t<P>::meta_type;
  static constexpr bool has_meta = true;
};

template <class P>
using packet_meta_t = typename packet_meta<P>::type;

// Non-template abstract base for polymorphic packet pointers
class NetPacketBase
{
protected:
  uint_fast16_t used_bytes{ 0 };

public:
  NetPacketBase() = default;
  virtual ~NetPacketBase() = default;
  NetPacketBase(const NetPacketBase &) = default;
  NetPacketBase &operator=(const NetPacketBase &) = default;
  NetPacketBase(NetPacketBase &&) = default;
  NetPacketBase &operator=(NetPacketBase &&) = default;

  virtual asio::const_buffer GetConstBuf() = 0;

  virtual asio::mutable_buffer GetMutableBuf() = 0;

  virtual std::span<unsigned char> GetData() = 0;
  virtual std::span<const unsigned char> GetData() const = 0;
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

template <typename MetaT = NoneMeta>
class NetPacketT : public NetPacketBase, public NetPacketMeta<MetaT>
{
public:
  NetPacketT() = default;
  NetPacketT(const NetPacketT &) = delete;
  NetPacketT &operator=(const NetPacketT &) = delete;
  NetPacketT(NetPacketT &&) = default;
  NetPacketT &operator=(NetPacketT &&) = default;

  explicit NetPacketT(typename NetPacketMeta<MetaT>::meta_ptr meta)
      : NetPacketMeta<MetaT>(std::move(meta))
  {
  }
};

using NetPacket = NetPacketBase;

template <typename T>
concept NetPacketLike
    = (requires { typename std::remove_cvref_t<T>::meta_type; }
       && std::is_base_of_v<
           NetPacketT<typename std::remove_cvref_t<T>::meta_type>,
           std::remove_cvref_t<T> >)
      || std::is_base_of_v<NetPacketBase, std::remove_cvref_t<T> >;

// Concept for containers holding items derived from NetPacketBase
template <typename T>
concept NetPacketContainer = requires(T t)
{
  typename T::value_type;
  typename T::iterator;
  t.begin();
  t.end();
}
&&(requires {
  typename std::remove_reference_t<T>::value_type;
  requires std::is_base_of_v<
      NetPacketBase,
      typename std::pointer_traits<
          typename std::remove_reference_t<T>::value_type>::element_type>;
});

template <typename T>
concept NetPacketWrapper
    = NetPacketContainer<T> ||
      // Case 2: T is a smart pointer to a type derived from NetPacketBase
      (requires {
        requires std::is_base_of_v<
            NetPacketBase, typename std::pointer_traits<
                               std::remove_reference_t<T> >::element_type>;
      });

template <std::size_t... Ns>
class NetPacketSW : public NetPacketT<TcpSeqMeta>
{
private:
  static constexpr std::size_t kTotalSize = (Ns + ...);
  std::array<unsigned char, kTotalSize> data_;

public:
  explicit NetPacketSW() : data_() {}

  virtual asio::const_buffer
  GetConstBuf() override
  {
    return asio::buffer(data_.data(), used_bytes);
  }

  virtual asio::mutable_buffer
  GetMutableBuf() override
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

  std::span<const unsigned char>
  GetData() const override
  {
    return std::span<const unsigned char>(data_.begin(), data_.end());
  };

  std::array<unsigned char, kTotalSize> &
  GetStorageBuffer()
  {
    return data_;
  };
};

using Ipv4TcpHdrPacket = NetPacketSW<kIpv4HdrSize, kTcpHdrMinimalSize>;
using Ipv6TcpHdrPacket = NetPacketSW<kIpv6HdrSize, kTcpHdrMinimalSize>;
using Ipv4UdpHdrPacket = NetPacketSW<kIpv4HdrSize, kUdpHdrSize>;
using Ipv6UdpHdrPacket = NetPacketSW<kIpv6HdrSize, kUdpHdrSize>;

template <typename MetaT = TcpSeqMeta>
class NetMemChunkT : public NetPacketT<MetaT>
{
protected:
  std::span<uint8_t> chunk_;

public:
  template <typename It>
  NetMemChunkT(It first, std::size_t count) : chunk_(first, count)
  {
  }

  template <typename It>
  NetMemChunkT(It first, std::size_t count,
               typename NetPacketMeta<MetaT>::meta_ptr meta)
      : NetPacketT<MetaT>(std::move(meta)), chunk_(first, count)
  {
  }

  template <typename It, typename End>
  NetMemChunkT(It first, End last) : chunk_(first, last)
  {
  }

  template <typename It, typename End>
  NetMemChunkT(It first, End last,
               typename NetPacketMeta<MetaT>::meta_ptr meta)
      : NetPacketT<MetaT>(std::move(meta)), chunk_(first, last)
  {
  }

  template <typename Container>
  NetMemChunkT(Container &cont)
      : chunk_(reinterpret_cast<uint8_t *>(std::data(cont)), std::size(cont))
  {
  }

  virtual ~NetMemChunkT() = default;
  NetMemChunkT(const NetMemChunkT &) = delete;
  NetMemChunkT &operator=(const NetMemChunkT &) = delete;
  NetMemChunkT(NetMemChunkT &&) = default;
  NetMemChunkT &operator=(NetMemChunkT &&) = default;

  virtual asio::const_buffer
  GetConstBuf() override
  {
    return asio::buffer(chunk_.data(), this->used_bytes);
  }

  virtual asio::mutable_buffer
  GetMutableBuf() override
  {
    return asio::buffer(chunk_.data(), chunk_.size_bytes());
  }

  virtual std::size_t
  GetMaximumSize() override
  {
    return chunk_.size_bytes();
  }

  virtual bool
  SetUsedBytes(uint_fast16_t bytes) override
  {
    if (bytes > chunk_.size_bytes())
      return false;

    this->used_bytes = bytes;

    return true;
  }

  std::span<unsigned char>
  GetData() override
  {
    return chunk_;
  };

  std::span<const unsigned char>
  GetData() const override
  {
    return std::span<const unsigned char>(chunk_.begin(), chunk_.end());
  };

  virtual std::size_t
  GetId()
  {
    return 0;
  };
};

template <typename T>
concept NetMemChunkLike = requires
{
  typename std::remove_cvref_t<T>::meta_type;
}
&&std::is_base_of_v<NetMemChunkT<typename std::remove_cvref_t<T>::meta_type>,
                    std::remove_cvref_t<T> >;

using NetMemChunk = NetMemChunkT<>;

template <typename MetaT>
class NetMemChunkMeta : public NetMemChunkT<MetaT>
{
public:
  NetMemChunkMeta(const NetMemChunkMeta &) = delete;
  NetMemChunkMeta &operator=(const NetMemChunkMeta &) = delete;
  NetMemChunkMeta(NetMemChunkMeta &&) = default;
  NetMemChunkMeta &operator=(NetMemChunkMeta &&) = default;

  template <typename It>
  NetMemChunkMeta(It first, std::size_t count)
      : NetMemChunkT<MetaT>(first, count)
  {
  }

  template <typename It>
  NetMemChunkMeta(It first, std::size_t count, std::unique_ptr<MetaT> meta)
      : NetMemChunkT<MetaT>(first, count, std::move(meta))
  {
  }

  template <typename It, typename End>
  NetMemChunkMeta(It first, End last) : NetMemChunkT<MetaT>(first, last)
  {
  }

  template <typename It, typename End>
  NetMemChunkMeta(It first, End last, std::unique_ptr<MetaT> meta)
      : NetMemChunkT<MetaT>(first, last, std::move(meta))
  {
  }
};

} // namespace celaratcp
