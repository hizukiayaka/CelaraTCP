/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * SPDX-FileCopyrightText: Hsia-Jun(Randy) Li
 */

#pragma once

extern "C"
{
#include <linux/if_ether.h>
#include <linux/if_packet.h>
}

#include <asio/any_io_executor.hpp>
#include <asio/awaitable.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/experimental/concurrent_channel.hpp>
#include <asio/generic/datagram_protocol.hpp>
#include <asio/redirect_error.hpp>
#include <asio/steady_timer.hpp>
#include <asio/strand.hpp>
#include <asio/use_awaitable.hpp>

#include <atomic>
#include <cassert>
#include <cstdint>
#include <deque>
#include <list>
#include <memory>
#include <queue>
#include <span>
#include <system_error>
#include <type_traits>
#include <utility>
#include <vector>

#include "net_packet.hpp"

namespace celaratcp {

namespace netio {
static asio::generic::datagram_protocol::endpoint
MakeEndpoint(int ifindex, std::span<uint8_t> endpoint_mac,
             uint_fast16_t ethernetii)
{
  struct sockaddr_ll s{};
  s.sll_family = AF_PACKET;
  s.sll_protocol = htons(ethernetii);
  s.sll_ifindex = ifindex;
  s.sll_halen = static_cast<uint8_t>(std::size(endpoint_mac));
  std::memcpy(
      s.sll_addr, std::data(endpoint_mac),
      std::min<std::size_t>(std::size(endpoint_mac), sizeof(s.sll_addr)));
  asio::generic::datagram_protocol::endpoint ep{
    reinterpret_cast<struct sockaddr *>(&s), sizeof(s), SOCK_DGRAM
  };
  return ep;
}

static std::array<uint8_t, ETH_HLEN>
GenerateEthernetFrame(std::span<uint8_t> dst_mac, std::span<uint8_t> src_mac,
                      uint16_t ethertype)
{
  std::array<uint8_t, ETH_HLEN> frame{};

  std::memcpy(std::data(frame), std::data(dst_mac), ETH_ALEN);
  std::memcpy(std::data(frame) + ETH_ALEN, std::data(src_mac), ETH_ALEN);
  uint16_t *ethertype_ptr
      = reinterpret_cast<uint16_t *>(std::data(frame) + 2 * ETH_ALEN);
  *ethertype_ptr = htons(ethertype);

  return frame;
}

} // namespace netio

namespace memmanager {

struct mutex_locking_policy
{
  using mutex_type = std::mutex;
  using lock_type = std::lock_guard<mutex_type>;
};

struct dgram_l3_tag
{
};
struct raw_l2_tag
{
};

template <typename LinkType>
struct proto_traits;

template <>
struct proto_traits<dgram_l3_tag>
{
  using protocol_type = asio::generic::datagram_protocol;
  using socket_type = asio::generic::datagram_protocol::socket;
  using endpoint_type = asio::generic::datagram_protocol::endpoint;

  static protocol_type
  make_proto()
  {
    return protocol_type(AF_PACKET, SOCK_DGRAM);
  }
};

template <>
struct proto_traits<raw_l2_tag>
{
  using protocol_type = asio::generic::raw_protocol;
  using socket_type = asio::generic::raw_protocol::socket;
  using endpoint_type = asio::generic::raw_protocol::endpoint;

  static protocol_type
  make_proto()
  {
    return protocol_type(AF_PACKET, SOCK_RAW);
  }
};

template <typename Value, typename LinkType = dgram_l3_tag>
class AFPacketTxRingAsync
{
public:
  using value_type = Value;
  using value_ptr = std::shared_ptr<value_type>;

  using traits = proto_traits<LinkType>;
  using socket_type = typename traits::socket_type;
  using endpoint_type = typename traits::endpoint_type;

private:
  struct impl : public std::enable_shared_from_this<impl>
  {
    struct FrameSlice
    {
      const uint32_t idx;
      std::span<uint8_t> frame_base;
      tpacket3_hdr *hdr;
      /* offset from tp_net */
      const std::size_t l3_offset;

      explicit FrameSlice(uint32_t i, std::span<uint8_t> frame,
                          std::span<uint8_t> ether_hdr)
          requires std::same_as<LinkType, raw_l2_tag>
          : idx(i),
            frame_base(frame),
            hdr(reinterpret_cast<tpacket3_hdr *>(std::data(frame))),
            l3_offset(std::size(ether_hdr))
      {
        ResetHeader();
        hdr->tp_snaplen = 0;
        std::memcpy(std::data(frame) + hdr->tp_mac, std::data(ether_hdr),
                    std::size(ether_hdr));
      }

      explicit FrameSlice(uint32_t i, std::span<uint8_t> frame)
          requires std::same_as<LinkType, dgram_l3_tag>
          : idx(i),
            frame_base(frame),
            hdr(reinterpret_cast<tpacket3_hdr *>(std::data(frame))),
            l3_offset(0)
      {
        ResetHeader();
        hdr->tp_snaplen = 0;
      }

      void
      ResetHeader() requires std::same_as<LinkType, raw_l2_tag>
      {
        hdr->tp_status = TP_STATUS_AVAILABLE;
        hdr->tp_len = 0;
        hdr->tp_mac = sizeof(tpacket3_hdr);
        hdr->tp_net = hdr->tp_mac;
      }

      void
      ResetHeader() requires std::same_as<LinkType, dgram_l3_tag>
      {
        hdr->tp_status = TP_STATUS_AVAILABLE;
        hdr->tp_len = 0;
        hdr->tp_mac = sizeof(tpacket3_hdr);
        hdr->tp_net = hdr->tp_mac + ETH_HLEN;
      }

      void
      SetPayloadSize(std::size_t size)
      {
        hdr->tp_len = size + l3_offset;
      }

      value_type *
      CreateResource()
      {
        uint8_t *payload_start
            = std::data(frame_base) + hdr->tp_net + l3_offset;
        size_t payload_size = std::size(frame_base) - hdr->tp_net - l3_offset;
        return new value_type(payload_start, payload_size);
      }
    };
    // End of struct FrameSlice

    asio::strand<asio::any_io_executor> strand_;
    std::priority_queue<uint32_t, std::vector<uint32_t>,
                        std::greater<uint32_t> >
        available_indices_;
    std::vector<FrameSlice> frames_;
    asio::experimental::concurrent_channel<void(asio::error_code)> notifier_;

    asio::experimental::concurrent_channel<void(asio::error_code, uint32_t)>
        pending_indices_;

    socket_type &sk_;
    const asio::const_buffer sent_buffer_;
    endpoint_type ep_;
    std::span<uint8_t> ether_hdr_;

    struct Deleter
    {
      std::weak_ptr<impl> pool_impl_;
      uint32_t frame_idx_;

      Deleter(std::weak_ptr<impl> p, uint32_t idx)
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
          auto idx = frame_idx_;
          asio::post(pool_sh->strand_,
                     [pool_sh, idx, used]() { pool_sh->Recycle(idx, used); });
        }
      }
    };

    asio::awaitable<value_ptr>
    Allocate() noexcept
    {
      co_await asio::dispatch(strand_, asio::use_awaitable);
      for (;;) {
        if (!available_indices_.empty()) {
          uint32_t frame_idx;
          frame_idx = available_indices_.top();
          available_indices_.pop();

          auto &frame = frames_[frame_idx];
          auto resource = frame.CreateResource();

          co_return value_ptr(resource,
                              Deleter(this->weak_from_this(), frame_idx));
        } else {
          // Queue is empty, so wait for a notification from the channel.
          // Loop back to try allocating again.

          asio::error_code ec;
          co_await notifier_.async_receive(
              asio::redirect_error(asio::use_awaitable, ec));
          if (ec) {
            // Channel was closed
            co_return value_ptr(nullptr);
          }
        }
      }
    }

    void
    Recycle(uint32_t frame_idx, std::size_t used_bytes)
    {
      bool was_empty;

      was_empty = available_indices_.empty();
      auto &frame = frames_[frame_idx];

      if (used_bytes) {
        // We don't need to lock here
        frame.SetPayloadSize(used_bytes);
        std::atomic_thread_fence(std::memory_order_release);
        pending_indices_.try_send(asio::error_code{}, frame_idx);
      } else {
        // Discard path: make available immediately
        frame.ResetHeader();
        available_indices_.push(frame_idx);

        if (was_empty) {
          // If the queue was empty, there might be waiters. Send a
          // notification.
          notifier_.try_send(asio::error_code{});
        }
      }
    }

    void
    MarkSending(uint32_t frame_idx)
    {
      auto &frame = frames_[frame_idx];
      std::atomic_thread_fence(std::memory_order_release);
      frame.hdr->tp_status = TP_STATUS_SEND_REQUEST;
    }

    asio::awaitable<void>
    RecycleWorker()
    {
      int32_t pending_idx = -1;
      std::deque<uint32_t> batch_indices;

      // batch_indices.reserve(16);
      for (;;) {
        uint32_t frame_idx;

        if (pending_idx >= 0) {
          frame_idx = pending_idx;
          pending_idx = -1;
        } else {
          asio::error_code ec;
          frame_idx = co_await pending_indices_.async_receive(
              asio::redirect_error(asio::use_awaitable, ec));
          if (ec) {
            co_return;
          }
        }

        MarkSending(frame_idx);
        batch_indices.clear();
        batch_indices.push_back(frame_idx);

        for (;;) {
          bool loop = true;
          bool success = pending_indices_.try_receive(
              [&pending_idx, &frame_idx, &loop](asio::error_code ec,
                                                uint32_t idx) {
                if (ec)
                  loop = false;

                if (idx < frame_idx) {
                  pending_idx = idx;
                  loop = false;
                  return;
                }
                frame_idx = idx;
              });

          if (!success || !loop)
            break;
          MarkSending(frame_idx);
          batch_indices.push_back(frame_idx);
        }

        asio::error_code ec;
        if constexpr (std::is_same_v<LinkType, dgram_l3_tag>) {
          co_await sk_.async_send_to(
              sent_buffer_, ep_,
              asio::redirect_error(asio::use_awaitable, ec));
        } else {
          co_await sk_.async_send(
              sent_buffer_, asio::redirect_error(asio::use_awaitable, ec));
        }

        if (ec) {
          for (const auto &idx : batch_indices) {
            asio::post(strand_, [self = this->shared_from_this(), idx]() {
              self->Recycle(idx, 0);
            });
          }

          Shutdown();
          co_return;
        }

        for (const auto &idx : batch_indices) {
          asio::post(strand_, [self = this->shared_from_this(), idx]() {
            self->Recycle(idx, 0);
          });
        }
      }
    }

    void
    Shutdown()
    {
      asio::post(strand_, [self = this->shared_from_this()]() {
        self->notifier_.close();
        self->pending_indices_.close();
      });
    }

    /* ctor */
    void
    InitFrames(std::span<uint8_t> ring_buf, std::size_t frame_size,
               std::size_t block_size)
    {
      const auto total_size = std::size(ring_buf);
      if (total_size % block_size)
        throw std::invalid_argument("unaligned block size");

      if (block_size % frame_size) {
        const std::size_t frame_nr = total_size / frame_size;
        frames_.reserve(frame_nr);

        for (std::size_t i = 0; i < frame_nr; i++) {
          if constexpr (std::is_same_v<LinkType, raw_l2_tag>) {
            frames_.emplace_back(
                i, ring_buf.subspan(i * frame_size, frame_size), ether_hdr_);
          } else {
            frames_.emplace_back(i,
                                 ring_buf.subspan(i * frame_size, frame_size));
          }
          available_indices_.push(i);
        }
      } else {
        const std::size_t frames_per_block = block_size / frame_size;
        const std::size_t block_nr = total_size / block_size;
        const std::size_t frame_nr = block_nr * frames_per_block;
        frames_.reserve(frame_nr);

        for (std::size_t i = 0; i < block_nr; i++) {
          const auto frame_nr_prev_blocks = frames_per_block * i;
          for (std::size_t j = 0; j < frames_per_block; j++) {
            if constexpr (std::is_same_v<LinkType, raw_l2_tag>) {
              frames_.emplace_back(
                  frame_nr_prev_blocks + j,
                  ring_buf.subspan(i * block_size + j * frame_size,
                                   frame_size),
                  ether_hdr_);
            } else {
              frames_.emplace_back(
                  frame_nr_prev_blocks + j,
                  ring_buf.subspan(i * block_size + j * frame_size,
                                   frame_size));
            }
            available_indices_.push(frame_nr_prev_blocks + j);
          }
        }
      }
    }

    explicit impl(asio::any_io_executor &ex, socket_type &socket,
                  std::span<uint8_t> ring_buf, std::size_t frame_size,
                  std::size_t block_size, std::span<uint8_t> ether_hdr)
        requires std::same_as<LinkType, raw_l2_tag>
        : strand_(ex),
          notifier_(strand_),
          pending_indices_(strand_),
          sk_(socket),
          sent_buffer_(nullptr, 0),
          ether_hdr_(ether_hdr)
    {
      InitFrames(ring_buf, frame_size, block_size);
    }

    explicit impl(asio::any_io_executor &ex, socket_type &socket,
                  std::span<uint8_t> ring_buf, std::size_t frame_size,
                  std::size_t block_size, endpoint_type &&endpoint) requires
        std::same_as<LinkType, dgram_l3_tag> : strand_(ex),
                                               notifier_(strand_),
                                               pending_indices_(strand_),
                                               sk_(socket),
                                               sent_buffer_(nullptr, 0),
                                               ep_(std::move(endpoint))
    {
      InitFrames(ring_buf, frame_size, block_size);
    }

    /* ctor end here */
  };

  std::shared_ptr<impl> pool_;

public:
  AFPacketTxRingAsync(asio::any_io_executor &ex, socket_type &socket,
                      std::span<uint8_t> ring_buf, std::size_t frame_size,
                      std::size_t block_size, std::span<uint8_t> ether_hdr)
      requires std::is_same_v<LinkType, raw_l2_tag>
      : pool_(std::make_shared<impl>(ex, socket, ring_buf, frame_size,
                                     block_size, ether_hdr))
  {
    static_assert(std::is_base_of_v<NetMemChunk, Value>,
                  "Value must derive from NetMemChunk");

    asio::co_spawn(ex, pool_->RecycleWorker(), asio::detached);
  }

  AFPacketTxRingAsync(asio::any_io_executor &ex, socket_type &socket,
                      std::span<uint8_t> ring_buf, std::size_t frame_size,
                      std::size_t block_size, endpoint_type &&endpoint)
      requires std::is_same_v<LinkType, dgram_l3_tag>
      : pool_(std::make_shared<impl>(ex, socket, ring_buf, frame_size,
                                     block_size, std::move(endpoint)))
  {
    static_assert(std::is_base_of_v<NetMemChunk, Value>,
                  "Value must derive from NetMemChunk");

    asio::co_spawn(ex, pool_->RecycleWorker(), asio::detached);
  }

  ~AFPacketTxRingAsync() { pool_->Shutdown(); }

  asio::awaitable<value_ptr>
  Allocate() noexcept
  {
    return pool_->Allocate();
  }
};

} // namesapce memmanager
} // namespace celaratcp
