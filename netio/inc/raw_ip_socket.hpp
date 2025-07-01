/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * SPDX-FileCopyrightText: Hsia-Jun(Randy) Li
 */

#ifndef RAW_IP_SOCKET_HPP_
#define RAW_IP_SOCKET_HPP_

extern "C"
{
#include <netinet/in.h>
#include <sys/socket.h>
}

#include <asio/awaitable.hpp>
#include <asio/bind_executor.hpp>
#include <asio/generic/raw_protocol.hpp>
#include <asio/ip/address_v4.hpp>
#include <asio/ip/address_v6.hpp>
#include <asio/strand.hpp>
#include <asio/use_awaitable.hpp>

#include "net_packet.hpp"

namespace celaratcp {
namespace netio {

template <typename AddrType>
class RawIpSocket
{
protected:
  asio::generic::raw_protocol::socket socket_;
  asio::strand<asio::any_io_executor> strand_write_;

public:
  explicit RawIpSocket(asio::any_io_executor ex);

  template <typename ConstBufferSequence, typename Token>
  auto
  async_send(const ConstBufferSequence &buffers, Token &&token)
  {
    return this->socket_.async_send(
        buffers,
        asio::bind_executor(strand_write_, std::forward<Token>(token)));
  }
};

class RawIpv4Socket : public RawIpSocket<asio::ip::address_v4>
{
public:
  explicit RawIpv4Socket(asio::any_io_executor ex);
};

class Ipv6AncillaMeta
{
private:
  static constexpr std::size_t kMaxCmsg
      = CMSG_SPACE(sizeof(int)) +        // IPV6_HOPLIMIT
        CMSG_SPACE(sizeof(in6_pktinfo)); // IPV6_PKTINFO

  struct sockaddr_in6 dst_;
  struct iovec iov_;

  std::array<std::byte, kMaxCmsg> ctrls_buf_;

  struct msghdr msg_;

public:
  Ipv6AncillaMeta(const asio::ip::address_v6 &dst,
                  const asio::ip::address_v6 &src, uint_fast8_t next_proto,
                  uint_fast8_t ttl);

  void
  Reset()
  {
    std::fill(std::begin(ctrls_buf_), std::end(ctrls_buf_),
              static_cast<std::byte>(0));
    iov_.iov_base = nullptr;
    iov_.iov_len = 0;

    ::memset(&dst_, 0, sizeof(dst_));
    ::memset(&msg_, 0, sizeof(msg_));
  }

  template <typename T>
  bool
  SetPayload(std::span<const T> payload, std::size_t payload_size)
  {
    auto bytes = std::as_bytes(payload);
    iov_.iov_base
        = const_cast<void *>(static_cast<const void *>(std::data(bytes)));
    iov_.iov_len = std::min(std::size(bytes), payload_size);

    msg_.msg_iovlen = 1;
    return true;
  }

  struct msghdr *
  GetMsg() noexcept
  {
    return &msg_;
  };
};

template <typename T>
concept Ipv6MetaChunk = std::is_base_of_v<NetMemChunkMeta<Ipv6AncillaMeta>,
                                          std::remove_reference_t<T> >;

class RawIpv6Socket : private RawIpSocket<asio::ip::address_v6>
{
private:
  static constexpr int kMandatoryFlags = MSG_DONTWAIT;

  class initiate_async_send
  {
  public:
    using executor_type = asio::any_io_executor;

    explicit initiate_async_send(RawIpv6Socket *self) : self_(self) {}

    executor_type
    get_executor() const noexcept
    {
      return self_->strand_write_.get_inner_executor();
    }

    template <typename WriteHandler, Ipv6MetaChunk BufT>
    void
    operator()(WriteHandler &&handler, BufT &packet,
               asio::socket_base::message_flags flags) const
    {
      // Validate meta.
      auto *meta = packet.GetMeta();
      if (!meta) {
        asio::post(asio::bind_executor(
            self_->strand_write_,
            [h = std::forward<WriteHandler>(handler)]() mutable {
              h(std::make_error_code(std::errc::invalid_argument), 0);
            }));
        return;
      }

      auto used = packet.GetUsedBytes();
      if (used) {
        meta->SetPayload(packet.GetData(), used);
      }

      // Operation state.
      struct State : std::enable_shared_from_this<State>
      {
        RawIpv6Socket *self;
        Ipv6AncillaMeta *meta;
        int flags;
        WriteHandler handler;

        State(RawIpv6Socket *s, Ipv6AncillaMeta *m, int f, WriteHandler &&h)
            : self(s), meta(m), flags(f), handler(std::move(h))
        {
        }

        void
        start()
        {
          do_send();
        }

        void
        do_send()
        {
          ssize_t sent = ::sendmsg(self->socket_.native_handle(),
                                   meta->GetMsg(), flags);
          if (sent >= 0) {
            handler(std::error_code(), static_cast<std::size_t>(sent));
            return;
          }

          int err = errno;
          if (err == EINTR) {
            do_send();
            return;
          }

          if (err == EAGAIN || err == EWOULDBLOCK) {
            self->socket_.async_wait(
                asio::socket_base::wait_write,
                asio::bind_executor(
                    self->strand_write_,
                    [self_ref = this->shared_from_this()](std::error_code ec) {
                      if (ec) {
                        self_ref->handler(ec, 0);
                        return;
                      }
                      self_ref->do_send();
                    }));
            return;
          }

          handler(std::error_code(err, std::generic_category()), 0);
        }
      };

      auto op = std::make_shared<State>(self_, meta, flags,
                                        std::forward<WriteHandler>(handler));

      asio::post(asio::bind_executor(self_->strand_write_,
                                     [op]() mutable { op->start(); }));
    }

  private:
    RawIpv6Socket *self_;
  };

public:
  explicit RawIpv6Socket(asio::any_io_executor ex);

  template <Ipv6MetaChunk BufT, typename CompletionToken>
  auto
  async_send(BufT &packet, CompletionToken &&token)
  {
    using signature = void(std::error_code, std::size_t);
    return asio::async_initiate<CompletionToken, signature>(
        initiate_async_send{ this }, std::forward<CompletionToken>(token),
        std::ref(packet), kMandatoryFlags);
  }
};

} // namespace netio
} // namespace celaratcp

#endif
