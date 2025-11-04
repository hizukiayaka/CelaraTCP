/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * SPDX-FileCopyrightText: Hsia-Jun(Randy) Li
 */

namespace celaratcp {
namespace netio {

class PacketSocketLinuxImpl::PacketSocketLinuxTxAllocator
{
private:
  struct FrameSlice
  {
    uint32_t idx;
    uint8_t *base;
    tpacket3_hdr *hdr;

    enum class State
    {
      Available,
      InUse,
      Released,
      PendingSend
    } state;

    uint_fast16_t used_bytes;

    FrameSlice(uint32_t i, uint8_t *b, std::size_t frame_size)
        : idx(i), base(b), hdr(reinterpret_cast<tpacket3_hdr *>(b)),
          state(State::Available), used_bytes(0)
    {
      resetHeader(frame_size);
    }

    void
    resetHeader(std::size_t frame_size)
    {
      hdr->tp_status = TP_STATUS_AVAILABLE;
      hdr->tp_len = 0;
      hdr->tp_snaplen = 0;
      hdr->tp_mac = sizeof(tpacket3_hdr);
      hdr->tp_net = hdr->tp_mac + ETH_HLEN;
      used_bytes = 0;
      // Payload region is (frame_size - sizeof(tpacket3_hdr))
      (void)frame_size;
    }

    uint8_t *
    payload()
    {
      return base + hdr->tp_net;
    }

    std::size_t
    payloadSize(std::size_t frame_size) const
    {
      return frame_size - hdr->tp_net;
    }
  };

  uint8_t *base_;
  const int fd_;
  const std::size_t frame_size_;
  const std::size_t total_frames_num_;
  std::mutex mtx_;

  std::vector<FrameSlice> frames_;
  std::priority_queue<uint32_t, std::vector<uint32_t>, std::greater<uint32_t>>
      avail_queue_; // Min-heap for lower-index allocation
  std::deque<uint32_t> alloc_order_;      // allocation order (FIFO)
  std::unordered_set<uint32_t> released_; // frames released by user
  std::vector<uint32_t> pending_send_;    // frames handed to kernel

  struct sockaddr_ll peer_addr_;

  void
  release(uint32_t frame_idx, uint_fast16_t used)
  {
    auto &fs = frames_[frame_idx];

    if (used == 0) {
      fs.resetHeader(frame_size_);
      fs.state = FrameSlice::State::Available;
      avail_queue_.push(frame_idx);
      return;
    }

    fs.hdr->tp_len = ETH_HLEN + used;
    fs.hdr->tp_snaplen = ETH_HLEN + used;
    fs.used_bytes = used;
    fs.state = FrameSlice::State::Released;
    released_.insert(frame_idx);
  }

public:
  /**
   * Only support tp_frame_size is a divisor of tp_block_size, which
   * means frames will be contiguously spaced by tp_frame_size bytes,
   * no gap between the frames.
   */
  PacketSocketLinuxTxAllocator(int fd, void *mmap_base, std::size_t frame_size,
                               std::size_t frame_nr)
      : base_(static_cast<uint8_t *>(mmap_base)), fd_(fd),
        frame_size_(frame_size), total_frames_num_(frame_nr)
  {
    frames_.reserve(frame_nr);
    for (uint32_t i = 0; i < frame_nr; ++i) {
      frames_.emplace_back(i, base_ + i * frame_size_, frame_size_);
      avail_queue_.push(i);
    }
  }

  void
  SetPeerMacAddress(std::span<uint8_t> mac_addr, int ifindex)
  {
    peer_addr_.sll_family = PF_PACKET;
    peer_addr_.sll_protocol = htons(ETH_P_IP);
    peer_addr_.sll_ifindex = ifindex;

    auto hw_addr_size = std::size(mac_addr);
    std::memcpy(&(peer_addr_.sll_addr), std::data(mac_addr), hw_addr_size);
    peer_addr_.sll_halen = hw_addr_size;
  }

  std::shared_ptr<NetMemChunk>
  allocate()
  {
    std::lock_guard<std::mutex> lock(mtx_);

    if (avail_queue_.empty())
      return {};

    uint32_t idx = avail_queue_.top();
    avail_queue_.pop();

    auto &fs = frames_[idx];
    fs.state = FrameSlice::State::InUse;

    alloc_order_.push_back(idx);

    uint8_t *payload = fs.payload();
    std::size_t payload_size = fs.payloadSize(frame_size_);

    auto deleter = [this, idx](NetMemChunk *p) {
      {
        std::lock_guard<std::mutex> lock(this->mtx_);
        this->release(idx, p->GetUsedBytes());
      }
      delete p;
    };

    return std::shared_ptr<NetMemChunk>(new NetMemChunk(payload, payload_size),
                                        deleter);
  }

  void
  flush()
  {
    std::lock_guard<std::mutex> lock(mtx_);

    // Promote in FIFO order only if released
    while (!alloc_order_.empty()) {
      uint32_t idx = alloc_order_.front();
      auto &fs = frames_[idx];
      if (fs.state != FrameSlice::State::Released)
        break;

      // Ready to send this frame
      alloc_order_.pop_front();
      released_.erase(idx);

      fs.hdr->tp_len = fs.used_bytes;
      fs.hdr->tp_snaplen = fs.used_bytes;
      fs.hdr->tp_status = TP_STATUS_SEND_REQUEST;
      fs.state = FrameSlice::State::PendingSend;
      pending_send_.push_back(idx);
    }

    if (pending_send_.empty())
      return;

    // Trigger kernel; loop until no immediate progress
    ::sendto(fd_, nullptr, 0, 0,
             reinterpret_cast<const struct sockaddr *>(&peer_addr_),
             sizeof(peer_addr_));

    // Recycle frames whose status flipped to AVAILABLE
    auto it = pending_send_.begin();
    while (it != pending_send_.end()) {
      auto &fs = frames_[*it];
      if (fs.hdr->tp_status == TP_STATUS_AVAILABLE) {
        fs.resetHeader(frame_size_);
        fs.state = FrameSlice::State::Available;
        avail_queue_.push(fs.idx);
        it = pending_send_.erase(it);
      } else {
        ++it;
      }
    }
  }
};

PacketSocketLinuxImpl::PacketSocketLinuxImpl(asio::any_io_executor &ex,
                                             int ifindex,
                                             std::span<uint8_t> mac_addr)
    : fd_(socket(PF_PACKET, SOCK_DGRAM, 0)), sd_(ex, fd_), ifindex_(ifindex),
      local_mac_addr_{}, peer_addr_{}, mmap_vaddr_(MAP_FAILED)
{
  std::ranges::copy(mac_addr, local_mac_addr_.begin());
}

bool
PacketSocketLinuxImpl::BindNetworkDevice()
{
  std::lock_guard<std::mutex> lock(mutex_);

  struct sockaddr_ll link_addr{};

  link_addr.sll_family = PF_PACKET;
  /**
   * The protocol can optionally be 0 in case we only want to transmit
   * via this socket, which avoids an expensive call to packet_rcv().
   * In this case, you also need to bind(2) the TX_RING
   * with sll_protocol = 0 set.
   */
  link_addr.sll_protocol = 0;
  link_addr.sll_ifindex = ifindex_;

  auto hw_addr_size = std::size(local_mac_addr_);
  std::memcpy(&(link_addr.sll_addr), std::data(local_mac_addr_), hw_addr_size);
  link_addr.sll_halen = hw_addr_size;

  if (bind(fd_, reinterpret_cast<struct sockaddr *>(&link_addr),
           sizeof(link_addr)))
  {
    return false;
  }

  return true;
}

bool
PacketSocketLinuxImpl::SetPeerMacAddress(std::span<uint8_t> mac_addr)
{
  std::lock_guard<std::mutex> lock(mutex_);

  peer_addr_.sll_family = PF_PACKET;
  peer_addr_.sll_protocol = htons(ETH_P_IP);
  peer_addr_.sll_ifindex = ifindex_;

  auto hw_addr_size = std::size(mac_addr);
  std::memcpy(&(peer_addr_.sll_addr), std::data(mac_addr), hw_addr_size);
  peer_addr_.sll_halen = hw_addr_size;

  /**
   * From man packet(7):
   * If an address is passed using sendto(2) or sendmsg(2), then
   * that overrides the socket default.
   * So I am not going to use this.
   */
  return true;
}

bool
PacketSocketLinuxImpl::SetTxRingBuf(struct tpacket_req3 *req)
{
  std::lock_guard<std::mutex> lock(mutex_);

  int v = TPACKET_V3;
  auto err = setsockopt(fd_, SOL_PACKET, PACKET_VERSION, &v, sizeof(v));
  if (err)
    return false;

  err = setsockopt(fd_, SOL_PACKET, PACKET_TX_RING,
                   reinterpret_cast<void *>(req), sizeof(*req));
  if (err)
    return false;

  return true;
}

void
PacketSocketLinuxImpl::SetupMemMap()
{
  std::lock_guard<std::mutex> lock(mutex_);
  /**
   * To use one socket for capture and transmission, the mapping of
   * both the RX and TX buffer ring has to be done with one call to mmap.
   * RX must be the first as the kernel maps the TX ring memory right after
   * the RX one.
   */
  // FIXME: you need to map the right size
  std::size_t total_size = 0;
  mmap_vaddr_
      = mmap(nullptr, total_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd_, 0);

  if (MAP_FAILED == mmap_vaddr_)
    return;
}

PacketSocketLinuxImpl::~PacketSocketLinuxImpl()
{
  std::lock_guard<std::mutex> lock(mutex_);

  // FIXME: you need to map the right size
  std::size_t total_size = 0;

  if (MAP_FAILED != mmap_vaddr_) {
    auto err = munmap(reinterpret_cast<void *>(mmap_vaddr_), total_size);
  }
}

} // namespace netio
} // namespace celaratcp
