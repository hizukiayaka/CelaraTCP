/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * SPDX-FileCopyrightText: Hsia-Jun(Randy) Li
 */

using namespace celaratcp;

int
testSimpleAllocPool()
{
  {
    memmanager::SimpleHeapAllocator<NetMemChunk> alloc(kIpv6HdrSize);

    recycle::shared_pool<NetMemChunk> pool(
        [&alloc]() { return alloc.Allocation(); });
    pool.reserve(2);

    auto packet = pool.allocate();

    {
      std::cout << "free " << pool.unused_resources() << std::endl;
      auto packet = pool.allocate();
      std::cout << "free " << pool.unused_resources() << std::endl;
    }
    pool.free_unused();
  }

  {
    memmanager::SimpleVectorAllocator<NetMemChunk> alloc(kIpv6HdrSize);

    recycle::shared_pool<NetMemChunk> pool(
        [&alloc]() { return alloc.Allocation(); });
    pool.reserve(2);

    auto packet = pool.allocate();

    {
      std::cout << "free " << pool.unused_resources() << std::endl;
      auto packet = pool.allocate();
      std::cout << "free " << pool.unused_resources() << std::endl;
    }
    pool.free_unused();
  }

  {
    std::vector<uint8_t> mems(2000);
    {
      auto alloc = memmanager::ManagedMemAllocator<NetMemChunk>::Create(
          mems.data(), mems.capacity(), kIpv6HdrSize, [&mems]() {
            mems.clear();
            mems.shrink_to_fit();
          });

      auto pool = std::make_shared<recycle::shared_pool<NetMemChunk> >(
          [&alloc]() { return alloc->Allocation(); });
      pool->reserve(20);

      auto packet = pool->allocate();
      std::cout << "container size is " << mems.size() << std::endl;
      {
        std::cout << "free " << pool->unused_resources() << std::endl;
        auto packet = pool->allocate();
        std::cout << "free " << pool->unused_resources() << std::endl;
        packet = pool->allocate();
        packet = pool->allocate();
      }
      std::cout << "packet location is " << packet->GetId() << std::endl;
      packet = pool->allocate();
      std::cout << "packet location is " << packet->GetId() << std::endl;
      pool->free_unused();

      try {
        pool->reserve(50);
      }
      catch (const std::bad_alloc &e) {
        std::cout << "can't allocate so many buffers: " << e.what()
                  << std::endl;
      }
      catch (...) {
        std::cout << "an unknown issue" << std::endl;
      }
    }

    std::cout << "clear mem, now container size is " << mems.size()
              << " capacity is " << mems.capacity() << std::endl;
  }

  return 0;
}

int
main(int argc, char *argv[])
{
  testSimpleAllocPool();

  return 0;
}
