/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * SPDX-FileCopyrightText: Hsia-Jun(Randy) Li
 */
#pragma once

#include <cstddef>
#include <cstring>
#include <iterator>
#include <type_traits>

template <typename Container>
inline const uint8_t *
as_bytes_ptr(const Container &c)
{
  return reinterpret_cast<const uint8_t *>(std::data(c));
}

template <typename Container>
inline std::size_t
as_bytes_len(const Container &c)
{
  return std::size(c) * sizeof(typename Container::value_type);
}

template <typename Container>
uint_fast32_t
InternetSum(const Container &buffer)
{
  const uint8_t *p = as_bytes_ptr(buffer);
  std::size_t len = as_bytes_len(buffer);
  uint_fast32_t sum = 0;

  // Process all bytes as 16-bit network-order words
  for (std::size_t i = 0; i < len - 1; i += 2) {
    // This correctly builds a 16-bit word in network byte order
    sum += (static_cast<uint_fast32_t>(p[i]) << 8)
           | static_cast<uint_fast32_t>(p[i + 1]);
  }

  // Handle odd byte if present (pad with zero in low byte)
  if (len % 2) {
    sum += static_cast<uint_fast32_t>(p[len - 1]) << 8;
  }

  return sum;
}

template <typename Container>
uint16_t
InternetChecksum(const Container &buffer, uint_fast32_t sum = 0)
{
  static_assert(std::is_integral_v<typename Container::value_type>,
                "Container must hold integral elements");
  sum += InternetSum(buffer);

  // fold carries (unrolled for speed)
  sum = (sum & 0xFFFF) + (sum >> 16);
  sum = (sum & 0xFFFF) + (sum >> 16); // one more fold for rare cases

  return static_cast<uint16_t>(~sum);
}
