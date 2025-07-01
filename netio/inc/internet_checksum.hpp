/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * SPDX-FileCopyrightText: Hsia-Jun(Randy) Li
 */
#pragma once

#include <cstdint>
#include <iterator>
#include <type_traits>

template <typename Container>
uint_fast32_t
InternetSum(const Container &buffer)
{
  // Ensure the container holds elements of integral type
  static_assert(std::is_integral_v<typename Container::value_type>,
                "Container must hold integral elements");

  uint_fast32_t sum = 0; // Use uint32_t for the sum

  // Iterate over the container and process each element
  for (const auto &element : buffer) {
    // Break the element into 8-bit chunks and add them to the sum
    const uint8_t *bytes = reinterpret_cast<const uint8_t *>(&element);
    for (std::size_t i = 0; i < sizeof(element); ++i) {
      sum += bytes[i] << ((i % 2 == 0)
                              ? 8
                              : 0); // Alternate between high and low bytes
    }
  }

  return sum;
}

template <typename Container>
uint16_t
InternetChecksum(const Container &buffer, uint_fast32_t sum = 0)
{
  // Ensure the container holds elements of integral type
  static_assert(std::is_integral_v<typename Container::value_type>,
                "Container must hold integral elements");

  // Iterate over the container and process each element
  for (const auto &element : buffer) {
    // Break the element into 8-bit chunks and add them to the sum
    const uint8_t *bytes = reinterpret_cast<const uint8_t *>(&element);
    for (std::size_t i = 0; i < sizeof(element); ++i) {
      sum += bytes[i] << ((i % 2 == 0)
                              ? 8
                              : 0); // Alternate between high and low bytes
    }
  }

  // Perform the wrap-around at the end
  while (sum > 0xFFFF) {
    sum = (sum & 0xFFFF) + (sum >> 16);
  }

  return static_cast<uint16_t>(~sum);
}
