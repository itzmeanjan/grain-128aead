#pragma once
#include <cstddef>
#include <cstdint>
#include <utility>

// Grain-128 Authenticated Encryption with Associated Data
namespace grain_128 {

// Given a bit index in a bit array, this function computes byte index ( =
// selected byte ) & bit to pick up from the selected byte, when the bit
// array is represented as a byte array
//
// Note, all these bit & byte indices are zero based.
inline static constexpr std::pair<size_t, size_t>
compute_index(
  const size_t idx // bit index to be splitted into byte and bit offset
)
{
  const size_t off = idx >> 3;
  const size_t boff = idx & 7;

  return std::make_pair(off, boff);
}

// Given a byte array, a byte offset & a bit offset ( inside the byte, selected
// using byte offset argument ), this routine extracts out the bit and places it
// in least significant position of a 8 -bit unsigned integer, which is returned
// back from this function.
inline static constexpr uint8_t
select_bit(
  const uint8_t* const __restrict arr, // byte array to extract the bit from
  const std::pair<size_t, size_t> idx  // byte and bit offset, in order
)
{
  constexpr uint8_t one = 0b1;

  const uint8_t byte = arr[idx.first];
  const uint8_t bit = (byte >> idx.second) & one;

  return bit;
}

}
