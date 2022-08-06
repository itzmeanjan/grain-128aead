#pragma once
#include <cstddef>
#include <cstdint>
#include <utility>

// Grain-128 Authenticated Encryption with Associated Data
namespace grain_128 {

// Grain-128 AEAD state, which has two main parts
//
// i)  Pre-output Generator
//      a) 128 -bit LFSR
//      b) 128 -bit NFSR
// ii) Authentication Generator
//      a) 64 -bit Accumulator
//      b) 64 -bit Shift Register
struct state_t
{
  uint8_t lfsr[16]; // 128 -bit linear feedback shift register
  uint8_t nfsr[16]; // 128 -bit non-linear feedback shift register
  uint8_t acc[8];   // 64 -bit accumulator
  uint8_t sreg[8];  // 64 -bit shift register
};

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
  const uint8_t byte = arr[idx.first];
  const uint8_t bit = byte >> idx.second;

  return bit & 0b1;
}

// Boolean function `h(x)`, which takes 9 state variable bits & produces single
// bit, using formula
//
// h(x) = x0x1 + x2x3 + x4x5 + x6x7 + x0x4x8
//
// 2 of these input bits are from NFSR, while remaining 7 of them are from LFSR.
//
// Bits correspond to (x0, x1, ...x7, x8) -> (NFSR12, LFSR8, LFSR13, LFSR20,
// NFSR95, LFSR42, LFSR60, LFSR79, LFSR94)
//
// See definition of `h(x)` function in page 7 of Grain-128 AEAD specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/grain-128aead-spec-final.pdf
inline static uint8_t
h(const state_t* const st)
{
  const uint8_t x0 = select_bit(st->nfsr, compute_index(12));
  const uint8_t x1 = select_bit(st->lfsr, compute_index(8));
  const uint8_t x2 = select_bit(st->lfsr, compute_index(13));
  const uint8_t x3 = select_bit(st->lfsr, compute_index(20));
  const uint8_t x4 = select_bit(st->nfsr, compute_index(95));
  const uint8_t x5 = select_bit(st->lfsr, compute_index(42));
  const uint8_t x6 = select_bit(st->lfsr, compute_index(60));
  const uint8_t x7 = select_bit(st->lfsr, compute_index(79));
  const uint8_t x8 = select_bit(st->lfsr, compute_index(94));

  const uint8_t x0x1 = x0 & x1;
  const uint8_t x2x3 = x2 & x3;
  const uint8_t x4x5 = x4 & x5;
  const uint8_t x6x7 = x6 & x7;
  const uint8_t x0x4x8 = x0 & x4 & x8;

  const uint8_t hx = x0x1 ^ x2x3 ^ x4x5 ^ x6x7 ^ x0x4x8;
  return hx;
}

// Pre-output generator function, producing single output (key stream) bit,
// using formula
//
// yt = h(x) + st93 + ∑ j∈A (btj)
//
// A = {2, 15, 36, 45, 64, 73, 89}
//
// See definition in page 7 of Grain-128 AEAD specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/grain-128aead-spec-final.pdf
inline static uint8_t
ksb(const state_t* const st)
{
  const uint8_t hx = h(st);

  const uint8_t s93 = select_bit(st->lfsr, compute_index(93));

  const uint8_t b2 = select_bit(st->nfsr, compute_index(2));
  const uint8_t b15 = select_bit(st->nfsr, compute_index(15));
  const uint8_t b36 = select_bit(st->nfsr, compute_index(36));
  const uint8_t b45 = select_bit(st->nfsr, compute_index(45));
  const uint8_t b64 = select_bit(st->nfsr, compute_index(64));
  const uint8_t b73 = select_bit(st->nfsr, compute_index(73));
  const uint8_t b89 = select_bit(st->nfsr, compute_index(89));

  const uint8_t bt = b2 ^ b15 ^ b36 ^ b45 ^ b64 ^ b73 ^ b89;

  const uint8_t yt = hx ^ s93 ^ bt;
  return yt;
}

}
