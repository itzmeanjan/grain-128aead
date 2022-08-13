#pragma once
#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstring>
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

// Given a byte array and a starting bit index ( in that byte array ), this
// routine extracts out 8 consecutive bits ( all indexing starts from 0 )
// starting from provided bit index | end index is calculated as (sidx + 7)
inline static constexpr uint8_t
get_8bits(const uint8_t* const arr, const size_t sidx)
{
  const size_t eidx = sidx + 7ul;

  const auto sidx_ = compute_index(sidx);
  const auto eidx_ = compute_index(eidx);

  const uint8_t lo = arr[sidx_.first] >> sidx_.second;
  const uint8_t hi = arr[eidx_.first] << (7ul - eidx_.second);

  const bool flg = (sidx & 7ul) == 0ul;
  const uint8_t bits = hi | (lo * !flg);

  return bits;
}

// Given a byte array and a starting bit index ( in that byte array ), this
// routine extracts out 32 consecutive bits ( all indexing starts from 0 )
// starting from provided bit index | end index is calculated as (sidx + 31)
inline static constexpr uint32_t
get_32bits(const uint8_t* const arr, const size_t sidx)
{
  const size_t eidx = sidx + 31ul;

  const auto sidx_ = compute_index(sidx);
  const auto eidx_ = compute_index(eidx);

  const uint8_t lo = arr[sidx_.first] >> sidx_.second;
  const uint8_t hi = arr[eidx_.first] << (7ul - eidx_.second);

  const size_t mid_bytes = eidx_.first - sidx_.first + 1ul;

  const uint32_t lsb = static_cast<uint32_t>(lo);
  const uint32_t msb = static_cast<uint32_t>(hi) << (mid_bytes << 3);

  uint32_t mid = 0u;

  for (size_t i = 0; i < mid_bytes; i++) {
    const size_t off = sidx_.first + 1ul;
    const size_t boff = i << 3;

    mid |= static_cast<uint32_t>(arr[off + i]) << boff;
  }

  const uint32_t res = msb | (mid << (8ul - sidx_.second)) | lsb;
  return res;
}

// Boolean function `h(x)`, which takes 9 state variable bits ( for 8
// consecutive cipher clocks ) & produces single bit ( for 8 consecutive cipher
// clocks ), using formula
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
  const uint8_t x0 = get_8bits(st->nfsr, 12);
  const uint8_t x1 = get_8bits(st->lfsr, 8);
  const uint8_t x2 = get_8bits(st->lfsr, 13);
  const uint8_t x3 = get_8bits(st->lfsr, 20);
  const uint8_t x4 = get_8bits(st->nfsr, 95);
  const uint8_t x5 = get_8bits(st->lfsr, 42);
  const uint8_t x6 = get_8bits(st->lfsr, 60);
  const uint8_t x7 = get_8bits(st->lfsr, 79);
  const uint8_t x8 = get_8bits(st->lfsr, 94);

  const uint8_t x0x1 = x0 & x1;
  const uint8_t x2x3 = x2 & x3;
  const uint8_t x4x5 = x4 & x5;
  const uint8_t x6x7 = x6 & x7;
  const uint8_t x0x4x8 = x0 & x4 & x8;

  const uint8_t hx = x0x1 ^ x2x3 ^ x4x5 ^ x6x7 ^ x0x4x8;
  return hx;
}

// Boolean function `h(x)`, which takes 9 state variable bits ( for 32
// consecutive cipher clocks ) & produces single bit ( for 32 consecutive cipher
// clocks i.e. 32 bits are produced ), using formula
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
inline static uint32_t
hx32(const state_t* const st)
{
  const uint32_t x0 = get_32bits(st->nfsr, 12);
  const uint32_t x1 = get_32bits(st->lfsr, 8);
  const uint32_t x2 = get_32bits(st->lfsr, 13);
  const uint32_t x3 = get_32bits(st->lfsr, 20);
  const uint32_t x4 = get_32bits(st->nfsr, 95);
  const uint32_t x5 = get_32bits(st->lfsr, 42);
  const uint32_t x6 = get_32bits(st->lfsr, 60);
  const uint32_t x7 = get_32bits(st->lfsr, 79);
  const uint32_t x8 = get_32bits(st->lfsr, 94);

  const uint32_t x0x1 = x0 & x1;
  const uint32_t x2x3 = x2 & x3;
  const uint32_t x4x5 = x4 & x5;
  const uint32_t x6x7 = x6 & x7;
  const uint32_t x0x4x8 = x0 & x4 & x8;

  const uint32_t hx = x0x1 ^ x2x3 ^ x4x5 ^ x6x7 ^ x0x4x8;
  return hx;
}

// Pre-output generator function, producing eight output (key stream) bits,
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

  const uint8_t s93 = get_8bits(st->lfsr, 93);

  const uint8_t b2 = get_8bits(st->nfsr, 2);
  const uint8_t b15 = get_8bits(st->nfsr, 15);
  const uint8_t b36 = get_8bits(st->nfsr, 36);
  const uint8_t b45 = get_8bits(st->nfsr, 45);
  const uint8_t b64 = get_8bits(st->nfsr, 64);
  const uint8_t b73 = get_8bits(st->nfsr, 73);
  const uint8_t b89 = get_8bits(st->nfsr, 89);

  const uint8_t bt = b2 ^ b15 ^ b36 ^ b45 ^ b64 ^ b73 ^ b89;

  const uint8_t yt = hx ^ s93 ^ bt;
  return yt;
}

// Pre-output generator function, producing 32 output (key stream) bits ( i.e.
// invoking 32 consecutive rounds in parallel ), using formula
//
// yt = h(x) + st93 + ∑ j∈A (btj)
//
// A = {2, 15, 36, 45, 64, 73, 89}
//
// See definition in page 7 of Grain-128 AEAD specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/grain-128aead-spec-final.pdf
inline static uint32_t
ksbx32(const state_t* const st)
{
  const uint32_t hx = hx32(st);

  const uint32_t s93 = get_32bits(st->lfsr, 93);

  const uint32_t b2 = get_32bits(st->nfsr, 2);
  const uint32_t b15 = get_32bits(st->nfsr, 15);
  const uint32_t b36 = get_32bits(st->nfsr, 36);
  const uint32_t b45 = get_32bits(st->nfsr, 45);
  const uint32_t b64 = get_32bits(st->nfsr, 64);
  const uint32_t b73 = get_32bits(st->nfsr, 73);
  const uint32_t b89 = get_32bits(st->nfsr, 89);

  const uint32_t bt = b2 ^ b15 ^ b36 ^ b45 ^ b64 ^ b73 ^ b89;

  const uint32_t yt = hx ^ s93 ^ bt;
  return yt;
}

// L(St) --- update function of LFSR, computing 8 bits of LFSR ( starting from
// bit index 120 ), for next eight cipher clock rounds
//
// See definition in page 7 of Grain-128 AEAD specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/grain-128aead-spec-final.pdf
inline static uint8_t
l(const state_t* const st)
{
  const uint8_t s0 = get_8bits(st->lfsr, 0);
  const uint8_t s7 = get_8bits(st->lfsr, 7);
  const uint8_t s38 = get_8bits(st->lfsr, 38);
  const uint8_t s70 = get_8bits(st->lfsr, 70);
  const uint8_t s81 = get_8bits(st->lfsr, 81);
  const uint8_t s96 = get_8bits(st->lfsr, 96);

  const uint8_t res = s0 ^ s7 ^ s38 ^ s70 ^ s81 ^ s96;
  return res;
}

// L(St) --- update function of LFSR, computing 32 bits of LFSR ( starting from
// bit index 96 ), for next 32 cipher clock rounds, in parallel
//
// See definition in page 7 of Grain-128 AEAD specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/grain-128aead-spec-final.pdf
inline static uint32_t
lx32(const state_t* const st)
{
  const uint32_t s0 = get_32bits(st->lfsr, 0);
  const uint32_t s7 = get_32bits(st->lfsr, 7);
  const uint32_t s38 = get_32bits(st->lfsr, 38);
  const uint32_t s70 = get_32bits(st->lfsr, 70);
  const uint32_t s81 = get_32bits(st->lfsr, 81);
  const uint32_t s96 = get_32bits(st->lfsr, 96);

  const uint32_t res = s0 ^ s7 ^ s38 ^ s70 ^ s81 ^ s96;
  return res;
}

// s0 + F(Bt) --- update function of NFSR, computing 8 bits of NFSR ( starting
// from bit index 120 ), for next eight cipher clock rounds
//
// See definition in page 7 of Grain-128 AEAD specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/grain-128aead-spec-final.pdf
inline static uint8_t
f(const state_t* const st)
{
  const uint8_t s0 = get_8bits(st->lfsr, 0);

  const uint8_t b0 = get_8bits(st->nfsr, 0);
  const uint8_t b26 = get_8bits(st->nfsr, 26);
  const uint8_t b56 = get_8bits(st->nfsr, 56);
  const uint8_t b91 = get_8bits(st->nfsr, 91);
  const uint8_t b96 = get_8bits(st->nfsr, 96);

  const uint8_t b3 = get_8bits(st->nfsr, 3);
  const uint8_t b67 = get_8bits(st->nfsr, 67);

  const uint8_t b11 = get_8bits(st->nfsr, 11);
  const uint8_t b13 = get_8bits(st->nfsr, 13);

  const uint8_t b17 = get_8bits(st->nfsr, 17);
  const uint8_t b18 = get_8bits(st->nfsr, 18);

  const uint8_t b27 = get_8bits(st->nfsr, 27);
  const uint8_t b59 = get_8bits(st->nfsr, 59);

  const uint8_t b40 = get_8bits(st->nfsr, 40);
  const uint8_t b48 = get_8bits(st->nfsr, 48);

  const uint8_t b61 = get_8bits(st->nfsr, 61);
  const uint8_t b65 = get_8bits(st->nfsr, 65);

  const uint8_t b68 = get_8bits(st->nfsr, 68);
  const uint8_t b84 = get_8bits(st->nfsr, 84);

  const uint8_t b22 = get_8bits(st->nfsr, 22);
  const uint8_t b24 = get_8bits(st->nfsr, 24);
  const uint8_t b25 = get_8bits(st->nfsr, 25);

  const uint8_t b70 = get_8bits(st->nfsr, 70);
  const uint8_t b78 = get_8bits(st->nfsr, 78);
  const uint8_t b82 = get_8bits(st->nfsr, 82);

  const uint8_t b88 = get_8bits(st->nfsr, 88);
  const uint8_t b92 = get_8bits(st->nfsr, 92);
  const uint8_t b93 = get_8bits(st->nfsr, 93);
  const uint8_t b95 = get_8bits(st->nfsr, 95);

  const uint8_t t0 = b0 ^ b26 ^ b56 ^ b91 ^ b96;
  const uint8_t t1 = b3 & b67;
  const uint8_t t2 = b11 & b13;
  const uint8_t t3 = b17 & b18;
  const uint8_t t4 = b27 & b59;
  const uint8_t t5 = b40 & b48;
  const uint8_t t6 = b61 & b65;
  const uint8_t t7 = b68 & b84;
  const uint8_t t8 = b22 & b24 & b25;
  const uint8_t t9 = b70 & b78 & b82;
  const uint8_t t10 = b88 & b92 & b93 & b95;

  const uint8_t fbt = t0 ^ t1 ^ t2 ^ t3 ^ t4 ^ t5 ^ t6 ^ t7 ^ t8 ^ t9 ^ t10;
  const uint8_t res = s0 ^ fbt;
  return res;
}

// s0 + F(Bt) --- update function of NFSR, computing 32 bits of NFSR ( starting
// from bit index 96 ), for next 32 cipher clock rounds, in parallel
//
// See definition in page 7 of Grain-128 AEAD specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/grain-128aead-spec-final.pdf
inline static uint32_t
fx32(const state_t* const st)
{
  const uint32_t s0 = get_32bits(st->lfsr, 0);

  const uint32_t b0 = get_32bits(st->nfsr, 0);
  const uint32_t b26 = get_32bits(st->nfsr, 26);
  const uint32_t b56 = get_32bits(st->nfsr, 56);
  const uint32_t b91 = get_32bits(st->nfsr, 91);
  const uint32_t b96 = get_32bits(st->nfsr, 96);

  const uint32_t b3 = get_32bits(st->nfsr, 3);
  const uint32_t b67 = get_32bits(st->nfsr, 67);

  const uint32_t b11 = get_32bits(st->nfsr, 11);
  const uint32_t b13 = get_32bits(st->nfsr, 13);

  const uint32_t b17 = get_32bits(st->nfsr, 17);
  const uint32_t b18 = get_32bits(st->nfsr, 18);

  const uint32_t b27 = get_32bits(st->nfsr, 27);
  const uint32_t b59 = get_32bits(st->nfsr, 59);

  const uint32_t b40 = get_32bits(st->nfsr, 40);
  const uint32_t b48 = get_32bits(st->nfsr, 48);

  const uint32_t b61 = get_32bits(st->nfsr, 61);
  const uint32_t b65 = get_32bits(st->nfsr, 65);

  const uint32_t b68 = get_32bits(st->nfsr, 68);
  const uint32_t b84 = get_32bits(st->nfsr, 84);

  const uint32_t b22 = get_32bits(st->nfsr, 22);
  const uint32_t b24 = get_32bits(st->nfsr, 24);
  const uint32_t b25 = get_32bits(st->nfsr, 25);

  const uint32_t b70 = get_32bits(st->nfsr, 70);
  const uint32_t b78 = get_32bits(st->nfsr, 78);
  const uint32_t b82 = get_32bits(st->nfsr, 82);

  const uint32_t b88 = get_32bits(st->nfsr, 88);
  const uint32_t b92 = get_32bits(st->nfsr, 92);
  const uint32_t b93 = get_32bits(st->nfsr, 93);
  const uint32_t b95 = get_32bits(st->nfsr, 95);

  const uint32_t t0 = b0 ^ b26 ^ b56 ^ b91 ^ b96;
  const uint32_t t1 = b3 & b67;
  const uint32_t t2 = b11 & b13;
  const uint32_t t3 = b17 & b18;
  const uint32_t t4 = b27 & b59;
  const uint32_t t5 = b40 & b48;
  const uint32_t t6 = b61 & b65;
  const uint32_t t7 = b68 & b84;
  const uint32_t t8 = b22 & b24 & b25;
  const uint32_t t9 = b70 & b78 & b82;
  const uint32_t t10 = b88 & b92 & b93 & b95;

  const uint32_t fbt = t0 ^ t1 ^ t2 ^ t3 ^ t4 ^ t5 ^ t6 ^ t7 ^ t8 ^ t9 ^ t10;
  const uint32_t res = s0 ^ fbt;
  return res;
}

// Updates 128 -bit register by dropping bit [0..8) & setting new bit [120..128)
// ( which is provided by parameter `bit120` ), while shifting other bits
// leftwards ( i.e. MSB moving towards LSB ) | bit0 -> LSB and bit127 -> MSB
//
// This generic function can be used for updating both 128 -bit LFSR and NFSR,
// when executing 8 consecutive rounds of cipher clocks, in parallel
inline static void
update(uint8_t* const reg,  // 128 -bit register to be updated
       const uint8_t bit120 // set bit [120..128) to this value
)
{
  for (size_t i = 0; i < 15; i++) {
    reg[i] = reg[i + 1];
  }

  reg[15] = bit120;
}

// Updates 128 -bit register by dropping bit [0..32) & setting new bit [96..128)
// ( which is provided by parameter `bit96` ), while shifting other bits
// leftwards ( i.e. MSB moving towards LSB ) | bit0 -> LSB and bit127 -> MSB
//
// This generic function can be used for updating both 128 -bit LFSR and NFSR,
// when executing 32 consecutive rounds of cipher clocks, in parallel
inline static void
update(uint8_t* const reg,  // 128 -bit register to be updated
       const uint32_t bit96 // set bit [96..128) to this value
)
{
  for (size_t i = 0; i < 12; i++) {
    reg[i] = reg[i + 4];
  }

  reg[12] = static_cast<uint8_t>(bit96 >> 0);
  reg[13] = static_cast<uint8_t>(bit96 >> 8);
  reg[14] = static_cast<uint8_t>(bit96 >> 16);
  reg[15] = static_cast<uint8_t>(bit96 >> 24);
}

// Updates LFSR, by shifting 128 -bit register by 8 -bits leftwards ( when least
// significant bit lives on left side of the bit array i.e. bits [0..8) are
// dropped ), while placing `s120` as [120..128) -th bits of LFSR for next
// iteration
//
// Use this routine, when executing 8 consecutive stream cipher clocks, in
// parallel
inline static void
update_lfsr(state_t* const st, const uint8_t s120)
{
  update(st->lfsr, s120);
}

// Updates LFSR, by shifting 128 -bit register by 32 -bits leftwards ( when
// least significant bit lives on left side of the bit array i.e. bits [0..32)
// are dropped ), while placing `s96` as [96..128) -th bits of LFSR for next
// iteration
//
// Use this routine, when executing 32 consecutive stream cipher clocks, in
// parallel
inline static void
update_lfsr(state_t* const st, const uint32_t s96)
{
  update(st->lfsr, s96);
}

// Updates NFSR, by shifting 128 -bit register by 8 -bits leftwards ( when least
// significant bit lives on left side of the bit array i.e. bits [0..8) are
// dropped ), while placing `b120` as [120..128) -th bits of NFSR for next
// iteration
//
// Use this routine, when executing 8 consecutive stream cipher clocks, in
// parallel
inline static void
update_nfsr(state_t* const st, const uint8_t b120)
{
  update(st->nfsr, b120);
}

// Updates NFSR, by shifting 128 -bit register by 32 -bits leftwards ( when
// least significant bit lives on left side of the bit array i.e. bits [0..32)
// are dropped ), while placing `b96` as [96..128) -th bits of NFSR for next
// iteration
//
// Use this routine, when executing 32 consecutive stream cipher clocks, in
// parallel
inline static void
update_nfsr(state_t* const st, const uint32_t b96)
{
  update(st->nfsr, b96);
}

// Given a byte array of length 8, this routine interprets those bytes in little
// endian byte order, computing a 64 -bit unsigned integer
inline static uint64_t
from_le_bytes(const uint8_t* const bytes)
{
  return (static_cast<uint64_t>(bytes[7]) << 56) |
         (static_cast<uint64_t>(bytes[6]) << 48) |
         (static_cast<uint64_t>(bytes[5]) << 40) |
         (static_cast<uint64_t>(bytes[4]) << 32) |
         (static_cast<uint64_t>(bytes[3]) << 24) |
         (static_cast<uint64_t>(bytes[2]) << 16) |
         (static_cast<uint64_t>(bytes[1]) << 8) |
         (static_cast<uint64_t>(bytes[0]) << 0);
}

// Given a 64 -bit unsigned integer & a byte array of length 8, this routine
// interprets u64 in little endian byte order and places each of 8 bytes in
// designated byte indices.
inline static void
to_le_bytes(const uint64_t v, uint8_t* const bytes)
{
  for (size_t i = 0; i < 8; i++) {
    const size_t boff = i << 3;

    bytes[i] = static_cast<uint8_t>(v >> boff);
  }
}

// Updates Grain-128 AEAD accumulator & shift register, authenticating 8 input
// message bits ( consuming into accumulator ), while also using eight
// authentication bits ( eight consecutive odd bits produced by pre-output
// generator i.e. `ksb` ) following definition provided in section 2.3 of
// Grain-128 AEAD specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/grain-128aead-spec-final.pdf
inline static void
authenticated_byte(
  state_t* const st, // Grain-128 AEAD cipher state
  const uint8_t msg, // eight input message bits ( to be authenticated )
  const uint8_t ksb  // eight odd pre-output generator bits ( auth bits )
)
{
  constexpr uint64_t br[]{
    0b0000000000000000000000000000000000000000000000000000000000000000ul,
    0b1111111111111111111111111111111111111111111111111111111111111111ul
  };

  uint64_t acc0, sreg0;

  if constexpr (std::endian::native == std::endian::little) {
    std::memcpy(&acc0, st->acc, 8);
    std::memcpy(&sreg0, st->sreg, 8);
  } else {
    acc0 = from_le_bytes(st->acc);
    sreg0 = from_le_bytes(st->sreg);
  }

  const uint8_t m0 = (msg >> 0) & 0b1;
  const uint8_t k0 = (ksb >> 0) & 0b1;

  const uint64_t acc1 = acc0 ^ (br[m0] & sreg0);
  const uint64_t sreg1 = (sreg0 >> 1) | (static_cast<uint64_t>(k0) << 63);

  const uint8_t m1 = (msg >> 1) & 0b1;
  const uint8_t k1 = (ksb >> 1) & 0b1;

  const uint64_t acc2 = acc1 ^ (br[m1] & sreg1);
  const uint64_t sreg2 = (sreg1 >> 1) | (static_cast<uint64_t>(k1) << 63);

  const uint8_t m2 = (msg >> 2) & 0b1;
  const uint8_t k2 = (ksb >> 2) & 0b1;

  const uint64_t acc3 = acc2 ^ (br[m2] & sreg2);
  const uint64_t sreg3 = (sreg2 >> 1) | (static_cast<uint64_t>(k2) << 63);

  const uint8_t m3 = (msg >> 3) & 0b1;
  const uint8_t k3 = (ksb >> 3) & 0b1;

  const uint64_t acc4 = acc3 ^ (br[m3] & sreg3);
  const uint64_t sreg4 = (sreg3 >> 1) | (static_cast<uint64_t>(k3) << 63);

  const uint8_t m4 = (msg >> 4) & 0b1;
  const uint8_t k4 = (ksb >> 4) & 0b1;

  const uint64_t acc5 = acc4 ^ (br[m4] & sreg4);
  const uint64_t sreg5 = (sreg4 >> 1) | (static_cast<uint64_t>(k4) << 63);

  const uint8_t m5 = (msg >> 5) & 0b1;
  const uint8_t k5 = (ksb >> 5) & 0b1;

  const uint64_t acc6 = acc5 ^ (br[m5] & sreg5);
  const uint64_t sreg6 = (sreg5 >> 1) | (static_cast<uint64_t>(k5) << 63);

  const uint8_t m6 = (msg >> 6) & 0b1;
  const uint8_t k6 = (ksb >> 6) & 0b1;

  const uint64_t acc7 = acc6 ^ (br[m6] & sreg6);
  const uint64_t sreg7 = (sreg6 >> 1) | (static_cast<uint64_t>(k6) << 63);

  const uint8_t m7 = (msg >> 7) & 0b1;
  const uint8_t k7 = (ksb >> 7) & 0b1;

  const uint64_t acc8 = acc7 ^ (br[m7] & sreg7);
  const uint64_t sreg8 = (sreg7 >> 1) | (static_cast<uint64_t>(k7) << 63);

  if constexpr (std::endian::native == std::endian::little) {
    std::memcpy(st->acc, &acc8, 8);
    std::memcpy(st->sreg, &sreg8, 8);
  } else {
    to_le_bytes(acc8, st->acc);
    to_le_bytes(sreg8, st->sreg);
  }
}

}
