#pragma once
#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
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

// Given a byte array and a starting bit index ( in that byte array ), this
// routine extracts out 8 consecutive bits ( all indexing starts from 0 )
// starting from provided bit index s.t. end index is calculated as (sidx + 7)
template<const size_t sidx>
inline static constexpr uint8_t
get_8bits(const uint8_t* const arr)
{
  constexpr size_t eidx = sidx + 7ul;

  constexpr auto sidx_ = std::make_pair(sidx >> 3, sidx & 7ul);
  constexpr auto eidx_ = std::make_pair(eidx >> 3, eidx & 7ul);

  const uint8_t lo = arr[sidx_.first] >> sidx_.second;
  const uint8_t hi = arr[eidx_.first] << (7ul - eidx_.second);

  const bool flg = static_cast<bool>(sidx & 7ul);
  const uint8_t bits = hi | (lo * flg);

  return bits;
}

// Given a word ( each word is 32 -bit wide ) array and a starting bit index (
// in that word array ), this routine extracts out 32 consecutive bits ( all
// indexing starts from 0 ) starting from provided bit index s.t. end index is
// calculated as (sidx + 31)
template<const size_t sidx>
inline static constexpr uint32_t
get_32bits(const uint32_t* const arr)
{
  constexpr size_t eidx = sidx + 31ul;

  constexpr auto sidx_ = std::make_pair(sidx >> 5, sidx & 31ul);
  constexpr auto eidx_ = std::make_pair(eidx >> 5, eidx & 31ul);

  const uint32_t lo = arr[sidx_.first] >> sidx_.second;
  const uint32_t hi = arr[eidx_.first] << (31ul - eidx_.second);

  const bool flg = static_cast<bool>(sidx & 31ul);
  const uint32_t bits = hi | (lo * flg);

  return bits;
}

// Compile-time check to ensure that only uint32_t or uint64_t can be converted
// to and/ or from byte array of length 4 and 8, respectively.
template<typename T>
inline static constexpr bool
check_type_bit_width()
{
  constexpr int blen = std::numeric_limits<T>::digits;
  return (blen == 32) || (blen == 64);
}

// Given a byte array of length 4/ 8, this routine interprets those bytes in
// little endian byte order, computing a 32/ 64 -bit unsigned integer
template<typename T>
inline static T
from_le_bytes(const uint8_t* const bytes) requires(check_type_bit_width<T>())
{
  constexpr size_t blen = static_cast<size_t>(std::numeric_limits<T>::digits);

  if constexpr (blen == 32ul) {
    return (static_cast<uint32_t>(bytes[3]) << 24) |
           (static_cast<uint32_t>(bytes[2]) << 16) |
           (static_cast<uint32_t>(bytes[1]) << 8) |
           (static_cast<uint32_t>(bytes[0]) << 0);
  } else if constexpr (blen == 64ul) {
    return (static_cast<uint64_t>(bytes[7]) << 56) |
           (static_cast<uint64_t>(bytes[6]) << 48) |
           (static_cast<uint64_t>(bytes[5]) << 40) |
           (static_cast<uint64_t>(bytes[4]) << 32) |
           (static_cast<uint64_t>(bytes[3]) << 24) |
           (static_cast<uint64_t>(bytes[2]) << 16) |
           (static_cast<uint64_t>(bytes[1]) << 8) |
           (static_cast<uint64_t>(bytes[0]) << 0);
  }
}

// Given a 32/ 64 -bit unsigned integer & a byte array of length 4/ 8, this
// routine interprets u32/ u64 in little endian byte order and places each of 4/
// 8 bytes in designated byte indices.
template<typename T>
inline static void
to_le_bytes(const T v, uint8_t* const bytes) requires(check_type_bit_width<T>())
{
  constexpr size_t blen = static_cast<size_t>(std::numeric_limits<T>::digits);
  static_assert((blen == 32) || (blen == 64), "Bit length of `T` ∈ {32, 64}");

  constexpr size_t bcnt = sizeof(T);

  for (size_t i = 0; i < bcnt; i++) {
    const size_t boff = i << 3;
    bytes[i] = static_cast<uint8_t>(v >> boff);
  }
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
  const uint8_t x0 = get_8bits<12ul>(st->nfsr);
  const uint8_t x1 = get_8bits<8ul>(st->lfsr);
  const uint8_t x2 = get_8bits<13ul>(st->lfsr);
  const uint8_t x3 = get_8bits<20ul>(st->lfsr);
  const uint8_t x4 = get_8bits<95ul>(st->nfsr);
  const uint8_t x5 = get_8bits<42ul>(st->lfsr);
  const uint8_t x6 = get_8bits<60ul>(st->lfsr);
  const uint8_t x7 = get_8bits<79ul>(st->lfsr);
  const uint8_t x8 = get_8bits<94ul>(st->lfsr);

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
  uint32_t nfsr[4]{};
  uint32_t lfsr[4]{};

  if constexpr (std::endian::native == std::endian::little) {
    std::memcpy(nfsr, st->nfsr, 16);
    std::memcpy(lfsr, st->lfsr, 16);
  } else {
    nfsr[0] = from_le_bytes<uint32_t>(st->nfsr + 0ul);
    nfsr[1] = from_le_bytes<uint32_t>(st->nfsr + 4ul);
    nfsr[2] = from_le_bytes<uint32_t>(st->nfsr + 8ul);
    nfsr[3] = from_le_bytes<uint32_t>(st->nfsr + 12ul);

    lfsr[0] = from_le_bytes<uint32_t>(st->lfsr + 0ul);
    lfsr[1] = from_le_bytes<uint32_t>(st->lfsr + 4ul);
    lfsr[2] = from_le_bytes<uint32_t>(st->lfsr + 8ul);
    lfsr[3] = from_le_bytes<uint32_t>(st->lfsr + 12ul);
  }

  const uint32_t x0 = get_32bits<12ul>(nfsr);
  const uint32_t x1 = get_32bits<8ul>(lfsr);
  const uint32_t x2 = get_32bits<13ul>(lfsr);
  const uint32_t x3 = get_32bits<20ul>(lfsr);
  const uint32_t x4 = get_32bits<95ul>(nfsr);
  const uint32_t x5 = get_32bits<42ul>(lfsr);
  const uint32_t x6 = get_32bits<60ul>(lfsr);
  const uint32_t x7 = get_32bits<79ul>(lfsr);
  const uint32_t x8 = get_32bits<94ul>(lfsr);

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

  const uint8_t s93 = get_8bits<93ul>(st->lfsr);

  const uint8_t b2 = get_8bits<2ul>(st->nfsr);
  const uint8_t b15 = get_8bits<15ul>(st->nfsr);
  const uint8_t b36 = get_8bits<36ul>(st->nfsr);
  const uint8_t b45 = get_8bits<45ul>(st->nfsr);
  const uint8_t b64 = get_8bits<64ul>(st->nfsr);
  const uint8_t b73 = get_8bits<73ul>(st->nfsr);
  const uint8_t b89 = get_8bits<89ul>(st->nfsr);

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
  uint32_t nfsr[4]{};
  uint32_t lfsr[4]{};

  if constexpr (std::endian::native == std::endian::little) {
    std::memcpy(nfsr, st->nfsr, 16);
    std::memcpy(lfsr, st->lfsr, 16);
  } else {
    nfsr[0] = from_le_bytes<uint32_t>(st->nfsr + 0ul);
    nfsr[1] = from_le_bytes<uint32_t>(st->nfsr + 4ul);
    nfsr[2] = from_le_bytes<uint32_t>(st->nfsr + 8ul);
    nfsr[3] = from_le_bytes<uint32_t>(st->nfsr + 12ul);

    lfsr[0] = from_le_bytes<uint32_t>(st->lfsr + 0ul);
    lfsr[1] = from_le_bytes<uint32_t>(st->lfsr + 4ul);
    lfsr[2] = from_le_bytes<uint32_t>(st->lfsr + 8ul);
    lfsr[3] = from_le_bytes<uint32_t>(st->lfsr + 12ul);
  }

  const uint32_t hx = hx32(st);

  const uint32_t s93 = get_32bits<93ul>(lfsr);

  const uint32_t b2 = get_32bits<2ul>(nfsr);
  const uint32_t b15 = get_32bits<15ul>(nfsr);
  const uint32_t b36 = get_32bits<36ul>(nfsr);
  const uint32_t b45 = get_32bits<45ul>(nfsr);
  const uint32_t b64 = get_32bits<64ul>(nfsr);
  const uint32_t b73 = get_32bits<73ul>(nfsr);
  const uint32_t b89 = get_32bits<89ul>(nfsr);

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
  const uint8_t s0 = get_8bits<0ul>(st->lfsr);
  const uint8_t s7 = get_8bits<7ul>(st->lfsr);
  const uint8_t s38 = get_8bits<38ul>(st->lfsr);
  const uint8_t s70 = get_8bits<70ul>(st->lfsr);
  const uint8_t s81 = get_8bits<81ul>(st->lfsr);
  const uint8_t s96 = get_8bits<96ul>(st->lfsr);

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
  uint32_t lfsr[4]{};

  if constexpr (std::endian::native == std::endian::little) {
    std::memcpy(lfsr, st->lfsr, 16);
  } else {
    lfsr[0] = from_le_bytes<uint32_t>(st->lfsr + 0ul);
    lfsr[1] = from_le_bytes<uint32_t>(st->lfsr + 4ul);
    lfsr[2] = from_le_bytes<uint32_t>(st->lfsr + 8ul);
    lfsr[3] = from_le_bytes<uint32_t>(st->lfsr + 12ul);
  }

  const uint32_t s0 = get_32bits<0ul>(lfsr);
  const uint32_t s7 = get_32bits<7ul>(lfsr);
  const uint32_t s38 = get_32bits<38ul>(lfsr);
  const uint32_t s70 = get_32bits<70ul>(lfsr);
  const uint32_t s81 = get_32bits<81ul>(lfsr);
  const uint32_t s96 = get_32bits<96ul>(lfsr);

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
  const uint8_t s0 = get_8bits<0ul>(st->lfsr);

  const uint8_t b0 = get_8bits<0ul>(st->nfsr);
  const uint8_t b26 = get_8bits<26ul>(st->nfsr);
  const uint8_t b56 = get_8bits<56ul>(st->nfsr);
  const uint8_t b91 = get_8bits<91ul>(st->nfsr);
  const uint8_t b96 = get_8bits<96ul>(st->nfsr);

  const uint8_t b3 = get_8bits<3ul>(st->nfsr);
  const uint8_t b67 = get_8bits<67ul>(st->nfsr);

  const uint8_t b11 = get_8bits<11ul>(st->nfsr);
  const uint8_t b13 = get_8bits<13ul>(st->nfsr);

  const uint8_t b17 = get_8bits<17ul>(st->nfsr);
  const uint8_t b18 = get_8bits<18ul>(st->nfsr);

  const uint8_t b27 = get_8bits<27ul>(st->nfsr);
  const uint8_t b59 = get_8bits<59ul>(st->nfsr);

  const uint8_t b40 = get_8bits<40ul>(st->nfsr);
  const uint8_t b48 = get_8bits<48ul>(st->nfsr);

  const uint8_t b61 = get_8bits<61ul>(st->nfsr);
  const uint8_t b65 = get_8bits<65ul>(st->nfsr);

  const uint8_t b68 = get_8bits<68ul>(st->nfsr);
  const uint8_t b84 = get_8bits<84ul>(st->nfsr);

  const uint8_t b22 = get_8bits<22ul>(st->nfsr);
  const uint8_t b24 = get_8bits<24ul>(st->nfsr);
  const uint8_t b25 = get_8bits<25ul>(st->nfsr);

  const uint8_t b70 = get_8bits<70ul>(st->nfsr);
  const uint8_t b78 = get_8bits<78ul>(st->nfsr);
  const uint8_t b82 = get_8bits<82ul>(st->nfsr);

  const uint8_t b88 = get_8bits<88ul>(st->nfsr);
  const uint8_t b92 = get_8bits<92ul>(st->nfsr);
  const uint8_t b93 = get_8bits<93ul>(st->nfsr);
  const uint8_t b95 = get_8bits<95ul>(st->nfsr);

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
  uint32_t nfsr[4]{};

  if constexpr (std::endian::native == std::endian::little) {
    std::memcpy(nfsr, st->nfsr, 16);
  } else {
    nfsr[0] = from_le_bytes<uint32_t>(st->nfsr + 0ul);
    nfsr[1] = from_le_bytes<uint32_t>(st->nfsr + 4ul);
    nfsr[2] = from_le_bytes<uint32_t>(st->nfsr + 8ul);
    nfsr[3] = from_le_bytes<uint32_t>(st->nfsr + 12ul);
  }

  const uint32_t s0 = from_le_bytes<uint32_t>(st->lfsr + 0ul);

  const uint32_t b0 = get_32bits<0ul>(nfsr);
  const uint32_t b26 = get_32bits<26ul>(nfsr);
  const uint32_t b56 = get_32bits<56ul>(nfsr);
  const uint32_t b91 = get_32bits<91ul>(nfsr);
  const uint32_t b96 = get_32bits<96ul>(nfsr);

  const uint32_t b3 = get_32bits<3ul>(nfsr);
  const uint32_t b67 = get_32bits<67ul>(nfsr);

  const uint32_t b11 = get_32bits<11ul>(nfsr);
  const uint32_t b13 = get_32bits<13ul>(nfsr);

  const uint32_t b17 = get_32bits<17ul>(nfsr);
  const uint32_t b18 = get_32bits<18ul>(nfsr);

  const uint32_t b27 = get_32bits<27ul>(nfsr);
  const uint32_t b59 = get_32bits<59ul>(nfsr);

  const uint32_t b40 = get_32bits<40ul>(nfsr);
  const uint32_t b48 = get_32bits<48ul>(nfsr);

  const uint32_t b61 = get_32bits<61ul>(nfsr);
  const uint32_t b65 = get_32bits<65ul>(nfsr);

  const uint32_t b68 = get_32bits<68ul>(nfsr);
  const uint32_t b84 = get_32bits<84ul>(nfsr);

  const uint32_t b22 = get_32bits<22ul>(nfsr);
  const uint32_t b24 = get_32bits<24ul>(nfsr);
  const uint32_t b25 = get_32bits<25ul>(nfsr);

  const uint32_t b70 = get_32bits<70ul>(nfsr);
  const uint32_t b78 = get_32bits<78ul>(nfsr);
  const uint32_t b82 = get_32bits<82ul>(nfsr);

  const uint32_t b88 = get_32bits<88ul>(nfsr);
  const uint32_t b92 = get_32bits<92ul>(nfsr);
  const uint32_t b93 = get_32bits<93ul>(nfsr);
  const uint32_t b95 = get_32bits<95ul>(nfsr);

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
updatex32(uint8_t* const reg,  // 128 -bit register to be updated
          const uint32_t bit96 // set bit [96..128) to this value
)
{
  for (size_t i = 0; i < 12; i++) {
    reg[i] = reg[i + 4];
  }

  if constexpr (std::endian::native == std::endian::little) {
    std::memcpy(reg + 12, &bit96, 4);
  } else {
    reg[12] = static_cast<uint8_t>(bit96 >> 0);
    reg[13] = static_cast<uint8_t>(bit96 >> 8);
    reg[14] = static_cast<uint8_t>(bit96 >> 16);
    reg[15] = static_cast<uint8_t>(bit96 >> 24);
  }
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
update_lfsrx32(state_t* const st, const uint32_t s96)
{
  updatex32(st->lfsr, s96);
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
update_nfsrx32(state_t* const st, const uint32_t b96)
{
  updatex32(st->nfsr, b96);
}

// Compile-time check that either 8 or 32 -bits are attempted to be
// encrypted/ authenticated at a time.
template<typename T>
inline static constexpr bool
check_auth_bit_width()
{
  constexpr int blen = std::numeric_limits<T>::digits;
  return (blen == 8) || (blen == 32);
}

// Updates Grain-128 AEAD accumulator & shift register, authenticating 8/ 32
// input message bits ( consuming into accumulator ), while also using
// equal-many authentication bits ( 8/ 32 consecutive odd bits produced by
// pre-output generator i.e. `ksb` ) following definition provided in
// section 2.3 of Grain-128 AEAD specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/grain-128aead-spec-final.pdf
template<typename T>
inline static void
authenticate(state_t* const st, // Grain-128 AEAD cipher state
             const T msg, // 8/ 32 input message bits ( to be authenticated )
             const T ksb  // 8/ 32 odd pre-output generator bits ( auth bits )
             ) requires(check_auth_bit_width<T>())
{
  uint64_t acc, sreg;

  if constexpr (std::endian::native == std::endian::little) {
    std::memcpy(&acc, st->acc, 8);
    std::memcpy(&sreg, st->sreg, 8);
  } else {
    acc = from_le_bytes<uint64_t>(st->acc);
    sreg = from_le_bytes<uint64_t>(st->sreg);
  }

  constexpr size_t blen = static_cast<size_t>(std::numeric_limits<T>::digits);

  for (size_t i = 0; i < blen; i++) {
    const bool m = static_cast<bool>((msg >> i) & 0b1);
    const uint8_t k = (ksb >> i) & 0b1;

    acc = acc ^ (m * sreg);
    sreg = (sreg >> 1) | (static_cast<uint64_t>(k) << 63);
  }

  if constexpr (std::endian::native == std::endian::little) {
    std::memcpy(st->acc, &acc, 8);
    std::memcpy(st->sreg, &sreg, 8);
  } else {
    to_le_bytes<uint64_t>(acc, st->acc);
    to_le_bytes<uint64_t>(sreg, st->sreg);
  }
}

}
