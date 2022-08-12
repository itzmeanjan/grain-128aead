#pragma once
#include "grain_128.hpp"
#include <bit>
#include <cstring>

// Grain-128 Authenticated Encryption with Associated Data
namespace aead {

// DER encoding of associated data length, returning back how many bytes of
// useful data is present in preallocated memory (`der`), while encoding
// associated data length in `der`.
//
// Note that it must be ensured that `der` has a length of 9 -bytes.
//
// See section 2.6.1 of Grain-128 AEAD specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/grain-128aead-spec-final.pdf,
// for understanding how DER encoding works.
static size_t
encode_der(const size_t dlen, // associated data length | >= 0 && < 2^64
           uint8_t* const der // DER encoded length | assert len(der) == 9
)
{
  std::memset(der, 0, 9);

  if (dlen < 128) {
    der[0] = static_cast<uint8_t>(dlen);

    return 1ul;
  } else {
    const size_t bw = std::bit_width(dlen);
    const size_t fcbc = (bw >> 3) + 1ul * ((bw & 7ul) > 0ul);

    der[0] = static_cast<uint8_t>(0b10000000ul ^ fcbc);
    for (size_t i = 1; i <= fcbc; i++) {
      const size_t mask = 0xfful << ((fcbc - i) << 3);
      der[i] = static_cast<uint8_t>((dlen & mask) >> ((fcbc - i) << 3));
    }

    return fcbc + 1;
  }
}

// Given two 8 -bit unsigned integers, representing 16 key stream bits produced
// by Grain-128 AEAD stream cipher ( in consecutive cipher clock cycles ), this
// routine seperates out even and odd index bits
//
// Note, first -> [b7, b6, b5, b4, b3, b2, b1, b0]
//     second -> [b15, b14, b13, b12, b11, b10, b9, b8]
//
// Returned byte pair looks like (even_bits, odd_bits)
static const std::pair<uint8_t, uint8_t>
split_bits(const uint8_t first, const uint8_t second)
{
  uint8_t even = 0;
  uint8_t odd = 0;

  for (size_t i = 0; i < 4; i++) {
    const size_t sboff_e = i << 1;
    const size_t sboff_o = sboff_e ^ 1;

    const size_t dboff0 = i;
    const size_t dboff1 = i + 4ul;

    even |= ((first >> sboff_e) & 0b1) << dboff0;
    even |= ((second >> sboff_e) & 0b1) << dboff1;

    odd |= ((first >> sboff_o) & 0b1) << dboff0;
    odd |= ((second >> sboff_o) & 0b1) << dboff1;
  }

  return std::make_pair(even, odd);
}

// Initialize the internal state of pre-output generator and authenticator
// generator registers with 128 -bit key and 96 -bit nonce, by clocking the
// cipher (total) 512 times
//
// See section 2.2 of Grain-128 AEAD specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/grain-128aead-spec-final.pdf
static void
initialize(grain_128::state_t* const __restrict st, // Grain-128 AEAD state
           const uint8_t* const __restrict key,     // 128 -bit secret key
           const uint8_t* const __restrict nonce // 96 -bit public message nonce
)
{
  constexpr uint8_t lfsr32[]{ 0xff, 0xff, 0xff, 0x7f };

  std::memcpy(st->nfsr, key, 16);
  std::memcpy(st->lfsr, nonce, 12);
  std::memcpy(st->lfsr + 12, lfsr32, 4);

  for (size_t t = 0; t < 40; t++) {
    const uint8_t yt = grain_128::ksb8(st);

    const uint8_t s120 = grain_128::l8(st);
    const uint8_t b120 = grain_128::f8(st);

    grain_128::update_lfsr8(st, s120 ^ yt);
    grain_128::update_nfsr8(st, b120 ^ yt);
  }

  for (size_t t = 0; t < 8; t++) {
    const size_t ta = t + 8;
    const size_t tb = t;

    const uint8_t ka = key[ta];
    const uint8_t kb = key[tb];

    const uint8_t yt = grain_128::ksb8(st);

    const uint8_t s120 = grain_128::l8(st);
    const uint8_t b120 = grain_128::f8(st);

    grain_128::update_lfsr8(st, s120 ^ yt ^ ka);
    grain_128::update_nfsr8(st, b120 ^ yt ^ kb);
  }

  for (size_t t = 0; t < 8; t++) {
    const uint8_t yt = grain_128::ksb8(st);

    st->acc[t] = yt;

    const uint8_t s120 = grain_128::l8(st);
    const uint8_t b120 = grain_128::f8(st);

    grain_128::update_lfsr8(st, s120);
    grain_128::update_nfsr8(st, b120);
  }

  for (size_t t = 0; t < 8; t++) {
    const uint8_t yt = grain_128::ksb8(st);

    st->sreg[t] = yt;

    const uint8_t s120 = grain_128::l8(st);
    const uint8_t b120 = grain_128::f8(st);

    grain_128::update_lfsr8(st, s120);
    grain_128::update_nfsr8(st, b120);
  }
}

// Authenticates associated data ( a bit at a time ), following specification
// defined in section 2.3, 2.5 & 2.6.1 of Grain-128 AEAD
//
// Find document
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/grain-128aead-spec-final.pdf
static void
auth_associated_data(
  grain_128::state_t* const __restrict st, // Grain-128 AEAD state
  const uint8_t* const __restrict data,    // N -bytes associated data
  const size_t dlen                        // len(data) = N | >= 0
)
{
  // DER encode length of associated data

  uint8_t der[9]{};
  const size_t der_len = encode_der(dlen, der);
  const size_t der_blen = der_len << 3;

  // Authenticate DER encoded length of associated data

  for (size_t i = 0; i < der_blen; i++) {
    const auto idx = grain_128::compute_index(i);
    const uint8_t der_bit = grain_128::get_bit(der, idx);

    [[maybe_unused]] const uint8_t yt_e = grain_128::ksb(st); // even

    {
      const uint8_t s127 = grain_128::l(st);
      const uint8_t b127 = grain_128::f(st);

      grain_128::update_lfsr(st, s127);
      grain_128::update_nfsr(st, b127);
    }

    const uint8_t yt_o = grain_128::ksb(st); // odd

    {
      const uint8_t s127 = grain_128::l(st);
      const uint8_t b127 = grain_128::f(st);

      grain_128::update_lfsr(st, s127);
      grain_128::update_nfsr(st, b127);
    }

    grain_128::update_accumulator(st, der_bit);
    grain_128::update_register(st, yt_o);
  }

  // Authenticate associated data bits

  const size_t dblen = dlen << 3;

  for (size_t i = 0; i < dblen; i++) {
    const auto idx = grain_128::compute_index(i);
    const uint8_t d_bit = grain_128::get_bit(data, idx);

    [[maybe_unused]] const uint8_t yt_e = grain_128::ksb(st); // even

    {
      const uint8_t s127 = grain_128::l(st);
      const uint8_t b127 = grain_128::f(st);

      grain_128::update_lfsr(st, s127);
      grain_128::update_nfsr(st, b127);
    }

    const uint8_t yt_o = grain_128::ksb(st); // odd

    {
      const uint8_t s127 = grain_128::l(st);
      const uint8_t b127 = grain_128::f(st);

      grain_128::update_lfsr(st, s127);
      grain_128::update_nfsr(st, b127);
    }

    grain_128::update_accumulator(st, d_bit);
    grain_128::update_register(st, yt_o);
  }
}

// Encrypts and authenticates plain text ( a bit at a time ), following
// specification defined in section 2.3, 2.5 & 2.6.1 of Grain-128 AEAD
//
// Find document
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/grain-128aead-spec-final.pdf
static void
enc_and_auth_txt(grain_128::state_t* const __restrict st,
                 const uint8_t* const __restrict txt,
                 uint8_t* const __restrict enc,
                 const size_t ctlen)
{
  // Encrypt and authenticate plain text bits

  const size_t ctblen = ctlen << 3;

  for (size_t i = 0; i < ctblen; i++) {
    const auto idx = grain_128::compute_index(i);
    const uint8_t t_bit = grain_128::get_bit(txt, idx);

    const uint8_t yt_e = grain_128::ksb(st); // even

    {
      const uint8_t s127 = grain_128::l(st);
      const uint8_t b127 = grain_128::f(st);

      grain_128::update_lfsr(st, s127);
      grain_128::update_nfsr(st, b127);
    }

    const uint8_t c_bit = t_bit ^ yt_e;
    grain_128::set_bit(enc, c_bit, idx);

    const uint8_t yt_o = grain_128::ksb(st); // odd

    {
      const uint8_t s127 = grain_128::l(st);
      const uint8_t b127 = grain_128::f(st);

      grain_128::update_lfsr(st, s127);
      grain_128::update_nfsr(st, b127);
    }

    grain_128::update_accumulator(st, t_bit);
    grain_128::update_register(st, yt_o);
  }
}

// Decrypts cipher text and authenticates decrypted text ( a bit at a time ),
// following specification defined in section 2.3, 2.5 & 2.6.2 of Grain-128 AEAD
//
// Find document
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/grain-128aead-spec-final.pdf
static void
dec_and_auth_txt(grain_128::state_t* const __restrict st,
                 const uint8_t* const __restrict enc,
                 uint8_t* const __restrict txt,
                 const size_t ctlen)
{
  // Decrypt cipher text and authenticate encrypted text bits

  const size_t ctblen = ctlen << 3;

  for (size_t i = 0; i < ctblen; i++) {
    const auto idx = grain_128::compute_index(i);
    const uint8_t c_bit = grain_128::get_bit(enc, idx);

    const uint8_t yt_e = grain_128::ksb(st); // even

    {
      const uint8_t s127 = grain_128::l(st);
      const uint8_t b127 = grain_128::f(st);

      grain_128::update_lfsr(st, s127);
      grain_128::update_nfsr(st, b127);
    }

    const uint8_t t_bit = c_bit ^ yt_e;
    grain_128::set_bit(txt, t_bit, idx);

    const uint8_t yt_o = grain_128::ksb(st); // odd

    {
      const uint8_t s127 = grain_128::l(st);
      const uint8_t b127 = grain_128::f(st);

      grain_128::update_lfsr(st, s127);
      grain_128::update_nfsr(st, b127);
    }

    grain_128::update_accumulator(st, t_bit);
    grain_128::update_register(st, yt_o);
  }
}

// Authenticates padding of single bit ( set to 1 ), following specification
// defined in section 2.3 & 2.6 of Grain-128 AEAD
//
// Find document
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/grain-128aead-spec-final.pdf
static void
auth_padding_bit(grain_128::state_t* const st)
{
  // Authenticate padding bit
  constexpr uint8_t padding = 0b1;

  [[maybe_unused]] const uint8_t yt_e = grain_128::ksb(st); // even

  {
    const uint8_t s127 = grain_128::l(st);
    const uint8_t b127 = grain_128::f(st);

    grain_128::update_lfsr(st, s127);
    grain_128::update_nfsr(st, b127);
  }

  const uint8_t yt_o = grain_128::ksb(st); // odd

  {
    const uint8_t s127 = grain_128::l(st);
    const uint8_t b127 = grain_128::f(st);

    grain_128::update_lfsr(st, s127);
    grain_128::update_nfsr(st, b127);
  }

  grain_128::update_accumulator(st, padding);
  grain_128::update_register(st, yt_o);
}

}
