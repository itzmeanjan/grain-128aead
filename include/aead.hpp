#pragma once
#include "grain_128.hpp"
#include <array>
#include <bit>
#include <cmath>
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

  for (size_t t = 0; t < 320; t++) {
    const uint8_t yt = grain_128::ksb(st);

    const uint8_t s127 = grain_128::l(st);
    const uint8_t b127 = grain_128::f(st);

    grain_128::update_lfsr(st, s127 ^ yt);
    grain_128::update_nfsr(st, b127 ^ yt);
  }

  for (size_t t = 0; t < 64; t++) {
    const size_t ta = t + 64;
    const size_t tb = t;

    const uint8_t ka = grain_128::get_bit(key, grain_128::compute_index(ta));
    const uint8_t kb = grain_128::get_bit(key, grain_128::compute_index(tb));

    const uint8_t yt = grain_128::ksb(st);

    const uint8_t s127 = grain_128::l(st);
    const uint8_t b127 = grain_128::f(st);

    grain_128::update_lfsr(st, s127 ^ yt ^ ka);
    grain_128::update_nfsr(st, b127 ^ yt ^ kb);
  }

  for (size_t t = 0; t < 64; t++) {
    const uint8_t yt = grain_128::ksb(st);

    grain_128::set_bit(st->acc, yt, grain_128::compute_index(t));

    const uint8_t s127 = grain_128::l(st);
    const uint8_t b127 = grain_128::f(st);

    grain_128::update_lfsr(st, s127);
    grain_128::update_nfsr(st, b127);
  }

  for (size_t t = 0; t < 64; t++) {
    const uint8_t yt = grain_128::ksb(st);

    grain_128::set_bit(st->sreg, yt, grain_128::compute_index(t));

    const uint8_t s127 = grain_128::l(st);
    const uint8_t b127 = grain_128::f(st);

    grain_128::update_lfsr(st, s127);
    grain_128::update_nfsr(st, b127);
  }
}

}
