#pragma once
#include "grain_128.hpp"
#include <cstring>

// Grain-128 Authenticated Encryption with Associated Data
namespace aead {

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
