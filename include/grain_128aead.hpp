#pragma once
#include "aead.hpp"

// Grain-128 Authenticated Encryption with Associated Data
namespace grain_128aead {

// Given 16 -bytes secret key, 12 -bytes public message nonce, N -bytes
// associated data & M -bytes plain text, this routine encrypts M -bytes plain
// text to equal length cipher text, while also authenticating both associated
// data & plain text bytes, using Grain-128 AEAD algorithm ( defined in
// algorithm 1 of Grain-128 AEAD specification )
//
// It also computes 8 -bytes authentication tag, which works like Message
// Authentication Code, for both associated data & plain text.
//
// Note, associated data is never encrypted.
//
// Avoid using same nonce more than once, under same secret key.
//
// Find specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/grain-128aead-spec-final.pdf
static void
encrypt(const uint8_t* const __restrict key,   // 128 -bit secret key
        const uint8_t* const __restrict nonce, // 96 -bit public message nonce
        const uint8_t* const __restrict data,  // N -bytes associated data
        const size_t dlen,                     // len(data) = N | >= 0
        const uint8_t* const __restrict txt,   // M -bytes plain text
        uint8_t* const __restrict enc,         // M -bytes encrypted text
        const size_t ctlen,                    // len(txt) = len(enc) = M | >= 0
        uint8_t* const __restrict tag          // 64 -bit authentication tag
)
{
  grain_128::state_t st;

  aead::initialize(&st, key, nonce);
  aead::auth_associated_data(&st, data, dlen);
  aead::enc_and_auth_txt(&st, txt, enc, ctlen);
  aead::auth_padding_bit(&st);

  std::memcpy(tag, st.acc, 8);
}

}
