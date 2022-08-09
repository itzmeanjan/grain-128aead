#include "grain_128aead.hpp"

// Thin C wrapper on top of underlying C++ implementation of Grain-128
// authenticated encryption with associated data, which can be used for
// producing shared library object with conformant C-ABI & used from other
// languages such as Rust, Python

// Function prototype
extern "C"
{
  void grain_128aead_encrypt(
    const uint8_t* const __restrict, // 128 -bit secret key
    const uint8_t* const __restrict, // 96 -bit nonce
    const uint8_t* const __restrict, // N -bytes associated data
    const size_t, // byte length of associated data = N | >= 0
    const uint8_t* const __restrict, // M -bytes plain text
    uint8_t* const __restrict,       // M -bytes encrypted text
    const size_t,             // byte length of plain/ encrypted text = M | >= 0
    uint8_t* const __restrict // 64 -bit authentication tag
  );

  bool grain_128aead_decrypt(
    const uint8_t* const __restrict, // 128 -bit secret key
    const uint8_t* const __restrict, // 96 -bit nonce
    const uint8_t* const __restrict, // 64 -bit authentication tag
    const uint8_t* const __restrict, // N -bytes associated data
    const size_t, // byte length of associated data = N | >= 0
    const uint8_t* const __restrict, // M -bytes encrypted text
    uint8_t* const __restrict,       // M -bytes decrypted text
    const size_t // byte length of encrypted/ decrypted text = M | >= 0
  );
}

// Function implementation
extern "C"
{
  void grain_128aead_encrypt(
    const uint8_t* const __restrict key,   // 128 -bit secret key
    const uint8_t* const __restrict nonce, // 96 -bit nonce
    const uint8_t* const __restrict data,  // N -bytes associated data
    const size_t dlen, // byte length of associated data = N | >= 0
    const uint8_t* const __restrict txt, // M -bytes plain text
    uint8_t* const __restrict enc,       // M -bytes encrypted text
    const size_t ctlen, // byte length of plain/ encrypted text = M | >= 0
    uint8_t* const __restrict tag // 64 -bit authentication tag
  )
  {
    grain_128aead::encrypt(key, nonce, data, dlen, txt, enc, ctlen, tag);
  }

  bool grain_128aead_decrypt(
    const uint8_t* const __restrict key,   // 128 -bit secret key
    const uint8_t* const __restrict nonce, // 96 -bit nonce
    const uint8_t* const __restrict tag,   // 64 -bit authentication tag
    const uint8_t* const __restrict data,  // N -bytes associated data
    const size_t dlen, // byte length of associated data = N | >= 0
    const uint8_t* const __restrict enc, // M -bytes encrypted text
    uint8_t* const __restrict txt,       // M -bytes decrypted text
    const size_t ctlen // byte length of encrypted/ decrypted text = M | >= 0
  )
  {
    using namespace grain_128aead;
    return decrypt(key, nonce, tag, data, dlen, enc, txt, ctlen);
  }
}
