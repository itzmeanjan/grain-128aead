#pragma once
#include "grain_128.hpp"

#if defined __BMI2__
#include <immintrin.h>
#endif

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

// Given two 8/ 32 -bit unsigned integers, representing 16/ 64 key stream bits
// produced by Grain-128 AEAD stream cipher ( in consecutive cipher clock cycles
// ), this routine seperates out even and odd index bits
//
// first -> [b7, b6, b5, b4, b3, b2, b1, b0]
// second -> [b15, b14, b13, b12, b11, b10, b9, b8] | when template parameter T
// = uint8_t
//
// or
//
// first -> [b31, b30, ..., b1, b0]
// second -> [b63, b62, ..., b33, b32] | when template parameter T = uint32_t
//
// Returned byte pair looks like (even_{8, 32}_bits, odd_{8, 32}_bits)
template<typename T>
static const std::pair<T, T>
split_bits(const T first,
           const T second) requires(grain_128::check_auth_bit_width<T>())
{
  T even = 0;
  T odd = 0;

  constexpr int blen = std::numeric_limits<T>::digits;

#if defined __BMI2__

  if constexpr (blen == 32) {
    constexpr uint32_t mask_even = 0b01010101010101010101010101010101u;
    constexpr uint32_t mask_odd = mask_even << 1;

    const uint32_t f_even = _pext_u32(first, mask_even);
    const uint32_t f_odd = _pext_u32(first, mask_odd);

    const uint32_t s_even = _pext_u32(second, mask_even);
    const uint32_t s_odd = _pext_u32(second, mask_odd);

    even = (s_even << 16) | f_even;
    odd = (s_odd << 16) | f_odd;

  } else if constexpr (blen == 8) {
    constexpr uint32_t mask_even = 0b01010101u;
    constexpr uint32_t mask_odd = mask_even << 1;

    const uint32_t f_even = _pext_u32(static_cast<uint32_t>(first), mask_even);
    const uint32_t f_odd = _pext_u32(static_cast<uint32_t>(first), mask_odd);

    const uint32_t s_even = _pext_u32(static_cast<uint32_t>(second), mask_even);
    const uint32_t s_odd = _pext_u32(static_cast<uint32_t>(second), mask_odd);

    even = static_cast<T>((s_even << 4) | f_even);
    odd = static_cast<T>((s_odd << 4) | f_odd);
  }

#else

  constexpr size_t hblen = static_cast<size_t>(blen) >> 1;

  for (size_t i = 0; i < hblen; i++) {
    const size_t sboff_e = i << 1;
    const size_t sboff_o = sboff_e ^ 1;

    const size_t dboff0 = i;
    const size_t dboff1 = i + hblen;

    even |= ((first >> sboff_e) & 0b1) << dboff0;
    even |= ((second >> sboff_e) & 0b1) << dboff1;

    odd |= ((first >> sboff_o) & 0b1) << dboff0;
    odd |= ((second >> sboff_o) & 0b1) << dboff1;
  }

#endif

  return std::make_pair(even, odd);
}

// Initialize the internal state of pre-output generator and authenticator
// generator registers with 128 -bit key and 96 -bit nonce, by clocking the
// cipher (total) 512 times
//
// Note, 32 consecutive clocks are executed in parallel !
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

  for (size_t t = 0; t < 10; t++) {
    const uint32_t yt = grain_128::ksbx32(st);

    const uint32_t s96 = grain_128::lx32(st);
    const uint32_t b96 = grain_128::fx32(st);

    grain_128::update_lfsrx32(st, s96 ^ yt);
    grain_128::update_nfsrx32(st, b96 ^ yt);
  }

  for (size_t t = 0; t < 2; t++) {
    const size_t toff = t << 2;

    const size_t ta = toff + 8;
    const size_t tb = toff + 0;

    uint32_t ka, kb;

    if (std::endian::native == std::endian::little) {
      std::memcpy(&ka, key + ta, 4);
      std::memcpy(&kb, key + tb, 4);
    } else {
      ka = static_cast<uint32_t>(key[ta ^ 3] << 24) |
           static_cast<uint32_t>(key[ta ^ 2] << 16) |
           static_cast<uint32_t>(key[ta ^ 1] << 8) |
           static_cast<uint32_t>(key[ta ^ 0] << 0);
      kb = static_cast<uint32_t>(key[tb ^ 3] << 24) |
           static_cast<uint32_t>(key[tb ^ 2] << 16) |
           static_cast<uint32_t>(key[tb ^ 1] << 8) |
           static_cast<uint32_t>(key[tb ^ 0] << 0);
    }

    const uint32_t yt = grain_128::ksbx32(st);

    const uint32_t s96 = grain_128::lx32(st);
    const uint32_t b96 = grain_128::fx32(st);

    grain_128::update_lfsrx32(st, s96 ^ yt ^ ka);
    grain_128::update_nfsrx32(st, b96 ^ yt ^ kb);
  }

  for (size_t t = 0; t < 2; t++) {
    const uint32_t yt = grain_128::ksbx32(st);

    const size_t toff = t << 2;

    if constexpr (std::endian::native == std::endian::little) {
      std::memcpy(st->acc + toff, &yt, 4);
    } else {
      st->acc[toff ^ 0] = static_cast<uint8_t>(yt >> 0);
      st->acc[toff ^ 1] = static_cast<uint8_t>(yt >> 8);
      st->acc[toff ^ 2] = static_cast<uint8_t>(yt >> 16);
      st->acc[toff ^ 3] = static_cast<uint8_t>(yt >> 24);
    }

    const uint32_t s96 = grain_128::lx32(st);
    const uint32_t b96 = grain_128::fx32(st);

    grain_128::update_lfsrx32(st, s96);
    grain_128::update_nfsrx32(st, b96);
  }

  for (size_t t = 0; t < 2; t++) {
    const uint32_t yt = grain_128::ksbx32(st);

    const size_t toff = t << 2;

    if constexpr (std::endian::native == std::endian::little) {
      std::memcpy(st->sreg + toff, &yt, 4);
    } else {
      st->sreg[toff ^ 0] = static_cast<uint8_t>(yt >> 0);
      st->sreg[toff ^ 1] = static_cast<uint8_t>(yt >> 8);
      st->sreg[toff ^ 2] = static_cast<uint8_t>(yt >> 16);
      st->sreg[toff ^ 3] = static_cast<uint8_t>(yt >> 24);
    }

    const uint32_t s96 = grain_128::lx32(st);
    const uint32_t b96 = grain_128::fx32(st);

    grain_128::update_lfsrx32(st, s96);
    grain_128::update_nfsrx32(st, b96);
  }
}

// Authenticates associated data ( 8/ 32 bits at a time ), following
// specification defined in section 2.3, 2.5 & 2.6.1 of Grain-128 AEAD
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

  // Authenticate DER encoded length of associated data

  for (size_t i = 0; i < der_len; i++) {
    const uint8_t yt0 = grain_128::ksb(st);

    {
      const uint8_t s120 = grain_128::l(st);
      const uint8_t b120 = grain_128::f(st);

      grain_128::update_lfsr(st, s120);
      grain_128::update_nfsr(st, b120);
    }

    const uint8_t yt1 = grain_128::ksb(st);

    {
      const uint8_t s120 = grain_128::l(st);
      const uint8_t b120 = grain_128::f(st);

      grain_128::update_lfsr(st, s120);
      grain_128::update_nfsr(st, b120);
    }

    const auto splitted = split_bits<uint8_t>(yt0, yt1);
    grain_128::authenticate<uint8_t>(st, der[i], splitted.second);
  }

  // Authenticate associated data bits

  const size_t word_cnt = dlen >> 2;
  const size_t rm_bytes = dlen & 3ul;

  for (size_t i = 0; i < word_cnt; i++) {
    const size_t off = i << 2;

    const uint32_t yt0 = grain_128::ksbx32(st);

    {
      const uint32_t s96 = grain_128::lx32(st);
      const uint32_t b96 = grain_128::fx32(st);

      grain_128::update_lfsrx32(st, s96);
      grain_128::update_nfsrx32(st, b96);
    }

    const uint32_t yt1 = grain_128::ksbx32(st);

    {
      const uint32_t s96 = grain_128::lx32(st);
      const uint32_t b96 = grain_128::fx32(st);

      grain_128::update_lfsrx32(st, s96);
      grain_128::update_nfsrx32(st, b96);
    }

    uint32_t dataw = 0u;

    if constexpr (std::endian::native == std::endian::little) {
      std::memcpy(&dataw, data + off, 4);
    } else {
      dataw = static_cast<uint32_t>(data[off ^ 3] << 24) |
              static_cast<uint32_t>(data[off ^ 2] << 16) |
              static_cast<uint32_t>(data[off ^ 1] << 8) |
              static_cast<uint32_t>(data[off ^ 0] << 0);
    }

    const auto splitted = split_bits<uint32_t>(yt0, yt1);
    grain_128::authenticate<uint32_t>(st, dataw, splitted.second);
  }

  const size_t off = word_cnt << 2;

  for (size_t i = 0; i < rm_bytes; i++) {
    const uint8_t yt0 = grain_128::ksb(st);

    {
      const uint8_t s120 = grain_128::l(st);
      const uint8_t b120 = grain_128::f(st);

      grain_128::update_lfsr(st, s120);
      grain_128::update_nfsr(st, b120);
    }

    const uint8_t yt1 = grain_128::ksb(st);

    {
      const uint8_t s120 = grain_128::l(st);
      const uint8_t b120 = grain_128::f(st);

      grain_128::update_lfsr(st, s120);
      grain_128::update_nfsr(st, b120);
    }

    const auto splitted = split_bits<uint8_t>(yt0, yt1);
    grain_128::authenticate<uint8_t>(st, data[off + i], splitted.second);
  }
}

// Encrypts and authenticates plain text ( 8/ 32 bits at a time ), following
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

  const size_t word_cnt = ctlen >> 2;
  const size_t rm_bytes = ctlen & 3ul;

  for (size_t i = 0; i < word_cnt; i++) {
    const size_t off = i << 2;

    const uint32_t yt0 = grain_128::ksbx32(st);

    {
      const uint32_t s96 = grain_128::lx32(st);
      const uint32_t b96 = grain_128::fx32(st);

      grain_128::update_lfsrx32(st, s96);
      grain_128::update_nfsrx32(st, b96);
    }

    const uint32_t yt1 = grain_128::ksbx32(st);

    {
      const uint32_t s96 = grain_128::lx32(st);
      const uint32_t b96 = grain_128::fx32(st);

      grain_128::update_lfsrx32(st, s96);
      grain_128::update_nfsrx32(st, b96);
    }

    const auto splitted = split_bits<uint32_t>(yt0, yt1);

    uint32_t txtw = 0u;

    if constexpr (std::endian::native == std::endian::little) {
      std::memcpy(&txtw, txt + off, 4);
    } else {
      txtw = static_cast<uint32_t>(txt[off ^ 3] << 24) |
             static_cast<uint32_t>(txt[off ^ 2] << 16) |
             static_cast<uint32_t>(txt[off ^ 1] << 8) |
             static_cast<uint32_t>(txt[off ^ 0] << 0);
    }

    const uint32_t encw = txtw ^ splitted.first; // encrypt

    if constexpr (std::endian::native == std::endian::little) {
      std::memcpy(enc + off, &encw, 4);
    } else {
      enc[off ^ 0] = static_cast<uint8_t>(encw >> 0);
      enc[off ^ 1] = static_cast<uint8_t>(encw >> 8);
      enc[off ^ 2] = static_cast<uint8_t>(encw >> 16);
      enc[off ^ 3] = static_cast<uint8_t>(encw >> 24);
    }

    grain_128::authenticate<uint32_t>(st, txtw, splitted.second);
  }

  const size_t off = word_cnt << 2;

  for (size_t i = 0; i < rm_bytes; i++) {
    const uint8_t yt0 = grain_128::ksb(st);

    {
      const uint8_t s120 = grain_128::l(st);
      const uint8_t b120 = grain_128::f(st);

      grain_128::update_lfsr(st, s120);
      grain_128::update_nfsr(st, b120);
    }

    const uint8_t yt1 = grain_128::ksb(st);

    {
      const uint8_t s120 = grain_128::l(st);
      const uint8_t b120 = grain_128::f(st);

      grain_128::update_lfsr(st, s120);
      grain_128::update_nfsr(st, b120);
    }

    const auto splitted = split_bits<uint8_t>(yt0, yt1);

    enc[off + i] = txt[off + i] ^ splitted.first; // encrypt
    grain_128::authenticate<uint8_t>(st, txt[off + i], splitted.second);
  }
}

// Decrypts cipher text and authenticates decrypted text ( 8/ 32 bits at a time
// ), following specification defined in section 2.3, 2.5 & 2.6.2 of Grain-128
// AEAD
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

  const size_t word_cnt = ctlen >> 2;
  const size_t rm_bytes = ctlen & 3ul;

  for (size_t i = 0; i < word_cnt; i++) {
    const size_t off = i << 2;

    const uint32_t yt0 = grain_128::ksbx32(st);

    {
      const uint32_t s96 = grain_128::lx32(st);
      const uint32_t b96 = grain_128::fx32(st);

      grain_128::update_lfsrx32(st, s96);
      grain_128::update_nfsrx32(st, b96);
    }

    const uint32_t yt1 = grain_128::ksbx32(st);

    {
      const uint32_t s96 = grain_128::lx32(st);
      const uint32_t b96 = grain_128::fx32(st);

      grain_128::update_lfsrx32(st, s96);
      grain_128::update_nfsrx32(st, b96);
    }

    const auto splitted = split_bits<uint32_t>(yt0, yt1);

    uint32_t encw = 0u;

    if constexpr (std::endian::native == std::endian::little) {
      std::memcpy(&encw, enc + off, 4);
    } else {
      encw = static_cast<uint32_t>(enc[off ^ 3] << 24) |
             static_cast<uint32_t>(enc[off ^ 2] << 16) |
             static_cast<uint32_t>(enc[off ^ 1] << 8) |
             static_cast<uint32_t>(enc[off ^ 0] << 0);
    }

    const uint32_t txtw = encw ^ splitted.first; // decrypt

    if constexpr (std::endian::native == std::endian::little) {
      std::memcpy(txt + off, &txtw, 4);
    } else {
      txt[off ^ 0] = static_cast<uint8_t>(txtw >> 0);
      txt[off ^ 1] = static_cast<uint8_t>(txtw >> 8);
      txt[off ^ 2] = static_cast<uint8_t>(txtw >> 16);
      txt[off ^ 3] = static_cast<uint8_t>(txtw >> 24);
    }

    grain_128::authenticate<uint32_t>(st, txtw, splitted.second);
  }

  const size_t off = word_cnt << 2;

  for (size_t i = 0; i < rm_bytes; i++) {
    const uint8_t yt0 = grain_128::ksb(st);

    {
      const uint8_t s120 = grain_128::l(st);
      const uint8_t b120 = grain_128::f(st);

      grain_128::update_lfsr(st, s120);
      grain_128::update_nfsr(st, b120);
    }

    const uint8_t yt1 = grain_128::ksb(st);

    {
      const uint8_t s120 = grain_128::l(st);
      const uint8_t b120 = grain_128::f(st);

      grain_128::update_lfsr(st, s120);
      grain_128::update_nfsr(st, b120);
    }

    const auto splitted = split_bits<uint8_t>(yt0, yt1);

    txt[off + i] = enc[off + i] ^ splitted.first; // decrypt
    grain_128::authenticate<uint8_t>(st, txt[off + i], splitted.second);
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
  // Authenticate padding bit ( note 7 most significant bits are set to 0, so
  // their presence doesn't hurt )
  constexpr uint8_t padding = 0b00000001;

  const uint8_t yt0 = grain_128::ksb(st);

  {
    const uint8_t s120 = grain_128::l(st);
    const uint8_t b120 = grain_128::f(st);

    grain_128::update_lfsr(st, s120);
    grain_128::update_nfsr(st, b120);
  }

  const uint8_t yt1 = grain_128::ksb(st);

  {
    const uint8_t s120 = grain_128::l(st);
    const uint8_t b120 = grain_128::f(st);

    grain_128::update_lfsr(st, s120);
    grain_128::update_nfsr(st, b120);
  }

  const auto splitted = split_bits<uint8_t>(yt0, yt1);
  grain_128::authenticate<uint8_t>(st, padding, splitted.second);
}

}
