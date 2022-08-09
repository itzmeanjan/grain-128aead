#pragma once
#include "grain_128aead.hpp"
#include "utils.hpp"
#include <benchmark/benchmark.h>

// Benchmark Grain-128 AEAD
namespace bench_grain_128aead {

// Benchmarks Grain-128 AEAD encryption algorithm implementation, on CPU system,
// with variable length associated data & plain text ( which are randomly
// generated )
static void
encrypt(benchmark::State& state)
{
  constexpr size_t klen = 16;
  constexpr size_t nlen = 12;
  constexpr size_t tlen = 8;

  const size_t dlen = state.range(0);
  const size_t ctlen = state.range(1);

  uint8_t* key = static_cast<uint8_t*>(std::malloc(klen));
  uint8_t* nonce = static_cast<uint8_t*>(std::malloc(nlen));
  uint8_t* tag = static_cast<uint8_t*>(std::malloc(tlen));
  uint8_t* data = static_cast<uint8_t*>(std::malloc(dlen));
  uint8_t* txt = static_cast<uint8_t*>(std::malloc(ctlen));
  uint8_t* enc = static_cast<uint8_t*>(std::malloc(ctlen));
  uint8_t* dec = static_cast<uint8_t*>(std::malloc(ctlen));

  random_data(key, klen);
  random_data(nonce, nlen);
  random_data(data, dlen);
  random_data(txt, ctlen);

  std::memset(tag, 0, tlen);
  std::memset(enc, 0, ctlen);
  std::memset(dec, 0, ctlen);

  for (auto _ : state) {
    grain_128aead::encrypt(key, nonce, data, dlen, txt, enc, ctlen, tag);

    benchmark::DoNotOptimize(enc);
    benchmark::DoNotOptimize(tag);
    benchmark::ClobberMemory();
  }

  bool f = false;
  f = grain_128aead::decrypt(key, nonce, tag, data, dlen, enc, dec, ctlen);
  assert(f);

  for (size_t i = 0; i < ctlen; i++) {
    assert((txt[i] ^ dec[i]) == 0);
  }

  const size_t per_itr_data = dlen + ctlen;
  const size_t total_data = per_itr_data * state.iterations();

  state.SetBytesProcessed(static_cast<int64_t>(total_data));

  std::free(key);
  std::free(nonce);
  std::free(tag);
  std::free(data);
  std::free(txt);
  std::free(enc);
  std::free(dec);
}

// Benchmarks Grain-128 AEAD decryption algorithm implementation, on CPU system,
// with variable length associated data & plain/ cipher text ( which are
// randomly generated )
static void
decrypt(benchmark::State& state)
{
  constexpr size_t klen = 16;
  constexpr size_t nlen = 12;
  constexpr size_t tlen = 8;

  const size_t dlen = state.range(0);
  const size_t ctlen = state.range(1);

  uint8_t* key = static_cast<uint8_t*>(std::malloc(klen));
  uint8_t* nonce = static_cast<uint8_t*>(std::malloc(nlen));
  uint8_t* tag = static_cast<uint8_t*>(std::malloc(tlen));
  uint8_t* data = static_cast<uint8_t*>(std::malloc(dlen));
  uint8_t* txt = static_cast<uint8_t*>(std::malloc(ctlen));
  uint8_t* enc = static_cast<uint8_t*>(std::malloc(ctlen));
  uint8_t* dec = static_cast<uint8_t*>(std::malloc(ctlen));

  random_data(key, klen);
  random_data(nonce, nlen);
  random_data(data, dlen);
  random_data(txt, ctlen);

  std::memset(tag, 0, tlen);
  std::memset(enc, 0, ctlen);
  std::memset(dec, 0, ctlen);

  grain_128aead::encrypt(key, nonce, data, dlen, txt, enc, ctlen, tag);

  for (auto _ : state) {
    bool f = false;
    f = grain_128aead::decrypt(key, nonce, tag, data, dlen, enc, dec, ctlen);

    benchmark::DoNotOptimize(f);
    benchmark::DoNotOptimize(dec);
    benchmark::ClobberMemory();
  }

  for (size_t i = 0; i < ctlen; i++) {
    assert((txt[i] ^ dec[i]) == 0);
  }

  const size_t per_itr_data = dlen + ctlen;
  const size_t total_data = per_itr_data * state.iterations();

  state.SetBytesProcessed(static_cast<int64_t>(total_data));

  std::free(key);
  std::free(nonce);
  std::free(tag);
  std::free(data);
  std::free(txt);
  std::free(enc);
  std::free(dec);
}

}
