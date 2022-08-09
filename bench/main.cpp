#include "bench_grain_128aead.hpp"

// register Grain-128 AEAD for benchmarking
BENCHMARK(bench_grain_128aead::encrypt)->Args({ 32, 64 });
BENCHMARK(bench_grain_128aead::decrypt)->Args({ 32, 64 });
BENCHMARK(bench_grain_128aead::encrypt)->Args({ 32, 128 });
BENCHMARK(bench_grain_128aead::decrypt)->Args({ 32, 128 });
BENCHMARK(bench_grain_128aead::encrypt)->Args({ 32, 256 });
BENCHMARK(bench_grain_128aead::decrypt)->Args({ 32, 256 });
BENCHMARK(bench_grain_128aead::encrypt)->Args({ 32, 512 });
BENCHMARK(bench_grain_128aead::decrypt)->Args({ 32, 512 });
BENCHMARK(bench_grain_128aead::encrypt)->Args({ 32, 1024 });
BENCHMARK(bench_grain_128aead::decrypt)->Args({ 32, 1024 });
BENCHMARK(bench_grain_128aead::encrypt)->Args({ 32, 2048 });
BENCHMARK(bench_grain_128aead::decrypt)->Args({ 32, 2048 });
BENCHMARK(bench_grain_128aead::encrypt)->Args({ 32, 4096 });
BENCHMARK(bench_grain_128aead::decrypt)->Args({ 32, 4096 });

// benchmark runner main function
BENCHMARK_MAIN();
