# grain-128aead

Grain-128AEAD: A Lightweight AEAD Stream Cipher

## Motivation

Grain-128 AEAD is a lightweight AEAD ( authenticated encryption with associated data ) scheme, which is closely based on Grain-128a stream cipher, competing in final round of NIST Light Weight Cryptography ( LWC ) standardization effort. 

> See NIST LWC finalists [here](https://csrc.nist.gov/Projects/lightweight-cryptography/finalists)

Grain-128 AEAD offers only one authenticated encryption/ verified decryption with associated data algorithm, which has following interface

Routine | Input Interface | Output Interface
--- | --- | ---
`encrypt` | 16 -bytes secret key, 12 -bytes nonce, N -bytes associated data, M -bytes plain text | M -bytes cipher text, 8 -bytes authentication tag
`decrypt` | 16 -bytes secret key, 12 -bytes nonce, 8 -bytes authentication tag, N -bytes associated data, M -bytes cipher text | M -bytes plain text, boolean verification flag

> In above table, N, M >= 0

Here, I present a header-only, zero-dependency, easy-to-use C++ library, implementing Grain-128 AEADv2, which is submitted to NIST LWC final round call, see [here](https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-submissions/grain-128aead.zip).

During this work, I've followed Grain-128 AEADv2 specification, which I suggest you to go through, to have a better view of this AEAD scheme. Find specification document [here](https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/grain-128aead-spec-final.pdf).

Also note, this is the 10th ( i.e. last ) AEAD scheme, that I decided to implement as easy-to-use C++ library, which is competing in NIST LWC final round. Previous 9 AEAD schemes, that I worked on, can be found

- [Ascon](https://github.com/itzmeanjan/ascon)
- [TinyJambu](https://github.com/itzmeanjan/tinyjambu)
- [Xoodyak](https://github.com/itzmeanjan/xoodyak)
- [Sparkle](https://github.com/itzmeanjan/sparkle)
- [Photon-Beetle](https://github.com/itzmeanjan/photon-beetle)
- [ISAP](https://github.com/itzmeanjan/isap)
- [Romulus](https://github.com/itzmeanjan/romulus)
- [GIFT-COFB](https://github.com/itzmeanjan/gift-cofb)
- [Elephant](https://github.com/itzmeanjan/elephant)

A few things to note before moving forward

- Asssociated data is never encrypted by AEAD scheme. Only plain text is encrypted while both associated data & plain text are authenticated.
- Don't reuse same public message nonce, under same secret key.
- If authentication check fails during decryption, unverified plain text is never released. Instead memory allocation for plain text is explicitly zeroed.

Follow progress of NIST LWC standardization [here](https://csrc.nist.gov/Projects/lightweight-cryptography).

## Prerequisites

- C++ compiler such as `g++`/ `clang++`, with C++20 standard library

```bash
$ g++ --version
g++ (Ubuntu 11.2.0-19ubuntu1) 11.2.0

$ clang++ --version
Ubuntu clang version 14.0.0-1ubuntu1
Target: aarch64-unknown-linux-gnu
Thread model: posix
InstalledDir: /usr/bin
```

- System development tools such as `make`, `cmake`, `git`

```bash
$ make --version
GNU Make 3.81

$ cmake --version
cmake version 3.23.2
```

- For testing functional correctness of Grain-128 AEAD, you must have `python3`, `wget` & `unzip` installed

```bash
$ python3 --version
Python 3.10.4

$ wget --version
GNU Wget 1.21.3 built on darwin21.3.0.

$ unzip -v
UnZip 6.00 of 20 April 2009
```

- For executing tests against Known Answer Tests ( KATs ), install Python dependencies

```bash
python3 -m pip install --user -r wrapper/python/requirements.txt
```

- For benchmarking Grain-128 AEAD on CPU systems, you need to have `google-benchmark`, globally installed; follow [this](https://github.com/google/benchmark/tree/60b16f1#installation)

## Testing

For ensuring functional correctness of Grain-128 AEAD implementation, I use known answer tests provided with NIST final round submission package for Grain-128 AEAD, which can be downloaded from [here](https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-submissions/grain-128aead.zip)

Given 16 -bytes secret key, 12 -bytes public message nonce, N -bytes associated data & M -bytes plain text, I use Grain-128 `encrypt` routine for computing M -bytes cipher text & 8 -bytes authentication tag. Now both cipher text and authentication tag are compared against known answer tests ( KATs ), which is provided in submission package. Finally to ensure correctness of `decrypt` routine, I try to decrypt cipher text back to plain text, while successfully passing authentication check.

For executing tests, issue

```bash
make
```

## Benchmarking

For benchmarking Grain-128 AEAD routines, issue

```bash
make benchmark
```

> For disabling CPU scaling when benchmarking, see [this](https://github.com/google/benchmark/blob/60b16f1/docs/user_guide.md#disabling-cpu-frequency-scaling)

Note that, when benchmarking, associated data length is always kept 32 -bytes, while variable length plain text is used | L ∈ [64..4096] && L = 2 ^ i.

### On AWS Graviton3

```bash
2022-08-09T11:50:34+00:00
Running ./bench/a.out
Run on (64 X 2100 MHz CPU s)
CPU Caches:
  L1 Data 64 KiB (x64)
  L1 Instruction 64 KiB (x64)
  L2 Unified 1024 KiB (x64)
  L3 Unified 32768 KiB (x1)
Load Average: 0.32, 0.12, 0.04
-----------------------------------------------------------------------------------------------
Benchmark                                     Time             CPU   Iterations UserCounters...
-----------------------------------------------------------------------------------------------
bench_grain_128aead::encrypt/32/64        40110 ns        40110 ns        17451 bytes_per_second=2.28256M/s
bench_grain_128aead::decrypt/32/64        39739 ns        39738 ns        17613 bytes_per_second=2.30389M/s
bench_grain_128aead::encrypt/32/128       61617 ns        61616 ns        11359 bytes_per_second=2.47644M/s
bench_grain_128aead::decrypt/32/128       60915 ns        60914 ns        11490 bytes_per_second=2.50499M/s
bench_grain_128aead::encrypt/32/256      104573 ns       104571 ns         6694 bytes_per_second=2.62652M/s
bench_grain_128aead::decrypt/32/256      103254 ns       103252 ns         6780 bytes_per_second=2.66007M/s
bench_grain_128aead::encrypt/32/512      190525 ns       190522 ns         3674 bytes_per_second=2.72305M/s
bench_grain_128aead::decrypt/32/512      187922 ns       187911 ns         3725 bytes_per_second=2.76088M/s
bench_grain_128aead::encrypt/32/1024     362795 ns       362789 ns         1930 bytes_per_second=2.77594M/s
bench_grain_128aead::decrypt/32/1024     357358 ns       357344 ns         1959 bytes_per_second=2.81824M/s
bench_grain_128aead::encrypt/32/2048     707411 ns       707366 ns          990 bytes_per_second=2.80427M/s
bench_grain_128aead::decrypt/32/2048     695944 ns       695926 ns         1006 bytes_per_second=2.85036M/s
bench_grain_128aead::encrypt/32/4096    1395791 ns      1395752 ns          502 bytes_per_second=2.82053M/s
bench_grain_128aead::decrypt/32/4096    1373470 ns      1373435 ns          510 bytes_per_second=2.86637M/s
```

### On AWS Graviton2

```bash
2022-08-09T11:47:28+00:00
Running ./bench/a.out
Run on (16 X 166.66 MHz CPU s)
CPU Caches:
  L1 Data 32 KiB (x16)
  L1 Instruction 48 KiB (x16)
  L2 Unified 2048 KiB (x4)
Load Average: 0.33, 0.15, 0.06
-----------------------------------------------------------------------------------------------
Benchmark                                     Time             CPU   Iterations UserCounters...
-----------------------------------------------------------------------------------------------
bench_grain_128aead::encrypt/32/64        89278 ns        89277 ns         7835 bytes_per_second=1050.11k/s
bench_grain_128aead::decrypt/32/64        88187 ns        88186 ns         7938 bytes_per_second=1063.1k/s
bench_grain_128aead::encrypt/32/128      138527 ns       138524 ns         5053 bytes_per_second=1.10153M/s
bench_grain_128aead::decrypt/32/128      136314 ns       136313 ns         5135 bytes_per_second=1.1194M/s
bench_grain_128aead::encrypt/32/256      237025 ns       237021 ns         2953 bytes_per_second=1.15879M/s
bench_grain_128aead::decrypt/32/256      232573 ns       232572 ns         3010 bytes_per_second=1.18096M/s
bench_grain_128aead::encrypt/32/512      434032 ns       434011 ns         1613 bytes_per_second=1.19536M/s
bench_grain_128aead::decrypt/32/512      425106 ns       425096 ns         1647 bytes_per_second=1.22043M/s
bench_grain_128aead::encrypt/32/1024     827995 ns       827980 ns          845 bytes_per_second=1.21631M/s
bench_grain_128aead::decrypt/32/1024     810133 ns       810128 ns          864 bytes_per_second=1.24311M/s
bench_grain_128aead::encrypt/32/2048    1616020 ns      1615947 ns          433 bytes_per_second=1.22754M/s
bench_grain_128aead::decrypt/32/2048    1580210 ns      1580201 ns          443 bytes_per_second=1.25531M/s
bench_grain_128aead::encrypt/32/4096    3191949 ns      3191907 ns          219 bytes_per_second=1.23336M/s
bench_grain_128aead::decrypt/32/4096    3120435 ns      3120414 ns          224 bytes_per_second=1.26162M/s
```

### On Intel(R) Core(TM) i5-8279U CPU @ 2.40GHz

```bash
2022-08-09T16:26:39+04:00
Running ./bench/a.out
Run on (8 X 2400 MHz CPU s)
CPU Caches:
  L1 Data 32 KiB
  L1 Instruction 32 KiB
  L2 Unified 256 KiB (x4)
  L3 Unified 6144 KiB
Load Average: 1.59, 1.68, 1.58
-----------------------------------------------------------------------------------------------
Benchmark                                     Time             CPU   Iterations UserCounters...
-----------------------------------------------------------------------------------------------
bench_grain_128aead::encrypt/32/64        49788 ns        48821 ns        14725 bytes_per_second=1.87528M/s
bench_grain_128aead::decrypt/32/64        49355 ns        48474 ns        13653 bytes_per_second=1.88869M/s
bench_grain_128aead::encrypt/32/128       73212 ns        72111 ns         9189 bytes_per_second=2.11602M/s
bench_grain_128aead::decrypt/32/128       76150 ns        74212 ns         9597 bytes_per_second=2.05612M/s
bench_grain_128aead::encrypt/32/256      119537 ns       118529 ns         5785 bytes_per_second=2.31721M/s
bench_grain_128aead::decrypt/32/256      120119 ns       118693 ns         5804 bytes_per_second=2.31402M/s
bench_grain_128aead::encrypt/32/512      217267 ns       214896 ns         3267 bytes_per_second=2.41419M/s
bench_grain_128aead::decrypt/32/512      216218 ns       213855 ns         3292 bytes_per_second=2.42594M/s
bench_grain_128aead::encrypt/32/1024     420431 ns       413424 ns         1728 bytes_per_second=2.43595M/s
bench_grain_128aead::decrypt/32/1024     420876 ns       412820 ns         1658 bytes_per_second=2.43951M/s
bench_grain_128aead::encrypt/32/2048     799828 ns       790757 ns          835 bytes_per_second=2.50854M/s
bench_grain_128aead::decrypt/32/2048     864628 ns       838243 ns          865 bytes_per_second=2.36643M/s
bench_grain_128aead::encrypt/32/4096    1625769 ns      1597487 ns          423 bytes_per_second=2.46435M/s
bench_grain_128aead::decrypt/32/4096    1638923 ns      1602030 ns          439 bytes_per_second=2.45736M/s
```

### On Intel(R) Xeon(R) CPU E5-2686 v4 @ 2.30GHz

```bash
2022-08-09T12:28:52+00:00
Running ./bench/a.out
Run on (4 X 2300 MHz CPU s)
CPU Caches:
  L1 Data 32 KiB (x2)
  L1 Instruction 32 KiB (x2)
  L2 Unified 256 KiB (x2)
  L3 Unified 46080 KiB (x1)
Load Average: 0.18, 0.08, 0.03
-----------------------------------------------------------------------------------------------
Benchmark                                     Time             CPU   Iterations UserCounters...
-----------------------------------------------------------------------------------------------
bench_grain_128aead::encrypt/32/64       118728 ns       118725 ns         5895 bytes_per_second=789.642k/s
bench_grain_128aead::decrypt/32/64       115951 ns       115948 ns         6033 bytes_per_second=808.551k/s
bench_grain_128aead::encrypt/32/128      183156 ns       183142 ns         3823 bytes_per_second=853.164k/s
bench_grain_128aead::decrypt/32/128      177456 ns       177438 ns         3941 bytes_per_second=880.59k/s
bench_grain_128aead::encrypt/32/256      312031 ns       312014 ns         2244 bytes_per_second=901.403k/s
bench_grain_128aead::decrypt/32/256      300724 ns       300693 ns         2328 bytes_per_second=935.339k/s
bench_grain_128aead::encrypt/32/512      569837 ns       569800 ns         1228 bytes_per_second=932.345k/s
bench_grain_128aead::decrypt/32/512      547200 ns       547153 ns         1280 bytes_per_second=970.935k/s
bench_grain_128aead::encrypt/32/1024    1085490 ns      1085492 ns          645 bytes_per_second=950.03k/s
bench_grain_128aead::decrypt/32/1024    1040005 ns      1039991 ns          673 bytes_per_second=991.595k/s
bench_grain_128aead::encrypt/32/2048    2118801 ns      2118742 ns          331 bytes_per_second=958.706k/s
bench_grain_128aead::decrypt/32/2048    2025749 ns      2025582 ns          345 bytes_per_second=1002.8k/s
bench_grain_128aead::encrypt/32/4096    4177143 ns      4177052 ns          168 bytes_per_second=965.094k/s
bench_grain_128aead::decrypt/32/4096    3994538 ns      3994287 ns          175 bytes_per_second=1009.25k/s
```
