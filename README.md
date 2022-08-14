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

Note that, when benchmarking, associated data length is always kept 32 -bytes, while variable length ( = L ) plain text is used | L ∈ [64..4096] && L = 2 ^ i.

> Note, in this implementation, 8 consecutive cycles of Grain-128 AEAD stream cipher are executed in parallel, after cipher internal state is initialized. During execution of initialization phase, 32 consecutive clocks are executed in parallel ( initialization is done by clocking cipher state 512 times ).

### On AWS Graviton3

```bash
2022-08-14T06:07:17+00:00
Running ./bench/a.out
Run on (64 X 2100 MHz CPU s)
CPU Caches:
  L1 Data 64 KiB (x64)
  L1 Instruction 64 KiB (x64)
  L2 Unified 1024 KiB (x64)
  L3 Unified 32768 KiB (x1)
Load Average: 0.14, 0.03, 0.01
-----------------------------------------------------------------------------------------------
Benchmark                                     Time             CPU   Iterations UserCounters...
-----------------------------------------------------------------------------------------------
bench_grain_128aead::encrypt/32/64         7939 ns         7939 ns        88196 bytes_per_second=11.5326M/s
bench_grain_128aead::decrypt/32/64         8216 ns         8216 ns        85203 bytes_per_second=11.1437M/s
bench_grain_128aead::encrypt/32/128       10372 ns        10372 ns        67486 bytes_per_second=14.7116M/s
bench_grain_128aead::decrypt/32/128       10818 ns        10818 ns        64707 bytes_per_second=14.1047M/s
bench_grain_128aead::encrypt/32/256       15211 ns        15211 ns        46024 bytes_per_second=18.0565M/s
bench_grain_128aead::decrypt/32/256       16018 ns        16017 ns        43697 bytes_per_second=17.1474M/s
bench_grain_128aead::encrypt/32/512       24851 ns        24850 ns        28168 bytes_per_second=20.8769M/s
bench_grain_128aead::decrypt/32/512       26413 ns        26412 ns        26502 bytes_per_second=19.6423M/s
bench_grain_128aead::encrypt/32/1024      44278 ns        44277 ns        15877 bytes_per_second=22.745M/s
bench_grain_128aead::decrypt/32/1024      46972 ns        46971 ns        14902 bytes_per_second=21.4405M/s
bench_grain_128aead::encrypt/32/2048      82530 ns        82528 ns         8481 bytes_per_second=24.0359M/s
bench_grain_128aead::decrypt/32/2048      88755 ns        88753 ns         7887 bytes_per_second=22.3502M/s
bench_grain_128aead::encrypt/32/4096     159410 ns       159406 ns         4391 bytes_per_second=24.6965M/s
bench_grain_128aead::decrypt/32/4096     171819 ns       171815 ns         4074 bytes_per_second=22.9128M/s
```

### On AWS Graviton2

```bash
2022-08-14T06:06:26+00:00
Running ./bench/a.out
Run on (16 X 166.66 MHz CPU s)
CPU Caches:
  L1 Data 32 KiB (x16)
  L1 Instruction 48 KiB (x16)
  L2 Unified 2048 KiB (x4)
Load Average: 0.08, 0.02, 0.01
-----------------------------------------------------------------------------------------------
Benchmark                                     Time             CPU   Iterations UserCounters...
-----------------------------------------------------------------------------------------------
bench_grain_128aead::encrypt/32/64        11443 ns        11443 ns        61134 bytes_per_second=8.0006M/s
bench_grain_128aead::decrypt/32/64        11454 ns        11454 ns        61115 bytes_per_second=7.99341M/s
bench_grain_128aead::encrypt/32/128       17126 ns        17126 ns        40875 bytes_per_second=8.90969M/s
bench_grain_128aead::decrypt/32/128       17136 ns        17135 ns        40849 bytes_per_second=8.90481M/s
bench_grain_128aead::encrypt/32/256       28489 ns        28489 ns        24571 bytes_per_second=9.64093M/s
bench_grain_128aead::decrypt/32/256       28500 ns        28500 ns        24561 bytes_per_second=9.63716M/s
bench_grain_128aead::encrypt/32/512       51218 ns        51217 ns        13667 bytes_per_second=10.1295M/s
bench_grain_128aead::decrypt/32/512       51231 ns        51228 ns        13665 bytes_per_second=10.1272M/s
bench_grain_128aead::encrypt/32/1024      96671 ns        96670 ns         7240 bytes_per_second=10.4177M/s
bench_grain_128aead::decrypt/32/1024      96690 ns        96687 ns         7240 bytes_per_second=10.4159M/s
bench_grain_128aead::encrypt/32/2048     187590 ns       187585 ns         3732 bytes_per_second=10.5746M/s
bench_grain_128aead::decrypt/32/2048     187619 ns       187614 ns         3731 bytes_per_second=10.573M/s
bench_grain_128aead::encrypt/32/4096     369432 ns       369426 ns         1895 bytes_per_second=10.6564M/s
bench_grain_128aead::decrypt/32/4096     369445 ns       369433 ns         1895 bytes_per_second=10.6562M/s
```

### On Intel(R) Core(TM) i5-8279U CPU @ 2.40GHz

```bash
2022-08-14T10:04:14+04:00
Running ./bench/a.out
Run on (8 X 2400 MHz CPU s)
CPU Caches:
  L1 Data 32 KiB
  L1 Instruction 32 KiB
  L2 Unified 256 KiB (x4)
  L3 Unified 6144 KiB
Load Average: 1.71, 2.33, 2.33
-----------------------------------------------------------------------------------------------
Benchmark                                     Time             CPU   Iterations UserCounters...
-----------------------------------------------------------------------------------------------
bench_grain_128aead::encrypt/32/64         5431 ns         5428 ns       120159 bytes_per_second=16.8669M/s
bench_grain_128aead::decrypt/32/64         5443 ns         5438 ns       121926 bytes_per_second=16.837M/s
bench_grain_128aead::encrypt/32/128        8501 ns         8493 ns        78511 bytes_per_second=17.9655M/s
bench_grain_128aead::decrypt/32/128        8652 ns         8620 ns        81125 bytes_per_second=17.7015M/s
bench_grain_128aead::encrypt/32/256       16225 ns        16010 ns        45959 bytes_per_second=17.1549M/s
bench_grain_128aead::decrypt/32/256       16612 ns        16383 ns        41319 bytes_per_second=16.7652M/s
bench_grain_128aead::encrypt/32/512       30356 ns        29256 ns        25416 bytes_per_second=17.7328M/s
bench_grain_128aead::decrypt/32/512       27383 ns        27331 ns        24107 bytes_per_second=18.9822M/s
bench_grain_128aead::encrypt/32/1024      55254 ns        54708 ns        13409 bytes_per_second=18.4081M/s
bench_grain_128aead::decrypt/32/1024      55436 ns        54904 ns        12272 bytes_per_second=18.3425M/s
bench_grain_128aead::encrypt/32/2048     103929 ns       103547 ns         6767 bytes_per_second=19.1569M/s
bench_grain_128aead::decrypt/32/2048     111206 ns       108785 ns         6634 bytes_per_second=18.2346M/s
bench_grain_128aead::encrypt/32/4096     201916 ns       201604 ns         3353 bytes_per_second=19.5272M/s
bench_grain_128aead::decrypt/32/4096     213681 ns       211716 ns         3439 bytes_per_second=18.5945M/s
```

### On Intel(R) Xeon(R) CPU E5-2686 v4 @ 2.30GHz

```bash
2022-08-14T06:05:20+00:00
Running ./bench/a.out
Run on (4 X 2300 MHz CPU s)
CPU Caches:
  L1 Data 32 KiB (x2)
  L1 Instruction 32 KiB (x2)
  L2 Unified 256 KiB (x2)
  L3 Unified 46080 KiB (x1)
Load Average: 0.14, 0.03, 0.01
-----------------------------------------------------------------------------------------------
Benchmark                                     Time             CPU   Iterations UserCounters...
-----------------------------------------------------------------------------------------------
bench_grain_128aead::encrypt/32/64        14046 ns        14045 ns        49790 bytes_per_second=6.51851M/s
bench_grain_128aead::decrypt/32/64        13666 ns        13666 ns        51215 bytes_per_second=6.69953M/s
bench_grain_128aead::encrypt/32/128       19346 ns        19346 ns        36204 bytes_per_second=7.88721M/s
bench_grain_128aead::decrypt/32/128       18892 ns        18892 ns        37063 bytes_per_second=8.07689M/s
bench_grain_128aead::encrypt/32/256       29962 ns        29962 ns        23377 bytes_per_second=9.16683M/s
bench_grain_128aead::decrypt/32/256       29288 ns        29289 ns        23906 bytes_per_second=9.37763M/s
bench_grain_128aead::encrypt/32/512       51059 ns        51056 ns        13697 bytes_per_second=10.1614M/s
bench_grain_128aead::decrypt/32/512       50028 ns        50029 ns        10000 bytes_per_second=10.3701M/s
bench_grain_128aead::encrypt/32/1024      93829 ns        93830 ns         7491 bytes_per_second=10.7331M/s
bench_grain_128aead::decrypt/32/1024      91690 ns        91690 ns         7646 bytes_per_second=10.9835M/s
bench_grain_128aead::encrypt/32/2048     178232 ns       178233 ns         3934 bytes_per_second=11.1295M/s
bench_grain_128aead::decrypt/32/2048     174480 ns       174457 ns         4010 bytes_per_second=11.3704M/s
bench_grain_128aead::encrypt/32/4096     346932 ns       346907 ns         2019 bytes_per_second=11.3482M/s
bench_grain_128aead::decrypt/32/4096     340194 ns       340168 ns         2058 bytes_per_second=11.573M/s
```

## Usage

Grain-128 AEAD is written such that it's pretty easy to start using in your project. All that is required is

- Include `./include/grain_128aead.hpp` header file in your source
- Use `encrypt`/ `decrypt` routines defined under namespace `grain_128aead`
- Let your compiler know where to find these header files ( i.e. `./include` directory )

For API documentation, I suggest you read through

- [encrypt( ... )](https://github.com/itzmeanjan/grain-128aead/blob/55539e43c5d3b5c098944706a8855ae226546593/include/grain_128aead.hpp#L7-L21)
- [decrypt( ... )](https://github.com/itzmeanjan/grain-128aead/blob/55539e43c5d3b5c098944706a8855ae226546593/include/grain_128aead.hpp#L43-L56)

I keep API usage example [here](./example/main.cpp).

```bash
Grain-128 AEAD

Key       : 08ecc6d3edaa57cbdf4bd4b6f43869fa
Nonce     : f8f755034bff227fa107fac0
Data      : f7b04b12051680d1af943e142e9e0e95e24c6bdf753edb4aa12480cc8d179ca5
Text      : 38937413bedf5c753d0eaebc61467b814b4e6e9d6c1ab6ec4fbde192e4581afa
Encrypted : 1cb5edd9aed81348df76ad4c197322daa0ec40f92020725d62fd52edf61906c9
Decrypted : 38937413bedf5c753d0eaebc61467b814b4e6e9d6c1ab6ec4fbde192e4581afa
Tag       : 1cb420123b94d3a7
```
