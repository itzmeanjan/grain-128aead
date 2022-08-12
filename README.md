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

> Note, in this implementation, 8 consecutive cycles of Grain-128 AEAD stream cipher are executed in parallel.

### On AWS Graviton3

```bash
2022-08-12T14:43:21+00:00
Running ./bench/a.out
Run on (64 X 2100 MHz CPU s)
CPU Caches:
  L1 Data 64 KiB (x64)
  L1 Instruction 64 KiB (x64)
  L2 Unified 1024 KiB (x64)
  L3 Unified 32768 KiB (x1)
Load Average: 0.08, 0.02, 0.01
-----------------------------------------------------------------------------------------------
Benchmark                                     Time             CPU   Iterations UserCounters...
-----------------------------------------------------------------------------------------------
bench_grain_128aead::encrypt/32/64         5237 ns         5237 ns       133578 bytes_per_second=17.4831M/s
bench_grain_128aead::decrypt/32/64         5315 ns         5315 ns       131702 bytes_per_second=17.2264M/s
bench_grain_128aead::encrypt/32/128        7679 ns         7679 ns        91182 bytes_per_second=19.8715M/s
bench_grain_128aead::decrypt/32/128        7912 ns         7912 ns        88459 bytes_per_second=19.2849M/s
bench_grain_128aead::encrypt/32/256       12552 ns        12552 ns        55768 bytes_per_second=21.8824M/s
bench_grain_128aead::decrypt/32/256       13110 ns        13110 ns        53398 bytes_per_second=20.9501M/s
bench_grain_128aead::encrypt/32/512       22280 ns        22280 ns        31420 bytes_per_second=23.2857M/s
bench_grain_128aead::decrypt/32/512       23503 ns        23503 ns        29785 bytes_per_second=22.0739M/s
bench_grain_128aead::encrypt/32/1024      41720 ns        41719 ns        16781 bytes_per_second=24.1395M/s
bench_grain_128aead::decrypt/32/1024      44286 ns        44286 ns        15807 bytes_per_second=22.7406M/s
bench_grain_128aead::encrypt/32/2048      80594 ns        80590 ns         8686 bytes_per_second=24.6139M/s
bench_grain_128aead::decrypt/32/2048      85854 ns        85852 ns         8155 bytes_per_second=23.1054M/s
bench_grain_128aead::encrypt/32/4096     158397 ns       158390 ns         4419 bytes_per_second=24.8549M/s
bench_grain_128aead::decrypt/32/4096     168921 ns       168916 ns         4144 bytes_per_second=23.3061M/s
```

### On AWS Graviton2

```bash
2022-08-12T14:42:19+00:00
Running ./bench/a.out
Run on (16 X 166.66 MHz CPU s)
CPU Caches:
  L1 Data 32 KiB (x16)
  L1 Instruction 48 KiB (x16)
  L2 Unified 2048 KiB (x4)
Load Average: 0.15, 0.03, 0.01
-----------------------------------------------------------------------------------------------
Benchmark                                     Time             CPU   Iterations UserCounters...
-----------------------------------------------------------------------------------------------
bench_grain_128aead::encrypt/32/64        11794 ns        11794 ns        59337 bytes_per_second=7.76266M/s
bench_grain_128aead::decrypt/32/64        11812 ns        11811 ns        59273 bytes_per_second=7.7513M/s
bench_grain_128aead::encrypt/32/128       17476 ns        17475 ns        40054 bytes_per_second=8.73154M/s
bench_grain_128aead::decrypt/32/128       17491 ns        17491 ns        40020 bytes_per_second=8.72391M/s
bench_grain_128aead::encrypt/32/256       28839 ns        28839 ns        24272 bytes_per_second=9.52378M/s
bench_grain_128aead::decrypt/32/256       28857 ns        28856 ns        24259 bytes_per_second=9.51823M/s
bench_grain_128aead::encrypt/32/512       51567 ns        51567 ns        13574 bytes_per_second=10.0607M/s
bench_grain_128aead::decrypt/32/512       51582 ns        51582 ns        13570 bytes_per_second=10.0578M/s
bench_grain_128aead::encrypt/32/1024      97024 ns        97022 ns         7214 bytes_per_second=10.3799M/s
bench_grain_128aead::decrypt/32/1024      97038 ns        97036 ns         7214 bytes_per_second=10.3784M/s
bench_grain_128aead::encrypt/32/2048     187944 ns       187939 ns         3724 bytes_per_second=10.5547M/s
bench_grain_128aead::decrypt/32/2048     187948 ns       187945 ns         3725 bytes_per_second=10.5544M/s
bench_grain_128aead::encrypt/32/4096     369809 ns       369803 ns         1893 bytes_per_second=10.6456M/s
bench_grain_128aead::decrypt/32/4096     369808 ns       369802 ns         1893 bytes_per_second=10.6456M/s
```

### On Intel(R) Core(TM) i5-8279U CPU @ 2.40GHz

```bash
2022-08-12T18:30:05+04:00
Running ./bench/a.out
Run on (8 X 2400 MHz CPU s)
CPU Caches:
  L1 Data 32 KiB
  L1 Instruction 32 KiB
  L2 Unified 256 KiB (x4)
  L3 Unified 6144 KiB
Load Average: 1.62, 1.47, 1.68
-----------------------------------------------------------------------------------------------
Benchmark                                     Time             CPU   Iterations UserCounters...
-----------------------------------------------------------------------------------------------
bench_grain_128aead::encrypt/32/64         6302 ns         6292 ns       104808 bytes_per_second=14.5499M/s
bench_grain_128aead::decrypt/32/64         6252 ns         6247 ns       110141 bytes_per_second=14.6556M/s
bench_grain_128aead::encrypt/32/128        9223 ns         9217 ns        74051 bytes_per_second=16.5542M/s
bench_grain_128aead::decrypt/32/128        9607 ns         9599 ns        73394 bytes_per_second=15.8954M/s
bench_grain_128aead::encrypt/32/256       15409 ns        15402 ns        45015 bytes_per_second=17.8324M/s
bench_grain_128aead::decrypt/32/256       15625 ns        15611 ns        43482 bytes_per_second=17.5937M/s
bench_grain_128aead::encrypt/32/512       27912 ns        27893 ns        25013 bytes_per_second=18.5995M/s
bench_grain_128aead::decrypt/32/512       29477 ns        29428 ns        23936 bytes_per_second=17.6297M/s
bench_grain_128aead::encrypt/32/1024      51964 ns        51938 ns        13170 bytes_per_second=19.3902M/s
bench_grain_128aead::decrypt/32/1024      51805 ns        51790 ns        13135 bytes_per_second=19.4456M/s
bench_grain_128aead::encrypt/32/2048     100100 ns       100024 ns         6886 bytes_per_second=19.8317M/s
bench_grain_128aead::decrypt/32/2048     101439 ns       101336 ns         6857 bytes_per_second=19.5748M/s
bench_grain_128aead::encrypt/32/4096     195531 ns       195455 ns         3556 bytes_per_second=20.1416M/s
bench_grain_128aead::decrypt/32/4096     199211 ns       199083 ns         3485 bytes_per_second=19.7745M/s
```

### On Intel(R) Xeon(R) CPU E5-2686 v4 @ 2.30GHz

```bash
2022-08-12T14:41:09+00:00
Running ./bench/a.out
Run on (4 X 2300 MHz CPU s)
CPU Caches:
  L1 Data 32 KiB (x2)
  L1 Instruction 32 KiB (x2)
  L2 Unified 256 KiB (x2)
  L3 Unified 46080 KiB (x1)
Load Average: 0.04, 0.01, 0.00
-----------------------------------------------------------------------------------------------
Benchmark                                     Time             CPU   Iterations UserCounters...
-----------------------------------------------------------------------------------------------
bench_grain_128aead::encrypt/32/64        11504 ns        11503 ns        60790 bytes_per_second=7.95909M/s
bench_grain_128aead::decrypt/32/64        11120 ns        11119 ns        63009 bytes_per_second=8.23411M/s
bench_grain_128aead::encrypt/32/128       16878 ns        16876 ns        41476 bytes_per_second=9.04184M/s
bench_grain_128aead::decrypt/32/128       16357 ns        16356 ns        42814 bytes_per_second=9.32891M/s
bench_grain_128aead::encrypt/32/256       27481 ns        27481 ns        25417 bytes_per_second=9.99446M/s
bench_grain_128aead::decrypt/32/256       26800 ns        26798 ns        26091 bytes_per_second=10.2491M/s
bench_grain_128aead::encrypt/32/512       48620 ns        48620 ns        14399 bytes_per_second=10.6704M/s
bench_grain_128aead::decrypt/32/512       47531 ns        47530 ns        14730 bytes_per_second=10.9151M/s
bench_grain_128aead::encrypt/32/1024      90885 ns        90886 ns         7706 bytes_per_second=11.0807M/s
bench_grain_128aead::decrypt/32/1024      89048 ns        89047 ns         7863 bytes_per_second=11.3095M/s
bench_grain_128aead::encrypt/32/2048     175603 ns       175599 ns         3987 bytes_per_second=11.2965M/s
bench_grain_128aead::decrypt/32/2048     172172 ns       172164 ns         3961 bytes_per_second=11.5218M/s
bench_grain_128aead::encrypt/32/4096     345171 ns       345161 ns         2026 bytes_per_second=11.4056M/s
bench_grain_128aead::decrypt/32/4096     338591 ns       338576 ns         2067 bytes_per_second=11.6274M/s
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
