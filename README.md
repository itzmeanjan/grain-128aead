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

> Note, in this implementation, 8/ 32 ( preferred ) consecutive cycles of Grain-128 AEAD stream cipher are executed in parallel, after cipher internal state is initialized. During execution of initialization phase, 32 consecutive clocks are executed in parallel ( initialization is done by clocking cipher state 512 times ).

### On AWS Graviton3

```bash
2022-08-31T16:05:56+00:00
Running ./bench/a.out
Run on (64 X 2100 MHz CPU s)
CPU Caches:
  L1 Data 64 KiB (x64)
  L1 Instruction 64 KiB (x64)
  L2 Unified 1024 KiB (x64)
  L3 Unified 32768 KiB (x1)
Load Average: 0.00, 0.00, 0.00
-----------------------------------------------------------------------------------------------
Benchmark                                     Time             CPU   Iterations UserCounters...
-----------------------------------------------------------------------------------------------
bench_grain_128aead::encrypt/32/64         2260 ns         2260 ns       309684 bytes_per_second=40.5189M/s
bench_grain_128aead::decrypt/32/64         2297 ns         2297 ns       304639 bytes_per_second=39.8507M/s
bench_grain_128aead::encrypt/32/128        3459 ns         3459 ns       202384 bytes_per_second=44.1175M/s
bench_grain_128aead::decrypt/32/128        3525 ns         3525 ns       198544 bytes_per_second=43.2822M/s
bench_grain_128aead::encrypt/32/256        5862 ns         5862 ns       119396 bytes_per_second=46.8546M/s
bench_grain_128aead::decrypt/32/256        5984 ns         5984 ns       117008 bytes_per_second=45.8975M/s
bench_grain_128aead::encrypt/32/512       10672 ns        10672 ns        65566 bytes_per_second=48.6149M/s
bench_grain_128aead::decrypt/32/512       10930 ns        10930 ns        64043 bytes_per_second=47.4664M/s
bench_grain_128aead::encrypt/32/1024      20291 ns        20290 ns        34500 bytes_per_second=49.6335M/s
bench_grain_128aead::decrypt/32/1024      20786 ns        20785 ns        33673 bytes_per_second=48.4518M/s
bench_grain_128aead::encrypt/32/2048      39525 ns        39524 ns        17717 bytes_per_second=50.1878M/s
bench_grain_128aead::decrypt/32/2048      40434 ns        40433 ns        17287 bytes_per_second=49.0603M/s
bench_grain_128aead::encrypt/32/4096      78112 ns        78110 ns         8957 bytes_per_second=50.4003M/s
bench_grain_128aead::decrypt/32/4096      79721 ns        79719 ns         8780 bytes_per_second=49.3829M/s
```

### On AWS Graviton2

```bash
2022-08-31T16:04:51+00:00
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
bench_grain_128aead::encrypt/32/64         3815 ns         3815 ns       183503 bytes_per_second=24.0005M/s
bench_grain_128aead::decrypt/32/64         3959 ns         3959 ns       176836 bytes_per_second=23.1279M/s
bench_grain_128aead::encrypt/32/128        5806 ns         5806 ns       120566 bytes_per_second=26.2823M/s
bench_grain_128aead::decrypt/32/128        6061 ns         6061 ns       115485 bytes_per_second=25.1749M/s
bench_grain_128aead::encrypt/32/256        9788 ns         9788 ns        71513 bytes_per_second=28.06M/s
bench_grain_128aead::decrypt/32/256       10266 ns        10266 ns        68180 bytes_per_second=26.7538M/s
bench_grain_128aead::encrypt/32/512       17753 ns        17753 ns        39429 bytes_per_second=29.2235M/s
bench_grain_128aead::decrypt/32/512       18677 ns        18677 ns        37480 bytes_per_second=27.7779M/s
bench_grain_128aead::encrypt/32/1024      33683 ns        33682 ns        20781 bytes_per_second=29.8993M/s
bench_grain_128aead::decrypt/32/1024      35499 ns        35498 ns        19719 bytes_per_second=28.3703M/s
bench_grain_128aead::encrypt/32/2048      65545 ns        65544 ns        10679 bytes_per_second=30.2645M/s
bench_grain_128aead::decrypt/32/2048      69141 ns        69140 ns        10124 bytes_per_second=28.6903M/s
bench_grain_128aead::encrypt/32/4096     129270 ns       129266 ns         5415 bytes_per_second=30.4548M/s
bench_grain_128aead::decrypt/32/4096     136443 ns       136436 ns         5130 bytes_per_second=28.8542M/s
```

### On Intel(R) Core(TM) i5-8279U CPU @ 2.40GHz

```bash
2022-08-31T16:22:03+04:00
Running ./bench/a.out
Run on (8 X 2400 MHz CPU s)
CPU Caches:
  L1 Data 32 KiB
  L1 Instruction 32 KiB
  L2 Unified 256 KiB (x4)
  L3 Unified 6144 KiB
Load Average: 1.74, 1.65, 1.68
-----------------------------------------------------------------------------------------------
Benchmark                                     Time             CPU   Iterations UserCounters...
-----------------------------------------------------------------------------------------------
bench_grain_128aead::encrypt/32/64         1453 ns         1451 ns       466614 bytes_per_second=63.1063M/s
bench_grain_128aead::decrypt/32/64         1462 ns         1461 ns       476547 bytes_per_second=62.6804M/s
bench_grain_128aead::encrypt/32/128        2179 ns         2178 ns       318384 bytes_per_second=70.0644M/s
bench_grain_128aead::decrypt/32/128        2169 ns         2168 ns       318480 bytes_per_second=70.3666M/s
bench_grain_128aead::encrypt/32/256        3651 ns         3648 ns       190775 bytes_per_second=75.2873M/s
bench_grain_128aead::decrypt/32/256        3632 ns         3629 ns       192214 bytes_per_second=75.6859M/s
bench_grain_128aead::encrypt/32/512        6645 ns         6638 ns       103301 bytes_per_second=78.1543M/s
bench_grain_128aead::decrypt/32/512        6540 ns         6534 ns       104490 bytes_per_second=79.4022M/s
bench_grain_128aead::encrypt/32/1024      12507 ns        12502 ns        54486 bytes_per_second=80.5554M/s
bench_grain_128aead::decrypt/32/1024      12421 ns        12412 ns        55613 bytes_per_second=81.1347M/s
bench_grain_128aead::encrypt/32/2048      24295 ns        24281 ns        28632 bytes_per_second=81.6966M/s
bench_grain_128aead::decrypt/32/2048      24457 ns        24436 ns        28425 bytes_per_second=81.1757M/s
bench_grain_128aead::encrypt/32/4096      48003 ns        47955 ns        14618 bytes_per_second=82.0922M/s
bench_grain_128aead::decrypt/32/4096      48276 ns        48254 ns        13964 bytes_per_second=81.5837M/s
```

### On Intel(R) Xeon(R) CPU E5-2686 v4 @ 2.30GHz

```bash
2022-08-31T12:28:04+00:00
Running ./bench/a.out
Run on (4 X 2300 MHz CPU s)
CPU Caches:
  L1 Data 32 KiB (x2)
  L1 Instruction 32 KiB (x2)
  L2 Unified 256 KiB (x2)
  L3 Unified 46080 KiB (x1)
Load Average: 0.33, 0.10, 0.03
-----------------------------------------------------------------------------------------------
Benchmark                                     Time             CPU   Iterations UserCounters...
-----------------------------------------------------------------------------------------------
bench_grain_128aead::encrypt/32/64         3619 ns         3619 ns       195348 bytes_per_second=25.2991M/s
bench_grain_128aead::decrypt/32/64         3789 ns         3789 ns       184952 bytes_per_second=24.1653M/s
bench_grain_128aead::encrypt/32/128        5232 ns         5232 ns       133591 bytes_per_second=29.1669M/s
bench_grain_128aead::decrypt/32/128        5621 ns         5621 ns       124339 bytes_per_second=27.1447M/s
bench_grain_128aead::encrypt/32/256        8499 ns         8499 ns        82400 bytes_per_second=32.3173M/s
bench_grain_128aead::decrypt/32/256        9139 ns         9139 ns        76565 bytes_per_second=30.0546M/s
bench_grain_128aead::encrypt/32/512       15039 ns        15037 ns        46525 bytes_per_second=34.5006M/s
bench_grain_128aead::decrypt/32/512       16307 ns        16306 ns        42871 bytes_per_second=31.8155M/s
bench_grain_128aead::encrypt/32/1024      28187 ns        28184 ns        24827 bytes_per_second=35.7327M/s
bench_grain_128aead::decrypt/32/1024      30596 ns        30595 ns        22879 bytes_per_second=32.9164M/s
bench_grain_128aead::encrypt/32/2048      54417 ns        54417 ns        12864 bytes_per_second=36.4529M/s
bench_grain_128aead::decrypt/32/2048      59023 ns        59020 ns        11836 bytes_per_second=33.6099M/s
bench_grain_128aead::encrypt/32/4096     106662 ns       106663 ns         6572 bytes_per_second=36.9085M/s
bench_grain_128aead::decrypt/32/4096     116021 ns       116022 ns         6030 bytes_per_second=33.9313M/s
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
