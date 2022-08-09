#include "grain_128aead.hpp"
#include "utils.hpp"
#include <cassert>
#include <iostream>

// Compile it with
//
// g++ -std=c++20 -Wall -Wextra -O3 -march=native -I ./include example/main.cpp
int
main()
{
  uint8_t key[16];          // secret key
  uint8_t nonce[12];        // public message nonce
  uint8_t tag[8];           // authentication tag
  uint8_t data[32];         // associated data
  uint8_t txt[32];          // plain text
  uint8_t enc[sizeof(txt)]; // encrypted text bytes
  uint8_t dec[sizeof(enc)]; // decrypted text bytes

  random_data(key, sizeof(key));
  random_data(nonce, sizeof(nonce));
  random_data(data, sizeof(data));
  random_data(txt, sizeof(txt));

  using namespace grain_128aead;
  encrypt(key, nonce, data, sizeof(data), txt, enc, sizeof(txt), tag);
  bool f0 = decrypt(key, nonce, tag, data, sizeof(data), enc, dec, sizeof(enc));

  // check that verification flag holds truth value
  assert(f0);

  // byte-by-byte comparison of plain text & decrypted text
  bool f1 = false;
  for (size_t i = 0; i < sizeof(txt); i++) {
    f1 |= txt[i] ^ dec[i];
  }

  assert(!f1);

  std::cout << "Grain-128 AEAD" << std::endl << std::endl;
  std::cout << "Key       : " << to_hex(key, sizeof(key)) << std::endl;
  std::cout << "Nonce     : " << to_hex(nonce, sizeof(nonce)) << std::endl;
  std::cout << "Data      : " << to_hex(data, sizeof(data)) << std::endl;
  std::cout << "Text      : " << to_hex(txt, sizeof(txt)) << std::endl;
  std::cout << "Encrypted : " << to_hex(enc, sizeof(enc)) << std::endl;
  std::cout << "Decrypted : " << to_hex(dec, sizeof(dec)) << std::endl;
  std::cout << "Tag       : " << to_hex(tag, sizeof(tag)) << std::endl;

  return EXIT_SUCCESS;
}
