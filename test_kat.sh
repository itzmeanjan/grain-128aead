#!/bin/bash

# Script for ease of execution of Known Answer Tests against Grain-128 AEAD implementation

make lib

# ---

mkdir -p tmp
pushd tmp

wget -O grain-128aead.zip https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-submissions/grain-128aead.zip
unzip grain-128aead.zip

cp grain-128aead/Implementations/crypto_aead/grain128aeadv2/LWC_AEAD_KAT_128_96.txt ../

popd

# ---

rm -rf tmp
mv LWC_AEAD_KAT_128_96.txt wrapper/python/

# ---

pushd wrapper/python

python3 -m pytest -v
rm LWC_AEAD_KAT_*.txt

popd

# ---
