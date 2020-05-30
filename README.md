# Mumble's crypto benchmark
Crypto benchmark is a tool for benchmarking modern [AEAD](https://en.wikipedia.org/wiki/Authenticated_encryption#Authenticated_encryption_with_associated_data_(AEAD)) algorithms.

## Motivation
Due to the use of the old AES-128-OCB algorithm and its slow implementation in [Mumble](https://github.com/mumble-voip/mumble), we decided to determine the best cipher and library for the VoIP communicator.


## Build status
We build the project using [Travis CI](https://travis-ci.com), on Ubuntu 18.04, using GCC and Clang compilers, on AMD64 and ARM64 platforms. Current status: [![Build Status](https://travis-ci.com/mumble-voip/crypto-benchmark.svg?branch=master)](https://travis-ci.com/mumble-voip/crypto-benchmark)

## Screenshot / demo
```
$ ./crypto_benchmark
[NSS] running AES-256-GCM benchmark...
[NSS] 4.007687 seconds for 1000000 iterations, 4096 bytes message
[NSS] running ChaCha20-Poly1305 benchmark...
[NSS] 32.563270 seconds for 1000000 iterations, 4096 bytes message
[OpenSSL] running AES-256-GCM benchmark...
[OpenSSL] 2.398911 seconds for 1000000 iterations, 4096 bytes message
[OpenSSL] running AES-256-OCB benchmark...
[OpenSSL] 2.441164 seconds for 1000000 iterations, 4096 bytes message
[OpenSSL] running ChaCha20-Poly1305 benchmark...
[OpenSSL] 4.500481 seconds for 1000000 iterations, 4096 bytes message
[libsodium] running AEGIS-128L benchmark...
[libsodium] 0.753556 seconds for 1000000 iterations, 4096 bytes message
[libsodium] running AEGIS-256 benchmark...
[libsodium] 1.144947 seconds for 1000000 iterations, 4096 bytes message
[libsodium] running AES-256-GCM benchmark...
[libsodium] 4.243719 seconds for 1000000 iterations, 4096 bytes message
[libsodium] running ChaCha20-Poly1305 benchmark...
[libsodium] 5.813727 seconds for 1000000 iterations, 4096 bytes message
[wolfCrypt] running AES-256-GCM benchmark...
[wolfCrypt] 122.332474 seconds for 1000000 iterations, 4096 bytes message
[wolfCrypt] running ChaCha20-Poly1305 benchmark...
[wolfCrypt] 29.525731 seconds for 1000000 iterations, 4096 bytes message
```

## Technology used
The benchmark is written in C language.
### Crypto libraries
[NSS](https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS), [OpenSSL](https://www.openssl.org/), [libsodium](https://doc.libsodium.org/) (custom build from the master branch, due to AEGIS availability), [wolfCrypt](https://www.wolfssl.com/products/wolfcrypt-2/)

| Algorithm | Library | License | Limitations |
| --------- | ------- | ------- | ----------- |
| AES-256-GCM | NSS | MPL 2 |  |
| ChaCha20-Poly1305 | NSS | MPL 2|  |
| AES-128-OCB | OpenSSL | Apache | Patented |
| AES-256-GCM | OpenSSL | Apache |  |
| ChaCha20-Poly1305 | OpenSSL | Apache |  |
| AEGIS-128L | libsodium | ISC |  |
| AEGIS-256 | libsodium | ISC |  |
| AES-256-GCM | libsodium | ISC | [Requires SSSE3 + `aesni` and `pclmul` instructions](https://doc.libsodium.org/secret-key_cryptography/aead/aes-256-gcm#limitations) |
| ChaCha20-Poly1305 | libsodium | ISC |  |
| AES-256-GCM | wolfCrypt | GPLv2 | [Optimizations disabled by default](https://github.com/wolfSSL/wolfssl/issues/2691#issuecomment-567711659) |
| ChaCha20-Poly1305 | wolfCrypt | GPLv2 | [Optimizations disabled by default](https://github.com/wolfSSL/wolfssl/issues/2691#issuecomment-567711659) |

## Contribute
If you are willing to help in development of this tool, feel free to create a new issue, pull request, or start a discussion on [#mumble-dev on Freenode](irc://chat.freenode.net/mumble-dev).
