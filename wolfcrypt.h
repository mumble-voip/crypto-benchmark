#pragma once

#include <stdbool.h>

#include <wolfssl/options.h>

#include <wolfssl/wolfcrypt/types.h>

typedef struct WC_RNG WC_RNG;

bool wolfcrypt_main(const size_t message_size, const size_t iterations);

bool wolfcrypt_random(WC_RNG *rng, const size_t size, byte *out);

double wolfcrypt_aes_256_gcm(const size_t iterations, WC_RNG *rng, byte *dst, const word32 size, const byte *src);
double wolfcrypt_chacha20_poly1305(const size_t iterations, WC_RNG *rng, byte *dst, const word32 size, const byte *src);

bool wolfcrypt_init(WC_RNG *rng);
bool wolfcrypt_cleanup(WC_RNG *rng);
