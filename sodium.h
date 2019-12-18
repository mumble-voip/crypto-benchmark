#pragma once

#include <stddef.h>
#include <stdbool.h>

bool sodium_main(const size_t message_size, const size_t iterations);

double sodium_aes_256_gcm(const size_t iterations, unsigned char *dst, const unsigned long long size, const unsigned char *src);
double sodium_chacha20_poly1305(const size_t iterations, unsigned char *dst, const unsigned long long size, const unsigned char *src);
