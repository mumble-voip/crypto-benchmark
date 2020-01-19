#pragma once

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

bool hydrogen_main(const size_t message_size, const size_t iterations);

double hydrogen_crypto(const size_t iterations, uint8_t *dst, const size_t size, const uint8_t *src);
