#pragma once

#include <stddef.h>
#include <stdbool.h>

typedef struct PK11SlotInfoStr PK11SlotInfo;

bool nss_main(const size_t message_size, const size_t iterations);

double nss_aes_256_gcm(const size_t iterations, PK11SlotInfo *slot, unsigned char *dst, const unsigned int size, const unsigned char *src);
double nss_chacha20_poly1305(const size_t iterations, PK11SlotInfo *slot, unsigned char *dst, const unsigned int size, const unsigned char *src);
