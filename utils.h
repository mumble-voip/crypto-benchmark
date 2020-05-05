#pragma once

#include <stdbool.h>
#include <stddef.h>

#define KEY_SIZE 32
#define IV_SIZE 12
#define TAG_SIZE 16

#define CIPHER_AES_256_GCM "AES-256-GCM"
#define CIPHER_AES_256_OCB "AES-256-OCB"
#define CIPHER_CHACHA20_POLY1305 "ChaCha20-Poly1305"
#define CIPHER_GIMLI_CURVE25519 "Gimli-Curve25519"

typedef struct Crypto {
	const char *(*name)();
	const char **(*ciphers)();
	bool (*init)(void **param);
	bool (*free)(void *param);
	bool (*random)(void *param, const size_t size, void *dst);
	bool (*set_cipher)(void *param, const char *cipher);
	size_t (*buffer_size)(const size_t size);
	size_t (*encrypt)(void *param, const size_t size, void *dst, const void *src);
	size_t (*decrypt)(void *param, const size_t size, void *dst, const void *src);
} Crypto;

double seconds();

bool validate(const size_t size, const void *buf_1, const void *buf_2);

void *zero_malloc(const size_t size);
