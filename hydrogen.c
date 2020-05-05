#include "hydrogen.h"

#include <hydrogen.h>

#include <stdio.h>

#define CONTEXT "benchmark"

typedef struct HydrogenParam {
	uint8_t key[hydro_secretbox_KEYBYTES];
} HydrogenParam;

const char *hydrogen_name() {
	return "libhydrogen";
}

const char **hydrogen_ciphers() {
	static const char *names[] = {
		CIPHER_GIMLI_CURVE25519,
		NULL
	};

	return names;
}

bool hydrogen_init(void **param) {
	if (!param) {
		return false;
	}

	if (hydro_init() != 0) {
		printf("hydrogen_init(): hydro_init() failed!\n");
		return false;
	}

	*param = malloc(sizeof(HydrogenParam));

	return true;
}

bool hydrogen_free(void *param) {
	if (!param) {
		return false;
	}

	free(param);

	return true;
}

bool hydrogen_random(void *param, const size_t size, void *dst) {
	if (!param || !dst) {
		return false;
	}

	hydro_random_buf(dst, sizeof(size));
	return true;
}

bool hydrogen_set_cipher(void *param, const char *cipher) {
	if (!param || !cipher) {
		return false;
	}

	if (cipher != CIPHER_GIMLI_CURVE25519) {
		printf("hydrogen_set_cipher(): \"%s\" is not a recognized cipher!\n", cipher);
		return false;
	}

	hydro_secretbox_keygen(((HydrogenParam *)param)->key);

	return true;
}

size_t hydrogen_buffer_size(const size_t size) {
	return size + hydro_secretbox_HEADERBYTES;
}

size_t hydrogen_encrypt(void *param, const size_t size, void *dst, const void *src) {
	if (!param || !dst || !src) {
		return 0;
	}

	hydro_secretbox_encrypt(dst, src, size, 0, CONTEXT, ((HydrogenParam *)param)->key);

	return size;
}

size_t hydrogen_decrypt(void *param, const size_t size, void *dst, const void *src) {
	if (!param || !dst || !src) {
		return 0;
	}

	if (hydro_secretbox_decrypt(dst, dst, hydrogen_buffer_size(size), 0, CONTEXT,((HydrogenParam *)param)->key) != 0) {
		printf("hydrogen_encrypt(): hydro_secretbox_decrypt() failed!\n");
		return 0;
	}

	return size;
}

const Crypto *hydrogen_get() {
	static const Crypto crypto = {
		hydrogen_name,
		hydrogen_ciphers,
		hydrogen_init,
		hydrogen_free,
		hydrogen_random,
		hydrogen_set_cipher,
		hydrogen_buffer_size,
		hydrogen_encrypt,
		hydrogen_decrypt
	};

	return &crypto;
}
