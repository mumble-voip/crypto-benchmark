#include "sodium.h"

#include <sodium.h>

typedef struct SodiumParam {
	unsigned char key[KEY_SIZE];
	unsigned char iv[IV_SIZE];
	unsigned char tag[TAG_SIZE];
	const char *current_cipher;
	crypto_aead_aes256gcm_state ctx;
} SodiumParam;

const char *sodium_name() {
	return "libsodium";
}

const char **sodium_ciphers() {
	static const char *names[] = {
		CIPHER_AEGIS_256,
		CIPHER_AES_256_GCM,
		CIPHER_CHACHA20_POLY1305,
		NULL
	};

	return names;
}

bool sodium_init_(void **param) {
	if (!param) {
		return false;
	}

	if (sodium_init() == -1) {
		printf("sodium_init_(): sodium_init() failed!\n");
		return false;
	}

	*param = malloc(sizeof(SodiumParam));

	return true;
}

bool sodium_free_(void *param) {
	if (!param) {
		return false;
	}

	free(param);

	return true;
}

bool sodium_random(void *param, const size_t size, void *dst) {
	if (!param || !dst) {
		return false;
	}

	randombytes_buf(dst, size);

	return true;
}

bool sodium_set_cipher(void *param, const char *cipher) {
	if (!param || !cipher) {
		return false;
	}

	SodiumParam *sp = param;

	if (cipher == CIPHER_AEGIS_256) {
		sp->current_cipher = CIPHER_AEGIS_256;
		crypto_aead_aegis256_keygen(sp->key);
	} else if (cipher == CIPHER_AES_256_GCM) {
		if (!crypto_aead_aes256gcm_is_available()) {
			printf("sodium_set_cipher(): AES-256-GCM requires SSSE3 extensions + \"aesni\" and \"pclmul\" instructions.\n");
			return false;
		}

		sp->current_cipher = CIPHER_AES_256_GCM;
		crypto_aead_aes256gcm_keygen(sp->key);
		crypto_aead_aes256gcm_beforenm(&sp->ctx, sp->key);
	} else if (cipher == CIPHER_CHACHA20_POLY1305) {
		sp->current_cipher = CIPHER_CHACHA20_POLY1305;
		crypto_aead_chacha20poly1305_ietf_keygen(sp->key);
	} else {
		printf("sodium_set_cipher(): \"%s\" is not a recognized cipher!\n", cipher);
		return false;
	}

	sodium_random(param, sizeof(sp->iv), sp->iv);

	return true;
}

size_t sodium_buffer_size(const size_t size) {
	return size;
}

size_t sodium_encrypt(void *param, const size_t size, void *dst, const void *src) {
	if (!param || !dst || !src) {
		return 0;
	}

	SodiumParam *sp = param;

	if (sp->current_cipher == CIPHER_AEGIS_256) {
		if (crypto_aead_aegis256_encrypt_detached(dst, sp->tag, NULL, src, size, NULL, 0, NULL, sp->iv, sp->key) != 0) {
			printf("sodium_encrypt(): crypto_aead_aegis256_encrypt_detached() failed!\n");
			return 0;
		}
	} else if (sp->current_cipher == CIPHER_AES_256_GCM) {
		if (crypto_aead_aes256gcm_encrypt_detached_afternm(dst, sp->tag, NULL, src, size, NULL, 0, NULL, sp->iv, &sp->ctx) != 0) {
			printf("sodium_encrypt(): crypto_aead_aes256gcm_encrypt_detached_afternm() failed!\n");
			return 0;
		}
	} else if (sp->current_cipher == CIPHER_CHACHA20_POLY1305) {
		if (crypto_aead_chacha20poly1305_ietf_encrypt_detached(dst, sp->tag, NULL, src, size, NULL, 0, NULL, sp->iv, sp->key) != 0) {
			printf("sodium_encrypt(): crypto_aead_chacha20poly1305_ietf_encrypt_detached() failed!\n");
			return 0;
		}
	} else {
		return 0;
	}

	return size;
}

size_t sodium_decrypt(void *param, const size_t size, void *dst, const void *src) {
	if (!param || !dst || !src) {
		return 0;
	}

	SodiumParam *sp = param;

	if (sp->current_cipher == CIPHER_AEGIS_256) {
		if (crypto_aead_aegis256_decrypt_detached(dst, NULL, dst, size, sp->tag, NULL, 0, sp->iv, sp->key) != 0) {
			printf("sodium_decrypt(): crypto_aead_aegis256_decrypt_detached() failed!\n");
			return 0;
		}
	} else if (sp->current_cipher == CIPHER_AES_256_GCM) {
		if (crypto_aead_aes256gcm_decrypt_detached_afternm(dst, NULL, dst, size, sp->tag, NULL, 0, sp->iv, &sp->ctx) != 0) {
			printf("sodium_decrypt(): crypto_aead_aes256gcm_decrypt_detached_afternm() failed!\n");
			return 0;
		}
	} else if (sp->current_cipher == CIPHER_CHACHA20_POLY1305) {
		if (crypto_aead_chacha20poly1305_ietf_decrypt_detached(dst, NULL, dst, size, sp->tag, NULL, 0, sp->iv, sp->key) != 0) {
			printf("sodium_decrypt(): crypto_aead_chacha20poly1305_ietf_decrypt_detached() failed!\n");
			return 0;
		}
	} else {
		return 0;
	}

	return size;
}

const Crypto *sodium_get() {
	static const Crypto crypto = {
		sodium_name,
		sodium_ciphers,
		sodium_init_,
		sodium_free_,
		sodium_random,
		sodium_set_cipher,
		sodium_buffer_size,
		sodium_encrypt,
		sodium_decrypt
	};

	return &crypto;
}
