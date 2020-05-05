#include "wolfcrypt.h"

#ifdef HAS_WOLFSSL_OPTIONS
# include <wolfssl/options.h>
#endif

#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/chacha20_poly1305.h>

#include <wolfssl/wolfcrypt/random.h>

typedef struct WolfCryptParam {
	byte key[KEY_SIZE];
	byte iv[IV_SIZE];
	byte tag[TAG_SIZE];
	WC_RNG rng;
	Aes aes;
	const char *current_cipher;
} WolfCryptParam;

const char *wolfcrypt_name() {
	return "wolfCrypt";
}

const char **wolfcrypt_ciphers() {
	static const char *names[] = {
		CIPHER_AES_256_GCM,
		CIPHER_CHACHA20_POLY1305,
		NULL
	};

	return names;
}

bool wolfcrypt_init(void **param) {
	if (!param) {
		return false;
	}

	int ret = wolfCrypt_Init();
	if (ret != 0) {
		printf("wolfcrypt_init(): wolfCrypt_Init() failed with error %d\n", ret);
		return false;
	}

	WolfCryptParam *wcp = malloc(sizeof(WolfCryptParam));

	ret = wc_InitRng(&wcp->rng);
	if (ret != 0) {
		printf("wolfcrypt_init(): wc_InitRng() failed with error %d\n", ret);
		free(wcp);
		return false;
	}

	*param = wcp;

	return true;
}

bool wolfcrypt_free(void *param) {
	if (!param) {
		return false;
	}

	bool ok = true;

	int ret = wc_FreeRng(&((WolfCryptParam *)param)->rng);
	if (ret != 0) {
		printf("wolfcrypt_cleanup(): wc_FreeRng() failed with error %d\n", ret);
		ok = false;
	}

	ret = wolfCrypt_Cleanup();
	if (ret != 0) {
		printf("wolfcrypt_cleanup(): wolfCrypt_Cleanup() failed with error %d!\n", ret);
		ok = false;
	}

	free(param);

	return ok;
}

bool wolfcrypt_random(void *param, const size_t size, void *dst) {
	if (!param || !dst) {
		return false;
	}

	const int ret = wc_RNG_GenerateBlock(&((WolfCryptParam *)param)->rng, dst, size);
	if (ret != 0) {
		printf("wolfcrypt_random(): wc_RNG_GenerateBlock() failed with error %d\n", ret);
		return false;
	}

	return true;
}

bool wolfcrypt_set_cipher(void *param, const char *cipher) {
	if (!param || !cipher) {
		return false;
	}

	WolfCryptParam *wcp = param;

	if (cipher == CIPHER_AES_256_GCM) {
		const int ret = wc_AesGcmSetKey(&wcp->aes, wcp->key, sizeof(wcp->key));
		if (ret != 0) {
			printf("wolfcrypt_set_cipher(): wc_AesGcmSetKey() failed with error %d\n", ret);
			return false;
		}

		wcp->current_cipher = CIPHER_AES_256_GCM;
	} else if (cipher == CIPHER_CHACHA20_POLY1305) {
		wcp->current_cipher = CIPHER_CHACHA20_POLY1305;
	} else {
		printf("wolfcrypt_set_cipher(): \"%s\" is not a recognized cipher!\n", cipher);
		return false;
	}

	if (!wolfcrypt_random(param, sizeof(wcp->key), wcp->key)) {
		printf("wolfcrypt_set_cipher(): wolfcrypt_random() failed to generate the key!\n");
		return false;
	}

	if (!wolfcrypt_random(param, sizeof(wcp->iv), wcp->iv)) {
		printf("wolfcrypt_set_cipher(): wolfcrypt_random() failed to generate the IV!\n");
		return false;
	}

	return true;
}

size_t wolfcrypt_buffer_size(size_t size) {
	return size;
}

size_t wolfcrypt_encrypt(void *param, const size_t size, void *dst, const void *src) {
	if (!param || !dst || !src) {
		return 0;
	}

	WolfCryptParam *wcp = param;

	if (wcp->current_cipher == CIPHER_AES_256_GCM) {
		const int ret = wc_AesGcmEncrypt(&wcp->aes, dst, src, size, wcp->iv, sizeof(wcp->iv), wcp->tag, sizeof(wcp->tag), NULL, 0);
		if (ret != 0) {
			printf("wolfcrypt_encrypt(): wc_AesGcmEncrypt() failed with error %d\n", ret);
			return 0;
		}
	} else if (wcp->current_cipher == CIPHER_CHACHA20_POLY1305) {
		const int ret = wc_ChaCha20Poly1305_Encrypt(wcp->key, wcp->iv, NULL, 0, src, size, dst, wcp->tag);
		if (ret != 0) {
			printf("wolfcrypt_encrypt(): wc_ChaCha20Poly1305_Encrypt() failed with error %d\n", ret);
			return 0;
		}
	} else {
		return 0;
	}

	return size;
}

size_t wolfcrypt_decrypt(void *param, const size_t size, void *dst, const void *src) {
	if (!param || !dst || !src) {
		return 0;
	}

	WolfCryptParam *wcp = param;

	if (wcp->current_cipher == CIPHER_AES_256_GCM) {
		const int ret = wc_AesGcmDecrypt(&wcp->aes, dst, src, size, wcp->iv, sizeof(wcp->iv), wcp->tag, sizeof(wcp->tag), NULL, 0);
		if (ret != 0) {
			printf("wolfcrypt_decrypt(): wc_AesGcmDecrypt() failed with error %d\n", ret);
			return 0;
		}
	} else if (wcp->current_cipher == CIPHER_CHACHA20_POLY1305) {
		const int ret = wc_ChaCha20Poly1305_Decrypt(wcp->key, wcp->iv, NULL, 0, src, size, wcp->tag, dst);
		if (ret != 0) {
			printf("wolfcrypt_decrypt(): wc_ChaCha20Poly1305_Decrypt() failed with error %d\n", ret);
			return 0;
		}
	} else {
		return 0;
	}

	return size;
}

const Crypto *wolfcrypt_get() {
	static const Crypto crypto = {
		wolfcrypt_name,
		wolfcrypt_ciphers,
		wolfcrypt_init,
		wolfcrypt_free,
		wolfcrypt_random,
		wolfcrypt_set_cipher,
		wolfcrypt_buffer_size,
		wolfcrypt_encrypt,
		wolfcrypt_decrypt
	};

	return &crypto;
}
