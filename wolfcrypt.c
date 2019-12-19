#include "wolfcrypt.h"
#include "utils.h"

#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/chacha20_poly1305.h>

bool wolfcrypt_main(const size_t message_size, const size_t iterations) 	{
	unsigned char message[message_size], out[message_size];
	bool ok = false;
	double elapsed;

	WC_RNG rng;
	if (!wolfcrypt_init(&rng)) {
		printf("wolfcrypt_main(): wolfcrypt_init() failed!\n");
		goto FINAL;
	}

	if (!wolfcrypt_random(&rng, sizeof(message), message)) {
		printf("wolfcrypt_main(): wolfcrypt_random() failed!\n");
		goto FINAL;
	}

	if (!(elapsed = wolfcrypt_aes_256_gcm(iterations, &rng, out, sizeof(message), message))) {
		printf("wolfcrypt_main(): wolfcrypt_aes_256_gcm() failed!\n");
		goto FINAL;
	}

	printf("[wolfCrypt] AES-256-GCM took %f seconds for %zu iterations, %zu bytes message\n", elapsed, iterations, message_size);

	if (!(elapsed = wolfcrypt_chacha20_poly1305(iterations, &rng, out, sizeof(message), message))) {
		printf("wolfcrypt_main(): wolfcrypt_chacha20_poly1305() failed!\n");
		goto FINAL;
	}

	printf("[wolfCrypt] ChaCha20-Poly1305 took %f seconds for %zu iterations, %zu bytes message\n", elapsed, iterations, message_size);

	ok = true;

FINAL:
	if (!wolfcrypt_cleanup(&rng)) {
		printf("wolfcrypt_main(): wolfcrypt_cleanup() failed!\n");
		return false;
	}

	return ok;
}

bool wolfcrypt_random(WC_RNG *rng, const size_t size, byte *out) { 
	const int ret = wc_RNG_GenerateBlock(rng, out, size);
	if (ret != 0) {
		printf("wolfcrypt_random(): wc_RNG_GenerateBlock() failed with error %d\n", ret);
		return false;
	}

	return true;
}

double wolfcrypt_aes_256_gcm(const size_t iterations, WC_RNG *rng, byte *dst, const word32 size, const byte *src) {
	byte key[AES_256_KEY_SIZE];
	byte iv[GCM_NONCE_MID_SZ];
	byte tag[AES_BLOCK_SIZE];

	if (!wolfcrypt_random(rng, sizeof(key), key)) {
		printf("wolfcrypt_aes_256_gcm(): wolfcrypt_random() failed to generate the key!\n");
		return 0;
	}

	if (!wolfcrypt_random(rng, sizeof(iv), iv)) {
		printf("wolfcrypt_aes_256_gcm(): wolfcrypt_random() failed to generate the IV!\n");
		return 0;
	}

	int ret;

	Aes encrypt_aes;
	ret = wc_AesGcmSetKey(&encrypt_aes, key, sizeof(key));
	if (ret != 0) {
		printf("wolfcrypt_aes_256_gcm(): [encrypt] wc_AesGcmSetKey() failed with error %d\n", ret);
		return 0;
	}

	Aes decrypt_aes;
	ret = wc_AesGcmSetKey(&decrypt_aes, key, sizeof(key));
	if (ret != 0) {
		printf("wolfcrypt_aes_256_gcm(): [decrypt] wc_AesGcmSetKey() failed with error %d\n", ret);
		return 0;
	}

	const double start = seconds();

	for (size_t i = 0; i < iterations; ++i) {
		ret = wc_AesGcmEncrypt(&encrypt_aes, dst, src, size, iv, sizeof(iv), tag, sizeof(tag), NULL, 0);
		if (ret != 0) {
			printf("wolfcrypt_aes_256_gcm(): wc_AesGcmEncrypt() failed with error %d\n", ret);
			return 0;
		}

		ret = wc_AesGcmDecrypt(&decrypt_aes, dst, dst, size, iv, sizeof(iv), tag, sizeof(tag), NULL, 0);
		if (ret != 0) {
			printf("wolfcrypt_aes_256_gcm(): wc_AesGcmDecrypt() failed with error %d\n", ret);
			return 0;
		}
	}

	const double elapsed = seconds() - start;

	validate(size, dst, src);

	return elapsed;
}

double wolfcrypt_chacha20_poly1305(const size_t iterations, WC_RNG *rng, byte *dst, const word32 size, const byte *src) {
	byte key[CHACHA20_POLY1305_AEAD_KEYSIZE];
	byte iv[CHACHA20_POLY1305_AEAD_IV_SIZE];
	byte tag[CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE];

	if (!wolfcrypt_random(rng, sizeof(key), key)) {
		printf("wolfcrypt_chacha20_poly1305(): wolfcrypt_random() failed to generate the key!\n");
		return 0;
	}

	if (!wolfcrypt_random(rng, sizeof(iv), iv)) {
		printf("wolfcrypt_chacha20_poly1305(): wolfcrypt_random() failed to generate the IV!\n");
		return 0;
	}

	int ret;

	const double start = seconds();

	for (size_t i = 0; i < iterations; ++i) {
		ret = wc_ChaCha20Poly1305_Encrypt(key, iv, NULL, 0, src, size, dst, tag);
		if (ret != 0) {
			printf("wolfcrypt_chacha20_poly1305(): wc_ChaCha20Poly1305_Encrypt() failed with error %d\n", ret);
			return 0;
		}

		ret = wc_ChaCha20Poly1305_Decrypt(key, iv, NULL, 0, dst, size, tag, dst);
		if (ret != 0) {
			printf("wolfcrypt_chacha20_poly1305(): wc_ChaCha20Poly1305_Decrypt() failed with error %d\n", ret);
			return 0;
		}
	}

	const double elapsed = seconds() - start;

	validate(size, dst, src);

	return elapsed;
}

bool wolfcrypt_init(WC_RNG *rng) {
	int ret = wolfCrypt_Init();
	if (ret != 0) {
		printf("wolfcrypt_init(): wolfCrypt_Init() failed with error %d\n", ret);
		return false;
	}

	ret = wc_InitRng(rng);
	if (ret != 0) {
		printf("wolfcrypt_init(): wc_InitRng() failed with error %d\n", ret);
		return false;
	}

	return true;
}

bool wolfcrypt_cleanup(WC_RNG *rng) {
	bool ok = true;

	int ret = wc_FreeRng(rng);
	if (ret != 0) {
		printf("wolfcrypt_cleanup(): wc_FreeRng() failed with error %d\n", ret);
		ok = false;
	}

	ret = wolfCrypt_Cleanup();
	if (ret != 0) {
		printf("wolfcrypt_cleanup(): wolfCrypt_Cleanup() failed with error %d!\n", ret);
		ok = false;
	}

	return ok;
}
