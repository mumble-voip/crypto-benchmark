#include "sodium.h"
#include "utils.h"

#include <sodium.h>

bool sodium_main(const size_t message_size, const size_t iterations) {
	unsigned char message[message_size], out[message_size];
	randombytes_buf(message, sizeof(message));

	double elapsed;

	if (!(elapsed = sodium_aes_256_gcm(iterations, out, sizeof(message), message))) {
		printf("sodium_main(): sodium_aes_256_gcm() failed!\n");
		return false;
	}

	printf("[libsodium] AES-256-GCM took %f seconds for %zu iterations, %zu bytes message\n", elapsed, iterations, message_size);

	if (!(elapsed = sodium_chacha20_poly1305(iterations, out, sizeof(message), message))) {
		printf("sodium_main(): sodium_chacha20_poly1305() failed!\n");
		return false;
	}

	printf("[libsodium] ChaCha20-Poly1305 took %f seconds for %zu iterations, %zu bytes message\n", elapsed, iterations, message_size);

	return true;
}

double sodium_aes_256_gcm(const size_t iterations, unsigned char *dst, const unsigned long long size, const unsigned char *src) {
	unsigned char key[crypto_aead_aes256gcm_KEYBYTES];
	unsigned char iv[crypto_aead_aes256gcm_NPUBBYTES];
	unsigned char tag[crypto_aead_aes256gcm_ABYTES];

	crypto_aead_aes256gcm_keygen(key);
	randombytes_buf(iv, sizeof(iv));

	crypto_aead_aes256gcm_state ctx;
	crypto_aead_aes256gcm_beforenm(&ctx, key);

	const double start = seconds();

	for (size_t i = 0; i < iterations; ++i) {
		if (crypto_aead_aes256gcm_encrypt_detached_afternm(dst, tag, NULL, src, size, NULL, 0, NULL, iv, &ctx) != 0) {
			printf("sodium_aes_256_gcm(): crypto_aead_aes256gcm_encrypt_detached_afternm() failed!\n");
			return 0;
		}

		if (crypto_aead_aes256gcm_decrypt_detached_afternm(dst, NULL, dst, size, tag, NULL, 0, iv, &ctx) != 0) {
			printf("sodium_aes_256_gcm(): crypto_aead_chacha20poly1305_ietf_decrypt_detached() failed!\n");
			return 0;
		}
	}

	const double elapsed = seconds() - start;

	validate(size, dst, src);

	return elapsed;
}

double sodium_chacha20_poly1305(const size_t iterations, unsigned char *dst, const unsigned long long size, const unsigned char *src) {
	unsigned char key[crypto_aead_chacha20poly1305_ietf_KEYBYTES];
	unsigned char iv[crypto_aead_chacha20poly1305_ietf_NPUBBYTES];
	unsigned char tag[crypto_aead_chacha20poly1305_ietf_ABYTES];

	crypto_aead_chacha20poly1305_ietf_keygen(key);
	randombytes_buf(iv, sizeof(iv));

	const double start = seconds();

	for (size_t i = 0; i < iterations; ++i) {
		if (crypto_aead_chacha20poly1305_ietf_encrypt_detached(dst, tag, NULL, src, size, NULL, 0, NULL, iv, key) != 0) {
			printf("sodium_chacha20_poly1305(): crypto_aead_chacha20poly1305_ietf_encrypt_detached() failed!\n");
			return 0;
		}

		if (crypto_aead_chacha20poly1305_ietf_decrypt_detached(dst, NULL, dst, size, tag, NULL, 0, iv, key) != 0) {
			printf("sodium_chacha20_poly1305(): crypto_aead_chacha20poly1305_ietf_decrypt_detached() failed!\n");
			return 0;
		}
	}

	const double elapsed = seconds() - start;

	validate(size, dst, src);

	return elapsed;
}
