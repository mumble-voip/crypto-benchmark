#include "openssl.h"
#include "utils.h"

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define openssl_error() (ERR_error_string(ERR_get_error(), NULL))

bool openssl_main(const size_t message_size, const size_t iterations) {
	unsigned char message[message_size], out[message_size];
	RAND_bytes(message, sizeof(message));

	double elapsed;

	if (!(elapsed = openssl_aead(EVP_aes_256_gcm(), iterations, out, sizeof(message), message))) {
		printf("openssl_main(): openssl_aead() failed!\n");
		return false;
	}

	printf("[OpenSSL] AES-256-GCM took %f seconds for %zu iterations, %zu bytes message\n", elapsed, iterations, message_size);

	if (!(elapsed = openssl_aead(EVP_aes_256_ocb(), iterations, out, sizeof(message), message))) {
		printf("openssl_main(): openssl_aead() failed!\n");
		return false;
	}

	printf("[OpenSSL] AES-256-OCB took %f seconds for %zu iterations, %zu bytes message\n", elapsed, iterations, message_size);

	if (!(elapsed = openssl_aead(EVP_chacha20_poly1305(), iterations, out, sizeof(message), message))) {
		printf("openssl_main(): openssl_aead() failed!\n");
		return false;
	}

	printf("[OpenSSL] ChaCha20-Poly1305 took %f seconds for %zu iterations, %zu bytes message\n", elapsed, iterations, message_size);

	return true;
}

int openssl_process(EVP_CIPHER_CTX *ctx, const bool enc, const unsigned char *key, const unsigned char *iv, const int tag_size, unsigned char *tag, unsigned char *dst, const int src_size, const unsigned char *src) {
	if (!EVP_CipherInit(ctx, NULL, key, iv, enc)) {
		printf("openssl_process(): EVP_CipherInit() failed with error: %s\n", openssl_error());
		return 0;
	}

	if (!enc && !EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, tag_size, tag)) {
		printf("openssl_process(): EVP_CIPHER_CTX_ctrl() failed to set the tag!\n");
		return 0;
	}

	int out = src_size;

	if (!EVP_CipherUpdate(ctx, dst, &out, src, src_size)) {
		printf("openssl_process(): EVP_CipherUpdate() failed with error: %s\n", openssl_error());
		return 0;
	}

	int out_2;

	if (!EVP_CipherFinal(ctx, dst + out, &out_2)) {
		printf("openssl_process(): EVP_CipherFinal() failed with error: %s\n", openssl_error());
		return 0;
	}

	if (enc && !EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, tag_size, tag)) {
		printf("openssl_process(): EVP_CIPHER_CTX_ctrl() failed to get the tag!\n");
		return 0;
	}

	return out + out_2;
}

double openssl_aead(const EVP_CIPHER *cipher, const size_t iterations, unsigned char *dst, const int size, const unsigned char *src) {
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

	if (!EVP_CipherInit(ctx, cipher, NULL, NULL, -1)) {
		printf("openssl_aead(): EVP_CipherInit() failed with error: %s\n", openssl_error());
		EVP_CIPHER_CTX_free(ctx);
		return 0;
	}

	unsigned char key[EVP_CIPHER_CTX_key_length(ctx)];
	unsigned char iv[EVP_CIPHER_CTX_iv_length(ctx)];
	unsigned char tag[16]; // EVP_CIPHER_CTX_tag_length() not in OpenSSL 1.1.1

	EVP_CIPHER_CTX_rand_key(ctx, key);

	RAND_bytes(iv, sizeof(iv));

	double elapsed = 0;
	const double start = seconds();

	for (size_t i = 0; i < iterations; ++i) {
		if (!openssl_process(ctx, 1, key, iv, sizeof(tag), tag, dst, size, src)) {
			printf("openssl_aead(): [encrypt] openssl_process() returned 0!\n");
			goto FINAL;
		}

		if (!openssl_process(ctx, 0, key, iv, sizeof(tag), tag, dst, size, dst)) {
			printf("openssl_aead(): [decrypt] openssl_process() returned 0!\n");
			goto FINAL;
		}
	}

	elapsed = seconds() - start;

	validate(size, dst, src);

FINAL:
	EVP_CIPHER_CTX_free(ctx);
	return elapsed;
}
