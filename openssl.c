#include "openssl.h"

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define KEY_SIZE 32
#define IV_SIZE 12
#define TAG_SIZE 16

#define openssl_error() (ERR_error_string(ERR_get_error(), NULL))

typedef struct OpenSSLParam {
	unsigned char key[KEY_SIZE];
	unsigned char iv[IV_SIZE];
	unsigned char tag[TAG_SIZE];
	EVP_CIPHER_CTX *ctx_encrypt;
	EVP_CIPHER_CTX *ctx_decrypt;
	const EVP_CIPHER *current_cipher;
} OpenSSLParam;

int openssl_aead(OpenSSLParam *op, const bool enc, unsigned char *dst, const int size, const unsigned char *src);

const char *openssl_name() {
	return "OpenSSL";
}

const char **openssl_ciphers() {
	static const char *names[] = {
		CIPHER_AES_256_GCM,
		CIPHER_AES_256_OCB,
		CIPHER_CHACHA20_POLY1305,
		NULL
	};

	return names;
}

bool openssl_init(void **param) {
	if (!param) {
		return false;
	}

	OpenSSLParam *op = malloc(sizeof(OpenSSLParam));

	op->ctx_encrypt = EVP_CIPHER_CTX_new();
	op->ctx_decrypt = EVP_CIPHER_CTX_new();

	*param = op;

	return true;
}

bool openssl_free(void *param) {
	if (!param) {
		return false;
	}

	OpenSSLParam *op = param;

	EVP_CIPHER_CTX_free(op->ctx_encrypt);
	EVP_CIPHER_CTX_free(op->ctx_decrypt);

	return true;
}

bool openssl_random(void *param, const size_t size, void *dst) {
	if (!param || !dst) {
		return false;
	}

	if (!RAND_bytes(dst, size)) {
		printf("openssl_random(): RAND_bytes() failed with error: %s\n", openssl_error());
		return false;
	}

	return true;
}

bool openssl_set_cipher(void *param, const char *cipher) {
	if (!param || !cipher) {
		return false;
	}

	OpenSSLParam *op = param;

	if (cipher == CIPHER_AES_256_GCM) {
		op->current_cipher = EVP_aes_256_gcm();
	} else if (cipher == CIPHER_AES_256_OCB) {
		op->current_cipher = EVP_aes_256_ocb();
	} else if (cipher == CIPHER_CHACHA20_POLY1305) {
		op->current_cipher = EVP_chacha20_poly1305();
	} else {
		printf("openssl_set_cipher(): \"%s\" is not a recognized cipher!\n", cipher);
		return false;
	}

	if (!openssl_random(param, sizeof(op->key), op->key)) {
		printf("openssl_set_cipher(): openssl_random() failed to generate the key!\n");
		return false;
	}

	if (!openssl_random(param, sizeof(op->iv), op->iv)) {
		printf("openssl_set_cipher(): openssl_random() failed to generate the IV!\n");
		return false;
	}

	if (!EVP_CipherInit(op->ctx_encrypt, op->current_cipher, op->key, op->iv, 1)) {
		printf("openssl_set_cipher(): [encrypt] EVP_CipherInit() failed with error: %s\n", openssl_error());
		return false;
	}

	if (!EVP_CipherInit(op->ctx_decrypt, op->current_cipher, op->key, op->iv, 0)) {
		printf("openssl_set_cipher(): [decrypt] EVP_CipherInit() failed with error: %s\n", openssl_error());
		return false;
	}

	return true;
}

size_t openssl_buffer_size(const size_t size) {
	return size;
}

size_t openssl_encrypt(void *param, const size_t size, void *dst, const void *src) {
	if (!param || !dst || !src) {
		return 0;
	}

	const size_t ret = openssl_aead(param, 1, dst, size, src);
	if (!ret) {
		printf("openssl_encrypt(): openssl_aead() failed!\n");
	}

	return ret;
}

size_t openssl_decrypt(void *param, const size_t size, void *dst, const void *src) {
	if (!param || !dst || !src) {
		return 0;
	}

	const size_t ret = openssl_aead(param, 0, dst, size, dst);
	if (!ret) {
		printf("openssl_decrypt(): openssl_aead() failed!\n");
	}

	return ret;
}

int openssl_aead(OpenSSLParam *op, const bool enc, unsigned char *dst, const int size, const unsigned char *src) {
	EVP_CIPHER_CTX *ctx = enc ? op->ctx_encrypt : op->ctx_decrypt;

	if (op->current_cipher == EVP_aes_256_gcm() || op->current_cipher == EVP_aes_256_ocb()) {
		// EVP_CipherUpdate() fails if we don't specify the IV every time.
		EVP_CipherInit(ctx, NULL, NULL, op->iv, -1);
	}

	if (!enc && !EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, TAG_SIZE, op->tag)) {
		printf("openssl_aead(): EVP_CIPHER_CTX_ctrl() failed to set the tag!\n");
		return 0;
	}

	int out = size;

	if (!EVP_CipherUpdate(ctx, dst, &out, src, size)) {
		printf("openssl_aead(): EVP_CipherUpdate() failed with error: %s\n", openssl_error());
		return 0;
	}

	int out_2;

	if (!EVP_CipherFinal(ctx, dst + out, &out_2)) {
		printf("openssl_aead(): EVP_CipherFinal() failed with error: %s\n", openssl_error());
		return 0;
	}

	if (enc && !EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, TAG_SIZE, op->tag)) {
		printf("openssl_aead(): EVP_CIPHER_CTX_ctrl() failed to get the tag!\n");
		return 0;
	}

	return out + out_2;
}

const Crypto *openssl_get() {
	static const Crypto crypto = {
		openssl_name,
		openssl_ciphers,
		openssl_init,
		openssl_free,
		openssl_random,
		openssl_set_cipher,
		openssl_buffer_size,
		openssl_encrypt,
		openssl_decrypt
	};

	return &crypto;
}
