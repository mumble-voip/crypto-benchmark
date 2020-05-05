#include "nss.h"
#include "utils.h"

#include <nspr/prerror.h>

#include <nss/nss.h>
#include <nss/pk11pub.h>

#define KEY_SIZE 32
#define IV_SIZE 12
#define TAG_SIZE 16

bool nss_main(const size_t message_size, const size_t iterations) {
	if (NSS_NoDB_Init(NULL) != SECSuccess) {
		printf("nss_main(): NSS_NoDB_Init() failed with error %d\n", PR_GetError());
		return false;
	}

	PK11SlotInfo *slot = PK11_GetInternalSlot();
	if (!slot) {
		printf("nss_main(): PK11_GetInternalSlot() failed with error %d\n", PR_GetError());
		return false;
	}

	bool ok = false;

	unsigned char message[message_size], out[message_size];
	if (PK11_GenerateRandomOnSlot(slot, message, sizeof(message)) != SECSuccess) {
		printf("nss_main(): PK11_GenerateRandomOnSlot() failed with error %d\n", PR_GetError());
		goto FINAL;
	}

	double elapsed;

	if (!(elapsed = nss_aes_256_gcm(iterations, slot, out, sizeof(message), message))) {
		printf("nss_main(): nss_aes_256_gcm() failed!\n");
		goto FINAL;
	}

	printf("[NSS] AES-256-GCM took %f seconds for %zu iterations, %zu bytes message\n", elapsed, iterations, message_size);

	if (!(elapsed = nss_chacha20_poly1305(iterations, slot, out, sizeof(message), message))) {
		printf("nss_main(): nss_chacha20_poly1305() failed!\n");
		goto FINAL;
	}

	printf("[NSS] ChaCha20-Poly1305 took %f seconds for %zu iterations, %zu bytes message\n", elapsed, iterations, message_size);

	ok = true;

FINAL:
	PK11_FreeSlot(slot);
	return ok;
}

double nss_aes_256_gcm(const size_t iterations, PK11SlotInfo *slot, unsigned char *dst, const unsigned int size, const unsigned char *src) {
	unsigned char iv[IV_SIZE];
	if (PK11_GenerateRandomOnSlot(slot, iv, sizeof(iv)) != SECSuccess) {
		printf("nss_aes_256_gcm(): PK11_GenerateRandomOnSlot() failed with error %d\n", PR_GetError());
		return 0;
	}

	PK11SymKey *key = PK11_KeyGen(slot, CKM_AES_GCM, NULL, KEY_SIZE, NULL);
	if (!key) {
		printf("nss_aes_256_gcm(): PK11_KeyGen() failed with error %d\n", PR_GetError());
		return 0;
	}

	CK_GCM_PARAMS gcm_params;
	gcm_params.pAAD = NULL;
	gcm_params.pIv = iv;
	gcm_params.ulAADLen = 0;
	gcm_params.ulIvLen = sizeof(iv);
	gcm_params.ulTagBits = TAG_SIZE * 8;

	SECItem params;
	params.data = (unsigned char *)&gcm_params;
	params.len = sizeof(gcm_params);
	params.type = siBuffer;

	// The tag is appended to the output buffer.
	unsigned char tmp[size + gcm_params.ulTagBits];
	unsigned int written;
	double elapsed = 0;

	const double start = seconds();

	for (size_t i = 0; i < iterations; ++i) {
		if (PK11_Encrypt(key, CKM_AES_GCM, &params, tmp, &written, sizeof(tmp), src, size) != SECSuccess) {
			printf("nss_aes_256_gcm(): PK11_Encrypt() failed with error %d\n", PR_GetError());
			goto FINAL;
		}

		if (PK11_Decrypt(key, CKM_AES_GCM, &params, tmp, &written, sizeof(tmp), tmp, written) != SECSuccess) {
			printf("nss_aes_256_gcm(): PK11_Decrypt() failed with error %d\n", PR_GetError());
			goto FINAL;
		}
	}

	elapsed = seconds() - start;

	memcpy(dst, tmp, size);

	validate(size, dst, src);

FINAL:
	PK11_FreeSymKey(key);
	return elapsed;
}

double nss_chacha20_poly1305(const size_t iterations, PK11SlotInfo *slot, unsigned char *dst, const unsigned int size, const unsigned char *src) {
	unsigned char iv[IV_SIZE];
	if (PK11_GenerateRandomOnSlot(slot, iv, sizeof(iv)) != SECSuccess) {
		printf("nss_chacha20_poly1305(): PK11_GenerateRandomOnSlot() failed with error %d\n", PR_GetError());
		return 0;
	}

	PK11SymKey *key = PK11_KeyGen(slot, CKM_NSS_CHACHA20_POLY1305, NULL, KEY_SIZE, NULL);
	if (!key) {
		printf("nss_chacha20_poly1305(): PK11_KeyGen() failed with error %d\n", PR_GetError());
		return 0;
	}

	CK_NSS_AEAD_PARAMS aead_params;
	aead_params.pAAD = NULL;
	aead_params.pNonce = iv;
	aead_params.ulAADLen = 0;
	aead_params.ulNonceLen = sizeof(iv);
	aead_params.ulTagLen = TAG_SIZE;

	SECItem params;
	params.data = (unsigned char *)&aead_params;
	params.len = sizeof(aead_params);
	params.type = siBuffer;

	// The tag is appended to the output buffer.
	unsigned char tmp[size + aead_params.ulTagLen];
	unsigned int written;
	double elapsed = 0;

	const double start = seconds();

	for (size_t i = 0; i < iterations; ++i) {
		if (PK11_Encrypt(key, CKM_NSS_CHACHA20_POLY1305, &params, tmp, &written, sizeof(tmp), src, size) != SECSuccess) {
			printf("nss_chacha20_poly1305(): PK11_Encrypt() failed with error %d\n", PR_GetError());
			goto FINAL;
		}

		if (PK11_Decrypt(key, CKM_NSS_CHACHA20_POLY1305, &params, tmp, &written, sizeof(tmp), tmp, written) != SECSuccess) {
			printf("nss_chacha20_poly1305(): PK11_Decrypt() failed with error %d\n", PR_GetError());
			goto FINAL;
		}
	}

	elapsed = seconds() - start;

	memcpy(dst, tmp, size);

	validate(size, dst, src);

FINAL:
	PK11_FreeSymKey(key);
	return elapsed;
}
