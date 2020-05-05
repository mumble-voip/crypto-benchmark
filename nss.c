#include "nss.h"

#include <nspr/prerror.h>

#include <nss/nss.h>
#include <nss/pk11pub.h>

typedef struct NSSParam {
	PK11SymKey *key;
	PK11SlotInfo *slot;
	CK_MECHANISM_TYPE ckmt;
	unsigned char iv[IV_SIZE];
	SECItem params;
	CK_GCM_PARAMS gcm_params;
	CK_NSS_AEAD_PARAMS aead_params;
} NSSParam;

bool nss_free(void *param);

const char *nss_name() {
	return "NSS";
}

const char **nss_ciphers() {
	static const char *names[] = {
		CIPHER_AES_256_GCM,
		CIPHER_CHACHA20_POLY1305,
		NULL
	};

	return names;
}

bool nss_init(void **param) {
	if (!param) {
		return false;
	}

	if (NSS_NoDB_Init(NULL) != SECSuccess) {
		printf("nss_init(): NSS_NoDB_Init() failed with error %d\n", PR_GetError());
		return false;
	}

	NSSParam *np = zero_malloc(sizeof(NSSParam));

	np->slot = PK11_GetInternalSlot();
	if (!np->slot) {
		printf("nss_init(): PK11_GetInternalSlot() failed with error %d\n", PR_GetError());
		nss_free(np);
		return false;
	}

	np->gcm_params.pAAD = NULL;
	np->gcm_params.pIv = np->iv;
	np->gcm_params.ulAADLen = 0;
	np->gcm_params.ulIvLen = IV_SIZE;
	np->gcm_params.ulTagBits = TAG_SIZE * 8;

	np->aead_params.pAAD = NULL;
	np->aead_params.pNonce = np->iv;
	np->aead_params.ulAADLen = 0;
	np->aead_params.ulNonceLen = IV_SIZE;
	np->aead_params.ulTagLen = TAG_SIZE;

	*param = np;

	return true;
}

bool nss_free(void *param) {
	if (!param) {
		return false;
	}

	NSSParam *np = param;

	if (np->slot) {
		PK11_FreeSlot(np->slot);
	}

	if (np->key) {
		PK11_FreeSymKey(np->key);
	}

	free(np);

	return true;
}

bool nss_random(void *param, const size_t size, void *dst) {
	if (!param || !dst) {
		return false;
	}

	if (PK11_GenerateRandomOnSlot(((NSSParam *)param)->slot, dst, size) != SECSuccess) {
		printf("nss_random(): PK11_GenerateRandomOnSlot() failed with error %d\n", PR_GetError());
		return false;
	}

	return true;
}

bool nss_set_cipher(void *param, const char *cipher) {
	if (!param || !cipher) {
		return false;
	}

	NSSParam *np = param;

	if (cipher == CIPHER_AES_256_GCM) {
		np->ckmt = CKM_AES_GCM;
		np->params.len = sizeof(np->gcm_params);
		np->params.data = (unsigned char *)&np->gcm_params;
	} else if (cipher == CIPHER_CHACHA20_POLY1305) {
		np->ckmt = CKM_NSS_CHACHA20_POLY1305;
		np->params.len = sizeof(np->aead_params);
		np->params.data = (unsigned char *)&np->aead_params;
	} else {
		printf("nss_set_cipher(): \"%s\" is not a recognized cipher!\n", cipher);
		return false;
	}

	np->params.type = siBuffer;

	if (np->key) {
		PK11_FreeSymKey(np->key);
	}

	np->key = PK11_KeyGen(np->slot, np->ckmt, NULL, KEY_SIZE, NULL);
	if (!np->key) {
		printf("nss_set_cipher(): PK11_KeyGen() failed with error %d\n", PR_GetError());
		return false;
	}

	if (!nss_random(np, sizeof(np->iv), np->iv)) {
		printf("nss_set_cipher(): nss_random() failed!\n");
		return false;
	}

	return true;
}

size_t nss_buffer_size(const size_t size) {
	return size + TAG_SIZE;
}

size_t nss_encrypt(void *param, const size_t size, void *dst, const void *src) {
	if (!param || !dst || !src) {
		return 0;
	}

	NSSParam *np = param;

	unsigned int written;

	if (PK11_Encrypt(np->key, np->ckmt, &np->params, dst, &written, nss_buffer_size(size), src, size) != SECSuccess) {
		printf("nss_encrypt(): PK11_Encrypt() failed with error %d\n", PR_GetError());
		return 0;
	}

	return written;
}

size_t nss_decrypt(void *param, const size_t size, void *dst, const void *src) {
	if (!param || !dst || !src) {
		return 0;
	}

	NSSParam *np = param;

	unsigned int written;

	if (PK11_Decrypt(np->key, np->ckmt, &np->params, dst, &written, size, src, size) != SECSuccess) {
		printf("nss_decrypt(): PK11_Decrypt() failed with error %d\n", PR_GetError());
		return 0;
	}

	return written;
}

const Crypto *nss_get() {
	static const Crypto crypto = {
		nss_name,
		nss_ciphers,
		nss_init,
		nss_free,
		nss_random,
		nss_set_cipher,
		nss_buffer_size,
		nss_encrypt,
		nss_decrypt
	};

	return &crypto;
}
