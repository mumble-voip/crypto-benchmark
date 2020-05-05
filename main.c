#define MESSAGE_SIZE 4096
#define ITERATIONS   1000000

#include "hydrogen.h"
#include "nss.h"
#include "openssl.h"
#include "sodium.h"
#include "wolfcrypt.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

bool benchmark(const Crypto *crypto, const size_t message_size, const size_t iterations) {
	if (!crypto) {
		return false;
	}

	const char *name = crypto->name();

	void *param = NULL;
	if (!crypto->init(&param)) {
		printf("[%s] initialization failed!\n", name);
		return false;
	}

	uint8_t *src = malloc(message_size);
	uint8_t *dst = malloc(crypto->buffer_size(message_size));

	if (!crypto->random(param, message_size, src)) {
		printf("[%s] input randomization failed!\n", name);
	}

	bool ok = true;

	const char **ciphers = crypto->ciphers();
	for (size_t i = 0; ciphers[i] != NULL; ++i) {
		const char *cipher = ciphers[i];
		if (!crypto->set_cipher(param, cipher)) {
			printf("[%s] failed to set %s, skipping it...\n", name, cipher);
			continue;
		}

		printf("[%s] running %s benchmark...\n", name, cipher);

		const double start = seconds();

		for (size_t i = 0; i < iterations; ++i) {
			size_t ret = crypto->encrypt(param, message_size, dst, src);
			if (!ret) {
				printf("[%s] encryption failed!\n", name);
				ok = false;
				break;
			}

			ret = crypto->decrypt(param, ret, dst, dst);
			if (!ret) {
				printf("[%s] decryption failed!\n", name);
				ok = false;
				break;
			}
		}

		const double elapsed = seconds() - start;

		if (!validate(message_size, dst, src)) {
			printf("[%s] decrypted message doesn't match original, encryption/decryption failure!\n", name);
			ok = false;
			continue;
		}

		printf("[%s] %f seconds for %zu iterations, %zu bytes message\n", name, elapsed, iterations, message_size);
	}

	crypto->free(param);

	free(src);
	free(dst);

	return ok;
}

int main() {
	bool ok = true;
#if BENCHMARK_HYDROGEN
	if (!benchmark(hydrogen_get(), MESSAGE_SIZE, ITERATIONS)) {
		ok = false;
	}
#endif
#if BENCHMARK_NSS
	if (!benchmark(nss_get(), MESSAGE_SIZE, ITERATIONS)) {
		ok = false;
	}
#endif
#if BENCHMARK_OPENSSL
	if (!benchmark(openssl_get(), MESSAGE_SIZE, ITERATIONS)) {
		ok = false;
	}
#endif
#if BENCHMARK_SODIUM
	if (!benchmark(sodium_get(), MESSAGE_SIZE, ITERATIONS)) {
		ok = false;
	}
#endif
#if BENCHMARK_WOLFCRYPT
	if (!benchmark(wolfcrypt_get(), MESSAGE_SIZE, ITERATIONS)) {
		ok = false;
	}
#endif
	return ok ? EXIT_SUCCESS : EXIT_FAILURE;
}
