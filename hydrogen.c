#include "hydrogen.h"
#include "utils.h"

#include <hydrogen.h>

#include <stdio.h>

#define CONTEXT "benchmark"

bool hydrogen_main(const size_t message_size, const size_t iterations) {
	if (hydro_init() != 0) {
		printf("hydrogen_main(): hydro_init() failed!\n");
		return false;
	}

	uint8_t message[message_size], out[message_size + hydro_secretbox_HEADERBYTES];
	hydro_random_buf(message, sizeof(message));

	const double elapsed = hydrogen_crypto(iterations, out, sizeof(message), message);
	if (!elapsed) {
		printf("hydrogen_main(): hydrogen_crypto() failed!\n");
		return false;
	}
	
	printf("[libhydrogen] Took %f seconds for %zu iterations, %zu bytes message\n", elapsed, iterations, message_size);
	
	return true;
}

double hydrogen_crypto(const size_t iterations, uint8_t *dst, const size_t size, const uint8_t *src) {
	uint8_t key[hydro_secretbox_KEYBYTES];
	hydro_secretbox_keygen(key);

	const double start = seconds();

	for (size_t i = 0; i < iterations; ++i) {
		hydro_secretbox_encrypt(dst, src, size, 0, CONTEXT, key);

		if (hydro_secretbox_decrypt(dst, dst, size + hydro_secretbox_HEADERBYTES, 0, CONTEXT, key) != 0) {
			printf("hydrogen_crypto(): hydro_secretbox_decrypt() failed!\n");
			return 0;
		}
	}

	const double elapsed = seconds() - start;

	validate(size, dst, src);

	return elapsed;
}
