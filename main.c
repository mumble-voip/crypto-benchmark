#define MESSAGE_SIZE 4096
#define ITERATIONS   1000000

#include "hydrogen.h"
#include "nss.h"
#include "openssl.h"
#include "sodium.h"
#include "wolfcrypt.h"

#include <stdlib.h>

int main() {
#if BENCHMARK_HYDROGEN
	if (!hydrogen_main(MESSAGE_SIZE, ITERATIONS)) {
		return EXIT_FAILURE;
	}
#endif
#if BENCHMARK_NSS
	if (!nss_main(MESSAGE_SIZE, ITERATIONS)) {
		return EXIT_FAILURE;
	}
#endif
#if BENCHMARK_OPENSSL
	if (!openssl_main(MESSAGE_SIZE, ITERATIONS)) {
		return EXIT_FAILURE;
	}
#endif
#if BENCHMARK_SODIUM
	if (!sodium_main(MESSAGE_SIZE, ITERATIONS)) {
		return EXIT_FAILURE;
	}
#endif
#if BENCHMARK_WOLFCRYPT
	if (!wolfcrypt_main(MESSAGE_SIZE, ITERATIONS)) {
		return EXIT_FAILURE;
	}
#endif

	return EXIT_SUCCESS;
}
