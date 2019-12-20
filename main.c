#define MESSAGE_SIZE 4096
#define ITERATIONS   1000000

#include "nss.h"
#include "openssl.h"
#include "sodium.h"
#include "wolfcrypt.h"

#include <stdlib.h>

int main() {
	if (!nss_main(MESSAGE_SIZE, ITERATIONS)) {
		return EXIT_FAILURE;
	}

	if (!openssl_main(MESSAGE_SIZE, ITERATIONS)) {
		return EXIT_FAILURE;
	}

	if (!sodium_main(MESSAGE_SIZE, ITERATIONS)) {
		return EXIT_FAILURE;
	}

	if (!wolfcrypt_main(MESSAGE_SIZE, ITERATIONS)) {
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
