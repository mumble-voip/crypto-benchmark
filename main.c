#define MESSAGE_SIZE 65536
#define ITERATIONS   1000000

#include "openssl.h"

#include <stdlib.h>

int main() {
	if (!openssl_main(MESSAGE_SIZE, ITERATIONS)) {
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
