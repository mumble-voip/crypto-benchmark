#include "utils.h"

#define _POSIX_C_SOURCE 199309L

#include <stdio.h>
#include <string.h>
#include <time.h>

double seconds() {
	struct timespec ts;
	if (clock_gettime(CLOCK_MONOTONIC_RAW, &ts) == -1) {
		printf("seconds(): clock_gettime() failed!\n");
		return 0.0;
	}

	return (double)ts.tv_sec + (double)ts.tv_nsec / 1000000000.0;
}

void validate(const int size, const unsigned char *buf_1, const unsigned char *buf_2) {
	if (memcmp(buf_1, buf_2, size) != 0) {
		printf("validate(): decrypted message doesn't match original, encryption/decryption failure!\n");
	}
}
