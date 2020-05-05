#include "utils.h"

#define _POSIX_C_SOURCE 199309L

#include <stdio.h>
#include <stdlib.h>
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

bool validate(const size_t size, const void *buf_1, const void *buf_2) {
	if (!buf_1 || !buf_2) {
		// Return true if both buffers are NULL
		return (!buf_1 && !buf_2);
	}

	return memcmp(buf_1, buf_2, size) == 0;
}

void *zero_malloc(const size_t size) {
	if (!size) {
		return NULL;
	}

	void *ptr = malloc(size);
	if (!ptr) {
		return NULL;
	}

	memset(ptr, 0, size);

	return ptr;
}
