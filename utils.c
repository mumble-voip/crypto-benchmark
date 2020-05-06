#include "utils.h"

#define _POSIX_C_SOURCE 199309L

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

void *progress_function(void *arg) {
	double elapsed_time;
	size_t iterations_completed;
	size_t iterations_total;
	const char *lib_name;
	uint8_t percent_completed;

	Progress *progress = arg;

	iterations_total = progress->iterations_total;
	lib_name = progress->lib_name;
	do {
		sleep(1);
		iterations_completed = progress->iterations_completed;
		elapsed_time = seconds() - progress->start_time;

		if ((uint64_t) elapsed_time % 10 == 0){
			percent_completed =  100 * iterations_completed / iterations_total;
			printf("[%s] Iteration %zu/%zu (%hhu%%), elapsed time: %f\n", lib_name, iterations_completed, iterations_total, percent_completed, elapsed_time);
		}
	} while (iterations_completed < iterations_total - 1);
}

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
