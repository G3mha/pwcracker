#ifndef PWCRACKER_BENCHMARK_H
#define PWCRACKER_BENCHMARK_H

#include <stdio.h>

/**
 * Run benchmark tests
 *
 * @param output Output file stream
 * @param verbose Verbose output flag
 * @return 0 on success, non-zero on failure
 */
int run_benchmark(FILE *output, int verbose);

#endif /* PWCRACKER_BENCHMARK_H */
