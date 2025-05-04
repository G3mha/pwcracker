#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "cli.h"
#include "benchmark.h"
#include "util.h"

/* Benchmark parameters */
#define NUM_PASSWORDS 5
#define NUM_ITERATIONS 1000
#define SALT_LENGTH 8

/* Generate random string */
static void random_string(char *str, size_t length) {
    static const char charset[] = "abcdefghijklmnopqrstuvwxyz"
                                 "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                 "0123456789";
    size_t charset_len = strlen(charset);
    
    for (size_t i = 0; i < length; i++) {
        int index = rand() % charset_len;
        str[i] = charset[index];
    }
    str[length] = '\0';
}

/* Run benchmark for a specific hash type */
static void benchmark_hash_type(hash_type_t type, const char *name, FILE *output, int verbose) {
    char passwords[NUM_PASSWORDS][32];
    char salts[NUM_PASSWORDS][SALT_LENGTH + 1];
    
    /* Generate random passwords and salts */
    for (int i = 0; i < NUM_PASSWORDS; i++) {
        random_string(passwords[i], 8);
        random_string(salts[i], SALT_LENGTH);
    }
    
    /* Time hashing operations */
    clock_t start = clock();
    
    for (int i = 0; i < NUM_ITERATIONS; i++) {
        int index = i % NUM_PASSWORDS;
        char *hash = hash_password(passwords[index], salts[index], type);
        if (hash) {
            free(hash);
        }
    }
    
    clock_t end = clock();
    double elapsed = (double)(end - start) / CLOCKS_PER_SEC;
    double hashes_per_second = NUM_ITERATIONS / elapsed;
    
    fprintf(output, "Benchmark results for %s:\n", name);
    fprintf(output, "- %d iterations completed in %.3f seconds\n", NUM_ITERATIONS, elapsed);
    fprintf(output, "- %.2f hashes per second\n", hashes_per_second);
    
    if (verbose) {
        /* Show example hash for each password */
        fprintf(output, "Hash examples:\n");
        for (int i = 0; i < NUM_PASSWORDS; i++) {
            char *hash = hash_password(passwords[i], salts[i], type);
            if (hash) {
                fprintf(output, "- Password: %s, Salt: %s -> %s\n", 
                        passwords[i], salts[i], hash);
                free(hash);
            }
        }
    }
    
    fprintf(output, "\n");
}

/* Run benchmark tests */
int run_benchmark(FILE *output, int verbose) {
    /* Seed random number generator */
    srand((unsigned int)time(NULL));
    
    fprintf(output, "Running password hashing benchmarks...\n\n");
    
    /* Benchmark each hash type */
    benchmark_hash_type(HASH_MD5, "MD5", output, verbose);
    benchmark_hash_type(HASH_SHA256, "SHA-256", output, verbose);
    benchmark_hash_type(HASH_BCRYPT, "bcrypt", output, verbose);
    
    fprintf(output, "Benchmark completed.\n");
    
    return 0;
}
