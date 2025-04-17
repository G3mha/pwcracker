#ifndef PWCRACKER_BRUTEFORCE_H
#define PWCRACKER_BRUTEFORCE_H

#include <stdio.h>
#include "shadow.h"

/**
 * Perform brute force attack on shadow entries
 *
 * @param entries Array of shadow entries
 * @param num_entries Number of entries
 * @param charset Character set to use
 * @param max_length Maximum password length
 * @param hash_type Hash type to use
 * @param num_threads Number of threads to use
 * @param output Output file stream
 * @param verbose Verbose output flag
 * @param cracked_count Pointer to cracked count (will be updated)
 * @param timeout_flag Pointer to timeout flag (will be checked)
 * @return 0 on success, non-zero on failure
 */
int bruteforce_attack(shadow_entry_t *entries, size_t num_entries,
                    const char *charset, int max_length, hash_type_t hash_type,
                    int num_threads, FILE *output, int verbose,
                    size_t *cracked_count, volatile int *timeout_flag);

#endif /* PWCRACKER_BRUTEFORCE_H */
