#ifndef PWCRACKER_DICTIONARY_H
#define PWCRACKER_DICTIONARY_H

#include <stdio.h>
#include "util.h"

/**
 * Perform dictionary attack on shadow entries
 *
 * @param entries Array of shadow entries
 * @param num_entries Number of entries
 * @param dictionary_file Path to dictionary file
 * @param hash_type Hash type to use
 * @param num_threads Number of threads to use
 * @param output Output file stream
 * @param verbose Verbose output flag
 * @param cracked_count Pointer to cracked count (will be updated)
 * @param timeout_flag Pointer to timeout flag (will be checked)
 * @return 0 on success, non-zero on failure
 */
int dictionary_attack(shadow_entry_t *entries, size_t num_entries,
                    const char *dictionary_file, hash_type_t hash_type,
                    int num_threads, FILE *output, int verbose,
                    size_t *cracked_count, volatile int *timeout_flag);

#endif /* PWCRACKER_DICTIONARY_H */
