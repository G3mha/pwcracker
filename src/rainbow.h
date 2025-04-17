#ifndef PWCRACKER_RAINBOW_H
#define PWCRACKER_RAINBOW_H

#include <stdio.h>
#include "../utils/shadow.h"

/**
 * Perform rainbow table attack on shadow entries
 *
 * @param entries Array of shadow entries
 * @param num_entries Number of entries
 * @param rainbow_file Path to rainbow table file
 * @param hash_type Hash type to use
 * @param output Output file stream
 * @param verbose Verbose output flag
 * @param cracked_count Pointer to cracked count (will be updated)
 * @param timeout_flag Pointer to timeout flag (will be checked)
 * @return 0 on success, non-zero on failure
 */
int rainbow_attack(shadow_entry_t *entries, size_t num_entries,
                 const char *rainbow_file, hash_type_t hash_type,
                 FILE *output, int verbose, size_t *cracked_count,
                 volatile int *timeout_flag);

#endif /* PWCRACKER_RAINBOW_H */
