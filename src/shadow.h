#ifndef PWCRACKER_SHADOW_H
#define PWCRACKER_SHADOW_H

#include <stdlib.h>
#include "cli.h"

/* Shadow file entry structure */
typedef struct {
  char *username;     /* Username */
  char *hash;         /* Full hash string */
  char *salt;         /* Extracted salt */
  hash_type_t type;   /* Hash type */
  char *password;     /* Cracked password (NULL if not cracked) */
} shadow_entry_t;

/**
 * Load shadow file entries
 *
 * @param filename Path to shadow file
 * @param entries Pointer to shadow entry array (will be allocated)
 * @param num_entries Pointer to number of entries (will be set)
 * @return 0 on success, non-zero on failure
 */
int load_shadow_file(const char *filename, shadow_entry_t **entries, size_t *num_entries);

/**
 * Detect hash type from shadow entry
 *
 * @param entry Shadow entry
 * @return Detected hash type
 */
hash_type_t detect_hash_type(const shadow_entry_t *entry);

/**
 * Extract salt from shadow entry
 *
 * @param entry Shadow entry
 * @return Extracted salt (must be freed by caller)
 */
char *extract_salt(const shadow_entry_t *entry);

/**
 * Hash a password with the specified algorithm and salt
 *
 * @param password Plain text password
 * @param salt Salt to use
 * @param type Hash type
 * @return Hashed password (must be freed by caller), NULL on error
 */
char *hash_password(const char *password, const char *salt, hash_type_t type);

/**
 * Check if a password matches a shadow entry
 *
 * @param entry Shadow entry
 * @param password Password to check
 * @return 1 if password matches, 0 otherwise
 */
int check_password(const shadow_entry_t *entry, const char *password);

#endif /* PWCRACKER_SHADOW_H */
