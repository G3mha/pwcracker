#ifndef PWCRACKER_UTIL_H
#define PWCRACKER_UTIL_H

#include <stdlib.h>
#include "cli.h"

#define SHADOW_FILE "../data/test_hashed_md5.txt"
#define SHADOW_FILE_SHA256 "../data/test_hashed_sha256.txt"
#define SHADOW_FILE_BCRYPT "../data/test_hashed_bcrypt.txt"
#define DICTIONARY_FILE "../data/test_pws.txt"
#define RAINBOW_FILE "../data/test_rainbow.txt"
#define OUTPUT_FILE "../data/test_output.txt"

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
 * 
 * @return 0 on success, non-zero on failure
 */
int load_shadow_file(const char *filename, shadow_entry_t **entries, size_t *num_entries);

/**
 * Detect hash type from shadow entry
 *
 * @param entry Shadow entry
 * 
 * @return Detected hash type
 */
hash_type_t detect_hash_type(const shadow_entry_t *entry);

/**
 * Extract salt from shadow entry
 *
 * @param entry Shadow entry
 * 
 * @return Extracted salt (must be freed by caller)
 */
char *extract_salt(const shadow_entry_t *entry);

/**
 * Check if a password matches a shadow entry
 *
 * @param entry Shadow entry
 * @param password Password to check
 * 
 * @return 1 if password matches, 0 otherwise
 */
int check_password(const shadow_entry_t *entry, const char *password);

/**
 * Compare a plaintext password against an MD5-crypt hash.
 *
 * @param password     Null-terminated plaintext password candidate.
 * @param stored_hash  Null-terminated MD5-crypt string of the form
 *                     "$1$<salt>$<hash(salt+password)>" (as found in /etc/shadow).
 *
 * @return 1 if the password produces an identical MD5-crypt hash;
 *         0 otherwise.
 */
int check_md5_crypt(const char *password, const char *stored_hash);

/**
 * Compare a plaintext password against a SHA256-crypt hash.
 *
 * @param password     Null-terminated plaintext password candidate.
 * @param stored_hash  Null-terminated SHA256-crypt string of the form
 *                     "$5$<salt>$<hash(salt+password)>" (as found in /etc/shadow).
 *
 * @return 1 if the password produces an identical SHA256-crypt hash;
 *         0 otherwise.
 */
int check_sha256_crypt(const char *password, const char *stored_hash);

/**
 * Compare a plaintext password against a bcrypt hash.
 *
 * @param password     Null-terminated plaintext password candidate.
 * @param stored_hash  Null-terminated bcrypt string of the form
 *                     "$2a$<cost>$<salt>$<hash(salt+password)>" (as found in /etc/shadow).
 *
 * @return 1 if the password produces an identical bcrypt hash;
 *         0 otherwise.
 */
int check_bcrypt_crypt(const char *password, const char *stored_hash);

/**
 * Hash a password with the specified algorithm and salt
 *
 * @param password Plain text password
 * @param salt Salt to use
 * @param type Hash type
 *
 * @return Hashed password (must be freed by caller), NULL on error
 */
char *hash_password(const char *password, const char *salt, hash_type_t type);

#endif /* PWCRACKER_UTIL_H */
