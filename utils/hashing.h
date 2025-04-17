#include "../src/cli.h"

/**
 * Hash a password with the specified algorithm and salt
 *
 * @param password Plain text password
 * @param salt Salt to use
 * @param type Hash type
 * @return Hashed password (must be freed by caller), NULL on error
 */
char *hash_password(const char *password, const char *salt, hash_type_t type);

