#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include "shadow.h"

/* Maximum line length in shadow file */
#define MAX_LINE_LENGTH 256

/* Load shadow file entries */
int load_shadow_file(const char *filename, shadow_entry_t **entries, size_t *num_entries) {
  FILE *file = fopen(filename, "r");
  if (!file) {
    return -1;
  }
  
  /* Count number of lines */
  size_t line_count = 0;
  char line[MAX_LINE_LENGTH];
  
  while (fgets(line, sizeof(line), file) != NULL) {
    line_count++;
  }
  
  /* Allocate memory for entries */
  *entries = (shadow_entry_t *)calloc(line_count, sizeof(shadow_entry_t));
  if (!*entries) {
    fclose(file);
    return -1;
  }
  
  /* Reset file position */
  rewind(file);
  
  /* Parse each line */
  size_t entry_count = 0;
  
  while (fgets(line, sizeof(line), file) != NULL) {
    /* Remove trailing newline */
    size_t len = strlen(line);
    if (len > 0 && line[len - 1] == '\n') {
      line[len - 1] = '\0';
      len--;
    }
    
    /* Skip empty lines */
    if (len == 0) {
      continue;
    }
    
    /* Parse line */
    char *username = strtok(line, ":");
    if (!username) {
      continue;
    }
    
    char *hash = strtok(NULL, ":");
    if (!hash) {
      continue;
    }
    
    /* Create entry */
    shadow_entry_t *entry = &(*entries)[entry_count];
    
    entry->username = strdup(username);
    entry->hash = strdup(hash);
    entry->type = detect_hash_type(entry);
    entry->salt = extract_salt(entry);
    entry->password = NULL;  /* Not cracked yet */
    
    entry_count++;
  }
  
  fclose(file);
  *num_entries = entry_count;
  
  return 0;
}

/* Detect hash type from shadow entry */
hash_type_t detect_hash_type(const shadow_entry_t *entry) {
  if (!entry || !entry->hash) {
    return HASH_AUTO;
  }
  
  if (strncmp(entry->hash, "$1$", 3) == 0) {
    return HASH_MD5;
  } else if (strncmp(entry->hash, "$5$", 3) == 0) {
    return HASH_SHA256;
  } else if (strncmp(entry->hash, "$2a$", 4) == 0) {
    return HASH_BCRYPT;
  }
  
  return HASH_AUTO;
}

/* Extract salt from shadow entry */
char *extract_salt(const shadow_entry_t *entry) {
  if (!entry || !entry->hash) {
    return NULL;
  }
  
  char *salt = NULL;
  
  switch (entry->type) {
    case HASH_MD5: {
      /* Format: $1$salt$hash */
      const char *salt_start = entry->hash + 3;  /* Skip $1$ */
      const char *salt_end = strchr(salt_start, '$');
      
      if (salt_end) {
        size_t salt_len = (size_t)(salt_end - salt_start);
        salt = (char *)malloc(salt_len + 1);
        if (salt) {
          memcpy(salt, salt_start, salt_len);
          salt[salt_len] = '\0';
        }
      }
      break;
    }
    
    case HASH_SHA256: {
      /* Format: $5$salt$hash */
      const char *salt_start = entry->hash + 3;  /* Skip $5$ */
      const char *salt_end = strchr(salt_start, '$');
      
      if (salt_end) {
        size_t salt_len = (size_t)(salt_end - salt_start);
        salt = (char *)malloc(salt_len + 1);
        if (salt) {
          memcpy(salt, salt_start, salt_len);
          salt[salt_len] = '\0';
        }
      }
      break;
    }
    
    case HASH_BCRYPT: {
      /* Format: $2a$XX$salthash */
      const char *salt_start = entry->hash;
      
      /* bcrypt salt includes the prefix and cost parameter */
      size_t salt_len = 29;  /* Standard length for bcrypt salt including prefix */
      if (strlen(salt_start) >= salt_len) {
        salt = (char *)malloc(salt_len + 1);
        if (salt) {
          memcpy(salt, salt_start, salt_len);
          salt[salt_len] = '\0';
        }
      }
      break;
    }
    
    default:
      break;
  }
  
  return salt;
}

/* Hash a password with MD5 and salt */
static char *hash_md5(const char *password, const char *salt) {
  /* This is a simplified implementation for demonstration */
  /* In a real implementation, you would use crypt_r() or similar */
  
  /* Combine salt and password */
  size_t salt_len = strlen(salt);
  size_t pass_len = strlen(password);
  char *salted = (char *)malloc(salt_len + pass_len + 1);
  
  if (!salted) {
    return NULL;
  }
  
  memcpy(salted, salt, salt_len);
  memcpy(salted + salt_len, password, pass_len);
  salted[salt_len + pass_len] = '\0';
  
  /* Hash the salted password */
  unsigned char md5_digest[MD5_DIGEST_LENGTH];
  MD5((unsigned char *)salted, salt_len + pass_len, md5_digest);
  
  /* Convert to hex string */
  char *result = (char *)malloc(2 * MD5_DIGEST_LENGTH + 5);
  if (!result) {
    free(salted);
    return NULL;
  }
  
  sprintf(result, "$1$%s$", salt);
  for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
    sprintf(result + 3 + salt_len + 1 + i * 2, "%02x", md5_digest[i]);
  }
  
  free(salted);
  return result;
}

/* Hash a password with SHA-256 and salt */
static char *hash_sha256(const char *password, const char *salt) {
  /* This is a simplified implementation for demonstration */
  /* In a real implementation, you would use crypt_r() or similar */
  
  /* Combine salt and password */
  size_t salt_len = strlen(salt);
  size_t pass_len = strlen(password);
  char *salted = (char *)malloc(salt_len + pass_len + 1);
  
  if (!salted) {
    return NULL;
  }
  
  memcpy(salted, salt, salt_len);
  memcpy(salted + salt_len, password, pass_len);
  salted[salt_len + pass_len] = '\0';
  
  /* Hash the salted password */
  unsigned char sha256_digest[SHA256_DIGEST_LENGTH];
  SHA256((unsigned char *)salted, salt_len + pass_len, sha256_digest);
  
  /* Convert to hex string */
  char *result = (char *)malloc(2 * SHA256_DIGEST_LENGTH + 5);
  if (!result) {
    free(salted);
    return NULL;
  }
  
  sprintf(result, "$5$%s$", salt);
  for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
    sprintf(result + 3 + salt_len + 1 + i * 2, "%02x", sha256_digest[i]);
  }
  
  free(salted);
  return result;
}

/* Hash a password with bcrypt and salt */
static char *hash_bcrypt(const char *password, const char *salt) {
  /* This is a placeholder for demonstration */
  /* In a real implementation, you would use a proper bcrypt library */
  
  /* bcrypt is computationally expensive and complex to implement */
  /* For a real implementation, use libcrypt or similar */
  fprintf(stderr, "Warning: bcrypt hashing not fully implemented\n");
  
  /* Return a dummy hash for now */
  size_t salt_len = strlen(salt);
  char *result = (char *)malloc(salt_len + 32);
  if (!result) {
    return NULL;
  }
  
  sprintf(result, "%s%s", salt, "BCRYPT_HASH_PLACEHOLDER");
  return result;
}

/* Hash a password with the specified algorithm and salt */
char *hash_password(const char *password, const char *salt, hash_type_t type) {
  switch (type) {
    case HASH_MD5:
      return hash_md5(password, salt);
    case HASH_SHA256:
      return hash_sha256(password, salt);
    case HASH_BCRYPT:
      return hash_bcrypt(password, salt);
    default:
      return NULL;
  }
}

/* Check if a password matches a shadow entry */
int check_password(const shadow_entry_t *entry, const char *password) {
  if (!entry || !entry->hash || !entry->salt || !password) {
    return 0;
  }
  
  char *hash = hash_password(password, entry->salt, entry->type);
  if (!hash) {
    return 0;
  }
  
  int result = (strcmp(hash, entry->hash) == 0);
  free(hash);
  
  return result;
}
