#ifndef PWCRACKER_CLI_H
#define PWCRACKER_CLI_H

#include <stdbool.h>

/* Attack modes */
typedef enum {
  MODE_NONE,
  MODE_DICTIONARY,
  MODE_BRUTEFORCE,
  MODE_RAINBOW
} attack_mode_t;

/* Hash types */
typedef enum {
  HASH_AUTO,  /* Auto-detect from shadow file */
  HASH_MD5,   /* $1$ prefix in shadow */
  HASH_SHA256,/* $5$ prefix in shadow */
  HASH_BCRYPT /* $2a$ prefix in shadow */
} hash_type_t;

/* CLI argument structure */
struct arguments {
  attack_mode_t mode;
  char *target_file;  /* Shadow file for attack modes, output file for generate mode */
  char *dictionary_file;
  char *rainbow_file;
  char *output_file;
  char *username_prefix;
  int max_length;
  const char *charset;
  int threads;
  int timeout;
  bool verbose;
  bool quiet;
  bool benchmark;
  hash_type_t hash_type;
};

/**
 * Parse command line arguments
 *
 * @param argc Argument count
 * @param argv Argument vector
 * @return Parsed arguments structure
 */
struct arguments parse_arguments(int argc, char **argv);

/**
 * Print the parsed arguments (for verbose mode)
 *
 * @param args Pointer to arguments structure
 */
void print_arguments(const struct arguments *args);

#endif /* PWCRACKER_CLI_H */
