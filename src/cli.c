#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <argp.h>
#include <stdbool.h>
#include "cli.h"

const char *argp_program_version = "password-cracker 1.0";
const char *argp_program_bug_address = "https://github.com/olincollege/password-hash-cracker/issues";

/* Program documentation */
static char doc[] = "Password Hash Cracker -- A security testing framework for password hashing";

/* Description of the arguments we accept */
static char args_doc[] = "SHADOW_FILE";

/* Flags for different command configurations */
static struct argp_option options[] = {
  {"verbose",      'v', 0,         0, "Produce verbose output"},
  {"quiet",        'q', 0,         0, "Don't produce any output"},
  {"dictionary",   'd', "FILE",    0, "Use dictionary attack with specified wordlist"},
  {"brute-force",  'b', 0,         0, "Use brute force attack"},
  {"rainbow",      'r', "FILE",    0, "Use rainbow table attack with specified table"},
  {"max-length",   'l', "LENGTH",  0, "Maximum password length for brute force (default: 8)"},
  {"charset",      'c', "CHARSET", 0, "Character set for brute force (default: abcdefghijklmnopqrstuvwxyz0123456789)"},
  {"threads",      't', "NUM",     0, "Number of threads to use (default: 1)"},
  {"timeout",      'T', "SECONDS", 0, "Timeout in seconds (default: 0 - no timeout)"},
  {"output",       'o', "FILE",    0, "Write results to FILE instead of standard output"},
  {"hash-type",    'H', "TYPE",    0, "Specify hash type (md5, sha256, bcrypt)"},
  {"benchmark",    'B', 0,         0, "Run in benchmark mode"},
  {"help",         '?', 0,         0, "Give this help list"},
  {0}
};

/* Parse a single option */
static error_t parse_opt(int key, char *arg, struct argp_state *state) {
  struct arguments *arguments = state->input;

  switch (key) {
    case 'v':
      arguments->verbose = true;
      break;
    case 'q':
      arguments->quiet = true;
      break;
    case 'd':
      arguments->dictionary_file = arg;
      arguments->mode = MODE_DICTIONARY;
      break;
    case 'b':
      arguments->mode = MODE_BRUTEFORCE;
      break;
    case 'r':
      arguments->rainbow_file = arg;
      arguments->mode = MODE_RAINBOW;
      break;
    case 'l':
      arguments->max_length = atoi(arg);
      if (arguments->max_length <= 0 || arguments->max_length > 16) {
        fprintf(stderr, "Error: Maximum length must be between 1 and 16\n");
        return EINVAL;
      }
      break;
    case 'c':
      arguments->charset = arg;
      break;
    case 't':
      arguments->threads = atoi(arg);
      if (arguments->threads <= 0) {
        fprintf(stderr, "Error: Thread count must be positive\n");
        return EINVAL;
      }
      break;
    case 'T':
      arguments->timeout = atoi(arg);
      if (arguments->timeout < 0) {
        fprintf(stderr, "Error: Timeout must be non-negative\n");
        return EINVAL;
      }
      break;
    case 'o':
      arguments->output_file = arg;
      break;
    case 'H':
      if (strcmp(arg, "md5") == 0) {
        arguments->hash_type = HASH_MD5;
      } else if (strcmp(arg, "sha256") == 0) {
        arguments->hash_type = HASH_SHA256;
      } else if (strcmp(arg, "bcrypt") == 0) {
        arguments->hash_type = HASH_BCRYPT;
      } else {
        fprintf(stderr, "Error: Unknown hash type '%s'\n", arg);
        return EINVAL;
      }
      break;
    case 'B':
      arguments->benchmark = true;
      break;

    case ARGP_KEY_ARG:
      if (state->arg_num == 0) {
        arguments->shadow_file = arg;
      } else {
        /* Too many arguments */
        argp_usage(state);
      }
      break;

    case ARGP_KEY_END:
      if (state->arg_num < 1 && !arguments->benchmark) {
        /* Not enough arguments */
        argp_usage(state);
      }
      break;

    default:
      return ARGP_ERR_UNKNOWN;
  }
  return 0;
}

/* Our argp parser */
static struct argp argp = {options, parse_opt, args_doc, doc};

void print_arguments(const struct arguments *args) {
  printf("Operating mode: ");
  switch (args->mode) {
    case MODE_DICTIONARY:
      printf("Dictionary attack using %s\n", args->dictionary_file);
      break;
    case MODE_BRUTEFORCE:
      printf("Brute force attack\n");
      printf("  Max length: %d\n", args->max_length);
      printf("  Charset: %s\n", args->charset);
      break;
    case MODE_RAINBOW:
      printf("Rainbow table attack using %s\n", args->rainbow_file);
      break;
    default:
      printf("Unknown\n");
  }

  printf("Shadow file: %s\n", args->shadow_file);
  printf("Hash type: ");
  switch (args->hash_type) {
    case HASH_MD5:
      printf("MD5\n");
      break;
    case HASH_SHA256:
      printf("SHA-256\n");
      break;
    case HASH_BCRYPT:
      printf("bcrypt\n");
      break;
    case HASH_AUTO:
      printf("Auto-detect\n");
      break;
    default:
      printf("Unknown\n");
  }
  
  printf("Threads: %d\n", args->threads);
  if (args->timeout > 0) {
    printf("Timeout: %d seconds\n", args->timeout);
  } else {
    printf("Timeout: None\n");
  }
  
  if (args->output_file) {
    printf("Output file: %s\n", args->output_file);
  } else {
    printf("Output: Standard output\n");
  }
  
  printf("Verbose: %s\n", args->verbose ? "Yes" : "No");
  printf("Quiet: %s\n", args->quiet ? "Yes" : "No");
  printf("Benchmark: %s\n", args->benchmark ? "Yes" : "No");
}

struct arguments parse_arguments(int argc, char **argv) {
  struct arguments arguments;
  
  /* Default values */
  arguments.mode = MODE_NONE;
  arguments.shadow_file = NULL;
  arguments.dictionary_file = NULL;
  arguments.rainbow_file = NULL;
  arguments.output_file = NULL;
  arguments.max_length = 8;
  arguments.charset = "abcdefghijklmnopqrstuvwxyz0123456789";
  arguments.threads = 1;
  arguments.timeout = 0;
  arguments.verbose = false;
  arguments.quiet = false;
  arguments.benchmark = false;
  arguments.hash_type = HASH_AUTO;
  
  /* Parse arguments */
  argp_parse(&argp, argc, argv, 0, 0, &arguments);
  
  /* Validate arguments */
  if (arguments.quiet && arguments.verbose) {
    fprintf(stderr, "Warning: Both quiet and verbose flags set; using quiet mode\n");
    arguments.verbose = false;
  }
  
  if (arguments.mode == MODE_NONE && !arguments.benchmark) {
    fprintf(stderr, "Warning: No attack mode specified; defaulting to dictionary attack\n");
    arguments.mode = MODE_DICTIONARY;
    if (arguments.dictionary_file == NULL) {
      arguments.dictionary_file = "data/common_passwords.txt";
      fprintf(stderr, "Warning: No dictionary file specified; using %s\n", 
              arguments.dictionary_file);
    }
  }
  
  return arguments;
}
