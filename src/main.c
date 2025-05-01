#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include <unistd.h>
#include "util.h"
#include "cli.h"
#include "dictionary.h"
#include "brute_force.h"
#include "rainbow.h"
#include "benchmark.h"

/* Global flag for timeout handling */
static volatile int g_timeout_flag = 0;

/* Signal handler for timeout */
static void timeout_handler(int signum) {
  (void)signum;  /* Unused parameter */
  g_timeout_flag = 1;
}

/* Main function */
int main(int argc, char **argv) {
  struct arguments args = parse_arguments(argc, argv);
  
  /* Print arguments if in verbose mode */
  if (args.verbose) {
    print_arguments(&args);
  }
  
  /* Setup timeout if specified */
  if (args.timeout > 0) {
    signal(SIGALRM, timeout_handler);
    alarm((unsigned int)args.timeout);
  }
  
  /* Open output file if specified */
  FILE *output = stdout;
  if (args.output_file) {
    output = fopen(args.output_file, "w");
    if (!output) {
      fprintf(stderr, "Error: Could not open output file '%s'\n", args.output_file);
      return EXIT_FAILURE;
    }
  }
  
  /* Start timer for benchmarking */
  clock_t start = clock();
  
  /* Run in benchmark mode if requested */
  if (args.benchmark) {
    if (!args.quiet) {
      fprintf(output, "Running in benchmark mode...\n");
    }
    run_benchmark(output, args.verbose);
    goto cleanup;
  }

  /* Load shadow file for attack modes */
  shadow_entry_t *entries = NULL;
  size_t num_entries = 0;
  
  if (load_shadow_file(args.target_file, &entries, &num_entries) != 0) {
    fprintf(stderr, "Error: Failed to load shadow file '%s'\n", args.target_file);
    if (output != stdout) fclose(output);
    return EXIT_FAILURE;
  }
  
  if (!args.quiet && args.verbose) {
    fprintf(output, "Loaded %zu entries from shadow file\n", num_entries);
  }
  
  /* Detect hash type if set to auto */
  if (args.hash_type == HASH_AUTO && num_entries > 0) {
    args.hash_type = detect_hash_type(&entries[0]);
    if (args.verbose) {
      fprintf(output, "Detected hash type: ");
      switch (args.hash_type) {
        case HASH_MD5:
          fprintf(output, "MD5\n");
          break;
        case HASH_SHA256:
          fprintf(output, "SHA-256\n");
          break;
        case HASH_BCRYPT:
          fprintf(output, "bcrypt\n");
          break;
        default:
          fprintf(output, "Unknown\n");
          break;
      }
    }
  }
  
  int result = 0;
  size_t cracked_count = 0;
  
  /* Run the requested attack */
  switch (args.mode) {
    case MODE_DICTIONARY:
      if (!args.quiet) {
        fprintf(output, "Running dictionary attack using '%s'...\n", args.dictionary_file);
      }
      result = dictionary_attack(entries, num_entries, args.dictionary_file, 
                                args.hash_type, args.threads, output, 
                                args.verbose, &cracked_count, &g_timeout_flag);
      break;
      
    case MODE_BRUTEFORCE:
      if (!args.quiet) {
        fprintf(output, "Running brute force attack (max length: %d)...\n", args.max_length);
      }
      result = bruteforce_attack(entries, num_entries, args.charset, args.max_length, 
                               args.hash_type, args.threads, output, 
                               args.verbose, &cracked_count, &g_timeout_flag);
      break;
      
    case MODE_RAINBOW:
      if (!args.quiet) {
        fprintf(output, "Running rainbow table attack using '%s'...\n", args.rainbow_file);
      }
      result = rainbow_attack(entries, num_entries, args.rainbow_file, 
                            args.hash_type, output, args.verbose, 
                            &cracked_count, &g_timeout_flag);
      break;
      
    default:
      fprintf(stderr, "Error: No attack mode specified\n");
      result = EXIT_FAILURE;
      break;
  }
  
  /* Report results */
  clock_t end = clock();
  double elapsed = (double)(end - start) / CLOCKS_PER_SEC;
  
  if (!args.quiet) {
    if (g_timeout_flag) {
      fprintf(output, "\nTimeout reached after %.2f seconds\n", elapsed);
    }
    
    fprintf(output, "\nResults summary:\n");
    fprintf(output, "- Cracked %zu out of %zu passwords (%.1f%%)\n", 
            cracked_count, num_entries, (num_entries > 0) ? 
            (100.0 * cracked_count / num_entries) : 0.0);
    fprintf(output, "- Total time: %.2f seconds\n", elapsed);
    
    if (cracked_count > 0 && elapsed > 0) {
      fprintf(output, "- Average time per cracked password: %.3f seconds\n", 
              elapsed / cracked_count);
    }
  }
  
  /* Free shadow entries */
  for (size_t i = 0; i < num_entries; i++) {
    free(entries[i].username);
    free(entries[i].hash);
    free(entries[i].salt);
    free(entries[i].password);
  }
  free(entries);
  
cleanup:
  /* Close output file if needed */
  if (output != stdout) {
    fclose(output);
  }
  
  return result;
}
