#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "rainbow.h"

#define MAX_LINE_LENGTH 1024

int rainbow_attack(shadow_entry_t *entries, size_t num_entries,
                 const char *rainbow_file, hash_type_t hash_type,
                 FILE *output, int verbose, size_t *cracked_count,
                 volatile int *timeout_flag) {
    /* Initialize cracked count */
    *cracked_count = 0;
    
    /* Open rainbow table file */
    FILE *file = fopen(rainbow_file, "r");
    if (!file) {
        fprintf(stderr, "Error: Could not open rainbow table file '%s'\n", rainbow_file);
        return -1;
    }
    
    if (verbose) {
        fprintf(output, "Starting rainbow table attack using '%s'\n", rainbow_file);
    }
    
    /* Process each shadow entry */
    for (size_t i = 0; i < num_entries; i++) {
        /* Skip if already cracked */
        if (entries[i].password) {
            continue;
        }
        
        /* Check timeout */
        if (*timeout_flag) {
            break;
        }
        
        /* For each entry, scan the entire file */
        rewind(file);
        
        char line[MAX_LINE_LENGTH];
        while (fgets(line, sizeof(line), file) != NULL) {
            /* Remove trailing newline */
            size_t len = strlen(line);
            if (len > 0 && line[len - 1] == '\n') {
                line[len - 1] = '\0';
            }
            
            /* Split the line at the colon */
            char *hash = line;
            char *password = strchr(line, ':');
            
            if (!password) {
                continue;  /* Invalid line format */
            }
            
            *password = '\0';  /* Terminate the hash string */
            password++;        /* Move to the password part */
            
            /* Check if hash matches */
            if (strcmp(entries[i].hash, hash) == 0) {
                /* Found a match */
                entries[i].password = strdup(password);
                if (entries[i].password) {
                    (*cracked_count)++;
                    
                    if (!verbose) {
                        fprintf(output, "Cracked password for %s: %s\n", 
                                entries[i].username, entries[i].password);
                    } else {
                        fprintf(output, "Cracked password for %s: %s (rainbow table match)\n", 
                                entries[i].username, entries[i].password);
                    }
                }
                break;  /* Done with this entry */
            }
        }
    }
    
    if (verbose) {
        fprintf(output, "Rainbow table attack completed. Cracked %zu passwords.\n", *cracked_count);
    }
    
    fclose(file);
    return 0;
}
