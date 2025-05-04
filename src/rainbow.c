#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "rainbow.h"

#define MAX_LINE_LENGTH 256
#define MAX_PASSWORD_LENGTH 100
#define MAX_HASH_LENGTH 100

/* Rainbow table entry structure */
typedef struct {
    char hash[MAX_HASH_LENGTH];
    char password[MAX_PASSWORD_LENGTH];
} rainbow_entry_t;

/* Perform rainbow table attack on shadow entries */
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
    
    /* Count lines in rainbow table */
    size_t line_count = 0;
    char line[MAX_LINE_LENGTH];
    
    while (fgets(line, sizeof(line), file) != NULL) {
        line_count++;
    }
    
    if (verbose) {
        fprintf(output, "Rainbow table contains %zu entries\n", line_count);
    }
    
    /* Reset file position */
    rewind(file);
    
    /* Load rainbow table into memory */
    rainbow_entry_t *rainbow = (rainbow_entry_t *)malloc(line_count * sizeof(rainbow_entry_t));
    if (!rainbow) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        fclose(file);
        return -1;
    }
    
    size_t entry_count = 0;
    while (fgets(line, sizeof(line), file) != NULL && entry_count < line_count) {
        /* Check timeout */
        if (*timeout_flag) {
            break;
        }
        
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
        
        /* Parse line (format: hash:password) */
        char *hash = strtok(line, ":");
        if (!hash) {
            continue;
        }
        
        char *password = strtok(NULL, ":");
        if (!password) {
            continue;
        }
        
        /* Store in rainbow table */
        strncpy(rainbow[entry_count].hash, hash, MAX_HASH_LENGTH - 1);
        rainbow[entry_count].hash[MAX_HASH_LENGTH - 1] = '\0';
        
        strncpy(rainbow[entry_count].password, password, MAX_PASSWORD_LENGTH - 1);
        rainbow[entry_count].password[MAX_PASSWORD_LENGTH - 1] = '\0';
        
        entry_count++;
    }
    
    fclose(file);
    
    if (verbose) {
        fprintf(output, "Loaded %zu entries from rainbow table\n", entry_count);
    }
    
    /* Process each shadow entry */
    for (size_t i = 0; i < num_entries; i++) {
        /* Check timeout */
        if (*timeout_flag) {
            break;
        }
        
        shadow_entry_t *entry = &entries[i];
        
        /* Skip already cracked entries */
        if (entry->password) {
            continue;
        }
        
        /* Look for match in rainbow table */
        for (size_t j = 0; j < entry_count; j++) {
            /* Match hash */
            if (strstr(entry->hash, rainbow[j].hash) != NULL) {
                /* Verify password */
                if (check_password(entry, rainbow[j].password)) {
                    entry->password = strdup(rainbow[j].password);
                    (*cracked_count)++;
                    
                    if (verbose) {
                        fprintf(output, "Cracked password for %s: %s (using rainbow table)\n", 
                                entry->username, entry->password);
                    } else {
                        fprintf(output, "Cracked password for %s: %s\n", 
                                entry->username, entry->password);
                    }
                    
                    break;
                }
            }
        }
    }
    
    /* Clean up */
    free(rainbow);
    
    return 0;
}
