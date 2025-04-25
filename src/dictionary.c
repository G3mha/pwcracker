#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include "dictionary.h"

#define MAX_PASSWORD_LENGTH 100

/* Thread data structure */
typedef struct {
    shadow_entry_t *entries;
    size_t num_entries;
    const char *dictionary_file;
    hash_type_t hash_type;
    FILE *output;
    int verbose;
    volatile int *timeout_flag;
    pthread_mutex_t *output_mutex;
    pthread_mutex_t *cracked_mutex;
    size_t *cracked_count;
    size_t start_line;
    size_t end_line;
    int thread_id;
} thread_data_t;

/* Count lines in a file */
static size_t count_lines(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        return 0;
    }
    
    size_t count = 0;
    int ch;
    int prev_ch = '\n';
    
    while ((ch = fgetc(file)) != EOF) {
        if (ch == '\n' && prev_ch != '\n') {
            count++;
        }
        prev_ch = ch;
    }
    
    /* Count last line if file doesn't end with newline */
    if (prev_ch != '\n') {
        count++;
    }
    
    fclose(file);
    return count;
}

/* Thread function for dictionary attack */
static void *dictionary_thread(void *arg) {
    thread_data_t *data = (thread_data_t *)arg;
    FILE *dict_file = fopen(data->dictionary_file, "r");
    if (!dict_file) {
        fprintf(stderr, "Thread %d: Could not open dictionary file\n", data->thread_id);
        return NULL;
    }
    
    /* Skip to start line */
    size_t line_num = 0;
    char password[MAX_PASSWORD_LENGTH];
    while (line_num < data->start_line && fgets(password, sizeof(password), dict_file)) {
        if (password[0] != '\0') {
            line_num++;
        }
    }
    
    /* Process assigned lines */
    while (line_num < data->end_line && fgets(password, sizeof(password), dict_file)) {
        /* Check timeout */
        if (*data->timeout_flag) {
            break;
        }
        
        /* Remove trailing newline */
        size_t len = strlen(password);
        if (len > 0 && password[len - 1] == '\n') {
            password[len - 1] = '\0';
            len--;
        }
        
        /* Skip empty lines */
        if (len == 0) {
            continue;
        }
        
        line_num++;
        
        /* Try password on all entries */
        for (size_t i = 0; i < data->num_entries; i++) {
            shadow_entry_t *entry = &data->entries[i];
            
            /* Skip already cracked entries */
            if (entry->password) {
                continue;
            }
            
            /* Check if password matches */
            if (check_password(entry, password)) {
                /* Lock for updating entry */
                pthread_mutex_lock(data->cracked_mutex);
                
                /* Double check that it's not cracked yet (race condition) */
                if (!entry->password) {
                    entry->password = strdup(password);
                    (*data->cracked_count)++;
                    
                    /* Print result */
                    pthread_mutex_lock(data->output_mutex);
                    if (data->verbose) {
                        fprintf(data->output, "[Thread %d] Cracked password for %s: %s\n", 
                                data->thread_id, entry->username, password);
                    } else {
                        fprintf(data->output, "Cracked password for %s: %s\n", 
                                entry->username, password);
                    }
                    pthread_mutex_unlock(data->output_mutex);
                }
                
                pthread_mutex_unlock(data->cracked_mutex);
            }
        }
    }
    
    fclose(dict_file);
    return NULL;
}

/* Perform dictionary attack on shadow entries */
int dictionary_attack(shadow_entry_t *entries, size_t num_entries,
                    const char *dictionary_file, hash_type_t hash_type,
                    int num_threads, FILE *output, int verbose,
                    size_t *cracked_count, volatile int *timeout_flag) {
    /* Initialize cracked count */
    *cracked_count = 0;
    
    /* Check if dictionary file exists */
    FILE *test_file = fopen(dictionary_file, "r");
    if (!test_file) {
        fprintf(stderr, "Error: Could not open dictionary file '%s'\n", dictionary_file);
        return -1;
    }
    fclose(test_file);
    
    /* Count total lines in dictionary */
    size_t total_lines = count_lines(dictionary_file);
    if (verbose) {
        fprintf(output, "Dictionary contains %zu passwords\n", total_lines);
    }
    
    /* Create mutexes */
    pthread_mutex_t output_mutex = PTHREAD_MUTEX_INITIALIZER;
    pthread_mutex_t cracked_mutex = PTHREAD_MUTEX_INITIALIZER;
    
    /* Create threads */
    pthread_t *threads = (pthread_t *)malloc(num_threads * sizeof(pthread_t));
    thread_data_t *thread_data = (thread_data_t *)malloc(num_threads * sizeof(thread_data_t));
    
    if (!threads || !thread_data) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        free(threads);
        free(thread_data);
        return -1;
    }
    
    /* Calculate lines per thread */
    size_t lines_per_thread = total_lines / num_threads;
    size_t remainder = total_lines % num_threads;
    
    /* Create and start threads */
    size_t start_line = 0;
    for (int i = 0; i < num_threads; i++) {
        size_t thread_lines = lines_per_thread + (i < (int)remainder ? 1 : 0);
        
        thread_data[i].entries = entries;
        thread_data[i].num_entries = num_entries;
        thread_data[i].dictionary_file = dictionary_file;
        thread_data[i].hash_type = hash_type;
        thread_data[i].output = output;
        thread_data[i].verbose = verbose;
        thread_data[i].timeout_flag = timeout_flag;
        thread_data[i].output_mutex = &output_mutex;
        thread_data[i].cracked_mutex = &cracked_mutex;
        thread_data[i].cracked_count = cracked_count;
        thread_data[i].start_line = start_line;
        thread_data[i].end_line = start_line + thread_lines;
        thread_data[i].thread_id = i;
        
        if (pthread_create(&threads[i], NULL, dictionary_thread, &thread_data[i]) != 0) {
            fprintf(stderr, "Error: Failed to create thread %d\n", i);
            /* Clean up already created threads */
            for (int j = 0; j < i; j++) {
                pthread_cancel(threads[j]);
                pthread_join(threads[j], NULL);
            }
            free(threads);
            free(thread_data);
            return -1;
        }
        
        start_line += thread_lines;
    }
    
    /* Wait for threads to finish */
    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }
    
    /* Clean up */
    pthread_mutex_destroy(&output_mutex);
    pthread_mutex_destroy(&cracked_mutex);
    free(threads);
    free(thread_data);
    
    return 0;
}
