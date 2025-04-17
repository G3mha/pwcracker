#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include "bruteforce.h"

#define MAX_PASSWORD_LENGTH 16

/* Thread data structure */
typedef struct {
    shadow_entry_t *entries;
    size_t num_entries;
    const char *charset;
    int max_length;
    hash_type_t hash_type;
    FILE *output;
    int verbose;
    volatile int *timeout_flag;
    pthread_mutex_t *output_mutex;
    pthread_mutex_t *cracked_mutex;
    size_t *cracked_count;
    int thread_id;
    int total_threads;
} thread_data_t;

/* Generate next password based on thread ID for work distribution */
static int next_password(char *password, int *length, const char *charset, 
                        int max_length, int thread_id, int total_threads) {
    size_t charset_len = strlen(charset);
    
    /* First call: initialize password */
    if (*length == 0) {
        *length = 1;
        password[0] = charset[thread_id % charset_len];
        password[1] = '\0';
        return 1;
    }
    
    /* Increment password */
    int i = *length - 1;
    while (i >= 0) {
        /* Find current character in charset */
        const char *pos = strchr(charset, password[i]);
        if (!pos) {
            /* Should not happen */
            return 0;
        }
        
        /* Distance from start of charset */
        size_t index = (size_t)(pos - charset);
        
        /* Move to next character based on thread distribution */
        index = (index + total_threads) % charset_len;
        
        /* Update character */
        password[i] = charset[index];
        
        /* If not wrapped around, we're done */
        if (index != (thread_id % charset_len)) {
            return 1;
        }
        
        /* Move to next position */
        i--;
    }
    
    /* All positions wrapped around, move to next length */
    (*length)++;
    
    /* Check if we exceeded max length */
    if (*length > max_length) {
        return 0;
    }
    
    /* Initialize new password with thread-specific starting point */
    for (i = 0; i < *length - 1; i++) {
        password[i] = charset[0];
    }
    password[*length - 1] = charset[thread_id % charset_len];
    password[*length] = '\0';
    
    return 1;
}

/* Thread function for brute force attack */
static void *bruteforce_thread(void *arg) {
    thread_data_t *data = (thread_data_t *)arg;
    char password[MAX_PASSWORD_LENGTH + 1];
    int length = 0;
    
    /* Generate passwords and check them */
    while (next_password(password, &length, data->charset, data->max_length, 
                         data->thread_id, data->total_threads)) {
        /* Check timeout */
        if (*data->timeout_flag) {
            break;
        }
        
        /* Output progress periodically */
        static int counter = 0;
        if (data->verbose && data->thread_id == 0 && (++counter % 100000) == 0) {
            pthread_mutex_lock(data->output_mutex);
            fprintf(data->output, "Trying password length %d: %s\n", length, password);
            pthread_mutex_unlock(data->output_mutex);
        }
        
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
    
    return NULL;
}

/* Perform brute force attack on shadow entries */
int bruteforce_attack(shadow_entry_t *entries, size_t num_entries,
                    const char *charset, int max_length, hash_type_t hash_type,
                    int num_threads, FILE *output, int verbose,
                    size_t *cracked_count, volatile int *timeout_flag) {
    /* Initialize cracked count */
    *cracked_count = 0;
    
    /* Check max length */
    if (max_length <= 0 || max_length > MAX_PASSWORD_LENGTH) {
        fprintf(stderr, "Error: Maximum length must be between 1 and %d\n", 
                MAX_PASSWORD_LENGTH);
        return -1;
    }
    
    /* Calculate charset size and total work */
    size_t charset_len = strlen(charset);
    size_t total_combinations = 0;
    size_t combinations = 1;
    
    for (int i = 1; i <= max_length; i++) {
        combinations *= charset_len;
        total_combinations += combinations;
        
        /* Check for overflow */
        if (combinations / charset_len != combinations / charset_len) {
            fprintf(stderr, "Warning: Work size overflow, limiting to length %d\n", i - 1);
            max_length = i - 1;
            break;
        }
    }
    
    if (verbose) {
        fprintf(output, "Brute force attack will try up to %zu combinations\n", 
                total_combinations);
        fprintf(output, "Using character set: %s (%zu characters)\n", 
                charset, charset_len);
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
    
    /* Create and start threads */
    for (int i = 0; i < num_threads; i++) {
        thread_data[i].entries = entries;
        thread_data[i].num_entries = num_entries;
        thread_data[i].charset = charset;
        thread_data[i].max_length = max_length;
        thread_data[i].hash_type = hash_type;
        thread_data[i].output = output;
        thread_data[i].verbose = verbose;
        thread_data[i].timeout_flag = timeout_flag;
        thread_data[i].output_mutex = &output_mutex;
        thread_data[i].cracked_mutex = &cracked_mutex;
        thread_data[i].cracked_count = cracked_count;
        thread_data[i].thread_id = i;
        thread_data[i].total_threads = num_threads;
        
        if (pthread_create(&threads[i], NULL, bruteforce_thread, &thread_data[i]) != 0) {
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
