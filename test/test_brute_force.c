#include <criterion/criterion.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/brute_force.h"
#include "../src/util.h"

Test(bruteforce_attack, basic_functionality) {
    // Create shadow entries for testing
    shadow_entry_t entries[3] = {0};
    size_t num_entries = 3;
    
    // Set up the first entry with a known password from the dictionary
    entries[0].username = strdup("user1");
    entries[0].hash = strdup("$1$zUDL$3fe34eba094562325c4e7260409fad83"); // "password" from test data
    entries[0].salt = strdup("zUDL");
    entries[0].type = HASH_MD5;
    entries[0].password = NULL;
    
    // Setup additional entries...
    
    // Variables for bruteforce_attack function
    FILE *output = tmpfile();
    int verbose = 0;
    size_t cracked_count = 0;
    volatile int timeout_flag = 0;
    
    // Call the actual function we want to test
    int result = bruteforce_attack(entries, num_entries, "abcdefghijklmnopqrstuvwxyz0123456789",
                                   8, HASH_MD5, 1, output, verbose, 
                                   &cracked_count, &timeout_flag);
    
    // Verify results
    cr_assert_eq(result, 0, "dictionary_attack should return 0 on success");
    cr_assert_gt(cracked_count, 0, "At least one password should be cracked");
    cr_assert_not_null(entries[0].password, "First password should be cracked");
    cr_assert_str_eq(entries[0].password, "password", "First password should be 'password'");
    
    
    // Clean up
    fclose(output);
    for (size_t i = 0; i < num_entries; i++) {
        cr_log_info("Username: %s, Hash: %s, Salt: %s, Password: %s", 
               entries[i].username, entries[i].hash, 
               entries[i].salt, entries[i].password ? entries[i].password : "NULL");
        free(entries[i].username);
        free(entries[i].hash);
        free(entries[i].salt);
        free(entries[i].password);
    }
}
